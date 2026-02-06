#pragma once

#include <map>
#include <vector>
#include <string>
#include <random>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <shared_mutex>

namespace triofuzz {

// Forward declaration
struct AlgorithmCombination;

// Thompson Sampling for dynamic algorithm combination
class ThompsonSampling {
public:
    // Beta distribution parameters for each algorithm
    struct BetaParams {
        std::atomic<double> alpha{1.0};
        std::atomic<double> beta{1.0};
        std::atomic<size_t> total_uses{0};
        std::atomic<double> total_reward{0.0};
        std::chrono::steady_clock::time_point last_update;

        BetaParams() : last_update(std::chrono::steady_clock::now()) {}

        void update(double reward, double decay_factor = 0.95) {
            // Apply decay to forget old experiences
            double current_alpha = alpha.load();
            double current_beta = beta.load();

            alpha.store(current_alpha * decay_factor + 1.0 * (1 - decay_factor));
            beta.store(current_beta * decay_factor + 1.0 * (1 - decay_factor));

            // Update based on reward (0 to 1)
            if (reward > 0.7) {
                double current = alpha.load();
                alpha.store(current + reward);
            } else if (reward < 0.3) {
                double current = beta.load();
                beta.store(current + (1.0 - reward));
            } else {
                double current_alpha = alpha.load();
                alpha.store(current_alpha + reward * 0.5);
                double current_beta = beta.load();
                beta.store(current_beta + (1.0 - reward) * 0.5);
            }

            // Cap parameters to prevent over-confidence
            if (alpha.load() > 30.0) alpha.store(30.0);
            if (beta.load() > 30.0) beta.store(30.0);

            total_uses.fetch_add(1);
            double current_reward = total_reward.load();
            total_reward.store(current_reward + reward);
            last_update = std::chrono::steady_clock::now();
        }

        double sample(std::mt19937& rng) const {
            std::gamma_distribution<double> gamma_alpha(alpha.load(), 1.0);
            std::gamma_distribution<double> gamma_beta(beta.load(), 1.0);

            double a = gamma_alpha(rng);
            double b = gamma_beta(rng);

            return (a + b > 0) ? a / (a + b) : 0.5;
        }

        double getMean() const {
            double a = alpha.load();
            double b = beta.load();
            return a / (a + b);
        }
    };

    // Combination history and performance
    struct CombinationStats {
        std::atomic<size_t> executions{0};
        std::atomic<double> total_reward{0.0};
        std::atomic<size_t> new_coverage_count{0};
        std::atomic<size_t> crash_count{0};
        std::atomic<size_t> success_count{0};
        std::atomic<size_t> failure_count{0};
        std::chrono::steady_clock::time_point first_use;
        std::chrono::steady_clock::time_point last_use;

        CombinationStats() {
            auto now = std::chrono::steady_clock::now();
            first_use = now;
            last_use = now;
        }

        void record(double reward, bool new_coverage, bool crashed, bool success) {
            executions.fetch_add(1);
            double current = total_reward.load();
            total_reward.store(current + reward);
            if (new_coverage) new_coverage_count.fetch_add(1);
            if (crashed) crash_count.fetch_add(1);
            if (success) {
                success_count.fetch_add(1);
            } else {
                failure_count.fetch_add(1);
            }
            last_use = std::chrono::steady_clock::now();
        }

        double getAverageReward() const {
            size_t execs = executions.load();
            return execs > 0 ? total_reward.load() / execs : 0.0;
        }

        double getCoverageRate() const {
            size_t execs = executions.load();
            return execs > 0 ? static_cast<double>(new_coverage_count.load()) / execs : 0.0;
        }

        double getSuccessRate() const {
            size_t execs = executions.load();
            return execs > 0 ? static_cast<double>(success_count.load()) / execs : 0.0;
        }

        double getFailureRate() const {
            size_t execs = executions.load();
            return execs > 0 ? static_cast<double>(failure_count.load()) / execs : 0.0;
        }
    };

private:
    // Individual algorithm performance tracking
    std::unordered_map<std::string, std::unique_ptr<BetaParams>> algorithm_params_;

    // Combination performance tracking
    std::unordered_map<std::string, std::unique_ptr<CombinationStats>> combination_stats_;

    // Synergy matrix: tracks how well algorithms work together
    std::map<std::pair<std::string, std::string>, double> synergy_matrix_;

    // Thread safety
    mutable std::shared_mutex params_mutex_;
    mutable std::shared_mutex stats_mutex_;
    mutable std::shared_mutex synergy_mutex_;

    // Random number generation
    thread_local static std::mt19937 rng_;

    // Configuration
    size_t min_algorithms_per_combo_ = 2;
    size_t max_algorithms_per_combo_ = 4;
    double exploration_bonus_ = 0.1;  // Bonus for unexplored combinations
    double synergy_weight_ = 0.2;     // Weight of synergy in scoring

public:
    ThompsonSampling() = default;

    // Select next algorithm combination using Thompson Sampling
    AlgorithmCombination selectCombination(const std::vector<std::string>& available_algorithms);

    // Update statistics after execution
    void updateStatistics(const AlgorithmCombination& combo, double reward, bool new_coverage, bool crashed, bool decoder_success);

    // Dynamic combination generation
    std::vector<AlgorithmCombination> generateDynamicCombinations(const std::vector<std::string>& algorithms);

    // Get or create Beta parameters for an algorithm
    BetaParams* getAlgorithmParams(const std::string& algorithm);

    // Get or create combination stats
    CombinationStats* getCombinationStats(const std::string& combo_key);

    // Calculate synergy between algorithms
    double calculateSynergy(const std::vector<std::string>& algorithms);

    // Score a combination based on Thompson Sampling
    double scoreCombination(const AlgorithmCombination& combo);

    // Apply exploration bonus for underexplored combinations
    double applyExplorationBonus(const AlgorithmCombination& combo, double base_score);

    // Periodic decay of old statistics
    void decayOldStatistics();

    // Get performance report
    std::string getPerformanceReport() const;

    // Configuration methods
    void setMinAlgorithmsPerCombo(size_t min) { min_algorithms_per_combo_ = min; }
    void setMaxAlgorithmsPerCombo(size_t max) { max_algorithms_per_combo_ = max; }
    void setExplorationBonus(double bonus) { exploration_bonus_ = bonus; }
    void setSynergyWeight(double weight) { synergy_weight_ = weight; }
};

} // namespace triofuzz
