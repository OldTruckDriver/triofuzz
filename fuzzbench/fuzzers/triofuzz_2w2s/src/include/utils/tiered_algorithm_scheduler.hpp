#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <random>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <shared_mutex>

namespace triofuzz {

/**
 * @brief Algorithm performance tiers
 *
 * Algorithms are divided into three tiers based on overhead:
 * - Tier 1 (ultra fast): < 0.5ms, frequent use (70% probability)
 * - Tier 2 (fast): 0.5-1.0ms, medium frequency (25% probability)
 * - Tier 3 (medium): 1.0-2.0ms, low frequency (5% probability)
 */
enum class AlgorithmTier {
    TIER_1_ULTRA_FAST = 1,  // < 0.5ms
    TIER_2_FAST = 2,        // 0.5-1.0ms
    TIER_3_MEDIUM = 3       // 1.0-2.0ms
};

/**
 * @brief Algorithm performance metadata
 */
struct AlgorithmPerformanceProfile {
    std::string name;
    AlgorithmTier tier;
    double avg_execution_time_ms;
    double coverage_gain_rate;      // Average coverage gain rate
    double mutation_diversity;      // Mutation diversity [0-1]

    // Usage statistics
    size_t total_executions = 0;
    size_t successful_executions = 0;  // Found new coverage
    double cumulative_reward = 0.0;

    // Compute cost-effectiveness (reward per millisecond)
    double getCostEffectiveness() const {
        if (avg_execution_time_ms <= 0) return 0.0;
        return coverage_gain_rate / avg_execution_time_ms;
    }

    // Compute success rate
    double getSuccessRate() const {
        if (total_executions == 0) return 0.5; // Prior
        return static_cast<double>(successful_executions) / total_executions;
    }
};

/**
 * @brief Tiered probabilistic scheduler
 *
 * Strategy:
 * 1. Tier 1 algorithms: 70% probability, run almost every time
 * 2. Tier 2 algorithms: 25% probability, run moderately often
 * 3. Tier 3 algorithms: 5% probability, sparse but useful for exploration
 *
 * Dynamic adjustments:
 * - Adjust each tier's base probability based on runtime performance
 * - Within each tier, select algorithms using UCB1 based on success rate
 * - Consider diversity to avoid excessive exploitation
 */
class TieredAlgorithmScheduler {
private:
    // Algorithm performance profiles
    std::map<std::string, AlgorithmPerformanceProfile> profiles_;

    // Tier lists
    std::vector<std::string> tier1_algorithms_;
    std::vector<std::string> tier2_algorithms_;
    std::vector<std::string> tier3_algorithms_;

    // Base probability split (restored best-known config; move redqueen to Tier 2 for better structured-format support)
    double tier1_base_probability_ = 0.73;
    double tier2_base_probability_ = 0.25;
    double tier3_base_probability_ = 0.02;

    // Performance thresholds (ms)
    double tier1_threshold_ms_ = 0.5;
    double tier2_threshold_ms_ = 1.0;
    double tier3_threshold_ms_ = 2.0;

    // Adaptation parameters
    double adaptation_rate_ = 0.01;     // Learning rate
    double ucb_exploration_c_ = 1.414;  // UCB exploration coefficient
    double diversity_bonus_ = 0.1;      // Diversity bonus
    size_t warmup_executions_ = 100;    // Warmup executions
    size_t update_interval_ = 100;      // Update interval

    // Global statistics
    size_t total_executions_ = 0;
    double avg_execution_time_ms_ = 0.0;
    double target_execution_time_ms_ = 0.8;  // Target average execution time

    // Speed budget parameters
    double speed_budget_threshold_ = 1.5;  // Enter budget mode when exceeding target by this factor
    bool speed_budget_mode_ = false;       // Whether speed budget mode is active
    size_t consecutive_slow_updates_ = 0;  // Consecutive slow updates
    size_t speed_budget_trigger_count_ = 3; // Threshold to enter speed budget mode

    // Coverage growth tracking (used to adjust exploration dynamically)
    double last_coverage_growth_rate_ = 1.0;
    size_t executions_since_last_coverage_ = 0;

    // Random number generator
    std::mt19937 rng_;

    // Round-robin indices (used during warmup)
    std::map<int, size_t> round_robin_indices_;

    // Thread safety: protects profiles_/tier lists/stats during concurrent access
    mutable std::recursive_mutex mutex_;

public:
    TieredAlgorithmScheduler() : rng_(std::random_device{}()) {}

    // Set base probabilities for tiers (ensure sum <= 1; no forced normalization internally)
    void setTierBaseProbabilities(double p1, double p2, double p3) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        tier1_base_probability_ = std::clamp(p1, 0.0, 1.0);
        tier2_base_probability_ = std::clamp(p2, 0.0, 1.0);
        tier3_base_probability_ = std::clamp(p3, 0.0, 1.0);
    }

    /**
     * @brief Register an algorithm and its performance profile
     */
    void registerAlgorithm(const AlgorithmPerformanceProfile& profile) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        profiles_[profile.name] = profile;

        // Assign to the corresponding tier
        switch (profile.tier) {
            case AlgorithmTier::TIER_1_ULTRA_FAST:
                tier1_algorithms_.push_back(profile.name);
                break;
            case AlgorithmTier::TIER_2_FAST:
                tier2_algorithms_.push_back(profile.name);
                break;
            case AlgorithmTier::TIER_3_MEDIUM:
                tier3_algorithms_.push_back(profile.name);
                break;
        }
    }

    /**
     * @brief Select the next algorithm to execute
     *
     * Two-stage selection:
     * 1. Select a tier based on tier probabilities
     * 2. Select an algorithm within that tier using UCB1
     */
    std::string selectAlgorithm() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        // Stage 1: select tier
        double rand_val = std::uniform_real_distribution<double>(0.0, 1.0)(rng_);

        std::vector<std::string>* selected_tier = nullptr;
        int tier_id = 0;

        if (rand_val < tier1_base_probability_) {
            selected_tier = &tier1_algorithms_;
            tier_id = 1;
        } else if (rand_val < tier1_base_probability_ + tier2_base_probability_) {
            selected_tier = &tier2_algorithms_;
            tier_id = 2;
        } else {
            selected_tier = &tier3_algorithms_;
            tier_id = 3;
        }

        // Fallback to another tier
        if (selected_tier->empty()) {
            if (!tier1_algorithms_.empty()) {
                selected_tier = &tier1_algorithms_;
                tier_id = 1;
            } else if (!tier2_algorithms_.empty()) {
                selected_tier = &tier2_algorithms_;
                tier_id = 2;
            } else if (!tier3_algorithms_.empty()) {
                selected_tier = &tier3_algorithms_;
                tier_id = 3;
            } else {
                throw std::runtime_error("No algorithms registered in any tier");
            }
        }

        // Stage 2: select within the tier using UCB1
        return selectFromTier(*selected_tier, tier_id);
    }

    /**
     * @brief Select multiple algorithms (for combinations)
     *
     * @param count Number of algorithms to select
     * @param ensure_diversity Whether to ensure diversity
     * @return Selected algorithm list
     */
    std::vector<std::string> selectAlgorithms(size_t count, bool ensure_diversity = true) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::vector<std::string> selected;
        std::set<std::string> selected_set;

        // Check that at least one algorithm is available
        if (tier1_algorithms_.empty() && tier2_algorithms_.empty() && tier3_algorithms_.empty()) {
            throw std::runtime_error("No algorithms registered in any tier");
        }

        // Ensure at least one Tier 1 algorithm (if Tier 1 is non-empty)
        if (count > 0 && !tier1_algorithms_.empty()) {
            std::string algo = selectFromTier(tier1_algorithms_, 1);
            selected.push_back(algo);
            selected_set.insert(algo);
        }

        // Select remaining algorithms
        for (size_t i = selected.size(); i < count; ++i) {
            std::string algo = selectAlgorithm();

            // If diversity is required, avoid duplicates
            if (ensure_diversity) {
                int attempts = 0;
                while (selected_set.count(algo) > 0 && attempts < 10) {
                    algo = selectAlgorithm();
                    attempts++;
                }
            }

            selected.push_back(algo);
            selected_set.insert(algo);
        }

        return selected;
    }

    /**
     * @brief Update algorithm performance
     *
     * @param algorithm_name Algorithm name
     * @param execution_time_ms Execution time
     * @param found_new_coverage Whether new coverage was found
     * @param reward Reward value [0-1]
     */
    void updatePerformance(const std::string& algorithm_name,
                          double execution_time_ms,
                          bool found_new_coverage,
                          double reward = 0.0) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = profiles_.find(algorithm_name);
        if (it == profiles_.end()) return;

        auto& profile = it->second;

        // Update statistics
        profile.total_executions++;
        if (found_new_coverage) {
            profile.successful_executions++;
        }
        profile.cumulative_reward += reward;

        // Update average execution time (exponential moving average)
        double alpha = 0.1;
        profile.avg_execution_time_ms =
            alpha * execution_time_ms + (1 - alpha) * profile.avg_execution_time_ms;

        // Update coverage gain rate
        profile.coverage_gain_rate = profile.getSuccessRate();

        // Global statistics
        total_executions_++;
        avg_execution_time_ms_ =
            (avg_execution_time_ms_ * (total_executions_ - 1) + execution_time_ms)
            / total_executions_;

        // Track coverage growth
        if (found_new_coverage) {
            double growth_rate = 1.0 / (executions_since_last_coverage_ + 1);
            last_coverage_growth_rate_ = 0.9 * last_coverage_growth_rate_ + 0.1 * growth_rate;
            executions_since_last_coverage_ = 0;
        } else {
            executions_since_last_coverage_++;
        }

        // Adapt tier probabilities
        if (total_executions_ > warmup_executions_ && total_executions_ % update_interval_ == 0) {
            adaptTierProbabilities();

            // Dynamically adjust exploration parameter
            adjustExplorationParameter();
        }

        // Dynamically reclassify tier (if performance changes significantly)
        if (profile.total_executions >= 50 && profile.total_executions % 50 == 0) {
            reclassifyAlgorithmIfNeeded(algorithm_name);
        }
    }

    /**
     * @brief Dynamically adjust exploration to avoid premature convergence
     */
    void adjustExplorationParameter() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        // If we run many times without new coverage, increase exploration
        if (total_executions_ > 1000000) {
            double coverage_stagnation = static_cast<double>(executions_since_last_coverage_) / 1000.0;

            if (coverage_stagnation > 100.0) {
                // Long time without new coverage: increase exploration significantly
                ucb_exploration_c_ = std::min(3.0, ucb_exploration_c_ * 1.2);
            } else if (coverage_stagnation > 50.0) {
                // Moderate stagnation: increase exploration moderately
                ucb_exploration_c_ = std::min(2.5, ucb_exploration_c_ * 1.1);
            } else if (coverage_stagnation < 10.0 && ucb_exploration_c_ > 1.414) {
                // Good coverage growth: exploration can be reduced
                ucb_exploration_c_ = std::max(1.414, ucb_exploration_c_ * 0.95);
            }
        }
    }

    /**
     * @brief Get algorithm performance profile
     */
    const AlgorithmPerformanceProfile& getProfile(const std::string& algorithm_name) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return profiles_.at(algorithm_name);
    }

    /**
     * @brief Get all algorithms sorted by cost-effectiveness
     */
    std::vector<std::string> getAlgorithmsByEffectiveness() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::vector<std::pair<std::string, double>> rankings;

        for (const auto& [name, profile] : profiles_) {
            rankings.emplace_back(name, profile.getCostEffectiveness());
        }

        std::sort(rankings.begin(), rankings.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });

        std::vector<std::string> result;
        for (const auto& [name, _] : rankings) {
            result.push_back(name);
        }

        return result;
    }

    /**
     * @brief Get statistics report
     */
    std::string getStatisticsReport() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::ostringstream oss;
        oss << "\n=== Tiered Algorithm Scheduler Statistics ===\n";
        oss << "Total Executions: " << total_executions_ << "\n";
        oss << "Average Execution Time: " << avg_execution_time_ms_ << " ms\n";
        oss << "Target Execution Time: " << target_execution_time_ms_ << " ms\n";
        oss << "\nTier Probabilities:\n";
        oss << "  Tier 1 (Ultra Fast): " << (tier1_base_probability_ * 100) << "%\n";
        oss << "  Tier 2 (Fast):       " << (tier2_base_probability_ * 100) << "%\n";
        oss << "  Tier 3 (Medium):     " << (tier3_base_probability_ * 100) << "%\n";

        oss << "\nTop Algorithms by Cost-Effectiveness:\n";
        auto rankings = getAlgorithmsByEffectiveness();
        for (size_t i = 0; i < std::min<size_t>(5, rankings.size()); ++i) {
            const auto& profile = profiles_.at(rankings[i]);
            oss << "  " << (i+1) << ". " << profile.name
                << " - CE: " << profile.getCostEffectiveness()
                << " (success: " << (profile.getSuccessRate() * 100) << "%, "
                << "execs: " << profile.total_executions << ")\n";
        }

        return oss.str();
    }

    /**
     * @brief Set target execution time
     */
    void setTargetExecutionTime(double target_ms) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        target_execution_time_ms_ = target_ms;
    }

    /**
     * @brief Get current tier probabilities
     */
    std::tuple<double, double, double> getTierProbabilities() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return {tier1_base_probability_, tier2_base_probability_, tier3_base_probability_};
    }

    /**
     * @brief Check whether any algorithms are registered
     */
    bool hasAlgorithms() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return !profiles_.empty();
    }

    /**
     * @brief Get total executions
     */
    size_t getTotalExecutions() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return total_executions_;
    }

private:
    /**
     * @brief Select algorithm within a tier using UCB1
     */
    std::string selectFromTier(const std::vector<std::string>& tier_algorithms, int tier_id) {
        if (tier_algorithms.empty()) {
            throw std::runtime_error("Cannot select from empty tier");
        }

        // If there is only one algorithm, return it directly
        if (tier_algorithms.size() == 1) {
            return tier_algorithms[0];
        }

        // Compute total executions for this tier
        double total_tier_executions = 0;
        for (const auto& algo : tier_algorithms) {
            total_tier_executions += profiles_[algo].total_executions;
        }

        // Warmup phase: round-robin selection
        if (total_tier_executions < warmup_executions_) {
            size_t& idx = round_robin_indices_[tier_id];
            std::string selected = tier_algorithms[idx % tier_algorithms.size()];
            idx++;
            return selected;
        }

        // UCB1 selection - consider efficiency (reward/time)
        double best_ucb = -1.0;
        std::string best_algo;

        for (const auto& algo : tier_algorithms) {
            const auto& profile = profiles_[algo];

            // Exploitation: efficiency = success rate / execution time
            // This balances reward and speed.
            double success_rate = profile.getSuccessRate();
            double time_normalized = std::max(0.1, profile.avg_execution_time_ms); // Avoid division by zero
            double efficiency = success_rate / time_normalized;

            // Normalize efficiency into [0, 1]
            double exploitation = std::min(1.0, efficiency * 0.5); // 0.5 is a scaling factor

            // Exploration: UCB term
            double exploration = 0.0;
            if (profile.total_executions > 0) {
                exploration = ucb_exploration_c_ * std::sqrt(
                    std::log(total_tier_executions + 1) / profile.total_executions
                );
            } else {
                exploration = 10.0; // Prefer never-executed algorithms
            }

            // Diversity: diversity bonus
            double diversity = diversity_bonus_ * profile.mutation_diversity;

            // In speed budget mode, emphasize efficiency more
            double efficiency_weight = speed_budget_mode_ ? 1.5 : 1.0;

            double ucb_score = exploitation * efficiency_weight + exploration + diversity;

            if (ucb_score > best_ucb) {
                best_ucb = ucb_score;
                best_algo = algo;
            }
        }

        return best_algo;
    }

    /**
     * @brief Adapt tier probabilities
     *
     * Strategy:
     * - If average execution time exceeds the target, increase Tier 1 probability.
     * - If there is slack, increase Tier 2/3 probability to explore more.
     * - Speed budget mechanism: when persistently slow, force a fast mode.
     */
    void adaptTierProbabilities() {
        // Compute execution-time ratio
        double time_ratio = avg_execution_time_ms_ / target_execution_time_ms_;

        // === Speed budget mechanism ===
        if (time_ratio > speed_budget_threshold_) {
            consecutive_slow_updates_++;

            // If we exceed the budget repeatedly, enter speed budget mode
            if (consecutive_slow_updates_ >= speed_budget_trigger_count_) {
                speed_budget_mode_ = true;
                // Force fast algorithms (80% Tier 1, 15% Tier 2, 5% Tier 3)
                tier1_base_probability_ = 0.80;
                tier2_base_probability_ = 0.15;
                tier3_base_probability_ = 0.02;  // Reduce Tier 3 from 5% to 2%
                return; // Return early; skip normal adjustment
            }
        } else {
            consecutive_slow_updates_ = 0;

            // If speed returns to normal, exit speed budget mode
            if (speed_budget_mode_ && time_ratio < 1.0) {
                speed_budget_mode_ = false;
            }
        }

        // === Normal adaptive adjustment ===
        if (speed_budget_mode_) {
            // In speed budget mode, recover gradually
            if (time_ratio < 1.0) {
                tier1_base_probability_ = std::max(0.70, tier1_base_probability_ - adaptation_rate_);
                tier2_base_probability_ = std::min(0.25, tier2_base_probability_ + adaptation_rate_ * 0.5);
                tier3_base_probability_ = std::min(0.02, tier3_base_probability_ + adaptation_rate_ * 0.3);  // Keep low frequency
            }
        } else {
            // Normal mode
            if (time_ratio > 1.2) {
                // Too slow: increase Tier 1 weight
                tier1_base_probability_ = std::min(0.85, tier1_base_probability_ + adaptation_rate_);
                tier2_base_probability_ = std::max(0.10, tier2_base_probability_ - adaptation_rate_ * 0.5);
                tier3_base_probability_ = std::max(0.02, tier3_base_probability_ - adaptation_rate_ * 0.5);  // Reduce from 0.05 to 0.02
            } else if (time_ratio < 0.8) {
                // Plenty of slack: increase exploration
                tier1_base_probability_ = std::max(0.50, tier1_base_probability_ - adaptation_rate_);
                tier2_base_probability_ = std::min(0.35, tier2_base_probability_ + adaptation_rate_ * 0.5);
                tier3_base_probability_ = std::min(0.10, tier3_base_probability_ + adaptation_rate_ * 0.5);  // Cap at 10%
            }
        }

        // Normalize
        double sum = tier1_base_probability_ + tier2_base_probability_ + tier3_base_probability_;
        tier1_base_probability_ /= sum;
        tier2_base_probability_ /= sum;
        tier3_base_probability_ /= sum;
    }

    /**
     * @brief Reclassify algorithm based on actual performance
     */
    void reclassifyAlgorithmIfNeeded(const std::string& algorithm_name) {
        auto it = profiles_.find(algorithm_name);
        if (it == profiles_.end()) return;

        auto& profile = it->second;

        AlgorithmTier new_tier = profile.tier;

        if (profile.avg_execution_time_ms < tier1_threshold_ms_) {
            new_tier = AlgorithmTier::TIER_1_ULTRA_FAST;
        } else if (profile.avg_execution_time_ms < tier2_threshold_ms_) {
            new_tier = AlgorithmTier::TIER_2_FAST;
        } else if (profile.avg_execution_time_ms < tier3_threshold_ms_) {
            new_tier = AlgorithmTier::TIER_3_MEDIUM;
        } else {
            // Exceeds threshold; keep in Tier 3 (do not remove).
            return;
        }

        // If tier changes, reassign
        if (new_tier != profile.tier) {
            // Check whether the old tier would become empty (safety: keep at least one algorithm per tier)
            size_t old_tier_size = 0;
            switch (profile.tier) {
                case AlgorithmTier::TIER_1_ULTRA_FAST:
                    old_tier_size = tier1_algorithms_.size();
                    break;
                case AlgorithmTier::TIER_2_FAST:
                    old_tier_size = tier2_algorithms_.size();
                    break;
                case AlgorithmTier::TIER_3_MEDIUM:
                    old_tier_size = tier3_algorithms_.size();
                    break;
            }

            // If removal would empty the tier, skip reclassification
            if (old_tier_size <= 1) {
                return;
            }

            // Remove from old tier
            removeFromTier(algorithm_name, profile.tier);

            // Add to new tier
            profile.tier = new_tier;
            switch (new_tier) {
                case AlgorithmTier::TIER_1_ULTRA_FAST:
                    tier1_algorithms_.push_back(algorithm_name);
                    break;
                case AlgorithmTier::TIER_2_FAST:
                    tier2_algorithms_.push_back(algorithm_name);
                    break;
                case AlgorithmTier::TIER_3_MEDIUM:
                    tier3_algorithms_.push_back(algorithm_name);
                    break;
            }
        }
    }

    void removeFromTier(const std::string& algorithm_name, AlgorithmTier tier) {
        std::vector<std::string>* tier_list = nullptr;

        switch (tier) {
            case AlgorithmTier::TIER_1_ULTRA_FAST:
                tier_list = &tier1_algorithms_;
                break;
            case AlgorithmTier::TIER_2_FAST:
                tier_list = &tier2_algorithms_;
                break;
            case AlgorithmTier::TIER_3_MEDIUM:
                tier_list = &tier3_algorithms_;
                break;
        }

        if (tier_list) {
            tier_list->erase(
                std::remove(tier_list->begin(), tier_list->end(), algorithm_name),
                tier_list->end()
            );
        }
    }
};

/**
 * @brief Predefined algorithm profiles - tuned based on empirical tests
 */
namespace TieredProfiles {

    // Tier 1: Ultra Fast (< 0.5ms)
    inline AlgorithmPerformanceProfile MAGIC_BYTE = {
        "magic_byte", AlgorithmTier::TIER_1_ULTRA_FAST, 0.2, 0.4, 0.6
    };

    inline AlgorithmPerformanceProfile BITFLIP = {
        "bitflip", AlgorithmTier::TIER_1_ULTRA_FAST, 0.3, 0.5, 0.7
    };

    inline AlgorithmPerformanceProfile VALUE_APPROXIMATION = {
        "value_approximation", AlgorithmTier::TIER_1_ULTRA_FAST, 0.35, 0.55, 0.65
    };

    inline AlgorithmPerformanceProfile LENGTH_EXTENSION = {
        "length_extension", AlgorithmTier::TIER_1_ULTRA_FAST, 0.35, 0.45, 0.6
    };

    inline AlgorithmPerformanceProfile ARITHMETIC = {
        "arithmetic", AlgorithmTier::TIER_1_ULTRA_FAST, 0.4, 0.5, 0.65
    };

    inline AlgorithmPerformanceProfile BYTE_WEIGHTED_HAVOC = {
        "byte_weighted_havoc", AlgorithmTier::TIER_1_ULTRA_FAST, 0.35, 0.55, 0.70
    };

    inline AlgorithmPerformanceProfile NIBBLE_SWAP = {
        "nibble_swap", AlgorithmTier::TIER_1_ULTRA_FAST, 0.25, 0.45, 0.65
    };

    inline AlgorithmPerformanceProfile BIT_ROTATE = {
        "bit_rotate", AlgorithmTier::TIER_1_ULTRA_FAST, 0.28, 0.5, 0.7
    };

    inline AlgorithmPerformanceProfile VARINT = {
        "varint", AlgorithmTier::TIER_1_ULTRA_FAST, 0.32, 0.55, 0.7
    };

    inline AlgorithmPerformanceProfile TOKEN = {
        "token", AlgorithmTier::TIER_1_ULTRA_FAST, 0.25, 0.6, 0.75
    };

    inline AlgorithmPerformanceProfile ENDIANNESS_SWAP = {
        "endianness_swap", AlgorithmTier::TIER_1_ULTRA_FAST, 0.15, 0.45, 0.6
    };

    // Tier 2: Fast (0.5-1.0ms)
    inline AlgorithmPerformanceProfile HAVOC = {
        "havoc", AlgorithmTier::TIER_2_FAST, 0.5, 0.7, 0.85
    };

    inline AlgorithmPerformanceProfile SPLICE = {
        "splice", AlgorithmTier::TIER_2_FAST, 0.5, 0.6, 0.8
    };

    inline AlgorithmPerformanceProfile CLASSIC_LIBFUZZER = {
        "classic_libfuzzer", AlgorithmTier::TIER_2_FAST, 0.65, 0.65, 0.8
    };

    inline AlgorithmPerformanceProfile TRIM = {
        "trim", AlgorithmTier::TIER_2_FAST, 0.4, 0.5, 0.6
    };

    inline AlgorithmPerformanceProfile BLOCK = {
        "block", AlgorithmTier::TIER_2_FAST, 0.5, 0.55, 0.7
    };

    inline AlgorithmPerformanceProfile CHUNK_BASED = {
        "chunk_based", AlgorithmTier::TIER_2_FAST, 0.7, 0.65, 0.7
    };

    inline AlgorithmPerformanceProfile CMPLOG = {
        "cmplog", AlgorithmTier::TIER_2_FAST, 0.8, 0.75, 0.85
    };

    inline AlgorithmPerformanceProfile REDQUEEN = {
        "redqueen", AlgorithmTier::TIER_2_FAST, 1.5, 0.85, 0.95
    };

    inline AlgorithmPerformanceProfile FORMAT_AWARE = {
        "format_aware", AlgorithmTier::TIER_2_FAST, 0.9, 0.7, 0.75
    };

    inline AlgorithmPerformanceProfile RUN_LENGTH = {
        "run_length", AlgorithmTier::TIER_2_FAST, 0.6, 0.55, 0.65
    };

    inline AlgorithmPerformanceProfile CHECKSUM_FIXUP = {
        "checksum_fixup", AlgorithmTier::TIER_2_FAST, 0.7, 0.5, 0.6
    };

    // Tier 3: Medium (1.0-2.0ms)
    inline AlgorithmPerformanceProfile SMART_DICTIONARY = {
        "smart_dictionary", AlgorithmTier::TIER_3_MEDIUM, 1.2, 0.75, 0.7
    };

    // Archived algorithms (not registered)
    // inline AlgorithmPerformanceProfile AFL_PLUS_PLUS = {
    //     "afl_plus_plus", AlgorithmTier::TIER_3_MEDIUM, 1.5, 0.8, 0.85
    // };

    // inline AlgorithmPerformanceProfile CLASSIC_LIBFUZZER = {
    //     "classic_libfuzzer", AlgorithmTier::TIER_2_FAST, 0.9, 0.8, 0.85
    // };

} // namespace TieredProfiles

} // namespace triofuzz
