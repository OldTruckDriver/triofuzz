#pragma once

#include <vector>
#include <string>
#include <map>
#include <deque>
#include <algorithm>
#include <cmath>

namespace triofuzz {

// Adaptive algorithm selector - generic tracking and selection based on effectiveness
class AdaptiveAlgorithmSelector {
private:
    // Algorithm performance tracking
    struct AlgorithmPerformance {
        size_t total_uses = 0;
        size_t coverage_contributions = 0;  // Times new coverage was produced
        size_t crash_contributions = 0;     // Times crashes were found
        double total_coverage_gain = 0.0;   // Total coverage gain
        std::deque<double> recent_rewards;  // Rewards of the last N runs
        size_t window_size = 100;

        // Compute the algorithm's current efficiency score
        double getEfficiencyScore() const {
            if (total_uses == 0) return 1.0;  // Encourage exploration for unused algorithms

            // Base success rate
            double success_rate = (double)(coverage_contributions + crash_contributions) / total_uses;

            // Recent performance (exponential moving average)
            double recent_avg = 0.0;
            if (!recent_rewards.empty()) {
                double weight = 1.0;
                double weight_sum = 0.0;
                for (auto it = recent_rewards.rbegin(); it != recent_rewards.rend(); ++it) {
                    recent_avg += (*it) * weight;
                    weight_sum += weight;
                    weight *= 0.95;  // Decay factor
                }
                recent_avg /= weight_sum;
            }

            // Combined score: 70% historical success rate + 30% recent performance
            return 0.7 * success_rate + 0.3 * recent_avg;
        }

        void recordReward(double reward, bool found_coverage, bool found_crash) {
            total_uses++;
            if (found_coverage) coverage_contributions++;
            if (found_crash) crash_contributions++;
            total_coverage_gain += reward;

            recent_rewards.push_back(reward);
            if (recent_rewards.size() > window_size) {
                recent_rewards.pop_front();
            }
        }
    };

    // Performance data per algorithm
    std::map<std::string, AlgorithmPerformance> algorithm_performance_;

    // Algorithm categories (by characteristics)
    enum class AlgorithmType {
        RANDOM,       // Random mutations: havoc, splice
        DETERMINISTIC, // Deterministic: bitflip, arithmetic
        GRADIENT,     // Gradient-guided: angora_gradient_descent, neuzz
        STRUCTURAL,   // Structure-aware: dictionary, smart_format
        COVERAGE,     // Coverage-guided: fairfuzz, afl_plus_plus
        TARGETED      // Targeted: aflgo, rare_edge
    };

    std::map<std::string, AlgorithmType> algorithm_types_ = {
        {"havoc", AlgorithmType::RANDOM},
        {"splice", AlgorithmType::RANDOM},
        {"bitflip", AlgorithmType::DETERMINISTIC},
        {"arithmetic", AlgorithmType::DETERMINISTIC},
        {"interesting", AlgorithmType::DETERMINISTIC},
        {"angora_gradient_descent", AlgorithmType::GRADIENT},
        {"neuzz", AlgorithmType::GRADIENT},
        {"dictionary", AlgorithmType::STRUCTURAL},
        {"smart_dictionary", AlgorithmType::STRUCTURAL},
        {"smart_format", AlgorithmType::STRUCTURAL},
        {"fairfuzz", AlgorithmType::COVERAGE},
        {"afl_plus_plus", AlgorithmType::COVERAGE},
        {"aflgo", AlgorithmType::TARGETED},
        {"rare_edge_scheduler", AlgorithmType::TARGETED}
    };

    // Performance tracking per algorithm type
    std::map<AlgorithmType, double> type_performance_;

    // Runtime characteristic detection
    struct RuntimeCharacteristics {
        bool has_deep_branches = false;       // Deep branches
        bool has_numeric_comparisons = false; // Numeric comparisons
        bool has_structured_input = false;    // Structured input
        bool has_rare_edges = false;          // Rare edges
        bool is_stagnant = false;             // Coverage stagnation
        double coverage_velocity = 0.0;       // Coverage growth velocity
        size_t execution_count = 0;

        void update(double coverage_gain, size_t new_edges, size_t rare_edges_count) {
            execution_count++;

            // Update coverage velocity (exponential moving average)
            coverage_velocity = 0.9 * coverage_velocity + 0.1 * coverage_gain;

            // Detect stagnation
            is_stagnant = (coverage_velocity < 0.001 && execution_count > 10000);

            // Detect rare edges
            has_rare_edges = (rare_edges_count > 0);

            // Simple heuristic detection
            if (execution_count > 1000) {
                // If certain algorithms are especially effective, infer input characteristics.
                // This is handled in inferProgramCharacteristics() below.
            }
        }
    };

    RuntimeCharacteristics runtime_chars_;

public:
    // Get the next batch of algorithms (adaptive selection)
    std::vector<std::string> selectAlgorithms(size_t count = 3) {
        std::vector<std::string> selected;

        // Step 1: Adjust algorithm weights based on runtime characteristics
        std::map<std::string, double> adjusted_scores;

        for (const auto& [algo_name, perf] : algorithm_performance_) {
            double score = perf.getEfficiencyScore();

            // Adjust score based on algorithm type and runtime characteristics
            if (algorithm_types_.count(algo_name)) {
                AlgorithmType type = algorithm_types_[algo_name];
                score *= getTypeMultiplier(type);
            }

            // Exploration bonus: rarely used algorithms get a boost
            if (perf.total_uses < 100) {
                score *= 1.5;
            }

            adjusted_scores[algo_name] = score;
        }

        // Step 2: Select algorithms (balance exploitation and exploration)
        std::vector<std::pair<std::string, double>> candidates;
        for (const auto& [name, score] : adjusted_scores) {
            candidates.emplace_back(name, score);
        }

        // Sort by score
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        // Selection: 80% choose the best, 20% random exploration
        for (size_t i = 0; i < count && i < candidates.size(); ++i) {
            if (i == 0 || (rand() % 100) < 80) {
                // Pick a high-scoring algorithm
                selected.push_back(candidates[i].first);
            } else {
                // Random exploration
                size_t random_idx = rand() % candidates.size();
                selected.push_back(candidates[random_idx].first);
            }
        }

        // If there aren't enough candidates, add default algorithms
        if (selected.empty()) {
            selected = {"havoc", "bitflip", "arithmetic"};
        }

        return selected;
    }

    // Record algorithm execution result
    void recordAlgorithmResult(const std::string& algorithm,
                               double reward,
                               bool found_coverage,
                               bool found_crash) {
        algorithm_performance_[algorithm].recordReward(reward, found_coverage, found_crash);

        // Update algorithm type performance
        if (algorithm_types_.count(algorithm)) {
            AlgorithmType type = algorithm_types_[algorithm];
            type_performance_[type] = 0.9 * type_performance_[type] + 0.1 * reward;
        }
    }

    // Update runtime characteristics
    void updateRuntimeCharacteristics(double coverage_gain, size_t new_edges, size_t rare_edges) {
        runtime_chars_.update(coverage_gain, new_edges, rare_edges);

        // Infer program characteristics based on algorithm effectiveness
        inferProgramCharacteristics();
    }

    // Get recommended composition mode
    std::string getRecommendedMode() {
        if (runtime_chars_.is_stagnant) {
            return "sequential";  // Use sequential execution for deeper exploration when stagnant
        } else if (runtime_chars_.coverage_velocity > 0.01) {
            return "parallel";    // Explore in parallel during rapid growth
        } else {
            return "weighted";    // Use weighted composition in general cases
        }
    }

private:
    // Get type weight multipliers based on runtime characteristics
    double getTypeMultiplier(AlgorithmType type) {
        double multiplier = 1.0;

        switch (type) {
            case AlgorithmType::DETERMINISTIC:
                // Boost deterministic mutations when stagnant
                if (runtime_chars_.is_stagnant) multiplier *= 2.0;
                // Also boost when numeric comparisons exist
                if (runtime_chars_.has_numeric_comparisons) multiplier *= 1.5;
                break;

            case AlgorithmType::GRADIENT:
                // Use gradient methods when deep branches exist
                if (runtime_chars_.has_deep_branches) multiplier *= 2.5;
                // Also useful during stagnation
                if (runtime_chars_.is_stagnant) multiplier *= 1.5;
                break;

            case AlgorithmType::STRUCTURAL:
                // Boost for structured inputs
                if (runtime_chars_.has_structured_input) multiplier *= 3.0;
                break;

            case AlgorithmType::TARGETED:
                // Boost when rare edges exist
                if (runtime_chars_.has_rare_edges) multiplier *= 2.0;
                break;

            case AlgorithmType::COVERAGE:
                // Generally useful
                multiplier *= 1.2;
                break;

            case AlgorithmType::RANDOM:
                // Boost during early exploration
                if (runtime_chars_.execution_count < 100000) multiplier *= 1.3;
                break;
        }

        // Adjust based on historical performance
        if (type_performance_.count(type) && type_performance_[type] > 0.5) {
            multiplier *= (1.0 + type_performance_[type]);
        }

        return multiplier;
    }

    // Infer program characteristics from algorithm effectiveness
    void inferProgramCharacteristics() {
        // If the arithmetic algorithm is particularly effective, numeric comparisons may exist.
        if (algorithm_performance_["arithmetic"].getEfficiencyScore() > 0.3) {
            runtime_chars_.has_numeric_comparisons = true;
        }

        // If dictionary algorithms are effective, the input may be structured.
        if (algorithm_performance_["dictionary"].getEfficiencyScore() > 0.3 ||
            algorithm_performance_["smart_dictionary"].getEfficiencyScore() > 0.3) {
            runtime_chars_.has_structured_input = true;
        }

        // If gradient algorithms are effective, deep branches may exist.
        if (algorithm_performance_["angora_gradient_descent"].getEfficiencyScore() > 0.2) {
            runtime_chars_.has_deep_branches = true;
        }
    }

public:
    // Get algorithm performance report (for debugging)
    std::string getPerformanceReport() const {
        std::string report = "Algorithm Performance Report:\n";

        std::vector<std::pair<std::string, double>> scores;
        for (const auto& [name, perf] : algorithm_performance_) {
            scores.emplace_back(name, perf.getEfficiencyScore());
        }

        std::sort(scores.begin(), scores.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        for (const auto& [name, score] : scores) {
            const auto& perf = algorithm_performance_.at(name);
            report += name + ": score=" + std::to_string(score) +
                     " uses=" + std::to_string(perf.total_uses) +
                     " coverage=" + std::to_string(perf.coverage_contributions) + "\n";
        }

        return report;
    }
};

} // namespace triofuzz
