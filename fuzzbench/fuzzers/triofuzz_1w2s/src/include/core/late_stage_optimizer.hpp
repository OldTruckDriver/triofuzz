#pragma once

#include "engine.hpp"
#include <unordered_map>
#include <deque>
#include <bitset>

namespace triofuzz {

// FuzzingStats is defined in engine.hpp

// Late-stage optimizer - addresses coverage stagnation
class LateStageOptimizer {
private:
    // Coverage growth tracking
    struct CoverageGrowthTracker {
        std::deque<double> coverage_history;  // Coverage over the last N time windows
        size_t window_size = 60;  // 1 minute per window
        double growth_rate = 0.0;

        void update(double coverage) {
            coverage_history.push_back(coverage);
            if (coverage_history.size() > window_size) {
                coverage_history.pop_front();
            }

            // Compute growth rate
            if (coverage_history.size() >= 2) {
                double old_coverage = coverage_history.front();
                double new_coverage = coverage_history.back();
                growth_rate = (new_coverage - old_coverage) / coverage_history.size();
            }
        }

        bool isStagnant() const {
            return growth_rate < 0.001;  // Growth rate below 0.1%
        }

        size_t getStagnationDuration() const {
            // Count consecutive stagnant windows.
            size_t count = 0;
            for (auto it = coverage_history.rbegin(); it != coverage_history.rend(); ++it) {
                if (it != coverage_history.rbegin()) {
                    auto prev = std::prev(it);
                    if (*it - *prev < 0.001) {
                        count++;
                    } else {
                        break;
                    }
                }
            }
            return count;
        }
    };

    CoverageGrowthTracker growth_tracker_;

    // Rare path tracking
    struct RarePathTracker {
        std::unordered_map<size_t, size_t> path_hits;  // path_hash -> hit_count
        std::unordered_map<size_t, double> path_scores;  // path_hash -> rarity_score

        void updatePath(const CoverageInfo& coverage) {
            // Compute path hash
            size_t path_hash = hashCoverage(coverage);
            path_hits[path_hash]++;

            // Update rarity score
            updateRarityScores();
        }

        double getRarityScore(const CoverageInfo& coverage) const {
            size_t path_hash = hashCoverage(coverage);
            auto it = path_scores.find(path_hash);
            return it != path_scores.end() ? it->second : 1.0;
        }

    private:
        size_t hashCoverage(const CoverageInfo& coverage) const {
            // Simple edge-based hash
            size_t hash = 0;
            for (uint64_t edge : coverage.covered_edges) {
                hash ^= std::hash<uint64_t>()(edge) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            }
            return hash;
        }

        void updateRarityScores() {
            size_t total_hits = 0;
            for (const auto& [_, hits] : path_hits) {
                total_hits += hits;
            }

            if (total_hits > 0) {
                for (auto& [path, hits] : path_hits) {
                    // Rarer paths get higher scores.
                    path_scores[path] = 1.0 / (1.0 + std::log(1 + hits));
                }
            }
        }
    };

    RarePathTracker rare_path_tracker_;

    // Runtime dictionary learning
    struct RuntimeDictionary {
        std::unordered_map<std::string, size_t> tokens;  // token -> success_count
        std::vector<std::vector<uint8_t>> effective_sequences;
        size_t max_dict_size = 1000;

        void learnFromExecution(const std::vector<uint8_t>& input, bool found_coverage) {
            if (!found_coverage) return;

            // Extract effective byte sequences (simplified).
            for (size_t i = 0; i < input.size(); ) {
                // Find potential token boundaries.
                size_t token_len = findTokenLength(input, i);
                if (token_len >= 2 && token_len <= 16) {
                    std::string token(input.begin() + i, input.begin() + i + token_len);
                    tokens[token]++;
                    i += token_len;
                } else {
                    i++;
                }
            }

            // Save the full effective sequence.
            if (effective_sequences.size() < max_dict_size) {
                effective_sequences.push_back(input);
            }
        }

        std::vector<uint8_t> getRandomToken() const {
            if (tokens.empty()) return {};

            // Weighted selection by success count.
            size_t total_weight = 0;
            for (const auto& [_, count] : tokens) {
                total_weight += count;
            }

            if (total_weight == 0) return {};

            size_t target = rand() % total_weight;
            size_t current = 0;

            for (const auto& [token, count] : tokens) {
                current += count;
                if (current > target) {
                    return std::vector<uint8_t>(token.begin(), token.end());
                }
            }

            return {};
        }

    private:
        size_t findTokenLength(const std::vector<uint8_t>& input, size_t start) const {
            // Simple boundary detection: look for separators/special characters.
            size_t len = 0;
            for (size_t i = start; i < input.size() && len < 16; ++i, ++len) {
                uint8_t byte = input[i];
                // Common separators
                if (byte == 0 || byte == ' ' || byte == '\n' ||
                    byte == ',' || byte == ';' || byte == ':') {
                    break;
                }
            }
            return len;
        }
    };

    RuntimeDictionary runtime_dict_;

    // Exploration modes
    enum class ExplorationMode {
        FAST,        // Fast fuzzing
        DEEP,        // Deep exploration
        TARGETED,    // Targeted
        SYSTEMATIC   // Systematic exploration
    };

    ExplorationMode current_mode_ = ExplorationMode::FAST;

public:
    // Check whether we've entered late stage.
    bool isLateStage(const FuzzingStats& stats) const {
        // Condition 1: executions exceed threshold.
        if (stats.total_executions < 100000) return false;

        // Condition 2: coverage growth stagnates.
        if (!growth_tracker_.isStagnant()) return false;

        // Condition 3: stagnation longer than 5 minutes.
        return growth_tracker_.getStagnationDuration() > 5;
    }

    // Update coverage history
    void updateCoverage(double coverage_percentage) {
        growth_tracker_.update(coverage_percentage);
    }

    // Update path info
    void updatePath(const CoverageInfo& coverage) {
        rare_path_tracker_.updatePath(coverage);
    }

    // Learn runtime dictionary
    void learnFromInput(const std::vector<uint8_t>& input, bool found_coverage) {
        runtime_dict_.learnFromExecution(input, found_coverage);
    }

    // Get optimized algorithm combination (late stage).
    AlgorithmCombination getOptimizedCombination() {
        AlgorithmCombination combo;

        switch (current_mode_) {
            case ExplorationMode::DEEP:
                // Deep exploration: use deterministic and gradient descent.
                combo.algorithm_names = {"deterministic", "angora_gradient_descent", "redqueen"};
                combo.combination_mode = "sequential";
                break;

            case ExplorationMode::TARGETED:
                // Targeted: use rare-edge-prioritizing algorithms.
                combo.algorithm_names = {"rare_edge_scheduler", "fairfuzz", "aflgo"};
                combo.combination_mode = "weighted";
                combo.weights["rare_edge_scheduler"] = 0.5;
                combo.weights["fairfuzz"] = 0.3;
                combo.weights["aflgo"] = 0.2;
                break;

            case ExplorationMode::SYSTEMATIC:
                // Systematic: AFL++-like deterministic stage.
                combo.algorithm_names = {"bitflip", "arithmetic", "interesting", "dictionary"};
                combo.combination_mode = "sequential";
                break;

            default:  // FAST
                // Fast fuzzing: balanced combination.
                combo.algorithm_names = {"havoc", "splice", "smart_dictionary"};
                combo.combination_mode = "parallel";
                break;
        }

        return combo;
    }

    // Adjust seed priority (late stage).
    double adjustSeedPriority(const Seed& seed, double base_priority) {
        double adjusted = base_priority;

        // 1. Rare path bonus
        double rarity_score = rare_path_tracker_.getRarityScore(seed.coverage);
        adjusted *= (1.0 + rarity_score);

        // 2. Depth-first (late stage favors deep paths)
        if (seed.depth > 10) {
            adjusted *= 1.5;
        }

        // 3. Revive old seeds (give them a second chance late stage)
        if (seed.execution_count > 100 && seed.execution_count < 200) {
            adjusted *= 1.2;  // Revival period
        }

        // 4. Prefer small inputs (easier to go deeper)
        if (seed.data.size() < 100) {
            adjusted *= 1.3;
        }

        return adjusted;
    }

    // Switch exploration mode
    void switchMode(const FuzzingStats& stats) {
        size_t stagnation = growth_tracker_.getStagnationDuration();

        if (stagnation < 5) {
            current_mode_ = ExplorationMode::FAST;
        } else if (stagnation < 10) {
            current_mode_ = ExplorationMode::DEEP;
        } else if (stagnation < 20) {
            current_mode_ = ExplorationMode::TARGETED;
        } else {
            current_mode_ = ExplorationMode::SYSTEMATIC;
        }
    }

    // Get runtime-dictionary token
    std::vector<uint8_t> getDictionaryToken() const {
        return runtime_dict_.getRandomToken();
    }

    // Should reset Thompson Sampling
    bool shouldResetThompsonSampling() const {
        // Reset after 30 minutes of stagnation to give new combinations a chance.
        return growth_tracker_.getStagnationDuration() > 30;
    }

    // Get current mode name
    std::string getCurrentModeName() const {
        switch (current_mode_) {
            case ExplorationMode::DEEP: return "DEEP";
            case ExplorationMode::TARGETED: return "TARGETED";
            case ExplorationMode::SYSTEMATIC: return "SYSTEMATIC";
            default: return "FAST";
        }
    }
};

} // namespace triofuzz
