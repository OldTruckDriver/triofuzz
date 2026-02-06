#include "../../include/core/algorithm_combination_manager.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iostream>

namespace triofuzz {

// =============================================================================
// AlgorithmCombinationManager Implementation
// =============================================================================

AlgorithmCombinationManager::AlgorithmCombinationManager() {
    initializeAlgorithmMetadata();
}

void AlgorithmCombinationManager::initializeAlgorithmMetadata() {
    // Basic mutation algorithms
    algorithm_registry_["havoc"] = {
        "havoc", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, false, 0.5, 0.1, 0.6},
        {"bitflip", "arithmetic", "splice"}, {}, {}, {}
    };

    algorithm_registry_["bitflip"] = {
        "bitflip", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, true, 0.3, 0.1, 0.4},
        {"havoc", "arithmetic"}, {}, {}, {}
    };

    algorithm_registry_["arithmetic"] = {
        "arithmetic", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, true, 0.4, 0.1, 0.5},
        {"havoc", "bitflip"}, {}, {}, {}
    };

    algorithm_registry_["deterministic"] = {
        "deterministic", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, true, 0.6, 0.2, 0.55},
        {"bitflip", "arithmetic"}, {}, {}, {}
    };

    algorithm_registry_["splice"] = {
        "splice", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, false, 0.5, 0.15, 0.5},
        {"havoc"}, {}, {}, {}
    };

    algorithm_registry_["value_approximation"] = {
        "value_approximation", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, true, 0.35, 0.1, 0.55},
        {"bitflip", "arithmetic"}, {}, {}, {}
    };

    algorithm_registry_["length_extension"] = {
        "length_extension", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, false, 0.35, 0.1, 0.45},
        {"havoc"}, {}, {}, {}
    };

    algorithm_registry_["magic_byte"] = {
        "magic_byte", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, false, true, false, true, 0.2, 0.05, 0.4},
        {"bitflip", "arithmetic", "value_approximation"}, {}, {}, {}
    };

    algorithm_registry_["classic_libfuzzer"] = {
        "classic_libfuzzer", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, false, false, 0.65, 0.3, 0.65},
        {"havoc"}, {}, {}, {}
    };

    algorithm_registry_["smart_dictionary"] = {
        "smart_dictionary", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, true, true, true, false, 1.2, 0.8, 0.75},
        {"runtime_dictionary"}, {}, {}, {}
    };

    algorithm_registry_["gradient_descent"] = {
        "gradient_descent", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {false, true, true, true, false, 5.0, 2.0, 0.8},
        {"rare_branch"}, {"havoc"},
        {"coverage_analyzer"}, {"performance_analyzer"}
    };

    algorithm_registry_["neuzz"] = {
        "neuzz", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {false, true, true, true, false, 8.0, 5.0, 0.85},
        {"gradient_descent"}, {"bitflip", "arithmetic"},
        {"coverage_analyzer"}, {}
    };

    algorithm_registry_["aflgo"] = {
        "aflgo", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {false, true, true, true, false, 2.5, 1.2, 0.75},
        {"smart_format", "cmplog"}, {},
        {}, {"havoc"}
    };

    algorithm_registry_["coverage_analyzer"] = {
        "coverage_analyzer", ExtendedAlgorithmType::FEEDBACK_ANALYSIS,
        {true, true, false, true, true, 1.0, 0.5, 0.0},
        {}, {}, {}, {"performance_analyzer"}
    };

    algorithm_registry_["crash_analyzer"] = {
        "crash_analyzer", ExtendedAlgorithmType::FEEDBACK_ANALYSIS,
        {true, true, false, true, true, 1.5, 0.5, 0.0},
        {"coverage_analyzer"}, {}, {"coverage_analyzer"}, {}
    };

    algorithm_registry_["performance_analyzer"] = {
        "performance_analyzer", ExtendedAlgorithmType::FEEDBACK_ANALYSIS,
        {true, true, false, true, true, 0.8, 0.3, 0.0},
        {"coverage_analyzer"}, {}, {}, {}
    };

    algorithm_registry_["rare_edge_scheduler"] = {
        "rare_edge_scheduler", ExtendedAlgorithmType::SEED_SCHEDULING,
        {false, true, false, true, true, 0.5, 0.2, 0.3},
        {"mopt_scheduler"}, {}, {}, {"havoc", "smart_format"}
    };

    algorithm_registry_["mopt_scheduler"] = {
        "mopt_scheduler", ExtendedAlgorithmType::SEED_SCHEDULING,
        {false, true, false, true, false, 0.6, 0.3, 0.4},
        {}, {}, {}, {}
    };

    algorithm_registry_["smart_format"] = {
        "smart_format", ExtendedAlgorithmType::PREPROCESSING,
        {true, true, true, false, false, 2.0, 1.0, 0.7},
        {"smart_dictionary", "runtime_dictionary", "format_aware"}, {}, {}, {"havoc"}
    };

    algorithm_registry_["format_aware"] = {
        "format_aware", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, false, false, 3.0, 1.5, 0.85},
        {"smart_format", "cmplog", "redqueen"},
        {},
        {},
        {"havoc", "bitflip"}
    };

    algorithm_registry_["smart_dictionary"] = {
        "smart_dictionary", ExtendedAlgorithmType::BASIC_MUTATION,
        {true, true, true, true, false, 1.5, 0.8, 0.65},
        {"smart_format", "runtime_dictionary"}, {}, {}, {}
    };

    // 添加更多常用算法
    algorithm_registry_["cmplog"] = {
        "cmplog", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, true, false, 2.5, 1.5, 0.8},
        {"redqueen", "format_aware"}, {}, {}, {"havoc"}
    };

    algorithm_registry_["redqueen"] = {
        "redqueen", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, true, false, 2.2, 1.3, 0.75},
        {"cmplog", "format_aware"}, {}, {}, {}
    };

    algorithm_registry_["afl_plus_plus"] = {
        "afl_plus_plus", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, false, false, 3.5, 2.0, 0.9},
        {"havoc", "bitflip"}, {}, {}, {}
    };

    algorithm_registry_["aflpp"] = algorithm_registry_["afl_plus_plus"];

    algorithm_registry_["classic_libfuzzer"] = {
        "classic_libfuzzer", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, false, false, 3.0, 1.8, 0.85},
        {"havoc"}, {}, {}, {}
    };

    algorithm_registry_["libfuzzer"] = algorithm_registry_["classic_libfuzzer"]; // 别名

    algorithm_registry_["rare_branch"] = {
        "rare_branch", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {false, true, true, true, false, 2.0, 1.0, 0.7},
        {}, {}, {}, {}
    };

    algorithm_registry_["honggfuzz"] = {
        "honggfuzz", ExtendedAlgorithmType::ADVANCED_MUTATION,
        {true, true, true, false, false, 2.3, 1.2, 0.72},
        {"havoc"}, {}, {}, {}
    };

    algorithm_registry_["energy_scheduler"] = {
        "energy_scheduler", ExtendedAlgorithmType::SEED_SCHEDULING,
        {false, true, false, true, true, 0.7, 0.4, 0.45},
        {"mopt_scheduler"}, {}, {}, {}
    };

    // Build compatibility matrix
    for (const auto& [name1, meta1] : algorithm_registry_) {
        for (const auto& [name2, meta2] : algorithm_registry_) {
            if (name1 == name2) continue;

            // Check explicit compatibility
            if (meta1.compatible_with.count(name2) || meta2.compatible_with.count(name1)) {
                compatibility_matrix_[name1].insert(name2);
                compatibility_matrix_[name2].insert(name1);
            }
            // Check explicit incompatibility
            else if (meta1.incompatible_with.count(name2) || meta2.incompatible_with.count(name1)) {
                // Don't add to compatibility matrix
            }
            // Default compatibility rules
            else {
                bool compatible = true;

                // Scheduling algorithms shouldn't parallelize with mutations
                if ((meta1.type == ExtendedAlgorithmType::SEED_SCHEDULING && meta2.type == ExtendedAlgorithmType::BASIC_MUTATION) ||
                    (meta2.type == ExtendedAlgorithmType::SEED_SCHEDULING && meta1.type == ExtendedAlgorithmType::BASIC_MUTATION)) {
                    compatible = false;
                }

                // Advanced mutations don't parallelize well with basic mutations
                if ((meta1.type == ExtendedAlgorithmType::ADVANCED_MUTATION && meta2.type == ExtendedAlgorithmType::BASIC_MUTATION) ||
                    (meta2.type == ExtendedAlgorithmType::ADVANCED_MUTATION && meta1.type == ExtendedAlgorithmType::BASIC_MUTATION)) {
                    compatible = false;
                }

                if (compatible) {
                    compatibility_matrix_[name1].insert(name2);
                    compatibility_matrix_[name2].insert(name1);
                }
            }
        }
    }
}

ExtendedAlgorithmType AlgorithmCombinationManager::getAlgorithmType(const std::string& algorithm_name) const {
    auto it = algorithm_registry_.find(algorithm_name);
    if (it != algorithm_registry_.end()) {
        return it->second.type;
    }
    return ExtendedAlgorithmType::UNKNOWN;
}

bool AlgorithmCombinationManager::areAlgorithmsCompatible(const std::string& algo1, const std::string& algo2) const {
    if (algo1 == algo2) return true;

    auto it = compatibility_matrix_.find(algo1);
    if (it != compatibility_matrix_.end()) {
        return it->second.count(algo2) > 0;
    }

    // Default to compatible if not in registry
    return true;
}

bool AlgorithmCombinationManager::isValidCombination(const EnhancedAlgorithmCombination& combo) const {
    // Empty combination is invalid
    if (combo.algorithm_names.empty()) {
        return false;
    }

    // Check parallel mode compatibility
    if (combo.combination_mode == "parallel") {
        for (size_t i = 0; i < combo.algorithm_names.size(); ++i) {
            for (size_t j = i + 1; j < combo.algorithm_names.size(); ++j) {
                if (!areAlgorithmsCompatible(combo.algorithm_names[i], combo.algorithm_names[j])) {
                    return false;
                }

                // Additional check: can both parallelize?
                auto it1 = algorithm_registry_.find(combo.algorithm_names[i]);
                auto it2 = algorithm_registry_.find(combo.algorithm_names[j]);
                if (it1 != algorithm_registry_.end() && it2 != algorithm_registry_.end()) {
                    if (!it1->second.capabilities.can_parallelize || !it2->second.capabilities.can_parallelize) {
                        return false;
                    }
                }
            }
        }
    }

    // Check sequential mode ordering
    if (combo.combination_mode == "sequential") {
        // Verify prerequisites are met
        for (size_t i = 0; i < combo.algorithm_names.size(); ++i) {
            auto it = algorithm_registry_.find(combo.algorithm_names[i]);
            if (it != algorithm_registry_.end()) {
                // Check if prerequisites appear before this algorithm
                for (const auto& prereq : it->second.prerequisites) {
                    auto prereq_pos = std::find(combo.algorithm_names.begin(),
                                               combo.algorithm_names.begin() + i,
                                               prereq);
                    if (prereq_pos == combo.algorithm_names.begin() + i) {
                        // Prerequisite not found before this algorithm
                        auto prereq_anywhere = std::find(combo.algorithm_names.begin(),
                                                        combo.algorithm_names.end(),
                                                        prereq);
                        if (prereq_anywhere != combo.algorithm_names.end()) {
                            // Prerequisite exists but in wrong order
                            return false;
                        }
                    }
                }
            }
        }
    }

    return true;
}

std::vector<std::string> AlgorithmCombinationManager::validateCombination(const EnhancedAlgorithmCombination& combo) const {
    std::vector<std::string> errors;

    if (combo.algorithm_names.empty()) {
        errors.push_back("Combination contains no algorithms");
        return errors;
    }

    // Validate each algorithm exists
    for (const auto& algo : combo.algorithm_names) {
        if (algorithm_registry_.find(algo) == algorithm_registry_.end()) {
            errors.push_back("Unknown algorithm: " + algo);
        }
    }

    // Check compatibility for parallel mode
    if (combo.combination_mode == "parallel") {
        for (size_t i = 0; i < combo.algorithm_names.size(); ++i) {
            for (size_t j = i + 1; j < combo.algorithm_names.size(); ++j) {
                if (!areAlgorithmsCompatible(combo.algorithm_names[i], combo.algorithm_names[j])) {
                    errors.push_back("Incompatible algorithms for parallel execution: " +
                                   combo.algorithm_names[i] + " and " + combo.algorithm_names[j]);
                }
            }
        }
    }

    // Check ordering for sequential mode
    if (combo.combination_mode == "sequential") {
        for (size_t i = 0; i < combo.algorithm_names.size(); ++i) {
            auto it = algorithm_registry_.find(combo.algorithm_names[i]);
            if (it != algorithm_registry_.end()) {
                for (const auto& prereq : it->second.prerequisites) {
                    auto prereq_pos = std::find(combo.algorithm_names.begin(),
                                               combo.algorithm_names.begin() + i,
                                               prereq);
                    if (prereq_pos == combo.algorithm_names.begin() + i) {
                        errors.push_back("Algorithm " + combo.algorithm_names[i] +
                                       " requires " + prereq + " to run first");
                    }
                }
            }
        }
    }

    return errors;
}

EnhancedAlgorithmCombination AlgorithmCombinationManager::optimizeCombination(const EnhancedAlgorithmCombination& combo) const {
    EnhancedAlgorithmCombination optimized = combo;

    // Reorder algorithms for efficiency in sequential mode
    if (combo.combination_mode == "sequential") {
        optimized.algorithm_names = reorderForEfficiency(combo.algorithm_names);
    }

    // Convert to pipeline mode if it makes sense
    if (combo.algorithm_names.size() >= 3) {
        bool has_preprocessing = false;
        bool has_mutation = false;
        bool has_postprocessing = false;

        for (const auto& algo : combo.algorithm_names) {
            auto type = getAlgorithmType(algo);
            if (type == ExtendedAlgorithmType::PREPROCESSING) has_preprocessing = true;
            if (type == ExtendedAlgorithmType::BASIC_MUTATION || type == ExtendedAlgorithmType::ADVANCED_MUTATION) has_mutation = true;
            if (type == ExtendedAlgorithmType::FEEDBACK_ANALYSIS || type == ExtendedAlgorithmType::POSTPROCESSING) has_postprocessing = true;
        }

        if (has_preprocessing && has_mutation && has_postprocessing) {
            optimized = buildPipeline(combo.algorithm_names);
        }
    }

    return optimized;
}

std::vector<std::string> AlgorithmCombinationManager::reorderForEfficiency(const std::vector<std::string>& algorithms) const {
    std::vector<std::string> reordered = algorithms;

    // Sort by type priority: Scheduling -> Preprocessing -> Mutation -> Feedback -> Postprocessing
    std::sort(reordered.begin(), reordered.end(), [this](const std::string& a, const std::string& b) {
        auto type_a = getAlgorithmType(a);
        auto type_b = getAlgorithmType(b);

        // Define type priority
        auto getPriority = [](ExtendedAlgorithmType type) {
            switch (type) {
                case ExtendedAlgorithmType::SEED_SCHEDULING: return 0;
                case ExtendedAlgorithmType::PREPROCESSING: return 1;
                case ExtendedAlgorithmType::BASIC_MUTATION: return 2;
                case ExtendedAlgorithmType::ADVANCED_MUTATION: return 3;
                case ExtendedAlgorithmType::OPTIMIZATION: return 4;
                case ExtendedAlgorithmType::FEEDBACK_ANALYSIS: return 5;
                case ExtendedAlgorithmType::POSTPROCESSING: return 6;
                default: return 7;
            }
        };

        return getPriority(type_a) < getPriority(type_b);
    });

    // Ensure prerequisites are satisfied
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < reordered.size(); ++i) {
            auto it = algorithm_registry_.find(reordered[i]);
            if (it != algorithm_registry_.end()) {
                for (const auto& prereq : it->second.prerequisites) {
                    auto prereq_pos = std::find(reordered.begin(), reordered.end(), prereq);
                    if (prereq_pos != reordered.end() && prereq_pos > reordered.begin() + i) {
                        // Move prerequisite before current algorithm
                        std::rotate(reordered.begin() + i, prereq_pos, prereq_pos + 1);
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) break;
        }
    }

    return reordered;
}

EnhancedAlgorithmCombination AlgorithmCombinationManager::buildPipeline(const std::vector<std::string>& algorithms) const {
    EnhancedAlgorithmCombination pipeline;
    pipeline.combination_mode = "pipeline";

    // Categorize algorithms by type
    std::vector<std::string> preprocessing;
    std::vector<std::string> mutations;
    std::vector<std::string> optimizations;
    std::vector<std::string> feedback;
    std::vector<std::string> postprocessing;

    for (const auto& algo : algorithms) {
        auto type = getAlgorithmType(algo);
        switch (type) {
            case ExtendedAlgorithmType::PREPROCESSING:
            case ExtendedAlgorithmType::SEED_SCHEDULING:
                preprocessing.push_back(algo);
                break;
            case ExtendedAlgorithmType::BASIC_MUTATION:
            case ExtendedAlgorithmType::ADVANCED_MUTATION:
                mutations.push_back(algo);
                break;
            case ExtendedAlgorithmType::OPTIMIZATION:
                optimizations.push_back(algo);
                break;
            case ExtendedAlgorithmType::FEEDBACK_ANALYSIS:
                feedback.push_back(algo);
                break;
            case ExtendedAlgorithmType::POSTPROCESSING:
                postprocessing.push_back(algo);
                break;
            default:
                mutations.push_back(algo); // Default to mutation
                break;
        }
    }

    // Build pipeline stages
    if (!preprocessing.empty()) {
        pipeline.pipeline_stages.push_back({"preprocessing", preprocessing, false});
    }
    if (!mutations.empty()) {
        pipeline.pipeline_stages.push_back({"mutation", mutations, mutations.size() > 1});
    }
    if (!optimizations.empty()) {
        pipeline.pipeline_stages.push_back({"optimization", optimizations, false});
    }
    if (!feedback.empty()) {
        pipeline.pipeline_stages.push_back({"feedback", feedback, true});
    }
    if (!postprocessing.empty()) {
        pipeline.pipeline_stages.push_back({"postprocessing", postprocessing, false});
    }

    // Collect all algorithms in order
    for (const auto& stage : pipeline.pipeline_stages) {
        for (const auto& algo : stage.algorithms) {
            pipeline.algorithm_names.push_back(algo);
        }
    }

    return pipeline;
}

void AlgorithmCombinationManager::recordCombinationPerformance(const std::string& combo_key,
                                                              double execution_time_ms,
                                                              bool found_new_coverage,
                                                              double reward) {
    auto& stats = combination_performance_[combo_key];
    stats.executions++;
    stats.avg_execution_time_ms = (stats.avg_execution_time_ms * (stats.executions - 1) + execution_time_ms) / stats.executions;
    if (found_new_coverage) {
        stats.coverage_improvement_rate = (stats.coverage_improvement_rate * (stats.executions - 1) + 1.0) / stats.executions;
    } else {
        stats.coverage_improvement_rate = (stats.coverage_improvement_rate * (stats.executions - 1)) / stats.executions;
    }
    stats.avg_reward = (stats.avg_reward * (stats.executions - 1) + reward) / stats.executions;
}

// =============================================================================
// CombinationRulesEngine Implementation
// =============================================================================

CombinationRulesEngine::CombinationRulesEngine() {
    initializeDefaultRules();
}

void CombinationRulesEngine::initializeDefaultRules() {
    // Rule: Scheduling algorithms must come first
    rules_.push_back({
        "scheduling_first",
        "Scheduling algorithms must be executed before mutations",
        [](const EnhancedAlgorithmCombination& combo) {
            if (combo.combination_mode != "sequential") return true;

            bool found_mutation = false;
            for (const auto& algo : combo.algorithm_names) {
                if (algo.find("scheduler") != std::string::npos) {
                    if (found_mutation) return false;  // Scheduler after mutation
                }
                if (algo.find("mutation") != std::string::npos ||
                    algo == "havoc" || algo == "bitflip" || algo == "arithmetic") {
                    found_mutation = true;
                }
            }
            return true;
        },
        [](EnhancedAlgorithmCombination& combo) {
            // Reorder to put schedulers first
            std::stable_partition(combo.algorithm_names.begin(), combo.algorithm_names.end(),
                                [](const std::string& algo) {
                                    return algo.find("scheduler") != std::string::npos;
                                });
        },
        100
    });

    // Rule: Feedback algorithms must come after mutations
    rules_.push_back({
        "feedback_after_mutation",
        "Feedback algorithms analyze mutation results",
        [](const EnhancedAlgorithmCombination& combo) {
            if (combo.combination_mode != "sequential") return true;

            bool found_feedback = false;
            for (auto it = combo.algorithm_names.rbegin(); it != combo.algorithm_names.rend(); ++it) {
                if (it->find("analyzer") != std::string::npos) {
                    found_feedback = true;
                }
                if (found_feedback && (it->find("mutation") != std::string::npos ||
                                      *it == "havoc" || *it == "bitflip")) {
                    return true;  // Found mutation before feedback (reverse iteration)
                }
            }
            return !found_feedback;  // No feedback or no mutation
        },
        [](EnhancedAlgorithmCombination& combo) {
            // Move feedback algorithms to the end
            std::stable_partition(combo.algorithm_names.begin(), combo.algorithm_names.end(),
                                [](const std::string& algo) {
                                    return algo.find("analyzer") == std::string::npos;
                                });
        },
        90
    });

    // Rule: Limit parallel algorithms to compatible ones
    rules_.push_back({
        "parallel_compatibility",
        "Only compatible algorithms can run in parallel",
        [](const EnhancedAlgorithmCombination& combo) {
            if (combo.combination_mode != "parallel") return true;

            // Check for incompatible parallel combinations
            for (const auto& algo : combo.algorithm_names) {
                if (algo.find("scheduler") != std::string::npos ||
                    algo.find("analyzer") != std::string::npos) {
                    return false;  // These shouldn't parallelize with mutations
                }
            }
            return true;
        },
        [](EnhancedAlgorithmCombination& combo) {
            // Convert to sequential if incompatible
            combo.combination_mode = "sequential";
        },
        80
    });

    // Rule: Limit combination size for performance
    rules_.push_back({
        "max_combination_size",
        "Limit combination to 5 algorithms for performance",
        [](const EnhancedAlgorithmCombination& combo) {
            return combo.algorithm_names.size() <= 5;
        },
        [](EnhancedAlgorithmCombination& combo) {
            // Keep only the most important algorithms
            if (combo.algorithm_names.size() > 5) {
                combo.algorithm_names.resize(5);
            }
        },
        50
    });
}

void CombinationRulesEngine::applyRules(EnhancedAlgorithmCombination& combo) const {
    // Sort rules by priority (higher first)
    std::vector<Rule> sorted_rules = rules_;
    std::sort(sorted_rules.begin(), sorted_rules.end(),
            [](const Rule& a, const Rule& b) { return a.priority > b.priority; });

    // Apply each rule
    for (const auto& rule : sorted_rules) {
        if (!rule.condition(combo)) {
            rule.action(combo);
        }
    }
}

std::vector<std::string> CombinationRulesEngine::checkViolations(const EnhancedAlgorithmCombination& combo) const {
    std::vector<std::string> violations;

    for (const auto& rule : rules_) {
        if (!rule.condition(combo)) {
            violations.push_back(rule.name + ": " + rule.description);
        }
    }

    return violations;
}

// =============================================================================
// CombinationUtils Implementation
// =============================================================================

namespace CombinationUtils {

std::vector<uint8_t> mergeDifferences(const std::vector<uint8_t>& original,
                                     const std::vector<uint8_t>& result1,
                                     const std::vector<uint8_t>& result2) {
    size_t max_size = std::max({original.size(), result1.size(), result2.size()});
    std::vector<uint8_t> merged(max_size);

    for (size_t i = 0; i < max_size; ++i) {
        uint8_t orig = (i < original.size()) ? original[i] : 0;
        uint8_t r1 = (i < result1.size()) ? result1[i] : orig;
        uint8_t r2 = (i < result2.size()) ? result2[i] : orig;

        // If both results changed the byte differently, prefer the one with larger change
        if (r1 != orig && r2 != orig) {
            int delta1 = std::abs(static_cast<int>(r1) - static_cast<int>(orig));
            int delta2 = std::abs(static_cast<int>(r2) - static_cast<int>(orig));
            merged[i] = (delta1 > delta2) ? r1 : r2;
        }
        // If only one changed it, use that change
        else if (r1 != orig) {
            merged[i] = r1;
        }
        else if (r2 != orig) {
            merged[i] = r2;
        }
        // If neither changed it, keep original
        else {
            merged[i] = orig;
        }
    }

    return merged;
}

std::vector<uint8_t> weightedAverage(const std::vector<uint8_t>& original,
                                    const std::vector<std::vector<uint8_t>>& results,
                                    const std::vector<double>& weights) {
    if (results.empty()) return original;

    // Normalize weights
    double total_weight = std::accumulate(weights.begin(), weights.end(), 0.0);
    if (total_weight == 0.0) total_weight = 1.0;

    size_t max_size = original.size();
    for (const auto& result : results) {
        max_size = std::max(max_size, result.size());
    }

    std::vector<uint8_t> averaged(max_size);

    for (size_t i = 0; i < max_size; ++i) {
        double weighted_sum = 0.0;
        double weight_sum = 0.0;

        for (size_t j = 0; j < results.size(); ++j) {
            if (i < results[j].size()) {
                double w = (j < weights.size()) ? weights[j] : 1.0;
                weighted_sum += results[j][i] * w;
                weight_sum += w;
            }
        }

        if (weight_sum > 0) {
            averaged[i] = static_cast<uint8_t>(std::round(weighted_sum / weight_sum));
        } else {
            averaged[i] = (i < original.size()) ? original[i] : 0;
        }
    }

    return averaged;
}

std::vector<uint8_t> votingMerge(const std::vector<uint8_t>& original,
                                const std::vector<std::vector<uint8_t>>& results) {
    if (results.empty()) return original;

    size_t max_size = original.size();
    for (const auto& result : results) {
        max_size = std::max(max_size, result.size());
    }

    std::vector<uint8_t> voted(max_size);

    for (size_t i = 0; i < max_size; ++i) {
        std::map<uint8_t, int> votes;

        // Count votes for each byte value
        for (const auto& result : results) {
            if (i < result.size()) {
                votes[result[i]]++;
            }
        }

        // Find the value with most votes
        uint8_t winner = (i < original.size()) ? original[i] : 0;
        int max_votes = 0;

        for (const auto& [value, count] : votes) {
            if (count > max_votes) {
                max_votes = count;
                winner = value;
            }
        }

        voted[i] = winner;
    }

    return voted;
}

double calculateDiversity(const std::vector<uint8_t>& input1,
                        const std::vector<uint8_t>& input2) {
    size_t max_size = std::max(input1.size(), input2.size());
    if (max_size == 0) return 0.0;

    size_t differences = 0;
    for (size_t i = 0; i < max_size; ++i) {
        uint8_t b1 = (i < input1.size()) ? input1[i] : 0;
        uint8_t b2 = (i < input2.size()) ? input2[i] : 0;
        if (b1 != b2) {
            differences++;
        }
    }

    return static_cast<double>(differences) / max_size;
}

size_t selectMostDiverse(const std::vector<uint8_t>& original,
                        const std::vector<std::vector<uint8_t>>& results) {
    if (results.empty()) return 0;

    double max_avg_diversity = 0.0;
    size_t most_diverse_index = 0;

    for (size_t i = 0; i < results.size(); ++i) {
        double total_diversity = 0.0;

        // Calculate diversity from original
        total_diversity += calculateDiversity(original, results[i]);

        // Calculate diversity from other results
        for (size_t j = 0; j < results.size(); ++j) {
            if (i != j) {
                total_diversity += calculateDiversity(results[i], results[j]);
            }
        }

        double avg_diversity = total_diversity / results.size();
        if (avg_diversity > max_avg_diversity) {
            max_avg_diversity = avg_diversity;
            most_diverse_index = i;
        }
    }

    return most_diverse_index;
}

} // namespace CombinationUtils

// Enhanced Algorithm Combination toString
std::string EnhancedAlgorithmCombination::toString() const {
    std::stringstream ss;
    ss << combination_mode << "[";
    for (size_t i = 0; i < algorithm_names.size(); ++i) {
        if (i > 0) ss << ",";
        ss << algorithm_names[i];
    }
    ss << "]";
    return ss.str();
}

// Additional methods for enhanced combination executor
bool AlgorithmCombinationManager::canParallelize(const std::vector<std::string>& algorithms) const {
    // Check if all algorithms can run in parallel
    for (size_t i = 0; i < algorithms.size(); ++i) {
        for (size_t j = i + 1; j < algorithms.size(); ++j) {
            // Check if algorithms are compatible for parallel execution
            auto it1 = compatibility_matrix_.find(algorithms[i]);
            if (it1 != compatibility_matrix_.end()) {
                if (it1->second.find(algorithms[j]) == it1->second.end()) {
                    return false;  // Not compatible
                }
            }

            // Check specific incompatibilities
            if ((algorithms[i].find("scheduler") != std::string::npos &&
                 algorithms[j].find("mutation") != std::string::npos) ||
                (algorithms[j].find("scheduler") != std::string::npos &&
                 algorithms[i].find("mutation") != std::string::npos)) {
                return false;
            }
        }
    }
    return true;
}

CombinationPerformanceStats
AlgorithmCombinationManager::getCombinationStats(const std::string& combination_name) const {
    auto it = combination_performance_.find(combination_name);
    if (it != combination_performance_.end()) {
        return it->second;
    }
    return CombinationPerformanceStats{};  // Return default stats
}

std::vector<uint8_t> AlgorithmCombinationManager::fuseResults(
    const std::vector<std::pair<std::string, std::vector<uint8_t>>>& results,
    const EnhancedAlgorithmCombination::FusionParams& params) const {

    if (results.empty()) {
        return std::vector<uint8_t>();
    }

    // Simple fusion strategy: combine results based on diversity
    std::vector<uint8_t> fused_result;

    // Start with the result that has the most diversity from others
    size_t best_idx = 0;
    double max_diversity = 0.0;

    for (size_t i = 0; i < results.size(); ++i) {
        double total_diversity = 0.0;
        for (size_t j = 0; j < results.size(); ++j) {
            if (i != j) {
                total_diversity += CombinationUtils::calculateDiversity(
                    results[i].second, results[j].second);
            }
        }
        if (total_diversity > max_diversity) {
            max_diversity = total_diversity;
            best_idx = i;
        }
    }

    fused_result = results[best_idx].second;

    // Apply fusion based on params.fusion_strategy
    if (params.merge_strategy == "interleave") {
        // Interleave bytes from different results
        size_t max_size = 0;
        for (const auto& [name, data] : results) {
            max_size = std::max(max_size, data.size());
        }

        fused_result.clear();
        fused_result.reserve(max_size);

        for (size_t i = 0; i < max_size; ++i) {
            // Round-robin selection from different results
            const auto& source = results[i % results.size()].second;
            if (i < source.size()) {
                fused_result.push_back(source[i]);
            }
        }
    } else if (params.merge_strategy == "concatenate") {
        // Concatenate results
        fused_result.clear();
        for (const auto& [name, data] : results) {
            fused_result.insert(fused_result.end(), data.begin(), data.end());
        }
        // Trim to reasonable size
        if (fused_result.size() > 1024 * 1024) {
            fused_result.resize(1024 * 1024);
        }
    }

    return fused_result;
}

std::string AlgorithmCombinationManager::selectAdaptiveAlgorithm(
    const EnhancedAlgorithmCombination& combo,
    const std::map<std::string, double>& avg_rewards) const {

    if (combo.algorithm_names.empty()) {
        return "";
    }

    // Thompson Sampling-like selection with exploration bonus
    double best_score = -1.0;
    std::string best_algo = combo.algorithm_names[0];

    for (const auto& algo : combo.algorithm_names) {
        double reward = 0.5;  // Default reward
        auto it = avg_rewards.find(algo);
        if (it != avg_rewards.end()) {
            reward = it->second;
        }

        // Add exploration bonus based on execution count
        auto stats_it = combination_performance_.find(algo);
        double exploration_bonus = 1.0;
        if (stats_it != combination_performance_.end()) {
            // Less executed algorithms get higher bonus
            exploration_bonus = 1.0 / (1.0 + std::log(1.0 + stats_it->second.executions));
        }

        double score = reward + 0.3 * exploration_bonus;

        if (score > best_score) {
            best_score = score;
            best_algo = algo;
        }
    }

    return best_algo;
}

} // namespace triofuzz