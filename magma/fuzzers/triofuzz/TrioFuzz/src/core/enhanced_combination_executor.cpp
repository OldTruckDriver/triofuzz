#include "../../include/core/engine.hpp"
#include "../../include/core/algorithm_combination_manager.hpp"
#include <future>
#include <deque>
#include <iostream>
#include <random>

namespace triofuzz {

// Enhanced version of applyAlgorithmCombination with all improvements
// This is a standalone implementation that can be integrated into FuzzingEngine
std::vector<uint8_t> applyEnhancedAlgorithmCombination(
    FuzzingEngine* engine,
    const std::vector<uint8_t>& input,
    const AlgorithmCombination& combination,
    ThreadLocalContext& local_context) {

    std::vector<uint8_t> result = input;

    // PERFORMANCE: Fast path for simple sequential combinations
    if (combination.combination_mode == "sequential" &&
        combination.algorithm_names.size() <= 2) {
        // Skip all validation and optimization for simple cases
        for (const auto& algorithm_name : combination.algorithm_names) {
            result = engine->applySingleAlgorithm(result, algorithm_name, local_context);
        }
        return result;
    }

    // Create enhanced combination manager (static for efficiency)
    static thread_local std::unique_ptr<AlgorithmCombinationManager> combo_manager =
        std::make_unique<AlgorithmCombinationManager>();
    static thread_local CombinationRulesEngine rules_engine;

    // PERFORMANCE: Cache for validated combinations
    static thread_local std::map<std::string, EnhancedAlgorithmCombination> validated_cache;
    static thread_local size_t cache_hits = 0;
    static thread_local size_t cache_misses = 0;

    try {
        // Convert to enhanced combination
        EnhancedAlgorithmCombination enhanced_combo;
        enhanced_combo.algorithm_names = combination.algorithm_names;
        enhanced_combo.combination_mode = combination.combination_mode;
        enhanced_combo.weights = combination.weights;

        // Check cache first
        std::string combo_key = combination.toString();
        auto cache_it = validated_cache.find(combo_key);

        if (cache_it != validated_cache.end()) {
            enhanced_combo = cache_it->second;
            cache_hits++;
        } else {
            cache_misses++;

            // Only validate and optimize complex combinations
            if (combination.combination_mode == "fusion" ||
                combination.combination_mode == "pipeline" ||
                combination.combination_mode == "adaptive") {

                // Lightweight validation
                auto violations = rules_engine.checkViolations(enhanced_combo);
                if (!violations.empty() && violations.size() > 2) {
                    rules_engine.applyRules(enhanced_combo);
                }

                // Skip heavy optimization for most cases
                if (combination.algorithm_names.size() > 4) {
                    enhanced_combo = combo_manager->optimizeCombination(enhanced_combo);
                }
            }

            // Cache the validated combination
            if (validated_cache.size() < 100) { // Limit cache size
                validated_cache[combo_key] = enhanced_combo;
            }
        }

        if (enhanced_combo.combination_mode == "parallel") {
            if (!enhanced_combo.algorithm_names.empty()) {
                static thread_local std::mt19937 gen(std::random_device{}());
                std::uniform_int_distribution<size_t> dist(
                    0, enhanced_combo.algorithm_names.size() - 1);
                const auto& selected = enhanced_combo.algorithm_names[dist(gen)];
                result = engine->applySingleAlgorithm(result, selected, local_context);
            }
        } else if (enhanced_combo.combination_mode == "weighted") {
            if (!enhanced_combo.algorithm_names.empty()) {
                double total_weight = 0.0;
                for (const auto& [algo, weight] : enhanced_combo.weights) {
                    total_weight += weight;
                }

                if (total_weight > 0.0) {
                    std::uniform_real_distribution<double> weight_dist(0.0, total_weight);
                    static thread_local std::mt19937 gen(std::random_device{}());
                    double random_value = weight_dist(gen);

                    double cumulative_weight = 0.0;
                    for (const auto& algorithm_name : enhanced_combo.algorithm_names) {
                        auto weight_it = enhanced_combo.weights.find(algorithm_name);
                        double weight = weight_it != enhanced_combo.weights.end() ? weight_it->second : 1.0;
                        cumulative_weight += weight;

                        if (random_value <= cumulative_weight) {
                            result = engine->applySingleAlgorithm(result, algorithm_name, local_context);
                            break;
                        }
                    }
                } else {
                    result = engine->applySingleAlgorithm(result, enhanced_combo.algorithm_names[0], local_context);
                }
            }

        } else {
            // Treat sequential/fusion/pipeline/adaptive/others as simple sequential execution
            for (const auto& algorithm_name : enhanced_combo.algorithm_names) {
                result = engine->applySingleAlgorithm(result, algorithm_name, local_context);
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to apply enhanced algorithm combination: " << e.what() << std::endl;
        // Fall back to basic mutation
        result = engine->applySingleAlgorithm(result, "havoc", local_context);
    }

    return result;
}

// Helper function to record adaptive mode rewards (standalone for now)
void recordAdaptiveReward(const std::string& algorithm_name, double reward) {
    static thread_local std::map<std::string, std::deque<double>> recent_rewards;
    const size_t window_size = 50;

    auto& rewards = recent_rewards[algorithm_name];
    rewards.push_back(reward);
    if (rewards.size() > window_size) {
        rewards.pop_front();
    }
}

} // namespace triofuzz
