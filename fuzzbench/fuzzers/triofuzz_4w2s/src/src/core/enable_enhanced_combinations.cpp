// Quick integration patch to enable enhanced combination features

#include "../../include/core/engine.hpp"
#include "../../include/core/algorithm_combination_manager.hpp"
#include <iostream>

namespace triofuzz {

// External declaration of enhanced combination function
std::vector<uint8_t> applyEnhancedAlgorithmCombination(
    FuzzingEngine* engine,
    const std::vector<uint8_t>& input,
    const AlgorithmCombination& combination,
    ThreadLocalContext& local_context);

// Note: The integration is now done directly in fuzzing_engine.cpp
// This file only contains the injection function for adding enhanced modes

// Function to inject new combination modes into candidate generation
void injectEnhancedCombinations(std::vector<AlgorithmCombination>& candidates) {
    static bool inject_enhanced = std::getenv("triofuzz_INJECT_MODES") != nullptr;

    if (!inject_enhanced || candidates.empty()) {
        return;
    }

    // Get a sample of existing algorithms
    std::set<std::string> available_algos;
    for (const auto& combo : candidates) {
        for (const auto& algo : combo.algorithm_names) {
            available_algos.insert(algo);
        }
    }

    if (available_algos.size() < 3) return;

    // Add fusion mode combinations
    {
        AlgorithmCombination fusion_combo;
        auto it = available_algos.begin();
        fusion_combo.algorithm_names.push_back(*it++);
        fusion_combo.algorithm_names.push_back(*it++);
        fusion_combo.algorithm_names.push_back(*it);
        fusion_combo.combination_mode = "fusion";
        candidates.push_back(fusion_combo);
    }

    // Add pipeline mode combinations
    {
        AlgorithmCombination pipeline_combo;
        // Try to create a logical pipeline
        for (const auto& algo : available_algos) {
            if (algo.find("format") != std::string::npos ||
                algo.find("dictionary") != std::string::npos) {
                pipeline_combo.algorithm_names.push_back(algo);
                break;
            }
        }
        if (pipeline_combo.algorithm_names.empty()) {
            pipeline_combo.algorithm_names.push_back(*available_algos.begin());
        }

        for (const auto& algo : available_algos) {
            if (algo == "havoc" || algo == "bitflip" || algo.find("mutation") != std::string::npos) {
                pipeline_combo.algorithm_names.push_back(algo);
                break;
            }
        }

        for (const auto& algo : available_algos) {
            if (algo.find("analyzer") != std::string::npos) {
                pipeline_combo.algorithm_names.push_back(algo);
                break;
            }
        }

        if (pipeline_combo.algorithm_names.size() >= 2) {
            pipeline_combo.combination_mode = "pipeline";
            candidates.push_back(pipeline_combo);
        }
    }

    // Add adaptive mode combination
    {
        AlgorithmCombination adaptive_combo;
        int count = 0;
        for (const auto& algo : available_algos) {
            adaptive_combo.algorithm_names.push_back(algo);
            if (++count >= 4) break;
        }
        adaptive_combo.combination_mode = "adaptive";
        candidates.push_back(adaptive_combo);
    }

    // Log injection
    static bool logged = false;
    if (!logged) {
        std::cout << "[EnhancedCombinations] Injected fusion, pipeline, and adaptive modes" << std::endl;
        logged = true;
    }
}

} // namespace triofuzz