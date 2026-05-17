#pragma once

#include <string>
#include <unordered_map>

namespace triofuzz {

/**
 * Algorithm weight boost configuration.
 * Used to give new or specific algorithms a higher selection probability.
 */
class AlgorithmBoostConfig {
public:
    static std::unordered_map<std::string, double> getBoostWeights() {
        return {
            // Treat algorithms evenly and let Thompson Sampling learn.
            // Give only some basic algorithms a slight boost to ensure exploration.
            {"havoc", 1.1},                   // Slight boost as baseline
            {"bitflip", 1.1},                  // Basic mutation
            {"arithmetic", 1.0},               // Arithmetic mutation
            {"splice", 1.0},                   // Splice mutation
            {"deterministic", 1.0},            // Deterministic mutation

            // Keep advanced algorithms at normal weights; avoid over-biasing.
            {"runtime_dictionary", 1.2},      // Slight boost (reduced from 3.0)
            {"smart_format", 1.1},             // Slight boost
            {"adaptive_length", 1.1},         // Slight boost (reduced from 2.5)
            {"value_approximation", 1.1},     // Slight boost (reduced from 3.0)

            // AI/ML algorithms
            // {"neuzz", 1.0}, // archived
            {"fairfuzz", 1.0},
            {"libfuzzer", 1.0},
            // {"libfuzzer_structured", 1.0}, // archived - high overhead
            // {"angora_gradient_descent", 1.0}, // archived - high overhead
            // {"zest", 1.0}, // archived - high overhead

            // Analyzers and schedulers
            {"coverage_analyzer", 0.8},       // Lower analyzer weight
            {"crash_analyzer", 0.8},
            {"performance_analyzer", 0.8},
            {"energy_scheduler", 0.9},
            {"enhanced_energy_scheduler", 0.9}
        };
    }
    
    static double getAlgorithmBoost(const std::string& algorithm) {
        auto weights = getBoostWeights();
        auto it = weights.find(algorithm);
        return (it != weights.end()) ? it->second : 1.0;
    }
    
    // Exploration phase (first ~10 minutes): give new algorithms higher probability.
    static bool isExplorationPhase(size_t total_executions) {
        return total_executions < 100000;  // First 100k executions
    }
    
    static double getExplorationBoost(const std::string& algorithm, size_t total_executions) {
        if (!isExplorationPhase(total_executions)) {
            return 1.0;
        }

        // During exploration, give all algorithms a small boost to encourage diversity,
        // but do not bias toward any particular algorithm.
        if (total_executions < 10000) {
            // For the first 10k executions, all algorithms get a small exploration boost.
            return 1.1;
        }
        return 1.0;
    }
};

} // namespace triofuzz
