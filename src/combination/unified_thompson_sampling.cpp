#include "../../include/combination/unified_thompson_sampling.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace triofuzz {

// Global instance for unified Thompson sampling
static std::unique_ptr<UnifiedThompsonSampling> g_unified_thompson_instance;
static std::once_flag g_unified_thompson_init_flag;

UnifiedThompsonSampling& getUnifiedThompsonSampling() {
    std::call_once(g_unified_thompson_init_flag, []() {
        g_unified_thompson_instance = std::make_unique<UnifiedThompsonSampling>();
    });
    return *g_unified_thompson_instance;
}

// Helper function to validate algorithm combination
bool validateAlgorithmCombination(const AlgorithmCombination& combo) {
    // Check if combination has at least one algorithm
    if (combo.algorithm_names.empty()) {
        return false;
    }

    // Check if combination mode is valid
    static const std::set<std::string> valid_modes = {
        "sequential", "parallel", "weighted", "adaptive"
    };

    if (valid_modes.find(combo.combination_mode) == valid_modes.end()) {
        return false;
    }

    return true;
}

// Helper function to format time duration
std::string formatDuration(std::chrono::seconds duration) {
    auto minutes = duration.count() / 60;
    auto seconds = duration.count() % 60;

    std::stringstream ss;
    if (minutes > 0) {
        ss << minutes << "m ";
    }
    ss << seconds << "s";
    return ss.str();
}

// Extension: Advanced combination creation strategies
AlgorithmCombination createAdvancedCombination(
    const std::vector<std::string>& available_algorithms,
    const std::string& strategy) {

    AlgorithmCombination combo;

    if (strategy == "complementary") {
        // Select algorithms that complement each other
        // e.g., one for exploration (havoc) and one for exploitation (bitflip)
        combo.algorithm_names = {"havoc", "bitflip", "splice"};
        combo.combination_mode = "weighted";
        combo.weights["havoc"] = 0.5;
        combo.weights["bitflip"] = 0.3;
        combo.weights["splice"] = 0.2;
    } else if (strategy == "coverage_focused") {
        // Focus on coverage-guided algorithms - 所有高级算法已归档
        combo.algorithm_names = {"havoc", "bitflip", "arithmetic"};
        combo.combination_mode = "sequential";
    } else if (strategy == "crash_focused") {
        // Focus on crash-finding algorithms - 所有高级算法已归档
        combo.algorithm_names = {"havoc", "bitflip", "magic_byte"};
        combo.combination_mode = "sequential";
    } else {
        // Default balanced approach
        combo.algorithm_names = {"havoc", "bitflip", "arithmetic"};
        combo.combination_mode = "sequential";
    }

    return combo;
}

// Extension: Performance-based combination adjustment
void adjustCombinationBasedOnPerformance(
    AlgorithmCombination& combo,
    const std::map<std::string, double>& algorithm_performance) {

    // Remove poorly performing algorithms
    auto it = combo.algorithm_names.begin();
    while (it != combo.algorithm_names.end()) {
        auto perf_it = algorithm_performance.find(*it);
        if (perf_it != algorithm_performance.end() && perf_it->second < 0.2) {
            it = combo.algorithm_names.erase(it);
        } else {
            ++it;
        }
    }

    // Adjust weights for weighted mode
    if (combo.combination_mode == "weighted") {
        double total_weight = 0.0;
        combo.weights.clear();

        for (const auto& algo : combo.algorithm_names) {
            auto perf_it = algorithm_performance.find(algo);
            double weight = perf_it != algorithm_performance.end() ?
                           perf_it->second : 0.5;
            combo.weights[algo] = weight;
            total_weight += weight;
        }

        // Normalize weights
        if (total_weight > 0) {
            for (auto& [algo, weight] : combo.weights) {
                weight /= total_weight;
            }
        }
    }
}

// Extension: Smart combination merger
AlgorithmCombination mergeCombinations(
    const AlgorithmCombination& combo1,
    const AlgorithmCombination& combo2,
    double weight1 = 0.5,
    double weight2 = 0.5) {

    AlgorithmCombination merged;

    // Merge algorithm lists, avoiding duplicates
    std::set<std::string> unique_algos;
    for (const auto& algo : combo1.algorithm_names) {
        unique_algos.insert(algo);
    }
    for (const auto& algo : combo2.algorithm_names) {
        unique_algos.insert(algo);
    }

    merged.algorithm_names.assign(unique_algos.begin(), unique_algos.end());

    // Determine combination mode
    if (combo1.combination_mode == combo2.combination_mode) {
        merged.combination_mode = combo1.combination_mode;
    } else {
        // Default to weighted when merging different modes
        merged.combination_mode = "weighted";
    }

    // Merge weights if applicable
    if (merged.combination_mode == "weighted") {
        for (const auto& algo : merged.algorithm_names) {
            double w1 = 0.0, w2 = 0.0;

            auto it1 = combo1.weights.find(algo);
            if (it1 != combo1.weights.end()) {
                w1 = it1->second;
            }

            auto it2 = combo2.weights.find(algo);
            if (it2 != combo2.weights.end()) {
                w2 = it2->second;
            }

            merged.weights[algo] = w1 * weight1 + w2 * weight2;
        }
    }

    return merged;
}

} // namespace triofuzz