#pragma once

#include <vector>
#include <string>
#include <map>
#include <set>
#include <functional>
#include <memory>
#include "algorithm.hpp"

namespace triofuzz {

// Extended algorithm type classification (extends base AlgorithmType)
enum class ExtendedAlgorithmType {
    BASIC_MUTATION,     // Basic mutation algorithms (havoc, bitflip, etc.)
    ADVANCED_MUTATION,  // Advanced mutation (gradient_descent, neuzz, etc.)
    FEEDBACK_ANALYSIS, // Feedback analysis (coverage_analyzer, crash_analyzer)
    SEED_SCHEDULING,   // Seed scheduling (rare_edge_scheduler, mopt_scheduler)
    OPTIMIZATION,      // Optimization algorithms (pso, gradient)
    PREPROCESSING,     // Input preprocessing
    POSTPROCESSING,    // Output postprocessing
    UNKNOWN
};

// Algorithm capability flags
struct AlgorithmCapabilities {
    bool can_parallelize = true;      // Can run in parallel with others
    bool requires_context = false;     // Needs context information
    bool modifies_input = true;        // Actually changes the input
    bool is_stateful = false;         // Maintains internal state
    bool is_deterministic = false;    // Produces same output for same input

    // Performance characteristics
    double avg_execution_time_ms = 1.0;
    double memory_usage_mb = 1.0;
    double coverage_improvement_rate = 0.5;
};

// Enhanced algorithm metadata for combination management
struct EnhancedAlgorithmMetadata {
    std::string name;
    ExtendedAlgorithmType type;
    AlgorithmCapabilities capabilities;
    std::set<std::string> compatible_with;     // Explicitly compatible algorithms
    std::set<std::string> incompatible_with;   // Explicitly incompatible algorithms
    std::vector<std::string> prerequisites;     // Algorithms that should run before
    std::vector<std::string> successors;       // Algorithms that should run after
};

// Enhanced algorithm combination with more modes
struct EnhancedAlgorithmCombination {
    std::vector<std::string> algorithm_names;
    std::string combination_mode;  // sequential, parallel, weighted, fusion, pipeline, adaptive
    std::map<std::string, double> weights;

    // Pipeline stages for pipeline mode
    struct PipelineStage {
        std::string stage_name;
        std::vector<std::string> algorithms;
        bool parallel_within_stage = false;
    };
    std::vector<PipelineStage> pipeline_stages;

    // Fusion parameters
    struct FusionParams {
        enum FusionStrategy {
            MERGE_DIFFERENCES,   // Merge non-overlapping changes
            WEIGHTED_AVERAGE,    // Weight average of changes
            VOTING,             // Majority voting for each byte
            CASCADING          // Apply changes in cascade
        } strategy = MERGE_DIFFERENCES;

        std::string merge_strategy = "default";  // String representation for flexible fusion
        std::map<std::string, double> algorithm_weights;
    } fusion_params;

    // Adaptive parameters
    struct AdaptiveParams {
        bool enable_runtime_selection = true;
        double switch_threshold = 0.1;  // Switch algorithm if reward < threshold
        size_t evaluation_window = 100; // Executions before evaluating
    } adaptive_params;

    std::string toString() const;
};

// Performance tracking structure
struct CombinationPerformanceStats {
    size_t executions = 0;
    double avg_execution_time_ms = 0.0;
    double coverage_improvement_rate = 0.0;
    double avg_reward = 0.5;
};

// Algorithm Combination Manager
class AlgorithmCombinationManager {
private:
    std::map<std::string, EnhancedAlgorithmMetadata> algorithm_registry_;
    std::map<std::string, std::set<std::string>> compatibility_matrix_;
    std::map<std::string, ExtendedAlgorithmType> type_cache_;

    // Performance tracking
    std::map<std::string, CombinationPerformanceStats> combination_performance_;

    // Initialize default algorithm metadata
    void initializeAlgorithmMetadata();

    // Helper functions
    ExtendedAlgorithmType getAlgorithmType(const std::string& algorithm_name) const;
    bool areAlgorithmsCompatible(const std::string& algo1, const std::string& algo2) const;
    std::vector<std::string> getPreprocessingAlgorithms(const EnhancedAlgorithmCombination& combo) const;
    std::vector<std::string> getMutationAlgorithms(const EnhancedAlgorithmCombination& combo) const;
    std::vector<std::string> getPostprocessingAlgorithms(const EnhancedAlgorithmCombination& combo) const;

public:
    AlgorithmCombinationManager();

    // Validation functions
    bool isValidCombination(const EnhancedAlgorithmCombination& combo) const;
    std::vector<std::string> validateCombination(const EnhancedAlgorithmCombination& combo) const;

    // Optimization functions
    EnhancedAlgorithmCombination optimizeCombination(const EnhancedAlgorithmCombination& combo) const;
    std::vector<std::string> reorderForEfficiency(const std::vector<std::string>& algorithms) const;

    // Combination generation
    std::vector<EnhancedAlgorithmCombination> generateIntelligentCombinations(
        const std::vector<std::string>& available_algorithms,
        const std::string& target_profile = "general") const;

    // Performance tracking
    void recordCombinationPerformance(const std::string& combo_key,
                                     double execution_time_ms,
                                     bool found_new_coverage,
                                     double reward);

    CombinationPerformanceStats getCombinationStats(const std::string& combo_key) const;

    // Algorithm information
    AlgorithmCapabilities getAlgorithmCapabilities(const std::string& algorithm_name) const;
    bool canParallelize(const std::vector<std::string>& algorithms) const;

    // Smart fusion functions
    std::vector<uint8_t> fuseResults(const std::vector<std::pair<std::string, std::vector<uint8_t>>>& results,
                                    const EnhancedAlgorithmCombination::FusionParams& params) const;

    // Pipeline construction
    EnhancedAlgorithmCombination buildPipeline(const std::vector<std::string>& algorithms) const;

    // Adaptive combination selection
    std::string selectAdaptiveAlgorithm(const EnhancedAlgorithmCombination& combo,
                                       const std::map<std::string, double>& recent_rewards) const;
};

// Compatibility Rules Engine
class CombinationRulesEngine {
public:
    struct Rule {
        std::string name;
        std::string description;
        std::function<bool(const EnhancedAlgorithmCombination&)> condition;
        std::function<void(EnhancedAlgorithmCombination&)> action;
        int priority = 0;  // Higher priority rules are evaluated first
    };

private:
    std::vector<Rule> rules_;

    void initializeDefaultRules();

public:
    CombinationRulesEngine();

    void addRule(const Rule& rule);
    void removeRule(const std::string& rule_name);

    // Apply all applicable rules to a combination
    void applyRules(EnhancedAlgorithmCombination& combo) const;

    // Check if combination violates any rules
    std::vector<std::string> checkViolations(const EnhancedAlgorithmCombination& combo) const;
};

// Utility functions for merging results
namespace CombinationUtils {
    // Merge two mutation results by taking non-overlapping changes
    std::vector<uint8_t> mergeDifferences(const std::vector<uint8_t>& original,
                                         const std::vector<uint8_t>& result1,
                                         const std::vector<uint8_t>& result2);

    // Weighted average of multiple results
    std::vector<uint8_t> weightedAverage(const std::vector<uint8_t>& original,
                                        const std::vector<std::vector<uint8_t>>& results,
                                        const std::vector<double>& weights);

    // Voting-based merge (majority wins for each byte)
    std::vector<uint8_t> votingMerge(const std::vector<uint8_t>& original,
                                    const std::vector<std::vector<uint8_t>>& results);

    // Calculate diversity score between two inputs
    double calculateDiversity(const std::vector<uint8_t>& input1,
                            const std::vector<uint8_t>& input2);

    // Find the most diverse result from a set
    size_t selectMostDiverse(const std::vector<uint8_t>& original,
                            const std::vector<std::vector<uint8_t>>& results);
}

} // namespace triofuzz