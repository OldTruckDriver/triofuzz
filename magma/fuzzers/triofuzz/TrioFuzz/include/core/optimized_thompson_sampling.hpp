#pragma once

#include "engine.hpp"
#include <vector>
#include <random>
#include <atomic>
#include <memory>

namespace triofuzz {

// Simplified Thompson Sampling for triofuzz-Mini
// This version uses basic Beta distribution sampling without:
// - UCB bonus
// - Adaptive exploration rate
// - Geometric credit assignment
// - Synergy tracking
// - Sampling cache
// The simplification enables fair comparison with AFL++ TS to isolate
// architectural differences (three-tier vs monolithic).
class OptimizedThompsonSampling {
public:
    OptimizedThompsonSampling();
    ~OptimizedThompsonSampling();

    // Configuration (mostly unused in simplified version, kept for API compatibility)
    void setExplorationProbability(double prob);
    void setStatsSyncFrequency(size_t freq);
    void enableFastPath(bool enable);

    // Core functionality
    AlgorithmCombination selectNext();
    void updatePerformance(const AlgorithmCombination& combination, double reward);
    void setCandidateCombinations(const std::vector<AlgorithmCombination>& candidates);

    // Statistics
    void printStats() const;

private:
    struct CombinationStats {
        std::atomic<size_t> successes{0};
        std::atomic<size_t> failures{0};
        std::atomic<size_t> total_uses{0};
        double alpha = 1.0;  // Beta distribution parameter (prior + successes)
        double beta = 1.0;   // Beta distribution parameter (prior + failures)
    };

    // Algorithm combinations and their statistics
    std::vector<AlgorithmCombination> combinations_;
    std::vector<std::unique_ptr<CombinationStats>> combination_stats_;

    // Statistics counters
    std::atomic<size_t> selection_count_{0};

    // Random number generator
    std::mt19937 rng_;

    // Internal methods
    std::string getCombinationKey(const AlgorithmCombination& combo) const;
};

} // namespace triofuzz
