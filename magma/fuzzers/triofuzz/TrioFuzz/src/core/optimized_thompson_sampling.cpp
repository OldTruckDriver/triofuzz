#include "../../include/core/optimized_thompson_sampling.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>

namespace triofuzz {

OptimizedThompsonSampling::OptimizedThompsonSampling() {
    // Initialize random number generator with random device
    std::random_device rd;
    rng_.seed(rd());

    std::cout << "[SimplifiedThompsonSampling] Initialized (basic Beta distribution, no advanced features)" << std::endl;
}

OptimizedThompsonSampling::~OptimizedThompsonSampling() = default;

// API compatibility - these are no-ops in simplified version
void OptimizedThompsonSampling::setExplorationProbability(double) {}
void OptimizedThompsonSampling::setStatsSyncFrequency(size_t) {}
void OptimizedThompsonSampling::enableFastPath(bool) {}

AlgorithmCombination OptimizedThompsonSampling::selectNext() {
    selection_count_.fetch_add(1, std::memory_order_relaxed);

    if (combination_stats_.empty()) {
        // No combinations available, return default
        AlgorithmCombination default_combo;
        default_combo.algorithm_names = {"havoc"};
        default_combo.combination_mode = "sequential";
        return default_combo;
    }

    // Pure Thompson Sampling: sample from Beta distribution for each combination
    // Select the one with highest sampled value
    double best_sample = -1.0;
    size_t best_idx = 0;

    for (size_t i = 0; i < combination_stats_.size(); ++i) {
        const auto& stats = combination_stats_[i];

        // Sample from Beta(alpha, beta) using Gamma distribution method
        // Beta(a,b) = Gamma(a) / (Gamma(a) + Gamma(b))
        std::gamma_distribution<double> gamma_alpha(stats->alpha, 1.0);
        std::gamma_distribution<double> gamma_beta(stats->beta, 1.0);

        double sample_alpha = gamma_alpha(rng_);
        double sample_beta = gamma_beta(rng_);

        double sample = sample_alpha / (sample_alpha + sample_beta + 1e-10);

        if (sample > best_sample) {
            best_sample = sample;
            best_idx = i;
        }
    }

    return combinations_[best_idx];
}

void OptimizedThompsonSampling::updatePerformance(const AlgorithmCombination& combination, double reward) {
    // Find the matching combination by hash
    size_t combo_hash = combination.hash();

    for (size_t i = 0; i < combinations_.size(); ++i) {
        if (combinations_[i].hash() == combo_hash) {
            auto& stats = combination_stats_[i];
            stats->total_uses.fetch_add(1, std::memory_order_relaxed);

            // Simple binary reward update:
            // - reward > 0.5 (found new coverage) -> success, increment alpha
            // - reward <= 0.5 (no new coverage) -> failure, increment beta
            // This matches AFL++ TS's binary reward model
            if (reward > 0.5) {
                stats->successes.fetch_add(1, std::memory_order_relaxed);
                stats->alpha += 1.0;
            } else {
                stats->failures.fetch_add(1, std::memory_order_relaxed);
                stats->beta += 1.0;
            }
            break;
        }
    }
}

void OptimizedThompsonSampling::setCandidateCombinations(const std::vector<AlgorithmCombination>& candidates) {
    combinations_ = candidates;

    // Initialize statistics for each combination with uniform prior (alpha=1, beta=1)
    combination_stats_.clear();
    for (size_t i = 0; i < combinations_.size(); ++i) {
        combination_stats_.push_back(std::make_unique<CombinationStats>());
    }

    std::cout << "[SimplifiedThompsonSampling] Set " << combinations_.size()
              << " candidate combinations" << std::endl;

    // Show first few combinations as examples
    for (size_t i = 0; i < std::min(combinations_.size(), size_t(5)); ++i) {
        std::cout << "  [" << i << "] " << combinations_[i].toString() << std::endl;
    }
}

std::string OptimizedThompsonSampling::getCombinationKey(const AlgorithmCombination& combo) const {
    std::string key;
    for (const auto& algo : combo.algorithm_names) {
        if (!key.empty()) key += "+";
        key += algo;
    }
    return key;
}

void OptimizedThompsonSampling::printStats() const {
    std::cout << "\n=========================================" << std::endl;
    std::cout << "  SimplifiedThompsonSampling Statistics" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Total selections: " << selection_count_.load() << std::endl;
    std::cout << "Number of combinations: " << combinations_.size() << std::endl;

    // Show top 5 combinations by success rate
    std::vector<std::tuple<size_t, double, size_t>> combo_rates;
    for (size_t i = 0; i < combination_stats_.size(); ++i) {
        const auto& stats = combination_stats_[i];
        size_t total = stats->total_uses.load();
        if (total > 0) {
            double rate = static_cast<double>(stats->successes.load()) / total;
            combo_rates.emplace_back(i, rate, total);
        }
    }

    std::sort(combo_rates.begin(), combo_rates.end(),
              [](const auto& a, const auto& b) { return std::get<1>(a) > std::get<1>(b); });

    std::cout << "Top combinations by success rate:" << std::endl;
    for (size_t i = 0; i < std::min(combo_rates.size(), size_t(5)); ++i) {
        size_t idx = std::get<0>(combo_rates[i]);
        double rate = std::get<1>(combo_rates[i]);
        size_t total = std::get<2>(combo_rates[i]);
        std::cout << "  " << combinations_[idx].toString()
                  << " - rate: " << (rate * 100) << "%, uses: " << total << std::endl;
    }
    std::cout << "=========================================" << std::endl;
}

} // namespace triofuzz
