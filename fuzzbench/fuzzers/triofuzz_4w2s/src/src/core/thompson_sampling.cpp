#include "../../include/core/thompson_sampling.hpp"
#include "../../include/core/engine.hpp"  // For AlgorithmCombination definition
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace triofuzz {

// Initialize thread-local random number generator
thread_local std::mt19937 ThompsonSampling::rng_{std::random_device{}()};

AlgorithmCombination ThompsonSampling::selectCombination(const std::vector<std::string>& available_algorithms) {
    if (available_algorithms.empty()) {
        AlgorithmCombination default_combo;
        default_combo.algorithm_names = {"havoc"};
        default_combo.combination_mode = "sequential";
        return default_combo;
    }

    // Periodically decay old statistics
    static std::chrono::steady_clock::time_point last_decay = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::minutes>(now - last_decay).count() > 5) {
        decayOldStatistics();
        last_decay = now;
    }

    // Generate dynamic combinations
    std::vector<AlgorithmCombination> candidates = generateDynamicCombinations(available_algorithms);

    if (candidates.empty()) {
        AlgorithmCombination fallback;
        fallback.algorithm_names = {available_algorithms[0]};
        fallback.combination_mode = "sequential";
        return fallback;
    }

    // Score each combination using Thompson Sampling
    std::vector<std::pair<AlgorithmCombination, double>> scored_combinations;
    scored_combinations.reserve(candidates.size());

    // Debug output controlled by environment variable
    static bool verbose_thompson = std::getenv("triofuzz_VERBOSE_THOMPSON") != nullptr;

    for (const auto& combo : candidates) {
        double score = scoreCombination(combo);
        score = applyExplorationBonus(combo, score);
        scored_combinations.emplace_back(combo, score);

        if (verbose_thompson) {
            std::cout << "[Thompson] Combo: " << combo.toString()
                     << " Score: " << std::fixed << std::setprecision(3) << score << std::endl;
        }
    }

    // Sort by score and select the best
    std::sort(scored_combinations.begin(), scored_combinations.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Add some randomization to avoid always picking the top choice
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double selection_prob = dist(rng_);

    size_t selection_idx = 0;
    if (selection_prob < 0.7) {
        // 70% chance: pick the best
        selection_idx = 0;
    } else if (selection_prob < 0.9 && scored_combinations.size() > 1) {
        // 20% chance: pick second best
        selection_idx = 1;
    } else if (scored_combinations.size() > 2) {
        // 10% chance: pick from top 5
        selection_idx = std::min(static_cast<size_t>(dist(rng_) * 5),
                                scored_combinations.size() - 1);
    }

    const auto& selected = scored_combinations[selection_idx];

    if (verbose_thompson) {
        std::cout << "[Thompson] Selected: " << selected.first.toString()
                 << " with score " << selected.second << std::endl;
    }

    return selected.first;
}

static std::string buildCombinationKey(const AlgorithmCombination& combo) {
    std::vector<std::string> canonical = combo.algorithm_names;
    // Keep order for sequential/interleaved by preserving but use joined string with delimiter including order.
    // For canonical key, we sort a copy but also include original order signature to distinguish sequential combos.
    std::vector<std::string> sorted = canonical;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::string key = combo.scheduler_name.empty() ? "default" : combo.scheduler_name;
    key += ":" + combo.combination_mode + "[";
    for (size_t i = 0; i < sorted.size(); ++i) {
        if (i > 0) key += ",";
        key += sorted[i];
    }
    key += "]";
    key += ":order(";
    for (size_t i = 0; i < canonical.size(); ++i) {
        if (i > 0) key += ">";
        key += canonical[i];
    }
    key += ")";
    key += ":" + (combo.feedback_analyzer.empty() ? std::string("default") : combo.feedback_analyzer);
    return key;
}

void ThompsonSampling::updateStatistics(const AlgorithmCombination& combo,
                                       double reward, bool new_coverage, bool crashed, bool decoder_success) {
    // Make a local copy of algorithm names to avoid race conditions
    // This prevents heap-use-after-free when another thread modifies/moves the combo object
    std::vector<std::string> algorithm_names_copy = combo.algorithm_names;
    std::string combo_string = buildCombinationKey(combo);

    // Update individual algorithm statistics
    // Compute geometric credit shares to avoid over-crediting the last step only
    auto computeShares = [](size_t n, double decay) {
        std::vector<double> s(n, 0.0);
        if (n == 0) return s;
        double sum = 0.0;
        for (size_t i = 0; i < n; ++i) {
            size_t from_end = (n - 1 - i);
            double w = std::pow(decay, static_cast<double>(from_end));
            s[i] = w;
            sum += w;
        }
        if (sum > 0.0) for (auto& v : s) v /= sum;
        return s;
    };

    {
        std::unique_lock lock(params_mutex_);
        auto shares = computeShares(algorithm_names_copy.size(), 0.7);
        for (size_t i = 0; i < algorithm_names_copy.size(); ++i) {
            auto* params = getAlgorithmParams(algorithm_names_copy[i]);
            if (!params) continue;
            double algo_reward = (i < shares.size() ? shares[i] : 1.0) * reward;
            if (new_coverage) algo_reward += 0.2 * (i < shares.size() ? shares[i] : 1.0);
            params->update(std::min(1.0, algo_reward));
        }
    }

    // Update combination statistics
    {
        std::unique_lock lock(stats_mutex_);
        auto* stats = getCombinationStats(combo_string);
        if (stats) {
            stats->record(reward, new_coverage, crashed, decoder_success);
        }
    }

    // Update synergy matrix (adjacent pairs with weighted credit)
    if (algorithm_names_copy.size() >= 2) {
        std::unique_lock lock(synergy_mutex_);
        auto shares = [&](size_t n) {
            std::vector<double> s(n, 0.0);
            if (n == 0) return s;
            double sum = 0.0;
            for (size_t i = 0; i < n; ++i) {
                size_t from_end = (n - 1 - i);
                double w = std::pow(0.7, static_cast<double>(from_end));
                s[i] = w;
                sum += w;
            }
            if (sum > 0.0) for (auto& v : s) v /= sum;
            return s;
        }(algorithm_names_copy.size());

        for (size_t i = 0; i + 1 < algorithm_names_copy.size(); ++i) {
            auto key = std::make_pair(
                std::min(algorithm_names_copy[i], algorithm_names_copy[i + 1]),
                std::max(algorithm_names_copy[i], algorithm_names_copy[i + 1])
            );
            double pair_share = 0.5 * (shares[i] + shares[i + 1]);
            double alpha = 0.1;
            double current = synergy_matrix_[key];
            synergy_matrix_[key] = alpha * (reward * pair_share) + (1 - alpha) * current;
        }
    }
}

std::vector<AlgorithmCombination> ThompsonSampling::generateDynamicCombinations(
    const std::vector<std::string>& algorithms) {

    std::vector<AlgorithmCombination> combinations;

    if (algorithms.empty()) return combinations;

    // Single algorithm combinations (for baseline)
    for (const auto& algo : algorithms) {
        AlgorithmCombination combo;
        combo.algorithm_names = {algo};
        combo.combination_mode = "single";
        combinations.push_back(combo);
    }

    // Sample Beta parameters to get current algorithm rankings
    std::vector<std::pair<std::string, double>> algo_scores;
    {
        std::shared_lock lock(params_mutex_);
        for (const auto& algo : algorithms) {
            auto* params = getAlgorithmParams(algo);
            if (params) {
                double score = params->sample(rng_);
                algo_scores.emplace_back(algo, score);
            } else {
                // New algorithm gets exploration bonus
                algo_scores.emplace_back(algo, 0.5 + exploration_bonus_);
            }
        }
    }

    // Sort by sampled scores
    std::sort(algo_scores.begin(), algo_scores.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Generate combinations of different sizes
    for (size_t combo_size = min_algorithms_per_combo_;
         combo_size <= std::min(max_algorithms_per_combo_, algorithms.size());
         ++combo_size) {

        // Top-k combinations based on Thompson sampling
        AlgorithmCombination top_k_combo;
        for (size_t i = 0; i < combo_size && i < algo_scores.size(); ++i) {
            top_k_combo.algorithm_names.push_back(algo_scores[i].first);
        }
        top_k_combo.combination_mode = "parallel";
        combinations.push_back(top_k_combo);

        // Sequential version of the same
        AlgorithmCombination seq_combo = top_k_combo;
        seq_combo.combination_mode = "sequential";
        combinations.push_back(seq_combo);

        // Random exploration combinations
        if (algorithms.size() >= combo_size) {
            std::vector<std::string> shuffled = algorithms;
            std::shuffle(shuffled.begin(), shuffled.end(), rng_);

            AlgorithmCombination random_combo;
            random_combo.algorithm_names.assign(shuffled.begin(), shuffled.begin() + combo_size);
            random_combo.combination_mode = "interleaved";
            combinations.push_back(random_combo);
        }

        // Synergy-based combinations
        if (combo_size == 2) {
            std::shared_lock lock(synergy_mutex_);

            // Find high-synergy pairs
            std::vector<std::tuple<std::string, std::string, double>> synergy_pairs;
            for (size_t i = 0; i < algorithms.size(); ++i) {
                for (size_t j = i + 1; j < algorithms.size(); ++j) {
                    auto key = std::make_pair(
                        std::min(algorithms[i], algorithms[j]),
                        std::max(algorithms[i], algorithms[j])
                    );

                    double synergy = 0.5;  // Default
                    auto it = synergy_matrix_.find(key);
                    if (it != synergy_matrix_.end()) {
                        synergy = it->second;
                    }

                    synergy_pairs.emplace_back(algorithms[i], algorithms[j], synergy);
                }
            }

            // Sort by synergy
            std::sort(synergy_pairs.begin(), synergy_pairs.end(),
                     [](const auto& a, const auto& b) {
                         return std::get<2>(a) > std::get<2>(b);
                     });

            // Add top synergy pairs
            size_t synergy_combos = std::min(static_cast<size_t>(3), synergy_pairs.size());
            for (size_t i = 0; i < synergy_combos; ++i) {
                AlgorithmCombination synergy_combo;
                synergy_combo.algorithm_names = {
                    std::get<0>(synergy_pairs[i]),
                    std::get<1>(synergy_pairs[i])
                };
                synergy_combo.combination_mode = "cooperative";
                combinations.push_back(synergy_combo);
            }
        }
    }

    // Limit total combinations to prevent explosion
    if (combinations.size() > 50) {
        // Keep diverse set: some top, some random, some synergy-based
        std::shuffle(combinations.begin() + 20, combinations.end(), rng_);
        combinations.resize(50);
    }

    return combinations;
}

ThompsonSampling::BetaParams* ThompsonSampling::getAlgorithmParams(const std::string& algorithm) {
    auto it = algorithm_params_.find(algorithm);
    if (it != algorithm_params_.end()) {
        return it->second.get();
    }

    // Create new params if not exists
    algorithm_params_[algorithm] = std::make_unique<BetaParams>();
    return algorithm_params_[algorithm].get();
}

ThompsonSampling::CombinationStats* ThompsonSampling::getCombinationStats(const std::string& combo_key) {
    auto it = combination_stats_.find(combo_key);
    if (it != combination_stats_.end()) {
        return it->second.get();
    }

    // Create new stats if not exists
    combination_stats_[combo_key] = std::make_unique<CombinationStats>();
    return combination_stats_[combo_key].get();
}

double ThompsonSampling::calculateSynergy(const std::vector<std::string>& algorithms) {
    if (algorithms.size() < 2) return 0.0;

    std::shared_lock lock(synergy_mutex_);

    double total_synergy = 0.0;
    size_t pair_count = 0;

    for (size_t i = 0; i < algorithms.size(); ++i) {
        for (size_t j = i + 1; j < algorithms.size(); ++j) {
            auto key = std::make_pair(
                std::min(algorithms[i], algorithms[j]),
                std::max(algorithms[i], algorithms[j])
            );

            auto it = synergy_matrix_.find(key);
            if (it != synergy_matrix_.end()) {
                total_synergy += it->second;
            } else {
                total_synergy += 0.5;  // Neutral synergy for unknown pairs
            }
            pair_count++;
        }
    }

    return pair_count > 0 ? total_synergy / pair_count : 0.0;
}

double ThompsonSampling::scoreCombination(const AlgorithmCombination& combo) {
    double score = 0.0;

    // Make a local copy to avoid race conditions
    std::vector<std::string> algorithm_names_copy = combo.algorithm_names;
    std::string combination_mode_copy = combo.combination_mode;
    std::string combo_key = buildCombinationKey(combo);

    // Individual algorithm scores (Thompson sampling)
    {
        std::shared_lock lock(params_mutex_);
        for (const auto& algo : algorithm_names_copy) {
            auto* params = getAlgorithmParams(algo);
            if (params) {
                score += params->sample(rng_);
            } else {
                score += 0.5;  // Default score for new algorithms
            }
        }
    }

    // Normalize by number of algorithms
    if (!algorithm_names_copy.empty()) {
        score /= algorithm_names_copy.size();
    }

    // Add synergy bonus
    double synergy = calculateSynergy(algorithm_names_copy);
    score = score * (1.0 - synergy_weight_) + synergy * synergy_weight_;

    // Incorporate historical success / coverage rates
    double success_rate = 0.5;
    double coverage_rate = 0.0;
    {
        std::shared_lock lock(stats_mutex_);
        auto it = combination_stats_.find(combo_key);
        if (it != combination_stats_.end()) {
            success_rate = it->second->getSuccessRate();
            coverage_rate = it->second->getCoverageRate();
        }
    }

    // Penalize combinations that rarely succeed at decoding
    double success_multiplier = 0.6 + success_rate * 0.4; // between 0.6 and 1.0
    if (success_rate < 0.1) {
        success_multiplier *= 0.3;
    } else if (success_rate < 0.25) {
        success_multiplier *= 0.6;
    }

    score *= success_multiplier;
    score += coverage_rate * 0.1;  // reward consistent coverage contributions

    // Mode bonus
    if (combination_mode_copy == "parallel") {
        score *= 1.05;  // Small bonus for parallel execution
    } else if (combination_mode_copy == "cooperative") {
        score *= 1.1;   // Larger bonus for cooperative mode
    }

    return score;
}

double ThompsonSampling::applyExplorationBonus(const AlgorithmCombination& combo, double base_score) {
    // Make a local copy to avoid race conditions
    std::string combo_string = buildCombinationKey(combo);

    std::shared_lock lock(stats_mutex_);

    auto it = combination_stats_.find(combo_string);
    if (it == combination_stats_.end() || it->second->executions.load() < 10) {
        // Unexplored or under-explored combination
        return base_score + exploration_bonus_;
    }

    // Check recency - bonus for combinations not used recently
    auto now = std::chrono::steady_clock::now();
    auto minutes_since_use = std::chrono::duration_cast<std::chrono::minutes>(
        now - it->second->last_use).count();

    if (minutes_since_use > 10) {
        base_score += exploration_bonus_ * 0.5;
    }

    double success_rate = it->second->getSuccessRate();
    if (success_rate < 0.1 && it->second->executions.load() > 50) {
        base_score *= 0.3;
    } else if (success_rate < 0.25 && it->second->executions.load() > 50) {
        base_score *= 0.6;
    }

    return base_score;
}

void ThompsonSampling::decayOldStatistics() {
    const double decay_factor = 0.95;

    // Decay algorithm parameters
    {
        std::unique_lock lock(params_mutex_);
        for (auto& [algo, params] : algorithm_params_) {
            if (params) {
                double current_alpha = params->alpha.load();
                double current_beta = params->beta.load();

                // Move towards uniform prior
                params->alpha.store(current_alpha * decay_factor + 1.0 * (1 - decay_factor));
                params->beta.store(current_beta * decay_factor + 1.0 * (1 - decay_factor));
            }
        }
    }

    // Decay synergy matrix
    {
        std::unique_lock lock(synergy_mutex_);
        for (auto& [pair, synergy] : synergy_matrix_) {
            // Move towards neutral synergy
            synergy = synergy * decay_factor + 0.5 * (1 - decay_factor);
        }
    }
}

std::string ThompsonSampling::getPerformanceReport() const {
    std::stringstream report;
    report << "=== Thompson Sampling Performance Report ===\n\n";

    // Algorithm performance
    {
        std::shared_lock lock(params_mutex_);
        report << "Algorithm Performance (Beta Parameters):\n";

        std::vector<std::pair<std::string, double>> algo_means;
        for (const auto& [algo, params] : algorithm_params_) {
            if (params) {
                double mean = params->getMean();
                algo_means.emplace_back(algo, mean);
            }
        }

        // Sort by mean performance
        std::sort(algo_means.begin(), algo_means.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });

        for (const auto& [algo, mean] : algo_means) {
            auto* params = algorithm_params_.at(algo).get();
            report << "  " << std::left << std::setw(25) << algo
                  << " Mean: " << std::fixed << std::setprecision(3) << mean
                  << " (α=" << params->alpha.load()
                  << ", β=" << params->beta.load()
                  << ", uses=" << params->total_uses.load() << ")\n";
        }
    }

    report << "\nTop Performing Combinations:\n";
    {
        std::shared_lock lock(stats_mutex_);

        std::vector<std::pair<std::string, double>> combo_performance;
        for (const auto& [combo_key, stats] : combination_stats_) {
            if (stats && stats->executions.load() > 0) {
                double avg_reward = stats->getAverageReward();
                combo_performance.emplace_back(combo_key, avg_reward);
            }
        }

        // Sort by average reward
        std::sort(combo_performance.begin(), combo_performance.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });

        // Show top 10
        size_t count = 0;
        for (const auto& [combo, reward] : combo_performance) {
            if (count++ >= 10) break;

            auto* stats = combination_stats_.at(combo).get();
            report << "  " << combo << "\n"
                  << "    Avg Reward: " << std::fixed << std::setprecision(3) << reward
                  << ", Executions: " << stats->executions.load()
                  << ", Coverage Rate: " << std::setprecision(1)
                  << (stats->getCoverageRate() * 100) << "%\n";
        }
    }

    report << "\nHigh Synergy Algorithm Pairs:\n";
    {
        std::shared_lock lock(synergy_mutex_);

        std::vector<std::tuple<std::string, std::string, double>> synergy_pairs;
        for (const auto& [pair, synergy] : synergy_matrix_) {
            if (synergy > 0.6) {  // Only show high synergy pairs
                synergy_pairs.emplace_back(pair.first, pair.second, synergy);
            }
        }

        // Sort by synergy
        std::sort(synergy_pairs.begin(), synergy_pairs.end(),
                 [](const auto& a, const auto& b) {
                     return std::get<2>(a) > std::get<2>(b);
                 });

        size_t count = 0;
        for (const auto& [algo1, algo2, synergy] : synergy_pairs) {
            if (count++ >= 5) break;
            report << "  " << algo1 << " + " << algo2
                  << ": " << std::fixed << std::setprecision(3) << synergy << "\n";
        }
    }

    return report.str();
}

} // namespace triofuzz
