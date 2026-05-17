#pragma once

#include "combiner.hpp"
#include "../core/algorithm.hpp"
#include "../core/engine.hpp"
#include <random>
#include <map>
#include <cmath>
#include <deque>
#include <set>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <functional>
#include <iostream>


namespace triofuzz {

// Beta distribution
class BetaDistribution {
private:
    double alpha_;  // Successes + 1
    double beta_;   // Failures + 1
    std::mt19937 gen_;
    
public:
    BetaDistribution(double alpha = 1.0, double beta = 1.0)
        : alpha_(alpha), beta_(beta), gen_(std::random_device{}()) {}
    
    // Sample
    double sample() {
        std::gamma_distribution<double> gamma_alpha(alpha_, 1.0);
        std::gamma_distribution<double> gamma_beta(beta_, 1.0);
        
        double x = gamma_alpha(gen_);
        double y = gamma_beta(gen_);
        
        return x / (x + y);
    }
    
    // Update parameters
    void update(bool success, double weight = 1.0) {
        if (success) {
            alpha_ += weight;
        } else {
            beta_ += weight;
        }
    }
    
    // Get mean
    double getMean() const {
        return alpha_ / (alpha_ + beta_);
    }
    
    // Get variance
    double getVariance() const {
        double n = alpha_ + beta_;
        return (alpha_ * beta_) / (n * n * (n + 1));
    }
    
    // Get confidence interval
    std::pair<double, double> getConfidenceInterval(double confidence = 0.95) const {
        // Normal approximation
        double mean = getMean();
        double std_dev = std::sqrt(getVariance());
        double z = 1.96; // 95% confidence
        
        return {
            std::max(0.0, mean - z * std_dev),
            std::min(1.0, mean + z * std_dev)
        };
    }
    
    double getAlpha() const { return alpha_; }
    double getBeta() const { return beta_; }
};

// Thompson sampling strategy
class ThompsonSamplingStrategy : public CombinationStrategy {
protected:  // Changed to protected for derived class access
    // Beta distribution per algorithm combination
    std::map<std::string, BetaDistribution> distributions_;

    // Combination history
    struct CombinationHistory {
        size_t total_uses = 0;
        size_t successes = 0;
        double total_reward = 0.0;
        double best_reward = 0.0;
        std::chrono::steady_clock::time_point last_used;
        std::chrono::steady_clock::time_point last_contribution_time;  // Time of last contribution
    };
    std::map<std::string, CombinationHistory> history_;

    // Exploration parameters
    double exploration_rate_ = 0.05;  // Lower initial exploration rate
    double decay_factor_ = 0.995;
    size_t min_samples_ = 50;  // Increase minimum sample count

    // Batch execution parameters - optimization: reduce batch size for faster feedback
    mutable size_t current_batch_count_ = 0;  // Executions in current batch
    mutable size_t current_batch_size_ = 500;  // Current batch size - reduced from 10000 to 500
    std::string current_combination_;  // Combination currently being executed
    std::chrono::steady_clock::time_point batch_start_time_;  // Batch start time
    std::chrono::seconds min_execution_time_{2};  // Minimum execution time - reduced from 10s to 2s
    double batch_initial_coverage_ = 0.0;  // Coverage at batch start

    // Added: adaptive batch parameters
    mutable size_t consecutive_no_coverage_ = 0;  // Consecutive runs with no coverage increase
    mutable double last_coverage_percentage_ = 0.0;  // Previous coverage percentage
    mutable size_t min_batch_size_ = 100;  // Minimum batch size
    mutable size_t max_batch_size_ = 5000;  // Maximum batch size - capped at 5000 (was unlimited)

    // Reward calculation weights
    struct RewardWeights {
        double coverage_weight = 0.4;
        double crash_weight = 0.3;
        double speed_weight = 0.2;
        double diversity_weight = 0.1;
    } reward_weights_;

    // Reward threshold for success/failure determination
    double reward_threshold_ = 0.5;
    
public:
    ThompsonSamplingStrategy() = default;
    
    // Select the next algorithm combination (supports batch execution)
    AlgorithmCombination selectNext() {
        // Check whether we're still in the current batch
        if (shouldContinueCurrentBatch()) {
            // Keep using the current combination
            current_batch_count_++;
            return parseCombinationName(current_combination_);
        }

        // Batch ended; select a new combination
        std::vector<std::pair<std::string, double>> candidates;

        // Sample for each known combination
        for (auto& [combo_name, dist] : distributions_) {
            // Cooldown check: penalize recently used combinations
            auto& hist = history_[combo_name];
            auto time_since_last_use = std::chrono::steady_clock::now() - hist.last_used;

            double sampled_value = dist.sample();

            // Apply exploration bonus
            if (hist.total_uses < min_samples_) {
                sampled_value += exploration_rate_;
            }

            // Apply cooldown penalty (if used within the last 30 seconds)
            if (time_since_last_use < std::chrono::seconds(30) && combo_name == current_combination_) {
                sampled_value *= 0.7;  // Reduce probability by 30%
            }

            candidates.emplace_back(combo_name, sampled_value);
        }

        // If there are no candidates, return the default combination
        if (candidates.empty()) {
            return createDefaultCombination();
        }

        // Choose the combination with the highest sampled value
        auto best_it = std::max_element(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });

        // Start a new batch
        startNewBatch(best_it->first);

        return parseCombinationName(best_it->first);
    }
    
    // Select an algorithm combination (context-aware)
    AlgorithmCombination selectWithContext(const SharedContext& context) {
        std::vector<std::pair<std::string, double>> candidates;
        
        // Get current state info
        auto coverage_info = context.getCoverageInfo();
        auto performance_info = context.getPerformanceInfo();
        
        for (auto& [combo_name, dist] : distributions_) {
            double sampled_value = dist.sample();
            
            // Adjust sampled value based on context
            if (coverage_info.has_value()) {
                // If coverage has recently stagnated, prefer exploring new combinations
                if (coverage_info->coverage_gain < 0.001) {
                    if (history_[combo_name].last_used > std::chrono::steady_clock::now() - std::chrono::minutes(5)) {
                        sampled_value *= 0.8; // Reduce probability of recently used combinations
                    }
                }
            }
            
            if (performance_info.has_value()) {
                // If performance is poor, prefer faster combinations
                if (performance_info->execution_time_ms > 100) {
                    double speed_factor = history_[combo_name].total_reward / 
                                        (history_[combo_name].total_uses + 1);
                    sampled_value *= (1.0 + speed_factor * reward_weights_.speed_weight);
                }
            }
            
            candidates.emplace_back(combo_name, sampled_value);
        }
        
        if (candidates.empty()) {
            return createDefaultCombination();
        }
        
        auto best_it = std::max_element(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        
        // Update last-used time
        history_[best_it->first].last_used = std::chrono::steady_clock::now();
        
        return parseCombinationName(best_it->first);
    }
    
    // Update reward
    void updateReward(const AlgorithmCombination& combo, double reward) {
        std::string combo_name = combo.toString();
        
        // Ensure the distribution exists
        if (distributions_.find(combo_name) == distributions_.end()) {
            distributions_[combo_name] = BetaDistribution(1.0, 1.0);
        }
        
        // Update history
        auto& hist = history_[combo_name];
        hist.total_uses++;
        hist.total_reward += reward;
        hist.best_reward = std::max(hist.best_reward, reward);
        
        // Convert reward into success/failure
        bool success = reward > computeAverageReward() * 0.8;
        if (success) {
            hist.successes++;
            hist.last_contribution_time = std::chrono::steady_clock::now();  // Record contribution time
        }
        
        // Update Beta distribution - higher update frequency
        static size_t update_counter = 0;
        if (++update_counter % 20 == 0) {  // Update distribution every 20 updates for faster learning
            distributions_[combo_name].update(success, std::min(1.0, reward));

            // Decay exploration rate, but more slowly
            if (update_counter % 5000 == 0) {  // Decay every 5000 updates
                exploration_rate_ *= decay_factor_;
                exploration_rate_ = std::max(0.01, exploration_rate_); // Keep at least 1% exploration
            }
        }
    }
    
    // Compute composite reward
    double computeReward(const ExecutionResult& result, const SharedContext& context) {
        double reward = 0.0;
        
        // Coverage reward
        if (result.coverage.hasNewCoverage()) {
            reward += reward_weights_.coverage_weight * result.coverage.coverage_gain;
            
            // Extra reward for rare edges
            reward += reward_weights_.coverage_weight * 0.5 * 
                     (result.coverage.rare_edges.size() / 100.0);
        }
        
        // Crash reward
        if (result.status == ExecutionResult::Status::Crash) {
            reward += reward_weights_.crash_weight;
            
            // Extra reward for unique crashes
            auto crash_hash = hashCrash(result);
            if (unique_crashes_.find(crash_hash) == unique_crashes_.end()) {
                unique_crashes_.insert(crash_hash);
                reward += reward_weights_.crash_weight * 0.5;
            }
        }
        
        // Execution speed reward
        double speed_reward = 1.0 / (result.performance.execution_time_ms + 1.0);
        reward += reward_weights_.speed_weight * speed_reward;
        
        // Diversity reward (based on differences from recent executions)
        double diversity_reward = computeDiversityReward(result);
        reward += reward_weights_.diversity_weight * diversity_reward;
        
        return std::min(1.0, reward); // Normalize to [0, 1]
    }
    
    // CombinationStrategy interface implementation
    CompositionMode selectMode(
        const std::vector<AlgorithmInfo>& algorithms,
        const SharedContext& context
    ) override {
        // Select composition mode based on algorithm types and count
        if (algorithms.size() == 1) {
            return CompositionMode::Sequential;
        }
        
        // Check dependencies between algorithms
        bool has_dependencies = checkDependencies(algorithms);
        
        if (has_dependencies) {
            return CompositionMode::Sequential; // Use sequential execution when dependencies exist
        }
        
        // Select based on performance info
        auto perf_info = context.getPerformanceInfo();
        if (perf_info.has_value() && perf_info->execution_time_ms > 50) {
            return CompositionMode::Parallel; // Try parallel execution when execution is slow
        }
        
        // Select based on algorithm types
        bool all_same_type = std::all_of(algorithms.begin(), algorithms.end(),
            [&](const auto& info) { return info.type == algorithms[0].type; });
        
        if (all_same_type) {
            return CompositionMode::Weighted; // Use weighted selection for same-type algorithms
        }
        
        return CompositionMode::Sequential; // Default to sequential execution
    }
    
    std::vector<double> computeWeights(
        const std::vector<AlgorithmInfo>& algorithms,
        const PerformanceMetrics& metrics
    ) override {
        std::vector<double> weights;
        
        for (const auto& algo_info : algorithms) {
            // Compute weights based on historical performance
            double weight = 1.0;
            
            auto it = algorithm_weights_.find(algo_info.name);
            if (it != algorithm_weights_.end()) {
                weight = it->second;
            }
            
            weights.push_back(weight);
        }
        
        // Normalize weights
        double sum = std::accumulate(weights.begin(), weights.end(), 0.0);
        if (sum > 0) {
            for (auto& w : weights) {
                w /= sum;
            }
        }
        
        return weights;
    }
    
    // Get statistics
    struct Statistics {
        std::map<std::string, double> combination_success_rates;
        std::map<std::string, size_t> combination_uses;
        std::map<std::string, double> combination_rewards;
        double overall_success_rate;
        size_t total_selections;
    };
    
    Statistics getStatistics() const {
        Statistics stats;
        stats.total_selections = 0;
        size_t total_successes = 0;
        
        for (const auto& [combo_name, dist] : distributions_) {
            stats.combination_success_rates[combo_name] = dist.getMean();
            
            if (history_.find(combo_name) != history_.end()) {
                const auto& hist = history_.at(combo_name);
                stats.combination_uses[combo_name] = hist.total_uses;
                stats.combination_rewards[combo_name] = 
                    hist.total_uses > 0 ? hist.total_reward / hist.total_uses : 0.0;
                
                stats.total_selections += hist.total_uses;
                total_successes += hist.successes;
            }
        }
        
        stats.overall_success_rate = stats.total_selections > 0 ? 
            static_cast<double>(total_successes) / stats.total_selections : 0.0;
        
        return stats;
    }
    
    // Reset statistics
    void reset() {
        distributions_.clear();
        history_.clear();
        unique_crashes_.clear();
        exploration_rate_ = 0.1;
    }

    // Virtual method for derived classes to override
    virtual AlgorithmCombination selectCombination() {
        return selectNext();
    }

    // Helper method to parse combo key to AlgorithmCombination
    AlgorithmCombination parseComboKey(const std::string& key) const {
        return parseCombinationName(key);
    }

    // Get current batch execution info
    struct BatchInfo {
        std::string combination_name;
        size_t executions;
        std::chrono::seconds elapsed_time;
        double coverage_gain;
    };

    BatchInfo getCurrentBatchInfo() const {
        BatchInfo info;
        info.combination_name = current_combination_;
        info.executions = current_batch_count_;
        info.elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - batch_start_time_);
        info.coverage_gain = 0.0;  // TODO: retrieve from context
        return info;
    }

private:
    std::set<size_t> unique_crashes_;
    std::map<std::string, double> algorithm_weights_;
    std::deque<ExecutionResult> recent_results_;
    static constexpr size_t MAX_RECENT_RESULTS = 100;
    
    // Create default combination
    AlgorithmCombination createDefaultCombination() {
        AlgorithmCombination combo;
        combo.algorithm_names = {"havoc", "bit_flip"};
        combo.combination_mode = "sequential";
        return combo;
    }
    
    // Parse combination name
    AlgorithmCombination parseCombinationName(const std::string& name) const {
        // Simplified implementation; real code may require more complex parsing.
        AlgorithmCombination combo;
        
        // Format: "mode[algo1,algo2,...]"
        size_t bracket_pos = name.find('[');
        if (bracket_pos != std::string::npos) {
            combo.combination_mode = name.substr(0, bracket_pos);
            
            size_t end_bracket = name.find(']');
            if (end_bracket != std::string::npos) {
                std::string algos = name.substr(bracket_pos + 1, end_bracket - bracket_pos - 1);
                
                // Split algorithm names
                size_t pos = 0;
                while (pos < algos.length()) {
                    size_t comma_pos = algos.find(',', pos);
                    if (comma_pos == std::string::npos) {
                        combo.algorithm_names.push_back(algos.substr(pos));
                        break;
                    } else {
                        combo.algorithm_names.push_back(algos.substr(pos, comma_pos - pos));
                        pos = comma_pos + 1;
                    }
                }
            }
        }
        
        return combo;
    }
    
    // Compute average reward
    double computeAverageReward() const {
        double total_reward = 0.0;
        size_t total_uses = 0;
        
        for (const auto& [_, hist] : history_) {
            total_reward += hist.total_reward;
            total_uses += hist.total_uses;
        }
        
        return total_uses > 0 ? total_reward / total_uses : 0.5;
    }
    
    // Compute crash hash
    size_t hashCrash(const ExecutionResult& result) const {
        std::hash<std::string> hasher;
        std::string crash_sig;
        
        for (const auto& info : result.crash_info) {
            crash_sig += info + "|";
        }
        
        return hasher(crash_sig);
    }
    
    // Compute diversity reward
    double computeDiversityReward(const ExecutionResult& result) {
        if (recent_results_.empty()) {
            recent_results_.push_back(result);
            return 1.0;
        }
        
        // Compute difference from recent results
        double total_diff = 0.0;
        size_t count = 0;
        
        for (const auto& recent : recent_results_) {
            // Coverage difference
            auto coverage_diff = (result.coverage.bitmap ^ recent.coverage.bitmap).count();
            total_diff += coverage_diff / static_cast<double>(CoverageInfo::MAP_SIZE);
            
            count++;
            if (count >= 10) break; // Only compare the most recent 10
        }
        
        // Maintain recent result queue
        recent_results_.push_back(result);
        if (recent_results_.size() > MAX_RECENT_RESULTS) {
            recent_results_.pop_front();
        }
        
        return count > 0 ? total_diff / count : 0.0;
    }
    
    // Check algorithm dependencies
    bool checkDependencies(const std::vector<AlgorithmInfo>& algorithms) const {
        // Check whether any algorithm requires info provided by another algorithm
        for (size_t i = 0; i < algorithms.size(); ++i) {
            for (size_t j = i + 1; j < algorithms.size(); ++j) {
                // Check whether i requires info provided by j
                for (const auto& req : algorithms[i].required_info) {
                    if (std::find(algorithms[j].provided_info.begin(),
                                algorithms[j].provided_info.end(), req) 
                        != algorithms[j].provided_info.end()) {
                        return true;
                    }
                }
                
                // Check whether j requires info provided by i
                for (const auto& req : algorithms[j].required_info) {
                    if (std::find(algorithms[i].provided_info.begin(),
                                algorithms[i].provided_info.end(), req) 
                        != algorithms[i].provided_info.end()) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    // Check whether we should continue the current batch (with early-exit optimization)
    bool shouldContinueCurrentBatch() {
        // If there is no current combination, return false.
        if (current_combination_.empty()) {
            return false;
        }

        auto elapsed = std::chrono::steady_clock::now() - batch_start_time_;
        auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);

        // Early exit: if there is no coverage growth for a long time, stop early.
        if (consecutive_no_coverage_ > 200 && elapsed_seconds > std::chrono::seconds(1)) {
            // No growth for 200 consecutive runs and already executed for >1s.
            return false;
        }

        // Check minimum execution time
        if (elapsed_seconds < min_execution_time_) {
            // If we've run enough times with no growth, we can still stop.
            if (current_batch_count_ > min_batch_size_ && consecutive_no_coverage_ > 100) {
                return false;
            }
            return true;  // Minimum execution time not reached; continue.
        }

        // Check batch execution count
        if (current_batch_count_ < current_batch_size_) {
            // If new coverage is still being produced (inertia mechanism)
            if (history_.count(current_combination_) > 0) {
                const auto& hist = history_.at(current_combination_);
                // Check whether there was recent success
                auto time_since_success = std::chrono::steady_clock::now() - hist.last_contribution_time;
                if (time_since_success < std::chrono::seconds(2)) {  // Reduced from 5s to 2s
                    // Contribution within the last 2 seconds; extend execution.
                    consecutive_no_coverage_ = 0;  // Reset counter
                    return true;
                }
            }
            return true;  // Batch size not reached; continue.
        }

        // Batch size reached; check whether to extend
        if (shouldExtendBatch()) {
            current_batch_size_ = std::min(max_batch_size_,
                static_cast<size_t>(current_batch_size_ * 1.2));  // Changed from 1.5 to 1.2 (gentler growth)
            return true;
        }

        return false;  // Batch ended
    }

    // Check whether the batch should be extended
    bool shouldExtendBatch() {
        if (history_.count(current_combination_) == 0) {
            return false;
        }

        const auto& hist = history_.at(current_combination_);

        // Extend batch if recent performance is particularly good
        double avg_reward = computeAverageReward();
        double recent_reward = hist.total_uses > 0 ?
            hist.total_reward / hist.total_uses : 0.0;

        if (recent_reward > avg_reward * 1.5) {
            return true;  // Excellent performance; extend
        }

        // If we've been running for a long time with no contribution, don't extend.
        if (current_batch_count_ > 30000) {
            return false;
        }

        return false;
    }

    // Start a new batch
    void startNewBatch(const std::string& combination) {
        current_combination_ = combination;
        current_batch_count_ = 0;
        batch_start_time_ = std::chrono::steady_clock::now();

        // Dynamically adjust batch size
        current_batch_size_ = calculateBatchSize(combination);

        // Update history
        if (history_.count(combination) > 0) {
            history_[combination].last_used = batch_start_time_;
        }

        std::cout << "[Thompson] Starting new batch: " << combination
                  << ", size: " << current_batch_size_
                  << ", min_time: " << min_execution_time_.count() << "s" << std::endl;
    }

    // Calculate batch size - optimization: adaptive batch sizing
    size_t calculateBatchSize(const std::string& combination) const {
        size_t base_batch = 500;  // Base batch size - reduced from 10000 to 500

        if (history_.count(combination) == 0) {
            // First time: give a moderate chance
            return base_batch * 2;  // 1000 executions
        }

        const auto& hist = history_.at(combination);
        double avg_reward = computeAverageReward();
        double combo_reward = hist.total_uses > 0 ?
            hist.total_reward / hist.total_uses : 0.0;

        // Adjust based on historical performance (finer-grained)
        if (combo_reward > avg_reward * 1.5) {
            return std::min(max_batch_size_, static_cast<size_t>(base_batch * 4));  // Excellent: 2000
        } else if (combo_reward > avg_reward * 1.2) {
            return static_cast<size_t>(base_batch * 2);  // Good: 1000
        } else if (combo_reward < avg_reward * 0.5) {
            return std::max(min_batch_size_, static_cast<size_t>(base_batch * 0.5));  // Poor: 250
        } else if (combo_reward < avg_reward * 0.8) {
            return static_cast<size_t>(base_batch * 0.8);  // Average: 400
        }

        return base_batch;  // Default: 500
    }
};

} // namespace triofuzz
