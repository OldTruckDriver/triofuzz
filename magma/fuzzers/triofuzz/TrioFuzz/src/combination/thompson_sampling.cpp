#include "../../include/combination/thompson_sampling.hpp"
#include "../../include/core/engine.hpp"
#include <algorithm>
#include <random>
#include <cmath>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace triofuzz {

// Enhanced Thompson Sampling for dynamic algorithm combination
class EnhancedThompsonSampling {
private:
    struct CombinationState {
        // Beta distribution parameters
        double alpha = 1.0;  // successes + 1
        double beta = 1.0;   // failures + 1
        
        // Performance metrics
        size_t total_uses = 0;
        double total_reward = 0.0;
        double best_reward = 0.0;
        double recent_reward = 0.0;  // Moving average of recent performance
        
        // Temporal information
        std::chrono::steady_clock::time_point last_used;
        std::chrono::steady_clock::time_point created_at;
        
        // Context-specific performance
        std::map<std::string, double> context_performance; // context -> avg_reward
        
        // Decay factor for old performance data
        double decay_factor = 0.95;
        
        void updateReward(double reward, const std::string& context = "") {
            total_uses++;
            total_reward += reward;
            best_reward = std::max(best_reward, reward);
            
            // Update recent reward with exponential moving average
            if (total_uses == 1) {
                recent_reward = reward;
            } else {
                recent_reward = 0.3 * reward + 0.7 * recent_reward;
            }
            
            // Update context-specific performance
            if (!context.empty()) {
                if (context_performance.find(context) == context_performance.end()) {
                    context_performance[context] = reward;
                } else {
                    context_performance[context] = 0.4 * reward + 0.6 * context_performance[context];
                }
            }
            
            // Update Beta distribution parameters with dampening to prevent over-convergence
            // Use a success threshold based on recent performance
            double success_threshold = std::max(0.5 * recent_reward, 0.1);

            // Stronger dampening factor to prevent over-exploitation
            double dampening = 1.0 / (1.0 + std::log(1.0 + total_uses * 0.3));

            // Additional dampening for frequently used combinations
            if (total_uses > 50) {
                dampening *= 0.5;  // Halve the learning rate after 50 uses
            }

            if (reward >= success_threshold) {
                // Weighted success with dampening
                alpha += dampening * reward / std::max(best_reward, 0.1);
            } else {
                // Weighted failure with dampening
                beta += dampening * (1.0 - reward / std::max(best_reward, 0.1));
            }

            // Lower confidence cap to encourage more exploration
            const double MAX_CONFIDENCE = 30.0;  // Reduced from 100.0
            if (alpha > MAX_CONFIDENCE) alpha = MAX_CONFIDENCE;
            if (beta > MAX_CONFIDENCE) beta = MAX_CONFIDENCE;
            
            last_used = std::chrono::steady_clock::now();
        }
        
        double getAverageReward() const {
            return total_uses > 0 ? total_reward / total_uses : 0.0;
        }
        
        double getSuccessRate() const {
            double total_trials = alpha + beta - 2.0;  // Subtract initial values
            return total_trials > 0 ? (alpha - 1.0) / total_trials : 0.5;
        }
        
        double getContextReward(const std::string& context) const {
            auto it = context_performance.find(context);
            return it != context_performance.end() ? it->second : getAverageReward();
        }
        
        // Time-based decay of old data
        void applyTimeDecay() {
            auto now = std::chrono::steady_clock::now();
            auto time_since_last_use = std::chrono::duration_cast<std::chrono::minutes>(now - last_used).count();
            
            if (time_since_last_use > 60) {  // 1 hour decay
                double decay = std::pow(decay_factor, time_since_last_use / 60.0);
                alpha = 1.0 + (alpha - 1.0) * decay;
                beta = 1.0 + (beta - 1.0) * decay;
                recent_reward *= decay;
            }
        }
    };
    
    std::map<std::string, CombinationState> combination_states_;
    std::mt19937 random_gen_;
    
    // Dynamic exploration parameters
    double base_epsilon_ = 0.25;  // Base exploration rate (increased from 0.18)
    double current_epsilon_ = 0.25;  // Current exploration rate (adaptive)
    double ucb_c_ = 2.0;      // UCB exploration constant
    double context_weight_ = 0.3;
    double novelty_bonus_ = 0.2;
    double diversity_bonus_ = 0.1;
    double time_exploration_bonus_ = 0.15;  // Bonus for long-unused combinations
    size_t total_selections_ = 0;  // Total number of selections made
    size_t stagnation_counter_ = 0;  // Counter for stagnation detection
    double last_coverage_percentage_ = 0.0;  // For stagnation detection
    
    // Algorithm type weights for intelligent combination
    std::map<std::string, double> algorithm_type_weights_ = {
        {"mutation", 1.0},
        {"feedback", 0.8},
        {"optimization", 0.6},
        {"instrumentation", 0.5}
    };
    
    // Recent performance tracking
    std::deque<std::pair<std::string, double>> recent_selections_;
    static constexpr size_t MAX_RECENT_HISTORY = 50;
    
public:
    EnhancedThompsonSampling() : random_gen_(std::random_device{}()) {}
    
    // Get current context string for context-aware selection
    std::string getCurrentContext(const SharedContext& global_context) {
        std::string context = "";
        
        auto coverage_info = global_context.getCoverageInfo();
        if (coverage_info.has_value()) {
            double coverage_percentage = coverage_info->bitmap.count() / (double)std::max(coverage_info->total_edges, static_cast<size_t>(1)) * 100.0;
            
            if (coverage_percentage < 10.0) context += "very_low_coverage,";
            else if (coverage_percentage < 30.0) context += "low_coverage,";
            else if (coverage_percentage < 60.0) context += "medium_coverage,";
            else if (coverage_percentage < 85.0) context += "high_coverage,";
            else context += "very_high_coverage,";
            
            if (coverage_info->coverage_gain < 0.001) context += "stagnant,";
            else if (coverage_info->coverage_gain > 0.01) context += "rapid_growth,";
            else context += "steady_growth,";
        }
        
        auto performance_info = global_context.getPerformanceInfo();
        if (performance_info.has_value()) {
            if (performance_info->execution_time_ms > 50) context += "slow_execution,";
            else context += "fast_execution,";
            
            if (performance_info->execution_time_ms < 1.0) context += "very_fast_execution,";
        }
        
        return context;
    }
    
    // Select algorithm combination using enhanced Thompson Sampling
    AlgorithmCombination selectCombination(const std::vector<AlgorithmCombination>& candidates,
                                         const SharedContext& global_context) {
        if (candidates.empty()) {
            AlgorithmCombination default_combo;
            default_combo.algorithm_names = {"havoc"};
            default_combo.combination_mode = "sequential";
            return default_combo;
        }

        total_selections_++;  // Increment total selection count

        // Adaptive epsilon: adjust based on stagnation
        auto coverage_info = global_context.getCoverageInfo();
        if (coverage_info.has_value()) {
            double current_coverage = coverage_info->bitmap.count() /
                                     (double)std::max(coverage_info->total_edges, static_cast<size_t>(1)) * 100.0;

            // Detect stagnation
            if (std::abs(current_coverage - last_coverage_percentage_) < 0.01) {  // Less than 0.01% progress
                stagnation_counter_++;
                if (stagnation_counter_ > 50) {  // After 50 selections with no progress (reduced from 100)
                    // Significantly increase exploration
                    current_epsilon_ = std::min(0.5, base_epsilon_ * 3.0);  // Increased from 0.35 and 2.0
                }
            } else {
                stagnation_counter_ = 0;
                // Gradually decrease epsilon when making progress
                current_epsilon_ = std::max(0.1, base_epsilon_ * (1.0 - 0.3 * current_coverage / 100.0));
            }
            last_coverage_percentage_ = current_coverage;
        }

        // Epsilon-greedy: With probability epsilon, select randomly
        std::uniform_real_distribution<double> uniform_dist(0.0, 1.0);
        if (uniform_dist(random_gen_) < current_epsilon_) {
            // Random exploration
            std::uniform_int_distribution<size_t> random_selection(0, candidates.size() - 1);
            size_t random_idx = random_selection(random_gen_);

            std::string selected_key = candidates[random_idx].toString();
            recent_selections_.emplace_back(selected_key, 0.0);
            if (recent_selections_.size() > MAX_RECENT_HISTORY) {
                recent_selections_.pop_front();
            }

            std::cout << "[Thompson Sampling] ε-greedy exploration (ε=" << std::fixed << std::setprecision(2)
                      << current_epsilon_ << "): " << selected_key << std::endl;
            return candidates[random_idx];
        }

        std::string current_context = getCurrentContext(global_context);

        // Apply time decay to all combinations
        for (auto& [combo_name, state] : combination_states_) {
            state.applyTimeDecay();
        }

        std::vector<std::pair<AlgorithmCombination, double>> scored_combinations;
        
        for (const auto& combo : candidates) {
            std::string combo_key = combo.toString();
            
            // Initialize new combinations
            if (combination_states_.find(combo_key) == combination_states_.end()) {
                combination_states_[combo_key] = CombinationState();
                combination_states_[combo_key].created_at = std::chrono::steady_clock::now();
            }
            
            auto& state = combination_states_[combo_key];

            // Thompson Sampling: sample from Beta distribution
            std::gamma_distribution<double> gamma_alpha(state.alpha, 1.0);
            std::gamma_distribution<double> gamma_beta(state.beta, 1.0);
            double x = gamma_alpha(random_gen_);
            double y = gamma_beta(random_gen_);
            double thompson_score = x / (x + y);

            // UCB (Upper Confidence Bound) exploration bonus
            double ucb_bonus = 0.0;
            if (state.total_uses > 0 && total_selections_ > 0) {
                ucb_bonus = ucb_c_ * std::sqrt(std::log(total_selections_) / state.total_uses);
            } else if (state.total_uses == 0) {
                ucb_bonus = ucb_c_;  // Maximum bonus for untried combinations
            }

            // Time-based exploration bonus for long-unused combinations
            double time_bonus = 0.0;
            if (state.total_uses > 0) {
                auto now = std::chrono::steady_clock::now();
                auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
                    now - state.last_used).count();

                // Bonus increases linearly with time not used (maxes at 300 seconds)
                if (time_since_last > 30) {
                    time_bonus = time_exploration_bonus_ * std::min(1.0, time_since_last / 300.0);
                }
            } else {
                // Untried combinations get maximum time bonus
                time_bonus = time_exploration_bonus_;
            }

            // Context-aware adjustment
            double context_bonus = 0.0;
            if (!current_context.empty()) {
                double context_reward = state.getContextReward(current_context);
                double global_avg = state.getAverageReward();
                if (context_reward > global_avg) {
                    context_bonus = context_weight_ * (context_reward - global_avg);
                }
            }

            // Enhanced novelty bonus for new or rarely used combinations
            double novelty_bonus = 0.0;
            if (state.total_uses == 0) {
                novelty_bonus = novelty_bonus_ * 1.5;  // 50% higher bonus for completely untried
            } else if (state.total_uses < 5) {
                novelty_bonus = novelty_bonus_ * (5 - state.total_uses) / 5.0;
            } else if (state.total_uses < 10) {
                novelty_bonus = novelty_bonus_ * 0.3 * (10 - state.total_uses) / 10.0;
            }

            // Diversity bonus - prefer combinations that haven't been used recently
            double diversity_bonus = 0.0;
            bool recently_used = false;
            int recent_count = 0;
            for (const auto& [recent_combo, _] : recent_selections_) {
                if (recent_combo == combo_key) {
                    recently_used = true;
                    recent_count++;
                }
            }

            if (!recently_used && recent_selections_.size() >= 5) {
                diversity_bonus = diversity_bonus_;
            } else if (recently_used && recent_count > 3) {
                // Penalty for overuse in recent history
                diversity_bonus = -0.1 * recent_count / recent_selections_.size();
            }

            // Combination complexity penalty (prefer simpler combinations when performance is similar)
            double complexity_penalty = 0.0;
            if (combo.algorithm_names.size() > 3) {
                complexity_penalty = 0.05 * (combo.algorithm_names.size() - 3);
            }

            // Algorithm type balance bonus
            double type_balance_bonus = calculateTypeBalanceBonus(combo);

            // Final score calculation with UCB and time bonuses
            double final_score = thompson_score + ucb_bonus + time_bonus + context_bonus +
                               novelty_bonus + diversity_bonus + type_balance_bonus - complexity_penalty;
            
            scored_combinations.emplace_back(combo, final_score);
        }
        
        // Select the combination with highest score
        auto best_combo = std::max_element(scored_combinations.begin(), scored_combinations.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        
        // Update recent selections history
        std::string selected_key = best_combo->first.toString();
        recent_selections_.emplace_back(selected_key, best_combo->second);
        if (recent_selections_.size() > MAX_RECENT_HISTORY) {
            recent_selections_.pop_front();
        }
        
        // Log selection information with details
        auto& selected_state = combination_states_[selected_key];
        std::cout << "[Thompson Sampling] Selected: " << selected_key
                  << " with score: " << std::fixed << std::setprecision(3) << best_combo->second;

        if (selected_state.total_uses == 0) {
            std::cout << " (NEW combination)";
        } else if (selected_state.total_uses < 5) {
            std::cout << " (uses: " << selected_state.total_uses << ", exploring)";
        } else {
            auto now = std::chrono::steady_clock::now();
            auto time_since = std::chrono::duration_cast<std::chrono::seconds>(
                now - selected_state.last_used).count();
            if (time_since > 60) {
                std::cout << " (uses: " << selected_state.total_uses
                         << ", not used for " << time_since << "s)";
            } else {
                std::cout << " (uses: " << selected_state.total_uses
                         << ", avg_reward: " << selected_state.getAverageReward() << ")";
            }
        }
        std::cout << std::endl;
        
        return best_combo->first;
    }
    
    // Update combination performance
    void updateCombinationPerformance(const AlgorithmCombination& combo, double reward, 
                                    const SharedContext& global_context) {
        std::string combo_key = combo.toString();
        std::string current_context = getCurrentContext(global_context);
        
        if (combination_states_.find(combo_key) == combination_states_.end()) {
            combination_states_[combo_key] = CombinationState();
        }
        
        combination_states_[combo_key].updateReward(reward, current_context);
        
        std::cout << "[THOMPSON] Updated " << combo_key 
                  << " with reward " << reward 
                  << " (total uses: " << combination_states_[combo_key].total_uses 
                  << ", success rate: " << combination_states_[combo_key].getSuccessRate() << ")"
                  << std::endl;
    }
    
    // Get statistics for all combinations
    std::map<std::string, std::map<std::string, double>> getStatistics() const {
        std::map<std::string, std::map<std::string, double>> stats;
        
        for (const auto& [combo_name, state] : combination_states_) {
            stats[combo_name] = {
                {"total_uses", static_cast<double>(state.total_uses)},
                {"average_reward", state.getAverageReward()},
                {"recent_reward", state.recent_reward},
                {"success_rate", state.getSuccessRate()},
                {"best_reward", state.best_reward},
                {"alpha", state.alpha},
                {"beta", state.beta}
            };
        }
        
        return stats;
    }
    
    // Reset learning data
    void reset() {
        combination_states_.clear();
        recent_selections_.clear();
    }
    
    // Get the best performing combinations
    std::vector<std::pair<std::string, double>> getTopCombinations(size_t count = 10) const {
        std::vector<std::pair<std::string, double>> combinations;
        
        for (const auto& [combo_name, state] : combination_states_) {
            if (state.total_uses > 0) {
                combinations.emplace_back(combo_name, state.getAverageReward());
            }
        }
        
        std::sort(combinations.begin(), combinations.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        if (combinations.size() > count) {
            combinations.resize(count);
        }
        
        return combinations;
    }
    
private:
    // Calculate bonus for balanced algorithm types in combination
    double calculateTypeBalanceBonus(const AlgorithmCombination& combo) {
        std::map<std::string, int> type_counts;
        bool has_cmplog = false;

        // Classify algorithms by type (simplified)
        for (const auto& algo_name : combo.algorithm_names) {
            if (algo_name == "cmplog") {
                has_cmplog = true;
                type_counts["constraint_solving"]++;
            } else if (algo_name.find("mutation") != std::string::npos ||
                algo_name == "havoc" || algo_name == "bitflip" || algo_name == "arithmetic" ||
                algo_name == "gradient_descent" || algo_name == "splice" || algo_name == "deterministic" ||
                algo_name == "smart_dictionary" || algo_name == "rare_branch") { // neuzz, zest, libfuzzer_structured已归档
                type_counts["mutation"]++;
            } else if (algo_name.find("analyzer") != std::string::npos ||
                      algo_name.find("feedback") != std::string::npos) {
                type_counts["feedback"]++;
            } else if (algo_name.find("pso") != std::string::npos ||
                      algo_name.find("optimizer") != std::string::npos) {
                type_counts["optimization"]++;
            }
        }
        
        // Calculate balance bonus
        double bonus = 0.0;
        if (type_counts.size() > 1) {  // Multi-type combination
            bonus += 0.05;

            // Extra bonus for having both mutation and feedback
            if (type_counts["mutation"] > 0 && type_counts["feedback"] > 0) {
                bonus += 0.05;
            }

            // Special bonus for CmpLog combinations - it works well with other mutations
            if (has_cmplog) {
                if (type_counts["mutation"] > 0) {
                    bonus += 0.08;  // CmpLog + mutation is very effective
                }
                if (combo.algorithm_names.size() == 2) {
                    bonus += 0.03;  // Prefer focused CmpLog combinations
                }
            }
        }

        return bonus;
    }

    // 更新组合的分布参数
    void updateDistribution(const std::string& combination_str, double reward) {
        auto& state = combination_states_[combination_str];
        std::string context = "recovery";  // 恢复场景的特殊上下文
        state.updateReward(reward, context);

        // 如果是显著成功，减少探索率以利用这个成功
        if (reward > 0.5) {
            current_epsilon_ = std::max(0.05, current_epsilon_ * 0.9);
        }
    }

    // 提升特定组合的探索权重
    void boostExplorationFor(const std::string& combination_str) {
        auto& state = combination_states_[combination_str];

        // 增加该组合的吸引力
        state.alpha += 2.0;  // 增加成功计数

        // 临时提高探索率以尝试类似组合
        current_epsilon_ = std::min(0.5, current_epsilon_ * 1.2);

        // 记录这是一个有潜力的组合
        if (recent_selections_.size() >= MAX_RECENT_HISTORY) {
            recent_selections_.pop_front();
        }
        recent_selections_.push_back({combination_str, 1.0});  // 高奖励标记
    }
};

// Global instance declaration
EnhancedThompsonSampling global_thompson_sampling;

// External access functions for the fuzzing engine
extern "C" {
    void updateCombinationPerformanceWrapper(const char* combo_str, double reward) {
        std::string combo_key(combo_str);
        
        // Parse combo string to AlgorithmCombination
        AlgorithmCombination combo;
        size_t bracket_pos = combo_key.find('[');
        if (bracket_pos != std::string::npos) {
            combo.combination_mode = combo_key.substr(0, bracket_pos);
            
            size_t end_bracket = combo_key.find(']');
            if (end_bracket != std::string::npos) {
                std::string algos = combo_key.substr(bracket_pos + 1, end_bracket - bracket_pos - 1);
                
                std::stringstream ss(algos);
                std::string algo;
                while (std::getline(ss, algo, ',')) {
                    if (!algo.empty()) {
                        combo.algorithm_names.push_back(algo);
                    }
                }
            }
        }
        
        if (combo.algorithm_names.empty()) {
            combo.algorithm_names.push_back(combo_key);
            combo.combination_mode = "sequential";
        }
        
        // Create a dummy SharedContext for now
        SharedContext dummy_context;
        global_thompson_sampling.updateCombinationPerformance(combo, reward, dummy_context);
    }
}

} // namespace triofuzz
