#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include <queue>
#include <cmath>
#include <random>
#include <sstream>

namespace triofuzz {

// Scheduling algorithm I/O types
using SchedulingInput = std::vector<Seed>;
using SchedulingOutput = Seed;

// Base class for seed scheduling algorithms
class SchedulingAlgorithm : public Algorithm<SchedulingInput, SchedulingOutput, SharedContext> {
protected:
    std::mt19937 random_gen_;
    
public:
    SchedulingAlgorithm() : random_gen_(std::random_device{}()) {}
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Scheduling;
        info.version = "1.0";
        return info;
    }
    
    void saveState(StateWriter& writer) const override {
        // Save RNG state
        std::ostringstream oss;
        oss << random_gen_;
        writer.writeString("random_gen_state", oss.str());
    }
    
    void loadState(StateReader& reader) override {
        // Load RNG state
        auto state = reader.readString("random_gen_state");
        if (state.has_value()) {
            std::istringstream iss(state.value());
            iss >> random_gen_;
        }
    }
};

// Energy scheduler (AFL-style) - archived
/* class EnergyScheduler : public SchedulingAlgorithm {
protected:
    std::map<size_t, double> seed_energy_; // Mapping from seed ID to energy
    double base_energy_ = 1.0;
    
    // Energy allocation parameters
    struct EnergyFactors {
        double execution_speed_factor = 1.0;
        double coverage_factor = 2.0;
        double depth_factor = 0.5;
        double rarity_factor = 3.0;
        double recency_factor = 0.8;
    } energy_factors_;
    
public:
    EnergyScheduler() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "energy_scheduler";
        info.provided_info = {InfoType::Energy};
        info.required_info = {InfoType::Coverage, InfoType::Performance};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override {
        return measureExecution([&]() {
            if (seeds.empty()) {
                throw std::runtime_error("No seeds available for scheduling");
            }
            
            // Compute energy for each seed
            std::vector<std::pair<size_t, double>> seed_energies;
            for (size_t i = 0; i < seeds.size(); ++i) {
                double energy = computeEnergy(seeds[i], ctx);
                seed_energies.emplace_back(i, energy);
            }
            
            // Select a seed probabilistically by energy
            size_t selected_idx = selectByEnergy(seed_energies);
            
            // Publish energy info to the context
            EnergyInfo energy_info;
            energy_info.current_energy = seed_energies[selected_idx].second;
            energy_info.base_energy = base_energy_;
            ctx.setEnergyInfo(energy_info);
            
            return seeds[selected_idx];
        });
    }
    
    // Set energy distribution
    void setEnergyDistribution(const std::map<size_t, double>& distribution) {
        seed_energy_ = distribution;
    }
    
    void updateParameters(const Parameters& params) override {
        SchedulingAlgorithm::updateParameters(params);
        
        auto base = params.get<double>("base_energy");
        if (base.has_value()) base_energy_ = base.value();
        
        // Update energy factors
        auto speed_factor = params.get<double>("execution_speed_factor");
        if (speed_factor.has_value()) energy_factors_.execution_speed_factor = speed_factor.value();
        
        auto coverage_factor = params.get<double>("coverage_factor");
        if (coverage_factor.has_value()) energy_factors_.coverage_factor = coverage_factor.value();
    }
    
    void saveState(StateWriter& writer) const override {
        SchedulingAlgorithm::saveState(writer);
        writer.writeDouble("base_energy", base_energy_);
        writer.writeDouble("execution_speed_factor", energy_factors_.execution_speed_factor);
        writer.writeDouble("coverage_factor", energy_factors_.coverage_factor);
        writer.writeDouble("depth_factor", energy_factors_.depth_factor);
        writer.writeDouble("rarity_factor", energy_factors_.rarity_factor);
        writer.writeDouble("recency_factor", energy_factors_.recency_factor);
    }
    
    void loadState(StateReader& reader) override {
        SchedulingAlgorithm::loadState(reader);
        auto base = reader.readDouble("base_energy");
        if (base.has_value()) base_energy_ = base.value();
        
        auto speed_factor = reader.readDouble("execution_speed_factor");
        if (speed_factor.has_value()) energy_factors_.execution_speed_factor = speed_factor.value();
        
        auto coverage_factor = reader.readDouble("coverage_factor");
        if (coverage_factor.has_value()) energy_factors_.coverage_factor = coverage_factor.value();
        
        auto depth_factor = reader.readDouble("depth_factor");
        if (depth_factor.has_value()) energy_factors_.depth_factor = depth_factor.value();
        
        auto rarity_factor = reader.readDouble("rarity_factor");
        if (rarity_factor.has_value()) energy_factors_.rarity_factor = rarity_factor.value();
        
        auto recency_factor = reader.readDouble("recency_factor");
        if (recency_factor.has_value()) energy_factors_.recency_factor = recency_factor.value();
    }
    
private:
    // Compute seed energy
    double computeEnergy(const Seed& seed, SharedContext& ctx) {
        double energy = base_energy_;
        
        // Execution speed factor
        if (seed.performance.execution_time_ms > 0) {
            double speed_bonus = 1000.0 / seed.performance.execution_time_ms;
            energy *= std::pow(speed_bonus, energy_factors_.execution_speed_factor);
        }
        
        // Coverage factor
        double coverage_bonus = 1.0 + seed.coverage.coverage_gain;
        energy *= std::pow(coverage_bonus, energy_factors_.coverage_factor);
        
        // Depth factor (higher generation -> lower energy)
        double depth_penalty = 1.0 / (1.0 + seed.generation * 0.1);
        energy *= std::pow(depth_penalty, energy_factors_.depth_factor);
        
        // Rare-edge factor
        if (!seed.coverage.rare_edges.empty()) {
            double rarity_bonus = 1.0 + seed.coverage.rare_edges.size() * 0.1;
            energy *= std::pow(rarity_bonus, energy_factors_.rarity_factor);
        }
        
        // Time decay factor
        auto age = std::chrono::system_clock::now() - seed.created_time;
        double age_minutes = std::chrono::duration<double, std::ratio<60>>(age).count();
        double recency_penalty = std::exp(-age_minutes / 60.0); // 1-hour half-life
        energy *= std::pow(recency_penalty, energy_factors_.recency_factor);
        
        return std::max(0.1, energy); // Minimum energy: 0.1
    }
    
    // Select a seed by energy
    size_t selectByEnergy(const std::vector<std::pair<size_t, double>>& seed_energies) {
        // Compute total energy
        double total_energy = 0.0;
        for (const auto& [idx, energy] : seed_energies) {
            total_energy += energy;
        }
        
        // Roulette-wheel selection
        std::uniform_real_distribution<double> dist(0.0, total_energy);
        double random_point = dist(random_gen_);
        
        double cumulative = 0.0;
        for (const auto& [idx, energy] : seed_energies) {
            cumulative += energy;
            if (random_point <= cumulative) {
                return idx;
            }
        }
        
        // Fallback to the last seed
        return seed_energies.back().first;
    }
}; */ // Archived

// Multi-armed bandit scheduler
class MABScheduler : public SchedulingAlgorithm {
private:
    // UCB parameters
    double exploration_constant_ = std::sqrt(2.0);
    
    // Seed statistics
    struct SeedStats {
        double total_reward = 0.0;
        size_t selection_count = 0;
        double average_reward = 0.0;
        std::deque<double> recent_rewards;
    };
    std::map<size_t, SeedStats> seed_stats_;
    
    size_t total_selections_ = 0;
    
public:
    MABScheduler() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "mab_scheduler";
        info.provided_info = {InfoType::Energy};
        info.required_info = {InfoType::Coverage};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override {
        return measureExecution([&]() {
            if (seeds.empty()) {
                throw std::runtime_error("No seeds available for scheduling");
            }
            
            // Compute UCB value for each seed
            std::vector<std::pair<size_t, double>> ucb_values;
            for (size_t i = 0; i < seeds.size(); ++i) {
                double ucb = computeUCB(i, seeds[i]);
                ucb_values.emplace_back(i, ucb);
            }
            
            // Select the seed with the highest UCB value
            auto best_it = std::max_element(ucb_values.begin(), ucb_values.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            
            size_t selected_idx = best_it->first;
            total_selections_++;
            seed_stats_[selected_idx].selection_count++;
            
            return seeds[selected_idx];
        });
    }
    
    // Update seed reward
    void updateReward(size_t seed_idx, double reward) {
        auto& stats = seed_stats_[seed_idx];
        stats.total_reward += reward;
        stats.average_reward = stats.total_reward / stats.selection_count;
        
        stats.recent_rewards.push_back(reward);
        if (stats.recent_rewards.size() > 10) {
            stats.recent_rewards.pop_front();
        }
    }
    
    void saveState(StateWriter& writer) const override {
        SchedulingAlgorithm::saveState(writer);
        writer.writeDouble("exploration_constant", exploration_constant_);
        writer.writeInt("total_selections", total_selections_);
        
        // Save seed statistics
        writer.writeInt("seed_stats_size", seed_stats_.size());
        for (const auto& [idx, stats] : seed_stats_) {
            std::string prefix = "seed_" + std::to_string(idx) + "_";
            writer.writeDouble(prefix + "total_reward", stats.total_reward);
            writer.writeInt(prefix + "selection_count", stats.selection_count);
            writer.writeDouble(prefix + "average_reward", stats.average_reward);
        }
    }
    
    void loadState(StateReader& reader) override {
        SchedulingAlgorithm::loadState(reader);
        auto exploration_const = reader.readDouble("exploration_constant");
        if (exploration_const.has_value()) exploration_constant_ = exploration_const.value();
        
        auto total_sel = reader.readInt("total_selections");
        if (total_sel.has_value()) total_selections_ = total_sel.value();
        
        // Load seed statistics
        auto stats_size = reader.readInt("seed_stats_size");
        if (stats_size.has_value()) {
            for (size_t i = 0; i < static_cast<size_t>(stats_size.value()); ++i) {
                std::string prefix = "seed_" + std::to_string(i) + "_";
                auto total_reward = reader.readDouble(prefix + "total_reward");
                auto selection_count = reader.readInt(prefix + "selection_count");
                auto average_reward = reader.readDouble(prefix + "average_reward");
                
                if (total_reward.has_value() && selection_count.has_value() && average_reward.has_value()) {
                    SeedStats stats;
                    stats.total_reward = total_reward.value();
                    stats.selection_count = selection_count.value();
                    stats.average_reward = average_reward.value();
                    seed_stats_[i] = stats;
                }
            }
        }
    }
    
private:
    // Compute UCB value
    double computeUCB(size_t seed_idx, const Seed& seed) {
        auto& stats = seed_stats_[seed_idx];
        
        if (stats.selection_count == 0) {
            return std::numeric_limits<double>::max(); // Prioritize untried seeds
        }
        
        // UCB = average reward + exploration term
        double exploitation = stats.average_reward;
        double exploration = exploration_constant_ * 
                           std::sqrt(std::log(total_selections_) / stats.selection_count);
        
        // Add some heuristic factors
        double heuristic_bonus = 0.0;
        
        // New coverage reward
        if (seed.coverage.hasNewCoverage()) {
            heuristic_bonus += 0.2;
        }
        
        // Rare-edge reward
        heuristic_bonus += seed.coverage.rare_edges.size() * 0.05;
        
        return exploitation + exploration + heuristic_bonus;
    }
};

// Reinforcement-learning scheduler (Q-learning)
class RLScheduler : public SchedulingAlgorithm {
private:
    // Q-table: state-action value function
    std::map<std::string, std::map<size_t, double>> q_table_;
    
    // Learning parameters
    double learning_rate_ = 0.1;
    double discount_factor_ = 0.9;
    double epsilon_ = 0.1; // ε-greedy exploration
    
    // State feature extractor
    std::string current_state_;
    
public:
    RLScheduler() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "rl_scheduler";
        info.provided_info = {InfoType::Energy};
        info.required_info = {InfoType::Coverage, InfoType::Performance};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override {
        return measureExecution([&]() {
            if (seeds.empty()) {
                throw std::runtime_error("No seeds available for scheduling");
            }
            
            // Extract current state
            current_state_ = extractState(ctx);
            
            // Choose action via ε-greedy policy
            size_t selected_idx;
            std::uniform_real_distribution<double> epsilon_dist(0.0, 1.0);
            
            if (epsilon_dist(random_gen_) < epsilon_) {
                // Explore: random selection
                std::uniform_int_distribution<size_t> rand_dist(0, seeds.size() - 1);
                selected_idx = rand_dist(random_gen_);
            } else {
                // Exploit: select the action with the highest Q-value
                selected_idx = selectBestAction(seeds);
            }
            
            return seeds[selected_idx];
        });
    }
    
    // Update Q-value
    void updateQValue(size_t action, double reward, const std::string& next_state) {
        auto& state_q = q_table_[current_state_];
        double old_q = state_q[action];
        
        // Compute max Q-value for the next state
        double max_next_q = 0.0;
        auto next_it = q_table_.find(next_state);
        if (next_it != q_table_.end()) {
            for (const auto& [act, q] : next_it->second) {
                max_next_q = std::max(max_next_q, q);
            }
        }
        
        // Q-learning update rule
        double new_q = old_q + learning_rate_ * (reward + discount_factor_ * max_next_q - old_q);
        state_q[action] = new_q;
    }
    
    void saveState(StateWriter& writer) const override {
        SchedulingAlgorithm::saveState(writer);
        writer.writeDouble("learning_rate", learning_rate_);
        writer.writeDouble("discount_factor", discount_factor_);
        writer.writeDouble("epsilon", epsilon_);
        writer.writeString("current_state", current_state_);
        
        // Save Q-table
        writer.writeInt("q_table_size", q_table_.size());
        size_t state_idx = 0;
        for (const auto& [state, actions] : q_table_) {
            writer.writeString("state_" + std::to_string(state_idx), state);
            writer.writeInt("state_" + std::to_string(state_idx) + "_actions_size", actions.size());
            
            for (const auto& [action, q_value] : actions) {
                std::string action_key = "state_" + std::to_string(state_idx) + "_action_" + std::to_string(action);
                writer.writeDouble(action_key, q_value);
            }
            state_idx++;
        }
    }
    
    void loadState(StateReader& reader) override {
        SchedulingAlgorithm::loadState(reader);
        
        auto lr = reader.readDouble("learning_rate");
        if (lr.has_value()) learning_rate_ = lr.value();
        
        auto df = reader.readDouble("discount_factor");
        if (df.has_value()) discount_factor_ = df.value();
        
        auto eps = reader.readDouble("epsilon");
        if (eps.has_value()) epsilon_ = eps.value();
        
        auto state = reader.readString("current_state");
        if (state.has_value()) current_state_ = state.value();
        
        // Load Q-table
        auto q_table_size = reader.readInt("q_table_size");
        if (q_table_size.has_value()) {
            q_table_.clear();
            for (size_t i = 0; i < static_cast<size_t>(q_table_size.value()); ++i) {
                auto state_str = reader.readString("state_" + std::to_string(i));
                auto actions_size = reader.readInt("state_" + std::to_string(i) + "_actions_size");
                
                if (state_str.has_value() && actions_size.has_value()) {
                    std::map<size_t, double> actions;
                    for (size_t j = 0; j < static_cast<size_t>(actions_size.value()); ++j) {
                        std::string action_key = "state_" + std::to_string(i) + "_action_" + std::to_string(j);
                        auto q_value = reader.readDouble(action_key);
                        if (q_value.has_value()) {
                            actions[j] = q_value.value();
                        }
                    }
                    q_table_[state_str.value()] = actions;
                }
            }
        }
    }
    
private:
    // Extract state features
    std::string extractState(SharedContext& ctx) {
        std::string state;
        
        // Coverage-based state
        auto coverage_info = ctx.getCoverageInfo();
        if (coverage_info.has_value()) {
            double coverage_pct = coverage_info->getCoveragePercentage();
            state += "cov:" + std::to_string(static_cast<int>(coverage_pct / 10) * 10) + ";";
            
            // Whether there is recent new coverage
            state += coverage_info->hasNewCoverage() ? "new:1;" : "new:0;";
        }
        
        // Performance-based state
        auto perf_info = ctx.getPerformanceInfo();
        if (perf_info.has_value()) {
            double exec_speed = perf_info->getExecPerSec();
            state += "speed:" + std::to_string(static_cast<int>(exec_speed / 100) * 100) + ";";
        }
        
        return state;
    }
    
    // Select the best action
    size_t selectBestAction(const SchedulingInput& seeds) {
        auto& state_q = q_table_[current_state_];
        
        size_t best_action = 0;
        double best_q = -std::numeric_limits<double>::infinity();
        
        for (size_t i = 0; i < seeds.size(); ++i) {
            double q = state_q[i];
            if (q > best_q) {
                best_q = q;
                best_action = i;
            }
        }
        
        return best_action;
    }
};

// Round-robin scheduler
class RoundRobinScheduler : public SchedulingAlgorithm {
private:
    size_t current_index_ = 0;
    
public:
    RoundRobinScheduler() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "round_robin";
        info.provided_info = {InfoType::Energy};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override {
        return measureExecution([&]() {
            if (seeds.empty()) {
                throw std::runtime_error("No seeds available for scheduling");
            }
            
            // Simple round robin
            size_t selected_idx = current_index_ % seeds.size();
            current_index_++;
            
            // Set base energy
            EnergyInfo energy_info;
            energy_info.current_energy = 1.0;
            energy_info.base_energy = 1.0;
            ctx.setEnergyInfo(energy_info);
            
            return seeds[selected_idx];
        });
    }
    
    void saveState(StateWriter& writer) const override {
        SchedulingAlgorithm::saveState(writer);
        writer.writeInt("current_index", current_index_);
    }
    
    void loadState(StateReader& reader) override {
        SchedulingAlgorithm::loadState(reader);
        auto idx = reader.readInt("current_index");
        if (idx.has_value()) {
            current_index_ = idx.value();
        }
    }
};

// Random scheduler
class RandomScheduler : public SchedulingAlgorithm {
public:
    RandomScheduler() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "random";
        info.provided_info = {InfoType::Energy};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override {
        return measureExecution([&]() {
            if (seeds.empty()) {
                throw std::runtime_error("No seeds available for scheduling");
            }
            
            // Random selection
            std::uniform_int_distribution<size_t> dist(0, seeds.size() - 1);
            size_t selected_idx = dist(random_gen_);
            
            // Set random energy
            EnergyInfo energy_info;
            std::uniform_real_distribution<double> energy_dist(0.5, 2.0);
            energy_info.current_energy = energy_dist(random_gen_);
            energy_info.base_energy = 1.0;
            ctx.setEnergyInfo(energy_info);
            
            return seeds[selected_idx];
        });
    }
    
    void saveState(StateWriter& writer) const override {
        SchedulingAlgorithm::saveState(writer);
        // RandomScheduler has no special state to save
    }
    
    void loadState(StateReader& reader) override {
        SchedulingAlgorithm::loadState(reader);
        // RandomScheduler has no special state to load
    }
};

// Coverage-guided scheduler
class CoverageGuidedScheduler : public SchedulingAlgorithm {
private:
    double coverage_weight_ = 0.7;
    double recency_weight_ = 0.3;
    
public:
    CoverageGuidedScheduler() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "coverage_guided";
        info.provided_info = {InfoType::Energy};
        info.required_info = {InfoType::Coverage};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override {
        return measureExecution([&]() {
            if (seeds.empty()) {
                throw std::runtime_error("No seeds available for scheduling");
            }
            
            // Compute a score for each seed
            std::vector<std::pair<size_t, double>> scores;
            
            for (size_t i = 0; i < seeds.size(); ++i) {
                double score = computeScore(seeds[i]);
                scores.emplace_back(i, score);
            }
            
            // Sort and prefer highest scores
            std::sort(scores.begin(), scores.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });
            
            // Softmax selection (not always the top one)
            size_t selected_idx = softmaxSelect(scores);
            
            return seeds[selected_idx];
        });
    }
    
    void saveState(StateWriter& writer) const override {
        SchedulingAlgorithm::saveState(writer);
        writer.writeDouble("coverage_weight", coverage_weight_);
        writer.writeDouble("recency_weight", recency_weight_);
    }
    
    void loadState(StateReader& reader) override {
        SchedulingAlgorithm::loadState(reader);
        auto coverage_weight = reader.readDouble("coverage_weight");
        if (coverage_weight.has_value()) coverage_weight_ = coverage_weight.value();
        
        auto recency_weight = reader.readDouble("recency_weight");
        if (recency_weight.has_value()) recency_weight_ = recency_weight.value();
    }
    
private:
        double computeScore(const Seed& seed) {
            double score = 0.0;
            
        // Coverage score
        double coverage_score = seed.coverage.coverage_gain * 100.0;
        coverage_score += seed.coverage.new_edges.size() * 10.0;
        coverage_score += seed.coverage.rare_edges.size() * 20.0;
        
        // Recency score (newer is better)
        auto age = std::chrono::system_clock::now() - seed.created_time;
        double age_hours = std::chrono::duration<double, std::ratio<3600>>(age).count();
        double recency_score = std::exp(-age_hours / 24.0) * 100.0; // 24-hour half-life
        
        score = coverage_weight_ * coverage_score + recency_weight_ * recency_score;
        
        return score;
    }
    
    size_t softmaxSelect(const std::vector<std::pair<size_t, double>>& scores) {
        std::vector<double> exp_scores;
        double sum = 0.0;
        
        // Compute softmax
        for (const auto& [idx, score] : scores) {
            double exp_score = std::exp(score / 100.0); // Temperature parameter: 100
            exp_scores.push_back(exp_score);
            sum += exp_score;
        }
        
        // Probabilistic selection
        std::uniform_real_distribution<double> dist(0.0, sum);
        double random_point = dist(random_gen_);
        
        double cumulative = 0.0;
        for (size_t i = 0; i < exp_scores.size(); ++i) {
            cumulative += exp_scores[i];
            if (random_point <= cumulative) {
                return scores[i].first;
            }
        }
        
        return scores.back().first;
    }
};

} // namespace triofuzz
