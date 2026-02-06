#pragma once

#include "../core/algorithm.hpp"
#include <vector>
#include <unordered_map>
#include <memory>
#include <cmath>
#include <random>
#include <deque>
#include <string>

namespace triofuzz {

// Input/output types for the multi-armed bandit algorithm
using MABInput = std::pair<size_t, double>;  // (selected_arm, reward)
using MABOutput = size_t;  // selected arm index

// Base class for Multi-Armed Bandit algorithms
class MultiArmedBandit : public Algorithm<MABInput, MABOutput, SharedContext> {
public:
    virtual ~MultiArmedBandit() = default;
    
    // Algorithm interface implementation
    MABOutput execute(const MABInput& input, SharedContext& context) override {
        // If input contains a reward update, process it
        if (input.first != static_cast<size_t>(-1)) {
            updateReward(input.first, input.second);
        }
        // Select next arm
        return selectArm();
    }
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Combination;  // MAB algorithms are used for combination selection
        info.name = "MultiArmedBandit";
        info.version = "1.0";
        info.description = "Base class for multi-armed bandit algorithms";
        return info;
    }
    
    PerformanceMetrics getMetrics() const override {
        return metrics_;
    }
    
    void updateParameters(const Parameters& params) override {
        // Default implementation - derived classes can override
    }
    
    Parameters getParameters() const override {
        return Parameters();
    }
    
    void saveState(StateWriter& writer) const override {
        writer.writeInt("num_arms", num_arms_);
        writer.writeInt("total_pulls", total_pulls_);
    }
    
    void loadState(StateReader& reader) override {
        auto num_arms = reader.readInt("num_arms");
        if (num_arms) num_arms_ = *num_arms;
        auto total_pulls = reader.readInt("total_pulls");
        if (total_pulls) total_pulls_ = *total_pulls;
    }
    
    void initialize() override {}
    void shutdown() override {}
    
    // Select an arm (algorithm combination)
    virtual size_t selectArm() = 0;
    
    // Update the reward for the selected arm
    virtual void updateReward(size_t arm, double reward) = 0;
    
    // Get the expected reward for an arm
    virtual double getExpectedReward(size_t arm) const = 0;
    
    // Reset the bandit (override from Algorithm base)
    void reset() override = 0;
    
    // Get statistics
    virtual std::string getStatistics() const = 0;
    
protected:
    size_t num_arms_;
    size_t total_pulls_ = 0;
    std::vector<size_t> arm_pulls_;
    std::vector<double> arm_rewards_;
    std::mt19937 rng_;
    PerformanceMetrics metrics_;
};

// Upper Confidence Bound (UCB) algorithm
class UCBBandit : public MultiArmedBandit {
public:
    explicit UCBBandit(size_t num_arms = 10, double exploration_constant = 2.0);
    
    // Override AlgorithmInfo for UCB
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Combination;
        info.name = "UCBBandit";
        info.version = "1.0";
        info.description = "Upper Confidence Bound multi-armed bandit algorithm";
        return info;
    }
    
    size_t selectArm() override;
    void updateReward(size_t arm, double reward) override;
    double getExpectedReward(size_t arm) const override;
    void reset() override;
    std::string getStatistics() const override;
    
    // UCB-specific methods
    double getUCBScore(size_t arm) const;
    void setExplorationConstant(double c) { exploration_constant_ = c; }
    
private:
    double exploration_constant_;
    std::vector<double> arm_averages_;
};

// UCB with contextual information
class ContextualUCB : public UCBBandit {
public:
    // Override AlgorithmInfo for ContextualUCB
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Combination;
        info.name = "ContextualUCB";
        info.version = "1.0";
        info.description = "Contextual Upper Confidence Bound algorithm";
        return info;
    }
    
    struct Context {
        double coverage_level;      // Current coverage percentage
        double discovery_rate;      // Recent discovery rate
        double execution_speed;     // Average execution speed
        size_t mutation_depth;      // Current mutation depth
        bool is_stagnant;          // Whether in stagnation
        
        std::vector<double> toVector() const {
            return {coverage_level, discovery_rate, execution_speed, 
                   static_cast<double>(mutation_depth), is_stagnant ? 1.0 : 0.0};
        }
    };
    
    explicit ContextualUCB(size_t num_arms = 10, size_t context_dim = 5);
    
    // Override base class virtual methods
    size_t selectArm() override;
    void updateReward(size_t arm, double reward) override;
    
    // Contextual versions
    size_t selectArm(const Context& context);
    void updateReward(size_t arm, double reward, const Context& context);
    
private:
    // Linear UCB parameters for each arm
    struct LinearModel {
        std::vector<std::vector<double>> A; // Context covariance matrix
        std::vector<double> b;              // Reward vector
        std::vector<double> theta;          // Estimated parameters
        
        void update(const std::vector<double>& context, double reward);
        double predict(const std::vector<double>& context) const;
        double getUCB(const std::vector<double>& context, double alpha) const;
    };
    
    std::vector<LinearModel> arm_models_;
    size_t context_dim_;
    double alpha_ = 1.0; // Exploration parameter
};

// Epsilon-Greedy algorithm
class EpsilonGreedyBandit : public MultiArmedBandit {
public:
    explicit EpsilonGreedyBandit(size_t num_arms = 10, double epsilon = 0.1);
    
    // Override AlgorithmInfo for EpsilonGreedy
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Combination;
        info.name = "EpsilonGreedyBandit";
        info.version = "1.0";
        info.description = "Epsilon-Greedy multi-armed bandit algorithm";
        return info;
    }
    
    size_t selectArm() override;
    void updateReward(size_t arm, double reward) override;
    double getExpectedReward(size_t arm) const override;
    void reset() override;
    std::string getStatistics() const override;
    
    // Epsilon-Greedy specific methods
    void setEpsilon(double epsilon) { epsilon_ = epsilon; }
    double getEpsilon() const { return epsilon_; }
    void decayEpsilon(double decay_rate = 0.995);
    
    // Variants
    void enableAdaptiveEpsilon(bool enable) { adaptive_epsilon_ = enable; }
    void enableOptimisticInit(double init_value = 1.0);
    
protected:
    double epsilon_;
    bool adaptive_epsilon_ = false;
    std::vector<double> arm_averages_;
    std::uniform_real_distribution<> uniform_dist_;
};

// Epsilon-Greedy with decay schedules
class DecayingEpsilonGreedy : public EpsilonGreedyBandit {
public:
    enum class DecaySchedule {
        Exponential,    // epsilon_t = epsilon_0 * decay^t
        Polynomial,     // epsilon_t = epsilon_0 / (1 + t)^p
        Logarithmic,    // epsilon_t = c / log(t + 2)
        Linear,         // epsilon_t = max(epsilon_min, epsilon_0 - decay * t)
        Adaptive        // Based on performance
    };
    
    DecayingEpsilonGreedy(size_t num_arms, double initial_epsilon = 0.5,
                          DecaySchedule schedule = DecaySchedule::Exponential);
    
    size_t selectArm() override;
    void updateSchedule();
    
private:
    double initial_epsilon_;
    double epsilon_min_ = 0.01;
    DecaySchedule schedule_;
    size_t time_step_ = 0;
    
    // Adaptive epsilon parameters
    std::deque<double> recent_rewards_;
    static constexpr size_t REWARD_WINDOW = 100;
};

// Softmax (Boltzmann) exploration
class SoftmaxBandit : public MultiArmedBandit {
public:
    explicit SoftmaxBandit(size_t num_arms, double temperature = 1.0);
    
    size_t selectArm() override;
    void updateReward(size_t arm, double reward) override;
    double getExpectedReward(size_t arm) const override;
    void reset() override;
    std::string getStatistics() const override;
    
    void setTemperature(double temp) { temperature_ = temp; }
    void coolDown(double cooling_rate = 0.99);
    
private:
    double temperature_;
    std::vector<double> arm_averages_;
    std::vector<double> computeProbabilities() const;
};

// Gradient Bandit algorithm
class GradientBandit : public MultiArmedBandit {
public:
    explicit GradientBandit(size_t num_arms, double learning_rate = 0.1);
    
    size_t selectArm() override;
    void updateReward(size_t arm, double reward) override;
    double getExpectedReward(size_t arm) const override;
    void reset() override;
    std::string getStatistics() const override;
    
private:
    double learning_rate_;
    std::vector<double> preferences_;
    double average_reward_ = 0.0;
    size_t total_updates_ = 0;
    
    std::vector<double> computeProbabilities() const;
};

// Hybrid bandit that combines multiple strategies
class HybridBandit : public MultiArmedBandit {
public:
    enum class Strategy {
        UCB,
        EpsilonGreedy,
        Softmax,
        Gradient
    };
    
    explicit HybridBandit(size_t num_arms);
    
    size_t selectArm() override;
    void updateReward(size_t arm, double reward) override;
    double getExpectedReward(size_t arm) const override;
    void reset() override;
    std::string getStatistics() const override;
    
    // Switch between strategies based on performance
    void adaptStrategy();
    Strategy getCurrentStrategy() const { return current_strategy_; }
    
private:
    Strategy current_strategy_ = Strategy::UCB;
    
    std::unique_ptr<UCBBandit> ucb_;
    std::unique_ptr<EpsilonGreedyBandit> epsilon_greedy_;
    std::unique_ptr<SoftmaxBandit> softmax_;
    std::unique_ptr<GradientBandit> gradient_;
    
    // Performance tracking for strategy selection
    std::unordered_map<Strategy, double> strategy_performance_;
    std::deque<std::pair<Strategy, double>> recent_performance_;
    static constexpr size_t PERFORMANCE_WINDOW = 50;
};

// Contextual bandit for algorithm selection in fuzzing
class FuzzingContextualBandit {
public:
    struct FuzzingContext {
        // Coverage metrics
        double total_coverage;
        double recent_coverage_increase;
        double coverage_stagnation_time;
        
        // Performance metrics
        double exec_per_second;
        double crash_rate;
        double unique_crash_count;
        
        // Input characteristics
        double average_input_size;
        double input_complexity;
        
        // Algorithm history
        std::vector<double> recent_algorithm_performance;
        
        std::vector<double> toFeatureVector() const;
    };
    
    struct AlgorithmCombination {
        std::vector<std::string> algorithms;
        std::string toString() const;
    };
    
    FuzzingContextualBandit(const std::vector<AlgorithmCombination>& combinations);
    
    // Select algorithm combination based on context
    size_t selectCombination(const FuzzingContext& context);
    
    // Update with observed reward
    void updateReward(size_t combination_idx, double reward, const FuzzingContext& context);
    
    // Get statistics and recommendations
    std::string getPerformanceReport() const;
    std::vector<std::pair<size_t, double>> getRankedCombinations() const;
    
    // Persistence
    void saveModel(const std::string& path) const;
    void loadModel(const std::string& path);
    
private:
    std::vector<AlgorithmCombination> combinations_;
    std::unique_ptr<ContextualUCB> contextual_ucb_;
    
    // Feature engineering
    std::vector<double> engineerFeatures(const FuzzingContext& context) const;
    
    // Performance tracking
    struct PerformanceStats {
        size_t selection_count = 0;
        double total_reward = 0.0;
        double best_reward = 0.0;
        std::deque<double> recent_rewards;
    };
    
    std::vector<PerformanceStats> combination_stats_;
};

} // namespace triofuzz
