#include "../../include/combination/multi_armed_bandit.hpp"
#include <sstream>
#include <algorithm>
#include <numeric>

namespace triofuzz {

// ===================== UCBBandit Implementation =====================

UCBBandit::UCBBandit(size_t num_arms, double exploration_constant) 
    : exploration_constant_(exploration_constant) {
    num_arms_ = num_arms;
    arm_pulls_.resize(num_arms, 0);
    arm_rewards_.resize(num_arms, 0.0);
    arm_averages_.resize(num_arms, 0.0);
    rng_ = std::mt19937(std::random_device{}());
}

size_t UCBBandit::selectArm() {
    // Initially pull each arm once
    for (size_t i = 0; i < num_arms_; ++i) {
        if (arm_pulls_[i] == 0) {
            return i;
        }
    }
    
    // Select arm with highest UCB score
    size_t best_arm = 0;
    double best_score = getUCBScore(0);
    
    for (size_t i = 1; i < num_arms_; ++i) {
        double score = getUCBScore(i);
        if (score > best_score) {
            best_score = score;
            best_arm = i;
        }
    }
    
    return best_arm;
}

void UCBBandit::updateReward(size_t arm, double reward) {
    if (arm >= num_arms_) return;
    
    arm_pulls_[arm]++;
    arm_rewards_[arm] += reward;
    arm_averages_[arm] = arm_rewards_[arm] / arm_pulls_[arm];
    total_pulls_++;
    
    // Update performance metrics
    metrics_.execution_count++;
    metrics_.recordExecution(1.0, true);
}

double UCBBandit::getExpectedReward(size_t arm) const {
    if (arm >= num_arms_ || arm_pulls_[arm] == 0) {
        return 0.0;
    }
    return arm_averages_[arm];
}

void UCBBandit::reset() {
    std::fill(arm_pulls_.begin(), arm_pulls_.end(), 0);
    std::fill(arm_rewards_.begin(), arm_rewards_.end(), 0.0);
    std::fill(arm_averages_.begin(), arm_averages_.end(), 0.0);
    total_pulls_ = 0;
}

std::string UCBBandit::getStatistics() const {
    std::stringstream ss;
    ss << "UCB Bandit Statistics:\n";
    ss << "Total pulls: " << total_pulls_ << "\n";
    for (size_t i = 0; i < num_arms_; ++i) {
        ss << "Arm " << i << ": pulls=" << arm_pulls_[i] 
           << ", avg_reward=" << arm_averages_[i] 
           << ", UCB=" << getUCBScore(i) << "\n";
    }
    return ss.str();
}

double UCBBandit::getUCBScore(size_t arm) const {
    if (arm >= num_arms_ || arm_pulls_[arm] == 0) {
        return std::numeric_limits<double>::max();
    }
    
    double exploration_term = exploration_constant_ * 
        std::sqrt(2.0 * std::log(total_pulls_) / arm_pulls_[arm]);
    
    return arm_averages_[arm] + exploration_term;
}

// ===================== ContextualUCB Implementation =====================

void ContextualUCB::LinearModel::update(const std::vector<double>& context, double reward) {
    // Simplified linear model update
    size_t d = context.size();
    if (A.empty()) {
        A.resize(d, std::vector<double>(d, 0.0));
        for (size_t i = 0; i < d; ++i) {
            A[i][i] = 1.0; // Identity matrix initialization
        }
        b.resize(d, 0.0);
        theta.resize(d, 0.0);
    }
    
    // Update A matrix (simplified - not full implementation)
    for (size_t i = 0; i < d; ++i) {
        for (size_t j = 0; j < d; ++j) {
            A[i][j] += context[i] * context[j];
        }
        b[i] += reward * context[i];
    }
    
    // Update theta (simplified - should solve A*theta = b)
    for (size_t i = 0; i < d; ++i) {
        theta[i] = b[i] / (A[i][i] + 1.0);
    }
}

double ContextualUCB::LinearModel::predict(const std::vector<double>& context) const {
    double prediction = 0.0;
    for (size_t i = 0; i < context.size() && i < theta.size(); ++i) {
        prediction += theta[i] * context[i];
    }
    return prediction;
}

double ContextualUCB::LinearModel::getUCB(const std::vector<double>& context, double alpha) const {
    double prediction = predict(context);
    
    // Simplified confidence bound calculation
    double confidence = alpha * std::sqrt(std::accumulate(context.begin(), context.end(), 0.0,
        [](double sum, double x) { return sum + x * x; }));
    
    return prediction + confidence;
}

ContextualUCB::ContextualUCB(size_t num_arms, size_t context_dim) 
    : UCBBandit(num_arms), context_dim_(context_dim) {
    arm_models_.resize(num_arms);
}

size_t ContextualUCB::selectArm() {
    // Default context when no context is provided
    Context default_context = {0.5, 0.1, 100.0, 1, false};
    return selectArm(default_context);
}

void ContextualUCB::updateReward(size_t arm, double reward) {
    // Default context when no context is provided  
    Context default_context = {0.5, 0.1, 100.0, 1, false};
    updateReward(arm, reward, default_context);
}

size_t ContextualUCB::selectArm(const Context& context) {
    std::vector<double> context_vec = context.toVector();
    
    // Validate context dimension
    if (context_vec.size() != context_dim_) {
        // Resize to expected dimension if needed
        context_vec.resize(context_dim_, 0.0);
    }
    
    size_t best_arm = 0;
    double best_ucb = arm_models_[0].getUCB(context_vec, alpha_);
    
    for (size_t i = 1; i < num_arms_; ++i) {
        double ucb = arm_models_[i].getUCB(context_vec, alpha_);
        if (ucb > best_ucb) {
            best_ucb = ucb;
            best_arm = i;
        }
    }
    
    return best_arm;
}

void ContextualUCB::updateReward(size_t arm, double reward, const Context& context) {
    if (arm >= num_arms_) return;
    
    std::vector<double> context_vec = context.toVector();
    
    // Validate context dimension
    if (context_vec.size() != context_dim_) {
        // Resize to expected dimension if needed
        context_vec.resize(context_dim_, 0.0);
    }
    
    arm_models_[arm].update(context_vec, reward);
    
    // Also update base UCB statistics
    UCBBandit::updateReward(arm, reward);
}

// ===================== EpsilonGreedyBandit Implementation =====================

EpsilonGreedyBandit::EpsilonGreedyBandit(size_t num_arms, double epsilon)
    : epsilon_(epsilon), uniform_dist_(0.0, 1.0) {
    num_arms_ = num_arms;
    arm_pulls_.resize(num_arms, 0);
    arm_rewards_.resize(num_arms, 0.0);
    arm_averages_.resize(num_arms, 0.0);
    rng_ = std::mt19937(std::random_device{}());
}

size_t EpsilonGreedyBandit::selectArm() {
    // Epsilon-greedy strategy
    if (uniform_dist_(rng_) < epsilon_) {
        // Exploration: random selection
        std::uniform_int_distribution<size_t> arm_dist(0, num_arms_ - 1);
        return arm_dist(rng_);
    } else {
        // Exploitation: select best arm
        auto it = std::max_element(arm_averages_.begin(), arm_averages_.end());
        return std::distance(arm_averages_.begin(), it);
    }
}

void EpsilonGreedyBandit::updateReward(size_t arm, double reward) {
    if (arm >= num_arms_) return;
    
    arm_pulls_[arm]++;
    arm_rewards_[arm] += reward;
    arm_averages_[arm] = arm_rewards_[arm] / arm_pulls_[arm];
    total_pulls_++;
    
    // Adaptive epsilon decay
    if (adaptive_epsilon_) {
        decayEpsilon();
    }
    
    // Update performance metrics
    metrics_.execution_count++;
    metrics_.recordExecution(1.0, true);
}

double EpsilonGreedyBandit::getExpectedReward(size_t arm) const {
    if (arm >= num_arms_ || arm_pulls_[arm] == 0) {
        return 0.0;
    }
    return arm_averages_[arm];
}

void EpsilonGreedyBandit::reset() {
    std::fill(arm_pulls_.begin(), arm_pulls_.end(), 0);
    std::fill(arm_rewards_.begin(), arm_rewards_.end(), 0.0);
    std::fill(arm_averages_.begin(), arm_averages_.end(), 0.0);
    total_pulls_ = 0;
}

std::string EpsilonGreedyBandit::getStatistics() const {
    std::stringstream ss;
    ss << "Epsilon-Greedy Bandit Statistics:\n";
    ss << "Total pulls: " << total_pulls_ << "\n";
    ss << "Epsilon: " << epsilon_ << "\n";
    for (size_t i = 0; i < num_arms_; ++i) {
        ss << "Arm " << i << ": pulls=" << arm_pulls_[i] 
           << ", avg_reward=" << arm_averages_[i] << "\n";
    }
    return ss.str();
}

void EpsilonGreedyBandit::decayEpsilon(double decay_rate) {
    epsilon_ *= decay_rate;
    epsilon_ = std::max(epsilon_, 0.01); // Minimum epsilon
}

void EpsilonGreedyBandit::enableOptimisticInit(double init_value) {
    std::fill(arm_averages_.begin(), arm_averages_.end(), init_value);
}

// ===================== DecayingEpsilonGreedy Implementation =====================

DecayingEpsilonGreedy::DecayingEpsilonGreedy(size_t num_arms, double initial_epsilon, DecaySchedule schedule)
    : EpsilonGreedyBandit(num_arms, initial_epsilon),
      initial_epsilon_(initial_epsilon),
      schedule_(schedule) {
}

size_t DecayingEpsilonGreedy::selectArm() {
    updateSchedule();
    return EpsilonGreedyBandit::selectArm();
}

void DecayingEpsilonGreedy::updateSchedule() {
    time_step_++;
    
    switch (schedule_) {
        case DecaySchedule::Exponential:
            epsilon_ = initial_epsilon_ * std::pow(0.995, time_step_);
            break;
            
        case DecaySchedule::Polynomial:
            epsilon_ = initial_epsilon_ / (1.0 + time_step_ * 0.001);
            break;
            
        case DecaySchedule::Logarithmic:
            epsilon_ = 0.5 / std::log(time_step_ + 2);
            break;
            
        case DecaySchedule::Linear:
            epsilon_ = std::max(epsilon_min_, initial_epsilon_ - 0.001 * time_step_);
            break;
            
        case DecaySchedule::Adaptive:
            // Adjust based on recent performance
            if (recent_rewards_.size() >= REWARD_WINDOW) {
                double avg_reward = std::accumulate(recent_rewards_.begin(), 
                                                   recent_rewards_.end(), 0.0) / recent_rewards_.size();
                if (avg_reward < 0.5) {
                    epsilon_ = std::min(1.0, epsilon_ * 1.1); // Increase exploration
                } else {
                    epsilon_ = std::max(epsilon_min_, epsilon_ * 0.99); // Decrease exploration
                }
            }
            break;
    }
    
    epsilon_ = std::max(epsilon_min_, epsilon_);
}

} // namespace triofuzz