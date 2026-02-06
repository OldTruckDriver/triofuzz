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

// Beta分布
class BetaDistribution {
private:
    double alpha_;  // 成功次数 + 1
    double beta_;   // 失败次数 + 1
    std::mt19937 gen_;
    
public:
    BetaDistribution(double alpha = 1.0, double beta = 1.0)
        : alpha_(alpha), beta_(beta), gen_(std::random_device{}()) {}
    
    // 采样
    double sample() {
        std::gamma_distribution<double> gamma_alpha(alpha_, 1.0);
        std::gamma_distribution<double> gamma_beta(beta_, 1.0);
        
        double x = gamma_alpha(gen_);
        double y = gamma_beta(gen_);
        
        return x / (x + y);
    }
    
    // 更新参数
    void update(bool success, double weight = 1.0) {
        if (success) {
            alpha_ += weight;
        } else {
            beta_ += weight;
        }
    }
    
    // 获取期望值
    double getMean() const {
        return alpha_ / (alpha_ + beta_);
    }
    
    // 获取方差
    double getVariance() const {
        double n = alpha_ + beta_;
        return (alpha_ * beta_) / (n * n * (n + 1));
    }
    
    // 获取置信区间
    std::pair<double, double> getConfidenceInterval(double confidence = 0.95) const {
        // 使用正态近似
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

// Thompson Sampling策略
class ThompsonSamplingStrategy : public CombinationStrategy {
protected:  // Changed to protected for derived class access
    // 每个算法组合的Beta分布
    std::map<std::string, BetaDistribution> distributions_;

    // 算法组合历史
    struct CombinationHistory {
        size_t total_uses = 0;
        size_t successes = 0;
        double total_reward = 0.0;
        double best_reward = 0.0;
        std::chrono::steady_clock::time_point last_used;
        std::chrono::steady_clock::time_point last_contribution_time;  // 最后一次产生贡献的时间
    };
    std::map<std::string, CombinationHistory> history_;

    // 探索参数
    double exploration_rate_ = 0.05;  // 降低初始探索率
    double decay_factor_ = 0.995;
    size_t min_samples_ = 50;  // 增加最小采样数

    // 批次执行参数 - 优化：减小批次大小，加快响应
    mutable size_t current_batch_count_ = 0;  // 当前批次已执行次数
    mutable size_t current_batch_size_ = 500;  // 当前批次大小 - 从10000减少到500
    std::string current_combination_;  // 当前执行的组合
    std::chrono::steady_clock::time_point batch_start_time_;  // 批次开始时间
    std::chrono::seconds min_execution_time_{2};  // 最小执行时间 - 从10秒减少到2秒
    double batch_initial_coverage_ = 0.0;  // 批次开始时的覆盖率

    // 新增：自适应批次参数
    mutable size_t consecutive_no_coverage_ = 0;  // 连续无覆盖率增长次数
    mutable double last_coverage_percentage_ = 0.0;  // 上次覆盖率百分比
    mutable size_t min_batch_size_ = 100;  // 最小批次大小
    mutable size_t max_batch_size_ = 5000;  // 最大批次大小 - 从无限制改为5000

    // 奖励计算参数
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
    
    // 选择下一个算法组合（支持批次执行）
    AlgorithmCombination selectNext() {
        // 检查是否仍在当前批次中
        if (shouldContinueCurrentBatch()) {
            // 继续使用当前组合
            current_batch_count_++;
            return parseCombinationName(current_combination_);
        }

        // 批次结束，选择新的组合
        std::vector<std::pair<std::string, double>> candidates;

        // 为每个已知的组合采样
        for (auto& [combo_name, dist] : distributions_) {
            // 冷却期检查：最近使用过的组合降低概率
            auto& hist = history_[combo_name];
            auto time_since_last_use = std::chrono::steady_clock::now() - hist.last_used;

            double sampled_value = dist.sample();

            // 应用探索奖励
            if (hist.total_uses < min_samples_) {
                sampled_value += exploration_rate_;
            }

            // 应用冷却期惩罚（如果最近30秒内使用过）
            if (time_since_last_use < std::chrono::seconds(30) && combo_name == current_combination_) {
                sampled_value *= 0.7;  // 降低30%概率
            }

            candidates.emplace_back(combo_name, sampled_value);
        }

        // 如果没有候选，返回默认组合
        if (candidates.empty()) {
            return createDefaultCombination();
        }

        // 选择采样值最高的组合
        auto best_it = std::max_element(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });

        // 开始新批次
        startNewBatch(best_it->first);

        return parseCombinationName(best_it->first);
    }
    
    // 选择算法组合（考虑上下文）
    AlgorithmCombination selectWithContext(const SharedContext& context) {
        std::vector<std::pair<std::string, double>> candidates;
        
        // 获取当前状态信息
        auto coverage_info = context.getCoverageInfo();
        auto performance_info = context.getPerformanceInfo();
        
        for (auto& [combo_name, dist] : distributions_) {
            double sampled_value = dist.sample();
            
            // 根据上下文调整采样值
            if (coverage_info.has_value()) {
                // 如果最近覆盖率停滞，倾向于探索新组合
                if (coverage_info->coverage_gain < 0.001) {
                    if (history_[combo_name].last_used > std::chrono::steady_clock::now() - std::chrono::minutes(5)) {
                        sampled_value *= 0.8; // 降低最近使用过的组合的概率
                    }
                }
            }
            
            if (performance_info.has_value()) {
                // 如果性能较差，倾向于选择更快的组合
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
        
        // 更新使用时间
        history_[best_it->first].last_used = std::chrono::steady_clock::now();
        
        return parseCombinationName(best_it->first);
    }
    
    // 更新奖励
    void updateReward(const AlgorithmCombination& combo, double reward) {
        std::string combo_name = combo.toString();
        
        // 确保分布存在
        if (distributions_.find(combo_name) == distributions_.end()) {
            distributions_[combo_name] = BetaDistribution(1.0, 1.0);
        }
        
        // 更新历史
        auto& hist = history_[combo_name];
        hist.total_uses++;
        hist.total_reward += reward;
        hist.best_reward = std::max(hist.best_reward, reward);
        
        // 将奖励转换为成功/失败
        bool success = reward > computeAverageReward() * 0.8;
        if (success) {
            hist.successes++;
            hist.last_contribution_time = std::chrono::steady_clock::now();  // 记录贡献时间
        }
        
        // 更新Beta分布 - 提高更新频率
        static size_t update_counter = 0;
        if (++update_counter % 20 == 0) {  // 每20次更新一次分布，更快的学习
            distributions_[combo_name].update(success, std::min(1.0, reward));

            // 衰减探索率，但更缓慢
            if (update_counter % 5000 == 0) {  // 每5000次衰减一次
                exploration_rate_ *= decay_factor_;
                exploration_rate_ = std::max(0.01, exploration_rate_); // 保持最低1%探索率
            }
        }
    }
    
    // 计算复合奖励
    double computeReward(const ExecutionResult& result, const SharedContext& context) {
        double reward = 0.0;
        
        // 覆盖率奖励
        if (result.coverage.hasNewCoverage()) {
            reward += reward_weights_.coverage_weight * result.coverage.coverage_gain;
            
            // 稀有边额外奖励
            reward += reward_weights_.coverage_weight * 0.5 * 
                     (result.coverage.rare_edges.size() / 100.0);
        }
        
        // 崩溃奖励
        if (result.status == ExecutionResult::Status::Crash) {
            reward += reward_weights_.crash_weight;
            
            // 唯一崩溃额外奖励
            auto crash_hash = hashCrash(result);
            if (unique_crashes_.find(crash_hash) == unique_crashes_.end()) {
                unique_crashes_.insert(crash_hash);
                reward += reward_weights_.crash_weight * 0.5;
            }
        }
        
        // 执行速度奖励
        double speed_reward = 1.0 / (result.performance.execution_time_ms + 1.0);
        reward += reward_weights_.speed_weight * speed_reward;
        
        // 多样性奖励（基于与最近执行的差异）
        double diversity_reward = computeDiversityReward(result);
        reward += reward_weights_.diversity_weight * diversity_reward;
        
        return std::min(1.0, reward); // 归一化到[0,1]
    }
    
    // CombinationStrategy接口实现
    CompositionMode selectMode(
        const std::vector<AlgorithmInfo>& algorithms,
        const SharedContext& context
    ) override {
        // 基于算法类型和数量选择组合模式
        if (algorithms.size() == 1) {
            return CompositionMode::Sequential;
        }
        
        // 检查算法之间的依赖关系
        bool has_dependencies = checkDependencies(algorithms);
        
        if (has_dependencies) {
            return CompositionMode::Sequential; // 有依赖关系时使用顺序执行
        }
        
        // 根据性能信息选择
        auto perf_info = context.getPerformanceInfo();
        if (perf_info.has_value() && perf_info->execution_time_ms > 50) {
            return CompositionMode::Parallel; // 执行慢时尝试并行
        }
        
        // 根据算法类型选择
        bool all_same_type = std::all_of(algorithms.begin(), algorithms.end(),
            [&](const auto& info) { return info.type == algorithms[0].type; });
        
        if (all_same_type) {
            return CompositionMode::Weighted; // 同类型算法使用加权选择
        }
        
        return CompositionMode::Sequential; // 默认顺序执行
    }
    
    std::vector<double> computeWeights(
        const std::vector<AlgorithmInfo>& algorithms,
        const PerformanceMetrics& metrics
    ) override {
        std::vector<double> weights;
        
        for (const auto& algo_info : algorithms) {
            // 基于算法历史表现计算权重
            double weight = 1.0;
            
            auto it = algorithm_weights_.find(algo_info.name);
            if (it != algorithm_weights_.end()) {
                weight = it->second;
            }
            
            weights.push_back(weight);
        }
        
        // 归一化权重
        double sum = std::accumulate(weights.begin(), weights.end(), 0.0);
        if (sum > 0) {
            for (auto& w : weights) {
                w /= sum;
            }
        }
        
        return weights;
    }
    
    // 获取统计信息
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
    
    // 重置统计
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

    // 获取当前批次执行信息
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
        info.coverage_gain = 0.0;  // 需要从context获取
        return info;
    }

private:
    std::set<size_t> unique_crashes_;
    std::map<std::string, double> algorithm_weights_;
    std::deque<ExecutionResult> recent_results_;
    static constexpr size_t MAX_RECENT_RESULTS = 100;
    
    // 创建默认组合
    AlgorithmCombination createDefaultCombination() {
        AlgorithmCombination combo;
        combo.algorithm_names = {"havoc", "bit_flip"};
        combo.combination_mode = "sequential";
        return combo;
    }
    
    // 解析组合名称
    AlgorithmCombination parseCombinationName(const std::string& name) const {
        // 简单实现，实际应该有更复杂的解析逻辑
        AlgorithmCombination combo;
        
        // 格式: "mode[algo1,algo2,...]"
        size_t bracket_pos = name.find('[');
        if (bracket_pos != std::string::npos) {
            combo.combination_mode = name.substr(0, bracket_pos);
            
            size_t end_bracket = name.find(']');
            if (end_bracket != std::string::npos) {
                std::string algos = name.substr(bracket_pos + 1, end_bracket - bracket_pos - 1);
                
                // 分割算法名
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
    
    // 计算平均奖励
    double computeAverageReward() const {
        double total_reward = 0.0;
        size_t total_uses = 0;
        
        for (const auto& [_, hist] : history_) {
            total_reward += hist.total_reward;
            total_uses += hist.total_uses;
        }
        
        return total_uses > 0 ? total_reward / total_uses : 0.5;
    }
    
    // 计算崩溃哈希
    size_t hashCrash(const ExecutionResult& result) const {
        std::hash<std::string> hasher;
        std::string crash_sig;
        
        for (const auto& info : result.crash_info) {
            crash_sig += info + "|";
        }
        
        return hasher(crash_sig);
    }
    
    // 计算多样性奖励
    double computeDiversityReward(const ExecutionResult& result) {
        if (recent_results_.empty()) {
            recent_results_.push_back(result);
            return 1.0;
        }
        
        // 计算与最近结果的差异
        double total_diff = 0.0;
        size_t count = 0;
        
        for (const auto& recent : recent_results_) {
            // 覆盖率差异
            auto coverage_diff = (result.coverage.bitmap ^ recent.coverage.bitmap).count();
            total_diff += coverage_diff / static_cast<double>(CoverageInfo::MAP_SIZE);
            
            count++;
            if (count >= 10) break; // 只比较最近10个
        }
        
        // 维护最近结果队列
        recent_results_.push_back(result);
        if (recent_results_.size() > MAX_RECENT_RESULTS) {
            recent_results_.pop_front();
        }
        
        return count > 0 ? total_diff / count : 0.0;
    }
    
    // 检查算法依赖
    bool checkDependencies(const std::vector<AlgorithmInfo>& algorithms) const {
        // 检查是否有算法需要其他算法提供的信息
        for (size_t i = 0; i < algorithms.size(); ++i) {
            for (size_t j = i + 1; j < algorithms.size(); ++j) {
                // 检查 i 是否需要 j 提供的信息
                for (const auto& req : algorithms[i].required_info) {
                    if (std::find(algorithms[j].provided_info.begin(),
                                algorithms[j].provided_info.end(), req) 
                        != algorithms[j].provided_info.end()) {
                        return true;
                    }
                }
                
                // 检查 j 是否需要 i 提供的信息
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

    // 检查是否应继续当前批次 - 优化：加入早期退出机制
    bool shouldContinueCurrentBatch() {
        // 如果没有当前组合，返回false
        if (current_combination_.empty()) {
            return false;
        }

        auto elapsed = std::chrono::steady_clock::now() - batch_start_time_;
        auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);

        // 早期退出：如果连续无覆盖率增长，提前结束
        if (consecutive_no_coverage_ > 200 && elapsed_seconds > std::chrono::seconds(1)) {
            // 连续200次无增长且已执行超过1秒，提前退出
            return false;
        }

        // 检查最小执行时间
        if (elapsed_seconds < min_execution_time_) {
            // 但如果已经执行了足够多次且无增长，也可以退出
            if (current_batch_count_ > min_batch_size_ && consecutive_no_coverage_ > 100) {
                return false;
            }
            return true;  // 未达到最小执行时间，继续
        }

        // 检查批次执行次数
        if (current_batch_count_ < current_batch_size_) {
            // 如果仍在产生新覆盖率（惯性机制）
            if (history_.count(current_combination_) > 0) {
                const auto& hist = history_.at(current_combination_);
                // 检查最近是否有成功
                auto time_since_success = std::chrono::steady_clock::now() - hist.last_contribution_time;
                if (time_since_success < std::chrono::seconds(2)) {  // 从5秒减少到2秒
                    // 最近2秒内有贡献，延长执行
                    consecutive_no_coverage_ = 0;  // 重置计数
                    return true;
                }
            }
            return true;  // 未达到批次大小，继续
        }

        // 达到最大批次大小，检查是否应延长
        if (shouldExtendBatch()) {
            current_batch_size_ = std::min(max_batch_size_,
                static_cast<size_t>(current_batch_size_ * 1.2));  // 从1.5改为1.2，更温和的增长
            return true;
        }

        return false;  // 批次结束
    }

    // 检查是否应延长批次
    bool shouldExtendBatch() {
        if (history_.count(current_combination_) == 0) {
            return false;
        }

        const auto& hist = history_.at(current_combination_);

        // 如果最近表现特别好，延长批次
        double avg_reward = computeAverageReward();
        double recent_reward = hist.total_uses > 0 ?
            hist.total_reward / hist.total_uses : 0.0;

        if (recent_reward > avg_reward * 1.5) {
            return true;  // 表现优秀，延长
        }

        // 如果已经执行了很久都没有贡献，不延长
        if (current_batch_count_ > 30000) {
            return false;
        }

        return false;
    }

    // 开始新批次
    void startNewBatch(const std::string& combination) {
        current_combination_ = combination;
        current_batch_count_ = 0;
        batch_start_time_ = std::chrono::steady_clock::now();

        // 动态调整批次大小
        current_batch_size_ = calculateBatchSize(combination);

        // 更新历史记录
        if (history_.count(combination) > 0) {
            history_[combination].last_used = batch_start_time_;
        }

        std::cout << "[Thompson] Starting new batch: " << combination
                  << ", size: " << current_batch_size_
                  << ", min_time: " << min_execution_time_.count() << "s" << std::endl;
    }

    // 计算批次大小 - 优化：自适应批次大小
    size_t calculateBatchSize(const std::string& combination) const {
        size_t base_batch = 500;  // 基础批次大小 - 从10000减少到500

        if (history_.count(combination) == 0) {
            // 首次运行，给予适中机会
            return base_batch * 2;  // 1000次
        }

        const auto& hist = history_.at(combination);
        double avg_reward = computeAverageReward();
        double combo_reward = hist.total_uses > 0 ?
            hist.total_reward / hist.total_uses : 0.0;

        // 根据历史表现调整 - 更细粒度的调整
        if (combo_reward > avg_reward * 1.5) {
            return std::min(max_batch_size_, static_cast<size_t>(base_batch * 4));  // 表现优秀：2000次
        } else if (combo_reward > avg_reward * 1.2) {
            return static_cast<size_t>(base_batch * 2);  // 表现良好：1000次
        } else if (combo_reward < avg_reward * 0.5) {
            return std::max(min_batch_size_, static_cast<size_t>(base_batch * 0.5));  // 表现较差：250次
        } else if (combo_reward < avg_reward * 0.8) {
            return static_cast<size_t>(base_batch * 0.8);  // 表现一般：400次
        }

        return base_batch;  // 标准批次：500次
    }
};

} // namespace triofuzz