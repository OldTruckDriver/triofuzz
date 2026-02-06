#pragma once

#include "../core/engine.hpp"
#include "../core/late_stage_optimizer.hpp"
#include "adaptive_algorithm_selector.hpp"
#include <random>
#include <cmath>
#include <deque>
#include <map>
#include <chrono>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <iomanip>
#include <sstream>

namespace triofuzz {

// Unified Thompson Sampling Implementation
// 统一的Thompson Sampling实现，整合了所有优化特性
class UnifiedThompsonSampling {
public:
    // 批次信息
    struct BatchInfo {
        std::string combination_name;
        size_t executions = 0;
        size_t batch_size = 1000;
        std::chrono::steady_clock::time_point start_time;
        double total_reward = 0.0;
        double coverage_at_start = 0.0;

        double getAverageReward() const {
            return executions > 0 ? total_reward / executions : 0.0;
        }

        std::chrono::seconds getElapsedTime() const {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_time);
        }
    };

    // 组合统计信息
    struct CombinationStats {
        size_t total_uses = 0;
        size_t successes = 0;
        double total_reward = 0.0;
        double best_reward = 0.0;
        std::chrono::steady_clock::time_point last_used;
        std::chrono::steady_clock::time_point last_success_time;

        double getSuccessRate() const {
            return total_uses > 0 ? static_cast<double>(successes) / total_uses : 0.0;
        }

        double getAverageReward() const {
            return total_uses > 0 ? total_reward / total_uses : 0.0;
        }
    };

private:
    // Beta分布实现
    class BetaDistribution {
    private:
        std::atomic<double> alpha_{1.0};
        std::atomic<double> beta_{1.0};
        mutable std::mt19937 gen_{std::random_device{}()};

    public:
        BetaDistribution(double alpha = 1.0, double beta = 1.0)
            : alpha_(alpha), beta_(beta) {}

        double sample() const {
            double a = alpha_.load();
            double b = beta_.load();
            std::gamma_distribution<double> gamma_alpha(a, 1.0);
            std::gamma_distribution<double> gamma_beta(b, 1.0);

            double x = gamma_alpha(gen_);
            double y = gamma_beta(gen_);

            return x / (x + y);
        }

        void update(bool success, double weight = 1.0) {
            if (success) {
                double current = alpha_.load();
                alpha_.store(std::min(50.0, current + weight));
            } else {
                double current = beta_.load();
                beta_.store(std::min(50.0, current + weight));
            }
        }

        double getMean() const {
            double a = alpha_.load();
            double b = beta_.load();
            return a / (a + b);
        }

        void reset(double new_alpha = 2.0, double new_beta = 1.0) {
            alpha_.store(new_alpha);
            beta_.store(new_beta);
        }

        std::pair<double, double> getParams() const {
            return {alpha_.load(), beta_.load()};
        }
    };

    // 多样性追踪器
    class DiversityTracker {
    private:
        std::deque<std::string> usage_history_;
        std::map<std::string, size_t> recent_usage_;
        const size_t window_size_ = 1000;
        mutable std::mutex mutex_;

    public:
        void recordUsage(const std::string& combo) {
            std::lock_guard<std::mutex> lock(mutex_);

            usage_history_.push_back(combo);
            recent_usage_[combo]++;

            if (usage_history_.size() > window_size_) {
                std::string old = usage_history_.front();
                usage_history_.pop_front();
                recent_usage_[old]--;
                if (recent_usage_[old] == 0) {
                    recent_usage_.erase(old);
                }
            }
        }

        double getDiversityScore() const {
            std::lock_guard<std::mutex> lock(mutex_);
            if (usage_history_.empty()) return 1.0;

            double entropy = 0.0;
            size_t total = usage_history_.size();

            for (const auto& [combo, count] : recent_usage_) {
                if (count > 0) {
                    double p = static_cast<double>(count) / total;
                    entropy -= p * std::log2(p);
                }
            }

            double max_entropy = std::log2(std::max(size_t(1), recent_usage_.size()));
            return max_entropy > 0 ? entropy / max_entropy : 0.0;
        }

        bool isConverged(double threshold = 0.3) const {
            return getDiversityScore() < threshold;
        }

        size_t getRecentUsage(const std::string& combo) const {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = recent_usage_.find(combo);
            return it != recent_usage_.end() ? it->second : 0;
        }
    };

    // 探索增强器
    class ExplorationBooster {
    private:
        std::atomic<bool> active_{false};
        std::atomic<size_t> countdown_{0};
        std::atomic<double> multiplier_{1.0};

    public:
        void activate(size_t duration = 1000, double boost = 2.0) {
            active_.store(true);
            countdown_.store(duration);
            multiplier_.store(boost);
        }

        void update() {
            if (active_.load() && countdown_.load() > 0) {
                countdown_.fetch_sub(1);
                if (countdown_.load() == 0) {
                    active_.store(false);
                    multiplier_.store(1.0);
                }
            }
        }

        double getMultiplier() const {
            return active_.load() ? multiplier_.load() : 1.0;
        }

        bool isActive() const {
            return active_.load();
        }
    };

    // 批次管理器
    class BatchManager {
    private:
        BatchInfo current_batch_;
        std::atomic<size_t> base_batch_size_{1000};
        std::atomic<size_t> min_batch_size_{100};
        std::atomic<size_t> max_batch_size_{10000};
        std::atomic<size_t> consecutive_no_improvement_{0};
        mutable std::mutex mutex_;

    public:
        void startNewBatch(const std::string& combination, double performance_score) {
            std::lock_guard<std::mutex> lock(mutex_);

            current_batch_.combination_name = combination;
            current_batch_.executions = 0;
            current_batch_.total_reward = 0.0;
            current_batch_.start_time = std::chrono::steady_clock::now();
            current_batch_.batch_size = calculateBatchSize(performance_score);

            consecutive_no_improvement_.store(0);
        }

        void recordExecution(double reward) {
            std::lock_guard<std::mutex> lock(mutex_);
            current_batch_.executions++;
            current_batch_.total_reward += reward;

            if (reward < 0.01) {
                consecutive_no_improvement_.fetch_add(1);
            } else {
                consecutive_no_improvement_.store(0);
            }
        }

        bool shouldSwitchCombination() const {
            std::lock_guard<std::mutex> lock(mutex_);

            // 基本条件：达到批次大小
            if (current_batch_.executions >= current_batch_.batch_size) {
                return true;
            }

            // 最小执行数保证
            if (current_batch_.executions < min_batch_size_.load()) {
                return false;
            }

            // 时间检查
            auto elapsed = current_batch_.getElapsedTime();

            // 覆盖率停滞检查
            if (consecutive_no_improvement_.load() > 200 && elapsed.count() > 30) {
                return true;
            }

            // 最大时间限制
            if (elapsed.count() > 300) {  // 5分钟
                return true;
            }

            // 性能极差时提前结束
            if (current_batch_.executions > 50 &&
                current_batch_.getAverageReward() < 0.1 &&
                elapsed.count() > 60) {
                return true;
            }

            return false;
        }

        BatchInfo getCurrentBatch() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return current_batch_;
        }

    private:
        size_t calculateBatchSize(double performance_score) const {
            size_t base = base_batch_size_.load();
            size_t min_size = min_batch_size_.load();

            // 改进: 给低性能算法更多机会，避免过早放弃
            // 对于结构化fuzzing，某些算法需要更多尝试才能显示效果
            if (performance_score > 0.8) {
                return std::min(max_batch_size_.load(), base * 3);
            } else if (performance_score > 0.5) {
                return base;
            } else if (performance_score > 0.3) {
                return std::max(min_size * 3, base / 2);  // 300 vs 500
            } else {
                // 即使性能低，也给500次最小尝试
                return std::max(size_t(500), min_size * 5);  // 500 vs 100
            }
        }
    };

    // 成员变量 - 使用unique_ptr避免拷贝问题
    std::map<std::string, std::unique_ptr<BetaDistribution>> distributions_;
    std::map<std::string, CombinationStats> statistics_;

    DiversityTracker diversity_tracker_;
    ExplorationBooster exploration_booster_;
    BatchManager batch_manager_;

    std::unique_ptr<LateStageOptimizer> late_stage_optimizer_;
    std::unique_ptr<AdaptiveAlgorithmSelector> algorithm_selector_;

    // UCB参数
    std::atomic<double> ucb_c_{3.0};  // 提高UCB探索bonus: 2.0 -> 3.0
    std::atomic<size_t> total_selections_{0};

    // 探索参数
    std::atomic<double> exploration_rate_{0.30};  // 提高初始探索率: 15% -> 30%
    std::atomic<double> decay_factor_{0.9998};    // 降低衰减速度: 0.9995 -> 0.9998

    // Bandit重置机制
    std::atomic<size_t> cycles_since_reset_{0};
    std::atomic<size_t> reset_threshold_{30000};  // 更频繁重置: 50k -> 30k

    // 线程安全
    mutable std::shared_mutex data_mutex_;

    // 随机数生成器
    mutable std::mt19937 rng_{std::random_device{}()};

    // 上下文引用
    const SharedContext* context_ = nullptr;

public:
    UnifiedThompsonSampling() {
        late_stage_optimizer_ = std::make_unique<LateStageOptimizer>();
        algorithm_selector_ = std::make_unique<AdaptiveAlgorithmSelector>();

        initializeDefaultCombinations();
    }

    // 设置上下文
    void setContext(const SharedContext* context) {
        context_ = context;
    }

    // 选择下一个算法组合
    AlgorithmCombination selectNext() {
        // 更新状态
        cycles_since_reset_.fetch_add(1);
        exploration_booster_.update();
        total_selections_.fetch_add(1);

        // 检查是否需要重置
        if (shouldResetBandits()) {
            performPartialReset();
        }

        // 检查多样性
        if (diversity_tracker_.isConverged()) {
            exploration_booster_.activate(1000, 2.0);
            std::cout << "[UnifiedThompson] Low diversity detected, boosting exploration\n";
        }

        // 检查批次是否应该结束
        if (batch_manager_.shouldSwitchCombination()) {
            endCurrentBatch();
        }

        // 选择新组合
        std::string selected = selectCombinationWithUCB();

        // 记录使用
        diversity_tracker_.recordUsage(selected);

        // 开始新批次
        double performance = getPerformanceScore(selected);
        batch_manager_.startNewBatch(selected, performance);

        // 更新统计
        {
            std::unique_lock<std::shared_mutex> lock(data_mutex_);
            statistics_[selected].last_used = std::chrono::steady_clock::now();
        }

        return parseCombinationString(selected);
    }

    // 更新奖励
    void updateReward(const AlgorithmCombination& combo, double reward,
                     bool found_coverage = false, bool found_crash = false) {
        std::string combo_key = combo.toString();

        // 记录批次执行
        batch_manager_.recordExecution(reward);

        // 更新统计
        {
            std::unique_lock<std::shared_mutex> lock(data_mutex_);

            auto& stats = statistics_[combo_key];
            stats.total_uses++;
            stats.total_reward += reward;
            stats.best_reward = std::max(stats.best_reward, reward);

            // 确定成功标准
            double avg_reward = getGlobalAverageReward();
            bool success = reward > avg_reward * 0.6 || found_coverage || found_crash;

            if (success) {
                stats.successes++;
                stats.last_success_time = std::chrono::steady_clock::now();
            }

            // 更新Beta分布
            if (distributions_.find(combo_key) == distributions_.end()) {
                distributions_[combo_key] = std::make_unique<BetaDistribution>(2.0, 1.0);
            }

            // 自适应权重更新
            double update_weight = calculateUpdateWeight(reward, stats);
            distributions_[combo_key]->update(success, update_weight);
        }

        // 更新算法选择器
        if (algorithm_selector_ && (found_coverage || found_crash)) {
            for (const auto& algo : combo.algorithm_names) {
                algorithm_selector_->recordAlgorithmResult(algo, reward, found_coverage, found_crash);
            }
        }

        // 自适应参数调整
        adaptExplorationParameters();
    }

    // 获取当前批次信息
    BatchInfo getCurrentBatchInfo() const {
        return batch_manager_.getCurrentBatch();
    }

    // 获取统计信息
    std::map<std::string, CombinationStats> getStatistics() const {
        std::shared_lock<std::shared_mutex> lock(data_mutex_);
        return statistics_;
    }

    // 获取性能报告
    std::string getPerformanceReport() const {
        std::stringstream ss;
        ss << "\n=== Thompson Sampling Performance Report ===\n";

        std::shared_lock<std::shared_mutex> lock(data_mutex_);

        // 排序组合by平均奖励
        std::vector<std::pair<std::string, double>> rankings;
        for (const auto& [combo, stats] : statistics_) {
            if (stats.total_uses > 0) {
                rankings.emplace_back(combo, stats.getAverageReward());
            }
        }

        std::sort(rankings.begin(), rankings.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        ss << "\nTop Algorithm Combinations:\n";
        for (size_t i = 0; i < std::min(size_t(10), rankings.size()); ++i) {
            const auto& [combo, avg_reward] = rankings[i];
            const auto& stats = statistics_.at(combo);

            ss << std::setw(3) << (i + 1) << ". " << combo << "\n";
            ss << "     Avg Reward: " << std::fixed << std::setprecision(3) << avg_reward;
            ss << ", Uses: " << stats.total_uses;
            ss << ", Success Rate: " << std::setprecision(1) << (stats.getSuccessRate() * 100) << "%\n";
        }

        ss << "\nDiversity Score: " << std::fixed << std::setprecision(2)
           << diversity_tracker_.getDiversityScore() << "\n";
        ss << "Exploration Rate: " << exploration_rate_.load() << "\n";
        ss << "Total Selections: " << total_selections_.load() << "\n";

        if (algorithm_selector_) {
            ss << "\n" << algorithm_selector_->getPerformanceReport();
        }

        return ss.str();
    }

private:
    // 初始化默认组合
    void initializeDefaultCombinations() {
        // 高性能组合
        distributions_["sequential[havoc,afl_plus_plus]"] = std::make_unique<BetaDistribution>(3.0, 1.0);
        distributions_["parallel[bitflip,arithmetic]"] = std::make_unique<BetaDistribution>(2.5, 1.0);  // 提升优先级
        distributions_["weighted[rare_branch,neuzz]"] = std::make_unique<BetaDistribution>(2.0, 1.0);

        // 结构化fuzzing组合 - 提升初始先验
        distributions_["sequential[deterministic,cmplog]"] = std::make_unique<BetaDistribution>(4.0, 1.0);
        distributions_["sequential[redqueen,magic_byte]"] = std::make_unique<BetaDistribution>(3.5, 1.0);
        distributions_["sequential[format_aware,smart_dictionary]"] = std::make_unique<BetaDistribution>(3.5, 1.0);
        distributions_["parallel[bitflip,deterministic]"] = std::make_unique<BetaDistribution>(3.0, 1.0);

        // 探索性组合
        distributions_["sequential[gradient_descent,smart_dictionary]"] = std::make_unique<BetaDistribution>(2.5, 1.0);
        distributions_["parallel[splice,length_extension]"] = std::make_unique<BetaDistribution>(2.0, 1.0);
    }

    // 使用UCB选择组合
    std::string selectCombinationWithUCB() {
        std::vector<std::pair<std::string, double>> candidates;

        {
            std::shared_lock<std::shared_mutex> lock(data_mutex_);

            for (const auto& [combo_name, dist] : distributions_) {
                double score = calculateCombinationScore(combo_name, dist);
                candidates.emplace_back(combo_name, score);
            }
        }

        // 如果没有候选，创建新组合
        if (candidates.empty()) {
            return createInnovativeCombination();
        }

        // Epsilon-greedy选择
        std::uniform_real_distribution<double> uniform(0.0, 1.0);
        double epsilon = exploration_rate_.load() * exploration_booster_.getMultiplier();

        if (uniform(rng_) < epsilon) {
            // 探索：随机选择
            std::uniform_int_distribution<size_t> rand_idx(0, candidates.size() - 1);
            return candidates[rand_idx(rng_)].first;
        } else {
            // 利用：选择最高分
            auto best = std::max_element(candidates.begin(), candidates.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            return best->first;
        }
    }

    // 计算组合得分
    double calculateCombinationScore(const std::string& combo_name,
                                     const std::unique_ptr<BetaDistribution>& dist) {
        // Thompson Sampling基础分
        double ts_score = dist->sample();

        // UCB探索加成 + 最小尝试次数保证
        double ucb_bonus = 0.0;
        auto stats_it = statistics_.find(combo_name);

        // 关键改进: 保证每个组合至少尝试1000次
        const size_t MIN_TRIALS = 1000;

        if (stats_it != statistics_.end() && stats_it->second.total_uses > 0) {
            size_t uses = stats_it->second.total_uses;

            // 如果尝试次数 < MIN_TRIALS, 给予极高bonus强制探索
            if (uses < MIN_TRIALS) {
                ucb_bonus = 20.0 * (1.0 - static_cast<double>(uses) / MIN_TRIALS);
            } else {
                ucb_bonus = ucb_c_.load() * std::sqrt(
                    std::log(total_selections_.load()) / uses);
            }
        } else {
            ucb_bonus = 25.0;  // 未探索组合的超高奖励: 10.0 -> 25.0
        }

        // 多样性加成
        size_t recent_usage = diversity_tracker_.getRecentUsage(combo_name);
        double diversity_bonus = 1.0 / (1.0 + recent_usage * 0.1);

        // 时间衰减加成
        double time_bonus = 0.0;
        if (stats_it != statistics_.end()) {
            auto time_since_use = std::chrono::steady_clock::now() - stats_it->second.last_used;
            auto minutes = std::chrono::duration_cast<std::chrono::minutes>(time_since_use).count();
            if (minutes > 5) {
                time_bonus = std::min(1.0, minutes / 30.0);
            }
        }

        // 后期优化调整
        if (isLateStage()) {
            ucb_bonus *= 1.5;
            diversity_bonus *= 2.0;
        }

        return ts_score + ucb_bonus + diversity_bonus + time_bonus;
    }

    // 创建创新组合
    std::string createInnovativeCombination() {
        AlgorithmCombination combo;

        // 使用自适应选择器
        if (algorithm_selector_) {
            size_t algo_count = 2 + (rng_() % 2);  // 2-3个算法
            combo.algorithm_names = algorithm_selector_->selectAlgorithms(algo_count);
            combo.combination_mode = algorithm_selector_->getRecommendedMode();
        } else {
            // 默认组合
            combo.algorithm_names = {"havoc", "bitflip"};
            combo.combination_mode = "sequential";
        }

        std::string combo_key = combo.toString();

        // 注册新组合
        {
            std::unique_lock<std::shared_mutex> lock(data_mutex_);
            if (distributions_.find(combo_key) == distributions_.end()) {
                distributions_[combo_key] = std::make_unique<BetaDistribution>(2.0, 1.0);
            }
        }

        return combo_key;
    }

    // 解析组合字符串
    AlgorithmCombination parseCombinationString(const std::string& combo_str) {
        AlgorithmCombination combo;

        // 格式: "mode[algo1,algo2,...]"
        size_t bracket_pos = combo_str.find('[');
        if (bracket_pos != std::string::npos) {
            combo.combination_mode = combo_str.substr(0, bracket_pos);

            size_t end_bracket = combo_str.find(']');
            if (end_bracket != std::string::npos) {
                std::string algos = combo_str.substr(bracket_pos + 1,
                                                     end_bracket - bracket_pos - 1);

                size_t start = 0;
                size_t pos = algos.find(',');
                while (pos != std::string::npos) {
                    combo.algorithm_names.push_back(algos.substr(start, pos - start));
                    start = pos + 1;
                    pos = algos.find(',', start);
                }
                if (start < algos.length()) {
                    combo.algorithm_names.push_back(algos.substr(start));
                }
            }
        }

        return combo;
    }

    // 计算更新权重
    double calculateUpdateWeight(double reward, const CombinationStats& stats) {
        // 基础权重
        double weight = reward;

        // 新组合获得更高权重
        if (stats.total_uses < 10) {
            weight *= 2.0;
        }

        // 后期阶段调整
        if (isLateStage()) {
            weight *= 1.5;
        }

        return std::min(1.0, weight);
    }

    // 自适应调整探索参数
    void adaptExplorationParameters() {
        // 衰减探索率 - 提高最低探索率阈值
        if (total_selections_.load() % 1000 == 0) {
            double current = exploration_rate_.load();
            exploration_rate_.store(std::max(0.15, current * decay_factor_.load()));  // 0.05 -> 0.15
        }

        // 根据多样性调整UCB参数
        double diversity = diversity_tracker_.getDiversityScore();
        if (diversity < 0.3) {
            ucb_c_.store(std::min(8.0, ucb_c_.load() * 1.15));  // 5.0 -> 8.0, 更强探索
        } else if (diversity > 0.7) {
            ucb_c_.store(std::max(2.0, ucb_c_.load() * 0.95));  // 1.0 -> 2.0, 保持最低探索
        }
    }

    // 判断是否后期阶段
    bool isLateStage() const {
        if (!late_stage_optimizer_) return false;

        // 获取覆盖率信息
        double coverage_pct = 0.0;
        if (context_) {
            auto cov_info = context_->getCoverageInfo();
            if (cov_info.has_value() && cov_info->total_edges > 0) {
                coverage_pct = (cov_info->covered_edges.size() * 100.0) / cov_info->total_edges;
            }
        }

        FuzzingStats stats{total_selections_.load(), coverage_pct};
        return late_stage_optimizer_->isLateStage(stats);
    }

    // 检查是否需要重置
    bool shouldResetBandits() const {
        if (cycles_since_reset_.load() < reset_threshold_.load()) {
            return false;
        }

        // 多样性过低
        if (diversity_tracker_.getDiversityScore() < 0.2) {
            return true;
        }

        return false;
    }

    // 执行部分重置
    void performPartialReset() {
        std::cout << "[UnifiedThompson] Performing partial reset to prevent convergence\n";

        std::unique_lock<std::shared_mutex> lock(data_mutex_);

        // 获取所有组合的性能排序
        std::vector<std::pair<std::string, double>> rankings;
        for (const auto& [combo, stats] : statistics_) {
            rankings.emplace_back(combo, stats.getAverageReward());
        }

        std::sort(rankings.begin(), rankings.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        // 保留前20%的组合，重置其余
        size_t keep_count = std::max(size_t(5), rankings.size() / 5);

        for (size_t i = keep_count; i < rankings.size(); ++i) {
            const std::string& combo = rankings[i].first;

            // 部分重置Beta分布
            if (distributions_.find(combo) != distributions_.end()) {
                distributions_[combo]->reset(2.0, 1.0);
            }

            // 部分重置统计
            statistics_[combo].total_uses /= 2;
            statistics_[combo].successes /= 2;
        }

        cycles_since_reset_.store(0);
        exploration_rate_.store(std::min(0.3, exploration_rate_.load() * 1.5));
        exploration_booster_.activate(5000, 2.0);
    }

    // 结束当前批次
    void endCurrentBatch() {
        auto batch_info = batch_manager_.getCurrentBatch();
        if (batch_info.executions == 0) return;

        std::cout << "[UnifiedThompson] Batch ended: " << batch_info.combination_name
                  << ", executions=" << batch_info.executions
                  << ", avg_reward=" << std::fixed << std::setprecision(3)
                  << batch_info.getAverageReward() << "\n";
    }

    // 获取性能分数
    double getPerformanceScore(const std::string& combo) const {
        std::shared_lock<std::shared_mutex> lock(data_mutex_);

        auto it = statistics_.find(combo);
        if (it == statistics_.end()) {
            return 0.5;  // 默认中等性能
        }

        return it->second.getAverageReward();
    }

    // 获取全局平均奖励
    double getGlobalAverageReward() const {
        double total_reward = 0.0;
        size_t total_uses = 0;

        for (const auto& [_, stats] : statistics_) {
            total_reward += stats.total_reward;
            total_uses += stats.total_uses;
        }

        return total_uses > 0 ? total_reward / total_uses : 0.5;
    }
};

// Global singleton getter
UnifiedThompsonSampling& getUnifiedThompsonSampling();

} // namespace triofuzz