#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <random>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <shared_mutex>

namespace triofuzz {

/**
 * @brief 算法性能层级
 *
 * 根据开销将算法分为三个层级：
 * - Tier 1 (极速): < 0.5ms, 高频使用 (70%概率)
 * - Tier 2 (快速): 0.5-1.0ms, 中频使用 (25%概率)
 * - Tier 3 (中等): 1.0-2.0ms, 低频使用 (5%概率)
 */
enum class AlgorithmTier {
    TIER_1_ULTRA_FAST = 1,  // < 0.5ms
    TIER_2_FAST = 2,        // 0.5-1.0ms
    TIER_3_MEDIUM = 3       // 1.0-2.0ms
};

/**
 * @brief 算法性能元数据
 */
struct AlgorithmPerformanceProfile {
    std::string name;
    AlgorithmTier tier;
    double avg_execution_time_ms;
    double coverage_gain_rate;      // 平均覆盖率增益
    double mutation_diversity;      // 变异多样性 [0-1]

    // 使用统计
    size_t total_executions = 0;
    size_t successful_executions = 0;  // 发现新覆盖
    double cumulative_reward = 0.0;

    // 计算性价比 (reward per millisecond)
    double getCostEffectiveness() const {
        if (avg_execution_time_ms <= 0) return 0.0;
        return coverage_gain_rate / avg_execution_time_ms;
    }

    // 计算成功率
    double getSuccessRate() const {
        if (total_executions == 0) return 0.5; // 先验概率
        return static_cast<double>(successful_executions) / total_executions;
    }
};

/**
 * @brief 分层概率调度器
 *
 * 策略：
 * 1. Tier 1算法: 70%概率, 几乎每次执行
 * 2. Tier 2算法: 25%概率, 适度执行
 * 3. Tier 3算法: 5%概率, 稀疏执行但用于探索
 *
 * 动态调整：
 * - 根据实时性能调整各tier的基础概率
 * - 算法内部根据成功率再次分配 (UCB1)
 * - 考虑多样性避免过度exploitation
 */
class TieredAlgorithmScheduler {
private:
    // 算法性能档案
    std::map<std::string, AlgorithmPerformanceProfile> profiles_;

    // 分层列表
    std::vector<std::string> tier1_algorithms_;
    std::vector<std::string> tier2_algorithms_;
    std::vector<std::string> tier3_algorithms_;

    // 基础概率分配（恢复最优配置，redqueen移至Tier2增强结构化格式支持）
    double tier1_base_probability_ = 0.73;
    double tier2_base_probability_ = 0.25;
    double tier3_base_probability_ = 0.02;

    // 性能阈值 (毫秒)
    double tier1_threshold_ms_ = 0.5;
    double tier2_threshold_ms_ = 1.0;
    double tier3_threshold_ms_ = 2.0;

    // 自适应参数
    double adaptation_rate_ = 0.01;     // 学习率
    double ucb_exploration_c_ = 1.414;  // UCB探索系数
    double diversity_bonus_ = 0.1;      // 多样性奖励
    size_t warmup_executions_ = 100;    // 预热次数
    size_t update_interval_ = 100;      // 更新间隔

    // 全局统计
    size_t total_executions_ = 0;
    double avg_execution_time_ms_ = 0.0;
    double target_execution_time_ms_ = 0.8;  // 目标平均执行时间

    // 速度预算参数
    double speed_budget_threshold_ = 1.5;  // 超过目标的倍数触发预算模式
    bool speed_budget_mode_ = false;       // 是否处于速度预算模式
    size_t consecutive_slow_updates_ = 0;  // 连续慢速更新次数
    size_t speed_budget_trigger_count_ = 3; // 触发速度预算模式的阈值

    // 覆盖率增长追踪（用于动态调整exploration）
    double last_coverage_growth_rate_ = 1.0;
    size_t executions_since_last_coverage_ = 0;

    // 随机数生成器
    std::mt19937 rng_;

    // Round-robin索引 (预热阶段使用)
    std::map<int, size_t> round_robin_indices_;

    // 线程安全：保护profiles_/tier列表/统计的并发访问
    mutable std::recursive_mutex mutex_;

public:
    TieredAlgorithmScheduler() : rng_(std::random_device{}()) {}

    // 动态设置各层基础概率（需保证三者相加≤1，内部不强制归一）
    void setTierBaseProbabilities(double p1, double p2, double p3) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        tier1_base_probability_ = std::clamp(p1, 0.0, 1.0);
        tier2_base_probability_ = std::clamp(p2, 0.0, 1.0);
        tier3_base_probability_ = std::clamp(p3, 0.0, 1.0);
    }

    /**
     * @brief 注册算法及其性能档案
     */
    void registerAlgorithm(const AlgorithmPerformanceProfile& profile) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        profiles_[profile.name] = profile;

        // 分配到相应层级
        switch (profile.tier) {
            case AlgorithmTier::TIER_1_ULTRA_FAST:
                tier1_algorithms_.push_back(profile.name);
                break;
            case AlgorithmTier::TIER_2_FAST:
                tier2_algorithms_.push_back(profile.name);
                break;
            case AlgorithmTier::TIER_3_MEDIUM:
                tier3_algorithms_.push_back(profile.name);
                break;
        }
    }

    /**
     * @brief 选择下一个要执行的算法
     *
     * 使用两阶段选择：
     * 1. 先根据tier概率选择层级
     * 2. 在层级内根据UCB1选择具体算法
     */
    std::string selectAlgorithm() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        // 阶段1: 选择tier
        double rand_val = std::uniform_real_distribution<double>(0.0, 1.0)(rng_);

        std::vector<std::string>* selected_tier = nullptr;
        int tier_id = 0;

        if (rand_val < tier1_base_probability_) {
            selected_tier = &tier1_algorithms_;
            tier_id = 1;
        } else if (rand_val < tier1_base_probability_ + tier2_base_probability_) {
            selected_tier = &tier2_algorithms_;
            tier_id = 2;
        } else {
            selected_tier = &tier3_algorithms_;
            tier_id = 3;
        }

        // Fallback到其他tier
        if (selected_tier->empty()) {
            if (!tier1_algorithms_.empty()) {
                selected_tier = &tier1_algorithms_;
                tier_id = 1;
            } else if (!tier2_algorithms_.empty()) {
                selected_tier = &tier2_algorithms_;
                tier_id = 2;
            } else if (!tier3_algorithms_.empty()) {
                selected_tier = &tier3_algorithms_;
                tier_id = 3;
            } else {
                throw std::runtime_error("No algorithms registered in any tier");
            }
        }

        // 阶段2: 在tier内使用UCB1选择
        return selectFromTier(*selected_tier, tier_id);
    }

    /**
     * @brief 批量选择多个算法 (用于组合)
     *
     * @param count 需要选择的算法数量
     * @param ensure_diversity 是否确保多样性
     * @return 选中的算法列表
     */
    std::vector<std::string> selectAlgorithms(size_t count, bool ensure_diversity = true) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::vector<std::string> selected;
        std::set<std::string> selected_set;

        // 检查是否有任何算法可用
        if (tier1_algorithms_.empty() && tier2_algorithms_.empty() && tier3_algorithms_.empty()) {
            throw std::runtime_error("No algorithms registered in any tier");
        }

        // 确保至少包含一个Tier 1算法（如果Tier 1非空）
        if (count > 0 && !tier1_algorithms_.empty()) {
            std::string algo = selectFromTier(tier1_algorithms_, 1);
            selected.push_back(algo);
            selected_set.insert(algo);
        }

        // 选择剩余算法
        for (size_t i = selected.size(); i < count; ++i) {
            std::string algo = selectAlgorithm();

            // 如果需要多样性，避免重复
            if (ensure_diversity) {
                int attempts = 0;
                while (selected_set.count(algo) > 0 && attempts < 10) {
                    algo = selectAlgorithm();
                    attempts++;
                }
            }

            selected.push_back(algo);
            selected_set.insert(algo);
        }

        return selected;
    }

    /**
     * @brief 更新算法性能
     *
     * @param algorithm_name 算法名称
     * @param execution_time_ms 执行时间
     * @param found_new_coverage 是否发现新覆盖
     * @param reward 奖励值 [0-1]
     */
    void updatePerformance(const std::string& algorithm_name,
                          double execution_time_ms,
                          bool found_new_coverage,
                          double reward = 0.0) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = profiles_.find(algorithm_name);
        if (it == profiles_.end()) return;

        auto& profile = it->second;

        // 更新统计
        profile.total_executions++;
        if (found_new_coverage) {
            profile.successful_executions++;
        }
        profile.cumulative_reward += reward;

        // 更新平均执行时间 (exponential moving average)
        double alpha = 0.1;
        profile.avg_execution_time_ms =
            alpha * execution_time_ms + (1 - alpha) * profile.avg_execution_time_ms;

        // 更新覆盖率增益率
        profile.coverage_gain_rate = profile.getSuccessRate();

        // 全局统计
        total_executions_++;
        avg_execution_time_ms_ =
            (avg_execution_time_ms_ * (total_executions_ - 1) + execution_time_ms)
            / total_executions_;

        // 追踪覆盖率增长
        if (found_new_coverage) {
            double growth_rate = 1.0 / (executions_since_last_coverage_ + 1);
            last_coverage_growth_rate_ = 0.9 * last_coverage_growth_rate_ + 0.1 * growth_rate;
            executions_since_last_coverage_ = 0;
        } else {
            executions_since_last_coverage_++;
        }

        // 自适应调整tier概率
        if (total_executions_ > warmup_executions_ && total_executions_ % update_interval_ == 0) {
            adaptTierProbabilities();

            // 动态调整exploration参数
            adjustExplorationParameter();
        }

        // 动态重分配tier (如果性能显著变化)
        if (profile.total_executions >= 50 && profile.total_executions % 50 == 0) {
            reclassifyAlgorithmIfNeeded(algorithm_name);
        }
    }

    /**
     * @brief 动态调整exploration参数，防止过早收敛
     */
    void adjustExplorationParameter() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        // 如果执行很多次但没有新覆盖，增加exploration
        if (total_executions_ > 1000000) {
            double coverage_stagnation = static_cast<double>(executions_since_last_coverage_) / 1000.0;

            if (coverage_stagnation > 100.0) {
                // 长时间无新覆盖，大幅增加exploration
                ucb_exploration_c_ = std::min(3.0, ucb_exploration_c_ * 1.2);
            } else if (coverage_stagnation > 50.0) {
                // 中等停滞，适度增加exploration
                ucb_exploration_c_ = std::min(2.5, ucb_exploration_c_ * 1.1);
            } else if (coverage_stagnation < 10.0 && ucb_exploration_c_ > 1.414) {
                // 覆盖率增长良好，可以降低exploration
                ucb_exploration_c_ = std::max(1.414, ucb_exploration_c_ * 0.95);
            }
        }
    }

    /**
     * @brief 获取算法性能档案
     */
    const AlgorithmPerformanceProfile& getProfile(const std::string& algorithm_name) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return profiles_.at(algorithm_name);
    }

    /**
     * @brief 获取所有算法按性价比排序
     */
    std::vector<std::string> getAlgorithmsByEffectiveness() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::vector<std::pair<std::string, double>> rankings;

        for (const auto& [name, profile] : profiles_) {
            rankings.emplace_back(name, profile.getCostEffectiveness());
        }

        std::sort(rankings.begin(), rankings.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });

        std::vector<std::string> result;
        for (const auto& [name, _] : rankings) {
            result.push_back(name);
        }

        return result;
    }

    /**
     * @brief 获取统计报告
     */
    std::string getStatisticsReport() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::ostringstream oss;
        oss << "\n=== Tiered Algorithm Scheduler Statistics ===\n";
        oss << "Total Executions: " << total_executions_ << "\n";
        oss << "Average Execution Time: " << avg_execution_time_ms_ << " ms\n";
        oss << "Target Execution Time: " << target_execution_time_ms_ << " ms\n";
        oss << "\nTier Probabilities:\n";
        oss << "  Tier 1 (Ultra Fast): " << (tier1_base_probability_ * 100) << "%\n";
        oss << "  Tier 2 (Fast):       " << (tier2_base_probability_ * 100) << "%\n";
        oss << "  Tier 3 (Medium):     " << (tier3_base_probability_ * 100) << "%\n";

        oss << "\nTop Algorithms by Cost-Effectiveness:\n";
        auto rankings = getAlgorithmsByEffectiveness();
        for (size_t i = 0; i < std::min<size_t>(5, rankings.size()); ++i) {
            const auto& profile = profiles_.at(rankings[i]);
            oss << "  " << (i+1) << ". " << profile.name
                << " - CE: " << profile.getCostEffectiveness()
                << " (success: " << (profile.getSuccessRate() * 100) << "%, "
                << "execs: " << profile.total_executions << ")\n";
        }

        return oss.str();
    }

    /**
     * @brief 设置目标执行时间
     */
    void setTargetExecutionTime(double target_ms) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        target_execution_time_ms_ = target_ms;
    }

    /**
     * @brief 获取当前tier概率
     */
    std::tuple<double, double, double> getTierProbabilities() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return {tier1_base_probability_, tier2_base_probability_, tier3_base_probability_};
    }

    /**
     * @brief 检查是否有已注册的算法
     */
    bool hasAlgorithms() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return !profiles_.empty();
    }

    /**
     * @brief 获取总执行次数
     */
    size_t getTotalExecutions() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return total_executions_;
    }

private:
    /**
     * @brief 在tier内使用UCB1选择算法
     */
    std::string selectFromTier(const std::vector<std::string>& tier_algorithms, int tier_id) {
        if (tier_algorithms.empty()) {
            throw std::runtime_error("Cannot select from empty tier");
        }

        // 如果只有一个算法，直接返回
        if (tier_algorithms.size() == 1) {
            return tier_algorithms[0];
        }

        // 计算该tier的总执行次数
        double total_tier_executions = 0;
        for (const auto& algo : tier_algorithms) {
            total_tier_executions += profiles_[algo].total_executions;
        }

        // 预热阶段：轮询选择
        if (total_tier_executions < warmup_executions_) {
            size_t& idx = round_robin_indices_[tier_id];
            std::string selected = tier_algorithms[idx % tier_algorithms.size()];
            idx++;
            return selected;
        }

        // UCB1选择 - 考虑效率(reward/time)
        double best_ucb = -1.0;
        std::string best_algo;

        for (const auto& algo : tier_algorithms) {
            const auto& profile = profiles_[algo];

            // Exploitation: 效率 = 成功率 / 执行时间
            // 这样可以平衡reward和速度
            double success_rate = profile.getSuccessRate();
            double time_normalized = std::max(0.1, profile.avg_execution_time_ms); // 避免除0
            double efficiency = success_rate / time_normalized;

            // 归一化efficiency到[0,1]范围
            double exploitation = std::min(1.0, efficiency * 0.5); // 0.5是缩放因子

            // Exploration: UCB项
            double exploration = 0.0;
            if (profile.total_executions > 0) {
                exploration = ucb_exploration_c_ * std::sqrt(
                    std::log(total_tier_executions + 1) / profile.total_executions
                );
            } else {
                exploration = 10.0; // 未执行过的算法优先
            }

            // Diversity: 多样性奖励
            double diversity = diversity_bonus_ * profile.mutation_diversity;

            // 速度预算模式下，更重视效率
            double efficiency_weight = speed_budget_mode_ ? 1.5 : 1.0;

            double ucb_score = exploitation * efficiency_weight + exploration + diversity;

            if (ucb_score > best_ucb) {
                best_ucb = ucb_score;
                best_algo = algo;
            }
        }

        return best_algo;
    }

    /**
     * @brief 自适应调整tier概率
     *
     * 策略：
     * - 如果平均执行时间超过目标，提高Tier 1概率
     * - 如果有余裕，提高Tier 2/3概率增加探索
     * - 实现速度预算机制：持续慢速时强制切换到快速模式
     */
    void adaptTierProbabilities() {
        // 计算执行时间偏差
        double time_ratio = avg_execution_time_ms_ / target_execution_time_ms_;

        // === 速度预算机制 ===
        if (time_ratio > speed_budget_threshold_) {
            consecutive_slow_updates_++;

            // 如果连续多次超速，进入速度预算模式
            if (consecutive_slow_updates_ >= speed_budget_trigger_count_) {
                speed_budget_mode_ = true;
                // 强制使用快速算法 (80% Tier 1, 15% Tier 2, 5% Tier 3)
                tier1_base_probability_ = 0.80;
                tier2_base_probability_ = 0.15;
                tier3_base_probability_ = 0.02;  // 降低Tier 3从5%到2%
                return; // 直接返回，跳过正常调整
            }
        } else {
            consecutive_slow_updates_ = 0;

            // 如果速度恢复正常，退出速度预算模式
            if (speed_budget_mode_ && time_ratio < 1.0) {
                speed_budget_mode_ = false;
            }
        }

        // === 正常自适应调整 ===
        if (speed_budget_mode_) {
            // 速度预算模式下，逐步恢复
            if (time_ratio < 1.0) {
                tier1_base_probability_ = std::max(0.70, tier1_base_probability_ - adaptation_rate_);
                tier2_base_probability_ = std::min(0.25, tier2_base_probability_ + adaptation_rate_ * 0.5);
                tier3_base_probability_ = std::min(0.02, tier3_base_probability_ + adaptation_rate_ * 0.3);  // 保持低频
            }
        } else {
            // 正常模式
            if (time_ratio > 1.2) {
                // 太慢，增加Tier 1权重
                tier1_base_probability_ = std::min(0.85, tier1_base_probability_ + adaptation_rate_);
                tier2_base_probability_ = std::max(0.10, tier2_base_probability_ - adaptation_rate_ * 0.5);
                tier3_base_probability_ = std::max(0.02, tier3_base_probability_ - adaptation_rate_ * 0.5);  // 从0.05降到0.02
            } else if (time_ratio < 0.8) {
                // 有余裕，可以增加探索
                tier1_base_probability_ = std::max(0.50, tier1_base_probability_ - adaptation_rate_);
                tier2_base_probability_ = std::min(0.35, tier2_base_probability_ + adaptation_rate_ * 0.5);
                tier3_base_probability_ = std::min(0.10, tier3_base_probability_ + adaptation_rate_ * 0.5);  // 限制最高到10%
            }
        }

        // 归一化
        double sum = tier1_base_probability_ + tier2_base_probability_ + tier3_base_probability_;
        tier1_base_probability_ /= sum;
        tier2_base_probability_ /= sum;
        tier3_base_probability_ /= sum;
    }

    /**
     * @brief 根据实际性能重新分类算法
     */
    void reclassifyAlgorithmIfNeeded(const std::string& algorithm_name) {
        auto it = profiles_.find(algorithm_name);
        if (it == profiles_.end()) return;

        auto& profile = it->second;

        AlgorithmTier new_tier = profile.tier;

        if (profile.avg_execution_time_ms < tier1_threshold_ms_) {
            new_tier = AlgorithmTier::TIER_1_ULTRA_FAST;
        } else if (profile.avg_execution_time_ms < tier2_threshold_ms_) {
            new_tier = AlgorithmTier::TIER_2_FAST;
        } else if (profile.avg_execution_time_ms < tier3_threshold_ms_) {
            new_tier = AlgorithmTier::TIER_3_MEDIUM;
        } else {
            // 超过阈值，但不移除，只是保持在Tier 3
            return;
        }

        // 如果tier变化，重新分配
        if (new_tier != profile.tier) {
            // 检查旧tier是否会变空（保护机制：每个tier至少保留1个算法）
            size_t old_tier_size = 0;
            switch (profile.tier) {
                case AlgorithmTier::TIER_1_ULTRA_FAST:
                    old_tier_size = tier1_algorithms_.size();
                    break;
                case AlgorithmTier::TIER_2_FAST:
                    old_tier_size = tier2_algorithms_.size();
                    break;
                case AlgorithmTier::TIER_3_MEDIUM:
                    old_tier_size = tier3_algorithms_.size();
                    break;
            }

            // 如果移除会导致tier变空，则不执行重分类
            if (old_tier_size <= 1) {
                return;
            }

            // 从旧tier移除
            removeFromTier(algorithm_name, profile.tier);

            // 添加到新tier
            profile.tier = new_tier;
            switch (new_tier) {
                case AlgorithmTier::TIER_1_ULTRA_FAST:
                    tier1_algorithms_.push_back(algorithm_name);
                    break;
                case AlgorithmTier::TIER_2_FAST:
                    tier2_algorithms_.push_back(algorithm_name);
                    break;
                case AlgorithmTier::TIER_3_MEDIUM:
                    tier3_algorithms_.push_back(algorithm_name);
                    break;
            }
        }
    }

    void removeFromTier(const std::string& algorithm_name, AlgorithmTier tier) {
        std::vector<std::string>* tier_list = nullptr;

        switch (tier) {
            case AlgorithmTier::TIER_1_ULTRA_FAST:
                tier_list = &tier1_algorithms_;
                break;
            case AlgorithmTier::TIER_2_FAST:
                tier_list = &tier2_algorithms_;
                break;
            case AlgorithmTier::TIER_3_MEDIUM:
                tier_list = &tier3_algorithms_;
                break;
        }

        if (tier_list) {
            tier_list->erase(
                std::remove(tier_list->begin(), tier_list->end(), algorithm_name),
                tier_list->end()
            );
        }
    }
};

/**
 * @brief 预定义算法档案 - 根据实际测试调整
 */
namespace TieredProfiles {

    // Tier 1: Ultra Fast (< 0.5ms)
    inline AlgorithmPerformanceProfile MAGIC_BYTE = {
        "magic_byte", AlgorithmTier::TIER_1_ULTRA_FAST, 0.2, 0.4, 0.6
    };

    inline AlgorithmPerformanceProfile BITFLIP = {
        "bitflip", AlgorithmTier::TIER_1_ULTRA_FAST, 0.3, 0.5, 0.7
    };

    inline AlgorithmPerformanceProfile VALUE_APPROXIMATION = {
        "value_approximation", AlgorithmTier::TIER_1_ULTRA_FAST, 0.35, 0.55, 0.65
    };

    inline AlgorithmPerformanceProfile LENGTH_EXTENSION = {
        "length_extension", AlgorithmTier::TIER_1_ULTRA_FAST, 0.35, 0.45, 0.6
    };

    inline AlgorithmPerformanceProfile ARITHMETIC = {
        "arithmetic", AlgorithmTier::TIER_1_ULTRA_FAST, 0.4, 0.5, 0.65
    };

    inline AlgorithmPerformanceProfile BYTE_WEIGHTED_HAVOC = {
        "byte_weighted_havoc", AlgorithmTier::TIER_1_ULTRA_FAST, 0.35, 0.55, 0.70
    };

    inline AlgorithmPerformanceProfile NIBBLE_SWAP = {
        "nibble_swap", AlgorithmTier::TIER_1_ULTRA_FAST, 0.25, 0.45, 0.65
    };

    inline AlgorithmPerformanceProfile BIT_ROTATE = {
        "bit_rotate", AlgorithmTier::TIER_1_ULTRA_FAST, 0.28, 0.5, 0.7
    };

    inline AlgorithmPerformanceProfile VARINT = {
        "varint", AlgorithmTier::TIER_1_ULTRA_FAST, 0.32, 0.55, 0.7
    };

    inline AlgorithmPerformanceProfile TOKEN = {
        "token", AlgorithmTier::TIER_1_ULTRA_FAST, 0.25, 0.6, 0.75
    };

    inline AlgorithmPerformanceProfile ENDIANNESS_SWAP = {
        "endianness_swap", AlgorithmTier::TIER_1_ULTRA_FAST, 0.15, 0.45, 0.6
    };

    // Tier 2: Fast (0.5-1.0ms)
    inline AlgorithmPerformanceProfile HAVOC = {
        "havoc", AlgorithmTier::TIER_2_FAST, 0.5, 0.7, 0.85
    };

    inline AlgorithmPerformanceProfile SPLICE = {
        "splice", AlgorithmTier::TIER_2_FAST, 0.5, 0.6, 0.8
    };

    inline AlgorithmPerformanceProfile CLASSIC_LIBFUZZER = {
        "classic_libfuzzer", AlgorithmTier::TIER_2_FAST, 0.65, 0.65, 0.8
    };

    inline AlgorithmPerformanceProfile TRIM = {
        "trim", AlgorithmTier::TIER_2_FAST, 0.4, 0.5, 0.6
    };

    inline AlgorithmPerformanceProfile BLOCK = {
        "block", AlgorithmTier::TIER_2_FAST, 0.5, 0.55, 0.7
    };

    inline AlgorithmPerformanceProfile CHUNK_BASED = {
        "chunk_based", AlgorithmTier::TIER_2_FAST, 0.7, 0.65, 0.7
    };

    inline AlgorithmPerformanceProfile CMPLOG = {
        "cmplog", AlgorithmTier::TIER_2_FAST, 0.8, 0.75, 0.85
    };

    inline AlgorithmPerformanceProfile REDQUEEN = {
        "redqueen", AlgorithmTier::TIER_2_FAST, 1.5, 0.85, 0.95
    };

    inline AlgorithmPerformanceProfile FORMAT_AWARE = {
        "format_aware", AlgorithmTier::TIER_2_FAST, 0.9, 0.7, 0.75
    };

    inline AlgorithmPerformanceProfile RUN_LENGTH = {
        "run_length", AlgorithmTier::TIER_2_FAST, 0.6, 0.55, 0.65
    };

    inline AlgorithmPerformanceProfile CHECKSUM_FIXUP = {
        "checksum_fixup", AlgorithmTier::TIER_2_FAST, 0.7, 0.5, 0.6
    };

    // Tier 3: Medium (1.0-2.0ms)
    inline AlgorithmPerformanceProfile SMART_DICTIONARY = {
        "smart_dictionary", AlgorithmTier::TIER_3_MEDIUM, 1.2, 0.75, 0.7
    };

    // Archived algorithms (not registered)
    // inline AlgorithmPerformanceProfile AFL_PLUS_PLUS = {
    //     "afl_plus_plus", AlgorithmTier::TIER_3_MEDIUM, 1.5, 0.8, 0.85
    // };

    // inline AlgorithmPerformanceProfile CLASSIC_LIBFUZZER = {
    //     "classic_libfuzzer", AlgorithmTier::TIER_2_FAST, 0.9, 0.8, 0.85
    // };

} // namespace TieredProfiles

} // namespace triofuzz
