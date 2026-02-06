#pragma once

#include <vector>
#include <string>
#include <map>
#include <deque>
#include <algorithm>
#include <cmath>

namespace triofuzz {

// 自适应算法选择器 - 通用的算法效果追踪和选择
class AdaptiveAlgorithmSelector {
private:
    // 算法性能追踪
    struct AlgorithmPerformance {
        size_t total_uses = 0;
        size_t coverage_contributions = 0;  // 产生新覆盖的次数
        size_t crash_contributions = 0;     // 发现crash的次数
        double total_coverage_gain = 0.0;   // 总覆盖率增益
        std::deque<double> recent_rewards;  // 最近N次的奖励
        size_t window_size = 100;

        // 计算算法的当前效率分数
        double getEfficiencyScore() const {
            if (total_uses == 0) return 1.0;  // 未使用的算法给高分鼓励尝试

            // 基础成功率
            double success_rate = (double)(coverage_contributions + crash_contributions) / total_uses;

            // 最近表现（指数移动平均）
            double recent_avg = 0.0;
            if (!recent_rewards.empty()) {
                double weight = 1.0;
                double weight_sum = 0.0;
                for (auto it = recent_rewards.rbegin(); it != recent_rewards.rend(); ++it) {
                    recent_avg += (*it) * weight;
                    weight_sum += weight;
                    weight *= 0.95;  // 衰减因子
                }
                recent_avg /= weight_sum;
            }

            // 综合分数：70%历史成功率 + 30%最近表现
            return 0.7 * success_rate + 0.3 * recent_avg;
        }

        void recordReward(double reward, bool found_coverage, bool found_crash) {
            total_uses++;
            if (found_coverage) coverage_contributions++;
            if (found_crash) crash_contributions++;
            total_coverage_gain += reward;

            recent_rewards.push_back(reward);
            if (recent_rewards.size() > window_size) {
                recent_rewards.pop_front();
            }
        }
    };

    // 每个算法的性能数据
    std::map<std::string, AlgorithmPerformance> algorithm_performance_;

    // 算法分类（基于特性）
    enum class AlgorithmType {
        RANDOM,       // 随机变异: havoc, splice
        DETERMINISTIC, // 确定性: bitflip, arithmetic
        GRADIENT,     // 梯度引导: angora_gradient_descent, neuzz
        STRUCTURAL,   // 结构感知: dictionary, smart_format
        COVERAGE,     // 覆盖引导: fairfuzz, afl_plus_plus
        TARGETED      // 定向: aflgo, rare_edge
    };

    std::map<std::string, AlgorithmType> algorithm_types_ = {
        {"havoc", AlgorithmType::RANDOM},
        {"splice", AlgorithmType::RANDOM},
        {"bitflip", AlgorithmType::DETERMINISTIC},
        {"arithmetic", AlgorithmType::DETERMINISTIC},
        {"interesting", AlgorithmType::DETERMINISTIC},
        {"angora_gradient_descent", AlgorithmType::GRADIENT},
        {"neuzz", AlgorithmType::GRADIENT},
        {"dictionary", AlgorithmType::STRUCTURAL},
        {"smart_dictionary", AlgorithmType::STRUCTURAL},
        {"smart_format", AlgorithmType::STRUCTURAL},
        {"fairfuzz", AlgorithmType::COVERAGE},
        {"afl_plus_plus", AlgorithmType::COVERAGE},
        {"aflgo", AlgorithmType::TARGETED},
        {"rare_edge_scheduler", AlgorithmType::TARGETED}
    };

    // 算法类型的性能追踪
    std::map<AlgorithmType, double> type_performance_;

    // 运行时特征检测
    struct RuntimeCharacteristics {
        bool has_deep_branches = false;      // 深层分支
        bool has_numeric_comparisons = false; // 数值比较
        bool has_structured_input = false;   // 结构化输入
        bool has_rare_edges = false;         // 稀有边
        bool is_stagnant = false;           // 覆盖率停滞
        double coverage_velocity = 0.0;      // 覆盖率增长速度
        size_t execution_count = 0;

        void update(double coverage_gain, size_t new_edges, size_t rare_edges_count) {
            execution_count++;

            // 更新覆盖率速度（指数移动平均）
            coverage_velocity = 0.9 * coverage_velocity + 0.1 * coverage_gain;

            // 检测停滞
            is_stagnant = (coverage_velocity < 0.001 && execution_count > 10000);

            // 检测稀有边
            has_rare_edges = (rare_edges_count > 0);

            // 简单的启发式检测
            if (execution_count > 1000) {
                // 如果某些算法特别有效，推断输入特征
                // 这会在下面的updateCharacteristics中完成
            }
        }
    };

    RuntimeCharacteristics runtime_chars_;

public:
    // 获取下一批算法组合（自适应选择）
    std::vector<std::string> selectAlgorithms(size_t count = 3) {
        std::vector<std::string> selected;

        // Step 1: 根据运行时特征调整算法权重
        std::map<std::string, double> adjusted_scores;

        for (const auto& [algo_name, perf] : algorithm_performance_) {
            double score = perf.getEfficiencyScore();

            // 根据算法类型和运行时特征调整分数
            if (algorithm_types_.count(algo_name)) {
                AlgorithmType type = algorithm_types_[algo_name];
                score *= getTypeMultiplier(type);
            }

            // 探索奖励：少用的算法获得加成
            if (perf.total_uses < 100) {
                score *= 1.5;
            }

            adjusted_scores[algo_name] = score;
        }

        // Step 2: 选择算法（兼顾利用和探索）
        std::vector<std::pair<std::string, double>> candidates;
        for (const auto& [name, score] : adjusted_scores) {
            candidates.emplace_back(name, score);
        }

        // 按分数排序
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        // 选择算法：80%概率选最优，20%随机探索
        for (size_t i = 0; i < count && i < candidates.size(); ++i) {
            if (i == 0 || (rand() % 100) < 80) {
                // 选择高分算法
                selected.push_back(candidates[i].first);
            } else {
                // 随机探索
                size_t random_idx = rand() % candidates.size();
                selected.push_back(candidates[random_idx].first);
            }
        }

        // 如果没有足够的候选，添加默认算法
        if (selected.empty()) {
            selected = {"havoc", "bitflip", "arithmetic"};
        }

        return selected;
    }

    // 记录算法执行结果
    void recordAlgorithmResult(const std::string& algorithm,
                               double reward,
                               bool found_coverage,
                               bool found_crash) {
        algorithm_performance_[algorithm].recordReward(reward, found_coverage, found_crash);

        // 更新算法类型性能
        if (algorithm_types_.count(algorithm)) {
            AlgorithmType type = algorithm_types_[algorithm];
            type_performance_[type] = 0.9 * type_performance_[type] + 0.1 * reward;
        }
    }

    // 更新运行时特征
    void updateRuntimeCharacteristics(double coverage_gain, size_t new_edges, size_t rare_edges) {
        runtime_chars_.update(coverage_gain, new_edges, rare_edges);

        // 基于算法效果推断程序特征
        inferProgramCharacteristics();
    }

    // 获取推荐的算法组合模式
    std::string getRecommendedMode() {
        if (runtime_chars_.is_stagnant) {
            return "sequential";  // 停滞时用顺序执行深入探索
        } else if (runtime_chars_.coverage_velocity > 0.01) {
            return "parallel";    // 快速增长时并行探索
        } else {
            return "weighted";    // 一般情况用加权组合
        }
    }

private:
    // 根据运行时特征获取算法类型的权重倍数
    double getTypeMultiplier(AlgorithmType type) {
        double multiplier = 1.0;

        switch (type) {
            case AlgorithmType::DETERMINISTIC:
                // 停滞时加强确定性变异
                if (runtime_chars_.is_stagnant) multiplier *= 2.0;
                // 有数值比较时也加强
                if (runtime_chars_.has_numeric_comparisons) multiplier *= 1.5;
                break;

            case AlgorithmType::GRADIENT:
                // 深层分支时使用梯度方法
                if (runtime_chars_.has_deep_branches) multiplier *= 2.5;
                // 停滞时也有用
                if (runtime_chars_.is_stagnant) multiplier *= 1.5;
                break;

            case AlgorithmType::STRUCTURAL:
                // 结构化输入时加强
                if (runtime_chars_.has_structured_input) multiplier *= 3.0;
                break;

            case AlgorithmType::TARGETED:
                // 有稀有边时加强
                if (runtime_chars_.has_rare_edges) multiplier *= 2.0;
                break;

            case AlgorithmType::COVERAGE:
                // 一般情况下都有用
                multiplier *= 1.2;
                break;

            case AlgorithmType::RANDOM:
                // 早期探索阶段加强
                if (runtime_chars_.execution_count < 100000) multiplier *= 1.3;
                break;
        }

        // 基于历史性能调整
        if (type_performance_.count(type) && type_performance_[type] > 0.5) {
            multiplier *= (1.0 + type_performance_[type]);
        }

        return multiplier;
    }

    // 基于算法效果推断程序特征
    void inferProgramCharacteristics() {
        // 如果arithmetic算法特别有效，可能有数值比较
        if (algorithm_performance_["arithmetic"].getEfficiencyScore() > 0.3) {
            runtime_chars_.has_numeric_comparisons = true;
        }

        // 如果dictionary算法有效，可能是结构化输入
        if (algorithm_performance_["dictionary"].getEfficiencyScore() > 0.3 ||
            algorithm_performance_["smart_dictionary"].getEfficiencyScore() > 0.3) {
            runtime_chars_.has_structured_input = true;
        }

        // 如果gradient算法有效，可能有深层分支
        if (algorithm_performance_["angora_gradient_descent"].getEfficiencyScore() > 0.2) {
            runtime_chars_.has_deep_branches = true;
        }
    }

public:
    // 获取算法性能统计（用于调试）
    std::string getPerformanceReport() const {
        std::string report = "Algorithm Performance Report:\n";

        std::vector<std::pair<std::string, double>> scores;
        for (const auto& [name, perf] : algorithm_performance_) {
            scores.emplace_back(name, perf.getEfficiencyScore());
        }

        std::sort(scores.begin(), scores.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        for (const auto& [name, score] : scores) {
            const auto& perf = algorithm_performance_.at(name);
            report += name + ": score=" + std::to_string(score) +
                     " uses=" + std::to_string(perf.total_uses) +
                     " coverage=" + std::to_string(perf.coverage_contributions) + "\n";
        }

        return report;
    }
};

} // namespace triofuzz