#pragma once

#include "engine.hpp"
#include <unordered_map>
#include <deque>
#include <bitset>

namespace triofuzz {

// FuzzingStats is defined in engine.hpp

// 后期优化器 - 解决覆盖率停滞问题
class LateStageOptimizer {
private:
    // 覆盖率增长追踪
    struct CoverageGrowthTracker {
        std::deque<double> coverage_history;  // 最近N个时间窗口的覆盖率
        size_t window_size = 60;  // 每个窗口1分钟
        double growth_rate = 0.0;

        void update(double coverage) {
            coverage_history.push_back(coverage);
            if (coverage_history.size() > window_size) {
                coverage_history.pop_front();
            }

            // 计算增长率
            if (coverage_history.size() >= 2) {
                double old_coverage = coverage_history.front();
                double new_coverage = coverage_history.back();
                growth_rate = (new_coverage - old_coverage) / coverage_history.size();
            }
        }

        bool isStagnant() const {
            return growth_rate < 0.001;  // 增长率低于0.1%
        }

        size_t getStagnationDuration() const {
            // 计算连续停滞的窗口数
            size_t count = 0;
            for (auto it = coverage_history.rbegin(); it != coverage_history.rend(); ++it) {
                if (it != coverage_history.rbegin()) {
                    auto prev = std::prev(it);
                    if (*it - *prev < 0.001) {
                        count++;
                    } else {
                        break;
                    }
                }
            }
            return count;
        }
    };

    CoverageGrowthTracker growth_tracker_;

    // 稀有路径追踪
    struct RarePathTracker {
        std::unordered_map<size_t, size_t> path_hits;  // path_hash -> hit_count
        std::unordered_map<size_t, double> path_scores;  // path_hash -> rarity_score

        void updatePath(const CoverageInfo& coverage) {
            // 计算路径哈希
            size_t path_hash = hashCoverage(coverage);
            path_hits[path_hash]++;

            // 更新稀有度分数
            updateRarityScores();
        }

        double getRarityScore(const CoverageInfo& coverage) const {
            size_t path_hash = hashCoverage(coverage);
            auto it = path_scores.find(path_hash);
            return it != path_scores.end() ? it->second : 1.0;
        }

    private:
        size_t hashCoverage(const CoverageInfo& coverage) const {
            // 基于边的简单哈希
            size_t hash = 0;
            for (uint64_t edge : coverage.covered_edges) {
                hash ^= std::hash<uint64_t>()(edge) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            }
            return hash;
        }

        void updateRarityScores() {
            size_t total_hits = 0;
            for (const auto& [_, hits] : path_hits) {
                total_hits += hits;
            }

            if (total_hits > 0) {
                for (auto& [path, hits] : path_hits) {
                    // 稀有路径得分更高
                    path_scores[path] = 1.0 / (1.0 + std::log(1 + hits));
                }
            }
        }
    };

    RarePathTracker rare_path_tracker_;

    // 运行时字典学习
    struct RuntimeDictionary {
        std::unordered_map<std::string, size_t> tokens;  // token -> success_count
        std::vector<std::vector<uint8_t>> effective_sequences;
        size_t max_dict_size = 1000;

        void learnFromExecution(const std::vector<uint8_t>& input, bool found_coverage) {
            if (!found_coverage) return;

            // 提取有效的byte序列 (简化实现)
            for (size_t i = 0; i < input.size(); ) {
                // 寻找可能的token边界
                size_t token_len = findTokenLength(input, i);
                if (token_len >= 2 && token_len <= 16) {
                    std::string token(input.begin() + i, input.begin() + i + token_len);
                    tokens[token]++;
                    i += token_len;
                } else {
                    i++;
                }
            }

            // 保存整个有效序列
            if (effective_sequences.size() < max_dict_size) {
                effective_sequences.push_back(input);
            }
        }

        std::vector<uint8_t> getRandomToken() const {
            if (tokens.empty()) return {};

            // 根据成功次数加权选择
            size_t total_weight = 0;
            for (const auto& [_, count] : tokens) {
                total_weight += count;
            }

            if (total_weight == 0) return {};

            size_t target = rand() % total_weight;
            size_t current = 0;

            for (const auto& [token, count] : tokens) {
                current += count;
                if (current > target) {
                    return std::vector<uint8_t>(token.begin(), token.end());
                }
            }

            return {};
        }

    private:
        size_t findTokenLength(const std::vector<uint8_t>& input, size_t start) const {
            // 简单的边界检测：寻找分隔符或特殊字符
            size_t len = 0;
            for (size_t i = start; i < input.size() && len < 16; ++i, ++len) {
                uint8_t byte = input[i];
                // 常见分隔符
                if (byte == 0 || byte == ' ' || byte == '\n' ||
                    byte == ',' || byte == ';' || byte == ':') {
                    break;
                }
            }
            return len;
        }
    };

    RuntimeDictionary runtime_dict_;

    // 深度探索模式
    enum class ExplorationMode {
        FAST,        // 快速模糊
        DEEP,        // 深度探索
        TARGETED,    // 目标导向
        SYSTEMATIC   // 系统性探索
    };

    ExplorationMode current_mode_ = ExplorationMode::FAST;

public:
    // 检测是否进入后期
    bool isLateStage(const FuzzingStats& stats) const {
        // 条件1：执行次数超过阈值
        if (stats.total_executions < 100000) return false;

        // 条件2：覆盖率增长停滞
        if (!growth_tracker_.isStagnant()) return false;

        // 条件3：停滞时间超过5分钟
        return growth_tracker_.getStagnationDuration() > 5;
    }

    // 更新覆盖率历史
    void updateCoverage(double coverage_percentage) {
        growth_tracker_.update(coverage_percentage);
    }

    // 更新路径信息
    void updatePath(const CoverageInfo& coverage) {
        rare_path_tracker_.updatePath(coverage);
    }

    // 学习运行时字典
    void learnFromInput(const std::vector<uint8_t>& input, bool found_coverage) {
        runtime_dict_.learnFromExecution(input, found_coverage);
    }

    // 获取优化的算法组合（后期专用）
    AlgorithmCombination getOptimizedCombination() {
        AlgorithmCombination combo;

        switch (current_mode_) {
            case ExplorationMode::DEEP:
                // 深度探索：使用确定性和梯度下降
                combo.algorithm_names = {"deterministic", "angora_gradient_descent", "redqueen"};
                combo.combination_mode = "sequential";
                break;

            case ExplorationMode::TARGETED:
                // 目标导向：使用稀有边优先算法
                combo.algorithm_names = {"rare_edge_scheduler", "fairfuzz", "aflgo"};
                combo.combination_mode = "weighted";
                combo.weights["rare_edge_scheduler"] = 0.5;
                combo.weights["fairfuzz"] = 0.3;
                combo.weights["aflgo"] = 0.2;
                break;

            case ExplorationMode::SYSTEMATIC:
                // 系统性探索：类似AFL++的确定性阶段
                combo.algorithm_names = {"bitflip", "arithmetic", "interesting", "dictionary"};
                combo.combination_mode = "sequential";
                break;

            default:  // FAST
                // 快速模糊：平衡的组合
                combo.algorithm_names = {"havoc", "splice", "smart_dictionary"};
                combo.combination_mode = "parallel";
                break;
        }

        return combo;
    }

    // 调整种子优先级（后期专用）
    double adjustSeedPriority(const Seed& seed, double base_priority) {
        double adjusted = base_priority;

        // 1. 稀有路径加成
        double rarity_score = rare_path_tracker_.getRarityScore(seed.coverage);
        adjusted *= (1.0 + rarity_score);

        // 2. 深度优先（后期更重视深路径）
        if (seed.depth > 10) {
            adjusted *= 1.5;
        }

        // 3. 老种子复活（后期给老种子第二次机会）
        if (seed.execution_count > 100 && seed.execution_count < 200) {
            adjusted *= 1.2;  // 复活期
        }

        // 4. 小输入偏好（后期偏好小输入，更容易深入）
        if (seed.data.size() < 100) {
            adjusted *= 1.3;
        }

        return adjusted;
    }

    // 切换探索模式
    void switchMode(const FuzzingStats& stats) {
        size_t stagnation = growth_tracker_.getStagnationDuration();

        if (stagnation < 5) {
            current_mode_ = ExplorationMode::FAST;
        } else if (stagnation < 10) {
            current_mode_ = ExplorationMode::DEEP;
        } else if (stagnation < 20) {
            current_mode_ = ExplorationMode::TARGETED;
        } else {
            current_mode_ = ExplorationMode::SYSTEMATIC;
        }
    }

    // 获取运行时字典token
    std::vector<uint8_t> getDictionaryToken() const {
        return runtime_dict_.getRandomToken();
    }

    // 应该重启Thompson Sampling
    bool shouldResetThompsonSampling() const {
        // 每30分钟停滞后重置，给新组合机会
        return growth_tracker_.getStagnationDuration() > 30;
    }

    // 获取当前模式名称
    std::string getCurrentModeName() const {
        switch (current_mode_) {
            case ExplorationMode::DEEP: return "DEEP";
            case ExplorationMode::TARGETED: return "TARGETED";
            case ExplorationMode::SYSTEMATIC: return "SYSTEMATIC";
            default: return "FAST";
        }
    }
};

} // namespace triofuzz