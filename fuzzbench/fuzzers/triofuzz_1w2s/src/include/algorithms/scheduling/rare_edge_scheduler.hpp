#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include "scheduling_algorithms.hpp"
#include <unordered_map>
#include <set>
#include <queue>

namespace triofuzz {

// 稀有边优先调度器
class RareEdgeScheduler : public SchedulingAlgorithm {
private:
    // 边/分支频率统计（统一用于edge和branch）
    struct EdgeStats {
        uint64_t edge_id;
        size_t hit_count = 0;
        double hit_frequency = 0.0;
        double rarity_score = 0.0;  // 稀有度分数（从FairFuzz迁移）
        bool is_rare = false;        // 是否为稀有边
        std::set<size_t> triggering_seeds; // 触发此边的种子
        std::chrono::system_clock::time_point first_hit;
        std::chrono::system_clock::time_point last_hit;
    };

    // 全局边统计
    std::unordered_map<uint64_t, EdgeStats> global_edge_stats_;

    // 分支频率统计（从FairFuzzMutation迁移）
    std::unordered_map<uint64_t, EdgeStats> branch_frequencies_;

    // 稀有分支集合（从FairFuzzMutation迁移）
    std::set<uint64_t> rare_branches_;

    // 种子到稀有分支的映射（从FairFuzzMutation迁移）
    std::unordered_map<size_t, std::set<uint64_t>> seed_rare_branches_;
    
    // 稀有边阈值参数
    struct RareEdgeParams {
        double rare_threshold = 0.01;        // 稀有边阈值（1%以下）
        double ultra_rare_threshold = 0.001; // 极稀有边阈值（0.1%以下）
        size_t min_executions = 1000;        // 开始统计的最小执行次数
        double rare_edge_bonus = 10.0;       // 稀有边奖励系数
        double ultra_rare_bonus = 50.0;      // 极稀有边奖励系数
        double fresh_rare_bonus = 20.0;      // 新发现稀有边奖励
    } params_;
    
    // 种子评分缓存
    mutable std::unordered_map<size_t, double> seed_score_cache_;
    mutable size_t cache_generation_ = 0;
    
    // 执行统计
    size_t total_executions_ = 0;
    std::chrono::system_clock::time_point stats_start_time_;
    
public:
    RareEdgeScheduler();
    
    AlgorithmInfo getInfo() const override {
        auto info = SchedulingAlgorithm::getInfo();
        info.name = "rare_edge_scheduler";
        info.description = "Scheduler prioritizing seeds that trigger rare edges";
        info.provided_info = {InfoType::Scheduling, InfoType::Coverage};
        info.required_info = {InfoType::Coverage};
        return info;
    }
    
    SchedulingOutput execute(const SchedulingInput& seeds, SharedContext& ctx) override;
    
    void updateParameters(const Parameters& params) override;
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
    // 边统计管理
    void updateEdgeStats(const CoverageInfo& coverage, size_t seed_idx);
    void updateGlobalStats(const std::vector<Seed>& seeds);
    
    // 稀有边分析
    std::vector<uint64_t> identifyRareEdges() const;
    std::vector<uint64_t> identifyUltraRareEdges() const;
    std::set<size_t> getSeedsWithRareEdges(const std::vector<Seed>& seeds) const;
    
    // 种子评分
    double calculateRareEdgeScore(const Seed& seed) const;
    double calculateEdgeRarityBonus(uint64_t edge_id) const;
    double calculateFreshnessBonus(const Seed& seed) const;
    
    // 调度策略
    size_t selectBestRareEdgeSeed(const std::vector<Seed>& seeds) const;
    size_t selectByRareEdgeProbability(const std::vector<Seed>& seeds);
    
    // 统计信息
    size_t getRareEdgeCount() const;
    size_t getUltraRareEdgeCount() const;
    double getAverageEdgeFrequency() const;

    // 从FairFuzzMutation迁移的方法
    void updateBranchFrequency(uint64_t branch_id, bool hit);
    void markSeedRareBranches(size_t seed_hash, const std::set<uint64_t>& rare_branches);
    const std::set<uint64_t>& getRareBranches() const { return rare_branches_; }
    double calculateFairnessScore(const Seed& seed) const;
    
private:
    // 缓存管理
    void invalidateCache() const;
    bool isCacheValid() const;
    
    // 概率计算
    std::vector<double> calculateRareEdgeProbabilities(const std::vector<Seed>& seeds) const;
    
    // 边频率更新
    void updateEdgeFrequencies();
    bool isRareEdge(uint64_t edge_id) const;
    bool isUltraRareEdge(uint64_t edge_id) const;
    
    // 种子过滤
    std::vector<size_t> filterSeedsByRareEdges(const std::vector<Seed>& seeds) const;
};

// 稀有边发现策略
class RareEdgeDiscoveryStrategy {
public:
    enum class DiscoveryMode {
        CONSERVATIVE,  // 保守模式：只关注已知稀有边
        AGGRESSIVE,    // 激进模式：积极探索新稀有边
        BALANCED      // 平衡模式：兼顾已知和探索
    };
    
private:
    DiscoveryMode mode_ = DiscoveryMode::BALANCED;
    double exploration_ratio_ = 0.3; // 探索vs利用比例
    
public:
    DiscoveryMode getMode() const { return mode_; }
    void setMode(DiscoveryMode mode) { mode_ = mode; }
    
    double getExplorationRatio() const { return exploration_ratio_; }
    void setExplorationRatio(double ratio) { exploration_ratio_ = ratio; }
    
    // 根据策略调整种子选择
    size_t selectSeed(const std::vector<Seed>& seeds, 
                     const std::set<size_t>& rare_edge_seeds,
                     const RareEdgeScheduler& scheduler) const;
};

// 边覆盖率跟踪器
class EdgeCoverageTracker {
private:
    std::unordered_map<uint64_t, size_t> edge_hit_counts_;
    std::set<uint64_t> discovered_edges_;
    size_t total_executions_ = 0;
    
public:
    void recordExecution(const CoverageInfo& coverage);
    void recordEdgeHit(uint64_t edge_id);
    
    double getEdgeFrequency(uint64_t edge_id) const;
    size_t getEdgeHitCount(uint64_t edge_id) const;
    size_t getTotalExecutions() const { return total_executions_; }
    
    std::vector<uint64_t> getRareEdges(double threshold) const;
    std::set<uint64_t> getAllDiscoveredEdges() const { return discovered_edges_; }
    
    void reset();
    void mergeStats(const EdgeCoverageTracker& other);
};

} // namespace triofuzz 