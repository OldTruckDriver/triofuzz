#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include "scheduling_algorithms.hpp"
#include <unordered_map>
#include <set>
#include <queue>

namespace triofuzz {

// Rare-edge-prioritizing scheduler
class RareEdgeScheduler : public SchedulingAlgorithm {
private:
    // Edge/branch frequency stats (shared for edges and branches).
    struct EdgeStats {
        uint64_t edge_id;
        size_t hit_count = 0;
        double hit_frequency = 0.0;
        double rarity_score = 0.0;  // Rarity score (migrated from FairFuzz)
        bool is_rare = false;        // Is rare edge?
        std::set<size_t> triggering_seeds; // Seeds that trigger this edge
        std::chrono::system_clock::time_point first_hit;
        std::chrono::system_clock::time_point last_hit;
    };

    // Global edge stats
    std::unordered_map<uint64_t, EdgeStats> global_edge_stats_;

    // Branch frequency stats (migrated from FairFuzzMutation)
    std::unordered_map<uint64_t, EdgeStats> branch_frequencies_;

    // Set of rare branches (migrated from FairFuzzMutation)
    std::set<uint64_t> rare_branches_;

    // Mapping from seed to rare branches (migrated from FairFuzzMutation)
    std::unordered_map<size_t, std::set<uint64_t>> seed_rare_branches_;
    
    // Rare-edge threshold parameters
    struct RareEdgeParams {
        double rare_threshold = 0.01;        // Rare-edge threshold (<1%)
        double ultra_rare_threshold = 0.001; // Ultra-rare threshold (<0.1%)
        size_t min_executions = 1000;        // Minimum executions before collecting stats
        double rare_edge_bonus = 10.0;       // Rare-edge bonus factor
        double ultra_rare_bonus = 50.0;      // Ultra-rare bonus factor
        double fresh_rare_bonus = 20.0;      // Bonus for newly discovered rare edges
    } params_;
    
    // Seed score cache
    mutable std::unordered_map<size_t, double> seed_score_cache_;
    mutable size_t cache_generation_ = 0;
    
    // Execution stats
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
    
    // Edge stats management
    void updateEdgeStats(const CoverageInfo& coverage, size_t seed_idx);
    void updateGlobalStats(const std::vector<Seed>& seeds);
    
    // Rare-edge analysis
    std::vector<uint64_t> identifyRareEdges() const;
    std::vector<uint64_t> identifyUltraRareEdges() const;
    std::set<size_t> getSeedsWithRareEdges(const std::vector<Seed>& seeds) const;
    
    // Seed scoring
    double calculateRareEdgeScore(const Seed& seed) const;
    double calculateEdgeRarityBonus(uint64_t edge_id) const;
    double calculateFreshnessBonus(const Seed& seed) const;
    
    // Scheduling strategy
    size_t selectBestRareEdgeSeed(const std::vector<Seed>& seeds) const;
    size_t selectByRareEdgeProbability(const std::vector<Seed>& seeds);
    
    // Statistics
    size_t getRareEdgeCount() const;
    size_t getUltraRareEdgeCount() const;
    double getAverageEdgeFrequency() const;

    // Methods migrated from FairFuzzMutation
    void updateBranchFrequency(uint64_t branch_id, bool hit);
    void markSeedRareBranches(size_t seed_hash, const std::set<uint64_t>& rare_branches);
    const std::set<uint64_t>& getRareBranches() const { return rare_branches_; }
    double calculateFairnessScore(const Seed& seed) const;
    
private:
    // Cache management
    void invalidateCache() const;
    bool isCacheValid() const;
    
    // Probability calculation
    std::vector<double> calculateRareEdgeProbabilities(const std::vector<Seed>& seeds) const;
    
    // Edge frequency update
    void updateEdgeFrequencies();
    bool isRareEdge(uint64_t edge_id) const;
    bool isUltraRareEdge(uint64_t edge_id) const;
    
    // Seed filtering
    std::vector<size_t> filterSeedsByRareEdges(const std::vector<Seed>& seeds) const;
};

// Rare-edge discovery strategy
class RareEdgeDiscoveryStrategy {
public:
    enum class DiscoveryMode {
        CONSERVATIVE,  // Conservative: focus on known rare edges
        AGGRESSIVE,    // Aggressive: explore new rare edges
        BALANCED      // Balanced: combine known and exploration
    };
    
private:
    DiscoveryMode mode_ = DiscoveryMode::BALANCED;
    double exploration_ratio_ = 0.3; // Exploration vs exploitation ratio
    
public:
    DiscoveryMode getMode() const { return mode_; }
    void setMode(DiscoveryMode mode) { mode_ = mode; }
    
    double getExplorationRatio() const { return exploration_ratio_; }
    void setExplorationRatio(double ratio) { exploration_ratio_ = ratio; }
    
    // Select seed based on strategy
    size_t selectSeed(const std::vector<Seed>& seeds, 
                     const std::set<size_t>& rare_edge_seeds,
                     const RareEdgeScheduler& scheduler) const;
};

// Edge coverage tracker
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
