#include "../../../include/algorithms/scheduling/rare_edge_scheduler.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <cstring>

namespace triofuzz {

RareEdgeScheduler::RareEdgeScheduler() {
    stats_start_time_ = std::chrono::system_clock::now();
}

SchedulingOutput RareEdgeScheduler::execute(const SchedulingInput& seeds, SharedContext& ctx) {
    return measureExecution([&]() {
        if (seeds.empty()) {
            throw std::runtime_error("No seeds available for rare edge scheduling");
        }
        
        // Update global statistics
        updateGlobalStats(seeds);
        
        // If total executions are insufficient, use random scheduling
        if (total_executions_ < params_.min_executions) {
            std::uniform_int_distribution<size_t> dist(0, seeds.size() - 1);
            size_t selected_idx = dist(random_gen_);
            
            // Update statistics
            total_executions_++;
            updateEdgeStats(seeds[selected_idx].coverage, selected_idx);
            
            return seeds[selected_idx];
        }
        
        // Update edge frequencies
        updateEdgeFrequencies();
        
        // Get seeds that contain rare edges
        auto rare_edge_seeds = getSeedsWithRareEdges(seeds);
        
        size_t selected_idx;
        if (!rare_edge_seeds.empty()) {
            // Prefer selecting from rare-edge seeds
            selected_idx = selectByRareEdgeProbability(seeds);
        } else {
            // If there are no rare-edge seeds, pick the most promising seed
            selected_idx = selectBestRareEdgeSeed(seeds);
        }
        
        // Update statistics
        total_executions_++;
        updateEdgeStats(seeds[selected_idx].coverage, selected_idx);
        
        // Update context
        SchedulingInfo scheduling_info;
        scheduling_info.selected_seed_index = selected_idx;
        scheduling_info.rare_edge_count = getRareEdgeCount();
        scheduling_info.ultra_rare_edge_count = getUltraRareEdgeCount();
        scheduling_info.average_edge_frequency = getAverageEdgeFrequency();
        ctx.setSchedulingInfo(scheduling_info);
        
        return seeds[selected_idx];
    });
}

void RareEdgeScheduler::updateGlobalStats(const std::vector<Seed>& seeds) {
    for (size_t i = 0; i < seeds.size(); ++i) {
        updateEdgeStats(seeds[i].coverage, i);
    }
}

void RareEdgeScheduler::updateEdgeStats(const CoverageInfo& coverage, size_t seed_idx) {
    auto now = std::chrono::system_clock::now();
    
    // Update covered-edge statistics
    for (uint64_t edge_id : coverage.covered_edges) {
        auto& stats = global_edge_stats_[edge_id];
        stats.edge_id = edge_id;
        stats.hit_count++;
        stats.triggering_seeds.insert(seed_idx);
        stats.last_hit = now;
        
        if (stats.hit_count == 1) {
            stats.first_hit = now;
        }
    }
    
    // Update rare-edge statistics
    for (uint64_t edge_id : coverage.rare_edges) {
        auto& stats = global_edge_stats_[edge_id];
        stats.edge_id = edge_id;
        stats.hit_count++;
        stats.triggering_seeds.insert(seed_idx);
        stats.last_hit = now;
        
        if (stats.hit_count == 1) {
            stats.first_hit = now;
        }
    }
    
    // Invalidate cache
    invalidateCache();
}

void RareEdgeScheduler::updateEdgeFrequencies() {
    if (total_executions_ == 0) return;
    
    for (auto& [edge_id, stats] : global_edge_stats_) {
        stats.hit_frequency = static_cast<double>(stats.hit_count) / total_executions_;
    }
}

std::vector<uint64_t> RareEdgeScheduler::identifyRareEdges() const {
    std::vector<uint64_t> rare_edges;
    
    for (const auto& [edge_id, stats] : global_edge_stats_) {
        if (stats.hit_frequency <= params_.rare_threshold && stats.hit_frequency > 0) {
            rare_edges.push_back(edge_id);
        }
    }
    
    return rare_edges;
}

std::vector<uint64_t> RareEdgeScheduler::identifyUltraRareEdges() const {
    std::vector<uint64_t> ultra_rare_edges;
    
    for (const auto& [edge_id, stats] : global_edge_stats_) {
        if (stats.hit_frequency <= params_.ultra_rare_threshold && stats.hit_frequency > 0) {
            ultra_rare_edges.push_back(edge_id);
        }
    }
    
    return ultra_rare_edges;
}

std::set<size_t> RareEdgeScheduler::getSeedsWithRareEdges(const std::vector<Seed>& seeds) const {
    std::set<size_t> rare_edge_seeds;
    auto rare_edges = identifyRareEdges();
    
    for (size_t i = 0; i < seeds.size(); ++i) {
        const auto& seed = seeds[i];
        
        // Check whether the seed contains rare edges
        for (uint64_t edge_id : seed.coverage.rare_edges) {
            if (std::find(rare_edges.begin(), rare_edges.end(), edge_id) != rare_edges.end()) {
                rare_edge_seeds.insert(i);
                break;
            }
        }
        
        // Check whether any covered edges are rare
        for (uint64_t edge_id : seed.coverage.covered_edges) {
            if (std::find(rare_edges.begin(), rare_edges.end(), edge_id) != rare_edges.end()) {
                rare_edge_seeds.insert(i);
                break;
            }
        }
    }
    
    return rare_edge_seeds;
}

double RareEdgeScheduler::calculateRareEdgeScore(const Seed& seed) const {
    // Check cache
    // Use a simple hash to avoid std::hash issues
    size_t seed_hash = 0;
    for (size_t i = 0; i < seed.data.size(); ++i) {
        seed_hash = seed_hash * 31 + seed.data[i];
    }
    
    if (isCacheValid() && seed_score_cache_.count(seed_hash)) {
        return seed_score_cache_[seed_hash];
    }
    
    double score = 0.0;
    
    // Base coverage score
    score += seed.coverage.coverage_gain * 5.0;
    
    // Rare-edge bonus
    for (uint64_t edge_id : seed.coverage.rare_edges) {
        score += calculateEdgeRarityBonus(edge_id);
    }
    
    // Rare-edge bonus among covered edges
    for (uint64_t edge_id : seed.coverage.covered_edges) {
        if (isRareEdge(edge_id)) {
            score += calculateEdgeRarityBonus(edge_id);
        }
    }
    
    // Freshness bonus
    score += calculateFreshnessBonus(seed);
    
    // Path depth bonus (moderate)
    score += std::log(1.0 + seed.coverage.path_depth) * 2.0;
    
    // Cache result
    seed_score_cache_[seed_hash] = score;
    
    return score;
}

double RareEdgeScheduler::calculateEdgeRarityBonus(uint64_t edge_id) const {
    auto it = global_edge_stats_.find(edge_id);
    if (it == global_edge_stats_.end()) {
        return 0.0;
    }
    
    const auto& stats = it->second;
    double bonus = 0.0;
    
    if (isUltraRareEdge(edge_id)) {
        bonus = params_.ultra_rare_bonus;
    } else if (isRareEdge(edge_id)) {
        bonus = params_.rare_edge_bonus;
    }
    
    // Adjust bonus by frequency (lower frequency => higher bonus)
    if (stats.hit_frequency > 0) {
        bonus *= (1.0 / stats.hit_frequency);
    }
    
    return bonus;
}

double RareEdgeScheduler::calculateFreshnessBonus(const Seed& seed) const {
    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::hours>(now - seed.created_time);
    
    // New seeds get a bonus that linearly decays over 24 hours
    double hours = age.count();
    if (hours < 24.0) {
        return params_.fresh_rare_bonus * (1.0 - hours / 24.0);
    }
    
    return 0.0;
}

size_t RareEdgeScheduler::selectBestRareEdgeSeed(const std::vector<Seed>& seeds) const {
    double best_score = -1.0;
    size_t best_idx = 0;
    
    for (size_t i = 0; i < seeds.size(); ++i) {
        double score = calculateRareEdgeScore(seeds[i]);
        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    
    return best_idx;
}

size_t RareEdgeScheduler::selectByRareEdgeProbability(const std::vector<Seed>& seeds) {
    auto probabilities = calculateRareEdgeProbabilities(seeds);
    
    // Roulette-wheel selection
    double total_prob = std::accumulate(probabilities.begin(), probabilities.end(), 0.0);
    
    if (total_prob <= 0.0) {
        // Fall back to best-seed selection
        return selectBestRareEdgeSeed(seeds);
    }
    
    std::uniform_real_distribution<double> dist(0.0, total_prob);
    double random_point = dist(random_gen_);
    
    double cumulative = 0.0;
    for (size_t i = 0; i < probabilities.size(); ++i) {
        cumulative += probabilities[i];
        if (random_point <= cumulative) {
            return i;
        }
    }
    
    return seeds.size() - 1;
}

std::vector<double> RareEdgeScheduler::calculateRareEdgeProbabilities(const std::vector<Seed>& seeds) const {
    std::vector<double> probabilities;
    probabilities.reserve(seeds.size());
    
    // Compute each seed's rare-edge score
    for (const auto& seed : seeds) {
        double prob = calculateRareEdgeScore(seed);
        probabilities.push_back(std::max(0.1, prob)); // Minimum probability: 0.1
    }
    
    return probabilities;
}

bool RareEdgeScheduler::isRareEdge(uint64_t edge_id) const {
    auto it = global_edge_stats_.find(edge_id);
    if (it == global_edge_stats_.end()) {
        return false;
    }
    
    return it->second.hit_frequency <= params_.rare_threshold && it->second.hit_frequency > 0;
}

bool RareEdgeScheduler::isUltraRareEdge(uint64_t edge_id) const {
    auto it = global_edge_stats_.find(edge_id);
    if (it == global_edge_stats_.end()) {
        return false;
    }
    
    return it->second.hit_frequency <= params_.ultra_rare_threshold && it->second.hit_frequency > 0;
}

std::vector<size_t> RareEdgeScheduler::filterSeedsByRareEdges(const std::vector<Seed>& seeds) const {
    std::vector<size_t> filtered_indices;
    auto rare_edge_seeds = getSeedsWithRareEdges(seeds);
    
    for (size_t idx : rare_edge_seeds) {
        filtered_indices.push_back(idx);
    }
    
    return filtered_indices;
}

size_t RareEdgeScheduler::getRareEdgeCount() const {
    return identifyRareEdges().size();
}

size_t RareEdgeScheduler::getUltraRareEdgeCount() const {
    return identifyUltraRareEdges().size();
}

double RareEdgeScheduler::getAverageEdgeFrequency() const {
    if (global_edge_stats_.empty()) {
        return 0.0;
    }
    
    double total_frequency = 0.0;
    for (const auto& [edge_id, stats] : global_edge_stats_) {
        total_frequency += stats.hit_frequency;
    }
    
    return total_frequency / global_edge_stats_.size();
}

void RareEdgeScheduler::invalidateCache() const {
    cache_generation_++;
    seed_score_cache_.clear();
}

bool RareEdgeScheduler::isCacheValid() const {
    // Simple cache validity check
    return !seed_score_cache_.empty();
}

void RareEdgeScheduler::updateParameters(const Parameters& params) {
    SchedulingAlgorithm::updateParameters(params);
    
    auto rare_threshold = params.get<double>("rare_threshold");
    if (rare_threshold.has_value()) params_.rare_threshold = rare_threshold.value();
    
    auto ultra_rare_threshold = params.get<double>("ultra_rare_threshold");
    if (ultra_rare_threshold.has_value()) params_.ultra_rare_threshold = ultra_rare_threshold.value();
    
    auto min_executions = params.get<size_t>("min_executions");
    if (min_executions.has_value()) params_.min_executions = min_executions.value();
    
    auto rare_edge_bonus = params.get<double>("rare_edge_bonus");
    if (rare_edge_bonus.has_value()) params_.rare_edge_bonus = rare_edge_bonus.value();
    
    auto ultra_rare_bonus = params.get<double>("ultra_rare_bonus");
    if (ultra_rare_bonus.has_value()) params_.ultra_rare_bonus = ultra_rare_bonus.value();
    
    auto fresh_rare_bonus = params.get<double>("fresh_rare_bonus");
    if (fresh_rare_bonus.has_value()) params_.fresh_rare_bonus = fresh_rare_bonus.value();
    
    // Invalidate cache
    invalidateCache();
}

void RareEdgeScheduler::saveState(StateWriter& writer) const {
    // Save parameters
    writer.writeDouble("rare_threshold", params_.rare_threshold);
    writer.writeDouble("ultra_rare_threshold", params_.ultra_rare_threshold);
    writer.writeInt("min_executions", params_.min_executions);
    writer.writeDouble("rare_edge_bonus", params_.rare_edge_bonus);
    writer.writeDouble("ultra_rare_bonus", params_.ultra_rare_bonus);
    writer.writeDouble("fresh_rare_bonus", params_.fresh_rare_bonus);
    
    // Save statistics
    writer.writeInt("total_executions", total_executions_);
    writer.writeInt("cache_generation", cache_generation_);
    
    // Save edge statistics (simplified; only key fields)
    std::vector<uint8_t> edge_stats_data;
    for (const auto& [edge_id, stats] : global_edge_stats_) {
        // Serialize edge stats (simplified)
        edge_stats_data.insert(edge_stats_data.end(), 
                              reinterpret_cast<const uint8_t*>(&edge_id),
                              reinterpret_cast<const uint8_t*>(&edge_id) + sizeof(edge_id));
        edge_stats_data.insert(edge_stats_data.end(),
                              reinterpret_cast<const uint8_t*>(&stats.hit_count),
                              reinterpret_cast<const uint8_t*>(&stats.hit_count) + sizeof(stats.hit_count));
    }
    writer.writeBytes("edge_stats", edge_stats_data);
}

void RareEdgeScheduler::loadState(StateReader& reader) {
    // Load parameters
    auto rare_threshold = reader.readDouble("rare_threshold");
    if (rare_threshold.has_value()) params_.rare_threshold = rare_threshold.value();
    
    auto ultra_rare_threshold = reader.readDouble("ultra_rare_threshold");
    if (ultra_rare_threshold.has_value()) params_.ultra_rare_threshold = ultra_rare_threshold.value();
    
    auto min_executions = reader.readInt("min_executions");
    if (min_executions.has_value()) params_.min_executions = min_executions.value();
    
    auto rare_edge_bonus = reader.readDouble("rare_edge_bonus");
    if (rare_edge_bonus.has_value()) params_.rare_edge_bonus = rare_edge_bonus.value();
    
    auto ultra_rare_bonus = reader.readDouble("ultra_rare_bonus");
    if (ultra_rare_bonus.has_value()) params_.ultra_rare_bonus = ultra_rare_bonus.value();
    
    auto fresh_rare_bonus = reader.readDouble("fresh_rare_bonus");
    if (fresh_rare_bonus.has_value()) params_.fresh_rare_bonus = fresh_rare_bonus.value();
    
    // Load statistics
    auto total_executions = reader.readInt("total_executions");
    if (total_executions.has_value()) total_executions_ = total_executions.value();
    
    auto cache_generation = reader.readInt("cache_generation");
    if (cache_generation.has_value()) cache_generation_ = cache_generation.value();
    
    // Load edge statistics (simplified)
    auto edge_stats_data = reader.readBytes("edge_stats");
    if (edge_stats_data.has_value()) {
        const auto& data = edge_stats_data.value();
        size_t pos = 0;
        
        while (pos + sizeof(uint64_t) + sizeof(size_t) <= data.size()) {
            uint64_t edge_id;
            size_t hit_count;
            
            memcpy(&edge_id, &data[pos], sizeof(edge_id));
            pos += sizeof(edge_id);
            
            memcpy(&hit_count, &data[pos], sizeof(hit_count));
            pos += sizeof(hit_count);
            
            auto& stats = global_edge_stats_[edge_id];
            stats.edge_id = edge_id;
            stats.hit_count = hit_count;
        }
    }
    
    // Recompute frequencies
    updateEdgeFrequencies();
}

// EdgeCoverageTracker implementation
void EdgeCoverageTracker::recordExecution(const CoverageInfo& coverage) {
    total_executions_++;
    
    for (uint64_t edge_id : coverage.covered_edges) {
        recordEdgeHit(edge_id);
    }
}

void EdgeCoverageTracker::recordEdgeHit(uint64_t edge_id) {
    edge_hit_counts_[edge_id]++;
    discovered_edges_.insert(edge_id);
}

double EdgeCoverageTracker::getEdgeFrequency(uint64_t edge_id) const {
    auto it = edge_hit_counts_.find(edge_id);
    if (it == edge_hit_counts_.end() || total_executions_ == 0) {
        return 0.0;
    }
    
    return static_cast<double>(it->second) / total_executions_;
}

size_t EdgeCoverageTracker::getEdgeHitCount(uint64_t edge_id) const {
    auto it = edge_hit_counts_.find(edge_id);
    return (it != edge_hit_counts_.end()) ? it->second : 0;
}

std::vector<uint64_t> EdgeCoverageTracker::getRareEdges(double threshold) const {
    std::vector<uint64_t> rare_edges;
    
    for (const auto& [edge_id, hit_count] : edge_hit_counts_) {
        double frequency = static_cast<double>(hit_count) / total_executions_;
        if (frequency <= threshold && frequency > 0) {
            rare_edges.push_back(edge_id);
        }
    }
    
    return rare_edges;
}

void EdgeCoverageTracker::reset() {
    edge_hit_counts_.clear();
    discovered_edges_.clear();
    total_executions_ = 0;
}

void EdgeCoverageTracker::mergeStats(const EdgeCoverageTracker& other) {
    total_executions_ += other.total_executions_;
    
    for (const auto& [edge_id, hit_count] : other.edge_hit_counts_) {
        edge_hit_counts_[edge_id] += hit_count;
        discovered_edges_.insert(edge_id);
    }
}

} // namespace triofuzz 
