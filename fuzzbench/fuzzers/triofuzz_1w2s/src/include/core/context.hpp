#pragma once

#include <any>
#include <map>
#include <string>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <bitset>
#include <cstdint>
#include <functional>
#include "../types/contraint_types.hpp"

namespace triofuzz {

// Forward declaration
struct Seed;

// ---------------------------------------------------------------------------
// Hint Bus: lightweight, general-purpose inter-algorithm hints for cooperation
// ---------------------------------------------------------------------------
// The HintBus aggregates lightweight signals that mutation algorithms can
// produce/consume within a single sequential composition to coordinate edits
// without heavy instrumentation. It is format-agnostic and safe for single
// thread use (SharedContext already provides synchronization when needed).
struct HintBus {
    // Bytes that should be modified cautiously (1 = protected, 0 = free). Size
    // should match current input length when applicable. Empty means no mask.
    std::vector<uint8_t> protected_mask;

    // Per-byte importance/heat score in [0, +inf). Empty means unknown.
    std::vector<double> byte_importance;

    // Token pool discovered from corpus/current input (generic byte tokens).
    std::vector<std::vector<uint8_t>> token_pool;

    // Candidate numeric constants (e.g., boundary values, cmp-like hints).
    std::vector<uint64_t> candidate_constants;

    // Global step size suggestion for numeric tweaks. Optional per-region
    // overrides below. A value of 1.0 means neutral.
    double step_size = 1.0;
    std::vector<double> step_size_per_region; // optional, same length as input

    // Lineage of algorithms executed in current sequential chain, in order.
    std::vector<std::string> lineage;

    void clear() {
        protected_mask.clear();
        byte_importance.clear();
        token_pool.clear();
        candidate_constants.clear();
        step_size = 1.0;
        step_size_per_region.clear();
        lineage.clear();
    }

    // Ensure mask/importance vectors have given size; other fields untouched.
    void ensureSize(size_t n) {
        if (protected_mask.size() != n) protected_mask.assign(n, 0);
        if (byte_importance.size() != n) byte_importance.assign(n, 0.0);
        if (step_size_per_region.size() == n) {
            // ok
        } else if (!step_size_per_region.empty()) {
            step_size_per_region.resize(n, step_size);
        }
    }
};

// Gradient information
struct GradientInfo {
    std::vector<double> gradients;      // Gradient value at each byte position
    std::vector<size_t> positions;      // Positions with valid gradients
    double learning_rate = 0.01;        // Learning rate
    double momentum = 0.9;              // Momentum
    std::vector<double> velocity;       // Momentum velocity
    
    // Get gradient at a specific position
    double getGradient(size_t pos) const {
        auto it = std::find(positions.begin(), positions.end(), pos);
        if (it != positions.end()) {
            size_t idx = std::distance(positions.begin(), it);
            return gradients[idx];
        }
        return 0.0;
    }
    
    // Apply gradients to the input
    void applyToInput(std::vector<uint8_t>& input, double step_size = 1.0) const {
        for (size_t i = 0; i < positions.size(); ++i) {
            if (positions[i] < input.size()) {
                double delta = gradients[i] * learning_rate * step_size;
                int new_val = static_cast<int>(input[positions[i]]) + static_cast<int>(delta);
                new_val = std::max(0, std::min(255, new_val));
                input[positions[i]] = static_cast<uint8_t>(new_val);
            }
        }
    }
};

// Constraint information
struct ConstraintInfo {
    std::vector<std::shared_ptr<Constraint>> path_constraints;   // Path constraints
    std::vector<SymbolicExprPtr> symbolic_values;  // Symbolic values
    std::map<size_t, std::vector<uint8_t>> concrete_values; // Concrete values from constraint solving
    
    // CmpLog-related fields
    std::vector<std::shared_ptr<Constraint>> constraints;  // All constraints
    double constraint_score = 0.0;                        // Constraint score
    size_t solvable_count = 0;                            // Number of solvable constraints
    
    bool has_solution = false;
    double solving_time_ms = 0.0;
};

// Coverage information
struct CoverageInfo {
    static constexpr size_t MAP_SIZE = 65536;
    
    std::bitset<MAP_SIZE> bitmap;              // Coverage bitmap
    std::vector<uint64_t> new_edges;            // Newly discovered edges
    std::vector<uint64_t> rare_edges;           // Rare edges (low execution count)
    std::vector<uint64_t> covered_edges;        // Covered edges
    double coverage_gain = 0.0;                 // Coverage gain
    size_t total_edges = 0;                     // Total number of edges
    size_t path_depth = 0;                      // Path depth
    
    // Branch coverage stats (new)
    std::vector<uint64_t> new_branches;         // Newly discovered branches
    std::vector<uint64_t> covered_branches;     // Covered branches
    std::vector<uint64_t> taken_branches;       // Taken branches
    std::vector<uint64_t> not_taken_branches;   // Not-taken branches
    std::vector<uint64_t> rare_branches;        // Rare branches (for inter-component communication)
    size_t total_branches = 0;                  // Total number of branches
    size_t covered_branch_count = 0;            // Number of covered branches
    double branch_coverage_gain = 0.0;          // Branch coverage gain
    
    // Enhanced coverage analysis fields
    std::vector<uint64_t> context_sensitive_edges; // Context-sensitive edges
    double coverage_quality_score = 0.0;        // Overall coverage quality score
    double immediate_value = 0.0;               // Immediate value
    double long_term_potential = 0.0;           // Long-term potential
    double exploration_value = 0.0;             // Exploration value
    double context_novelty = 0.0;               // Context novelty
    double path_diversity = 0.0;                // Path diversity
    
    // Compute coverage percentage
    double getCoveragePercentage() const {
        return (total_edges > 0) ? (bitmap.count() * 100.0 / total_edges) : 0.0;
    }
    
    // Compute branch coverage percentage - fix: use covered_branch_count for consistency.
    double getBranchCoveragePercentage() const {
        // Use covered_branch_count rather than covered_branches.size(), because covered_branch_count
        // is the verified, aggregated value while covered_branches may contain duplicates/invalid IDs.
        return (total_branches > 0) ? (covered_branch_count * 100.0 / total_branches) : 0.0;
    }
    
    // Check for new coverage
    bool hasNewCoverage() const {
        return !new_edges.empty() || !new_branches.empty();
    }
    
    // Check for new branch coverage (new)
    bool hasNewBranchCoverage() const {
        return !new_branches.empty();
    }
    
    // Merge another coverage info (improvement: added merge method).
    void merge(const CoverageInfo& other) {
        bitmap |= other.bitmap;
        total_edges = std::max(total_edges, other.total_edges);
        
        // Merge edge information
        for (auto edge : other.new_edges) {
            if (std::find(new_edges.begin(), new_edges.end(), edge) == new_edges.end()) {
                new_edges.push_back(edge);
            }
        }
        
        for (auto edge : other.covered_edges) {
            if (std::find(covered_edges.begin(), covered_edges.end(), edge) == covered_edges.end()) {
                covered_edges.push_back(edge);
            }
        }
        
        // Merge branch information
        for (auto branch : other.new_branches) {
            if (std::find(new_branches.begin(), new_branches.end(), branch) == new_branches.end()) {
                new_branches.push_back(branch);
            }
        }
        
        // Update coverage gains
        coverage_gain = std::max(coverage_gain, other.coverage_gain);
        branch_coverage_gain = std::max(branch_coverage_gain, other.branch_coverage_gain);
    }
};

// Taint information
struct TaintInfo {
    std::vector<size_t> tainted_offsets;        // Tainted offsets
    std::map<size_t, std::vector<size_t>> taint_flow; // Taint flow
    std::vector<std::pair<size_t, size_t>> critical_bytes; // Critical byte pairs
    
    // Check whether an offset is tainted
    bool isTainted(size_t offset) const {
        return std::find(tainted_offsets.begin(), tainted_offsets.end(), offset) 
               != tainted_offsets.end();
    }
};

// Performance information
struct PerformanceInfo {
    double execution_time_ms = 0.0;             // Execution time
    size_t memory_usage_bytes = 0;              // Memory usage
    size_t peak_memory_bytes = 0;               // Peak memory
    size_t syscall_count = 0;                   // System call count
    std::map<std::string, size_t> syscall_histogram; // System call histogram
    
    // Compute execution speed (exec/s)
    double getExecPerSec() const {
        return (execution_time_ms > 0) ? (1000.0 / execution_time_ms) : 0.0;
    }
};

// Energy information
struct EnergyInfo {
    double current_energy = 1.0;                // Current energy
    double base_energy = 1.0;                   // Base energy
    std::map<std::string, double> energy_factors; // Energy factors
    
    // Compute final energy
    double computeFinalEnergy() const {
        double final_energy = base_energy;
        for (const auto& [factor, value] : energy_factors) {
            final_energy *= value;
        }
        return final_energy * current_energy;
    }
};

// Scheduling information
struct SchedulingInfo {
    size_t selected_seed_index = 0;          // Selected seed index
    double coverage_gain_prediction = 0.0;   // Predicted coverage gain
    std::string scheduling_mode;              // Scheduling mode
    double energy_score = 1.0;               // Energy score
    size_t rare_edge_count = 0;              // Rare edge count
    size_t ultra_rare_edge_count = 0;        // Ultra-rare edge count
    double average_edge_frequency = 0.0;     // Average edge frequency
};

// Data-flow information
struct DataFlowInfo {
    std::vector<uint64_t> operations;        // Data-flow operation addresses
    size_t vulnerability_count = 0;          // Vulnerability count
    double taint_coverage = 0.0;             // Taint coverage
    std::map<std::string, size_t> vuln_types; // Vulnerability type stats
};

// Trace information
struct TraceInfo {
    std::vector<uint64_t> control_flow_events; // Control-flow event addresses
    size_t anomaly_count = 0;                 // Anomaly count
    double anomaly_score = 0.0;               // Anomaly score
    std::vector<std::string> anomaly_types;   // Anomaly types
};

// Target program information
struct TargetInfo {
    std::string target_path;                  // Target program path
    std::vector<std::string> args;            // Command-line arguments
    std::string working_dir;                  // Working directory
    std::map<std::string, std::string> env_vars; // Environment variables
    std::chrono::milliseconds timeout{5000}; // Execution timeout
    size_t memory_limit_mb = 1024;           // Memory limit
};

// Shared context
class SharedContext {
private:
    mutable std::shared_mutex mutex_;
    std::map<std::string, std::any> data_;
    
    // Subscription mechanism
    std::map<std::string, std::vector<std::function<void(const std::any&)>>> subscribers_;
    
public:
    // Set value
    template<typename T>
    void set(const std::string& key, T&& value) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        data_[key] = std::forward<T>(value);
        
        // Notify subscribers
        auto it = subscribers_.find(key);
        if (it != subscribers_.end()) {
            for (const auto& callback : it->second) {
                callback(data_[key]);
            }
        }
    }
    
    // Get value
    template<typename T>
    std::optional<T> get(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = data_.find(key);
        if (it != data_.end()) {
            try {
                return std::any_cast<T>(it->second);
            } catch (const std::bad_any_cast&) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }
    
    // Thread-safe data access via callback to avoid race conditions
    template<typename T, typename Func>
    auto withData(const std::string& key, Func&& callback) const -> decltype(callback(std::declval<const T&>())) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = data_.find(key);
        if (it != data_.end()) {
            try {
                const T& data = std::any_cast<const T&>(it->second);
                return callback(data);
            } catch (const std::bad_any_cast&) {
                // Return default-constructed result
                using ReturnType = decltype(callback(std::declval<const T&>()));
                return ReturnType{};
            }
        }
        // Return default-constructed result
        using ReturnType = decltype(callback(std::declval<const T&>()));
        return ReturnType{};
    }
    
    // Specialized helper for safe corpus access
    template<typename Func>
    auto withCorpusData(Func&& callback) const -> decltype(callback(std::declval<const std::vector<std::vector<uint8_t>>&>())) {
        return withData<std::vector<std::vector<uint8_t>>>("corpus", std::forward<Func>(callback));
    }
    
    // Thread-safe corpus set/access - use shared_ptr to keep lifetime safe
    void setCorpusSafe(const std::vector<std::vector<uint8_t>>& corpus_data) {
        auto shared_corpus = std::make_shared<std::vector<std::vector<uint8_t>>>();
        
        // Copy data safely to avoid race conditions.
        try {
            shared_corpus->reserve(corpus_data.size());
            for (const auto& item : corpus_data) {
                shared_corpus->emplace_back(item); // Deep-copy each entry
            }
        } catch (const std::exception& e) {
            // If copying fails, create an empty shared pointer.
            shared_corpus = std::make_shared<std::vector<std::vector<uint8_t>>>();
        }
        
        std::unique_lock<std::shared_mutex> lock(mutex_);
        data_["corpus_safe"] = shared_corpus;
    }
    
    template<typename Func>
    auto withCorpusDataSafe(Func&& callback) const -> decltype(callback(std::declval<const std::vector<std::vector<uint8_t>>&>())) {
        std::shared_ptr<std::vector<std::vector<uint8_t>>> shared_corpus;
        
        // Get the shared pointer under lock.
        {
            std::shared_lock<std::shared_mutex> lock(mutex_);
            auto it = data_.find("corpus_safe");
            if (it != data_.end()) {
                try {
                    shared_corpus = std::any_cast<std::shared_ptr<std::vector<std::vector<uint8_t>>>>(it->second);
                } catch (const std::bad_any_cast&) {
                    // Type cast failed; return default value.
                    using ReturnType = decltype(callback(std::declval<const std::vector<std::vector<uint8_t>>&>()));
                    return ReturnType{};
                }
            }
        } // Lock released
        
        // Invoke callback outside the lock; shared_ptr ensures validity.
        if (shared_corpus && !shared_corpus->empty()) {
            try {
                return callback(*shared_corpus);
            } catch (const std::exception& e) {
                // Callback failed; return default value.
                using ReturnType = decltype(callback(std::declval<const std::vector<std::vector<uint8_t>>&>()));
                return ReturnType{};
            }
        }
        
        // Return default-constructed result
        using ReturnType = decltype(callback(std::declval<const std::vector<std::vector<uint8_t>>&>()));
        return ReturnType{};
    }
    
    // Enhanced: safe corpus access with timeout
    template<typename Func>
    auto withCorpusDataSafeTimeout(Func&& callback, std::chrono::milliseconds timeout = std::chrono::milliseconds(100)) const 
        -> std::optional<decltype(callback(std::declval<const std::vector<std::vector<uint8_t>>&>()))> {
        
        std::shared_ptr<std::vector<std::vector<uint8_t>>> shared_corpus;
        
        // Try to acquire the lock within the timeout.
        {
            std::unique_lock<std::shared_mutex> lock(mutex_, std::try_to_lock);
            if (!lock.owns_lock()) {
                // If the lock is not immediately available, wait up to the timeout.
                if (!lock.try_lock_for(timeout)) {
                    return std::nullopt; // Timed out
                }
            }
            
            auto it = data_.find("corpus_safe");
            if (it != data_.end()) {
                try {
                    shared_corpus = std::any_cast<std::shared_ptr<std::vector<std::vector<uint8_t>>>>(it->second);
                } catch (const std::bad_any_cast&) {
                    return std::nullopt;
                }
            }
        } // Lock released
        
        // Invoke callback outside the lock
        if (shared_corpus && !shared_corpus->empty()) {
            try {
                return callback(*shared_corpus);
            } catch (const std::exception& e) {
                return std::nullopt;
            }
        }
        
        return std::nullopt;
    }
    
    // Atomic update
    template<typename T, typename Func>
    void update(const std::string& key, Func&& updater) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = data_.find(key);
        if (it != data_.end()) {
            try {
                T value = std::any_cast<T>(it->second);
                updater(value);
                data_[key] = value;
                
                // Notify subscribers
                auto sub_it = subscribers_.find(key);
                if (sub_it != subscribers_.end()) {
                    for (const auto& callback : sub_it->second) {
                        callback(data_[key]);
                    }
                }
            } catch (const std::bad_any_cast&) {
                // Type mismatch; ignore update.
            }
        }
    }
    
    // Check existence
    bool has(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return data_.find(key) != data_.end();
    }
    
    // Remove key
    void remove(const std::string& key) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        data_.erase(key);
    }
    
    // Clear all data
    void clear() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        data_.clear();
    }
    
    // Subscribe to updates
    void subscribe(const std::string& key, std::function<void(const std::any&)> callback) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        subscribers_[key].push_back(callback);
    }
    
    // Get all keys
    std::vector<std::string> keys() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        result.reserve(data_.size());
        for (const auto& [key, _] : data_) {
            result.push_back(key);
        }
        return result;
    }
    
    // Convenience: get gradient info
    std::optional<GradientInfo> getGradientInfo() const {
        return get<GradientInfo>("gradient_info");
    }
    
    void setGradientInfo(const GradientInfo& info) {
        set("gradient_info", info);
    }
    
    // Convenience: get constraint info
    std::optional<ConstraintInfo> getConstraintInfo() const {
        return get<ConstraintInfo>("constraint_info");
    }
    
    void setConstraintInfo(const ConstraintInfo& info) {
        set("constraint_info", info);
    }
    
    // Convenience: get coverage info
    std::optional<CoverageInfo> getCoverageInfo() const {
        return get<CoverageInfo>("coverage_info");
    }

    void setCoverageInfo(const CoverageInfo& info) {
        set("coverage_info", info);
    }

    // Convenience: get current seed info (uses std::any to avoid circular dependencies)
    template<typename T>
    std::optional<T> getCurrentSeedInfo() const {
        return get<T>("current_seed");
    }

    template<typename T>
    void setCurrentSeedInfo(const T& seed) {
        set("current_seed", seed);
    }

    // Mark deterministic stage done for the current seed.
    void markDeterministicDone() {
        // This needs to be implemented at the call site because it requires the full Seed definition.
        set("deterministic_done", true);
    }
    
    // Convenience: get taint info
    std::optional<TaintInfo> getTaintInfo() const {
        return get<TaintInfo>("taint_info");
    }
    
    void setTaintInfo(const TaintInfo& info) {
        set("taint_info", info);
    }
    
    // Convenience: get performance info
    std::optional<PerformanceInfo> getPerformanceInfo() const {
        return get<PerformanceInfo>("performance_info");
    }
    
    void setPerformanceInfo(const PerformanceInfo& info) {
        set("performance_info", info);
    }
    
    // Convenience: get energy info
    std::optional<EnergyInfo> getEnergyInfo() const {
        return get<EnergyInfo>("energy_info");
    }
    
    void setEnergyInfo(const EnergyInfo& info) {
        set("energy_info", info);
    }
    
    // Convenience: get scheduling info
    std::optional<SchedulingInfo> getSchedulingInfo() const {
        return get<SchedulingInfo>("scheduling_info");
    }
    
    void setSchedulingInfo(const SchedulingInfo& info) {
        set("scheduling_info", info);
    }
    
    // Convenience: get data-flow info
    std::optional<DataFlowInfo> getDataFlowInfo() const {
        return get<DataFlowInfo>("dataflow_info");
    }
    
    void setDataFlowInfo(const DataFlowInfo& info) {
        set("dataflow_info", info);
    }
    
    // Convenience: get trace info
    std::optional<TraceInfo> getTraceInfo() const {
        return get<TraceInfo>("trace_info");
    }
    
    void setTraceInfo(const TraceInfo& info) {
        set("trace_info", info);
    }
    
    // Convenience: get target info
    std::optional<TargetInfo> getTargetInfo() const {
        return get<TargetInfo>("target_info");
    }
    
    void setTargetInfo(const TargetInfo& info) {
        set("target_info", info);
    }

    // Convenience: access HintBus
    std::optional<HintBus> getHintBus() const {
        return get<HintBus>("hint_bus");
    }

    void setHintBus(const HintBus& hints) {
        set("hint_bus", hints);
    }

    // Initialize/reset HintBus (optional: pre-size mask/importance by input length).
    void resetHintBus(size_t input_size = 0) {
        HintBus hb;
        if (input_size > 0) {
            hb.protected_mask.assign(input_size, 0);
            hb.byte_importance.assign(input_size, 0.0);
        }
        set("hint_bus", hb);
    }
};

// Thread-local context (to avoid lock contention)
class ThreadLocalContext : public SharedContext {
private:
    SharedContext* global_context_;
    std::vector<std::string> dirty_keys_;
    
public:
    explicit ThreadLocalContext(SharedContext* global) : global_context_(global) {}
    
    // Sync local modifications to the global context.
    void sync() {
        for (const auto& key : dirty_keys_) {
            // Sync local data to global.
            auto local_data = SharedContext::get<std::any>(key);
            if (local_data.has_value()) {
                global_context_->set(key, local_data.value());
            }
        }
        dirty_keys_.clear();
    }
    
    // Override set to track dirty keys.
    template<typename T>
    void set(const std::string& key, T&& value) {
        SharedContext::set(key, std::forward<T>(value));
        if (std::find(dirty_keys_.begin(), dirty_keys_.end(), key) == dirty_keys_.end()) {
            dirty_keys_.push_back(key);
        }
    }
};

} // namespace triofuzz
