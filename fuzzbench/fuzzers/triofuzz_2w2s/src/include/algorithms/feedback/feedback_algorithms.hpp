#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include "../../types/contraint_types.hpp"
#include <unordered_map>
#include <set>
#include <sstream>

namespace triofuzz {

// Feedback algorithm input/output types
using FeedbackInput = ExecutionResult;
using FeedbackOutput = std::map<std::string, std::any>;

// Base class for feedback processing algorithms
class FeedbackAlgorithm : public Algorithm<FeedbackInput, FeedbackOutput, SharedContext> {
public:
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Feedback;
        info.version = "1.0";
        return info;
    }
    
    void saveState(StateWriter& writer) const override {
        // Feedback algorithms typically persist statistics.
    }
    
    void loadState(StateReader& reader) override {
        // Feedback algorithms typically restore statistics.
    }
};

// Coverage analysis algorithm
class CoverageAnalyzer : public FeedbackAlgorithm {
private:
    // Coverage stats
    struct CoverageStats {
        std::bitset<65536> global_bitmap;
        std::unordered_map<uint64_t, size_t> edge_hit_count;
        std::set<uint64_t> unique_edges;
        std::vector<uint64_t> rare_edges;
        size_t total_executions = 0;
    };
    
    CoverageStats stats_;
    double rare_edge_threshold_ = 0.01; // Edges below 1% frequency are considered rare
    
public:
    CoverageAnalyzer() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = FeedbackAlgorithm::getInfo();
        info.name = "coverage_analyzer";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    FeedbackOutput execute(const FeedbackInput& result, SharedContext& ctx) override {
        return measureExecution([&]() {
            FeedbackOutput output;
            
            // Update global coverage.
            CoverageInfo updated_coverage = updateGlobalCoverage(result.coverage);
            
            // Analyze coverage patterns.
            analyzeCoveragePatterns(updated_coverage);
            
            // Compute coverage metrics.
            output["coverage_percentage"] = calculateCoveragePercentage();
            output["new_edges_count"] = updated_coverage.new_edges.size();
            output["rare_edges_count"] = updated_coverage.rare_edges.size();
            output["coverage_gain"] = updated_coverage.coverage_gain;
            
            // Update context.
            ctx.setCoverageInfo(updated_coverage);
            
            return output;
        });
    }
    
    void updateParameters(const Parameters& params) override {
        FeedbackAlgorithm::updateParameters(params);
        
        auto threshold = params.get<double>("rare_edge_threshold");
        if (threshold.has_value()) rare_edge_threshold_ = threshold.value();
    }
    
private:
    CoverageInfo updateGlobalCoverage(const CoverageInfo& new_coverage);
    void analyzeCoveragePatterns(const CoverageInfo& coverage);
    double calculateCoveragePercentage();
};

// Crash analysis algorithm
class CrashAnalyzer : public FeedbackAlgorithm {
public:
    // Crash signature
    struct CrashSignature {
        std::string stack_trace_hash;
        std::string fault_address;
        std::string signal_type;
        std::vector<std::string> call_stack;
        
        std::string toString() const {
            return signal_type + "_" + fault_address + "_" + stack_trace_hash;
        }
    };

private:
    // Crash stats
    std::unordered_map<std::string, std::vector<std::vector<uint8_t>>> unique_crashes_;
    std::unordered_map<std::string, size_t> crash_counts_;
    std::unordered_map<std::string, CrashSignature> crash_signatures_;
    
public:
    CrashAnalyzer() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = FeedbackAlgorithm::getInfo();
        info.name = "crash_analyzer";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    // Check whether a crash is unique
    bool isUniqueCrash(const ExecutionResult& result) {
        if (result.status != ExecutionResult::Status::Crash) {
            return false;
        }
        
        CrashSignature signature = extractSignature(result);
        std::string sig_str = signature.toString();
        return unique_crashes_.find(sig_str) == unique_crashes_.end();
    }
    
    FeedbackOutput execute(const FeedbackInput& result, SharedContext& ctx) override {
        return measureExecution([&]() {
            FeedbackOutput output;
            
            if (result.status != ExecutionResult::Status::Crash) {
                output["is_crash"] = false;
                return output;
            }
            
            output["is_crash"] = true;
            
            // Extract crash signature.
            CrashSignature signature = extractSignature(result);
            std::string sig_str = signature.toString();
            
            // Check whether this is a new crash.
            bool is_unique = (unique_crashes_.find(sig_str) == unique_crashes_.end());
            output["is_unique_crash"] = is_unique;
            
            if (is_unique) {
                // Save new crash.
                unique_crashes_[sig_str].push_back(result.output);
                crash_signatures_[sig_str] = signature;
            }
            
            // Update crash counts.
            crash_counts_[sig_str]++;
            
            // Analyze crash severity.
            output["severity"] = analyzeSeverity(signature);
            output["exploitability"] = analyzeExploitability(signature);
            
            // Classify crash.
            output["crash_type"] = classifyCrash(signature);
            
            // Generate crash report.
            output["crash_report"] = generateCrashReport(signature, result);
            
            return output;
        });
    }
    
private:
    CrashSignature extractSignature(const FeedbackInput& result);
    std::string hashStackTrace(const std::vector<std::string>& stack);
    std::string extractFaultAddress(const std::vector<std::string>& crash_info);
    double analyzeSeverity(const CrashSignature& sig);
    double analyzeExploitability(const CrashSignature& sig);
    std::string classifyCrash(const CrashSignature& sig);
    std::string generateCrashReport(const CrashSignature& sig, const FeedbackInput& result);
};

// Performance analysis algorithm
class PerformanceAnalyzer : public FeedbackAlgorithm {
private:
    // Performance stats
    struct PerformanceStats {
        double avg_exec_time = 0.0;
        double min_exec_time = std::numeric_limits<double>::max();
        double max_exec_time = 0.0;
        size_t total_executions = 0;
        
        std::vector<double> exec_time_history;
        std::unordered_map<std::string, size_t> syscall_counts;
        
        double percentile_50 = 0.0;
        double percentile_95 = 0.0;
        double percentile_99 = 0.0;
    };
    
    PerformanceStats stats_;
    size_t history_window_ = 1000;
    
public:
    PerformanceAnalyzer() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = FeedbackAlgorithm::getInfo();
        info.name = "performance_analyzer";
        info.provided_info = {InfoType::Performance};
        return info;
    }
    
    FeedbackOutput execute(const FeedbackInput& result, SharedContext& ctx) override {
        return measureExecution([&]() {
            FeedbackOutput output;
            
            // Update execution-time stats.
            updateExecutionTimeStats(result.performance.execution_time_ms);
            
            // Update memory-usage stats.
            updateMemoryStats(result.performance);
            
            // Update syscall stats.
            updateSyscallStats(result.performance);
            
            // Detect performance anomalies.
            bool is_slow = detectSlowExecution(result.performance.execution_time_ms);
            bool is_memory_spike = detectMemorySpike(result.performance.memory_usage_bytes);
            
            output["is_slow_execution"] = is_slow;
            output["is_memory_spike"] = is_memory_spike;
            output["avg_exec_time"] = stats_.avg_exec_time;
            output["exec_time_percentile_95"] = stats_.percentile_95;
            
            // Performance trend analysis.
            output["performance_trend"] = analyzePerformanceTrend();
            
            // Update context.
            PerformanceInfo perf_info = result.performance;
            perf_info.execution_time_ms = stats_.avg_exec_time;
            ctx.setPerformanceInfo(perf_info);
            
            return output;
        });
    }
    
private:
    void updateExecutionTimeStats(double exec_time);
    void updatePercentiles();
    void updateMemoryStats(const PerformanceInfo& perf);
    void updateSyscallStats(const PerformanceInfo& perf);
    bool detectSlowExecution(double exec_time);
    bool detectMemorySpike(size_t memory_usage);
    std::string analyzePerformanceTrend();
};

// Constraint collection algorithm
class ConstraintCollector : public FeedbackAlgorithm {
private:
    // Path-constraint storage
    std::unordered_map<std::string, std::vector<std::shared_ptr<Constraint>>> path_constraints_;
    size_t max_constraints_per_path_ = 100;
    
public:
    ConstraintCollector() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = FeedbackAlgorithm::getInfo();
        info.name = "constraint_collector";
        info.provided_info = {InfoType::Constraint};
        info.required_info = {InfoType::Coverage};
        return info;
    }
    
    FeedbackOutput execute(const FeedbackInput& result, SharedContext& ctx) override {
        return measureExecution([&]() {
            FeedbackOutput output;
            
            // Collect path constraints.
            std::string path_id = extractPathId(result);
            std::vector<std::shared_ptr<Constraint>> new_constraints = collectConstraints(result);
            
            output["path_id"] = path_id;
            output["constraint_count"] = new_constraints.size();
            
            // Update path constraints.
            updatePathConstraints(path_id, new_constraints);
            
            // Analyze constraint complexity.
            output["constraint_complexity"] = analyzeConstraintComplexity(new_constraints);
            output["solvable_constraints"] = countSolvableConstraints(new_constraints);
            
            // Build constraint info.
            ConstraintInfo constraint_info;
            constraint_info.path_constraints = new_constraints;
            constraint_info.has_solution = !new_constraints.empty();
            
            // Update context.
            ctx.setConstraintInfo(constraint_info);
            
            return output;
        });
    }
    
private:
    std::string extractPathId(const FeedbackInput& result);
    std::vector<std::shared_ptr<Constraint>> collectConstraints(const FeedbackInput& result);
    void updatePathConstraints(const std::string& path_id, 
                              const std::vector<std::shared_ptr<Constraint>>& constraints);
    double analyzeConstraintComplexity(const std::vector<std::shared_ptr<Constraint>>& constraints);
    size_t countSolvableConstraints(const std::vector<std::shared_ptr<Constraint>>& constraints);
};

} // namespace triofuzz
