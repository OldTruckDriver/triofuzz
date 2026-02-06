#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include "../../types/contraint_types.hpp"
#include <unordered_map>
#include <set>
#include <sstream>

namespace triofuzz {

// 反馈算法输入输出类型
using FeedbackInput = ExecutionResult;
using FeedbackOutput = std::map<std::string, std::any>;

// 反馈处理算法基类
class FeedbackAlgorithm : public Algorithm<FeedbackInput, FeedbackOutput, SharedContext> {
public:
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Feedback;
        info.version = "1.0";
        return info;
    }
    
    void saveState(StateWriter& writer) const override {
        // 反馈算法通常保存统计信息
    }
    
    void loadState(StateReader& reader) override {
        // 反馈算法通常加载统计信息
    }
};

// 覆盖率分析算法
class CoverageAnalyzer : public FeedbackAlgorithm {
private:
    // 覆盖率统计
    struct CoverageStats {
        std::bitset<65536> global_bitmap;
        std::unordered_map<uint64_t, size_t> edge_hit_count;
        std::set<uint64_t> unique_edges;
        std::vector<uint64_t> rare_edges;
        size_t total_executions = 0;
    };
    
    CoverageStats stats_;
    double rare_edge_threshold_ = 0.01; // 1%以下为稀有边
    
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
            
            // 更新全局覆盖率
            CoverageInfo updated_coverage = updateGlobalCoverage(result.coverage);
            
            // 分析覆盖率特征
            analyzeCoveragePatterns(updated_coverage);
            
            // 计算覆盖率指标
            output["coverage_percentage"] = calculateCoveragePercentage();
            output["new_edges_count"] = updated_coverage.new_edges.size();
            output["rare_edges_count"] = updated_coverage.rare_edges.size();
            output["coverage_gain"] = updated_coverage.coverage_gain;
            
            // 更新上下文
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

// 崩溃分析算法
class CrashAnalyzer : public FeedbackAlgorithm {
public:
    // 崩溃签名
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
    // 崩溃统计
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
    
    // 检查是否为唯一崩溃
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
            
            // 提取崩溃签名
            CrashSignature signature = extractSignature(result);
            std::string sig_str = signature.toString();
            
            // 检查是否为新崩溃
            bool is_unique = (unique_crashes_.find(sig_str) == unique_crashes_.end());
            output["is_unique_crash"] = is_unique;
            
            if (is_unique) {
                // 保存新崩溃
                unique_crashes_[sig_str].push_back(result.output);
                crash_signatures_[sig_str] = signature;
            }
            
            // 更新崩溃计数
            crash_counts_[sig_str]++;
            
            // 分析崩溃严重性
            output["severity"] = analyzeSeverity(signature);
            output["exploitability"] = analyzeExploitability(signature);
            
            // 崩溃分类
            output["crash_type"] = classifyCrash(signature);
            
            // 生成崩溃报告
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

// 性能分析算法
class PerformanceAnalyzer : public FeedbackAlgorithm {
private:
    // 性能统计
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
            
            // 更新执行时间统计
            updateExecutionTimeStats(result.performance.execution_time_ms);
            
            // 更新内存使用统计
            updateMemoryStats(result.performance);
            
            // 更新系统调用统计
            updateSyscallStats(result.performance);
            
            // 检测性能异常
            bool is_slow = detectSlowExecution(result.performance.execution_time_ms);
            bool is_memory_spike = detectMemorySpike(result.performance.memory_usage_bytes);
            
            output["is_slow_execution"] = is_slow;
            output["is_memory_spike"] = is_memory_spike;
            output["avg_exec_time"] = stats_.avg_exec_time;
            output["exec_time_percentile_95"] = stats_.percentile_95;
            
            // 性能趋势分析
            output["performance_trend"] = analyzePerformanceTrend();
            
            // 更新上下文
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

// 约束收集算法
class ConstraintCollector : public FeedbackAlgorithm {
private:
    // 路径约束存储
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
            
            // 收集路径约束
            std::string path_id = extractPathId(result);
            std::vector<std::shared_ptr<Constraint>> new_constraints = collectConstraints(result);
            
            output["path_id"] = path_id;
            output["constraint_count"] = new_constraints.size();
            
            // 更新路径约束
            updatePathConstraints(path_id, new_constraints);
            
            // 分析约束复杂度
            output["constraint_complexity"] = analyzeConstraintComplexity(new_constraints);
            output["solvable_constraints"] = countSolvableConstraints(new_constraints);
            
            // 生成约束信息
            ConstraintInfo constraint_info;
            constraint_info.path_constraints = new_constraints;
            constraint_info.has_solution = !new_constraints.empty();
            
            // 更新上下文
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