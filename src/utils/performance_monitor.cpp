#include "../../include/utils/performance_monitor.hpp"
#include <numeric>

namespace triofuzz {

// Create metrics
Metrics PerformanceMonitor::createMetrics(const ExecutionResult& result, 
                                        const CombinationPerformance& perf) const {
    Metrics metrics;
    metrics.timestamp = std::chrono::system_clock::now();
    
    // Effectiveness metrics
    metrics.coverage_gain_rate = result.coverage.coverage_gain;
    metrics.bug_finding_rate = (result.status == ExecutionResult::Status::Crash) ? 1.0 : 0.0;
    metrics.unique_crash_rate = result.coverage.hasNewCoverage() ? 1.0 : 0.0;
    metrics.path_discovery_rate = static_cast<double>(result.coverage.new_edges.size());
    
    // Efficiency metrics
    metrics.execution_speed = result.performance.getExecPerSec();
    metrics.memory_efficiency = 1.0 / (1.0 + static_cast<double>(result.performance.memory_usage_bytes) / 1024.0);
    metrics.cpu_utilization = result.performance.execution_time_ms / 1000.0; // Simplified calculation
    metrics.throughput = metrics.execution_speed;
    
    // Combination metrics
    metrics.combination_effectiveness = calculateEffectiveness(result, perf);
    metrics.algorithm_diversity = 0.5; // Placeholder
    metrics.synergy_score = metrics.combination_effectiveness * metrics.algorithm_diversity;
    
    return metrics;
}

// Aggregate metrics
void PerformanceMonitor::aggregateMetrics(Metrics& aggregated, const Metrics& metric) const {
    aggregated.coverage_gain_rate += metric.coverage_gain_rate;
    aggregated.bug_finding_rate += metric.bug_finding_rate;
    aggregated.unique_crash_rate += metric.unique_crash_rate;
    aggregated.path_discovery_rate += metric.path_discovery_rate;
    aggregated.execution_speed += metric.execution_speed;
    aggregated.memory_efficiency += metric.memory_efficiency;
    aggregated.cpu_utilization += metric.cpu_utilization;
    aggregated.throughput += metric.throughput;
    aggregated.combination_effectiveness += metric.combination_effectiveness;
    aggregated.algorithm_diversity += metric.algorithm_diversity;
    aggregated.synergy_score += metric.synergy_score;
}

// Normalize metrics
void PerformanceMonitor::normalizeMetrics(Metrics& metrics, size_t count) const {
    if (count == 0) return;
    
    double factor = 1.0 / static_cast<double>(count);
    metrics.coverage_gain_rate *= factor;
    metrics.bug_finding_rate *= factor;
    metrics.unique_crash_rate *= factor;
    metrics.path_discovery_rate *= factor;
    metrics.execution_speed *= factor;
    metrics.memory_efficiency *= factor;
    metrics.cpu_utilization *= factor;
    metrics.throughput *= factor;
    metrics.combination_effectiveness *= factor;
    metrics.algorithm_diversity *= factor;
    metrics.synergy_score *= factor;
}

// Update statistics
void PerformanceMonitor::updateStatistics(CombinationPerformance& perf) const {
    if (perf.metrics_history.empty()) return;
    
    // Compute mean and standard deviation of coverage gain
    double sum = 0.0, sum_sq = 0.0;
    for (const auto& metric : perf.metrics_history) {
        sum += metric.coverage_gain_rate;
        sum_sq += metric.coverage_gain_rate * metric.coverage_gain_rate;
    }
    
    size_t n = perf.metrics_history.size();
    perf.stats.mean_coverage_gain = sum / n;
    perf.stats.std_coverage_gain = std::sqrt((sum_sq / n) - (perf.stats.mean_coverage_gain * perf.stats.mean_coverage_gain));
    
    // Compute execution time statistics
    sum = sum_sq = 0.0;
    for (const auto& metric : perf.metrics_history) {
        double exec_time = (metric.execution_speed > 0) ? (1.0 / metric.execution_speed * 1000.0) : 0.0;
        sum += exec_time;
        sum_sq += exec_time * exec_time;
    }
    
    perf.stats.mean_execution_time = sum / n;
    perf.stats.std_execution_time = std::sqrt((sum_sq / n) - (perf.stats.mean_execution_time * perf.stats.mean_execution_time));
    
    // Compute success rate
    perf.stats.success_rate = static_cast<double>(perf.success_count.load()) / static_cast<double>(perf.execution_count.load());
}

// Compute combination score
double PerformanceMonitor::calculateCombinationScore(const CombinationPerformance& perf) const {
    if (perf.metrics_history.empty()) return 0.0;
    
    // Compute score based on the latest metrics
    const auto& latest = perf.metrics_history.back();
    
    // Overall score = effectiveness * efficiency
    double effectiveness = (latest.coverage_gain_rate + latest.bug_finding_rate + latest.path_discovery_rate) / 3.0;
    double efficiency = (latest.execution_speed + latest.memory_efficiency + latest.throughput) / 3.0;
    
    return effectiveness * efficiency * latest.synergy_score;
}

// Compute effectiveness
double PerformanceMonitor::calculateEffectiveness(const ExecutionResult& result,
                                                 const CombinationPerformance& perf) const {
    double coverage_score = result.coverage.getCoveragePercentage() / 100.0;
    double crash_score = (result.status == ExecutionResult::Status::Crash) ? 1.0 : 0.0;
    double new_coverage_score = result.coverage.hasNewCoverage() ? 1.0 : 0.0;
    
    return (coverage_score + crash_score + new_coverage_score) / 3.0;
}

// Compute deviation
double PerformanceMonitor::calculateDeviation(const Metrics& current, const Metrics& baseline) const {
    // Compute normalized deviation for each metric
    std::vector<double> deviations;
    
    if (baseline.coverage_gain_rate > 0) {
        deviations.push_back(std::abs(current.coverage_gain_rate - baseline.coverage_gain_rate) / baseline.coverage_gain_rate);
    }
    if (baseline.execution_speed > 0) {
        deviations.push_back(std::abs(current.execution_speed - baseline.execution_speed) / baseline.execution_speed);
    }
    if (baseline.memory_efficiency > 0) {
        deviations.push_back(std::abs(current.memory_efficiency - baseline.memory_efficiency) / baseline.memory_efficiency);
    }
    
    if (deviations.empty()) return 0.0;
    
    // Return average deviation
    return std::accumulate(deviations.begin(), deviations.end(), 0.0) / deviations.size();
}

// Compute linear trend
double PerformanceMonitor::calculateLinearTrend(const std::vector<std::pair<double, double>>& points) const {
    if (points.size() < 2) return 0.0;
    
    size_t n = points.size();
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
    
    for (const auto& [x, y] : points) {
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
    }
    
    double denominator = n * sum_x2 - sum_x * sum_x;
    if (std::abs(denominator) < 1e-10) return 0.0;
    
    return (n * sum_xy - sum_x * sum_y) / denominator;
}

// Update global metrics
void PerformanceMonitor::updateGlobalMetrics() {
    std::shared_lock<std::shared_mutex> lock(performance_mutex_);
    
    double total_coverage = 0.0;
    size_t active_combinations = 0;
    
    for (const auto& [combo_name, perf] : combination_performance_) {
        if (!perf.metrics_history.empty()) {
            total_coverage += perf.metrics_history.back().coverage_gain_rate;
            active_combinations++;
        }
    }
    
    if (active_combinations > 0) {
        total_coverage_.store(total_coverage / active_combinations);
    }
}

// Run anomaly detection
void PerformanceMonitor::performAnomalyDetection() {
    std::shared_lock<std::shared_mutex> lock(performance_mutex_);
    
    for (const auto& [combo_name, perf] : combination_performance_) {
        if (perf.metrics_history.size() < 10) continue; // Need sufficient history
        
        const auto& current = perf.metrics_history.back();
        auto baseline = calculateBaseline(perf.metrics_history);
        
        if (detectAnomaly(current, baseline)) {
            // Notify anomaly callbacks
            for (const auto& callback : anomaly_callbacks_) {
                callback(current, baseline);
            }
        }
    }
}

// Compute baseline
Metrics PerformanceMonitor::calculateBaseline(const std::deque<Metrics>& history) const {
    if (history.empty()) return Metrics{};
    
    Metrics baseline{};
    size_t count = std::min<size_t>(history.size(), 20); // Use the most recent 20 samples
    
    for (size_t i = history.size() - count; i < history.size(); ++i) {
        aggregateMetrics(baseline, history[i]);
    }
    
    normalizeMetrics(baseline, count);
    return baseline;
}

// Detect anomaly
bool PerformanceMonitor::detectAnomaly(const Metrics& current, const Metrics& baseline) const {
    double deviation = calculateDeviation(current, baseline);
    return deviation > config_.anomaly_threshold;
}

// Get top combinations
std::vector<std::pair<AlgorithmCombination, double>> PerformanceMonitor::getTopCombinations(
    size_t limit) const {
    
    std::shared_lock<std::shared_mutex> lock(performance_mutex_);
    
    std::vector<std::pair<AlgorithmCombination, double>> result;
    
    for (const auto& [combo_name, perf] : combination_performance_) {
        double score = calculateCombinationScore(perf);
        result.emplace_back(perf.combination, score);
    }
    
    // Sort by score
    std::sort(result.begin(), result.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    if (result.size() > limit) {
        result.resize(limit);
    }
    
    return result;
}

// Analyze trend (signature matches header)
PerformanceMonitor::PerformanceTrend PerformanceMonitor::analyzeTrend(
    const std::string& combo_name, std::chrono::hours period) const {
    
    std::shared_lock<std::shared_mutex> lock(performance_mutex_);
    
    PerformanceTrend trend{};
    
    auto it = combination_performance_.find(combo_name);
    if (it == combination_performance_.end()) {
        trend.overall_trend = "unknown";
        return trend;
    }
    
    const auto& perf = it->second;
    
    // Create time window
    auto now = std::chrono::system_clock::now();
    auto start_time = now - period;
    
    // Build time-series data
    std::vector<std::pair<double, double>> coverage_points;
    std::vector<std::pair<double, double>> crash_points;
    std::vector<std::pair<double, double>> execution_points;
    
    for (const auto& metric : perf.metrics_history) {
        if (metric.timestamp >= start_time && metric.timestamp <= now) {
            auto time_val = std::chrono::duration<double>(metric.timestamp.time_since_epoch()).count();
            coverage_points.emplace_back(time_val, metric.coverage_gain_rate);
            crash_points.emplace_back(time_val, metric.bug_finding_rate);
            execution_points.emplace_back(time_val, metric.execution_speed);
        }
    }
    
    // Compute trend
    trend.coverage_trend = calculateLinearTrend(coverage_points);
    trend.crash_trend = calculateLinearTrend(crash_points);
    trend.execution_trend = calculateLinearTrend(execution_points);
    
    // Determine overall trend
    double overall = (trend.coverage_trend + trend.crash_trend + trend.execution_trend) / 3.0;
    if (overall > 0.1) {
        trend.overall_trend = "improving";
    } else if (overall < -0.1) {
        trend.overall_trend = "degrading";
    } else {
        trend.overall_trend = "stable";
    }
    
    return trend;
}

// Generate report
PerformanceMonitor::PerformanceReport PerformanceMonitor::generateReport() const {
    std::shared_lock<std::shared_mutex> lock(performance_mutex_);
    
    PerformanceReport report;
    report.generated_at = std::chrono::system_clock::now();
    report.total_executions = total_executions_.load();
    report.total_crashes = total_crashes_.load();
    report.coverage_percentage = total_coverage_.load();
    
    // Collect combination summaries
    std::vector<std::pair<std::string, double>> combination_scores;
    
    for (const auto& [combo_name, perf] : combination_performance_) {
        PerformanceReport::CombinationSummary summary;
        summary.name = combo_name;
        summary.executions = perf.execution_count.load();
        summary.success_rate = perf.stats.success_rate;
        summary.avg_coverage_gain = perf.stats.mean_coverage_gain;
        summary.effectiveness_score = calculateCombinationScore(perf);
        
        double score = summary.effectiveness_score;
        combination_scores.emplace_back(combo_name, score);
        
        if (report.top_combinations.size() < 10) {
            report.top_combinations.push_back(summary);
        } else if (score > report.top_combinations.back().effectiveness_score) {
            report.top_combinations.back() = summary;
            std::sort(report.top_combinations.begin(), report.top_combinations.end(),
                     [](const auto& a, const auto& b) { return a.effectiveness_score > b.effectiveness_score; });
        }
    }
    
    // Worst combinations
    std::sort(combination_scores.begin(), combination_scores.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    for (size_t i = 0; i < std::min<size_t>(5, combination_scores.size()); ++i) {
        auto it = combination_performance_.find(combination_scores[i].first);
        if (it != combination_performance_.end()) {
            PerformanceReport::CombinationSummary summary;
            summary.name = combination_scores[i].first;
            summary.executions = it->second.execution_count.load();
            summary.success_rate = it->second.stats.success_rate;
            summary.avg_coverage_gain = it->second.stats.mean_coverage_gain;
            summary.effectiveness_score = combination_scores[i].second;
            report.worst_combinations.push_back(summary);
        }
    }
    
    return report;
}

// Update config
void PerformanceMonitor::updateConfig(const Config& config) {
    config_ = config;
}

// Register anomaly callback
void PerformanceMonitor::registerAnomalyCallback(
    std::function<void(const Metrics&, const Metrics&)> callback) {
    anomaly_callbacks_.push_back(callback);
}

} // namespace triofuzz
