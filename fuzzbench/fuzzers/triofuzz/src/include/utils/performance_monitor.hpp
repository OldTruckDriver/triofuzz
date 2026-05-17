#pragma once

#include "../core/algorithm.hpp"
#include "../core/engine.hpp"
#include <chrono>
#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <cmath>

namespace triofuzz {

// Performance metrics
struct Metrics {
    // Effectiveness metrics
    double coverage_gain_rate = 0.0;       // Coverage gain rate
    double bug_finding_rate = 0.0;         // Bug finding rate
    double unique_crash_rate = 0.0;        // Unique crash rate
    double path_discovery_rate = 0.0;      // Path discovery rate
    
    // Efficiency metrics
    double execution_speed = 0.0;          // Execution speed (exec/s)
    double memory_efficiency = 0.0;        // Memory efficiency
    double cpu_utilization = 0.0;          // CPU utilization
    double throughput = 0.0;               // Throughput
    
    // Composite metrics
    double combination_effectiveness = 0.0; // Combination effectiveness
    double algorithm_diversity = 0.0;       // Algorithm diversity
    double synergy_score = 0.0;            // Synergy score
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;
};

// Time window
struct TimeWindow {
    std::chrono::system_clock::time_point start;
    std::chrono::system_clock::time_point end;
    
    std::chrono::duration<double> duration() const {
        return end - start;
    }
    
    bool contains(const std::chrono::system_clock::time_point& time) const {
        return time >= start && time <= end;
    }
};

// Performance monitor
class PerformanceMonitor {
public:
    // Monitoring configuration
    struct Config {
        size_t metrics_history_size = 1000;
        std::chrono::seconds metrics_update_interval{10};
        std::chrono::seconds anomaly_detection_interval{30};
        double anomaly_threshold = 3.0; // Standard deviation multiplier
        bool enable_real_time_monitoring = true;
    };
    
    // Algorithm-combination performance record
    struct CombinationPerformance {
        AlgorithmCombination combination;
        std::deque<Metrics> metrics_history;
        std::atomic<size_t> execution_count{0};
        std::atomic<size_t> success_count{0};
        std::atomic<size_t> crash_count{0};
        std::atomic<size_t> new_coverage_count{0};
        
        // Statistics
        struct Statistics {
            double mean_coverage_gain = 0.0;
            double std_coverage_gain = 0.0;
            double mean_execution_time = 0.0;
            double std_execution_time = 0.0;
            double success_rate = 0.0;
        } stats;
        
        std::chrono::system_clock::time_point first_use;
        std::chrono::system_clock::time_point last_use;
    };

private:
    Config config_;
    
    // Performance data storage
    std::map<std::string, CombinationPerformance> combination_performance_;
    mutable std::shared_mutex performance_mutex_;
    
    // Global stats
    std::atomic<size_t> total_executions_{0};
    std::atomic<size_t> total_crashes_{0};
    std::atomic<double> total_coverage_{0.0};
    
    // Monitoring thread
    std::thread monitoring_thread_;
    std::atomic<bool> monitoring_active_{false};
    
    // Anomaly detection
    std::vector<std::function<void(const Metrics&, const Metrics&)>> anomaly_callbacks_;
    
public:
    PerformanceMonitor() = default;
    
    ~PerformanceMonitor() {
        stopMonitoring();
    }
    
    // Start monitoring
    void startMonitoring() {
        if (monitoring_active_.load()) return;
        
        // Ensure any previous thread has terminated cleanly.
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
        
        monitoring_active_ = true;
        monitoring_thread_ = std::thread([this]() {
            monitoringLoop();
        });
    }
    
    // Stop monitoring
    void stopMonitoring() {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
    }
    
    // Record execution
    void recordExecution(const AlgorithmCombination& combo, const ExecutionResult& result) {
        std::unique_lock<std::shared_mutex> lock(performance_mutex_);
        
        auto& perf = combination_performance_[combo.toString()];
        perf.combination = combo;
        perf.execution_count++;
        
        if (perf.first_use == std::chrono::system_clock::time_point{}) {
            perf.first_use = std::chrono::system_clock::now();
        }
        perf.last_use = std::chrono::system_clock::now();
        
        // Update counters
        if (result.status == ExecutionResult::Status::Success) {
            perf.success_count++;
        } else if (result.status == ExecutionResult::Status::Crash) {
            perf.crash_count++;
            total_crashes_++;
        }
        
        if (result.coverage.hasNewCoverage()) {
            perf.new_coverage_count++;
        }
        
        total_executions_++;
        
        // Create metrics
        Metrics metrics = createMetrics(result, perf);
        
        // Append to history
        perf.metrics_history.push_back(metrics);
        if (perf.metrics_history.size() > config_.metrics_history_size) {
            perf.metrics_history.pop_front();
        }
        
        // Update statistics
        updateStatistics(perf);
    }
    
    // Analyze performance
    Metrics analyzePerformance(const TimeWindow& window) const {
        std::shared_lock<std::shared_mutex> lock(performance_mutex_);
        
        Metrics aggregated;
        size_t count = 0;
        
        for (const auto& [combo_name, perf] : combination_performance_) {
            for (const auto& metric : perf.metrics_history) {
                if (window.contains(metric.timestamp)) {
                    aggregateMetrics(aggregated, metric);
                    count++;
                }
            }
        }
        
        if (count > 0) {
            normalizeMetrics(aggregated, count);
        }
        
        return aggregated;
    }
    
    // Get combination performance
    const CombinationPerformance* getCombinationPerformance(
        const std::string& combo_name) const {
        std::shared_lock<std::shared_mutex> lock(performance_mutex_);
        
        auto it = combination_performance_.find(combo_name);
        if (it != combination_performance_.end()) {
            return &(it->second);
        }
        
        return nullptr;
    }
    
    // Get top combinations
    std::vector<std::pair<AlgorithmCombination, double>> getTopCombinations(
        size_t n = 10) const;
    
    // Detect anomaly
    bool detectAnomaly(const Metrics& current, const Metrics& baseline) const;
    
    // Register anomaly callback
    void registerAnomalyCallback(
        std::function<void(const Metrics&, const Metrics&)> callback);
    
    // Get performance trend
    struct PerformanceTrend {
        double coverage_trend;      // Positive means increasing.
        double crash_trend;
        double execution_trend;
        std::string overall_trend;  // "improving", "stable", "degrading"
    };
    
    PerformanceTrend analyzeTrend(const std::string& combo_name,
                                  std::chrono::hours period = std::chrono::hours(1)) const;
    
    // Export performance report
    struct PerformanceReport {
        std::chrono::system_clock::time_point generated_at;
        size_t total_executions;
        size_t total_crashes;
        double coverage_percentage;
        
        struct CombinationSummary {
            std::string name;
            size_t executions;
            double success_rate;
            double avg_coverage_gain;
            double effectiveness_score;
        };
        
        std::vector<CombinationSummary> top_combinations;
        std::vector<CombinationSummary> worst_combinations;
        
        std::map<std::string, PerformanceTrend> trends;
        std::vector<std::string> anomalies;
    };
    
    PerformanceReport generateReport() const;
    
    // Configuration update
    void updateConfig(const Config& config);
    
	private:
    // Monitoring loop
    void monitoringLoop() {
        auto last_update = std::chrono::steady_clock::now();
        auto last_anomaly_check = last_update;
        
        while (monitoring_active_.load()) {
            auto now = std::chrono::steady_clock::now();
            
            // Periodically update metrics
            if (now - last_update >= config_.metrics_update_interval) {
                updateGlobalMetrics();
                last_update = now;
            }
            
            // Periodically run anomaly detection
            if (now - last_anomaly_check >= config_.anomaly_detection_interval) {
                performAnomalyDetection();
                last_anomaly_check = now;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    // Create metrics
    Metrics createMetrics(const ExecutionResult& result, 
                         const CombinationPerformance& perf) const;
    
    // Aggregate metrics
    void aggregateMetrics(Metrics& aggregated, const Metrics& metric) const;
    
    // Normalize metrics
    void normalizeMetrics(Metrics& metrics, size_t count) const;
    
    // Update statistics
    void updateStatistics(CombinationPerformance& perf) const;
    
    // Calculate combination score
    double calculateCombinationScore(const CombinationPerformance& perf) const;
    
    // Calculate effectiveness
    double calculateEffectiveness(const ExecutionResult& result,
                                 const CombinationPerformance& perf) const;
    
    // Calculate deviation
    double calculateDeviation(const Metrics& current, const Metrics& baseline) const;
    
    // Calculate linear trend
    double calculateLinearTrend(const std::vector<std::pair<double, double>>& points) const;
    
    // Update global metrics
    void updateGlobalMetrics();
    
    // Run anomaly detection
    void performAnomalyDetection();
    
    // Compute baseline
    Metrics calculateBaseline(const std::deque<Metrics>& history) const;
};

} // namespace triofuzz
