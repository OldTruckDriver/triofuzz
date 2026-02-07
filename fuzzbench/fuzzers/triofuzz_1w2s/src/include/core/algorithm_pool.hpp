#pragma once

#include <memory>
#include <vector>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <thread>
#include "../core/algorithm.hpp"
#include "../utils/algorithm_registry.hpp"

namespace triofuzz {

// Algorithm pool - pre-create and reuse algorithm instances
class AlgorithmPool {
public:
    // Pooled algorithm instance
    struct PooledAlgorithm {
        std::unique_ptr<AlgorithmBase> instance;
        std::chrono::steady_clock::time_point last_used;
        std::atomic<bool> in_use{false};
        size_t use_count = 0;
        double accumulated_score = 0.0;

        // Performance stats
        struct Performance {
            double avg_execution_time = 0.0;
            size_t successful_mutations = 0;
            size_t total_mutations = 0;
            double coverage_contribution = 0.0;
        } performance;
    };

    // Pool configuration
    struct PoolConfig {
        size_t initial_pool_size;      // Initial instances per algorithm
        size_t max_pool_size;         // Max instances per algorithm
        size_t prewarm_size;           // Prewarm instance count
        bool enable_auto_scaling;   // Auto scaling
        bool enable_lazy_init;     // Lazy initialization
        std::chrono::seconds idle_timeout;  // Idle timeout

        PoolConfig()
            : initial_pool_size(4)
            , max_pool_size(16)
            , prewarm_size(2)
            , enable_auto_scaling(true)
            , enable_lazy_init(false)
            , idle_timeout(300) {}
    };

private:
    PoolConfig config_;
    mutable std::mutex pool_mutex_;

    // Map from algorithm name to pool
    std::unordered_map<std::string, std::vector<std::shared_ptr<PooledAlgorithm>>> pools_;

    // Hot algorithms list (by usage frequency)
    std::vector<std::string> hot_algorithms_;

    // Algorithm usage stats
    struct UsageStats {
        std::atomic<size_t> total_requests{0};
        std::atomic<size_t> hits{0};         // Pool hit
        std::atomic<size_t> misses{0};       // Pool miss
        std::atomic<size_t> creates{0};      // Instances created
        std::atomic<size_t> evictions{0};    // Instances evicted
    };
    std::unordered_map<std::string, UsageStats> usage_stats_;

    // Algorithm registry reference
    AlgorithmRegistry& registry_;

    // Background cleanup thread
    std::thread cleanup_thread_;
    std::atomic<bool> stop_cleanup_{false};
    std::condition_variable cleanup_cv_;

public:
    explicit AlgorithmPool(const PoolConfig& config = PoolConfig());
    ~AlgorithmPool();

    // Disable copy
    AlgorithmPool(const AlgorithmPool&) = delete;
    AlgorithmPool& operator=(const AlgorithmPool&) = delete;

    // Prewarm algorithm pool
    void prewarm(const std::vector<std::string>& algorithm_names);

    // Acquire algorithm instance
    std::shared_ptr<PooledAlgorithm> acquire(const std::string& algorithm_name);

    // Release algorithm instance
    void release(std::shared_ptr<PooledAlgorithm> algorithm);

    // Acquire instances in batch
    std::vector<std::shared_ptr<PooledAlgorithm>> acquireBatch(
        const std::string& algorithm_name, size_t count);

    // Batch release
    void releaseBatch(std::vector<std::shared_ptr<PooledAlgorithm>>& algorithms);

    // Adjust pool size dynamically
    void adjustPoolSize(const std::string& algorithm_name, size_t new_size);

    // Auto-scale based on usage
    void autoScale();

    // Cleanup idle instances
    void cleanupIdle();

    // Get pool status
    struct PoolStatus {
        size_t total_instances;
        size_t available_instances;
        size_t in_use_instances;
        double utilization_rate;
        double hit_rate;
    };

    PoolStatus getStatus(const std::string& algorithm_name) const;
    std::unordered_map<std::string, PoolStatus> getAllStatus() const;

    // Get performance report
    std::string getPerformanceReport() const;

    // Reset stats
    void resetStats();

    // RAII wrapper to manage algorithm lifecycle automatically
    class AlgorithmGuard {
    private:
        AlgorithmPool& pool_;
        std::shared_ptr<PooledAlgorithm> algorithm_;

    public:
        AlgorithmGuard(AlgorithmPool& pool, const std::string& algorithm_name)
            : pool_(pool), algorithm_(pool.acquire(algorithm_name)) {}

        ~AlgorithmGuard() {
            if (algorithm_) {
                pool_.release(algorithm_);
            }
        }

        // Disable copy, allow move
        AlgorithmGuard(const AlgorithmGuard&) = delete;
        AlgorithmGuard& operator=(const AlgorithmGuard&) = delete;
        AlgorithmGuard(AlgorithmGuard&& other) noexcept
            : pool_(other.pool_), algorithm_(std::move(other.algorithm_)) {}

        AlgorithmBase* operator->() { return algorithm_->instance.get(); }
        AlgorithmBase& operator*() { return *algorithm_->instance; }
        AlgorithmBase* get() { return algorithm_->instance.get(); }
    };

    // Create RAII guard
    AlgorithmGuard getAlgorithm(const std::string& algorithm_name) {
        return AlgorithmGuard(*this, algorithm_name);
    }

private:
    // Create new algorithm instance
    std::shared_ptr<PooledAlgorithm> createInstance(const std::string& algorithm_name);

    // Get available instance from pool
    std::shared_ptr<PooledAlgorithm> getFromPool(const std::string& algorithm_name);

    // Return instance to pool
    void returnToPool(const std::string& algorithm_name, std::shared_ptr<PooledAlgorithm> algorithm);

    // Cleanup thread function
    void cleanupThread();

    // Evict least recently used instance
    void evictLRU(const std::string& algorithm_name);

};


// Global algorithm pool instance
AlgorithmPool& getGlobalAlgorithmPool();

} // namespace triofuzz
