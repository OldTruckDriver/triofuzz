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

// 算法池 - 预创建和复用算法实例
class AlgorithmPool {
public:
    // 池化算法实例
    struct PooledAlgorithm {
        std::unique_ptr<AlgorithmBase> instance;
        std::chrono::steady_clock::time_point last_used;
        std::atomic<bool> in_use{false};
        size_t use_count = 0;
        double accumulated_score = 0.0;

        // 性能统计
        struct Performance {
            double avg_execution_time = 0.0;
            size_t successful_mutations = 0;
            size_t total_mutations = 0;
            double coverage_contribution = 0.0;
        } performance;
    };

    // 池配置
    struct PoolConfig {
        size_t initial_pool_size;      // 每种算法初始实例数
        size_t max_pool_size;         // 每种算法最大实例数
        size_t prewarm_size;           // 预热实例数
        bool enable_auto_scaling;   // 自动扩缩容
        bool enable_lazy_init;     // 延迟初始化
        std::chrono::seconds idle_timeout;  // 空闲超时

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

    // 算法名称到池的映射
    std::unordered_map<std::string, std::vector<std::shared_ptr<PooledAlgorithm>>> pools_;

    // 热门算法列表（根据使用频率）
    std::vector<std::string> hot_algorithms_;

    // 算法使用统计
    struct UsageStats {
        std::atomic<size_t> total_requests{0};
        std::atomic<size_t> hits{0};         // 池命中
        std::atomic<size_t> misses{0};       // 池未命中
        std::atomic<size_t> creates{0};      // 新建实例
        std::atomic<size_t> evictions{0};    // 驱逐实例
    };
    std::unordered_map<std::string, UsageStats> usage_stats_;

    // 算法注册表引用
    AlgorithmRegistry& registry_;

    // 后台清理线程
    std::thread cleanup_thread_;
    std::atomic<bool> stop_cleanup_{false};
    std::condition_variable cleanup_cv_;

public:
    explicit AlgorithmPool(const PoolConfig& config = PoolConfig());
    ~AlgorithmPool();

    // 禁止拷贝
    AlgorithmPool(const AlgorithmPool&) = delete;
    AlgorithmPool& operator=(const AlgorithmPool&) = delete;

    // 预热算法池
    void prewarm(const std::vector<std::string>& algorithm_names);


    // 获取算法实例
    std::shared_ptr<PooledAlgorithm> acquire(const std::string& algorithm_name);

    // 释放算法实例
    void release(std::shared_ptr<PooledAlgorithm> algorithm);

    // 批量获取算法实例
    std::vector<std::shared_ptr<PooledAlgorithm>> acquireBatch(
        const std::string& algorithm_name, size_t count);

    // 批量释放
    void releaseBatch(std::vector<std::shared_ptr<PooledAlgorithm>>& algorithms);

    // 动态调整池大小
    void adjustPoolSize(const std::string& algorithm_name, size_t new_size);

    // 根据使用情况自动调整
    void autoScale();

    // 清理空闲实例
    void cleanupIdle();

    // 获取池状态
    struct PoolStatus {
        size_t total_instances;
        size_t available_instances;
        size_t in_use_instances;
        double utilization_rate;
        double hit_rate;
    };

    PoolStatus getStatus(const std::string& algorithm_name) const;
    std::unordered_map<std::string, PoolStatus> getAllStatus() const;

    // 获取性能报告
    std::string getPerformanceReport() const;

    // 重置统计
    void resetStats();

    // RAII 包装器，自动管理算法生命周期
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

        // 禁止拷贝，允许移动
        AlgorithmGuard(const AlgorithmGuard&) = delete;
        AlgorithmGuard& operator=(const AlgorithmGuard&) = delete;
        AlgorithmGuard(AlgorithmGuard&& other) noexcept
            : pool_(other.pool_), algorithm_(std::move(other.algorithm_)) {}

        AlgorithmBase* operator->() { return algorithm_->instance.get(); }
        AlgorithmBase& operator*() { return *algorithm_->instance; }
        AlgorithmBase* get() { return algorithm_->instance.get(); }
    };

    // 创建RAII guard
    AlgorithmGuard getAlgorithm(const std::string& algorithm_name) {
        return AlgorithmGuard(*this, algorithm_name);
    }

private:
    // 创建新算法实例
    std::shared_ptr<PooledAlgorithm> createInstance(const std::string& algorithm_name);

    // 从池中获取可用实例
    std::shared_ptr<PooledAlgorithm> getFromPool(const std::string& algorithm_name);

    // 回收实例到池中
    void returnToPool(const std::string& algorithm_name, std::shared_ptr<PooledAlgorithm> algorithm);

    // 清理线程函数
    void cleanupThread();

    // 驱逐最少使用的实例
    void evictLRU(const std::string& algorithm_name);

};


// 全局算法池实例
AlgorithmPool& getGlobalAlgorithmPool();

} // namespace triofuzz