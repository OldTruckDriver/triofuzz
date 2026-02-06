#include "../../include/core/algorithm_pool.hpp"
// program_features archived (unused)
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace triofuzz {

AlgorithmPool::AlgorithmPool(const PoolConfig& config)
    : config_(config), registry_(AlgorithmRegistry::getInstance()) {

    // 启动清理线程
    if (!config_.enable_lazy_init) {
        cleanup_thread_ = std::thread(&AlgorithmPool::cleanupThread, this);
    }

    // 设置默认热门算法
    hot_algorithms_ = {
        "havoc", "bitflip", "arithmetic", "smart_format",
        "splice", "deterministic", "libfuzzer", "afl_plus_plus", "rare_branch"
    };
}

AlgorithmPool::~AlgorithmPool() {
    // 停止清理线程
    stop_cleanup_ = true;
    cleanup_cv_.notify_all();

    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }

    // 清理所有池中的算法实例
    std::lock_guard<std::mutex> lock(pool_mutex_);
    pools_.clear();
}

void AlgorithmPool::prewarm(const std::vector<std::string>& algorithm_names) {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    for (const auto& name : algorithm_names) {
        // 确保池存在
        if (pools_.find(name) == pools_.end()) {
            pools_[name] = std::vector<std::shared_ptr<PooledAlgorithm>>();
        }

        auto& pool = pools_[name];

        // 创建预热实例
        size_t current_size = pool.size();
        size_t target_size = std::min(config_.prewarm_size, config_.max_pool_size);

        for (size_t i = current_size; i < target_size; i++) {
            auto instance = createInstance(name);
            if (instance) {
                pool.push_back(instance);
                usage_stats_[name].creates++;
            }
        }
    }
}


std::shared_ptr<AlgorithmPool::PooledAlgorithm> AlgorithmPool::acquire(
    const std::string& algorithm_name) {

    usage_stats_[algorithm_name].total_requests++;

    // 先尝试从池中获取
    auto pooled = getFromPool(algorithm_name);
    if (pooled) {
        usage_stats_[algorithm_name].hits++;
        pooled->in_use = true;
        pooled->use_count++;
        pooled->last_used = std::chrono::steady_clock::now();
        return pooled;
    }

    // 池中没有可用实例，创建新的
    usage_stats_[algorithm_name].misses++;

    std::lock_guard<std::mutex> lock(pool_mutex_);

    // 再次检查（避免竞态条件）
    if (pools_.find(algorithm_name) != pools_.end()) {
        auto& pool = pools_[algorithm_name];
        for (auto& algo : pool) {
            if (!algo->in_use.exchange(true)) {
                algo->use_count++;
                algo->last_used = std::chrono::steady_clock::now();
                return algo;
            }
        }
    }

    // 创建新实例
    auto new_instance = createInstance(algorithm_name);
    if (new_instance) {
        new_instance->in_use = true;
        new_instance->use_count = 1;
        new_instance->last_used = std::chrono::steady_clock::now();

        // 如果池未满，添加到池中
        if (pools_[algorithm_name].size() < config_.max_pool_size) {
            pools_[algorithm_name].push_back(new_instance);
        }

        usage_stats_[algorithm_name].creates++;
        return new_instance;
    }

    return nullptr;
}

void AlgorithmPool::release(std::shared_ptr<PooledAlgorithm> algorithm) {
    if (!algorithm) return;

    algorithm->in_use = false;

    // 如果启用自动扩缩容，检查是否需要调整池大小
    if (config_.enable_auto_scaling) {
        autoScale();
    }
}

std::vector<std::shared_ptr<AlgorithmPool::PooledAlgorithm>> AlgorithmPool::acquireBatch(
    const std::string& algorithm_name, size_t count) {

    std::vector<std::shared_ptr<PooledAlgorithm>> batch;
    batch.reserve(count);

    for (size_t i = 0; i < count; i++) {
        auto algo = acquire(algorithm_name);
        if (algo) {
            batch.push_back(algo);
        }
    }

    return batch;
}

void AlgorithmPool::releaseBatch(std::vector<std::shared_ptr<PooledAlgorithm>>& algorithms) {
    for (auto& algo : algorithms) {
        release(algo);
    }
    algorithms.clear();
}

std::shared_ptr<AlgorithmPool::PooledAlgorithm> AlgorithmPool::createInstance(
    const std::string& algorithm_name) {

    // 使用简单工厂模式创建算法
    std::unique_ptr<AlgorithmBase> algorithm;
    // TODO: 实现算法创建逻辑
    // algorithm = AlgorithmFactory::create(algorithm_name);
    if (!algorithm) {
        return nullptr;
    }

    auto pooled = std::make_shared<PooledAlgorithm>();
    pooled->instance = std::move(algorithm);
    pooled->last_used = std::chrono::steady_clock::now();

    return pooled;
}

std::shared_ptr<AlgorithmPool::PooledAlgorithm> AlgorithmPool::getFromPool(
    const std::string& algorithm_name) {

    std::lock_guard<std::mutex> lock(pool_mutex_);

    auto it = pools_.find(algorithm_name);
    if (it == pools_.end()) {
        return nullptr;
    }

    auto& pool = it->second;
    for (auto& algo : pool) {
        if (!algo->in_use.exchange(true)) {
            return algo;
        }
    }

    return nullptr;
}

void AlgorithmPool::adjustPoolSize(const std::string& algorithm_name, size_t new_size) {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    auto it = pools_.find(algorithm_name);
    if (it == pools_.end()) {
        pools_[algorithm_name] = std::vector<std::shared_ptr<PooledAlgorithm>>();
        it = pools_.find(algorithm_name);
    }

    auto& pool = it->second;
    size_t current_size = pool.size();

    if (new_size > current_size) {
        // 扩容
        for (size_t i = current_size; i < new_size && i < config_.max_pool_size; i++) {
            auto instance = createInstance(algorithm_name);
            if (instance) {
                pool.push_back(instance);
            }
        }
    } else if (new_size < current_size) {
        // 缩容 - 移除空闲实例
        pool.erase(
            std::remove_if(pool.begin(), pool.end(),
                [](const std::shared_ptr<PooledAlgorithm>& algo) {
                    return !algo->in_use.load();
                }),
            pool.end()
        );
    }
}

void AlgorithmPool::autoScale() {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    for (auto& pool_pair : pools_) {
        const std::string& name = pool_pair.first;
        auto& pool = pool_pair.second;

        // 计算利用率
        size_t in_use = 0;
        for (const auto& algo : pool) {
            if (algo->in_use.load()) {
                in_use++;
            }
        }

        double utilization = pool.empty() ? 0.0 :
            static_cast<double>(in_use) / pool.size();

        // 高利用率时扩容
        if (utilization > 0.8 && pool.size() < config_.max_pool_size) {
            size_t new_size = std::min(pool.size() * 2, config_.max_pool_size);
            adjustPoolSize(name, new_size);
        }
        // 低利用率时缩容
        else if (utilization < 0.2 && pool.size() > config_.initial_pool_size) {
            size_t new_size = std::max(pool.size() / 2, config_.initial_pool_size);
            adjustPoolSize(name, new_size);
        }
    }
}

void AlgorithmPool::cleanupIdle() {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    auto now = std::chrono::steady_clock::now();

    for (auto& [name, pool] : pools_) {
        // 复制名称以避免lambda捕获结构化绑定的问题
        std::string algorithm_name = name;
        pool.erase(
            std::remove_if(pool.begin(), pool.end(),
                [&, algorithm_name](const std::shared_ptr<PooledAlgorithm>& algo) {
                    if (!algo->in_use.load()) {
                        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                            now - algo->last_used).count();
                        if (idle_time > config_.idle_timeout.count()) {
                            usage_stats_[algorithm_name].evictions++;
                            return true;
                        }
                    }
                    return false;
                }),
            pool.end()
        );
    }
}

void AlgorithmPool::cleanupThread() {
    while (!stop_cleanup_) {
        std::unique_lock<std::mutex> lock(pool_mutex_);
        cleanup_cv_.wait_for(lock, std::chrono::seconds(60),
            [this] { return stop_cleanup_.load(); });

        if (!stop_cleanup_) {
            lock.unlock();  // 释放锁再执行清理
            cleanupIdle();

            if (config_.enable_auto_scaling) {
                autoScale();
            }
        }
    }
}

AlgorithmPool::PoolStatus AlgorithmPool::getStatus(const std::string& algorithm_name) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    PoolStatus status{};

    auto it = pools_.find(algorithm_name);
    if (it != pools_.end()) {
        const auto& pool = it->second;
        status.total_instances = pool.size();

        for (const auto& algo : pool) {
            if (algo->in_use.load()) {
                status.in_use_instances++;
            } else {
                status.available_instances++;
            }
        }

        status.utilization_rate = status.total_instances > 0 ?
            static_cast<double>(status.in_use_instances) / status.total_instances : 0.0;
    }

    // 计算命中率
    auto stats_it = usage_stats_.find(algorithm_name);
    if (stats_it != usage_stats_.end()) {
        const auto& stats = stats_it->second;
        size_t total = stats.hits.load() + stats.misses.load();
        status.hit_rate = total > 0 ?
            static_cast<double>(stats.hits.load()) / total : 0.0;
    }

    return status;
}

std::unordered_map<std::string, AlgorithmPool::PoolStatus> AlgorithmPool::getAllStatus() const {
    std::unordered_map<std::string, PoolStatus> all_status;

    std::lock_guard<std::mutex> lock(pool_mutex_);
    for (const auto& [name, _] : pools_) {
        all_status[name] = getStatus(name);
    }

    return all_status;
}

std::string AlgorithmPool::getPerformanceReport() const {
    std::stringstream ss;

    ss << "=== Algorithm Pool Performance Report ===" << std::endl;
    ss << std::fixed << std::setprecision(2);

    auto all_status = getAllStatus();

    for (const auto& [name, status] : all_status) {
        ss << "\nAlgorithm: " << name << std::endl;
        ss << "  Total instances: " << status.total_instances << std::endl;
        ss << "  In use: " << status.in_use_instances << std::endl;
        ss << "  Available: " << status.available_instances << std::endl;
        ss << "  Utilization: " << (status.utilization_rate * 100) << "%" << std::endl;
        ss << "  Hit rate: " << (status.hit_rate * 100) << "%" << std::endl;

        auto stats_it = usage_stats_.find(name);
        if (stats_it != usage_stats_.end()) {
            const auto& stats = stats_it->second;
            ss << "  Total requests: " << stats.total_requests.load() << std::endl;
            ss << "  Creates: " << stats.creates.load() << std::endl;
            ss << "  Evictions: " << stats.evictions.load() << std::endl;
        }
    }

    return ss.str();
}

void AlgorithmPool::resetStats() {
    for (auto& [_, stats] : usage_stats_) {
        stats.total_requests = 0;
        stats.hits = 0;
        stats.misses = 0;
        stats.creates = 0;
        stats.evictions = 0;
    }
}


// 全局实例
AlgorithmPool& getGlobalAlgorithmPool() {
    static AlgorithmPool instance;
    return instance;
}

} // namespace triofuzz