#pragma once

#include "algorithm.hpp"
#include "context.hpp"
#include "engine.hpp"
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <functional>
#include <chrono>
#include <shared_mutex>
#include <optional>
#include <map>
#include <set>
#include <random>

namespace triofuzz {

// =============================================================================
// Thread-Safe Forward Declarations
// =============================================================================

class ImprovedBatchAlgorithmSelector;
class ImprovedCoverageCollector;
class ImprovedFuzzingEngine;

// =============================================================================
// Thread-Safe Coverage Memory Structure
// =============================================================================

struct CoverageSharedMemory {
    static constexpr size_t MAX_GUARDS = 1000000;
    
    std::atomic<uint32_t> total_guards;
    std::atomic<uint32_t> initialized;
    std::atomic<uint8_t> coverage_bitmap[MAX_GUARDS];
    
    std::atomic<uint32_t> guard_start_offset;
    std::atomic<uint32_t> guard_count;
};

// =============================================================================
// Thread-Safe Algorithm Combination Selector
// =============================================================================

class ImprovedBatchAlgorithmSelector {
private:
    struct BatchInfo {
        AlgorithmCombination current_combination;
        std::atomic<size_t> executions_in_batch{0};
        std::atomic<size_t> batch_size{50000};
        std::atomic<double> total_reward{0.0};
        std::atomic<std::chrono::steady_clock::time_point> batch_start_time;
        
        std::atomic<size_t> min_batch_size{200000};
        std::atomic<size_t> max_batch_size{500000};
        std::atomic<double> adaptive_factor{1.1};
        std::atomic<size_t> stability_threshold{1000};
        std::atomic<double> min_confidence_interval{0.1};
        std::atomic<size_t> min_runtime_seconds{15};
        std::atomic<double> performance_threshold{0.15};
    };
    
    struct ThompsonSamplingData {
        // Use thread-safe wrappers for Beta distribution parameters
        struct BetaParams {
            std::atomic<double> alpha{1.0};
            std::atomic<double> beta{1.0};

            void update(double success_rate, double executions, double decay_factor = 0.7) {
                double new_alpha_delta = success_rate * executions * decay_factor;
                double new_beta_delta = (1.0 - success_rate) * executions * decay_factor;

                // Atomic add operations
                double current_alpha = alpha.load(std::memory_order_relaxed);
                while (!alpha.compare_exchange_weak(current_alpha,
                    std::min(50.0, current_alpha + new_alpha_delta),
                    std::memory_order_release, std::memory_order_relaxed));

                double current_beta = beta.load(std::memory_order_relaxed);
                while (!beta.compare_exchange_weak(current_beta,
                    std::min(50.0, current_beta + new_beta_delta),
                    std::memory_order_release, std::memory_order_relaxed));
            }

            std::pair<double, double> sample() const {
                return {alpha.load(std::memory_order_acquire),
                        beta.load(std::memory_order_acquire)};
            }
        };

        struct CombinationStats {
            std::atomic<size_t> uses{0};
            std::atomic<double> total_reward{0.0};

            void update(size_t executions, double avg_reward) {
                uses.fetch_add(executions, std::memory_order_relaxed);

                // Atomic floating point addition using CAS
                double reward_delta = avg_reward * executions;
                double current_total = total_reward.load(std::memory_order_relaxed);
                while (!total_reward.compare_exchange_weak(current_total,
                    current_total + reward_delta,
                    std::memory_order_release, std::memory_order_relaxed));
            }
        };

        // Thread-safe concurrent maps using fine-grained locking
        mutable std::shared_mutex distributions_mutex_;
        std::unordered_map<std::string, std::unique_ptr<BetaParams>> beta_distributions_;

        mutable std::shared_mutex history_mutex_;
        std::unordered_map<std::string, std::unique_ptr<CombinationStats>> combination_history_;
    };
    
    BatchInfo current_batch_;
    ThompsonSamplingData thompson_data_;
    
    const FuzzingConfig& config_;
    const std::unique_ptr<SharedContext>& global_context_;
    
    mutable std::shared_mutex batch_mutex_;
    
    // Thread-local random generator
    thread_local static std::unique_ptr<std::mt19937> local_generator_;
    
    static std::mt19937& getThreadLocalGenerator();
    AlgorithmCombination parseComboKey(const std::string& combo_key);
    
    bool shouldEndCurrentBatch() const;
    void endCurrentBatch();
    void initializeNewBatch();
    void updateThompsonSampling(const std::string& combo_key, double avg_reward, size_t executions);
    void adaptBatchSize(double avg_reward);
    AlgorithmCombination selectWithThompsonSampling();
    std::vector<AlgorithmCombination> generateCandidateCombinations();
    
public:
    ImprovedBatchAlgorithmSelector(const FuzzingConfig& config, const std::unique_ptr<SharedContext>& context);
    
    AlgorithmCombination getCurrentCombination();
    void recordExecution(double reward);
    void forceEndBatch();
    
    size_t getCurrentBatchExecutions() const;
    size_t getCurrentBatchSize() const;
    double getCurrentBatchAverageReward() const;
};

// =============================================================================
// Thread-Safe Coverage Collector
// =============================================================================

class ImprovedCoverageCollector {
private:
    static constexpr size_t MAX_EDGES = 1000000;
    
    CoverageSharedMemory* shared_memory_ = nullptr;
    std::atomic<std::set<uint32_t>*> seen_guards_ptr_{nullptr};
    mutable std::shared_mutex guards_mutex_;
    
    std::atomic<size_t> total_guards_{0};
    std::atomic<size_t> covered_edges_{0};
    
    bool initSharedMemory();
    
public:
    ImprovedCoverageCollector();
    ~ImprovedCoverageCollector();
    
    CoverageInfo getCurrentCoverage();
    void resetCoverage();
    void markGuardHit(uint32_t guard_id);
    
    size_t getCoveredEdges() const;
    double getCoveragePercentage() const;
    
    // Compatibility methods
    void clearCoverageState() { resetCoverage(); }
    size_t getTotalGuards() const { return total_guards_.load(); }
    bool isInitialized() const { return shared_memory_ != nullptr; }
};

// =============================================================================
// Thread-Safe Fuzzing Engine
// =============================================================================

class ImprovedFuzzingEngine : public FuzzingEngine {
private:
    struct MCTSData {
        std::map<std::string, std::pair<std::atomic<double>, std::atomic<size_t>>> node_stats_;
        mutable std::shared_mutex mcts_mutex_;
    };
    
    MCTSData mcts_data_;
    
    // Thread-local random generators
    thread_local static std::unique_ptr<std::mt19937> mcts_generator_;
    thread_local static std::unique_ptr<std::mt19937> adaptive_generator_;
    
    static std::mt19937& getMCTSGenerator();
    static std::mt19937& getAdaptiveGenerator();
    
    // Thread-local cleanup methods
    static void cleanupThreadLocalGenerators();
    static void cleanupAllThreadLocalData();
    
public:
    using FuzzingEngine::FuzzingEngine;  // Inherit constructors
    
    // Thread-safe algorithm selection methods
    AlgorithmCombination selectWithThompsonSampling(const std::vector<std::string>& enabled_algorithms);
    AlgorithmCombination selectWithMCTS(const std::vector<std::string>& enabled_algorithms);
    
    // Thread-safe performance update
    void updateCombinationPerformance(const AlgorithmCombination& combination, 
                                    double reward, const ExecutionResult& result);
    
    // Enhanced shutdown with thread-local cleanup
    void enhancedShutdown();
    
    // Factory methods for improved components
    std::unique_ptr<ImprovedBatchAlgorithmSelector> createImprovedBatchSelector(
        const FuzzingConfig& config, const std::unique_ptr<SharedContext>& context) {
        return std::make_unique<ImprovedBatchAlgorithmSelector>(config, context);
    }
    
    std::unique_ptr<ImprovedCoverageCollector> createImprovedCoverageCollector() {
        return std::make_unique<ImprovedCoverageCollector>();
    }
};

// =============================================================================
// Thread-Safe Utility Functions
// =============================================================================

namespace concurrency_utils {

/**
 * @brief Thread-safe singleton pattern helper
 * @tparam T The singleton type
 */
template<typename T>
class ThreadSafeSingleton {
private:
    static std::atomic<T*> instance_;
    static std::mutex creation_mutex_;
    
public:
    static T& getInstance() {
        T* tmp = instance_.load(std::memory_order_consume);
        if (!tmp) {
            std::lock_guard<std::mutex> lock(creation_mutex_);
            tmp = instance_.load(std::memory_order_consume);
            if (!tmp) {
                tmp = new T();
                instance_.store(tmp, std::memory_order_release);
            }
        }
        return *tmp;
    }
    
    static void destroy() {
        std::lock_guard<std::mutex> lock(creation_mutex_);
        T* tmp = instance_.load();
        if (tmp) {
            delete tmp;
            instance_.store(nullptr);
        }
    }
};

template<typename T>
std::atomic<T*> ThreadSafeSingleton<T>::instance_{nullptr};

template<typename T>
std::mutex ThreadSafeSingleton<T>::creation_mutex_;

/**
 * @brief Thread-safe statistics aggregator
 */
class ThreadSafeStatsAggregator {
private:
    mutable std::shared_mutex stats_mutex_;
    std::map<std::string, std::atomic<double>> numeric_stats_;
    std::map<std::string, std::atomic<size_t>> counter_stats_;
    
public:
    void updateNumeric(const std::string& key, double value) {
        std::shared_lock<std::shared_mutex> lock(stats_mutex_);
        auto it = numeric_stats_.find(key);
        if (it != numeric_stats_.end()) {
            double current = it->second.load();
            while (!it->second.compare_exchange_weak(current, current + value)) {}
        } else {
            lock.unlock();
            std::unique_lock<std::shared_mutex> write_lock(stats_mutex_);
            numeric_stats_[key].store(value);
        }
    }
    
    void incrementCounter(const std::string& key, size_t increment = 1) {
        std::shared_lock<std::shared_mutex> lock(stats_mutex_);
        auto it = counter_stats_.find(key);
        if (it != counter_stats_.end()) {
            it->second.fetch_add(increment);
        } else {
            lock.unlock();
            std::unique_lock<std::shared_mutex> write_lock(stats_mutex_);
            counter_stats_[key].store(increment);
        }
    }
    
    double getNumeric(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(stats_mutex_);
        auto it = numeric_stats_.find(key);
        return it != numeric_stats_.end() ? it->second.load() : 0.0;
    }
    
    size_t getCounter(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(stats_mutex_);
        auto it = counter_stats_.find(key);
        return it != counter_stats_.end() ? it->second.load() : 0;
    }
    
    std::map<std::string, double> getAllNumericStats() const {
        std::shared_lock<std::shared_mutex> lock(stats_mutex_);
        std::map<std::string, double> result;
        for (const auto& pair : numeric_stats_) {
            result[pair.first] = pair.second.load();
        }
        return result;
    }
    
    std::map<std::string, size_t> getAllCounterStats() const {
        std::shared_lock<std::shared_mutex> lock(stats_mutex_);
        std::map<std::string, size_t> result;
        for (const auto& pair : counter_stats_) {
            result[pair.first] = pair.second.load();
        }
        return result;
    }
};

/**
 * @brief Thread-safe circular buffer for performance metrics
 * @tparam T The element type
 */
template<typename T>
class ThreadSafeCircularBuffer {
private:
    std::vector<std::atomic<T>> buffer_;
    std::atomic<size_t> head_{0};
    std::atomic<size_t> tail_{0};
    std::atomic<size_t> size_{0};
    const size_t capacity_;
    mutable std::shared_mutex access_mutex_;
    
public:
    explicit ThreadSafeCircularBuffer(size_t capacity) 
        : buffer_(capacity), capacity_(capacity) {
        for (auto& element : buffer_) {
            element.store(T{});
        }
    }
    
    bool push(const T& item) {
        std::unique_lock<std::shared_mutex> lock(access_mutex_);
        
        size_t current_tail = tail_.load();
        size_t next_tail = (current_tail + 1) % capacity_;
        
        if (next_tail == head_.load()) {
            // Buffer is full, overwrite oldest
            head_.store((head_.load() + 1) % capacity_);
        } else {
            size_.fetch_add(1);
        }
        
        buffer_[current_tail].store(item);
        tail_.store(next_tail);
        
        return true;
    }
    
    std::optional<T> pop() {
        std::unique_lock<std::shared_mutex> lock(access_mutex_);
        
        if (size_.load() == 0) {
            return std::nullopt;
        }
        
        size_t current_head = head_.load();
        T item = buffer_[current_head].load();
        head_.store((current_head + 1) % capacity_);
        size_.fetch_sub(1);
        
        return item;
    }
    
    std::vector<T> getAll() const {
        std::shared_lock<std::shared_mutex> lock(access_mutex_);
        
        std::vector<T> result;
        result.reserve(size_.load());
        
        size_t current = head_.load();
        for (size_t i = 0; i < size_.load(); ++i) {
            result.push_back(buffer_[current].load());
            current = (current + 1) % capacity_;
        }
        
        return result;
    }
    
    size_t size() const {
        return size_.load();
    }
    
    bool empty() const {
        return size_.load() == 0;
    }
    
    bool full() const {
        return size_.load() == capacity_;
    }
};

} // namespace concurrency_utils

// =============================================================================
// Factory Functions
// =============================================================================

/**
 * @brief Create an improved fuzzing engine with all thread-safety fixes
 */
std::unique_ptr<ImprovedFuzzingEngine> createImprovedFuzzingEngine(const FuzzingConfig& config);

/**
 * @brief Create thread-safe components separately
 */
std::unique_ptr<ImprovedBatchAlgorithmSelector> createThreadSafeBatchSelector(
    const FuzzingConfig& config, const std::unique_ptr<SharedContext>& context);

std::unique_ptr<ImprovedCoverageCollector> createThreadSafeCoverageCollector();

} // namespace triofuzz 