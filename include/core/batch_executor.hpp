#pragma once

#include <vector>
#include <queue>
#include <future>
#include <functional>
#include <atomic>
#include <thread>
#include "../core/context.hpp"
#include "../core/algorithm.hpp"
#include "../utils/corpus_manager.hpp"
#include "lockfree_coverage_collector.hpp"

namespace triofuzz {

// Batch execution framework - improves throughput
class BatchExecutor {
public:
    static constexpr size_t DEFAULT_BATCH_SIZE = 128;
    static constexpr size_t MAX_BATCH_SIZE = 1024;
    static constexpr size_t PREFETCH_DISTANCE = 4;

    // Execution status enum
    enum class ExecutionStatus {
        SUCCESS,
        CRASHED,
        TIMEOUT,
        ERROR
    };

    // Execution result definition
    struct ExecutionResult {
        std::vector<uint8_t> input_data;
        CoverageInfo coverage;
        PerformanceInfo performance;
        ExecutionStatus status = ExecutionStatus::SUCCESS;
        std::string error_message;
    };

    // Batch execution result
    struct BatchResult {
        std::vector<ExecutionResult> results;
        std::bitset<MAX_BATCH_SIZE> has_new_coverage;
        size_t new_edge_count = 0;
        size_t crash_count = 0;
        double total_exec_time = 0.0;

        // Statistics
        double avg_exec_time() const {
            return results.empty() ? 0.0 : total_exec_time / results.size();
        }

        double new_coverage_rate() const {
            return results.empty() ? 0.0 :
                   static_cast<double>(has_new_coverage.count()) / results.size();
        }
    };

    // Batch configuration
    struct BatchConfig {
        size_t batch_size;
        bool enable_parallel;
        bool enable_prefetch;
        bool enable_vectorization;
        size_t worker_threads;

        BatchConfig()
            : batch_size(DEFAULT_BATCH_SIZE)
            , enable_parallel(true)
            , enable_prefetch(true)
            , enable_vectorization(true)
            , worker_threads(std::thread::hardware_concurrency()) {}
    };

private:
    BatchConfig config_;
    LockFreeCoverageCollector& coverage_collector_;

    // Executor function type
    using Executor = std::function<ExecutionResult(const std::vector<uint8_t>&)>;
    Executor target_executor_;

    // Thread pool
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};

    // Performance stats
    struct BatchStats {
        std::atomic<uint64_t> total_executions{0};
        std::atomic<uint64_t> total_batches{0};
        std::atomic<uint64_t> total_new_coverage{0};
        std::atomic<uint64_t> total_crashes{0};
        std::atomic<double> total_time{0.0};
    };
    BatchStats stats_;

    // Memory pool to avoid frequent allocations
    struct MemoryPool {
        std::vector<std::vector<uint8_t>> buffers;
        std::mutex mutex;

        std::vector<uint8_t> acquire() {
            std::lock_guard<std::mutex> lock(mutex);
            if (!buffers.empty()) {
                auto buffer = std::move(buffers.back());
                buffers.pop_back();
                return buffer;
            }
            return std::vector<uint8_t>();
        }

        void release(std::vector<uint8_t>&& buffer) {
            std::lock_guard<std::mutex> lock(mutex);
            buffer.clear();
            buffers.push_back(std::move(buffer));
        }
    };
    MemoryPool memory_pool_;

public:
    explicit BatchExecutor(const BatchConfig& config = BatchConfig());
    ~BatchExecutor();

    // Set target executor
    void setTargetExecutor(Executor executor) {
        target_executor_ = std::move(executor);
    }

    // Execute inputs in batch
    BatchResult executeBatch(const std::vector<std::vector<uint8_t>>& inputs);

    // Async batch execution
    std::future<BatchResult> executeBatchAsync(const std::vector<std::vector<uint8_t>>& inputs);

    // Execute a mutation batch
    template<typename MutationAlgorithm>
    BatchResult executeMutationBatch(
        const std::vector<Seed>& seeds,
        MutationAlgorithm& mutation_algo,
        SharedContext& context);

    // Parallel pipeline execution
    class Pipeline {
    public:
        // Stage definition
        enum Stage {
            MUTATION,
            EXECUTION,
            ANALYSIS,
            FEEDBACK
        };

    private:
        struct PipelineStage {
            Stage stage;
            std::function<void(void*)> processor;
            std::queue<void*> input_queue;
            std::queue<void*> output_queue;
            std::mutex mutex;
            std::condition_variable cv;

            // Make PipelineStage non-copyable and non-moveable due to mutex
            PipelineStage() = default;
            PipelineStage(PipelineStage&&) = delete;
            PipelineStage& operator=(PipelineStage&&) = delete;
            PipelineStage(const PipelineStage&) = delete;
            PipelineStage& operator=(const PipelineStage&) = delete;
        };

        std::vector<std::unique_ptr<PipelineStage>> stages_;
        std::vector<std::thread> stage_threads_;

    public:
        Pipeline();
        ~Pipeline();

        // Add processing stage
        void addStage(Stage stage, std::function<void(void*)> processor);

        // Run pipeline
        void run();

        // Stop pipeline
        void stop();

        // Submit data to pipeline
        void submit(void* data);

        // Get result
        void* getResult();
    };

    // Create optimized execution pipeline
    std::unique_ptr<Pipeline> createOptimizedPipeline();

    // Adaptive batch size adjustment
    void adjustBatchSize(double coverage_rate, double exec_time);

    // Get performance report
    std::string getPerformanceReport() const;

    // Reset stats
    void resetStats();

private:
    // Worker thread function
    void workerThread();

    // Execute a single input (internal)
    ExecutionResult executeOne(const std::vector<uint8_t>& input);

    // Prefetch data into cache
    void prefetchData(const std::vector<uint8_t>& data);

    // SIMD-optimized batch mutation
    std::vector<std::vector<uint8_t>> vectorizedMutation(
        const std::vector<std::vector<uint8_t>>& inputs);

    // Helper for parallel execution
    std::vector<ExecutionResult> parallelExecute(
        const std::vector<std::vector<uint8_t>>& inputs);

    // Batch coverage analysis
    void batchCoverageAnalysis(BatchResult& batch_result);
};

// Template implementation
template<typename MutationAlgorithm>
BatchExecutor::BatchResult BatchExecutor::executeMutationBatch(
    const std::vector<Seed>& seeds,
    MutationAlgorithm& mutation_algo,
    SharedContext& context) {

    std::vector<std::vector<uint8_t>> mutated_inputs;
    mutated_inputs.reserve(config_.batch_size);

    // Generate mutated inputs in batch
    for (size_t i = 0; i < config_.batch_size && i < seeds.size(); i++) {
        // Prefetch next seed data
        if (config_.enable_prefetch && i + PREFETCH_DISTANCE < seeds.size()) {
            prefetchData(seeds[i + PREFETCH_DISTANCE].data);
        }

        // Apply mutation
        std::vector<uint8_t> mutation_input = seeds[i].data;
        auto mutated = mutation_algo.execute(mutation_input, context);
        mutated_inputs.push_back(std::move(mutated));
    }

    // Execute batch
    return executeBatch(mutated_inputs);
}

} // namespace triofuzz
