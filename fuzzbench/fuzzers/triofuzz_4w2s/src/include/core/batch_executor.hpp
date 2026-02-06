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

// 批处理执行框架 - 提升吞吐量
class BatchExecutor {
public:
    static constexpr size_t DEFAULT_BATCH_SIZE = 128;
    static constexpr size_t MAX_BATCH_SIZE = 1024;
    static constexpr size_t PREFETCH_DISTANCE = 4;

    // 执行状态枚举
    enum class ExecutionStatus {
        SUCCESS,
        CRASHED,
        TIMEOUT,
        ERROR
    };

    // 执行结果定义
    struct ExecutionResult {
        std::vector<uint8_t> input_data;
        CoverageInfo coverage;
        PerformanceInfo performance;
        ExecutionStatus status = ExecutionStatus::SUCCESS;
        std::string error_message;
    };

    // 批次执行结果
    struct BatchResult {
        std::vector<ExecutionResult> results;
        std::bitset<MAX_BATCH_SIZE> has_new_coverage;
        size_t new_edge_count = 0;
        size_t crash_count = 0;
        double total_exec_time = 0.0;

        // 统计信息
        double avg_exec_time() const {
            return results.empty() ? 0.0 : total_exec_time / results.size();
        }

        double new_coverage_rate() const {
            return results.empty() ? 0.0 :
                   static_cast<double>(has_new_coverage.count()) / results.size();
        }
    };

    // 批次配置
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

    // 执行器函数类型
    using Executor = std::function<ExecutionResult(const std::vector<uint8_t>&)>;
    Executor target_executor_;

    // 线程池
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};

    // 性能统计
    struct BatchStats {
        std::atomic<uint64_t> total_executions{0};
        std::atomic<uint64_t> total_batches{0};
        std::atomic<uint64_t> total_new_coverage{0};
        std::atomic<uint64_t> total_crashes{0};
        std::atomic<double> total_time{0.0};
    };
    BatchStats stats_;

    // 内存池，避免频繁分配
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

    // 设置目标执行器
    void setTargetExecutor(Executor executor) {
        target_executor_ = std::move(executor);
    }

    // 批量执行输入
    BatchResult executeBatch(const std::vector<std::vector<uint8_t>>& inputs);

    // 异步批量执行
    std::future<BatchResult> executeBatchAsync(const std::vector<std::vector<uint8_t>>& inputs);

    // 执行变异批次
    template<typename MutationAlgorithm>
    BatchResult executeMutationBatch(
        const std::vector<Seed>& seeds,
        MutationAlgorithm& mutation_algo,
        SharedContext& context);

    // 并行管道执行
    class Pipeline {
    public:
        // 阶段定义
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

        // 添加处理阶段
        void addStage(Stage stage, std::function<void(void*)> processor);

        // 运行管道
        void run();

        // 停止管道
        void stop();

        // 提交数据到管道
        void submit(void* data);

        // 获取结果
        void* getResult();
    };

    // 创建优化的执行管道
    std::unique_ptr<Pipeline> createOptimizedPipeline();

    // 自适应批次大小调整
    void adjustBatchSize(double coverage_rate, double exec_time);

    // 获取性能报告
    std::string getPerformanceReport() const;

    // 重置统计
    void resetStats();

private:
    // 工作线程函数
    void workerThread();

    // 执行单个输入（内部使用）
    ExecutionResult executeOne(const std::vector<uint8_t>& input);

    // 预取数据到缓存
    void prefetchData(const std::vector<uint8_t>& data);

    // SIMD优化的批量变异
    std::vector<std::vector<uint8_t>> vectorizedMutation(
        const std::vector<std::vector<uint8_t>>& inputs);

    // 并行执行辅助函数
    std::vector<ExecutionResult> parallelExecute(
        const std::vector<std::vector<uint8_t>>& inputs);

    // 批量覆盖率分析
    void batchCoverageAnalysis(BatchResult& batch_result);
};

// 模板实现
template<typename MutationAlgorithm>
BatchExecutor::BatchResult BatchExecutor::executeMutationBatch(
    const std::vector<Seed>& seeds,
    MutationAlgorithm& mutation_algo,
    SharedContext& context) {

    std::vector<std::vector<uint8_t>> mutated_inputs;
    mutated_inputs.reserve(config_.batch_size);

    // 批量生成变异输入
    for (size_t i = 0; i < config_.batch_size && i < seeds.size(); i++) {
        // 预取下一个种子数据
        if (config_.enable_prefetch && i + PREFETCH_DISTANCE < seeds.size()) {
            prefetchData(seeds[i + PREFETCH_DISTANCE].data);
        }

        // 应用变异
        std::vector<uint8_t> mutation_input = seeds[i].data;
        auto mutated = mutation_algo.execute(mutation_input, context);
        mutated_inputs.push_back(std::move(mutated));
    }

    // 批量执行
    return executeBatch(mutated_inputs);
}

} // namespace triofuzz