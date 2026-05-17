#include "../../include/core/batch_executor.hpp"
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>
#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace triofuzz {

BatchExecutor::BatchExecutor(const BatchConfig& config)
    : config_(config),
      coverage_collector_(getGlobalCoverageCollector()) {

    // Initialize thread pool
    if (config_.enable_parallel) {
        for (size_t i = 0; i < config_.worker_threads; i++) {
            workers_.emplace_back(&BatchExecutor::workerThread, this);
        }
    }

    // Preallocate memory pool
    for (size_t i = 0; i < config_.batch_size * 2; i++) {
        memory_pool_.buffers.emplace_back();
        memory_pool_.buffers.back().reserve(65536);  // Preallocate 64KB
    }
}

BatchExecutor::~BatchExecutor() {
    // Stop worker threads
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    cv_.notify_all();

    // Wait for all threads to finish
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void BatchExecutor::workerThread() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });

            if (stop_ && tasks_.empty()) {
                return;
            }

            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }

        if (task) {
            task();
        }
    }
}

BatchExecutor::BatchResult BatchExecutor::executeBatch(
    const std::vector<std::vector<uint8_t>>& inputs) {

    auto start_time = std::chrono::high_resolution_clock::now();

    BatchResult batch_result;
    batch_result.results.reserve(inputs.size());

    if (config_.enable_parallel && inputs.size() > 4) {
        // Parallel execution
        batch_result.results = parallelExecute(inputs);
    } else {
        // Serial execution
        for (const auto& input : inputs) {
            batch_result.results.push_back(executeOne(input));
        }
    }

    // Batch coverage analysis
    batchCoverageAnalysis(batch_result);

    // Count crashes
    for (const auto& result : batch_result.results) {
        if (result.status == ExecutionStatus::CRASHED) {
            batch_result.crash_count++;
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    batch_result.total_exec_time = std::chrono::duration<double>(end_time - start_time).count();

    // Update statistics
    stats_.total_executions.fetch_add(inputs.size(), std::memory_order_relaxed);
    stats_.total_batches.fetch_add(1, std::memory_order_relaxed);
    stats_.total_new_coverage.fetch_add(batch_result.new_edge_count, std::memory_order_relaxed);
    stats_.total_crashes.fetch_add(batch_result.crash_count, std::memory_order_relaxed);
    // atomic<double> doesn't support fetch_add; use a mutex.
    static std::mutex time_mutex;
    {
        std::lock_guard<std::mutex> lock(time_mutex);
        double current = stats_.total_time.load();
        stats_.total_time.store(current + batch_result.total_exec_time);
    }

    return batch_result;
}

std::future<BatchExecutor::BatchResult> BatchExecutor::executeBatchAsync(
    const std::vector<std::vector<uint8_t>>& inputs) {

    return std::async(std::launch::async, [this, inputs]() {
        return executeBatch(inputs);
    });
}

std::vector<BatchExecutor::ExecutionResult> BatchExecutor::parallelExecute(
    const std::vector<std::vector<uint8_t>>& inputs) {

    std::vector<BatchExecutor::ExecutionResult> results(inputs.size());
    std::vector<std::future<void>> futures;

    // Dispatch execution tasks to the thread pool
    for (size_t i = 0; i < inputs.size(); i++) {
        auto task = [this, &inputs, &results, i]() {
            results[i] = executeOne(inputs[i]);
        };

        std::packaged_task<void()> packaged_task(task);
        futures.push_back(packaged_task.get_future());

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            tasks_.emplace([pt = std::make_shared<std::packaged_task<void()>>(std::move(packaged_task))]() {
                (*pt)();
            });
        }
        cv_.notify_one();
    }

    // Wait for all tasks to complete
    for (auto& future : futures) {
        future.wait();
    }

    return results;
}

BatchExecutor::ExecutionResult BatchExecutor::executeOne(const std::vector<uint8_t>& input) {
    if (!target_executor_) {
        throw std::runtime_error("Target executor not set");
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Execute target function
    BatchExecutor::ExecutionResult result = target_executor_(input);

    auto end = std::chrono::high_resolution_clock::now();
    result.performance.execution_time_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    return result;
}

    void BatchExecutor::batchCoverageAnalysis(BatchResult& batch_result) {
    size_t new_edges_total = 0;

    // Batch-check for new coverage
    for (size_t i = 0; i < batch_result.results.size(); i++) {
        auto& result = batch_result.results[i];

        // Check for new coverage
        bool has_new = false;
        if (!result.coverage.new_edges.empty()) {
            // Update the coverage collector in batch
            // Convert uint64_t to uint32_t for the coverage collector
            std::vector<uint32_t> edges_32;
            edges_32.reserve(result.coverage.new_edges.size());
            for (uint64_t edge : result.coverage.new_edges) {
                edges_32.push_back(static_cast<uint32_t>(edge));
            }
            size_t new_edges = coverage_collector_.recordCoverageBatch(edges_32);
            if (new_edges > 0) {
                has_new = true;
                new_edges_total += new_edges;
            }
        }

        if (has_new && i < MAX_BATCH_SIZE) {
            batch_result.has_new_coverage.set(i);
        }
    }

    batch_result.new_edge_count = new_edges_total;
}

void BatchExecutor::prefetchData(const std::vector<uint8_t>& data) {
    #ifdef __builtin_prefetch
    // Prefetch data into L1 cache
    const size_t cache_line_size = 64;
    const uint8_t* ptr = data.data();
    size_t size = data.size();

    for (size_t i = 0; i < size; i += cache_line_size) {
        __builtin_prefetch(ptr + i, 0, 3);  // Prefetch for reading; high temporal locality
    }
    #endif
}

std::vector<std::vector<uint8_t>> BatchExecutor::vectorizedMutation(
    const std::vector<std::vector<uint8_t>>& inputs) {

    std::vector<std::vector<uint8_t>> mutated;
    mutated.reserve(inputs.size());

    // Simple SIMD-optimized bit-flip mutation example
    #ifdef __AVX2__
    const __m256i flip_mask = _mm256_set1_epi8(0x01);  // Flip the lowest bit

    for (const auto& input : inputs) {
        std::vector<uint8_t> output = input;
        size_t size = input.size();
        size_t simd_size = size & ~31;  // Align to 32 bytes

        for (size_t i = 0; i < simd_size; i += 32) {
            __m256i data = _mm256_loadu_si256((__m256i*)(input.data() + i));
            __m256i mutated_data = _mm256_xor_si256(data, flip_mask);
            _mm256_storeu_si256((__m256i*)(output.data() + i), mutated_data);
        }

        // Handle remaining bytes
        for (size_t i = simd_size; i < size; i++) {
            output[i] ^= 0x01;
        }

        mutated.push_back(std::move(output));
    }
    #else
    // Non-SIMD fallback
    for (const auto& input : inputs) {
        std::vector<uint8_t> output = input;
        for (auto& byte : output) {
            byte ^= 0x01;
        }
        mutated.push_back(std::move(output));
    }
    #endif

    return mutated;
}

void BatchExecutor::adjustBatchSize(double coverage_rate, double exec_time) {
    // Adaptively adjust batch size
    if (coverage_rate > 0.1) {
        // High coverage discovery rate: shrink batch for faster feedback
        config_.batch_size = std::max(size_t(32),
            config_.batch_size - config_.batch_size / 4);
    } else if (coverage_rate < 0.01 && exec_time < 10.0) {
        // Low coverage and fast execution: grow batch to increase throughput
        config_.batch_size = std::min(MAX_BATCH_SIZE,
            config_.batch_size + config_.batch_size / 4);
    }
}

std::unique_ptr<BatchExecutor::Pipeline> BatchExecutor::createOptimizedPipeline() {
    auto pipeline = std::make_unique<Pipeline>();

    // Mutation stage
    pipeline->addStage(Pipeline::MUTATION, [](void* data) {
        // Mutation processing logic
    });

    // Execution stage
    pipeline->addStage(Pipeline::EXECUTION, [this](void* data) {
        auto* input = static_cast<std::vector<uint8_t>*>(data);
        auto result = executeOne(*input);
        // Pass results to the next stage
    });

    // Analysis stage
    pipeline->addStage(Pipeline::ANALYSIS, [](void* data) {
        // Coverage analysis logic
    });

    // Feedback stage
    pipeline->addStage(Pipeline::FEEDBACK, [](void* data) {
        // Feedback processing logic
    });

    return pipeline;
}

std::string BatchExecutor::getPerformanceReport() const {
    std::stringstream ss;

    ss << "=== Batch Executor Performance Report ===" << std::endl;
    ss << std::fixed << std::setprecision(2);

    uint64_t total_execs = stats_.total_executions.load();
    uint64_t total_batches = stats_.total_batches.load();
    uint64_t new_coverage = stats_.total_new_coverage.load();
    uint64_t crashes = stats_.total_crashes.load();
    double total_time = stats_.total_time.load();

    if (total_batches > 0) {
        ss << "Total executions: " << total_execs << std::endl;
        ss << "Total batches: " << total_batches << std::endl;
        ss << "Avg batch size: " << total_execs / total_batches << std::endl;
        ss << "Executions/sec: " << total_execs / total_time << std::endl;
        ss << "New coverage edges: " << new_coverage << std::endl;
        ss << "Crashes found: " << crashes << std::endl;
        ss << "Coverage efficiency: " << (new_coverage * 100.0) / total_execs << "%" << std::endl;
    }

    ss << "Batch configuration:" << std::endl;
    ss << "  Current batch size: " << config_.batch_size << std::endl;
    ss << "  Parallel execution: " << (config_.enable_parallel ? "enabled" : "disabled") << std::endl;
    ss << "  Worker threads: " << config_.worker_threads << std::endl;

    return ss.str();
}

void BatchExecutor::resetStats() {
    stats_.total_executions = 0;
    stats_.total_batches = 0;
    stats_.total_new_coverage = 0;
    stats_.total_crashes = 0;
    stats_.total_time = 0.0;
}

// Pipeline implementation
BatchExecutor::Pipeline::Pipeline() {}

BatchExecutor::Pipeline::~Pipeline() {
    stop();
}

void BatchExecutor::Pipeline::addStage(Stage stage, std::function<void(void*)> processor) {
    auto ps = std::make_unique<PipelineStage>();
    ps->stage = stage;
    ps->processor = processor;
    stages_.push_back(std::move(ps));
}

void BatchExecutor::Pipeline::run() {
    for (auto& stage : stages_) {
        stage_threads_.emplace_back([s = stage.get()]() {
            while (true) {
                void* data = nullptr;

                {
                    std::unique_lock<std::mutex> lock(s->mutex);
                    s->cv.wait(lock, [s] {
                        return !s->input_queue.empty();
                    });

                    if (!s->input_queue.empty()) {
                        data = s->input_queue.front();
                        s->input_queue.pop();
                    }
                }

                if (data) {
                    s->processor(data);

                    {
                        std::lock_guard<std::mutex> lock(s->mutex);
                        s->output_queue.push(data);
                    }
                    s->cv.notify_all();
                }
            }
        });
    }
}

void BatchExecutor::Pipeline::stop() {
    // Stop all stage threads
    for (auto& thread : stage_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void BatchExecutor::Pipeline::submit(void* data) {
    if (!stages_.empty()) {
        std::lock_guard<std::mutex> lock(stages_[0]->mutex);
        stages_[0]->input_queue.push(data);
        stages_[0]->cv.notify_one();
    }
}

void* BatchExecutor::Pipeline::getResult() {
    if (!stages_.empty()) {
        auto& last_stage = stages_.back();
        std::unique_lock<std::mutex> lock(last_stage->mutex);

        last_stage->cv.wait(lock, [&last_stage] {
            return !last_stage->output_queue.empty();
        });

        if (!last_stage->output_queue.empty()) {
            void* result = last_stage->output_queue.front();
            last_stage->output_queue.pop();
            return result;
        }
    }
    return nullptr;
}

} // namespace triofuzz
