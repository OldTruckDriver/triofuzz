#pragma once

#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <deque>
#include <memory>
#include <shared_mutex>
#include <functional>
#include <map>
#include <unordered_map>
#include <atomic>
#include <string>
#include <random>
#include "engine.hpp"
#include "mopt_online_learner.hpp"
#include "triofuzz_unified_learner.hpp"

namespace triofuzz {

// Forward declarations
class CorpusManager;
class CoverageTracker;
class ExecutionTracer;
class InProcessExecutor;

struct SynergyContribution {
    std::string key;
    double reward;
};

// TrioFuzz seed selection result (used by schedules such as EcoFuzz).
struct SeedSelectionResult {
    std::shared_ptr<std::vector<uint8_t>> seed;
    uint64_t seed_hash = 0;          // Hash of the *parent* seed data.
    uint64_t ecofuzz_cycle_id = 0;   // Non-zero only for EcoFuzz scheduled tasks.
};

// Task structure - worker threads dequeue from the task queue
struct FuzzTask {
    AlgorithmCombination combination;
    std::shared_ptr<std::vector<uint8_t>> seed;
    size_t task_id;
    uint64_t seed_hash = 0;          // Hash of the *parent* seed data.
    uint64_t ecofuzz_cycle_id = 0;   // Non-zero only for EcoFuzz scheduled tasks.
};

// Execution result feedback
struct TaskResult {
    size_t task_id;
    AlgorithmCombination combination;
    bool found_new_coverage;
    bool crashed;
    double reward;
    double execution_time_ms;  // Execution time (ms), used for time normalization
    uint64_t seed_hash = 0;          // Hash of the *parent* seed data.
    uint64_t ecofuzz_cycle_id = 0;   // Non-zero only for EcoFuzz scheduled tasks.
};

// Execution callback type - FuzzingEngine provides the actual execution logic
using ExecutionCallback = std::function<ExecutionResult(
    const std::vector<uint8_t>& seed,
    const AlgorithmCombination& combination
)>;

// Coverage callback type - get current number of covered edges
using CoverageCallback = std::function<size_t()>;

	// Specialized thread engine - separates scheduling from execution
	class SpecializedThreadEngine {
	public:
    SpecializedThreadEngine(
        FuzzingConfig config,
        CorpusManager* corpus_manager,
        CoverageTracker* coverage_tracker,
        ExecutionTracer* execution_tracer,
        InProcessExecutor* executor,
        ExecutionCallback execution_callback,
        CoverageCallback coverage_callback
    );

    ~SpecializedThreadEngine();

    // Start/stop
    void start();
    void stop();

    // Statistics
    size_t getTotalExecutions() const { return total_executions_.load(); }
    double getCoveragePercentage() const;
    size_t getUniqueCrashes() const;

	private:
	    // Three thread types
	    void schedulerThread();      // Scheduler thread - Thompson Sampling decisions
	    void workerThread(size_t id);   // Worker thread - fast execution
	    void explorerThread(size_t id); // Explorer thread - test new combinations
	    void schedulerThreadMOpt();     // Scheduler thread - MOpt (PSO) operator selection
	    void workerThreadMOpt(size_t id);   // Worker thread - execute MOpt tasks
	    void explorerThreadMOpt(size_t id); // Explorer thread - random operator exploration
	    void schedulerThreadTS();    // Scheduler thread - Trio-TS (TS over configs + AFL++ schedules)
	    void workerThreadTS(size_t id);   // Worker thread - execute TS tasks
	    void explorerThreadTS(size_t id); // Explorer thread - TS exploration tasks
	    void schedulerThreadTrioFuzz();      // Scheduler thread - TrioFuzz three-layer learning
	    void workerThreadTrioFuzz(size_t id);    // Worker thread - execute TrioFuzz tasks
	    void explorerThreadTrioFuzz(size_t id);  // Explorer thread - TrioFuzz exploration tasks
	    bool waitAndPopTask(size_t worker_id, FuzzTask& task);
	    bool stealTask(size_t thief_id, FuzzTask& task);
    void submitResult(const TaskResult& result);
    void submitResultsBatch(const std::vector<TaskResult>& results);

    // Hybrid mode helper functions
    bool tryStealNewerTask(size_t worker_id, FuzzTask& task);  // Non-blocking task acquisition
    bool hasRecentCoverage(const std::vector<TaskResult>& results, size_t window);  // Check recent coverage
    double calculateAvgReward(const std::vector<TaskResult>& results, size_t window);  // Calculate average reward

    // Adaptive exploit count
    size_t calculateAdaptiveExploitCount(const AlgorithmCombination& combo);  // Dynamically compute exploit count

    // Internal helper methods
    AlgorithmCombination selectTopCombination();
    AlgorithmCombination selectExplorationCombination();
    std::shared_ptr<std::vector<uint8_t>> getSeedFromCorpus();
    // Trio-TS helpers
    struct TsConfigArm;
    AlgorithmCombination buildTsCombination(const TsConfigArm& arm, bool explorer, std::mt19937& rng);
    std::shared_ptr<std::vector<uint8_t>> getSeedFromCorpusForSchedule(const TsConfigArm& arm, std::mt19937& rng);
    SeedSelectionResult getSeedFromCorpusForTrioSchedule(const std::string& schedule, std::mt19937& rng);
    void executeTask(const FuzzTask& task, TaskResult& result, size_t thread_id);
    std::shared_ptr<std::vector<uint8_t>> acquireSeedBuffer();
    void recycleSeedBuffer(std::vector<uint8_t>* buffer);
    void enqueueTask(size_t worker_index, FuzzTask&& task);
    void recordSynergyContribution(const AlgorithmCombination& combination, double reward);
    void flushSynergyUpdates(std::vector<SynergyContribution>& updates);
    void flushThreadLocalSynergyCache();
    size_t getQueueSize(size_t worker_index);

    // Configuration and components
    FuzzingConfig config_;
    CorpusManager* corpus_manager_;
    CoverageTracker* coverage_tracker_;
    ExecutionTracer* execution_tracer_;
    InProcessExecutor* executor_;
    ExecutionCallback execution_callback_;  // Execution callback
    CoverageCallback coverage_callback_;    // Coverage callback

	    // Thompson Sampling component
	    std::unique_ptr<OptimizedThompsonSampling> thompson_sampling_;

	    // AFL++ MOpt (PSO) online learner (used when config_.use_mopt_learning=true)
	    std::unique_ptr<MOptOnlineLearner> mopt_learner_;
	    std::vector<std::string> mopt_operator_names_;
	    std::unordered_map<std::string, size_t> mopt_operator_index_;

	    // Trio-TS: TS over AFL++ configs + (optional) inner MOpt learners
	    enum class TsPowerSchedule { Explore, Fast, Coe };
	    enum class TsMutator { Havoc, Mopt, Analysis };  // Analysis: advanced analysis algorithms (cmplog/redqueen/dictionary)
	    struct TsConfigArm {
	        TsPowerSchedule schedule = TsPowerSchedule::Explore;
	        TsMutator mutator = TsMutator::Havoc;
	        bool splice = false;
	        std::string key;  // e.g., "fast_mopt_splice", "explore_analysis"
	    };
	    struct TsArmStats {
	        double alpha = 1.0;
	        double beta = 1.0;
	        size_t executions = 0;
	        size_t updates = 0;
	        size_t total_finds = 0;
	        size_t window_execs = 0;
	        size_t window_finds = 0;
	        size_t last_window_finds = 0;
	        size_t last_window_cycles = 0;
	    };
	    std::vector<TsConfigArm> ts_arms_;
	    std::vector<TsArmStats> ts_stats_;
	    std::unordered_map<std::string, size_t> ts_key_to_index_;

	    std::unique_ptr<MOptOnlineLearner> ts_mopt_learner_splice_;
	    std::unique_ptr<MOptOnlineLearner> ts_mopt_learner_nosplice_;
	    std::vector<std::string> ts_mopt_ops_splice_;
	    std::vector<std::string> ts_mopt_ops_nosplice_;
	    std::unordered_map<std::string, size_t> ts_mopt_index_splice_;
	    std::unordered_map<std::string, size_t> ts_mopt_index_nosplice_;

	    // TrioFuzz Unified: three-layer learning architecture (Thompson Sampling TS + MOpt PSO + MuoFuzz Markov)
	    std::unique_ptr<triofuzz::TrioFuzzUnifiedLearner> triofuzz_learner_;

    // Tiered algorithm scheduler
    std::unique_ptr<class TieredAlgorithmScheduler> tiered_scheduler_;
    bool use_tiered_scheduler_ = true;  // Enabled by default

    // Available algorithm list (for dynamic exploration)
    std::vector<std::string> available_algorithms_;

    // Combination performance tracking (hash-based keys instead of strings, reduced overhead)
    struct CombinationPerformance {
        AlgorithmCombination combination;
        size_t executions = 0;
        size_t new_coverage_count = 0;
        size_t crash_count = 0;
        double total_reward = 0.0;
        double avg_reward = 0.0;

        // Execution time statistics (for UCB + time normalization)
        double total_execution_time_ms = 0.0;  // Cumulative execution time
        double avg_execution_time_ms = 0.0;     // Average execution time
    };
    std::unordered_map<size_t, CombinationPerformance> combination_performance_;  // Hash as key
    std::mutex performance_mutex_;

    // Algorithm Combination Learning - learn algorithm synergy effects
    struct AlgorithmPairSynergy {
        size_t co_occurrences = 0;  // Co-occurrence count
        double synergy_score = 0.0;  // Synergy score (reward boost)
    };
    std::map<std::string, AlgorithmPairSynergy> algorithm_synergies_;  // "algo1+algo2" -> synergy
    mutable std::shared_mutex synergy_mutex_;

    // N-gram (triple-step motif) synergy
    struct AlgorithmMotifStats {
        size_t support = 0;      // Occurrence count
        double score = 0.0;      // Synergy score (EMA)
    };
    std::map<std::string, AlgorithmMotifStats> algorithm_motifs_; // "a+b+c" -> stats

    // Thread management
    std::unique_ptr<std::thread> scheduler_thread_;
    std::vector<std::unique_ptr<std::thread>> worker_threads_;
    std::vector<std::unique_ptr<std::thread>> explorer_threads_;

    struct WorkerQueue {
        std::deque<FuzzTask> tasks;
        std::mutex mutex;
        std::condition_variable cv;
    };

    // Seed buffer pooling to avoid repeated large allocations
    std::mutex seed_pool_mutex_;
    std::vector<std::unique_ptr<std::vector<uint8_t>>> seed_buffer_pool_;
    size_t seed_pool_limit_;

    std::atomic<bool> running_{false};

    // Double-buffered result queue - reduces lock contention
    struct DoubleBufferedResultQueue {
        std::vector<TaskResult> active_buffer;    // Workers write here
        std::vector<TaskResult> processing_buffer; // Scheduler reads here
        std::mutex mutex;

        // Submit result (called by Worker)
        void submit(const TaskResult& result) {
            std::lock_guard<std::mutex> lock(mutex);
            active_buffer.push_back(result);
        }

        // Batch submit (called by Worker)
        void submitBatch(const std::vector<TaskResult>& results) {
            std::lock_guard<std::mutex> lock(mutex);
            active_buffer.insert(active_buffer.end(), results.begin(), results.end());
        }

        // Swap and get results (called by Scheduler)
        std::vector<TaskResult> swapAndGet() {
            std::lock_guard<std::mutex> lock(mutex);
            std::swap(active_buffer, processing_buffer);
            active_buffer.clear();  // Clear active buffer for next write cycle
            return processing_buffer;
        }
    };
    std::vector<std::unique_ptr<DoubleBufferedResultQueue>> result_queues_;  // One result queue per thread
    std::condition_variable result_cv_;

    // Worker queues for reduced contention
    std::vector<std::unique_ptr<WorkerQueue>> worker_queues_;
    size_t next_worker_to_fill_ = 0;

    // Scheduler coordination
    std::mutex scheduler_mutex_;
    std::condition_variable scheduler_cv_;

    // Top combination cache - maintained by scheduler thread, read by worker threads
    std::vector<AlgorithmCombination> top_combinations_;
    std::mutex top_combinations_mutex_;

    // Statistics
    std::atomic<size_t> total_executions_{0};
    std::atomic<size_t> scheduler_decisions_{0};
    std::atomic<size_t> worker_executions_{0};
    std::atomic<size_t> explorer_executions_{0};
    std::atomic<size_t> task_id_counter_{0};
    std::atomic<size_t> last_coverage_print_{0};  // total_results value at last coverage stats print

    // Telemetry counters
    std::atomic<size_t> fanout_triggers_{0};
    std::atomic<size_t> mcts_constructed_{0};
    std::atomic<size_t> baton_enqueued_{0};
    std::atomic<size_t> two_stage_triggers_{0};

    // Coverage stagnation fallback: time of most recent new coverage (steady_clock, nanoseconds)
    std::atomic<long long> last_new_cov_ns_{0};

    // ---------------------------------------------------------------------
    // EcoFuzz schedule state (ported from TS EcoFuzz prototype)
    // ---------------------------------------------------------------------
    struct EcoFuzzSeedStats {
        uint32_t serial = 0;
        uint32_t state = 0;  // 0 or 2
        bool was_fuzzed = false;

        uint64_t mutation_num = 0;
        uint64_t exec_by_mutation = 1;  // Start at 1 to avoid zero products.

        uint32_t last_found = 0;
        uint32_t last_energy = 0;
        uint32_t fuzz_level = 0;

        uint32_t n_fuzz_entry = 0;
    };

    struct EcoFuzzGlobalStats {
        static constexpr size_t kNFuzzSize = (1u << 21);
        std::vector<uint32_t> n_fuzz;

        uint64_t queued_paths_initial = 0;
        uint8_t init_flag = 0;

        uint32_t path_increase = 0;
        uint64_t total_fuzz = 0;

        uint64_t calculate_coe = 0;
        float rate = 1.0f;

        EcoFuzzGlobalStats() : n_fuzz(kNFuzzSize, 0) {}
    };

    struct EcoFuzzCycle {
        uint64_t seed_hash = 0;
        uint32_t assigned_energy = 0;
        uint32_t results_seen = 0;
        uint32_t record_num = 0;
        uint32_t found_count = 0;
        uint64_t start_mutation_num = 0;
        uint32_t state_of_fuzz = 0;
    };

    std::mutex ecofuzz_mutex_;
    EcoFuzzGlobalStats ecofuzz_global_;
    std::unordered_map<uint64_t, EcoFuzzSeedStats> ecofuzz_seed_stats_;
    std::vector<uint64_t> ecofuzz_seed_pool_;
    std::unordered_map<uint64_t, EcoFuzzCycle> ecofuzz_cycles_;
    std::atomic<uint64_t> ecofuzz_next_cycle_id_{1};
    uint32_t ecofuzz_serial_cnt_ = 0;
    size_t ecofuzz_last_corpus_size_ = 0;
    std::chrono::steady_clock::time_point ecofuzz_last_refresh_time_{};

    // Thread configuration
    size_t num_workers_;
    size_t num_explorers_;
};

} // namespace triofuzz
