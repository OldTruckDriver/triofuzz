#pragma once

#include "algorithm.hpp"
#include "context.hpp"
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <functional>
#include <chrono>
#include <shared_mutex>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <set>
#include <cmath>
#include <iostream>

// ---- Compile-time performance instrumentation switch ----
// Set to 1 to enable detailed per-iteration timing logs and counters
// across SpecializedThreadEngine and FuzzingEngine.
#ifndef ENABLE_DETAILED_PERF
#define ENABLE_DETAILED_PERF 0
#endif

namespace triofuzz {

// Forward declarations
class AlgorithmRegistry;
class AlgorithmCombiner;
class PerformanceMonitor;
class ConfigManager;
class CorpusManager;
class CoverageCollector;
class CrashAnalyzer;
class BatchAlgorithmSelector;
class Executor;
class AlgorithmPool;
class BatchExecutor;
class LockFreeCoverageCollector;
class OptimizedThompsonSampling;

// Seed structure
struct Seed {
    std::vector<uint8_t> data;
    uint64_t data_hash = 0;  // Hash of |data| (computed by CorpusManager for fast lookup)
    CoverageInfo coverage;
    PerformanceInfo performance;
    std::vector<std::string> algorithm_history;
    double energy = 1.0;
    size_t generation = 0;
    size_t execution_count = 0;  // Track how many times this seed has been executed
    std::chrono::system_clock::time_point created_time;
    std::map<std::string, std::any> metadata;

    // AFL++-style attributes
    size_t handicap = 0;  // Execution penalty
    size_t fuzz_level = 0;  // Mutation level
    double perf_score = 1.0;  // Performance score
    size_t depth = 0;  // Path depth
    bool favored = false;  // Whether this seed is favored
    size_t parent_id = 0;  // Parent seed ID
    bool deterministic_done = false;  // Whether deterministic stage is complete

    // AFL++ core calibration and trimming attributes
    bool calibrated = false;          // Whether seed has been calibrated
    bool trimmed = false;             // Whether seed has been trimmed
    uint32_t exec_cksum = 0;          // Execution path checksum (for stability checks)
    uint64_t exec_us = 0;             // Average execution time (microseconds)
    std::vector<uint8_t> trace_bits;  // Coverage bitmap for this seed (8-bit counters)

    // Calibration results
    bool stable_coverage = true;      // Whether path is stable (same coverage across runs)
    size_t calibration_cycles = 0;    // Number of calibration runs
    double stability_ratio = 1.0;     // Stability ratio (stable runs / total runs)

    // Compute seed priority
    double getPriority() const {
        double priority = energy;

        // Coverage gain (enhanced weight)
        priority *= (1.0 + coverage.coverage_gain * 2.0);

        // Rare edges (enhanced weight)
        priority *= (1.0 + coverage.rare_edges.size() * 0.2);

        // Execution speed factor
        if (performance.execution_time_ms > 0) {
            priority *= (100.0 / performance.execution_time_ms);
        }

        // Execution count decay
        priority *= std::pow(0.99, execution_count);

        // Performance score factor
        priority *= perf_score;

        // Favored seed bonus
        if (favored) {
            priority *= 1.5;
        }

        return priority;
    }

    // Compute seed quality score
    double getQualityScore() const {
        double score = 0.0;

        // Coverage contribution
        score += coverage.coverage_gain * 100;
        score += coverage.branch_coverage_gain * 50;
        score += coverage.rare_edges.size() * 10;
        score += coverage.new_edges.size() * 5;

        // Performance contribution
        if (performance.execution_time_ms < 10) {
            score += 20;
        } else if (performance.execution_time_ms < 50) {
            score += 10;
        }

        // Size contribution
        if (data.size() < 100) {
            score += 10;
        } else if (data.size() < 1000) {
            score += 5;
        }

        return score;
    }
};

// Execution result
struct ExecutionResult {
    enum class Status {
        Success,
        Crash,
        Timeout,
        Error
    };
    
    Status status = Status::Success;
    std::vector<uint8_t> output;
    std::vector<uint8_t> input_data;
    CoverageInfo coverage;
    PerformanceInfo performance;
    std::string error_message;
    std::vector<std::string> crash_info;
    std::vector<std::string> stack_trace;
    std::optional<int> exit_code;
    
    bool isInteresting() const {
        return status == Status::Crash || coverage.hasNewCoverage();
    }
};

// Algorithm combination - complete fuzzing pipeline
struct AlgorithmCombination {
    // Layer 1: Seed scheduler (optional; empty uses CorpusManager default)
    std::string scheduler_name = "";  // e.g., "rare_edge_scheduler", "fast_scheduler", "mopt_scheduler"

    // Layer 2: Mutation algorithms
    std::vector<std::string> algorithm_names;
    std::string combination_mode = "sequential"; // Initialize with default value
    std::map<std::string, double> weights;

    // Layer 3: Feedback analyzer (optional; empty uses default CoverageAnalyzer)
    std::string feedback_analyzer = "";  // e.g., "coverage_analyzer", "crash_analyzer", "enhanced_coverage_analyzer"

    // Default constructor
    AlgorithmCombination() = default;

    // Copy constructor with safety checks
    AlgorithmCombination(const AlgorithmCombination& other) {
        // Validate source data before copying
        const size_t MAX_REASONABLE_SIZE = 10000; // Maximum reasonable number of algorithms

        // Check if the source vector size is reasonable
        if (other.algorithm_names.size() > MAX_REASONABLE_SIZE) {
            // Data appears corrupted, create empty object instead
            std::cerr << "[WARNING] AlgorithmCombination copy constructor: source has unreasonable size "
                      << other.algorithm_names.size() << ", creating empty object" << std::endl;
            combination_mode = "sequential";
            return;
        }

        // Safe copy
        try {
            scheduler_name = other.scheduler_name;
            algorithm_names = other.algorithm_names;
            combination_mode = other.combination_mode;
            weights = other.weights;
            feedback_analyzer = other.feedback_analyzer;
        } catch (const std::bad_alloc& e) {
            std::cerr << "[ERROR] AlgorithmCombination copy constructor: bad_alloc caught, creating empty object" << std::endl;
            scheduler_name.clear();
            algorithm_names.clear();
            combination_mode = "sequential";
            weights.clear();
            feedback_analyzer.clear();
        } catch (...) {
            std::cerr << "[ERROR] AlgorithmCombination copy constructor: unknown exception, creating empty object" << std::endl;
            scheduler_name.clear();
            algorithm_names.clear();
            combination_mode = "sequential";
            weights.clear();
            feedback_analyzer.clear();
        }
    }

    // Move constructor
    AlgorithmCombination(AlgorithmCombination&& other) noexcept
        : scheduler_name(std::move(other.scheduler_name)),
          algorithm_names(std::move(other.algorithm_names)),
          combination_mode(std::move(other.combination_mode)),
          weights(std::move(other.weights)),
          feedback_analyzer(std::move(other.feedback_analyzer)) {
    }

    // Copy assignment operator
    AlgorithmCombination& operator=(const AlgorithmCombination& other) {
        if (this != &other) {
            AlgorithmCombination temp(other); // Use copy constructor
            std::swap(scheduler_name, temp.scheduler_name);
            std::swap(algorithm_names, temp.algorithm_names);
            std::swap(combination_mode, temp.combination_mode);
            std::swap(weights, temp.weights);
            std::swap(feedback_analyzer, temp.feedback_analyzer);
        }
        return *this;
    }

    // Move assignment operator
    AlgorithmCombination& operator=(AlgorithmCombination&& other) noexcept {
        if (this != &other) {
            scheduler_name = std::move(other.scheduler_name);
            algorithm_names = std::move(other.algorithm_names);
            combination_mode = std::move(other.combination_mode);
            weights = std::move(other.weights);
            feedback_analyzer = std::move(other.feedback_analyzer);
        }
        return *this;
    }

    // Compute combination hash (for fast lookup, avoiding string operations)
    size_t hash() const {
        size_t h = 0;
        std::hash<std::string> hasher;

        h ^= hasher(scheduler_name) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= hasher(combination_mode) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= hasher(feedback_analyzer) + 0x9e3779b9 + (h << 6) + (h >> 2);

        for (const auto& algo : algorithm_names) {
            h ^= hasher(algo) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }

        return h;
    }

    std::string toString() const {
        std::string result;

        // Add scheduler prefix (empty string displayed as "default")
        if (!scheduler_name.empty()) {
            result += scheduler_name + ":";
        } else {
            result += "default:";
        }

        result += combination_mode + "[";
        for (size_t i = 0; i < algorithm_names.size(); ++i) {
            if (i > 0) result += ",";
            result += algorithm_names[i];
        }
        result += "]";

        // Add feedback suffix (empty string displayed as "default")
        if (!feedback_analyzer.empty()) {
            result += ":" + feedback_analyzer;
        } else {
            result += ":default";
        }

        return result;
    }

    // Check if combination contains specific algorithm
    bool hasAlgorithm(const std::string& algo_name) const {
        return std::find(algorithm_names.begin(), algorithm_names.end(), algo_name) != algorithm_names.end();
    }

    // Add algorithm to combination
    void addAlgorithm(const std::string& algo_name) {
        algorithm_names.push_back(algo_name);
    }

    // Generate mutations using the algorithms in the combination
    std::vector<std::vector<uint8_t>> generateMutations(const std::vector<uint8_t>& seed, size_t count) const {
        std::vector<std::vector<uint8_t>> mutations;
        mutations.reserve(count);

        // Simple implementation: just create variations of the seed
        for (size_t i = 0; i < count; ++i) {
            std::vector<uint8_t> mutation = seed;

            // Apply simple mutations based on algorithm names
            if (!mutation.empty()) {
                // Random byte flip
                size_t pos = rand() % mutation.size();
                mutation[pos] ^= (1 << (rand() % 8));

                // Random insertion/deletion
                if (rand() % 2 == 0 && mutation.size() < 1024*1024) {
                    mutation.insert(mutation.begin() + pos, rand() % 256);
                } else if (mutation.size() > 1) {
                    mutation.erase(mutation.begin() + pos);
                }
            }

            mutations.push_back(mutation);
        }

        return mutations;
    }

    // Validate the combination
    bool isValid() const {
        const size_t MAX_REASONABLE_SIZE = 10000;

        // Check vector size
        if (algorithm_names.size() > MAX_REASONABLE_SIZE) {
            return false;
        }

        // Check if combination_mode is set
        if (combination_mode.empty()) {
            return false;
        }

        // Check weights map size
        if (weights.size() > MAX_REASONABLE_SIZE) {
            return false;
        }

        return true;
    }

    // Reset to safe defaults
    void reset() {
        algorithm_names.clear();
        combination_mode = "sequential";
        weights.clear();
    }
};

// Fuzzing configuration
struct FuzzingConfig {
    // Basic configuration
    std::string target_binary;
    std::vector<std::string> target_args;
    std::string input_dir;
    std::string output_dir;
    std::string dictionary_file; // Dictionary file path (for smart_dictionary algorithm)

    // Execution configuration
    size_t thread_count = std::thread::hardware_concurrency();
    size_t memory_limit_mb = 1024;
    std::chrono::milliseconds timeout = std::chrono::milliseconds(1000);
    size_t max_input_size = 1024 * 1024; // 1MB

    // Algorithm configuration
    std::vector<std::string> enabled_algorithms;
    std::string combination_strategy = "thompson_sampling";
    bool enable_dynamic_combination = true;

    // Strict algorithm isolation mode (for ablation experiments)
    bool strict_algorithm_isolation = false;  // Enable strict mode: only use specified algorithms, disable all extra optimizations
    bool disable_system_algorithms = false;   // Disable system-level algorithms (coverage_analyzer, crash_analyzer, etc.)
    bool disable_corpus_optimization = false; // Disable corpus optimization
    bool disable_feedback_optimization = false; // Disable feedback optimization

    // Fixed algorithm combination config (used when dynamic combination is disabled)
    struct FixedCombinationConfig {
        std::vector<std::vector<std::string>> thread_algorithm_combinations;  // Fixed algorithm combo per thread
        std::string fixed_combination_mode = "sequential";  // Fixed combination mode
    } fixed_combination;

    // Performance configuration
    bool enable_performance_monitoring = true;
    bool enable_crash_analysis = true;
    std::chrono::seconds stats_interval = std::chrono::seconds(60);

    // Corpus optimization configuration (AFL++-style)
    bool corpus_optimization_enabled = true;
    size_t corpus_optimization_interval = 300;  // seconds
    size_t target_corpus_size = 100000;
    size_t min_corpus_size = 10000;
    double corpus_bloat_threshold = 0.8;
    bool enable_aggressive_cleanup = false;

    // Specialized thread engine configuration
    bool use_specialized_threads = true;  // Enable specialized thread architecture
    size_t scheduler_threads = 1;          // Number of scheduler threads (typically 1)
    size_t explorer_threads = 1;           // Number of explorer threads
    double exploration_ratio = 0.1;        // Exploration ratio
    bool enable_adaptive_scheduling = true; // Adaptive scheduling
    size_t batch_size_for_specialized = 1000;  // Batch size for specialized threads
    // Micro-batch configuration (specialized thread engine only)
    size_t micro_batch_workers = 1;        // Consecutive executions per worker thread (>=1)
    size_t micro_batch_explorers = 8;      // Consecutive executions per explorer thread (>=1)
    // Worker queue target depth (pending tasks per worker during scheduling)
    size_t worker_queue_target_depth = 4;  // Default 4, reduces scheduling round-trip frequency

    // Worker continuous exploit configuration (hybrid mode)
    size_t worker_exploit_count = 100;     // Exploit iterations per worker task (default 100)
    size_t worker_exploit_check_interval = 50;  // Check for new tasks every N exploits (reduces lock contention)
    bool enable_exploit_early_stop = true; // Enable diminishing-returns early stop (default true)
    size_t exploit_early_stop_window = 20; // Early stop check window (default 20 iterations)
    double exploit_early_stop_threshold = 0.5; // Early stop threshold (reward drops 50%)

    // Adaptive exploit configuration (dynamically adjust batch size)
    bool enable_adaptive_exploit_count = true;  // Enable adaptive exploit count
    size_t min_exploit_count = 50;              // Minimum exploit count (slow algorithms)
    size_t max_exploit_count = 2000;            // Maximum exploit count (very fast algorithms)
    double target_exploit_duration_sec = 1.0;   // Target exploit cycle duration (seconds)

    // Live stats display configuration - controls whether coverage stats are shown during fuzzing
    // Note: independent of --enable-coverage-tracking (which records coverage to files)
    bool show_coverage_in_stats = false;    // Show coverage in live stats (may incur performance overhead)

    // Complementarity experiment config - save covered edge ID lists (for algorithm complementarity analysis)
    bool save_covered_edges = false;        // Whether to save covered edge list
    std::string covered_edges_file = "covered_edges.txt";  // Covered edge list filename

    // Collaborative mode configuration (Explorer-only; only two-stage cascade enabled by default)
    bool enable_two_stage = true;                 // Enable two-stage cascade (coarse mutation -> fine polishing)
    double two_stage_trigger_reward = 0.6;        // Minimum reward threshold to trigger second stage
    bool two_stage_trigger_on_new_coverage = true;// New coverage directly triggers second stage
    size_t two_stage_polish_min = 1;              // Minimum algorithm count for second stage
    size_t two_stage_polish_max = 2;              // Maximum algorithm count for second stage

    // Additional collaborative modes (Explorer-only)
    bool enable_mcts_step = true;                 // Intra-chain adaptive step selection (MCTS/UCB)
    bool mcts_on_stagnation_only = true;          // Only enable MCTS during stagnation
    size_t mcts_max_depth = 2;                    // Maximum depth
    size_t mcts_children = 4;                     // Candidate branches per step

    bool enable_fanout = true;                    // Fan-out best-of-K (K=2) enabled by default
    double fanout_probability = 0.20;             // Trigger probability (Explorer)

    // Adaptive weight between MCTS and fanout during stagnation (mode selection probability only)
    double mcts_min_probability = 0.30;           // Lower bound for MCTS selection probability at stagnation onset
    double mcts_max_probability = 0.80;           // Upper bound for MCTS selection probability during prolonged stagnation

    // Cross-thread baton pass
    bool enable_baton_pass = true;                // Default on: pass promising samples to polishing algorithms
    double baton_threshold_reward = 0.30;         // Minimum reward threshold to trigger baton pass

    // Sparse burst gating (heavy algorithms)
    bool enable_burst = true;                     // Default on (minimal quota)
    double burst_exec_pct = 0.01;                 // Trigger probability (Explorer)
    size_t burst_cooldown_sec = 20;               // Cooldown time (seconds)

    // N-gram synergy (triple-step motifs)
    bool enable_ngram_motifs = true;              // Default on
    size_t motif_capacity = 512;                  // Motif table capacity limit
    size_t motif_min_support = 5;                 // Minimum support count for sampling inclusion
    double motif_sample_prob = 0.30;              // Explorer motif sampling probability

    // Coverage stagnation detection window (seconds) - triggers MCTS/fan-out strategies
    size_t stagnation_seconds = 12;               // Faster stagnation detection for quicker strategy switching

	    // Crash recovery / Checkpoint configuration
	    bool enable_crash_recovery = false;           // Enable crash recovery (checkpoint + auto-restart)
	    std::string checkpoint_dir = "./checkpoints"; // Checkpoint save directory
	    size_t checkpoint_interval_sec = 60;          // Checkpoint interval (seconds)
	    bool restore_from_checkpoint = false;         // Restore from checkpoint (at startup)

	    // AFL++ MOpt (PSO) online learning configuration
	    // Learns mutation operator probability distribution, replacing Thompson Sampling for combination selection
	    bool use_mopt_learning = false;               // Enable MOpt (PSO) learning mode
	    size_t mopt_min_sequence_length = 1;          // Minimum operator sequence length per execution
	    size_t mopt_max_sequence_length = 1;          // Maximum operator sequence length per execution
	    size_t mopt_update_period = 500000;           // PSO update period (in executions, close to AFL++ MOpt core period)

	    // Thompson Sampling outer-loop configuration learning
	    // Thompson Sampling over AFL++-style configurations:
	    // power schedule x {havoc,mopt} x splice.
	    bool use_ts_scheduler = false;                // Enable TS scheduling/learning mode
	    size_t ts_update_period = 50000;              // TS update window (in executions, per-config independent count)
	    double ts_decay = 0.95;                       // EMA-style decay for Beta params (0..1, closer to 1 = longer memory)
	    uint32_t ts_havoc_stack_pow2 = 4;             // stack length: 1<<(1+rand_below(pow2)) (default=4)

		    // TrioFuzz Unified: Three-layer learning architecture
		    // Layer 1: Thompson Sampling (config arm selection)
		    // Layer 2: MOpt PSO (operator probability learning)
		    // Layer 3: MuoFuzz Markov (operator transition sequences)
		    bool use_triofuzz_unified = false;            // Enable three-layer unified learning mode
		    bool enable_ts = true;                        // Layer 1: TS config selection
		    bool enable_ecofuzz = true;                   // Allow EcoFuzz power schedule in unified learner
		    bool enable_mopt_pso = true;                  // Layer 2: MOpt PSO operator learning
		    bool enable_muofuzz_markov = true;            // Layer 3: MuoFuzz Markov transitions

	    // Hybrid period configuration for non-stationary adaptation
	    // Time periods ensure learning happens even for slow targets
	    uint32_t ts_time_period_sec = 30;              // TS time period (default: 30s)
	    uint32_t mopt_time_period_sec = 30;           // MOpt PSO time period (default: 30s)
	    uint32_t markov_time_period_sec = 5;          // Markov time period (default: 5s)

	    // Minimum samples required for time-triggered updates (noise protection)
	    size_t ts_min_samples = 100;                   // TS minimum samples
	    size_t mopt_min_samples = 500;                // MOpt PSO minimum samples
	    size_t markov_min_samples = 50;               // Markov minimum samples
	};

// Fuzzing statistics
struct FuzzingStats {
    // Execution statistics
    std::atomic<size_t> total_executions{0};
    std::atomic<size_t> executions_per_second{0};
    std::atomic<size_t> total_crashes{0};
    std::atomic<size_t> unique_crashes{0};

    // Coverage statistics
    std::atomic<size_t> total_coverage{0};
    std::atomic<double> coverage_percentage{0.0};
    std::atomic<size_t> new_coverage_found{0};

    // Branch coverage statistics
    std::atomic<size_t> total_branches{0};
    std::atomic<size_t> covered_branches{0};
    std::atomic<double> branch_coverage_percentage{0.0};
    std::atomic<size_t> new_branches_found{0};
    std::atomic<size_t> taken_branches{0};
    std::atomic<size_t> not_taken_branches{0};

    // Performance statistics
    std::atomic<double> average_exec_time_ms{0.0};
    std::atomic<size_t> total_memory_usage_mb{0};

    // Algorithm statistics
    std::map<std::string, size_t> algorithm_usage;
    std::map<std::string, double> algorithm_effectiveness;

    // Time statistics
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_coverage_time;
    std::chrono::system_clock::time_point last_crash_time;
};

// Fuzzing engine
class FuzzingEngine {
private:
    // Configuration
    FuzzingConfig config_;

    // Core components (each FuzzingEngine instance is independent; no global singletons)
    std::unique_ptr<AlgorithmRegistry> algorithm_registry_;
    std::unique_ptr<AlgorithmCombiner> algorithm_combiner_;
    std::unique_ptr<PerformanceMonitor> performance_monitor_;
    std::unique_ptr<ConfigManager> config_manager_;
    std::unique_ptr<CorpusManager> corpus_manager_;
    std::unique_ptr<CoverageCollector> coverage_collector_;
    // AFL-compatible coverage collector (independent instance to avoid cross-fuzzer pollution)
    std::unique_ptr<class AFLCompatibleCoverage> afl_coverage_;
    
    // Batch algorithm selector
    std::unique_ptr<BatchAlgorithmSelector> batch_selector_;

    // Performance optimization components
    std::unique_ptr<AlgorithmPool> algorithm_pool_;
    std::unique_ptr<BatchExecutor> batch_executor_;
    std::unique_ptr<LockFreeCoverageCollector> lockfree_coverage_collector_;

    // Optimized Thompson Sampling (preserves dynamic algorithm combination ability)
    std::unique_ptr<OptimizedThompsonSampling> optimized_thompson_;
    bool use_optimized_thompson_ = false;  // Disabled; tiered scheduler takes priority

    // Tiered algorithm scheduler - cost-based probabilistic scheduling
    std::unique_ptr<class TieredAlgorithmScheduler> tiered_scheduler_;
    bool use_tiered_scheduler_ = true;  // Enabled by default

    // Specialized thread engine - for high-performance execution
    std::unique_ptr<class SpecializedThreadEngine> specialized_engine_;
    bool use_specialized_threads_ = true;

    // Track unknown algorithm warnings (avoid duplicate output)
    mutable std::set<std::string> logged_unknown_algorithms_;
    mutable std::mutex logged_algorithms_mutex_;

	    // Shared context
	    std::unique_ptr<SharedContext> global_context_;

	    // ---------------------------------------------------------------------
	    // Lightweight online learning state (TrioFuzz-only, harness-agnostic)
	    // ---------------------------------------------------------------------
	    // Auto-dictionary epoch: incremented when auto_dictionary is updated.
	    std::atomic<uint64_t> auto_dictionary_epoch_{0};

	    // Preferred input length (moving average over new-coverage inputs).
	    std::atomic<uint64_t> preferred_length_sum_{0};
	    std::atomic<uint64_t> preferred_length_count_{0};
	    std::atomic<uint32_t> preferred_length_{0};
    
    // Custom executor (for in-process execution)
    std::shared_ptr<Executor> custom_executor_;
    
    // Default executor (avoid creating a new one each time)
    std::shared_ptr<Executor> default_executor_;

    // Worker threads
    std::vector<std::thread> worker_threads_;
    std::atomic<bool> running_{false};

    // Global start time for tracking execution time limits
    std::chrono::steady_clock::time_point global_start_time_;

    // External execution limits (set by main program)
    std::atomic<int> max_total_time_{0};
    std::atomic<size_t> max_executions_{0};

    // Dedicated algorithm threads (for recovery and specific algorithms)
    struct DedicatedAlgorithmThread {
        std::string thread_name;
        std::vector<std::string> algorithms;  // Restricted algorithm set
        std::thread thread_handle;
        std::atomic<bool> should_stop{false};
        size_t thread_id;
        // Statistics
        std::atomic<size_t> executions{0};
        std::atomic<size_t> crashes{0};
        std::atomic<size_t> new_coverage{0};
    };
    std::vector<std::unique_ptr<DedicatedAlgorithmThread>> dedicated_threads_;
    std::mutex dedicated_threads_mutex_;
    
    // Stats thread management
    std::thread stats_thread_;
    std::atomic<bool> stats_running_{false};
    
    // Statistics
    FuzzingStats stats_;

    // Algorithm diversity tracking variables
    std::map<std::string, size_t> algorithm_usage_stats_;
    std::map<std::string, std::chrono::steady_clock::time_point> last_combo_usage_;
    size_t total_algorithm_uses_ = 0;
    mutable std::mutex diversity_stats_mutex_;
    
    // Thompson Sampling variables
    std::map<std::string, std::pair<double, double>> beta_distributions_; // alpha, beta
    std::map<std::string, std::pair<size_t, double>> combination_history_; // uses, total_reward
    mutable std::mutex thompson_sampling_mutex_;

    // Callbacks
    std::function<void(const Seed&, const AlgorithmCombination&)> on_new_coverage_;
    std::function<void(const ExecutionResult&, const AlgorithmCombination&)> on_crash_;
    std::function<void(const FuzzingStats&)> on_stats_update_;
    
    // Thread lifecycle management
    std::atomic<bool> force_stop_{false};
    std::condition_variable thread_stop_cv_;
    std::mutex thread_stop_mutex_;
    
    // Thread cleanup tracking
    void registerWorkerThread(size_t thread_id);
    void unregisterWorkerThread(size_t thread_id);
    void cleanupWorkerThreadData(size_t thread_id);

    std::set<size_t> active_worker_threads_;
    std::mutex worker_threads_mutex_;

    // Checkpoint manager for crash recovery
    std::unique_ptr<class CheckpointManager> checkpoint_manager_;
    std::chrono::steady_clock::time_point last_checkpoint_time_;

public:
    explicit FuzzingEngine(const FuzzingConfig& config);
    ~FuzzingEngine();
    
    // Lifecycle management
    void initialize();
    void start();
    void stop();
    void shutdown();

    // Dedicated algorithm thread management
    void startDedicatedAlgorithmThreads(size_t libfuzzer_threads, size_t aflpp_threads);
    void stopDedicatedAlgorithmThreads();
    
    // Algorithm management
    void registerAlgorithm(const std::string& name, AlgorithmFactory factory);
    void enableAlgorithm(const std::string& name);
    void disableAlgorithm(const std::string& name);
    
    // Executor management
    void setCustomExecutor(std::shared_ptr<Executor> executor) {
        custom_executor_ = executor;
    }
    
    // Seed management
    void addSeed(const std::vector<uint8_t>& data);
    void addSeedFromFile(const std::string& filename);
    void loadInitialSeeds(const std::string& dir);
    
    // Configuration management
    void updateConfig(const FuzzingConfig& config);
    void loadConfigFromFile(const std::string& filename);

    // Set execution limits
    void setMaxTotalTime(int seconds) { max_total_time_ = seconds; }
    void setMaxExecutions(size_t max_execs) { max_executions_ = max_execs; }
    
    // Statistics query
    const FuzzingStats& getStats() const { return stats_; }

    // TUI support methods
    size_t getCorpusSize() const;
    std::optional<AlgorithmCombination> getCurrentAlgorithmCombination() const;

    // Batch info structure
    struct BatchInfo {
        size_t executions_in_batch;
        size_t batch_size;
        double average_reward;
        size_t total_switches;
    };
    std::optional<BatchInfo> getBatchInfo() const;
    std::map<std::string, size_t> getAlgorithmUsageHistory() const;
    SharedContext* getContext() { return global_context_.get(); }

    // Access instantiated components (avoids global singletons)
    AlgorithmRegistry& getAlgorithmRegistry() { return *algorithm_registry_; }
    const AlgorithmRegistry& getAlgorithmRegistry() const { return *algorithm_registry_; }
    AFLCompatibleCoverage* getAFLCoverage() { return afl_coverage_.get(); }

    // Validation and debug methods
    std::vector<std::string> getEnabledAlgorithms() const;
    std::vector<AlgorithmCombination> getActiveCombinations() const;
    
    // Strict mode validation methods
    bool validateStrictAlgorithmIsolation() const;
    void logAlgorithmUsage() const;
    std::vector<std::string> getUnauthorizedAlgorithms() const;

    // Target type detection
    bool detectStructuredInputTarget() const;

    // Set callback functions
    void setOnNewCoverage(std::function<void(const Seed&, const AlgorithmCombination&)> callback) {
        on_new_coverage_ = callback;
    }
    
    void setOnCrash(std::function<void(const ExecutionResult&, const AlgorithmCombination&)> callback) {
        on_crash_ = callback;
    }
    
    void setOnStatsUpdate(std::function<void(const FuzzingStats&)> callback) {
        on_stats_update_ = callback;
    }
    
    // Thread lifecycle management
    void forceStopAllThreads();
    void cleanupThreadLocalData();
    bool waitForThreadsToStop(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    // Print optimization statistics
    void printOptimizationStats();

    // Checkpoint / crash recovery methods
    bool saveCheckpoint();
    bool loadCheckpoint();
    void maybeCheckpoint();  // Called periodically to check if checkpoint is needed

private:
    // Core processing methods
    void workerLoop(size_t thread_id);
    void dedicatedAlgorithmLoop(DedicatedAlgorithmThread* thread_info);
    void fuzzingIteration(ThreadLocalContext& local_context);
    
    // Seed selection
    Seed selectSeed();
    Seed selectSeedWithScheduler(const AlgorithmCombination& combination);  // Seed selection with scheduler support
    void updateSeedPowerSchedule(Seed& seed);  // AFL++ power scheduling
    AlgorithmCombination selectAlgorithmCombination();
    
    // Algorithm combination selection strategies
    AlgorithmCombination selectWithThompsonSampling(const std::vector<std::string>& enabled_algorithms);
    AlgorithmCombination selectWithMCTS(const std::vector<std::string>& enabled_algorithms);
    AlgorithmCombination selectAdaptiveCombination();
    
    // Combination generation and adjustment
    std::vector<AlgorithmCombination> generateCandidateCombinations();
    AlgorithmCombination createCombination(const std::vector<std::string>& algorithms, const std::string& mode);
    double calculateContextAdjustment(const AlgorithmCombination& combo);
    
    // Algorithm selection helper methods
    std::vector<std::string> selectExploratoryAlgorithms(const std::vector<std::string>& enabled_algorithms);
    std::vector<std::string> selectFastAlgorithms(const std::vector<std::string>& enabled_algorithms);
    std::vector<std::string> selectCrashFocusedAlgorithms(const std::vector<std::string>& enabled_algorithms);
    std::vector<std::string> selectBalancedAlgorithms(const std::vector<std::string>& enabled_algorithms);
    AlgorithmCombination selectDiversityForcedCombination();

	    // Mutation operations - core methods
	    std::vector<uint8_t> applyAlgorithmCombination(
	        const std::vector<uint8_t>& input,
	        const AlgorithmCombination& combination,
	        ThreadLocalContext& local_context);

	    // Post-processing for mutated inputs (repair + distribution shaping).
	    void postProcessMutatedInput(
	        const std::vector<uint8_t>& original_input,
	        std::vector<uint8_t>& mutated_input,
	        ThreadLocalContext& local_context);

	public:  // Make applySingleAlgorithm accessible for enhanced combination executor
	    std::vector<uint8_t> applySingleAlgorithm(
	        const std::vector<uint8_t>& input,
        const std::string& algorithm_name,
        ThreadLocalContext& local_context);

private:
    
	    // Execution and result processing
	    ExecutionResult executeInput(const std::vector<uint8_t>& input);
	    void processResult(const ExecutionResult& result, const Seed& original_seed, const AlgorithmCombination& combination);
	    void processResultFast(const ExecutionResult& result, const Seed& original_seed, const AlgorithmCombination& combination);

	    // CmpLog/AutoDict publishing for the last executed input (per-thread).
	    // Returns true if auto_dictionary changed and auto_dictionary_epoch_ was bumped.
	    bool publishCmpLogFromLastExecution();

	    // Online input length preference update (called on new coverage).
	    void updatePreferredLengthOnNewCoverage(size_t input_len);

    // Feedback analyzer integration
    void processFeedbackWithAnalyzer(const ExecutionResult& result, const Seed& seed, const AlgorithmCombination& combination);
    void analyzeCrash(const ExecutionResult& result, const Seed& seed, const AlgorithmCombination& combination);
    void enhancedCoverageAnalysis(const ExecutionResult& result, const Seed& seed, const AlgorithmCombination& combination);
    
    // Performance evaluation and statistics
    double calculateCombinationReward(const ExecutionResult& result, const Seed& original_seed);
    double applyRewardSmoothing(double raw_reward, const AlgorithmCombination& combination);
    void updateAlgorithmUsageStats(const AlgorithmCombination& combination);
    void printAlgorithmUsageStats();
    void updateCombinationPerformance(const AlgorithmCombination& combination, double reward, const ExecutionResult& result);
    
    // Maintenance tasks
    void updateStats();
    void periodicTasks();
    
    // Initialization
    void registerDefaultAlgorithms();
    void initializeSmartSeeds();
};

// Executor interface
class Executor {
public:
    virtual ~Executor() = default;

    // Execute target program
    virtual ExecutionResult execute(
        const std::vector<uint8_t>& input,
        const std::chrono::milliseconds& timeout
    ) = 0;
    
    // Set environment
    virtual void setEnvironment(const std::map<std::string, std::string>& env) = 0;
    
    // Set resource limits
    virtual void setMemoryLimit(size_t limit_mb) = 0;
    virtual void setTimeLimit(std::chrono::milliseconds limit) = 0;
};

} // namespace triofuzz
