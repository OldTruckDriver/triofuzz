#include "../../include/core/engine.hpp"
#include "../../include/core/optimized_thompson_sampling.hpp"  // Optimized Thompson Sampling
#include "../../include/core/specialized_thread_engine.hpp"    // Dedicated thread engine
#include "../../include/core/afl_compatible_coverage.hpp"      // AFL++ compatible coverage
#include "../../include/core/inline_8bit_coverage.hpp"         // Inline 8-bit counters coverage
#include "../../include/core/cmplog_trace_buffer.hpp"           // Lightweight trace-cmp recording
#include "../../include/utils/checkpoint_manager.hpp"           // Checkpoint manager
#include "../../include/algorithms/instrumentation/cmplog_instrumentation.hpp" // For ComparisonInfo definition
#include "../../include/utils/algorithm_registry.hpp"  // Old registry for internal FuzzingEngine use
// NOTE: Cannot include algorithms/algorithm_registry.hpp due to naming conflicts with utils/algorithm_registry.hpp
// TODO: Refactor to use a unified registry system or rename one of the classes
#include "../../include/utils/performance_monitor.hpp"
#include "../../include/utils/config_manager.hpp"
#include "../../include/utils/algorithm_config.hpp"    // Centralized algorithm config - SSOT (included after config_manager to avoid naming conflict)
#include "../../include/utils/tiered_algorithm_scheduler.hpp"  // Tiered algorithm scheduler
#include "../../include/utils/corpus_manager.hpp"
// trace_collector archived (empty stub)
#include "../../include/utils/random_utils.hpp"
#include "../../include/utils/algorithm_boost_config.hpp"
#include "../../include/combination/combiner.hpp"
#include "../../include/combination/thompson_sampling.hpp"
// anti_convergence_thompson_standalone archived (unused in unified path)
#include "../../include/core/thompson_sampling.hpp"  // New dynamic Thompson sampling
#include "../../include/core/algorithm_combination_manager.hpp"

// Algorithm header files
// #include "../../include/algorithms/mutation/all_mutations.hpp"  // archived
// #include "../../include/algorithms/mutation/classic_libfuzzer_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/trim_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/block_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/token_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/endianness_swap_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/chunk_based_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/nibble_swap_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/bit_rotate_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/varint_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/run_length_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/checksum_fixup_mutation.hpp"  // archived
#include "../../include/algorithms/mutation/format_aware_mutation.hpp"
#include "../../include/algorithms/mutation/runtime_dictionary_mutation.hpp"
#include "../../include/algorithms/mutation/format_overflow_mutation.hpp"
// #include "../../include/algorithms/mutation/value_approximation_mutation.hpp"  // archived
#include "../../include/algorithms/mutation/smart_dictionary_mutation.hpp"
#include "../../include/algorithms/mutation/structure_aware_mutation.hpp"

#include "../../include/algorithms/scheduling/scheduling_algorithms.hpp"

#include "../../include/algorithms/mutation/redqueen_mutation.hpp"
#include "../../include/algorithms/mutation/cmplog_mutation.hpp"
// #include "../../include/algorithms/mutation/rare_branch_mutation.hpp"  // archived

// #include "../../include/algorithms/mutation/magic_byte_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/length_extension_mutation.hpp"  // archived
// #include "../../include/algorithms/mutation/byte_weighted_havoc.hpp"  // archived

// AFL++ Individual Mutations (37 operators for Thompson Sampling comparison)
#include "../../include/algorithms/mutation/aflpp_individual_mutations.hpp"

#include "../../include/algorithms/instrumentation/instrumentation_algorithms.hpp"

#include "../../include/algorithms/optimization/optimization_algorithms.hpp"
#include "../../include/algorithms/optimization/pso_specialization.hpp"

#include "../../include/combination/multi_armed_bandit.hpp"
#include "../../include/core/lockfree_coverage_collector.hpp"
#include "../../include/core/batch_executor.hpp"
#include "../../include/core/algorithm_pool.hpp"

#include <iostream>
#include <chrono>
#include <filesystem>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <future>
#include <shared_mutex>
#include <random>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <set>
#include <cmath>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <deque>
#include <array>
#include <cstdio>
#include <iomanip>
#include <utility>
#include <sstream>
#include <sys/mman.h>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <bitset>
#include <numeric>
#include <iomanip>

// Forward declaration for enhanced Thompson sampling
namespace triofuzz {
    class EnhancedThompsonSampling;
}

// External declaration
extern triofuzz::EnhancedThompsonSampling global_thompson_sampling;

// Global crash handler variable declarations - using local definitions
thread_local std::vector<uint8_t> g_current_fuzzing_input;

namespace triofuzz {

// Namespace alias to disambiguate between struct AlgorithmConfig (from config_manager.hpp)
// and namespace AlgorithmConfig (from algorithm_config.hpp)
namespace AlgoConfig = AlgorithmConfig;

namespace {

// Fast 64-bit hash for coverage bitmaps.
// We intentionally avoid weak XOR folding (high collision risk) and avoid
// unaligned/aliasing loads. This is used only for in-process de-duplication of
// "new coverage" candidates before adding them to the on-disk corpus.
static inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t read_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint32_t read_u32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint32_t getenv_u32(const char* name, uint32_t default_value) {
    const char* v = std::getenv(name);
    if (!v || !*v) return default_value;
    char* end = nullptr;
    unsigned long parsed = std::strtoul(v, &end, 10);
    if (!end || end == v) return default_value;
    if (parsed > std::numeric_limits<uint32_t>::max()) return default_value;
    return static_cast<uint32_t>(parsed);
}

static inline bool looks_text(const std::vector<uint8_t>& in) {
    if (in.empty()) return false;
    size_t sample = std::min<size_t>(in.size(), 256);
    size_t printable = 0;
    size_t nul = 0;
    for (size_t i = 0; i < sample; ++i) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        if (c == 0) nul++;
        if (std::isprint(c) || std::isspace(c)) printable++;
    }
    // Treat as text when mostly printable/whitespace and not dominated by NULs.
    return (printable * 100 >= sample * 85) && (nul * 10 < sample);
}

static inline uint64_t xxh64_round(uint64_t acc, uint64_t input) {
    static constexpr uint64_t PRIME64_1 = 11400714785074694791ULL;
    static constexpr uint64_t PRIME64_2 = 14029467366897019727ULL;
    acc += input * PRIME64_2;
    acc = rotl64(acc, 31);
    acc *= PRIME64_1;
    return acc;
}

static inline uint64_t xxh64_merge_round(uint64_t acc, uint64_t val) {
    static constexpr uint64_t PRIME64_1 = 11400714785074694791ULL;
    static constexpr uint64_t PRIME64_4 = 9650029242287828579ULL;
    acc ^= xxh64_round(0, val);
    acc = acc * PRIME64_1 + PRIME64_4;
    return acc;
}

static inline uint64_t hash_xxh64(const uint8_t* data, size_t len, uint64_t seed = 0) {
    static constexpr uint64_t PRIME64_1 = 11400714785074694791ULL;
    static constexpr uint64_t PRIME64_2 = 14029467366897019727ULL;
    static constexpr uint64_t PRIME64_3 = 1609587929392839161ULL;
    static constexpr uint64_t PRIME64_4 = 9650029242287828579ULL;
    static constexpr uint64_t PRIME64_5 = 2870177450012600261ULL;

    const uint8_t* p = data;
    const uint8_t* const end = p + len;
    uint64_t h64;

    if (len >= 32) {
        const uint8_t* const limit = end - 32;
        uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
        uint64_t v2 = seed + PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - PRIME64_1;

        do {
            v1 = xxh64_round(v1, read_u64(p));
            p += 8;
            v2 = xxh64_round(v2, read_u64(p));
            p += 8;
            v3 = xxh64_round(v3, read_u64(p));
            p += 8;
            v4 = xxh64_round(v4, read_u64(p));
            p += 8;
        } while (p <= limit);

        h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
        h64 = xxh64_merge_round(h64, v1);
        h64 = xxh64_merge_round(h64, v2);
        h64 = xxh64_merge_round(h64, v3);
        h64 = xxh64_merge_round(h64, v4);
    } else {
        h64 = seed + PRIME64_5;
    }

    h64 += static_cast<uint64_t>(len);

    while (p + 8 <= end) {
        uint64_t k1 = xxh64_round(0, read_u64(p));
        h64 ^= k1;
        h64 = rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
        p += 8;
    }

    if (p + 4 <= end) {
        h64 ^= static_cast<uint64_t>(read_u32(p)) * PRIME64_1;
        h64 = rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
        p += 4;
    }

    while (p < end) {
        h64 ^= static_cast<uint64_t>(*p) * PRIME64_5;
        h64 = rotl64(h64, 11) * PRIME64_1;
        ++p;
    }

    // Avalanche
    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

static inline uint64_t hash_coverage_bitmap(const std::vector<uint8_t>& bitmap) {
    if (bitmap.empty()) {
        return 0;
    }
    return hash_xxh64(bitmap.data(), bitmap.size(), /*seed=*/0);
}

}  // namespace

// =============================================================================
// Global Debug Counter for Unified Logging
// =============================================================================
static std::atomic<size_t> global_debug_counter{0};

// =============================================================================
// Thread-Safe Logger for Clean Output
// =============================================================================
class ThreadSafeLogger {
private:
    static ThreadSafeLogger* instance_;
    std::mutex log_mutex_;
    std::queue<std::string> log_buffer_;
    std::atomic<bool> shutdown_{false};
    std::thread flush_thread_;
    std::condition_variable cv_;
    static constexpr size_t BUFFER_THRESHOLD = 100;
    static constexpr auto FLUSH_INTERVAL = std::chrono::milliseconds(100);

    void flushWorker() {
        while (!shutdown_.load()) {
            std::unique_lock<std::mutex> lock(log_mutex_);
            cv_.wait_for(lock, FLUSH_INTERVAL, [this] {
                return !log_buffer_.empty() || shutdown_.load();
            });

            if (!log_buffer_.empty()) {
                std::vector<std::string> batch;
                while (!log_buffer_.empty() && batch.size() < BUFFER_THRESHOLD) {
                    batch.push_back(std::move(log_buffer_.front()));
                    log_buffer_.pop();
                }
                lock.unlock();

                // Batch output to reduce system calls
                for (const auto& msg : batch) {
                    std::cerr << msg;
                }
                std::cerr.flush();
            }
        }
    }

public:
    static ThreadSafeLogger& getInstance() {
        static ThreadSafeLogger instance;
        return instance;
    }

    ThreadSafeLogger() : flush_thread_(&ThreadSafeLogger::flushWorker, this) {}

    ~ThreadSafeLogger() {
        shutdown_.store(true);
        cv_.notify_all();
        if (flush_thread_.joinable()) {
            flush_thread_.join();
        }
        // Flush remaining logs
        std::lock_guard<std::mutex> lock(log_mutex_);
        while (!log_buffer_.empty()) {
            std::cerr << log_buffer_.front();
            log_buffer_.pop();
        }
    }

    void log(const std::string& message) {
        if (shutdown_.load()) return;

        std::lock_guard<std::mutex> lock(log_mutex_);
        log_buffer_.push(message);

        if (log_buffer_.size() >= BUFFER_THRESHOLD) {
            cv_.notify_one();
        }
    }

    void logImmediate(const std::string& message) {
        if (shutdown_.load()) return;

        std::lock_guard<std::mutex> lock(log_mutex_);
        std::cerr << message;
        std::cerr.flush();
    }
};

ThreadSafeLogger* ThreadSafeLogger::instance_ = nullptr;

// =============================================================================
// Real Coverage Collection Infrastructure
// =============================================================================

// Shared memory layout for coverage data with AFL++ style 8-bit counters
struct CoverageSharedMemory {
    static constexpr size_t MAX_GUARDS = 1000000;
    static constexpr size_t MAX_BRANCHES = 500000;  // Branch count upper limit

    volatile uint32_t total_guards;
    volatile uint32_t initialized;

    // AFL++ style 8-bit counters instead of simple bitmap
    volatile uint8_t coverage_counters[MAX_GUARDS];  // 8-bit execution counters
    volatile uint8_t virgin_bits[MAX_GUARDS];        // Untouched edges (0xFF = untouched)
    volatile uint8_t virgin_crash[MAX_GUARDS];       // New edges causing crashes
    volatile uint8_t virgin_tmout[MAX_GUARDS];       // New edges causing timeouts

    // Guard information
    uint32_t guard_start_offset;
    uint32_t guard_count;

    // Branch coverage with 8-bit counters
    volatile uint32_t total_branches;                       // Total branch count
    volatile uint32_t branch_initialized;                   // Branch initialization flag
    volatile uint8_t branch_counters[MAX_BRANCHES];        // Branch execution counters
    volatile uint8_t branch_virgin_bits[MAX_BRANCHES];     // Branch virgin bits

    // Branch information - following guard information management pattern
    uint32_t branch_start_offset;
    uint32_t branch_count;
};

// Batch algorithm combination selector
class BatchAlgorithmSelector {
private:
    // Add combination manager and rules engine
    std::unique_ptr<AlgorithmCombinationManager> combo_manager_;
    std::unique_ptr<CombinationRulesEngine> rules_engine_;

    // Dynamic Thompson sampling for algorithm selection
    std::unique_ptr<ThompsonSampling> dynamic_thompson_;

    // Reference to AlgorithmRegistry instance (not singleton)
    AlgorithmRegistry& algorithm_registry_;

    struct BatchInfo {
        AlgorithmCombination current_combination;
        std::atomic<size_t> executions_in_batch{0}; // Atomic type
        std::atomic<size_t> batch_size{50000}; // Small batch size for fast adaptation
        std::atomic<double> total_reward{0.0}; // Atomic type
        std::atomic<size_t> successful_executions{0};
        std::chrono::steady_clock::time_point batch_start_time;

        // Configuration parameters - optimized for fast response
        std::atomic<size_t> min_batch_size{10000};    // Very small batch, fast exploration
        std::atomic<size_t> max_batch_size{100000};   // Small max batch, frequent strategy switches
        std::atomic<double> adaptive_factor{0.3};    // Reduced adaptive adjustment factor for stability

        // Stability control parameters - optimized for fast response
        std::atomic<size_t> stability_threshold{100};  // Very small stability threshold, fast switching
        std::atomic<double> min_confidence_interval{0.05}; // Small confidence interval, sensitive response

        // Parameters to prevent excessive switching while maintaining exploration
        std::atomic<size_t> min_runtime_seconds{60};     // Increased min runtime to avoid premature switching
        std::atomic<double> performance_threshold{0.15};  // Higher performance threshold, switch only on significant differences
    };
    
    BatchInfo current_batch_;
    
    std::random_device rd_;
    

    
    // Reference to main engine configuration
    const FuzzingConfig& config_;
    const std::unique_ptr<SharedContext>& global_context_;
    std::mt19937 gen_;
    
    // Thread synchronization protection
    mutable std::shared_mutex batch_mutex_;
    mutable std::mutex thompson_mutex_; // Dedicated mutex for Thompson Sampling data

    // Cache invalidation notification mechanism
    static std::atomic<uint64_t> cache_version_;
    
    void invalidateAllCaches() {
        cache_version_.fetch_add(1, std::memory_order_release);
    }
    
    // Helper function to parse combo key string into AlgorithmCombination
    AlgorithmCombination parseComboKey(const std::string& combo_key) {
        AlgorithmCombination combo;
        
        // Format: "mode[algo1,algo2,...]"
        size_t bracket_pos = combo_key.find('[');
        if (bracket_pos != std::string::npos) {
            combo.combination_mode = combo_key.substr(0, bracket_pos);
            
            size_t end_bracket = combo_key.find(']');
            if (end_bracket != std::string::npos) {
                std::string algos = combo_key.substr(bracket_pos + 1, end_bracket - bracket_pos - 1);
                
                // Split algorithms by comma
                std::stringstream ss(algos);
                std::string algo;
                while (std::getline(ss, algo, ',')) {
                    if (!algo.empty()) {
                        combo.algorithm_names.push_back(algo);
                    }
                }
            }
        }
        
        // Fallback for simple algorithm names
        if (combo.algorithm_names.empty()) {
            combo.algorithm_names.push_back(combo_key);
            combo.combination_mode = "sequential";
        }
        
        return combo;
    }
    
public:
    BatchAlgorithmSelector(const FuzzingConfig& config, const std::unique_ptr<SharedContext>& context,
                          AlgorithmRegistry& registry,
                          std::map<std::string, std::pair<double, double>>& beta_dist,
                          std::map<std::string, std::pair<size_t, double>>& combo_hist,
                          std::mutex& thompson_mutex,
                          std::map<std::string, size_t>& algo_usage_stats,
                          std::map<std::string, std::chrono::steady_clock::time_point>& combo_usage,
                          size_t& total_algo_uses,
                          std::mutex& diversity_mutex,
                          std::function<bool()> structured_input_detector = nullptr)
        : config_(config), global_context_(context), algorithm_registry_(registry), gen_(rd_()),
          beta_distributions_(beta_dist), combination_history_(combo_hist),
          thompson_sampling_mutex_(thompson_mutex),
          algorithm_usage_stats_(algo_usage_stats), last_combo_usage_(combo_usage),
          total_algorithm_uses_(total_algo_uses), diversity_stats_mutex_(diversity_mutex),
          detect_structured_input_(structured_input_detector) {
        // Initialize combination manager and rules engine
        try {
            combo_manager_ = std::make_unique<AlgorithmCombinationManager>();
            rules_engine_ = std::make_unique<CombinationRulesEngine>();
            std::cout << "[BatchAlgorithmSelector] Initialized with AlgorithmCombinationManager and CombinationRulesEngine" << std::endl;

            // Initialize dynamic Thompson sampling
            dynamic_thompson_ = std::make_unique<ThompsonSampling>();
            dynamic_thompson_->setMinAlgorithmsPerCombo(1);
            dynamic_thompson_->setMaxAlgorithmsPerCombo(2);
            dynamic_thompson_->setExplorationBonus(0.15);  // 15% bonus for exploration
            dynamic_thompson_->setSynergyWeight(0.25);      // 25% weight for synergy
            std::cout << "[BatchAlgorithmSelector] Initialized dynamic Thompson sampling" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Failed to initialize combination managers: " << e.what() << std::endl;
            // Will work without enhanced features
        }

        // Initialize first batch
        std::unique_lock<std::shared_mutex> lock(batch_mutex_);
        initializeNewBatch();
    }
    
    // Get current batch algorithm combination
    AlgorithmCombination getCurrentCombination() {
        // Use versioned cache to reduce lock contention
        static thread_local AlgorithmCombination cached_combination;
        static thread_local uint64_t cached_version = 0;
        
        uint64_t current_version = cache_version_.load(std::memory_order_acquire);
        
        // If cache version is valid, return directly
        if (cached_version == current_version && cached_version > 0) {
            return cached_combination;
        }
        
        // Only lock when cache is invalidated
        std::shared_lock<std::shared_mutex> lock(batch_mutex_);
        cached_combination = current_batch_.current_combination;
        cached_version = current_version;
        return cached_combination;
    }
    
    // Record current execution reward - reduced lock granularity
    void recordExecution(double reward, bool new_coverage = false, bool crashed = false, bool decoder_success = false) {
        // Use atomic operations to reduce lock contention
        current_batch_.executions_in_batch.fetch_add(1, std::memory_order_relaxed);
        if (decoder_success) {
            current_batch_.successful_executions.fetch_add(1, std::memory_order_relaxed);
        }

        // Atomic floating-point accumulation (via CAS)
        double current_reward = current_batch_.total_reward.load(std::memory_order_relaxed);
        double new_reward;
        do {
            new_reward = current_reward + reward;
        } while (!current_batch_.total_reward.compare_exchange_weak(
            current_reward, new_reward, std::memory_order_relaxed));

        // Update dynamic Thompson sampling statistics
        if (dynamic_thompson_) {
            // Create a copy to avoid race condition with initializeNewBatch()
            // This prevents heap-use-after-free when another thread modifies current_combination
            AlgorithmCombination combo_copy;
            {
                std::shared_lock<std::shared_mutex> lock(batch_mutex_);
                combo_copy = current_batch_.current_combination;
            }
            dynamic_thompson_->updateStatistics(combo_copy,
                                               reward, new_coverage, crashed, decoder_success);
        }
        
        // Only lock when batch needs to end
        if (current_batch_.executions_in_batch.load(std::memory_order_relaxed) >= 
            current_batch_.batch_size.load(std::memory_order_relaxed)) {
            
            std::unique_lock<std::shared_mutex> lock(batch_mutex_);
            // Double-check to avoid ending batch twice
            if (shouldEndCurrentBatch()) {
                endCurrentBatch();
                initializeNewBatch();
                
                // Invalidate caches for all threads
                invalidateAllCaches();
            }
        }
    }
    
    // Manually end current batch (e.g., when new coverage is found)
    void forceEndBatch() {
        std::unique_lock<std::shared_mutex> lock(batch_mutex_);
        if (current_batch_.executions_in_batch.load(std::memory_order_relaxed) > 0) {
            endCurrentBatch();
            initializeNewBatch();
            invalidateAllCaches();
        }
    }
    
    // Get batch statistics - lock-free reads
    size_t getCurrentBatchExecutions() const {
        return current_batch_.executions_in_batch.load(std::memory_order_relaxed);
    }
    
    size_t getCurrentBatchSize() const {
        return current_batch_.batch_size.load(std::memory_order_relaxed);
    }
    
    double getCurrentBatchAverageReward() const {
        size_t executions = current_batch_.executions_in_batch.load(std::memory_order_relaxed);
        if (executions == 0) return 0.0;
        double total_reward = current_batch_.total_reward.load(std::memory_order_relaxed);
        return total_reward / executions;
    }
    
private:
    bool shouldEndCurrentBatch() {
        // Note: this method should be called while holding the lock

        // Basic condition: reached batch size
        if (current_batch_.executions_in_batch >= current_batch_.batch_size) {
            return true;
        }
        
        // Minimum execution count check: ensure sufficient statistical samples
        if (current_batch_.executions_in_batch < current_batch_.min_batch_size) {
            return false;
        }
        
        // Minimum time check: ensure each batch runs at least the specified time (1 minute)
        auto now = std::chrono::steady_clock::now();
        auto batch_duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - current_batch_.batch_start_time);
        if (static_cast<size_t>(batch_duration.count()) < current_batch_.min_runtime_seconds) {
            return false; // Not enough time, continue running
        }
        
        // === Coverage stagnation check to promote algorithm combination exploration ===
        auto coverage_info = global_context_->getCoverageInfo();
        if (coverage_info.has_value()) {
            double coverage_gain = coverage_info->coverage_gain;
            
            // If coverage stagnates, switch algorithm combination for exploration
            if (coverage_gain < 0.0001 && current_batch_.executions_in_batch >= 30000) {
                std::cout << "[EXPLORATION] Coverage stagnation detected (gain=" << coverage_gain 
                          << "), switching algorithm combination for exploration after " 
                          << current_batch_.executions_in_batch << " executions" << std::endl;
                return true;
            }
            
            // If coverage is completely stagnant, switch earlier
            if (coverage_gain == 0.0 && current_batch_.executions_in_batch >= 20000) {
                std::cout << "[EXPLORATION] Zero coverage gain, forcing algorithm exploration" << std::endl;
                return true;
            }
        }
        
        // === Algorithm combination diversity check to prevent overuse of a single combination ===
        static std::map<std::string, std::chrono::steady_clock::time_point> last_combo_usage;
        static std::map<std::string, size_t> combo_usage_count;
        std::string current_combo_key = current_batch_.current_combination.toString();
        
        // Prevent algorithm combination overuse, promote diversity
        combo_usage_count[current_combo_key]++;
        if (combo_usage_count[current_combo_key] > 5 && current_batch_.executions_in_batch >= 30000) {
            std::cout << "[EXPLORATION] Algorithm combination overuse detected (" 
                      << current_combo_key << " used " << combo_usage_count[current_combo_key] 
                      << " times), forcing diversity exploration" << std::endl;
            return true;
        }
        
        last_combo_usage[current_combo_key] = now;
        
        // Stability check: balance performance and exploration
        if (current_batch_.executions_in_batch >= current_batch_.stability_threshold) {
            double current_avg = current_batch_.total_reward / current_batch_.executions_in_batch;
            
            // === Balanced switching strategy, maintain exploration ===
            if (current_avg > 0.6) {
                // Good performance, extend run time moderately (10 minutes)
                if (batch_duration.count() > 600) {
                    std::cout << "[EXPLORATION] Good performance but switching for diversity" << std::endl;
                    return true;
                }
                return false; // Continue running
            }
            
            // Medium performance, switch moderately (5 minutes)
            if (current_avg > 0.3 && batch_duration.count() > 300) {
                return true;
            }
        }
        
        // Early termination: switch when performance is poor
        if (current_batch_.executions_in_batch >= current_batch_.min_batch_size && 
            static_cast<size_t>(batch_duration.count()) >= current_batch_.min_runtime_seconds) {
            double current_avg = current_batch_.total_reward / current_batch_.executions_in_batch;
            
            // Switch algorithm combination on poor performance
            if (current_avg < current_batch_.performance_threshold) {
                std::cout << "[EXPLORATION] Poor performance (" << current_avg 
                          << "), switching algorithm combination" << std::endl;
                return true;
            }
        }
        
        // === Maximum time limit to keep exploration active ===
        if (batch_duration.count() > 300) { // 5 minute maximum run time
            std::cout << "[EXPLORATION] Maximum batch time reached (5 minutes), forcing exploration" << std::endl;
            return true;
        }
        
        return false;
    }
    
    void endCurrentBatch() {
        // Note: this method should be called while holding the lock
        if (current_batch_.executions_in_batch == 0) return;

        // Calculate batch average reward
        double avg_reward = current_batch_.total_reward / current_batch_.executions_in_batch;
        
        // Update Thompson Sampling Beta distribution
        std::string combo_key = current_batch_.current_combination.toString();
        updateThompsonSampling(combo_key, avg_reward, current_batch_.executions_in_batch);
        
        // Record batch size before adjustment
        size_t old_batch_size = current_batch_.batch_size.load();

        // Adaptively adjust next batch size
        adaptBatchSize(avg_reward);

        // Enable verbose batch end logging
        static bool verbose_batch = std::getenv("triofuzz_VERBOSE_BATCH") != nullptr;
        if (verbose_batch) {
            size_t new_batch_size = current_batch_.batch_size.load();
            std::cout << "[BATCH] Ended batch for " << combo_key
                      << ": " << current_batch_.executions_in_batch << " executions"
                      << ", avg_reward=" << std::fixed << std::setprecision(3) << avg_reward
                      << ", old_size=" << old_batch_size
                      << ", new_size=" << new_batch_size
                      << ", trend=" << (new_batch_size > old_batch_size ? "↑" :
                                      (new_batch_size < old_batch_size ? "↓" : "→"))
                      << std::endl;
        }
    }
    
    void initializeNewBatch() {
        // Note: this method should be called while holding the lock
        // Use Thompson Sampling to select new algorithm combination
        current_batch_.current_combination = selectWithThompsonSampling();
        current_batch_.executions_in_batch = 0;
        current_batch_.total_reward = 0.0;
        current_batch_.successful_executions = 0;
        current_batch_.batch_start_time = std::chrono::steady_clock::now();

        // Enable debug logging for combination selection - via environment variable
        static bool verbose_combination = std::getenv("triofuzz_VERBOSE_COMBINATION") != nullptr;
        if (verbose_combination) {
            double coverage_pct = 10.0; // Default coverage percentage
            // Try to get coverage from context if available
            if (global_context_) {
                auto cov_info = global_context_->getCoverageInfo();
                if (cov_info.has_value() && cov_info->total_edges > 0) {
                    coverage_pct = (cov_info->covered_edges.size() * 100.0) / cov_info->total_edges;
                }
            }
            std::cout << "[BATCH] Started new batch with " << current_batch_.current_combination.toString()
                      << ", batch_size=" << current_batch_.batch_size
                      << ", coverage=" << std::fixed << std::setprecision(2) << coverage_pct << "%"
                      << std::endl;
        }
    }
    
    void updateThompsonSampling(const std::string& combo_key, double avg_reward, size_t executions) {
        // Direct update using thread-safe internal method
        // No locking needed as internal structures are thread-safe
        updateThompsonSamplingInternal(combo_key, avg_reward, executions);
    }

private:
    // Simple thread-safe Beta parameters structure
    struct ThreadSafeBetaParams {
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

    struct ThreadSafeCombinationStats {
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

    // Thread-safe maps for Thompson Sampling
    mutable std::shared_mutex beta_params_mutex_;
    std::unordered_map<std::string, std::unique_ptr<ThreadSafeBetaParams>> thread_safe_beta_params_;

    mutable std::shared_mutex combo_stats_mutex_;
    std::unordered_map<std::string, std::unique_ptr<ThreadSafeCombinationStats>> thread_safe_combo_stats_;

    ThreadSafeBetaParams* getBetaParams(const std::string& key) {
        std::shared_lock<std::shared_mutex> lock(beta_params_mutex_);
        auto it = thread_safe_beta_params_.find(key);
        return (it != thread_safe_beta_params_.end()) ? it->second.get() : nullptr;
    }

    void createBetaParams(const std::string& key) {
        std::unique_lock<std::shared_mutex> lock(beta_params_mutex_);
        if (thread_safe_beta_params_.find(key) == thread_safe_beta_params_.end()) {
            thread_safe_beta_params_[key] = std::make_unique<ThreadSafeBetaParams>();
        }
    }

    ThreadSafeCombinationStats* getCombinationStats(const std::string& key) {
        std::shared_lock<std::shared_mutex> lock(combo_stats_mutex_);
        auto it = thread_safe_combo_stats_.find(key);
        return (it != thread_safe_combo_stats_.end()) ? it->second.get() : nullptr;
    }

    void createCombinationStats(const std::string& key) {
        std::unique_lock<std::shared_mutex> lock(combo_stats_mutex_);
        if (thread_safe_combo_stats_.find(key) == thread_safe_combo_stats_.end()) {
            thread_safe_combo_stats_[key] = std::make_unique<ThreadSafeCombinationStats>();
        }
    }

    // Reference to the main engine's member variables
    std::map<std::string, std::pair<double, double>>& beta_distributions_;
    std::map<std::string, std::pair<size_t, double>>& combination_history_;
    std::mutex& thompson_sampling_mutex_;
    
    // Reference to main engine's diversity tracking variables
    std::map<std::string, size_t>& algorithm_usage_stats_;
    std::map<std::string, std::chrono::steady_clock::time_point>& last_combo_usage_;
    size_t& total_algorithm_uses_;
    std::mutex& diversity_stats_mutex_;
    std::function<bool()> detect_structured_input_;

    void updateThompsonSamplingInternal(const std::string& combo_key, double avg_reward, size_t executions) {
        // Thread-safe update using the new data structures
        // No need to hold lock as the data structures are internally thread-safe

        // Get or create beta parameters
        auto* beta_params = getBetaParams(combo_key);
        if (!beta_params) {
            createBetaParams(combo_key);
            beta_params = getBetaParams(combo_key);
        }

        // Get or create combination stats
        auto* combo_stats = getCombinationStats(combo_key);
        if (!combo_stats) {
            createCombinationStats(combo_key);
            combo_stats = getCombinationStats(combo_key);
        }

        // Update using thread-safe methods
        double success_rate = std::max(0.01, std::min(0.99, avg_reward));
        double decay_factor = 0.7;

        if (beta_params) {
            beta_params->update(success_rate, executions, decay_factor);
        }

        if (combo_stats) {
            combo_stats->update(executions, avg_reward);
        }
    }
    
    void adaptBatchSize(double avg_reward) {
        size_t current_size = current_batch_.batch_size.load(std::memory_order_relaxed);
        size_t min_size = current_batch_.min_batch_size.load(std::memory_order_relaxed);
        size_t max_size = current_batch_.max_batch_size.load(std::memory_order_relaxed);

        // Detect whether target uses structured input
        bool is_structured = detect_structured_input_ ? detect_structured_input_() : false;

        size_t new_size = current_size;

        if (is_structured) {
            // Structured input batch adjustment - aggressive to find effective combinations quickly
            if (avg_reward > 0.5) {
                // High reward: rapidly expand batch to leverage effective algorithms
                new_size = std::min(max_size, static_cast<size_t>(current_size * 1.5));
            } else if (avg_reward > 0.2) {
                // Medium reward: moderate increase
                new_size = std::min(max_size, static_cast<size_t>(current_size * 1.2));
            } else if (avg_reward > 0.05) {
                // Low reward: keep current size, give algorithms more chances
                new_size = current_size;
            } else {
                // Very low reward: quickly switch to other algorithm combinations
                new_size = std::max(min_size, static_cast<size_t>(current_size * 0.5));
            }

            // Smaller min batch for structured input, for faster combination exploration
            min_size = std::max(size_t(100), min_size / 2);
        } else {
            // Original strategy for non-structured input
            if (avg_reward > 0.6) {
                new_size = std::min(max_size, static_cast<size_t>(current_size * 1.2));
            } else if (avg_reward > 0.3) {
                new_size = std::min(max_size, static_cast<size_t>(current_size * 1.05));
            } else if (avg_reward > 0.1) {
                new_size = static_cast<size_t>(current_size * 0.95);
                new_size = std::max(min_size, new_size);
            } else if (avg_reward > 0.01) {
                new_size = static_cast<size_t>(current_size * 0.85);
                new_size = std::max(min_size, new_size);
            } else {
                new_size = static_cast<size_t>(current_size * 0.7);
                new_size = std::max(min_size, new_size);
            }
        }

        // Ensure batch size is within reasonable range
        new_size = std::max(min_size, std::min(max_size, new_size));

        // Atomically update batch size
        current_batch_.batch_size.store(new_size, std::memory_order_relaxed);
    }
    
    AlgorithmCombination selectWithThompsonSampling() {
        // Use dynamic Thompson sampling if available
        if (dynamic_thompson_) {
            // Get available algorithms from registry
            std::vector<std::string> available_algorithms;
            try {
                std::vector<std::string> all_algorithms = algorithm_registry_.getAllAlgorithms();
                for (const auto& algo : all_algorithms) {
                    if (algorithm_registry_.isEnabled(algo)) {
                        available_algorithms.push_back(algo);
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[WARNING] Failed to get algorithms from registry: " << e.what() << std::endl;
            }

            // Fallback to configured algorithms if registry is empty
            if (available_algorithms.empty()) {
                available_algorithms = config_.enabled_algorithms;
            }

            // Use dynamic Thompson sampling to select combination
            AlgorithmCombination selected = dynamic_thompson_->selectCombination(available_algorithms);

            // Log selection if verbose mode is enabled
            static bool verbose_thompson = std::getenv("triofuzz_VERBOSE_THOMPSON") != nullptr;
            if (verbose_thompson) {
                std::cout << "[Dynamic Thompson] Selected: " << selected.toString() << std::endl;
            }

            return selected;
        }

        // Fallback to original implementation if dynamic Thompson is not available
        // === Normal Thompson Sampling algorithm selection, maintain combination exploration ===
        static std::map<std::string, double> cached_scores;
        static std::chrono::steady_clock::time_point last_cache_update = std::chrono::steady_clock::now();

        auto now = std::chrono::steady_clock::now();
        auto time_since_cache_update = std::chrono::duration_cast<std::chrono::minutes>(now - last_cache_update);

        // Moderate cache usage while keeping algorithm combination selection active
        bool use_cached_scores = (time_since_cache_update.count() < 2) && !cached_scores.empty();

        // Generate candidate combinations
        std::vector<AlgorithmCombination> candidates = generateCandidateCombinations();
        
        if (candidates.empty()) {
            AlgorithmCombination default_combo;
            default_combo.algorithm_names = {"havoc"};
            default_combo.combination_mode = "sequential";
            return default_combo;
        }
        
        // === Simplified Thompson Sampling logic, reduced computational overhead ===
        std::vector<std::pair<AlgorithmCombination, double>> scored_combinations;
        
        for (const auto& combo : candidates) {
            std::string combo_key = combo.toString();
            
            double final_score = 0.5; // Default medium score
            
            if (use_cached_scores) {
                // Use cached score
                auto cache_it = cached_scores.find(combo_key);
                if (cache_it != cached_scores.end()) {
                    final_score = cache_it->second;
                    scored_combinations.emplace_back(combo, final_score);
                    continue;
                }
            }
            
            // Thread-safe access to Beta parameters
            auto* beta_params = getBetaParams(combo_key);
            if (!beta_params) {
                createBetaParams(combo_key);
                beta_params = getBetaParams(combo_key);
            }

            auto* combo_stats = getCombinationStats(combo_key);
            if (!combo_stats) {
                createCombinationStats(combo_key);
                combo_stats = getCombinationStats(combo_key);
            }

            double sampled_theta = 0.5; // Default value
            double uses = 0.0;

            if (beta_params && combo_stats) {
                // Sample from Beta distribution using thread-safe access
                auto [alpha, beta] = beta_params->sample();
                uses = static_cast<double>(combo_stats->uses.load(std::memory_order_acquire));

                // Thompson Sampling: sample from Beta distribution
                std::gamma_distribution<double> gamma_alpha(alpha, 1.0);
                std::gamma_distribution<double> gamma_beta(beta, 1.0);
                double x = gamma_alpha(gen_);
                double y = gamma_beta(gen_);
                sampled_theta = x / (x + y);
            }
            
            // Enhanced exploration reward, encourage trying different combinations
            double exploration_bonus = 0.0;
            if (uses < 100) {  // Expanded exploration range to 100 uses
                exploration_bonus = 0.8 * (100 - uses) / 100.0;  // Significantly higher exploration reward
            } else if (uses < 500) {  // Continue with medium exploration reward
                exploration_bonus = 0.3 * (500 - uses) / 500.0;
            }
            
                    // Algorithm diversity reward - encourage using different algorithms
        double diversity_bonus = 0.0;
        double novelty_bonus = 0.0;
        {
            // Make a local copy to avoid race conditions
            std::vector<std::string> algorithm_names_copy = combo.algorithm_names;

            std::lock_guard<std::mutex> lock(diversity_stats_mutex_);
            for (const auto& algo_name : algorithm_names_copy) {
                // If this algorithm has been rarely used recently, give extra reward
                auto algo_usage_it = algorithm_usage_stats_.find(algo_name);
                if (algo_usage_it == algorithm_usage_stats_.end() ||
                    algo_usage_it->second < total_algorithm_uses_ * 0.05) { // If usage rate is below 5%
                    diversity_bonus += 0.2;  // Diversity reward
                }
            }
            
            // Time-decayed novelty reward
            auto current_time = std::chrono::steady_clock::now();
            auto combo_it = last_combo_usage_.find(combo_key);
            if (combo_it == last_combo_usage_.end()) {
                novelty_bonus = 0.25;  // Never-used combinations get high reward
            } else {
                auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>
                    (current_time - combo_it->second).count();
                if (time_since_last > 300) {  // Not used in 5 minutes
                    novelty_bonus = 0.15 * std::min(1.0, time_since_last / 600.0);
                }
            }
        }
            
            // Apply algorithm weight boost configuration
            double algorithm_boost = 1.0;
            static size_t thread_total_executions = 0;
            thread_total_executions++; // Simple increment for exploration phase tracking

            // Make a local copy to avoid race conditions
            std::vector<std::string> algorithm_names_copy = combo.algorithm_names;

            // Calculate average boost for all algorithms in the combination
            for (const auto& algo_name : algorithm_names_copy) {
                double base_boost = AlgorithmBoostConfig::getAlgorithmBoost(algo_name);
                double exploration_boost = AlgorithmBoostConfig::getExplorationBoost(algo_name, thread_total_executions);
                algorithm_boost *= (base_boost * exploration_boost);
            }

            // For multi-algorithm combinations, use geometric mean
            if (algorithm_names_copy.size() > 1) {
                algorithm_boost = std::pow(algorithm_boost, 1.0 / algorithm_names_copy.size());
            }
            
            // Usage frequency decay - overused combinations are penalized
            double usage_decay = 1.0;
            if (uses > 1000) {
                usage_decay = 1.0 / (1.0 + (uses - 1000) / 5000.0);  // More use = stronger decay
            } else if (uses > 500) {
                usage_decay = 1.0 - 0.2 * (uses - 500) / 500.0;  // Slight decay
            }

            // Add small random noise to avoid always selecting the same combination
            std::uniform_real_distribution<double> noise_dist(0.0, 0.1);
            double random_noise = noise_dist(gen_);

            // Remove structured input bias, let Thompson Sampling learn on its own
            double structured_boost = 1.0;
            // No longer pre-biasing any algorithm

            final_score = (sampled_theta + exploration_bonus + diversity_bonus + novelty_bonus + random_noise) * algorithm_boost * structured_boost * usage_decay;
            scored_combinations.emplace_back(combo, final_score);
            
            // Update cache
            cached_scores[combo_key] = final_score;
        }
        
        // Epsilon-greedy exploration: 20% chance to select random combination
        std::uniform_real_distribution<double> epsilon_dist(0.0, 1.0);
        auto selected_combo = scored_combinations.begin();

        if (epsilon_dist(gen_) < 0.2) {  // 20% exploration rate
            // Randomly select from combinations with low usage
            std::vector<decltype(scored_combinations.begin())> low_usage_combos;
            for (auto it = scored_combinations.begin(); it != scored_combinations.end(); ++it) {
                auto combo_history_it = combination_history_.find(it->first.toString());
                if (combo_history_it == combination_history_.end() ||
                    combo_history_it->second.first < 10) {  // .first is the use count
                    low_usage_combos.push_back(it);
                }
            }

            if (!low_usage_combos.empty()) {
                std::uniform_int_distribution<size_t> combo_dist(0, low_usage_combos.size() - 1);
                selected_combo = low_usage_combos[combo_dist(gen_)];
            } else {
                // If all combos have been used, select randomly from all
                std::uniform_int_distribution<size_t> combo_dist(0, scored_combinations.size() - 1);
                std::advance(selected_combo, combo_dist(gen_));
            }
        } else {
            // 80% exploitation: select best combo
            selected_combo = std::max_element(scored_combinations.begin(), scored_combinations.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
        }

        auto best_combo = selected_combo;

        // Debug output: show Thompson Sampling selection process
        static bool verbose_thompson = std::getenv("triofuzz_VERBOSE_THOMPSON") != nullptr;
        if (verbose_thompson) {
            std::cout << "[Thompson Sampling] Selected: " << best_combo->first.toString()
                      << " with score: " << best_combo->second << std::endl;
            static bool verbose_thompson_detail = std::getenv("triofuzz_VERBOSE_THOMPSON_DETAIL") != nullptr;
            if (verbose_thompson_detail) {
                std::cout << "  Top 5 candidates:" << std::endl;
                std::sort(scored_combinations.begin(), scored_combinations.end(),
                    [](const auto& a, const auto& b) { return a.second > b.second; });
                for (size_t i = 0; i < std::min(size_t(5), scored_combinations.size()); ++i) {
                    std::cout << "    " << scored_combinations[i].first.toString()
                              << ": " << scored_combinations[i].second << std::endl;
                }
            }
        }

        last_cache_update = now;

        return best_combo->first;
    }
    
    std::vector<AlgorithmCombination> generateCandidateCombinations() {
        // Use static local variables for caching
        static std::vector<AlgorithmCombination> cached_combinations;
        static std::chrono::steady_clock::time_point last_generation;
        static std::mutex cache_mutex;
        static constexpr std::chrono::seconds CACHE_DURATION{60};

        // Check if cache is valid
        {
            std::lock_guard<std::mutex> lock(cache_mutex);
            auto now = std::chrono::steady_clock::now();
            if (!cached_combinations.empty() &&
                (now - last_generation) < CACHE_DURATION) {
                return cached_combinations;  // Return cached combinations
            }
        }

        std::vector<AlgorithmCombination> candidates;

        // Get all available algorithms (dynamically from registry, only enabled ones)
        std::vector<std::string> available_algorithms;
        try {
            std::vector<std::string> all_algorithms = algorithm_registry_.getAllAlgorithms();
            for (const auto& algo : all_algorithms) {
                if (algorithm_registry_.isEnabled(algo)) {
                    available_algorithms.push_back(algo);
                }
            }
        } catch (const std::exception& e) {
            std::cout << "[WARNING] Failed to get algorithms from registry: " << e.what() << std::endl;
        }

        // If registry is empty, use configured algorithms
        if (available_algorithms.empty()) {
            available_algorithms = config_.enabled_algorithms;
        }

        // If still empty, get all registered algorithms from registry
        if (available_algorithms.empty()) {
            // Dynamically get all algorithms from registry, avoid hardcoding
            try {
                available_algorithms = algorithm_registry_.getAllAlgorithms();
                std::cout << "[INFO] Using all registered algorithms from registry: " << available_algorithms.size() << " algorithms found" << std::endl;
            } catch (const std::exception& e) {
                std::cout << "[WARNING] Failed to get algorithms from registry, using AlgorithmConfig fallback: " << e.what() << std::endl;
                // Use AlgorithmConfig as fallback
                available_algorithms = AlgoConfig::ENABLED_MUTATIONS;
            }
        }
        
        // Classify algorithms by function
        std::map<std::string, std::vector<std::string>> algorithm_groups;
        
        // Format-specific algorithm group - highest priority
        // algorithm_groups["icc_profile_specialized"] = {"icc_aggressive", "smart_format", "smart_dictionary"}; // archived

        // Basic mutation algorithms - using AlgorithmConfig
        algorithm_groups["basic_mutation"] = AlgoConfig::ENABLED_MUTATIONS;

        // Advanced mutation algorithms (including format_aware)
        algorithm_groups["advanced_mutation"] = {"rare_branch_mutation", "honggfuzz" /* "format_aware" */}; // gradient_descent, zest, libfuzzer_structured, aflgo, icc_aggressive, fairfuzz, neuzz, format_aware archived

        // Note: feedback analyzers should not be used in algorithm_names, commented out
        // algorithm_groups["feedback"] = {"coverage_analyzer", "crash_analyzer"}; // should use feedback_analyzer field

        // Optimization algorithms
        algorithm_groups["optimization"] = {"rare_branch_mutation"}; // gradient_descent, fairfuzz, neuzz archived

        // Note: scheduling algorithms should not be used in algorithm_names, commented out
        // algorithm_groups["scheduling"] = {"fast_scheduler", "rare_edge_scheduler"}; // should use scheduler_name field

        // Exploration algorithms
        algorithm_groups["exploration"] = {"havoc", "random_walk"}; // deterministic archived
        
        // Filter to actually available algorithms
        for (auto& [group_name, algos] : algorithm_groups) {
            algos.erase(std::remove_if(algos.begin(), algos.end(),
                [&available_algorithms](const std::string& algo) {
                    return std::find(available_algorithms.begin(), available_algorithms.end(), algo) == available_algorithms.end();
                }), algos.end());
        }

        // Completely remove structured input bias, let Thompson Sampling learn all algorithms fairly

        // 1. Single-algorithm combinations (try each algorithm) - limit count to avoid combinatorial explosion
        size_t single_algo_limit = std::min(size_t(20), available_algorithms.size());
        // Shuffle and take first N for diversity
        std::vector<std::string> shuffled_algorithms = available_algorithms;
        std::shuffle(shuffled_algorithms.begin(), shuffled_algorithms.end(), gen_);

        for (size_t i = 0; i < single_algo_limit; ++i) {
            AlgorithmCombination combo;
            combo.algorithm_names = {shuffled_algorithms[i]};
            combo.combination_mode = "sequential";
            candidates.push_back(combo);
        }
        
        // 2. Same-group dual algorithm combinations
        for (const auto& [group_name, algos] : algorithm_groups) {
            if (algos.size() >= 2) {
                for (size_t i = 0; i < algos.size(); ++i) {
                    for (size_t j = i + 1; j < algos.size(); ++j) {
                        // Sequential combination
                        AlgorithmCombination combo;
                        combo.algorithm_names = {algos[i], algos[j]};
                        combo.combination_mode = "sequential";
                        candidates.push_back(combo);
                        
                        // Parallel combination
                        combo.combination_mode = "parallel";
                        candidates.push_back(combo);
                    }
                }
            }
        }
        
            // 3. Format-specific high-priority combinations
    if (!algorithm_groups["icc_profile_specialized"].empty()) {
        // Format-specific algorithm standalone combinations
        for (const auto& icc_algo : algorithm_groups["icc_profile_specialized"]) {
            AlgorithmCombination combo;
            combo.algorithm_names = {icc_algo};
            combo.combination_mode = "sequential";
            candidates.push_back(combo);
            
            // Format-specific algorithm + basic mutation combinations
            if (!algorithm_groups["basic_mutation"].empty()) {
                for (const auto& basic_algo : algorithm_groups["basic_mutation"]) {
                    combo.algorithm_names = {icc_algo, basic_algo};
                    combo.combination_mode = "sequential";
                    candidates.push_back(combo);
                    
                    combo.combination_mode = "parallel";
                    candidates.push_back(combo);
                }
            }
            
            // Note: feedback analyzers should not be in algorithm_names, combination generation disabled
            // if (!algorithm_groups["feedback"].empty()) {
            //     for (const auto& feedback_algo : algorithm_groups["feedback"]) {
            //         combo.algorithm_names = {icc_algo, feedback_algo};
            //         combo.combination_mode = "sequential";
            //         candidates.push_back(combo);
            //     }
            // }
        }
    }
    
    // Note: the following combinations contain feedback analyzers, disabled (should use feedback_analyzer field)

    // // 4. Cross-category algorithm combinations (mutation+feedback+optimization)
    // if (!algorithm_groups["basic_mutation"].empty() && !algorithm_groups["feedback"].empty()) {
    //         for (const auto& mutation : algorithm_groups["basic_mutation"]) {
    //             for (const auto& feedback : algorithm_groups["feedback"]) {
    //                 AlgorithmCombination combo;
    //                 combo.algorithm_names = {mutation, feedback};
    //                 combo.combination_mode = "sequential";
    //                 candidates.push_back(combo);
    //
    //                 combo.combination_mode = "parallel";
    //                 candidates.push_back(combo);
    //             }
    //         }
    //     }
    //
    //     // 4. Advanced mutation + feedback combinations
    //     if (!algorithm_groups["advanced_mutation"].empty() && !algorithm_groups["feedback"].empty()) {
    //         for (const auto& mutation : algorithm_groups["advanced_mutation"]) {
    //             for (const auto& feedback : algorithm_groups["feedback"]) {
    //                 AlgorithmCombination combo;
    //                 combo.algorithm_names = {mutation, feedback};
    //                 combo.combination_mode = "sequential";
    //                 candidates.push_back(combo);
    //             }
    //         }
    //     }
    //
    //     // 5. Triple combinations (mutation+feedback+optimization)
    //     if (!algorithm_groups["basic_mutation"].empty() && !algorithm_groups["feedback"].empty() && !algorithm_groups["optimization"].empty()) {
    //         for (const auto& mutation : algorithm_groups["basic_mutation"]) {
    //             for (const auto& feedback : algorithm_groups["feedback"]) {
    //                 for (const auto& optimization : algorithm_groups["optimization"]) {
    //                     AlgorithmCombination combo;
    //                     combo.algorithm_names = {mutation, feedback, optimization};
    //                     combo.combination_mode = "sequential";
    //                     candidates.push_back(combo);
    //                 }
    //             }
    //         }
    //     }
        
        // 6. Dedicated exploration combinations (when coverage stagnates)
        auto coverage_info = global_context_->getCoverageInfo();
        if (coverage_info.has_value()) {
            double coverage_percentage = coverage_info->bitmap.count() / (double)std::max(coverage_info->total_edges, static_cast<size_t>(1)) * 100.0;
            
            // Generate specific combinations based on coverage phase
            if (coverage_percentage < 5.0) {
                // Very low coverage: use diversified exploratory algorithms
                for (const auto& explorer : algorithm_groups["exploration"]) {
                    if (!explorer.empty()) {
                        AlgorithmCombination combo;
                        combo.algorithm_names = {explorer};
                        combo.combination_mode = "sequential";
                        candidates.push_back(combo);
                        
                        // Add parallel mode for diversity
                        combo.combination_mode = "parallel";
                        candidates.push_back(combo);
                    }
                }
            } else if (coverage_percentage < 15.0) {
                // Low coverage: combine basic mutation and exploration
                for (const auto& mutation : algorithm_groups["basic_mutation"]) {
                    for (const auto& explorer : algorithm_groups["exploration"]) {
                        AlgorithmCombination combo;
                        combo.algorithm_names = {mutation, explorer};
                        combo.combination_mode = "sequential";
                        candidates.push_back(combo);
                        
                        // Add parallel mode
                        combo.combination_mode = "parallel";
                        candidates.push_back(combo);
                    }
                }
                
                // Note: combinations containing feedback are disabled
                // for (const auto& basic : algorithm_groups["basic_mutation"]) {
                //     for (const auto& advanced : algorithm_groups["advanced_mutation"]) {
                //         for (const auto& feedback : algorithm_groups["feedback"]) {
                //             AlgorithmCombination combo;
                //             combo.algorithm_names = {basic, advanced, feedback};
                //             combo.combination_mode = "parallel";
                //             candidates.push_back(combo);
                //         }
                //     }
                // }
            } else if (coverage_percentage > 50.0) {
                // Note: combinations containing scheduler are disabled
                // for (const auto& advanced : algorithm_groups["advanced_mutation"]) {
                //     for (const auto& scheduler : algorithm_groups["scheduling"]) {
                //         AlgorithmCombination combo;
                //         combo.algorithm_names = {advanced, scheduler};
                //         combo.combination_mode = "sequential";
                //         candidates.push_back(combo);
                //     }
                // }
            }
        }
        
        // 7. Random multi-combinations (increase exploration)
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> size_dist(2, 4);
        std::uniform_int_distribution<size_t> algo_dist(0, available_algorithms.size() - 1);
        std::uniform_int_distribution<int> mode_dist(0, 1);
        
        for (int i = 0; i < 5; ++i) { // Generate 5 random combinations
            size_t combo_size = size_dist(gen);
            AlgorithmCombination combo;
            std::set<std::string> used_algos; // Avoid duplicates
            
            for (size_t j = 0; j < combo_size; ++j) {
                std::string algo;
                int attempts = 0;
                do {
                    algo = available_algorithms[algo_dist(gen)];
                    attempts++;
                } while (used_algos.count(algo) && attempts < 10);
                
                if (!used_algos.count(algo)) {
                    combo.algorithm_names.push_back(algo);
                    used_algos.insert(algo);
                }
            }
            
            if (!combo.algorithm_names.empty()) {
                combo.combination_mode = "sequential"; // Only sequential, parallel has sync overhead
                candidates.push_back(combo);
            }
        }
        
        // 8. Remove duplicate combinations
        std::set<std::string> seen_combinations;
        candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
            [&seen_combinations](const AlgorithmCombination& combo) {
                std::string combo_str = combo.toString();
                if (seen_combinations.count(combo_str)) {
                    return true; // Duplicate, remove
                }
                seen_combinations.insert(combo_str);
                return false;
            }), candidates.end());
        
        // std::cout << "[BATCH] Generated " << candidates.size() << " candidate combinations for selection" << std::endl;

        // BALANCED: Add complex modes with reasonable frequency
        static size_t generation_counter = 0;
        generation_counter++;

        // Add complex modes 30% of the time for better exploration
        bool should_add_complex = (generation_counter % 3 == 0);

        if (should_add_complex && available_algorithms.size() >= 2) {
            // Add adaptive mode (most useful) - every time complex modes are added
            AlgorithmCombination adaptive;
            adaptive.algorithm_names = AlgoConfig::ENABLED_MUTATIONS;
            adaptive.combination_mode = "adaptive";
            candidates.push_back(adaptive);

            // Add pipeline mode 50% of the time when complex modes are added
            if (generation_counter % 6 == 0) {
                AlgorithmCombination pipeline;
                pipeline.algorithm_names = {"smart_dictionary", "havoc"};
                pipeline.combination_mode = "pipeline";
                candidates.push_back(pipeline);
            }

            // Add fusion mode sparingly (20% of complex mode additions) as it's expensive
            if (generation_counter % 15 == 0 && available_algorithms.size() >= 3) {
                AlgorithmCombination fusion;
                fusion.algorithm_names = {available_algorithms[0], available_algorithms[1], available_algorithms[2]};
                fusion.combination_mode = "fusion";
                candidates.push_back(fusion);
            }

            static bool logged = false;
            if (!logged) {
                std::cout << "[Enhanced] Added fusion, pipeline, and adaptive combination modes" << std::endl;
                logged = true;
            }
        }

        // Apply combination manager validation and optimization if available
        // PERFORMANCE OPTIMIZATION: Only validate complex combinations
        if (combo_manager_ && rules_engine_) {
            static size_t optimization_counter = 0;
            static const size_t OPTIMIZATION_INTERVAL = 100; // Only optimize every N generations

            // Only optimize periodically or for complex modes
            bool should_optimize = (optimization_counter++ % OPTIMIZATION_INTERVAL == 0);

            if (should_optimize) {
                for (auto& combo : candidates) {
                    // Skip optimization for simple sequential combinations
                    if (combo.combination_mode == "sequential" && combo.algorithm_names.size() <= 2) {
                        continue;
                    }

                    // Only validate complex combinations (fusion, pipeline, adaptive)
                    if (combo.combination_mode == "fusion" ||
                        combo.combination_mode == "pipeline" ||
                        combo.combination_mode == "adaptive") {

                        // Convert to enhanced combination for validation
                        EnhancedAlgorithmCombination enhanced;
                        enhanced.algorithm_names = combo.algorithm_names;
                        enhanced.combination_mode = combo.combination_mode;
                        enhanced.weights = combo.weights;

                        // Lightweight validation only
                        auto violations = rules_engine_->checkViolations(enhanced);
                        if (!violations.empty() && violations.size() > 2) {
                            // Only fix if there are significant violations
                            rules_engine_->applyRules(enhanced);
                            combo.algorithm_names = enhanced.algorithm_names;
                            combo.combination_mode = enhanced.combination_mode;
                        }
                    }
                }
            }

            static bool optimization_logged = false;
            if (!optimization_logged) {
                std::cout << "[BatchAlgorithmSelector] Applied combination optimization and rules" << std::endl;
                optimization_logged = true;
            }
        }

        // Update cache
        {
            std::lock_guard<std::mutex> lock(cache_mutex);
            cached_combinations = candidates;
            last_generation = std::chrono::steady_clock::now();
        }

        return candidates;
    }
    
    double calculateContextAdjustment(const AlgorithmCombination& combo) {
        // Simplified context adjustment logic
        double adjustment = 0.0;
        
        // Base adjustment by algorithm type
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "havoc") != combo.algorithm_names.end()) {
            adjustment += 0.1; // havoc is a general-purpose high-efficiency algorithm
        }
        
        // Smart dictionary algorithm adjustment
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "smart_dictionary") != combo.algorithm_names.end()) {
            adjustment += 0.15; // Smart dictionary is very effective during exploration
        }
        
        // Coverage analyzer adjustment
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "coverage_analyzer") != combo.algorithm_names.end()) {
            adjustment += 0.12; // Coverage guidance is important
        }
        
        // Crash analyzer adjustment
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "crash_analyzer") != combo.algorithm_names.end()) {
            adjustment += 0.18; // Crash discovery is the primary goal
        }
        
        // Performance analyzer adjustment
        // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "performance_analyzer") != combo.algorithm_names.end()) {
        //     adjustment += 0.08; // Performance monitoring helps optimization
        // } // archived
        
        // Deterministic algorithm adjustment
        // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "deterministic") != combo.algorithm_names.end()) {
        //     adjustment += 0.1; // Deterministic mutation is reliable
        // } // archived
        
        // PSO algorithm adjustment
        // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "binary_pso") != combo.algorithm_names.end()) {
        //     adjustment += 0.2; // PSO has strong optimization capability
        // } // archived
        
        // Combination mode adjustment
        if (combo.combination_mode == "parallel" && combo.algorithm_names.size() > 1) {
            adjustment += 0.05; // Encourage parallel combinations
        }
        
        // New and old algorithm mix reward
        bool has_new_algo = false;
        bool has_classic_algo = false;
        std::vector<std::string> new_algos = {"smart_dictionary", "coverage_analyzer", "crash_analyzer"};
        std::vector<std::string> classic_algos = AlgoConfig::ENABLED_MUTATIONS;
        
        for (const auto& algo : combo.algorithm_names) {
            if (std::find(new_algos.begin(), new_algos.end(), algo) != new_algos.end()) {
                has_new_algo = true;
            }
            if (std::find(classic_algos.begin(), classic_algos.end(), algo) != classic_algos.end()) {
                has_classic_algo = true;
            }
        }
        
        if (has_new_algo && has_classic_algo) {
            adjustment += 0.1; // New+old algorithm combination reward
        }
        
        return adjustment;
    }
};

// Define static member variables
std::atomic<uint64_t> BatchAlgorithmSelector::cache_version_{1};

// Actual batch algorithm selector instance, tuned for high performance

// Global coverage state for trace-pc-guard instrumentation
class RealCoverageCollector {
private:
    static const char* SHM_NAME;
    static constexpr size_t MAX_EDGES = 1000000;
    static constexpr size_t MAX_BRANCHES = 500000;  // Consistent with CoverageSharedMemory

    // AFL++ style count classification lookup table
    // Map execution count to bucket for detecting coverage changes
    static constexpr uint8_t count_class_lookup8[256] = {
        0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128
    };

    std::atomic<CoverageSharedMemory*> coverage_shm_{nullptr};  // Atomic pointer
    std::atomic<bool> shutdown_requested_{false};  // added: shutdown flag
    std::unique_ptr<std::atomic<uint8_t>[]> guard_seen_flags_;
    std::unique_ptr<std::atomic<uint8_t>[]> branch_seen_flags_;
    std::unique_ptr<std::atomic<uint8_t>[]> guard_max_counters_;
    std::unique_ptr<std::atomic<uint8_t>[]> branch_max_counters_;
    mutable std::mutex coverage_mutex_;
    mutable std::mutex shm_mutex_;  // added: mutex specifically for protecting shared memory operations
    std::atomic<size_t> total_seen_guards_{0};
    std::atomic<size_t> total_seen_branches_{0};
    std::atomic<bool> trace_pc_mode_{false};  // Flag for whether running in trace-pc mode
    std::atomic<uint32_t> max_edge_id_{0};  // Dynamically track maximum edge_id
    std::atomic<size_t> covered_edges_cache_{0};  // Cache covered edges count to avoid locking and computing size() each time

    // Coverage cache mechanism - use smart pointers to avoid large object copies
    mutable std::shared_ptr<CoverageInfo> cached_coverage_;
    mutable std::chrono::steady_clock::time_point last_cache_update_;
    mutable std::atomic<uint32_t> last_total_guards_{0};
    mutable std::atomic<size_t> cache_hits_{0};
    mutable std::atomic<size_t> cache_misses_{0};
    mutable std::mutex cache_mutex_;  // Protect cache access
    static constexpr auto CACHE_VALIDITY_DURATION = std::chrono::milliseconds(10);  // Cache validity period 10ms

    struct ExecutionThreadState {
        uint64_t epoch = 0;
        std::vector<uint32_t> guard_hits;
        std::vector<uint32_t> branch_hits;

        void ensureEpoch(uint64_t target_epoch) {
            if (epoch != target_epoch) {
                epoch = target_epoch;
                guard_hits.clear();
                branch_hits.clear();
            }
        }
    };

    static thread_local ExecutionThreadState tls_execution_state_;

    std::atomic<uint64_t> current_epoch_{1};
    std::vector<uint64_t> guard_epoch_;
    std::vector<uint64_t> branch_epoch_;
    
    // Initialize shared memory connection
    bool initSharedMemory() {
        std::lock_guard<std::mutex> lock(shm_mutex_);  // Protect shared memory initialization

        CoverageSharedMemory* shm = coverage_shm_.load();
        if (shm && shm != MAP_FAILED) return true;

        // Track if we created new shared memory
        bool fd_created_new = false;

        // Try to connect to existing shared memory first
        int fd = shm_open(SHM_NAME, O_RDWR, 0644);
        if (fd == -1) {
            // Create new shared memory if it doesn't exist
            fd = shm_open(SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0644);
            if (fd == -1) {
                // If creation failed because it exists, try to unlink and recreate
                if (errno == EEXIST) {
                    shm_unlink(SHM_NAME);
                    fd = shm_open(SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0644);
                    if (fd == -1) {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            fd_created_new = true;

            // Set size for new shared memory - MUST be done before mmap on Linux
            if (ftruncate(fd, sizeof(CoverageSharedMemory)) == -1) {
                close(fd);
                shm_unlink(SHM_NAME);
                return false;
            }
        } else {
            // For existing shared memory, verify its size
            struct stat sb;
            if (fstat(fd, &sb) == -1 || sb.st_size < sizeof(CoverageSharedMemory)) {
                close(fd);
                // Size mismatch, recreate it
                shm_unlink(SHM_NAME);
                fd = shm_open(SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0644);
                if (fd == -1) {
                    return false;
                }
                fd_created_new = true;
                if (ftruncate(fd, sizeof(CoverageSharedMemory)) == -1) {
                    close(fd);
                    shm_unlink(SHM_NAME);
                    return false;
                }
            }
        }
        
        // Map the shared memory
        shm = static_cast<CoverageSharedMemory*>(
            mmap(nullptr, sizeof(CoverageSharedMemory), 
                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
        
        close(fd);
        
        if (shm == MAP_FAILED) {
            coverage_shm_.store(nullptr);
            return false;
        }
        
        // Check if shared memory needs initialization
        // IMPORTANT: Must check these fields carefully to avoid accessing uninitialized memory
        bool needs_init = true;

        // Try to read initialized flag safely
        // First, zero out the entire structure for new allocations
        if (fd_created_new) {
            // For new shared memory on Linux, we must initialize it properly
            // Use volatile pointer to ensure writes are not optimized away
            volatile char* mem = reinterpret_cast<volatile char*>(shm);
            for (size_t i = 0; i < sizeof(CoverageSharedMemory); i++) {
                mem[i] = 0;
            }
            needs_init = true;
        } else {
            // For existing shared memory, carefully check if it's valid
            // First ensure memory is accessible by reading a byte
            volatile char test_byte = *reinterpret_cast<volatile char*>(shm);
            (void)test_byte;  // Suppress unused variable warning

            // Now safely read the actual fields
            volatile uint32_t init_flag = shm->initialized;
            volatile uint32_t guard_count = shm->total_guards;

            if (init_flag == 1 && guard_count > 0 && guard_count <= MAX_EDGES) {
                needs_init = false;  // Already initialized
            } else {
                needs_init = true;   // Need to initialize
            }
        }

        if (needs_init) {
            // Initialize new shared memory
            // First clear all management fields
            shm->total_guards = 0;
            shm->guard_start_offset = 0;
            shm->guard_count = 0;
            shm->total_branches = 0;
            shm->branch_initialized = 0;
            shm->branch_start_offset = 0;
            shm->branch_count = 0;

            // Initialize arrays using volatile-safe method
            // Use smaller chunks to avoid alignment issues
            const size_t initial_size = 65536;  // 64KB
            for (size_t i = 0; i < initial_size; i++) {
                shm->coverage_counters[i] = 0;
                shm->virgin_bits[i] = 0xFF;
                shm->virgin_crash[i] = 0xFF;
                shm->virgin_tmout[i] = 0xFF;
            }

            // Initialize branch arrays
            const size_t initial_branch_size = 32768;  // 32KB
            for (size_t i = 0; i < initial_branch_size; i++) {
                shm->branch_counters[i] = 0;
                shm->branch_virgin_bits[i] = 0xFF;
            }

            // Memory barrier to ensure all writes complete before marking as initialized
            std::atomic_thread_fence(std::memory_order_release);

            // Finally mark as initialized
            shm->initialized = 1;

            // Another memory barrier to ensure the initialized flag is visible
            std::atomic_thread_fence(std::memory_order_release);
        }

        // Memory barrier before storing the pointer
        std::atomic_thread_fence(std::memory_order_acquire);

        // Now it's safe to store the pointer
        coverage_shm_.store(shm);
        
        return true;
    }
    
    // Safely get shared memory pointer
    CoverageSharedMemory* getSharedMemorySafe() {
        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm || shm == MAP_FAILED) {
            if (initSharedMemory()) {
                shm = coverage_shm_.load();
            }
        }
        return (shm && shm != MAP_FAILED) ? shm : nullptr;
    }
    
public:
    static RealCoverageCollector& getInstance() {
        static RealCoverageCollector instance;
        return instance;
    }
    
    RealCoverageCollector()
        : guard_seen_flags_(std::make_unique<std::atomic<uint8_t>[]>(MAX_EDGES)),
          branch_seen_flags_(std::make_unique<std::atomic<uint8_t>[]>(MAX_BRANCHES)),
          guard_max_counters_(std::make_unique<std::atomic<uint8_t>[]>(MAX_EDGES)),
          branch_max_counters_(std::make_unique<std::atomic<uint8_t>[]>(MAX_BRANCHES)),
          guard_epoch_(MAX_EDGES, 0),
          branch_epoch_(MAX_BRANCHES, 0) {
        for (size_t i = 0; i < MAX_EDGES; ++i) {
            guard_seen_flags_[i].store(0, std::memory_order_relaxed);
            guard_max_counters_[i].store(0, std::memory_order_relaxed);
        }
        for (size_t i = 0; i < MAX_BRANCHES; ++i) {
            branch_seen_flags_[i].store(0, std::memory_order_relaxed);
            branch_max_counters_[i].store(0, std::memory_order_relaxed);
        }
        initSharedMemory();
    }
    
    ~RealCoverageCollector() {
        // Set shutdown flag, block new accesses
        shutdown_requested_.store(true);

        // Memory barrier to ensure shutdown flag is visible to all threads
        std::atomic_thread_fence(std::memory_order_release);

        // Wait for all in-progress operations to complete
        // Use exclusive lock to ensure no other thread is accessing
        std::lock_guard<std::mutex> coverage_lock(coverage_mutex_);
        std::lock_guard<std::mutex> shm_lock(shm_mutex_);
        std::lock_guard<std::mutex> cache_lock(cache_mutex_);

        // Clear cache to prevent dangling pointers
        cached_coverage_.reset();

        CoverageSharedMemory* shm = coverage_shm_.load();
        if (shm && shm != MAP_FAILED) {
            // Set pointer to nullptr first to prevent other thread access
            coverage_shm_.store(nullptr);

            // Memory barrier before unmapping
            std::atomic_thread_fence(std::memory_order_release);

            // Then unmap
            if (munmap(shm, sizeof(CoverageSharedMemory)) == -1) {
                // Silently fail - not critical during shutdown
            }
            // Do not delete shared memory, let other processes or final stats access it
            // shm_unlink(SHM_NAME);
        }
    }

    // added: safe shutdown method
    void shutdown() {
        shutdown_requested_.store(true);
    }
    
    // Get current coverage information by reading from shared memory
    CoverageInfo getCurrentCoverage() {
        if (shutdown_requested_.load()) {
            return CoverageInfo{};
        }

        CoverageSharedMemory* shm = getSharedMemorySafe();
        if (!shm) {
            return CoverageInfo{};
        }

        uint64_t epoch = current_epoch_.load(std::memory_order_acquire);
        tls_execution_state_.ensureEpoch(epoch);
        auto& tls_state = tls_execution_state_;

        std::vector<uint64_t> new_edges;
        std::vector<uint64_t> new_branches;
        std::vector<uint64_t> taken_branches;
        std::vector<uint64_t> not_taken_branches;

        new_edges.reserve(tls_state.guard_hits.size());
        new_branches.reserve(tls_state.branch_hits.size());

        for (uint32_t guard_id : tls_state.guard_hits) {
            if (guard_id == 0) {
                continue;
            }

            uint32_t index = guard_id - 1;
            if (index >= MAX_EDGES || index >= shm->total_guards) {
                continue;
            }

            uint8_t counter = shm->coverage_counters[index];
            uint8_t max_val = guard_max_counters_[index].load(std::memory_order_relaxed);
            while (counter > max_val &&
                   !guard_max_counters_[index].compare_exchange_weak(
                       max_val, counter, std::memory_order_relaxed)) {
                // retry until the maximum counter is updated
            }

            uint8_t seen = guard_seen_flags_[index].load(std::memory_order_relaxed);
            if (!seen &&
                guard_seen_flags_[index].compare_exchange_strong(
                    seen, 1, std::memory_order_acq_rel)) {
                new_edges.push_back(guard_id);
            }
        }

        for (uint32_t branch_id : tls_state.branch_hits) {
            if (branch_id == 0) {
                continue;
            }

            uint32_t index = branch_id - 1;
            if (index >= MAX_BRANCHES || index >= shm->total_branches) {
                continue;
            }

            uint8_t counter = shm->branch_counters[index];
            uint8_t max_val = branch_max_counters_[index].load(std::memory_order_relaxed);
            while (counter > max_val &&
                   !branch_max_counters_[index].compare_exchange_weak(
                       max_val, counter, std::memory_order_relaxed)) {
                // retry until the maximum counter is updated
            }

            uint64_t normalized_id = static_cast<uint64_t>(branch_id) + 3000000ULL;
            if (counter > 128) {
                taken_branches.push_back(normalized_id);
            } else {
                not_taken_branches.push_back(normalized_id);
            }

            uint8_t seen = branch_seen_flags_[index].load(std::memory_order_relaxed);
            if (!seen &&
                branch_seen_flags_[index].compare_exchange_strong(
                    seen, 1, std::memory_order_acq_rel)) {
                new_branches.push_back(normalized_id);
            }
        }

        size_t added_edges = new_edges.size();
        size_t added_branches = new_branches.size();

        if (added_edges > 0) {
            total_seen_guards_.fetch_add(added_edges, std::memory_order_relaxed);
        }
        if (added_branches > 0) {
            total_seen_branches_.fetch_add(added_branches, std::memory_order_relaxed);
        }

        {
            std::lock_guard<std::mutex> lock(coverage_mutex_);
            if (!cached_coverage_) {
                cached_coverage_ = std::make_shared<CoverageInfo>();
            }
            CoverageInfo& cached = *cached_coverage_;

            if (added_edges > 0) {
                cached.covered_edges.insert(
                    cached.covered_edges.end(), new_edges.begin(), new_edges.end());
                for (uint64_t edge : new_edges) {
                    if (edge > 0 && edge <= CoverageInfo::MAP_SIZE) {
                        cached.bitmap.set(static_cast<size_t>(edge - 1));
                    }
                }
            }

            if (added_branches > 0) {
                cached.covered_branches.insert(
                    cached.covered_branches.end(), new_branches.begin(), new_branches.end());
            }

            cached.total_edges = total_seen_guards_.load(std::memory_order_relaxed);
            cached.total_branches = shm->total_branches;
            cached.covered_branch_count = total_seen_branches_.load(std::memory_order_relaxed);
            cached.new_edges.clear();
            cached.new_branches.clear();
            cached.coverage_gain = 0.0;
            cached.branch_coverage_gain = 0.0;
        }

        CoverageInfo result;
        {
            std::lock_guard<std::mutex> lock(coverage_mutex_);
            if (!cached_coverage_) {
                cached_coverage_ = std::make_shared<CoverageInfo>();
            }
            result = *cached_coverage_;
        }

        result.new_edges = std::move(new_edges);
        result.coverage_gain = (shm->total_guards > 0)
                                   ? static_cast<double>(result.new_edges.size()) /
                                         static_cast<double>(shm->total_guards)
                                   : 0.0;
        result.new_branches = std::move(new_branches);
        result.branch_coverage_gain = (shm->total_branches > 0)
                                          ? static_cast<double>(result.new_branches.size()) /
                                                static_cast<double>(shm->total_branches)
                                          : 0.0;
        result.taken_branches = std::move(taken_branches);
        result.not_taken_branches = std::move(not_taken_branches);

        covered_edges_cache_.store(
            total_seen_guards_.load(std::memory_order_relaxed), std::memory_order_relaxed);
        last_total_guards_.store(shm->total_guards, std::memory_order_relaxed);
        last_cache_update_ = std::chrono::steady_clock::now();

        tls_state.guard_hits.clear();
        tls_state.branch_hits.clear();

        return result;
    }
    
    // Reset coverage for new execution
    void resetCoverage() {
        if (shutdown_requested_.load()) {
            return;
        }

        uint64_t new_epoch = current_epoch_.fetch_add(1, std::memory_order_acq_rel) + 1;

        if (new_epoch == 0) {
            new_epoch = 1;
            current_epoch_.store(new_epoch, std::memory_order_release);
            std::fill(guard_epoch_.begin(), guard_epoch_.end(), 0);
            std::fill(branch_epoch_.begin(), branch_epoch_.end(), 0);
        }

        tls_execution_state_.ensureEpoch(new_epoch);

        {
            std::lock_guard<std::mutex> cache_lock(cache_mutex_);
            if (cached_coverage_) {
                cached_coverage_->new_edges.clear();
                cached_coverage_->new_branches.clear();
                cached_coverage_->rare_edges.clear();
                cached_coverage_->rare_branches.clear();
            }
        }

        last_total_guards_.store(0, std::memory_order_relaxed);
        last_cache_update_ = std::chrono::steady_clock::time_point::min();
    }
    
    // added: method to manually reset coverage state
    void clearCoverageState() {
        // Check if shutdown is in progress
        if (shutdown_requested_.load()) {
            return;
        }

        // First ensure shared memory is initialized
        if (!initSharedMemory()) {
            // Cannot initialize shared memory, return silently
            return;
        }

        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm || shm == MAP_FAILED) {
            return; // Cannot get shared memory
        }

        {
            std::lock_guard<std::mutex> lock(coverage_mutex_);
            if (cached_coverage_) {
                cached_coverage_->covered_edges.clear();
                cached_coverage_->covered_branches.clear();
                cached_coverage_->bitmap.reset();
                cached_coverage_->total_edges = 0;
                cached_coverage_->total_branches = 0;
                cached_coverage_->covered_branch_count = 0;
            }
        }

        covered_edges_cache_.store(0, std::memory_order_relaxed);
        total_seen_guards_.store(0, std::memory_order_relaxed);
        total_seen_branches_.store(0, std::memory_order_relaxed);

        for (size_t i = 0; i < MAX_EDGES; ++i) {
            guard_seen_flags_[i].store(0, std::memory_order_relaxed);
            guard_max_counters_[i].store(0, std::memory_order_relaxed);
        }
        for (size_t i = 0; i < MAX_BRANCHES; ++i) {
            branch_seen_flags_[i].store(0, std::memory_order_relaxed);
            branch_max_counters_[i].store(0, std::memory_order_relaxed);
        }

        // If newly allocated shared memory, total_guards should already be 0
        // Only clean up if there is actually data
        uint32_t total_guards = shm->total_guards;

        // Validate total_guards value
        if (total_guards > 0 && total_guards <= MAX_EDGES) {
            // Use volatile-safe method to clear arrays, avoiding alignment issues
            for (uint32_t i = 0; i < total_guards; i++) {
                shm->coverage_counters[i] = 0;
                shm->virgin_bits[i] = 0xFF;
                shm->virgin_crash[i] = 0xFF;
                shm->virgin_tmout[i] = 0xFF;
            }
        }

        // Clean up branch data
        uint32_t total_branches = shm->total_branches;
        if (total_branches > 0 && total_branches <= MAX_BRANCHES) {
            // Use volatile-safe method to clear branch arrays
            for (uint32_t i = 0; i < total_branches; i++) {
                shm->branch_counters[i] = 0;
                shm->branch_virgin_bits[i] = 0xFF;
            }
        }
        
        // Removed std::cout calls to avoid using stdout during program initialization
        // std::cout << "[INFO] Coverage state cleared - ready for fresh coverage measurement" << std::endl;

        current_epoch_.store(1, std::memory_order_release);
        std::fill(guard_epoch_.begin(), guard_epoch_.end(), 0);
        std::fill(branch_epoch_.begin(), branch_epoch_.end(), 0);
        tls_execution_state_.ensureEpoch(1);
    }
    
    size_t getTotalGuards() const {
        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm || shm == MAP_FAILED) return 0;

        // In trace-pc mode, use dynamically tracked maximum edge_id
        if (trace_pc_mode_.load()) {
            uint32_t max_id = max_edge_id_.load();
            // Ensure at least a reasonable value is returned
            return max_id > 0 ? max_id : shm->total_guards;
        }

        return shm->total_guards;
    }

    // Dynamically update maximum edge_id (for GCC trace-pc mode)
    void updateMaxEdgeId(uint32_t edge_id) {
        if (!trace_pc_mode_.load()) return;

        // Atomically update maximum value
        uint32_t current_max = max_edge_id_.load();
        while (edge_id > current_max) {
            if (max_edge_id_.compare_exchange_weak(current_max, edge_id)) {
                // Also update total_guards in shared memory
                CoverageSharedMemory* shm = coverage_shm_.load();
                if (shm && shm != MAP_FAILED) {
                    // Conservative approach: only increase, never decrease
                    if (edge_id > shm->total_guards) {
                        shm->total_guards = edge_id;
                    }
                }
                break;
            }
        }
    }
    
    size_t getCoveredEdges() const {
        // Use atomic cache to avoid locking each time
        return covered_edges_cache_.load(std::memory_order_relaxed);
    }

    // Save covered edges to file (for complementarity analysis)
    bool saveCoveredEdgesToFile(const std::string& output_path) const {
        std::ofstream out(output_path);
        if (!out.is_open()) {
            std::cerr << "[RealCoverageCollector] Failed to open file for writing: "
                      << output_path << std::endl;
            return false;
        }

        std::vector<std::pair<uint32_t, uint64_t>> edge_counts;
        edge_counts.reserve(total_seen_guards_.load(std::memory_order_relaxed));
        for (uint32_t i = 0; i < MAX_EDGES; ++i) {
            if (guard_seen_flags_[i].load(std::memory_order_relaxed) == 0) {
                continue;
            }
            uint64_t count = guard_max_counters_[i].load(std::memory_order_relaxed);
            edge_counts.emplace_back(i + 1, count);
        }

        // Sort by edge_id for easier inspection and debugging
        std::sort(edge_counts.begin(), edge_counts.end());

        // Write to file - CSV format for subsequent analysis
        out << "# Covered Edges with Hit Counts - Total: " << edge_counts.size() << "\n";
        out << "# Format: edge_id,hit_count\n";
        out << "edge_id,hit_count\n";
        for (const auto& [edge_id, count] : edge_counts) {
            out << edge_id << "," << count << "\n";
        }
        out.close();

        std::cout << "[RealCoverageCollector] Saved " << edge_counts.size()
                  << " covered edges with hit counts to " << output_path << std::endl;
        return true;
    }

    double getCoveragePercentage() const {
        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm || shm == MAP_FAILED) return 0.0;
        
        uint32_t total = shm->total_guards;
        if (total == 0) {
            return 0.0;
        }
        
        double percentage =
            (static_cast<double>(total_seen_guards_.load(std::memory_order_relaxed)) / total) *
            100.0;

        return percentage;
    }
    
    bool isInitialized() const {
        CoverageSharedMemory* shm = coverage_shm_.load();
        return shm != nullptr && shm != MAP_FAILED && shm->initialized;
    }
    
    // Initialize for GCC trace-pc mode (without guard arrays)
    void initForTracePC(uint32_t estimated_edges) {
        if (!coverage_shm_.load()) {
            initSharedMemory();
            if (!coverage_shm_.load()) return;
        }

        CoverageSharedMemory* shm = coverage_shm_.load();
        if (shm && shm != MAP_FAILED) {
            // Mark as trace-pc mode
            trace_pc_mode_.store(true);

            // For GCC trace-pc, use initial estimate
            // But will be dynamically adjusted at runtime
            shm->total_guards = estimated_edges;
            shm->initialized = 1;

            // Clear counters and initialize virgin bits
            memset((void*)shm->coverage_counters, 0, sizeof(shm->coverage_counters));
            memset((void*)shm->virgin_bits, 0xFF, sizeof(shm->virgin_bits));
            memset((void*)shm->virgin_crash, 0xFF, sizeof(shm->virgin_crash));
            memset((void*)shm->virgin_tmout, 0xFF, sizeof(shm->virgin_tmout));
        }
    }
    
    // Add guards for in-process coverage collection
    void addGuards(uint32_t* start, uint32_t count) {
        if (!coverage_shm_.load()) {
            initSharedMemory();
            if (!coverage_shm_.load()) return;
        }

        // Fix: ensure instrumentation point count consistency
        // Use a static variable to track whether instrumentation points have been initialized
        static bool guards_initialized = false;
        static uint32_t total_program_guards = 0;

        if (!guards_initialized) {
            // First initialization: calculate total instrumentation point count
            total_program_guards = count;
            guards_initialized = true;

            // If shared memory has data but doesn't match current program, reset it
            if (coverage_shm_.load()->total_guards > 0 && coverage_shm_.load()->total_guards != total_program_guards) {
                // Removed std::cout calls to avoid using stdout during program initialization
                // std::cout << "[WARNING] Shared memory has inconsistent guard count ("
                //           << coverage_shm_.load()->total_guards << " vs " << total_program_guards
                //           << "), resetting..." << std::endl;

                // Reset shared memory counters and virgin bits
                for (size_t i = 0; i < MAX_EDGES; i++) {
                    coverage_shm_.load()->coverage_counters[i] = 0;
                    coverage_shm_.load()->virgin_bits[i] = 0xFF;
                    coverage_shm_.load()->virgin_crash[i] = 0xFF;
                    coverage_shm_.load()->virgin_tmout[i] = 0xFF;
                }
                coverage_shm_.load()->total_guards = 0;
                coverage_shm_.load()->initialized = 0;
            }
        } else {
            // Subsequent calls: verify count consistency
            if (count != total_program_guards) {
                // Removed std::cout calls to avoid using stdout during program initialization
                // std::cout << "[WARNING] Inconsistent guard count in subsequent call: "
                //           << count << " vs " << total_program_guards << std::endl;
                // Use the value recorded on first call
                count = total_program_guards;
            }
        }

        // Only set if shared memory is not yet initialized
        if (coverage_shm_.load()->total_guards == 0) {
            // Initialize guards with sequential IDs
            for (uint32_t i = 0; i < count; i++) {
                start[i] = i + 1; // Guard IDs start from 1
            }
            coverage_shm_.load()->total_guards = count;
            coverage_shm_.load()->initialized = 1;

            // Removed std::cout calls to avoid using stdout during program initialization
            // std::cout << "[INFO] Initialized " << count << " guards (total: "
            //           << coverage_shm_.load()->total_guards << ")" << std::endl;
        } else {
            // Shared memory already initialized, verify consistency
            if (coverage_shm_.load()->total_guards != total_program_guards) {
                // Removed std::cout calls to avoid using stdout during program initialization
                // std::cout << "[ERROR] Guard count mismatch: shared memory has "
                //           << coverage_shm_.load()->total_guards << " but program expects "
                //           << total_program_guards << std::endl;
            }

            // Reset guard IDs (without changing total_guards)
            for (uint32_t i = 0; i < count; i++) {
                start[i] = i + 1; // Guard IDs start from 1
            }
        }
    }
    
    // Mark a guard as hit for in-process coverage collection with AFL++ style counting
    void markGuardHit(uint32_t guard_id) {
        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm || guard_id == 0) return;

        uint32_t index = guard_id - 1;
        if (index >= MAX_EDGES || index >= shm->total_guards) {
            return;
        }

        uint8_t old_val = shm->coverage_counters[index];
        uint8_t new_val = (old_val < 255) ? (old_val + 1) : 255;
        shm->coverage_counters[index] = new_val;

        uint8_t cur_bucket = count_class_lookup8[new_val];
        shm->virgin_bits[index] &= ~(1 << (cur_bucket & 7));

        uint64_t epoch = current_epoch_.load(std::memory_order_acquire);
        tls_execution_state_.ensureEpoch(epoch);

        if (guard_epoch_[index] != epoch) {
            guard_epoch_[index] = epoch;
            tls_execution_state_.guard_hits.push_back(guard_id);
        }
    }
    
    // added: branch management, following the guards workflow
    void addBranches(uint32_t* start, uint32_t count) {
        if (!coverage_shm_.load()) {
            initSharedMemory();
            if (!coverage_shm_.load()) return;
        }
        
        static bool branches_initialized = false;
        static uint32_t total_program_branches = 0;
        
        if (!branches_initialized) {
            total_program_branches = count;
            branches_initialized = true;
            
            // Reset branch-related shared memory data (using 8-bit counters)
            if (coverage_shm_.load()->total_branches > 0 && coverage_shm_.load()->total_branches != total_program_branches) {
                for (size_t i = 0; i < MAX_BRANCHES; i++) {
                    coverage_shm_.load()->branch_counters[i] = 0;
                    coverage_shm_.load()->branch_virgin_bits[i] = 0xFF;
                }
                coverage_shm_.load()->total_branches = 0;
                coverage_shm_.load()->branch_initialized = 0;
            }
        }
        
        // Initialize branch IDs
        if (coverage_shm_.load()->total_branches == 0) {
            for (uint32_t i = 0; i < count; i++) {
                start[i] = i + 1; // Branch IDs start from 1
            }
            coverage_shm_.load()->total_branches = count;
            coverage_shm_.load()->branch_initialized = 1;
        } else {
            // Reset branch IDs
            for (uint32_t i = 0; i < count; i++) {
                start[i] = i + 1;
            }
        }
    }
    
    // added: mark branch hit using AFL++-style 8-bit counters
    void markBranchHit(uint32_t branch_id, bool taken) {
        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm || branch_id == 0) return;

        uint32_t index = branch_id - 1;
        if (index >= MAX_BRANCHES || index >= shm->total_branches) {
            return;
        }

        uint8_t old_val = shm->branch_counters[index];
        uint8_t new_val = (old_val < 255) ? (old_val + 1) : 255;

        uint8_t old_bucket = count_class_lookup8[old_val];
        uint8_t new_bucket = count_class_lookup8[new_val];

        shm->branch_counters[index] = new_val;

        if (old_bucket != new_bucket) {
            shm->branch_virgin_bits[index] &= ~(1 << (new_bucket % 8));
        }

        (void)taken; // Parameter kept for future compatibility

        uint64_t epoch = current_epoch_.load(std::memory_order_acquire);
        tls_execution_state_.ensureEpoch(epoch);

        if (branch_epoch_[index] != epoch) {
            branch_epoch_[index] = epoch;
            tls_execution_state_.branch_hits.push_back(branch_id);
        }
    }
    
    // added: branch comparison recording method - now uses the new branch management workflow
    template<typename T>
    void recordBranchComparison(T arg1, T arg2, size_t size) {
        if (!coverage_shm_.load()) return;
        
        // Check if total_branches is initialized to prevent division by zero
        if (coverage_shm_.load()->total_branches == 0) return;
        
        // Generate branch state info based on comparison result
        uint64_t comparison_hash = hashComparison(arg1, arg2, size);
        uint32_t branch_id = (comparison_hash % coverage_shm_.load()->total_branches) + 1;
        
        // Determine branch state from comparison result
        bool taken = (arg1 == arg2);
        
        // Use new branch hit marking method, following guards workflow
        markBranchHit(branch_id, taken);
    }
    
    void initialize8BitCounters(uint8_t* start, uint8_t* stop) {
        // 8-bit counter initialization for finer-grained coverage tracking
        if (!start || !stop || start >= stop) return;
        
        // These counters provide richer information than simple hit/no-hit
        // e.g., hit frequency, path hotness, etc.
        size_t counter_count = stop - start;
        (void)counter_count; // mark as used to avoid warning
        // Initialize counter mapping...
    }

private:
    template<typename T>
    uint64_t hashComparison(T arg1, T arg2, size_t size) {
        // Simple hash function to generate branch identifiers
        uint64_t hash = 0;
        hash ^= std::hash<T>{}(arg1) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<T>{}(arg2) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= size;
        return hash;
    }
    
    void setBranchState(uint32_t branch_index, bool taken) {
        if (branch_index >= MAX_EDGES) return;

        CoverageSharedMemory* shm = coverage_shm_.load();
        if (!shm) return;

        // Use 8-bit counters to encode taken/not_taken state
        // taken branch: odd value
        // not_taken branch: even value
        if (taken) {
            uint8_t current_val = shm->coverage_counters[branch_index];
            if (current_val % 2 == 0) {
                shm->coverage_counters[branch_index] = (current_val < 254) ? (current_val + 1) : 255;
            }
        } else {
            uint8_t current_val = shm->coverage_counters[branch_index];
            if (current_val % 2 == 1) {
                shm->coverage_counters[branch_index] = (current_val < 254) ? (current_val + 1) : 254;
            } else if (current_val == 0) {
                shm->coverage_counters[branch_index] = 2; // set directly to even
            }
        }
    }
};

// Static member definition
const char* RealCoverageCollector::SHM_NAME = "/collafuzz_coverage";
thread_local RealCoverageCollector::ExecutionThreadState RealCoverageCollector::tls_execution_state_;

// =============================================================================
// Clang Sanitizer Coverage Callback Functions
// =============================================================================
// These functions provide the interface between clang's coverage instrumentation
// and our coverage collection system via shared memory

extern "C" {
    // Lightweight runtime toggle for CmpLog recording (default: enabled).
    static inline bool __collafuzz_cmplog_enabled() {
        static int cached = -1; // -1: uninitialized, 0: disabled, 1: enabled
        if (cached == -1) {
            const char* env = std::getenv("triofuzz_DISABLE_CMPLOG");
            cached = (env == nullptr) ? 1 : 0;
        }
        return cached != 0;
    }

    // Called by clang instrumentation during startup
    // triofuzz-Mini: Uses AFL++-compatible bitmap coverage for fair comparison
    void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
        // Initialize AFL-compatible coverage (65536 byte bitmap like AFL++)
        // AFLCompatibleCoverage is initialized on first getInstance() call

        // For in-process execution, assign unique IDs to guards for AFL-style XOR hashing
        if (start && stop && start < stop) {
            // Assign unique IDs using a prime multiplier for good distribution
            for (uint32_t* guard = start; guard < stop; ++guard) {
                // Use guard index XORed with a prime for better distribution in bitmap
                *guard = static_cast<uint32_t>((guard - start + 1) * 2654435761U) & 0xFFFF;
            }
        }
    }

    // GCC trace-pc does not need an initialization function
    __attribute__((constructor))
    void __collafuzz_gcc_trace_pc_init() {
        // AFLCompatibleCoverage is initialized on first getInstance() call
        // Nothing special needed here for GCC
    }

    // Called by clang instrumentation on every edge
    // triofuzz-Mini: Uses AFL++-style XOR edge hashing for fair comparison with AFL++
	    void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
	        // Prevent recursive calls
	        static thread_local bool in_guard_trace = false;
	        if (in_guard_trace) return;

	        if (guard && *guard > 0) {
	            in_guard_trace = true;

	            uint32_t cur_loc = *guard;
	            // AFL++-style XOR edge hashing: edge_id = cur_loc ^ prev_loc
	            // Distinguishes A->B from B->A (asymmetric edges).
	            //
	            // NOTE: prev_loc is maintained thread-locally inside AFLCompatibleCoverage
	            // and is reset for each input execution via AFLCompatibleCoverage::reset().
	            uint32_t edge_id = triofuzz::AFLCompatibleCoverage::computeEdgeId(cur_loc);

	            // Record edge in AFL-compatible bitmap (primary coverage for fuzzing feedback)
	            auto& afl_cov = triofuzz::AFLCompatibleCoverage::getInstance();
	            afl_cov.recordEdge(edge_id);
	
	            // Optional: also record the guard ID itself (basic-block style coverage)
	            // into the same bitmap. This can reduce the gap between "dynamic"
	            // llvm-cov coverage (all executed inputs) and FuzzBench snapshot replay
	            // coverage (only on-disk corpus), by making new-coverage detection less
	            // lossy than pure AFL edge hashing.
	            static int include_guard_coverage = -1;
	            if (include_guard_coverage == -1) {
	                include_guard_coverage =
	                    (std::getenv("TRIOFUZZ_INCLUDE_GUARD_COVERAGE") != nullptr) ? 1 : 0;
	            }
	            if (include_guard_coverage) {
	                afl_cov.recordEdge(cur_loc);
	            }

	            in_guard_trace = false;
	        }
	    }
    
    // NOTE: `trace-cmp` is extremely hot (called for every comparison). TrioFuzz
    // already gets strong coverage feedback from AFL-style edge hashing
    // (`trace-pc-guard`). To avoid a large throughput hit, we gate the
    // non-const comparison callbacks behind a "full cmplog" mode that is only
    // enabled for analysis-style combinations.
    //
    // When full mode is disabled, we still record:
    //   - __sanitizer_cov_trace_const_cmp*   (compile-time constants)
    //   - __sanitizer_cov_trace_memcmp/str* (mem/string tokens)
    // gated by cmplog::isEnabled().
	    void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {
	        if (!cmplog::isFullEnabled()) return;
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint8_t>(pc, arg1, arg2, cmplog::CmpKind::Int);
	    }
    
	    void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {
	        if (!cmplog::isFullEnabled()) return;
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint16_t>(pc, arg1, arg2, cmplog::CmpKind::Int);
	    }
    
	    void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {
	        if (!cmplog::isFullEnabled()) return;
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint32_t>(pc, arg1, arg2, cmplog::CmpKind::Int);
	    }
    
	    void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {
	        if (!cmplog::isFullEnabled()) return;
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint64_t>(pc, arg1, arg2, cmplog::CmpKind::Int);
	    }

	    void __sanitizer_cov_trace_switch(uint64_t val, uint64_t* cases) {
	        if (!cmplog::isFullEnabled()) return;
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        if (!cases) return;
	        uint64_t num = cases[0];
	        if (num == 0) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        // cases[1] is the bit width of val (commonly 8/16/32/64).
	        uint64_t bits = cases[1];
	        uint64_t pick = cases[2 + (val % std::min<uint64_t>(num, 16))];
	        if (bits <= 8) {
	            cmplog::recordInt<uint8_t>(pc, static_cast<uint8_t>(val), static_cast<uint8_t>(pick), cmplog::CmpKind::Switch);
	        } else if (bits <= 16) {
	            cmplog::recordInt<uint16_t>(pc, static_cast<uint16_t>(val), static_cast<uint16_t>(pick), cmplog::CmpKind::Switch);
	        } else if (bits <= 32) {
	            cmplog::recordInt<uint32_t>(pc, static_cast<uint32_t>(val), static_cast<uint32_t>(pick), cmplog::CmpKind::Switch);
	        } else {
	            cmplog::recordInt<uint64_t>(pc, val, pick, cmplog::CmpKind::Switch);
	        }
	    }

	    // Const-int comparisons (one side is a constant)
	    void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint8_t>(pc, arg1, arg2, cmplog::CmpKind::ConstInt);
	    }
	    void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint16_t>(pc, arg1, arg2, cmplog::CmpKind::ConstInt);
	    }
	    void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint32_t>(pc, arg1, arg2, cmplog::CmpKind::ConstInt);
	    }
	    void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordInt<uint64_t>(pc, arg1, arg2, cmplog::CmpKind::ConstInt);
	    }

	    // Memory/string comparisons
	    void __sanitizer_cov_trace_memcmp(const void* s1, const void* s2, size_t n) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordMem(pc, s1, s2, n, cmplog::CmpKind::Mem);
	    }
	    void __sanitizer_cov_trace_strncmp(const char* s1, const char* s2, size_t n) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        cmplog::recordMem(pc, s1, s2, n, cmplog::CmpKind::StrN);
	    }

	    void __sanitizer_cov_trace_strcmp(const char* s1, const char* s2) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        if (!s1 || !s2) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        size_t n1 = 0;
	        size_t n2 = 0;
	        while (n1 + 1 < cmplog::MAX_BYTES && s1[n1]) n1++;
	        while (n2 + 1 < cmplog::MAX_BYTES && s2[n2]) n2++;
	        size_t n = std::min<size_t>(cmplog::MAX_BYTES, std::max(n1, n2) + 1);
	        cmplog::recordMem(pc, s1, s2, n, cmplog::CmpKind::Str);
	    }

	    void __sanitizer_cov_trace_strstr(const char* s1, const char* s2) {
	        if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return;
	        if (!s1 || !s2) return;
	        void* pc_ptr = __builtin_return_address(0);
	        uint64_t pc = reinterpret_cast<uint64_t>(pc_ptr);
	        size_t n1 = 0;
	        size_t n2 = 0;
	        while (n1 + 1 < cmplog::MAX_BYTES && s1[n1]) n1++;
	        while (n2 + 1 < cmplog::MAX_BYTES && s2[n2]) n2++;
	        // Record (haystack, needle) pair.
	        size_t n = std::min<size_t>(cmplog::MAX_BYTES, std::max(n1, n2) + 1);
	        cmplog::recordMem(pc, s1, s2, n, cmplog::CmpKind::Str);
	    }

    // [REMOVED] Legacy 8-bit counter support - replaced by implementation in inline_8bit_coverage.hpp
    // void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
    //     auto& real_collector = RealCoverageCollector::getInstance();
    //     real_collector.initialize8BitCounters(start, stop);
    // }

    // added: branch initialization function - following the guards initialization workflow
    void __sanitizer_cov_trace_branch_init(uint32_t *start, uint32_t *stop) {
        auto& real_collector = RealCoverageCollector::getInstance();
        
        if (start && stop && start < stop) {
            uint32_t branch_count = stop - start;
            real_collector.addBranches(start, branch_count);
        }
    }
    
    // ========================================================================
    // GCC Trace-PC Support (Alternative to Clang's trace-pc-guard)
    // ========================================================================
    // GCC uses simpler trace-pc instrumentation without guard arrays
    // This is called on every basic block when compiled with -fsanitize-coverage=trace-pc
    
    void __sanitizer_cov_trace_pc() {
        // Prevent recursive calls
        static thread_local bool in_trace_pc = false;
        if (in_trace_pc) return;
        in_trace_pc = true;

        // Get return address as PC value, used as unique edge identifier
        void* pc = __builtin_return_address(0);

        // Convert PC to edge ID (using hash to map into our bitmap space)
        uint64_t pc_value = reinterpret_cast<uint64_t>(pc);
        uint32_t edge_id = (pc_value ^ (pc_value >> 32)) & 0xFFFF; // map to 16-bit space

        // Use existing coverage collection infrastructure
        auto& real_collector = RealCoverageCollector::getInstance();

        // For GCC trace-pc, dynamically update maximum edge_id
        real_collector.updateMaxEdgeId(edge_id + 1);

        // For GCC trace-pc, we emulate the guard mechanism
        // Use edge_id + 1 as guard value (guard value 0 means uninitialized)
        if (edge_id < 65536) {  // 16-bit space limit
            real_collector.markGuardHit(edge_id + 1);
        }

        in_trace_pc = false;
    }
    
    // GCC trace-pc-indir for indirect call tracking
    void __sanitizer_cov_trace_pc_indir(void* callee) {
        static thread_local bool in_trace_pc_indir = false;
        if (in_trace_pc_indir) return;
        in_trace_pc_indir = true;
        
        // Record indirect call target
        uint64_t callee_addr = reinterpret_cast<uint64_t>(callee);
        uint32_t edge_id = (callee_addr ^ (callee_addr >> 32)) & 0xFFFF;
        
        auto& real_collector = RealCoverageCollector::getInstance();
        if (edge_id < 65536) {  // 16-bit space limit
            real_collector.markGuardHit(edge_id + 1);
        }
        
        in_trace_pc_indir = false;
    }
}


// =============================================================================
// Coverage Collection Helper (for global state management)
// =============================================================================

class CoverageCollector {
private:
    // Use atomic bitmap to reduce lock contention
    std::array<std::atomic<uint64_t>, 1024> atomic_bitmap_;  // 65536 / 64 = 1024
    std::unordered_map<uint64_t, std::atomic<size_t>> edge_hit_count_;
    std::atomic<size_t> unique_edges_count_{0};
    
    // Fallback legacy bitmap (for compatibility)
    std::bitset<65536> global_bitmap_;
    mutable std::shared_mutex bitmap_mutex_;

public:
    CoverageCollector() {
        // Initialize atomic bitmap
        for (auto& word : atomic_bitmap_) {
            word.store(0, std::memory_order_relaxed);
        }
    }
    
    void updateCoverage(const std::bitset<65536>& new_bitmap) {
        // Fast atomic update, avoiding lock contention
        size_t new_edges = 0;
        for (size_t i = 0; i < 1024; ++i) {
            uint64_t new_word = 0;
            for (size_t j = 0; j < 64; ++j) {
                if (new_bitmap[i * 64 + j]) {
                    new_word |= (1ULL << j);
                }
            }
            
            if (new_word != 0) {
                // Atomic OR operation
                uint64_t old_word = atomic_bitmap_[i].fetch_or(new_word, std::memory_order_relaxed);
                // Count newly discovered edges
                uint64_t new_bits = new_word & ~old_word;
                if (new_bits) {
                    new_edges += __builtin_popcountll(new_bits);
                }
            }
        }
        
        // Atomically update unique edge count
        if (new_edges > 0) {
            unique_edges_count_.fetch_add(new_edges, std::memory_order_relaxed);
        }
        
        // Keep legacy bitmap in sync (less frequent lock operations)
        if (new_edges > 0) {
            std::unique_lock<std::shared_mutex> lock(bitmap_mutex_);
            global_bitmap_ |= new_bitmap;
        }
    }
    
    bool updateCoverageWithEdges(const CoverageInfo& coverage_info) {
        // Fixed: Only report truly new edges globally, not edges that are "new" from execution perspective
        bool has_new_edges = false;
        std::vector<uint64_t> truly_new_edges;

        // Need to use lock to check and update atomically to avoid race conditions
        std::unique_lock<std::shared_mutex> lock(bitmap_mutex_);

        // Check bitmap for new coverage
        auto old_bitmap = global_bitmap_;
        global_bitmap_ |= coverage_info.bitmap;
        bool bitmap_changed = (global_bitmap_ != old_bitmap);

        // Check each edge to see if it's truly new globally
        for (uint64_t edge : coverage_info.new_edges) {
            auto edge_it = edge_hit_count_.find(edge);
            if (edge_it == edge_hit_count_.end()) {
                // This is truly a new edge globally
                edge_hit_count_[edge].store(1, std::memory_order_relaxed);
                unique_edges_count_.fetch_add(1, std::memory_order_relaxed);
                truly_new_edges.push_back(edge);
                has_new_edges = true;
            } else {
                // Edge already exists, just increment hit count
                edge_it->second.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Also check for edges in the bitmap that aren't in new_edges list
        // This handles cases where the bitmap has coverage not reflected in edge list
        if (bitmap_changed && !has_new_edges) {
            // Bitmap changed but no new edges reported - this might indicate
            // an inconsistency, but we should still report new coverage
            has_new_edges = bitmap_changed;
        }

        return has_new_edges;
    }
    
    CoverageInfo getCoverageInfo() const {
        std::shared_lock<std::shared_mutex> lock(bitmap_mutex_);
        
        CoverageInfo info;
        info.bitmap = global_bitmap_;
        info.total_edges = unique_edges_count_.load(std::memory_order_relaxed);
        return info;
    }
    
    bool hasNewCoverage(const std::bitset<65536>& bitmap) const {
        // Fast atomic check, no lock needed
        for (size_t i = 0; i < 1024; ++i) {
            uint64_t new_word = 0;
            for (size_t j = 0; j < 64; ++j) {
                if (bitmap[i * 64 + j]) {
                    new_word |= (1ULL << j);
                }
            }
            
            uint64_t current = atomic_bitmap_[i].load(std::memory_order_relaxed);
            if ((new_word & ~current) != 0) {
                return true;  // found new coverage
            }
        }
        return false;
    }
    
    double getCoveragePercentage() const {
        std::shared_lock<std::shared_mutex> lock(bitmap_mutex_);
        
        // Use the real coverage collector if available
        auto& real_collector = RealCoverageCollector::getInstance();
        if (real_collector.getTotalGuards() > 0) {
            return real_collector.getCoveragePercentage();
        }
        
        // Fallback to bitmap-based calculation
        return (global_bitmap_.count() * 100.0) / 65536.0;
    }
    
    size_t getUniqueEdgesCount() const {
        return unique_edges_count_.load(std::memory_order_relaxed);
    }
};

// Declare LLVMFuzzerTestOneInput function outside the class
extern "C" __attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

// Real executor implementation
class SimpleExecutor : public Executor {
private:
    std::string target_binary_;
    std::map<std::string, std::string> environment_;
    size_t memory_limit_mb_ = 1024;
   std::chrono::milliseconds time_limit_{1000};
   bool use_inprocess_mode_ = true; // default to in-process mode

    // Signal handlers installed once, avoid reinstalling on every execution
    static void installSignalHandlers();
    static void signalHandler(int sig);
    static std::once_flag signal_once_flag_;
    static std::array<struct sigaction, 3> previous_handlers_;
    static std::array<int, 3> handled_signals_;
    static volatile sig_atomic_t crash_counter_;
    
    // LLVMFuzzerTestOneInput function pointer declaration (for dynamic loading)
    typedef int (*LLVMFuzzerTestOneInput_t)(const uint8_t* data, size_t size);
    [[maybe_unused]] LLVMFuzzerTestOneInput_t LLVMFuzzerTestOneInput_func = nullptr;
    
    // Write input to temporary file
    std::string writeInputToFile(const std::vector<uint8_t>& input) {
        static std::atomic<size_t> file_counter{0};
        std::string filename = "/tmp/fuzzer_input_" + std::to_string(getpid()) + 
                              "_" + std::to_string(file_counter++);
        
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot create input file: " + filename);
        }
        
        // Fix: safely handle empty input to avoid null pointer access
        if (!input.empty()) {
            file.write(reinterpret_cast<const char*>(input.data()), input.size());
        }
        // If input is empty, create empty file (write nothing)
        file.close();
        
        return filename;
    }
    
    // Clean up temporary file
    void cleanupFile(const std::string& filename) {
        std::filesystem::remove(filename);
    }
    
public:
    explicit SimpleExecutor(const std::string& target) : target_binary_(target) {
        // Try to find LLVMFuzzerTestOneInput function - if the target is a compiled executable containing it
        // For in-process mode, we directly declare the external function
    }
    
    // Removed extern "C" declaration from inside the class
    
    ExecutionResult execute(const std::vector<uint8_t>& input,
                          const std::chrono::milliseconds& timeout) override {
        ExecutionResult result;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        try {
            // Validate input parameters
            if (input.size() > 16777216) { // 16MB limit
                result.status = ExecutionResult::Status::Error;
                result.error_message = "Input too large";
                return result;
            }
            
            // If using in-process mode (fix: support empty input)
            if (use_inprocess_mode_) {
                try {
                    // [PERF-FIX] Removed resetCoverage() call - this was a performance bottleneck!
                    // libFuzzer does not actively reset; coverage counters are managed by target instrumentation
                    // Calling resetCoverage() on every execution caused:
                    // 1. Atomic operation epoch increment
                    // 2. mutex lock on cache_mutex_
                    // 3. vector clear operation
                    // These accumulated to add several ms overhead per execution, causing 26x slowdown!
                    // RealCoverageCollector::getInstance().resetCoverage();  // removed

                    // Install signal handlers once, for crash detection
                    installSignalHandlers();

                    // Save current input for signal handler use
                    g_current_fuzzing_input = input;

                    // triofuzz-Mini: Reset AFL-compatible bitmap before execution
                    triofuzz::AFLCompatibleCoverage::getInstance().reset();

	                    // Before starting this execution, clear this thread's cmplog record cache (supports per-thread dynamic sampling)
	                    if (__collafuzz_cmplog_enabled() && cmplog::isEnabled()) cmplog::startNewInput();

                    // Directly call LLVMFuzzerTestOneInput function
                    int ret_code = 0;
                    if (LLVMFuzzerTestOneInput) {
                        ret_code = LLVMFuzzerTestOneInput(input.data(), input.size());
                    }

                    // Set execution result
                    result.exit_code = ret_code;
                    // Fix: do not treat all non-zero return values as errors
                    // Return values 100-110 are typically normal functional returns from test programs
                    if (ret_code == 0 || (ret_code >= 100 && ret_code <= 110)) {
                        result.status = ExecutionResult::Status::Success;
                    } else if (ret_code < 0 || ret_code > 200) {
                        // Only abnormal return values are considered errors
                        result.status = ExecutionResult::Status::Error;
                    } else {
                        // Other cases also considered success (may be special functional return values)
                        result.status = ExecutionResult::Status::Success;
                    }

                } catch (const std::exception& e) {
                    // Caught crash or exception
                    result.status = ExecutionResult::Status::Crash;
                    result.crash_info.push_back("Exception: " + std::string(e.what()));
                } catch (...) {
                    // Caught unknown exception
                    result.status = ExecutionResult::Status::Crash;
                    result.crash_info.push_back("Unknown exception");
                }
                
            } else {
                // Fall back to subprocess mode
                std::string input_file;
                try {
                    // Write input to temporary file
                    input_file = writeInputToFile(input);
                    
                    // Create child process to execute target program
                    pid_t pid = fork();
                    
                    if (pid == 0) {
                        // Child process

                        // Set resource limits
                        struct rlimit rlim;
                        
                        // Memory limit
                        rlim.rlim_cur = rlim.rlim_max = memory_limit_mb_ * 1024 * 1024;
                        setrlimit(RLIMIT_AS, &rlim);
                        
                        // CPU time limit
                        rlim.rlim_cur = rlim.rlim_max = timeout.count() / 1000 + 1; // seconds
                        setrlimit(RLIMIT_CPU, &rlim);
                        
                        // Redirect stdout/stderr to /dev/null
                        int dev_null = open("/dev/null", O_WRONLY);
                        if (dev_null != -1) {
                            dup2(dev_null, STDOUT_FILENO);
                            dup2(dev_null, STDERR_FILENO);
                            close(dev_null);
                        }
                        
                        // Execute target program
                        execl(target_binary_.c_str(), target_binary_.c_str(), input_file.c_str(), nullptr);
                        
                        // If execl failed
                        exit(127);
                    } else if (pid > 0) {
                        // Parent process
                        int status;
                        
                        // Wait for child process to finish or timeout
                        auto timeout_time = start_time + timeout;
                        int wait_result = 0;
                        
                        while (std::chrono::high_resolution_clock::now() < timeout_time) {
                            wait_result = waitpid(pid, &status, WNOHANG);
                            if (wait_result != 0) break; // child process finished
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                        
                        // If timed out, kill child process
                        if (wait_result == 0) {
                            kill(pid, SIGKILL);
                            waitpid(pid, &status, 0);
                            result.status = ExecutionResult::Status::Timeout;
                        } else {
                            // Process execution result
                            if (WIFEXITED(status)) {
                                int exit_code = WEXITSTATUS(status);
                                result.exit_code = exit_code;
                                // Fix: use same logic for return value judgment
                                if (exit_code == 0 || (exit_code >= 100 && exit_code <= 110)) {
                                    result.status = ExecutionResult::Status::Success;
                                } else if (exit_code < 0 || exit_code > 200) {
                                    result.status = ExecutionResult::Status::Error;
                                } else {
                                    result.status = ExecutionResult::Status::Success;
                                }
                            } else if (WIFSIGNALED(status)) {
                                int signal = WTERMSIG(status);
                                result.status = ExecutionResult::Status::Crash;
                                result.crash_info.push_back("Signal: " + std::to_string(signal));
                                
                                // Record signal type
                                switch (signal) {
                                    case SIGSEGV:
                                        result.crash_info.push_back("SIGSEGV");
                                        break;
                                    case SIGABRT:
                                        result.crash_info.push_back("SIGABRT");
                                        break;
                                    case SIGFPE:
                                        result.crash_info.push_back("SIGFPE");
                                        break;
                                    default:
                                        result.crash_info.push_back("Signal " + std::to_string(signal));
                                }
                                
                                // Save crash input for external process execution mode
                                try {
                                    std::filesystem::create_directories("output/crashes");
                                    
                                    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count();
                                    
                                    std::string crash_filename = "output/crashes/crash_fork_signal_" + 
                                                               std::to_string(signal) + "_" +
                                                               std::to_string(timestamp) + ".bin";
                                    
                                    std::ofstream crash_file(crash_filename, std::ios::binary);
                                    if (crash_file.is_open()) {
                                        crash_file.write(reinterpret_cast<const char*>(input.data()), 
                                                       input.size());
                                        crash_file.close();
                                        
                                        // Save crash information
                                        std::string info_filename = "output/crashes/crash_fork_signal_" + 
                                                                  std::to_string(signal) + "_" +
                                                                  std::to_string(timestamp) + "_info.txt";
                                        std::ofstream info_file(info_filename);
                                        if (info_file.is_open()) {
                                            info_file << "=== Fork Process Crash Report ===" << std::endl;
                                            info_file << "Signal: " << signal << " (";
                                            switch(signal) {
                                                case SIGSEGV: info_file << "SIGSEGV - Segmentation fault"; break;
                                                case SIGABRT: info_file << "SIGABRT - Abort"; break;
                                                case SIGFPE: info_file << "SIGFPE - Floating point exception"; break;
                                                default: info_file << "Unknown signal"; break;
                                            }
                                            info_file << ")" << std::endl;
                                            info_file << "Input Size: " << input.size() << " bytes" << std::endl;
                                            info_file << "Timestamp: " << timestamp << std::endl;
                                            info_file << "Process Status: Terminated by signal" << std::endl;
                                            info_file.close();
                                        }
                                    }
                                } catch (const std::exception& e) {
                                    // Log error but do not affect main flow
                                    std::cerr << "[WARNING] Failed to save fork crash: " << e.what() << std::endl;
                                }
                            }
                        }
                        
                        // Give target program a moment to write coverage data
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        
                    } else {
                        // fork failed
                        result.status = ExecutionResult::Status::Error;
                        result.error_message = "Fork failed";
                    }
                    
                } catch (const std::exception& e) {
                    result.status = ExecutionResult::Status::Error;
                    result.error_message = e.what();
                }
                
                // Clean up temporary file
                if (!input_file.empty()) {
                    try {
                        cleanupFile(input_file);
                    } catch (...) {
                        // Ignore cleanup errors
                    }
                }
            }
            
            auto end_time = std::chrono::high_resolution_clock::now();
            // Use microsecond precision to avoid sub-1ms executions being recorded as 0
            auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

            // Fill performance info (convert to milliseconds, preserve decimal precision)
            result.performance.execution_time_ms = duration_us.count() / 1000.0;
            result.performance.memory_usage_bytes = input.size() * 10; // simplified estimate

            // [PERF-FIX] Completely removed coverage collection from hot path!
            //
            // Performance bottleneck analysis:
            // - getCurrentCoverage() has two coverage_mutex locks (global serialization point)
            // - Even with lazy strategy, threads still contend on this lock
            // - 16 threads: 2ms execution, 32 threads: 12ms execution (6x slowdown)
            //
            // libFuzzer approach:
            // 1. During execution, ignore coverage entirely, just run target
            // 2. Coverage judgment handled by corpus dedup logic when adding
            // 3. No getCurrentCoverage() calls on hot path
            //
            // Our fix:
            // - Do not collect coverage when executeInput returns
            // - Defer coverage judgment to corpus saving (already protected by global_coverage_mutex)
            // - This allows execution to run fully lock-free in parallel
            result.coverage = CoverageInfo{};  // empty object, extremely fast

            // [PERF-FIX] Avoid unnecessary vector copies
            // Do not set output and input_data, only set when needed
            // result.output = input; // removed - large vector copy
            // result.input_data = input; // removed - large vector copy
            
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Execute fatal error: " << e.what() << std::endl;
            result.status = ExecutionResult::Status::Error;
            result.error_message = "Fatal execution error: " + std::string(e.what());
        } catch (...) {
            std::cerr << "[ERROR] Execute unknown fatal error" << std::endl;
            result.status = ExecutionResult::Status::Error;
            result.error_message = "Unknown fatal execution error";
        }
        
        return result;
    }

public:
    void setEnvironment(const std::map<std::string, std::string>& env) override {
        environment_ = env;
    }
    
    void setMemoryLimit(size_t limit_mb) override {
        memory_limit_mb_ = limit_mb;
    }
    
void setTimeLimit(std::chrono::milliseconds limit) override {
        time_limit_ = limit;
    }
};

std::once_flag SimpleExecutor::signal_once_flag_;
std::array<struct sigaction, 3> SimpleExecutor::previous_handlers_{};
std::array<int, 3> SimpleExecutor::handled_signals_{{SIGSEGV, SIGABRT, SIGFPE}};
volatile sig_atomic_t SimpleExecutor::crash_counter_ = 0;

void SimpleExecutor::installSignalHandlers() {
    std::call_once(signal_once_flag_, []() {
        for (size_t i = 0; i < handled_signals_.size(); ++i) {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = &SimpleExecutor::signalHandler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;
            if (sigaction(handled_signals_[i], &sa, &previous_handlers_[i]) != 0) {
                // If installation fails we continue with the previous handler
            }
        }
    });
}

void SimpleExecutor::signalHandler(int sig) {
    constexpr const char* crash_dir = "output/crashes";
    ::mkdir(crash_dir, 0755);

    sig_atomic_t local_id = ++crash_counter_;

    char crash_path[256];
    std::snprintf(crash_path, sizeof(crash_path),
                  "%s/crash_signal_%d_%d.bin",
                  crash_dir, sig, static_cast<int>(local_id));

    FILE* crash_file = std::fopen(crash_path, "wb");
    if (crash_file) {
        if (!g_current_fuzzing_input.empty()) {
            std::fwrite(g_current_fuzzing_input.data(), 1, g_current_fuzzing_input.size(), crash_file);
        }
        std::fclose(crash_file);
    }

    char info_path[256];
    std::snprintf(info_path, sizeof(info_path),
                  "%s/crash_signal_%d_%d_info.txt",
                  crash_dir, sig, static_cast<int>(local_id));
    FILE* info_file = std::fopen(info_path, "w");
    if (info_file) {
        std::fprintf(info_file, "Signal: %d\n", sig);
        std::fprintf(info_file, "Input Size: %zu bytes\n", g_current_fuzzing_input.size());
        std::fclose(info_file);
    }

    _exit(1);
}

// Fuzzing engine implementation
FuzzingEngine::FuzzingEngine(const FuzzingConfig& config) : config_(config) {
    std::cout << "[FuzzingEngine] Initializing with ";
    if (config_.strict_algorithm_isolation) {
        std::cout << "STRICT ALGORITHM ISOLATION mode" << std::endl;
    } else {
        std::cout << "standard mode" << std::endl;
    }
    
    // Initialize core components (always needed)
    // Each FuzzingEngine instance owns an independent Registry and Coverage to avoid cross-instance pollution
    algorithm_registry_ = std::make_unique<AlgorithmRegistry>();
    algorithm_combiner_ = std::make_unique<AlgorithmCombiner>();
    config_manager_ = std::make_unique<ConfigManager>();
    corpus_manager_ = std::make_unique<CorpusManager>();
    global_context_ = std::make_unique<SharedContext>();
    afl_coverage_ = std::make_unique<AFLCompatibleCoverage>();  // independent AFL coverage instance

    std::cout << "[FuzzingEngine] Created independent AlgorithmRegistry and AFLCoverage instances" << std::endl;

    // Initialize performance optimization components (non-strict mode only)
    if (!config_.strict_algorithm_isolation) {
        algorithm_pool_ = std::make_unique<AlgorithmPool>();

        // Configure BatchExecutor with correct thread count
        BatchExecutor::BatchConfig batch_config;
        batch_config.worker_threads = config_.thread_count > 0 ? config_.thread_count : std::thread::hardware_concurrency();
        batch_executor_ = std::make_unique<BatchExecutor>(batch_config);

        lockfree_coverage_collector_ = std::make_unique<LockFreeCoverageCollector>();
        std::cout << "[OPTIMIZATION] Performance optimization components initialized with "
                  << batch_config.worker_threads << " worker threads" << std::endl;
    }
    
    // In strict mode, initialize the minimal set of components
    if (config_.strict_algorithm_isolation) {
        std::cout << "[STRICT MODE] Minimal component initialization" << std::endl;
        
        // Choose coverage collector type based on disable_system_algorithms
        if (config_.disable_system_algorithms) {
            std::cout << "[STRICT MODE] Using minimal coverage collector (LibFuzzer-like)" << std::endl;
            // TODO: Initialize a minimal coverage collector here (if needed)
            coverage_collector_ = std::make_unique<CoverageCollector>();
            
            // Disable all enhancements
            std::cout << "[STRICT MODE] All CollaFuzz enhancements disabled for fair comparison" << std::endl;
            
        } else {
            // Use the full coverage collector
            coverage_collector_ = std::make_unique<CoverageCollector>();
        }
        
        // Only initialize performance monitoring and crash analysis when necessary
        if (!config_.disable_system_algorithms) {
            performance_monitor_ = std::make_unique<PerformanceMonitor>();
            // crash_analyzer_ = std::make_unique<CrashAnalyzer>(); // archived
        } else {
            std::cout << "[STRICT MODE] System algorithms disabled" << std::endl;
        }
        
        // In strict mode, do not use dynamic combinations
        std::cout << "[STRICT MODE] Dynamic combination disabled, using only fixed combinations" << std::endl;
    } else {
        std::cout << "[Standard Mode] Full component initialization" << std::endl;
        
        // Standard mode: initialize all components
        performance_monitor_ = std::make_unique<PerformanceMonitor>();
        coverage_collector_ = std::make_unique<CoverageCollector>();
        // crash_analyzer_ = std::make_unique<CrashAnalyzer>(); // archived
        
        // Create BatchAlgorithmSelector only when dynamic combination is enabled
        if (config_.enable_dynamic_combination) {
            batch_selector_ = std::make_unique<BatchAlgorithmSelector>(config, global_context_,
                                                               *algorithm_registry_,
                                                               beta_distributions_, combination_history_,
                                                               thompson_sampling_mutex_,
                                                               algorithm_usage_stats_, last_combo_usage_,
                                                               total_algorithm_uses_, diversity_stats_mutex_,
                                                               [this]() { return this->detectStructuredInputTarget(); });
            std::cout << "[FuzzingEngine] BatchAlgorithmSelector initialized for dynamic combination" << std::endl;
        } else {
            std::cout << "[FuzzingEngine] Dynamic combination disabled, using fixed combinations" << std::endl;
        }
    }
    
    // Initialize default executor
    default_executor_ = std::make_shared<SimpleExecutor>(config_.target_binary);
    std::cout << "[FuzzingEngine] Default executor initialized" << std::endl;

    // Initialize CheckpointManager (if crash recovery is enabled)
    if (config_.enable_crash_recovery) {
        CheckpointManager::Config ckpt_config;
        ckpt_config.enabled = true;
        ckpt_config.checkpoint_dir = config_.checkpoint_dir;
        ckpt_config.checkpoint_interval = std::chrono::seconds(config_.checkpoint_interval_sec);
        ckpt_config.atomic_write = true;

        checkpoint_manager_ = std::make_unique<CheckpointManager>(ckpt_config);
        last_checkpoint_time_ = std::chrono::steady_clock::now();

        std::cout << "[FuzzingEngine] Crash recovery enabled with checkpoint interval: "
                  << config_.checkpoint_interval_sec << " seconds" << std::endl;

        // Restore from checkpoint if requested
        if (config_.restore_from_checkpoint) {
            if (loadCheckpoint()) {
                std::cout << "[FuzzingEngine] Successfully restored from checkpoint" << std::endl;
            } else {
                std::cout << "[FuzzingEngine] No checkpoint to restore, starting fresh" << std::endl;
            }
        }
    }
}

FuzzingEngine::~FuzzingEngine() {
    // Wrap everything in try-catch to prevent exceptions from escaping destructor
    try {
        // Set force_stop flag first
        force_stop_.store(true);
        running_.store(false);
        stats_running_.store(false);

        // Detach stats thread if joinable
        if (stats_thread_.joinable()) {
            stats_thread_.detach();
        }

        // Detach all worker threads
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.detach();
            }
        }

        // Clear thread vectors
        worker_threads_.clear();

        // Try to cleanup thread-local data (may fail if threads are still running)
        try {
            cleanupThreadLocalData();
        } catch (...) {
            // Ignore cleanup errors
        }

        // Try to shutdown components (may fail)
        try {
            shutdown();
        } catch (...) {
            // Ignore shutdown errors
        }

        // Component cleanup in proper order to avoid circular dependencies
        // Use try-catch for each reset in case they throw
        try { batch_selector_.reset(); } catch (...) {}
        try { global_context_.reset(); } catch (...) {}
        // try { crash_analyzer_.reset(); } catch (...) {} // archived
        try { coverage_collector_.reset(); } catch (...) {}
        try { corpus_manager_.reset(); } catch (...) {}
        try { config_manager_.reset(); } catch (...) {}
        try { performance_monitor_.reset(); } catch (...) {}
        try { algorithm_combiner_.reset(); } catch (...) {}
        try { algorithm_registry_.reset(); } catch (...) {}

        std::cout << "[FuzzingEngine] Destructor completed" << std::endl;
    } catch (const std::exception& e) {
        // Log but don't rethrow
        std::cerr << "[FuzzingEngine] Exception in destructor: " << e.what() << std::endl;
    } catch (...) {
        // Catch all other exceptions
        std::cerr << "[FuzzingEngine] Unknown exception in destructor" << std::endl;
    }
}

void FuzzingEngine::initialize() {
    std::cout << "Initializing Fuzzing Engine..." << std::endl;
    
    // Register default algorithms
    registerDefaultAlgorithms();

    // Initialize performance optimization components (non-strict mode only)
    if (!config_.strict_algorithm_isolation) {
        // Initialize algorithm pool: prewarm hot algorithms (via AlgorithmConfig)
        if (algorithm_pool_) {
            std::vector<std::string> hot_algorithms = AlgoConfig::ENABLED_MUTATIONS;
            algorithm_pool_->prewarm(hot_algorithms);
            std::cout << "[OPTIMIZATION] Algorithm pool prewarmed with " << hot_algorithms.size() << " algorithms" << std::endl;
        }

        // Configure batch executor
        if (batch_executor_) {
            // Set executor callback
            batch_executor_->setTargetExecutor([this](const std::vector<uint8_t>& input) {
                BatchExecutor::ExecutionResult result;
                auto exec_result = executeInput(input);
                result.input_data = input;
                result.coverage = exec_result.coverage;
                result.performance = exec_result.performance;
                result.status = (exec_result.status == ExecutionResult::Status::Crash) ?
                              BatchExecutor::ExecutionStatus::CRASHED : BatchExecutor::ExecutionStatus::SUCCESS;
                return result;
            });
            std::cout << "[OPTIMIZATION] Batch executor configured with batch size: "
                      << BatchExecutor::DEFAULT_BATCH_SIZE << std::endl;
        }

        // Use lock-free coverage collector
        if (lockfree_coverage_collector_) {
            std::cout << "[OPTIMIZATION] Lock-free coverage collector enabled" << std::endl;
        }
    }

    // Configure CorpusManager with the correct output dirs and AFL++-style optimizations
    if (corpus_manager_) {
        CorpusManager::Config corpus_config;
        corpus_config.max_corpus_size = 10000;
        corpus_config.corpus_dir = config_.output_dir + "/corpus";
        corpus_config.crash_dir = config_.output_dir + "/crashes";
        corpus_config.enable_minimization = true;
        corpus_config.enable_prioritization = true;
        corpus_config.energy_update_rate = 0.1;
        
        // Configure corpus optimization based on strict mode
        if (config_.strict_algorithm_isolation) {
            // Strict mode: disable all corpus optimizations to keep ablation experiments clean
            corpus_config.enable_auto_optimization = false;
            corpus_config.enable_coverage_based_optimization = false;
            corpus_config.enable_aggressive_cleanup = false;
            corpus_config.optimization_interval_seconds = 0;
            corpus_config.corpus_bloat_threshold = 1.0; // no cleanup
            corpus_config.performance_degradation_threshold = 1.0; // no cleanup
            corpus_config.max_daily_corpus_growth = std::numeric_limits<size_t>::max(); // unlimited
            
            // Further disable optimizations to emulate native libFuzzer
            if (config_.disable_system_algorithms) {
                corpus_config.enable_minimization = false;  // Disable seed minimization
                corpus_config.enable_prioritization = false; // Disable prioritization
                corpus_config.energy_update_rate = 0.0;     // Disable energy updates
                std::cout << "[STRICT MODE] All corpus enhancements disabled (LibFuzzer-like mode)" << std::endl;
            } else {
                std::cout << "[STRICT MODE] Basic corpus optimizations disabled for fair comparison" << std::endl;
            }
        } else {
            // Standard mode: enable AFL++-style corpus optimization (configured via flags)
            corpus_config.enable_auto_optimization = config_.corpus_optimization_enabled;
            corpus_config.optimization_interval_seconds = config_.corpus_optimization_interval;
            corpus_config.corpus_bloat_threshold = config_.corpus_bloat_threshold;
            corpus_config.min_corpus_size = config_.min_corpus_size;
            corpus_config.target_corpus_size = config_.target_corpus_size;
            corpus_config.enable_coverage_based_optimization = true;
            corpus_config.performance_degradation_threshold = 0.3;
            corpus_config.enable_aggressive_cleanup = config_.enable_aggressive_cleanup;
            corpus_config.max_daily_corpus_growth = 2000;
        }
        
        corpus_manager_->updateConfig(corpus_config);
        std::cout << "[FuzzingEngine] CorpusManager configured with output dir: " << config_.output_dir << std::endl;
        
        if (config_.corpus_optimization_enabled) {
            std::cout << "[FuzzingEngine] AFL++ style corpus optimization enabled:" << std::endl;
            std::cout << "  - Optimization interval: " << config_.corpus_optimization_interval << " seconds" << std::endl;
            std::cout << "  - Target corpus size: " << config_.target_corpus_size << std::endl;
            std::cout << "  - Min corpus size: " << config_.min_corpus_size << std::endl;
            std::cout << "  - Bloat threshold: " << config_.corpus_bloat_threshold * 100 << "%" << std::endl;
            std::cout << "  - Aggressive cleanup: " << (config_.enable_aggressive_cleanup ? "Yes" : "No") << std::endl;
        } else {
            std::cout << "[FuzzingEngine] AFL++ style corpus optimization disabled" << std::endl;
        }
        
        // **NEW**: Auto-load existing corpus to restore coverage
        std::string corpus_dir = config_.output_dir + "/corpus";
        if (std::filesystem::exists(corpus_dir)) {
            try {
                size_t file_count = 0;
                for (const auto& entry : std::filesystem::directory_iterator(corpus_dir)) {
                    if (entry.is_regular_file()) {
                        file_count++;
                    }
                }
                
                if (file_count > 0) {
                    std::cout << "[FuzzingEngine] Found existing corpus with " << file_count << " files, loading..." << std::endl;
                    corpus_manager_->loadCorpus(corpus_dir);
                    std::cout << "[FuzzingEngine] Successfully loaded " << corpus_manager_->getCurrentCorpusSize() 
                             << " test cases from previous corpus" << std::endl;
                } else {
                    std::cout << "[FuzzingEngine] No existing corpus found, starting fresh" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "[WARNING] Failed to load existing corpus: " << e.what() << std::endl;
                std::cerr << "[WARNING] Continuing with fresh start..." << std::endl;
            }
        } else {
            std::cout << "[FuzzingEngine] No existing corpus directory found, starting fresh" << std::endl;
        }
    }
    
    // Initialize smart seeds for complex test programs
    initializeSmartSeeds();

    // Removed: anti-convergence combination strategy setup

    // Initialize optimized Thompson Sampling (preserves dynamic algorithm combination)
    if (config_.enable_dynamic_combination && use_optimized_thompson_) {
        optimized_thompson_ = std::make_unique<OptimizedThompsonSampling>();

        // Tuning: significantly increase exploration rate
        optimized_thompson_->setExplorationProbability(0.50);  // 50% exploration (was 20%)
        optimized_thompson_->setStatsSyncFrequency(10000);     // Sync every 10,000 iterations
        optimized_thompson_->enableFastPath(false);            // Disable fast path; force Thompson Sampling

        // Generate candidate full pipeline combinations (scheduler, mutation, feedback)
        std::vector<AlgorithmCombination> candidates = generateCandidateCombinations();
        optimized_thompson_->setCandidateCombinations(candidates);

        std::cout << "[FuzzingEngine] ===== Optimized Thompson Sampling Enabled =====" << std::endl;
        std::cout << "[FuzzingEngine] Preserving core capability: Algorithm Dynamic Combination" << std::endl;
        std::cout << "[FuzzingEngine]   - Fast Path: DISABLED (100% Thompson Sampling)" << std::endl;
        std::cout << "[FuzzingEngine]   - Exploration: 50% pure exploration + 50% Thompson Sampling" << std::endl;
        std::cout << "[FuzzingEngine]   - MIN_TRIALS: 500 (forced exploration for all algorithms)" << std::endl;
        std::cout << "[FuzzingEngine]   - UCB Bonus: Enabled (bonus for under-explored algorithms)" << std::endl;
        std::cout << "[FuzzingEngine] This breakthrough coverage bottleneck via algorithm combination!" << std::endl;
        std::cout << "[FuzzingEngine] ================================================" << std::endl;
    }

    // added: Initialize tiered algorithm scheduler
    if (use_tiered_scheduler_) {
        tiered_scheduler_ = std::make_unique<TieredAlgorithmScheduler>();

        // Register all enabled algorithms and their performance profiles
        // Tier 1: Ultra Fast
        tiered_scheduler_->registerAlgorithm(TieredProfiles::BITFLIP);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::MAGIC_BYTE);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::VALUE_APPROXIMATION);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::ARITHMETIC);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::LENGTH_EXTENSION);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::BYTE_WEIGHTED_HAVOC);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::TOKEN);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::ENDIANNESS_SWAP);
        // Tier 2: Fast
        tiered_scheduler_->registerAlgorithm(TieredProfiles::HAVOC);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::SPLICE);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::TRIM);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::BLOCK);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::CHUNK_BASED);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::CMPLOG);
        tiered_scheduler_->registerAlgorithm(TieredProfiles::REDQUEEN);  // Moved to Tier 2
        tiered_scheduler_->registerAlgorithm(TieredProfiles::FORMAT_AWARE);  // Protect structured formats
        // Tier 3: Medium
        tiered_scheduler_->registerAlgorithm(TieredProfiles::SMART_DICTIONARY);
        // Archived: CLASSIC_LIBFUZZER, AFL_PLUS_PLUS

        // Set target execution time
        tiered_scheduler_->setTargetExecutionTime(0.8);  // Target: avg 0.8ms/exec

        std::cout << "[FuzzingEngine] ===== Tiered Algorithm Scheduler Enabled =====" << std::endl;
        std::cout << "[FuzzingEngine] Tier 1 (Ultra Fast <0.5ms): 73% probability" << std::endl;
        std::cout << "[FuzzingEngine]   - bitflip, magic_byte, value_approximation, arithmetic, length_extension, byte_weighted_havoc, token, endianness_swap, nibble_swap, bit_rotate, varint" << std::endl;
        std::cout << "[FuzzingEngine] Tier 2 (Fast 0.5-1.0ms): 25% probability" << std::endl;
        std::cout << "[FuzzingEngine]   - havoc, splice, trim, block, chunk_based, cmplog, redqueen, format_aware, run_length, checksum_fixup" << std::endl;
        std::cout << "[FuzzingEngine] Tier 3 (Medium 1.0-2.0ms): 2% probability" << std::endl;
        std::cout << "[FuzzingEngine]   - smart_dictionary" << std::endl;
        std::cout << "[FuzzingEngine] Archived: classic_libfuzzer, afl_plus_plus" << std::endl;
        std::cout << "[FuzzingEngine] Target Avg Time: 0.8ms | Auto-Adaptive: Enabled" << std::endl;
        std::cout << "[FuzzingEngine] ================================================" << std::endl;
    }

    // Create output directories
    std::filesystem::create_directories(config_.output_dir);
    std::filesystem::create_directories(config_.output_dir + "/corpus");
    std::filesystem::create_directories(config_.output_dir + "/crashes");
    
    // Start performance monitoring
    if (config_.enable_performance_monitoring && performance_monitor_) {
        performance_monitor_->startMonitoring();
    }
    
    // Initialize stats
    stats_.start_time = std::chrono::system_clock::now();
    
    // Start AFL++-style automatic corpus optimization (non-strict mode, if enabled)
    if (corpus_manager_ && !config_.strict_algorithm_isolation &&
        config_.corpus_optimization_enabled) {
        corpus_manager_->startAutoOptimization();
        std::cout << "[FuzzingEngine] AFL++ corpus auto-optimization started" << std::endl;
    } else if (config_.strict_algorithm_isolation) {
        std::cout << "[STRICT MODE] AFL++ corpus auto-optimization disabled" << std::endl;
    } else {
        std::cout << "[FuzzingEngine] AFL++ corpus auto-optimization disabled" << std::endl;
    }
    
    // Validate strict-mode algorithm isolation
    if (config_.strict_algorithm_isolation) {
        bool validation_passed = validateStrictAlgorithmIsolation();
        if (!validation_passed) {
            std::cerr << "[ERROR] Strict algorithm isolation validation failed!" << std::endl;
            std::cerr << "[ERROR] This may compromise the fairness of ablation experiments" << std::endl;
        }

        // Log algorithm usage for debugging
        logAlgorithmUsage();
    }

    // Initialize specialized-thread engine (if enabled)
    std::cout << "[DEBUG] config_.use_specialized_threads = " << config_.use_specialized_threads << std::endl;
    if (config_.use_specialized_threads) {
        std::cout << "[FuzzingEngine] ===== INITIALIZING SPECIALIZED THREAD ENGINE =====" << std::endl;
        use_specialized_threads_ = true;

        // Create execution callback - wraps the full mutate + execute + save pipeline
        auto execution_callback = [this](const std::vector<uint8_t>& seed, const AlgorithmCombination& combination) -> ExecutionResult {
            // ===== [PERF] Fine-grained performance breakdown (optional) =====
            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            thread_local struct {
                size_t count = 0;
                uint64_t context_creation_us = 0;
                uint64_t mutation_us = 0;
                uint64_t execution_us = 0;
                uint64_t coverage_check_us = 0;
                uint64_t corpus_save_us = 0;
                uint64_t total_overhead_us = 0;
                std::chrono::steady_clock::time_point last_print = std::chrono::steady_clock::now();
            } detailed_stats;

            auto callback_start = std::chrono::high_resolution_clock::now();
            #endif

            // Create thread-local context
            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            auto t_context_start = std::chrono::high_resolution_clock::now();
            #endif
	            thread_local ThreadLocalContext local_context(global_context_.get());
	            // Initialize Hint Bus for this execution and record lineage
	            {
	                HintBus hb;
	                hb.lineage = combination.algorithm_names;
	                // Generic lightweight "repair": for binary-ish seeds, protect a small prefix
	                // (usually magic bytes / fixed headers) to keep the decoder progressing.
	                if (!looks_text(seed) && !seed.empty()) {
	                    const size_t protect_len = std::min<size_t>(
	                        std::max<uint32_t>(1, getenv_u32("TRIOFUZZ_PROTECT_PREFIX_LEN", 8)),
	                        seed.size());
	                    hb.protected_mask.assign(protect_len, 1);
	                }
	                local_context.setHintBus(hb);
	            }
            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            auto t_context_end = std::chrono::high_resolution_clock::now();
            detailed_stats.context_creation_us += std::chrono::duration_cast<std::chrono::microseconds>(t_context_end - t_context_start).count();
            #endif

            // 0. Micro deterministic warmup stage (once per seed, strict budget)
            // [PERF] Disabled by default because it causes ~4x slowdown
            // Set TRIOFUZZ_ENABLE_WARMUP=1 to enable
            static const bool enable_warmup = (std::getenv("TRIOFUZZ_ENABLE_WARMUP") != nullptr);
            if (enable_warmup) {
                auto computeSeedSig = [](const std::vector<uint8_t>& s) -> uint64_t {
                    uint64_t h = static_cast<uint64_t>(s.size()) * 0x9e3779b97f4a7c15ULL;
                    if (!s.empty()) {
                        h ^= s[0];
                        h ^= (static_cast<uint64_t>(s[s.size() - 1]) << 8);
                        if (s.size() > 2) {
                            h ^= (static_cast<uint64_t>(s[1]) << 16);
                            h ^= (static_cast<uint64_t>(s[s.size() - 2]) << 24);
                        }
                    }
                    return h;
                };

                static thread_local std::unordered_set<uint64_t> warmed_up_seeds;
                static thread_local size_t warm_set_guard = 0;

                uint64_t sig = computeSeedSig(seed);
                if (warmed_up_seeds.find(sig) == warmed_up_seeds.end()) {
                    if (warm_set_guard++ > 4096) { warmed_up_seeds.clear(); warm_set_guard = 0; }
                    warmed_up_seeds.insert(sig);

                    // At most three tiny candidates
                    std::array<std::vector<uint8_t>, 3> candidates;
                    for (auto& c : candidates) c = seed;

                    if (!candidates[0].empty()) {
                        candidates[0][0] ^= 0x01;
                    }
                    if (!candidates[1].empty()) {
                        static const uint8_t interesting[] = {0x00, 0xFF, 0x7F, 0x80};
                        static thread_local std::mt19937 gen(std::random_device{}());
                        std::uniform_int_distribution<int> d(0, 3);
                        candidates[1][0] = interesting[d(gen)];
                    }
                    if (candidates[2].size() >= 2) {
                        uint16_t v = static_cast<uint16_t>(candidates[2][0] | (candidates[2][1] << 8));
                        v = static_cast<uint16_t>(v + 1);
                        candidates[2][0] = static_cast<uint8_t>(v & 0xFF);
                        candidates[2][1] = static_cast<uint8_t>((v >> 8) & 0xFF);
                    }

                    // triofuzz-Mini: Use AFLCompatibleCoverage for fair comparison with AFL++
                    auto& afl_cov_warm = triofuzz::AFLCompatibleCoverage::getInstance();
                    auto maybeSaveSeed = [&](const std::vector<uint8_t>& data, ExecutionResult& r) {
                        // Never promote crashing inputs to the corpus — they are already
                        // persisted under findings/crashes/ by the signal handler, and
                        // re-fuzzing them just produces the same crash again.
                        if (r.status == ExecutionResult::Status::Crash) return;
                        if (!afl_cov_warm.hasNewCoverage()) return;
                        // Use bitmap hash for deduplication
                        auto bitmap = afl_cov_warm.getCurrentBitmap();
                        uint64_t coverage_hash = hash_coverage_bitmap(bitmap);
                        constexpr size_t NUM_SHARDS = 16;
                        static std::array<std::mutex, NUM_SHARDS> coverage_mutexes_warm;
                        static std::array<std::unordered_set<uint64_t>, NUM_SHARDS> seen_hashes_warm;
                        size_t shard_idx = coverage_hash % NUM_SHARDS;
                        bool is_new = false;
                        {
                            std::lock_guard<std::mutex> lock(coverage_mutexes_warm[shard_idx]);
                            is_new = seen_hashes_warm[shard_idx].insert(coverage_hash).second;
                        }
                        if (!is_new) return;
                        r.coverage.total_edges = afl_cov_warm.getTotalEdges();
                        r.coverage.new_edges.push_back(coverage_hash);
                        if (corpus_manager_) {
                            Seed ns; ns.data = data; ns.coverage = CoverageInfo{}; ns.coverage.total_edges = r.coverage.total_edges;
                            ns.coverage.new_edges.push_back(coverage_hash);  // Set new_edges so it can be persisted to disk
                            ns.created_time = std::chrono::system_clock::now(); ns.generation = 1; ns.energy = 1.3;
                            corpus_manager_->addSeed(std::move(ns));
                            stats_.new_coverage_found.fetch_add(1, std::memory_order_relaxed);
                        }
                    };

                    for (size_t i = 0; i < candidates.size(); ++i) {
                        if (candidates[i].empty()) continue;
                        ExecutionResult wr = executeInput(candidates[i]);
                        maybeSaveSeed(candidates[i], wr);
                    }
                }
            }

            // 1. Apply the algorithm combination to mutate
            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            auto t0 = std::chrono::high_resolution_clock::now();
            #endif
            std::vector<uint8_t> mutated_input = applyAlgorithmCombination(seed, combination, local_context);
            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            auto t1 = std::chrono::high_resolution_clock::now();
            detailed_stats.mutation_us += std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            #endif

	            // 2. Execute the mutated input
	            // CmpLog sampling: enable trace-cmp recording only for a subset of executions to
	            // bound overhead, but collect aggressively for analysis-style combinations.
	            thread_local uint64_t tls_exec_counter = 0;
	            tls_exec_counter++;
	            const uint32_t sample_rate = std::max<uint32_t>(1, getenv_u32("TRIOFUZZ_CMPLOG_SAMPLE_RATE", 8));
	            bool is_analysis_combo = false;
	            for (const auto& op : combination.algorithm_names) {
	                const bool is_aflpp_op =
	                    (op.rfind("mut_", 0) == 0) || (op.rfind("mopt_", 0) == 0);
	                if (!is_aflpp_op) { is_analysis_combo = true; break; }
	            }
	            const bool collect_cmplog =
	                is_analysis_combo ||
	                (auto_dictionary_epoch_.load(std::memory_order_relaxed) < 8) ||
	                (sample_rate == 1) ||
	                ((tls_exec_counter % sample_rate) == 0);
	            cmplog::setEnabled(collect_cmplog);
	            cmplog::setFullEnabled(collect_cmplog && is_analysis_combo);

	            ExecutionResult result = executeInput(mutated_input);
	            if (collect_cmplog) {
	                publishCmpLogFromLastExecution();
	            }
	            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
	            auto t2 = std::chrono::high_resolution_clock::now();
	            detailed_stats.execution_us += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
	            #endif

            // 3. [PERF-FIX] Fast lock-free coverage check using inline 8-bit counters
            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            auto t_cov_start = std::chrono::high_resolution_clock::now();
            #endif

            // triofuzz-Mini: Use AFLCompatibleCoverage for fair comparison with AFL++
            // Check coverage after every execution (AFL++ style).
            // Crashing inputs are intentionally NOT eligible for corpus admission:
            // they are already saved under findings/crashes/ by the signal handler,
            // and feeding them back into the corpus just makes the same target bug
            // get re-hit on every scheduling pass, wasting cycles.
            auto& afl_cov = triofuzz::AFLCompatibleCoverage::getInstance();
            bool might_have_new_coverage =
                result.status != ExecutionResult::Status::Crash &&
                afl_cov.hasNewCoverage();

                if (might_have_new_coverage) {
                    // New coverage found! Compute bitmap hash for deduplication
                    auto bitmap = afl_cov.getCurrentBitmap();
                    uint64_t coverage_hash = hash_coverage_bitmap(bitmap);

                    // Use sharded locks to reduce contention
                    constexpr size_t NUM_SHARDS = 16;
                    static std::array<std::mutex, NUM_SHARDS> coverage_mutexes;
                    static std::array<std::unordered_set<uint64_t>, NUM_SHARDS> seen_coverage_hashes;

                size_t shard_idx = coverage_hash % NUM_SHARDS;
                bool is_truly_new = false;

                {
                    std::lock_guard<std::mutex> lock(coverage_mutexes[shard_idx]);
                    is_truly_new = seen_coverage_hashes[shard_idx].insert(coverage_hash).second;
                }

                #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
                auto t3 = std::chrono::high_resolution_clock::now();
                detailed_stats.coverage_check_us += std::chrono::duration_cast<std::chrono::microseconds>(t3 - t_cov_start).count();
                #endif

	                // Save seed only if it contributed truly new coverage
	                if (is_truly_new) {
	                    updatePreferredLengthOnNewCoverage(mutated_input.size());
	                    result.coverage.total_edges = afl_cov.getTotalEdges();
	                    result.coverage.new_edges.push_back(coverage_hash);

                    Seed new_seed;
                    new_seed.data = mutated_input;
                    new_seed.coverage = CoverageInfo{};
                    new_seed.coverage.total_edges = afl_cov.getTotalEdges();
                    new_seed.coverage.new_edges.push_back(coverage_hash);  // Set new_edges so it can be persisted to disk
                    new_seed.created_time = std::chrono::system_clock::now();
                    new_seed.generation = 1;
                    new_seed.energy = 1.3;  // Fixed energy bonus for new coverage

                    if (corpus_manager_) {
                        corpus_manager_->addSeed(std::move(new_seed));
                        stats_.new_coverage_found.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
                auto t4 = std::chrono::high_resolution_clock::now();
                detailed_stats.corpus_save_us += std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
                #endif
            } else {
                // Fast path: no new coverage
                #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
                auto t3 = std::chrono::high_resolution_clock::now();
                detailed_stats.coverage_check_us += std::chrono::duration_cast<std::chrono::microseconds>(t3 - t_cov_start).count();
                #endif
            }

            #ifdef ENABLE_DETAILED_PERF_BREAKDOWN
            // Compute total overhead
            auto callback_end = std::chrono::high_resolution_clock::now();
            detailed_stats.total_overhead_us += std::chrono::duration_cast<std::chrono::microseconds>(callback_end - callback_start).count();
            detailed_stats.count++;

            // Print fine-grained stats every 5 seconds
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - detailed_stats.last_print).count() >= 5) {
                double avg_context = detailed_stats.context_creation_us / (double)detailed_stats.count / 1000.0;
                double avg_mutation = detailed_stats.mutation_us / (double)detailed_stats.count / 1000.0;
                double avg_execution = detailed_stats.execution_us / (double)detailed_stats.count / 1000.0;
                double avg_coverage = detailed_stats.coverage_check_us / (double)detailed_stats.count / 1000.0;
                double avg_corpus = detailed_stats.corpus_save_us / (double)detailed_stats.count / 1000.0;
                double avg_total = detailed_stats.total_overhead_us / (double)detailed_stats.count / 1000.0;

                std::cout << "\n[PERF-BREAKDOWN] Thread " << std::this_thread::get_id()
                          << " | Samples: " << detailed_stats.count << std::endl;
                std::cout << "  Context:   " << std::fixed << std::setprecision(3) << avg_context << "ms" << std::endl;
                std::cout << "  Mutation:  " << avg_mutation << "ms" << std::endl;
                std::cout << "  Execution: " << avg_execution << "ms" << std::endl;
                std::cout << "  Coverage:  " << avg_coverage << "ms" << std::endl;
                std::cout << "  Corpus:    " << avg_corpus << "ms" << std::endl;
                std::cout << "  TOTAL:     " << avg_total << "ms" << std::endl;
                std::cout << "  Overhead:  " << (avg_total - avg_mutation - avg_execution) << "ms ("
                          << std::fixed << std::setprecision(1)
                          << (avg_total - avg_mutation - avg_execution) / avg_total * 100.0 << "%)" << std::endl;

                detailed_stats.last_print = now;
            }
            #endif

            // 4. Update stats
            stats_.total_executions.fetch_add(1, std::memory_order_relaxed);

            return result;
        };

        // Create coverage callback: returns current covered edge count
        // triofuzz-Mini: Use AFLCompatibleCoverage for coverage tracking
        auto coverage_callback = []() -> size_t {
            auto& afl_cov = triofuzz::AFLCompatibleCoverage::getInstance();
            return afl_cov.getTotalEdges();  // Return number of unique covered edges
        };

        specialized_engine_ = std::make_unique<SpecializedThreadEngine>(
            config_,
            corpus_manager_.get(),
            nullptr,  // coverage_tracker - not used for now
            nullptr,  // execution_tracer - not used for now
            nullptr,  // executor - not used for now
            execution_callback,
            coverage_callback
        );
        std::cout << "[FuzzingEngine] Specialized thread architecture enabled" << std::endl;
        std::cout << "[FuzzingEngine] =================================================" << std::endl;
    }

    std::cout << "Fuzzing Engine initialized successfully" << std::endl;
}

void FuzzingEngine::start() {
    if (running_.load()) {
        return;
    }

    // If using specialized-thread architecture, use the dedicated start logic
    if (use_specialized_threads_ && specialized_engine_) {
        std::cout << "[FuzzingEngine] Starting with specialized thread architecture..." << std::endl;
        global_start_time_ = std::chrono::steady_clock::now();
        running_ = true;

        // Start stats/checkpoint thread (not started by default in specialized-thread mode)
        stats_running_ = true;
        stats_thread_ = std::thread([this]() {
            auto last_update = std::chrono::steady_clock::now();

            while (stats_running_.load()) {
                // Use short sleep intervals for responsive shutdown
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

                // Check if we should update stats
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - last_update) >= config_.stats_interval) {
                    if (stats_running_.load()) {  // Double-check to avoid a shutdown race
                        updateStats();

                        if (on_stats_update_) {
                            on_stats_update_(stats_);
                        }
                        last_update = now;

                        // Check if we need to save a checkpoint (crash recovery)
                        maybeCheckpoint();
                    }
                }
            }
        });

        specialized_engine_->start();
        return;  // No need to start the traditional worker threads
    }

    std::cout << "Starting Fuzzing Engine with " << config_.thread_count << " threads..." << std::endl;

    running_ = true;
    global_start_time_ = std::chrono::steady_clock::now();

    // Start worker threads
    for (size_t i = 0; i < config_.thread_count; ++i) {
        worker_threads_.emplace_back([this, i]() {
            workerLoop(i);
        });
    }
    
    // Start stats thread (store it as a member instead of detaching)
    stats_running_ = true;
    stats_thread_ = std::thread([this]() {
        auto last_update = std::chrono::steady_clock::now();

        while (stats_running_.load()) {
            // Use short sleep intervals for responsive shutdown
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Check if we should update stats
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_update) >= config_.stats_interval) {
                if (stats_running_.load()) {  // Double-check to avoid a shutdown race
                    updateStats();

                    if (on_stats_update_) {
                        on_stats_update_(stats_);
                    }
                    last_update = now;

                    // Check if we need to save a checkpoint (crash recovery)
                    maybeCheckpoint();
                }
            }
        }
    });
}

void FuzzingEngine::stop() {
    if (!running_.load()) {
        return;
    }

    // If using specialized-thread architecture, use the dedicated stop logic
    if (use_specialized_threads_ && specialized_engine_) {
        std::cout << "[FuzzingEngine] Stopping specialized thread engine..." << std::endl;
        stats_running_ = false;
        if (stats_thread_.joinable()) {
            // Match the standard path and avoid blocking in stop()
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            std::cout << "[INFO] Detaching stats thread" << std::endl;
            stats_thread_.detach();
        }
        specialized_engine_->stop();
        running_ = false;
        return;
    }

    std::cout << "Stopping Fuzzing Engine..." << std::endl;

    // Signal all threads to stop
    running_ = false;

    // Notify any waiting threads
    {
        std::lock_guard<std::mutex> lock(thread_stop_mutex_);
        thread_stop_cv_.notify_all();
    }

    // First stop the stats thread
    std::cout << "[DEBUG] Stopping stats thread..." << std::endl;
    stats_running_ = false;
    if (stats_thread_.joinable()) {
        // Since the stats thread now checks every 100ms, it should stop quickly
        // We'll wait up to 500ms for it to stop
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Now detach it to avoid blocking
        std::cout << "[INFO] Detaching stats thread" << std::endl;
        stats_thread_.detach();
    }
    std::cout << "[DEBUG] Stats thread stopped" << std::endl;


    // Wait for worker threads to finish with timeout (reduced from 5000ms to 1000ms)
    std::cout << "[DEBUG] Waiting for worker threads to stop..." << std::endl;
    if (!waitForThreadsToStop(std::chrono::milliseconds(1000))) {
        std::cout << "[WARNING] Threads did not stop gracefully, forcing termination..." << std::endl;
        forceStopAllThreads();
    }

    // Clean up worker threads
    std::cout << "[DEBUG] Clearing worker threads..." << std::endl;
    worker_threads_.clear();

    // Fix: add an extra wait after clearing worker_threads_
    // Ensure detached threads actually finish and stop touching shared resources
    std::cout << "[DEBUG] Waiting for all threads to fully terminate..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "[DEBUG] All threads terminated" << std::endl;

    // Fix: release optimized_thompson_ early, before cleaning up other components
    // This ensures nothing is still using it
    if (optimized_thompson_) {
        std::cout << "[DEBUG] Releasing OptimizedThompsonSampling..." << std::endl;
        optimized_thompson_.reset();
        std::cout << "[DEBUG] OptimizedThompsonSampling released" << std::endl;
    }

    // Stop other components
    if (corpus_manager_) {
        std::cout << "[DEBUG] Stopping auto optimization..." << std::endl;
        corpus_manager_->stopAutoOptimization();
        std::cout << "[DEBUG] Auto optimization stopped" << std::endl;
    }

    // Save corpus state - skip on forced shutdown
    if (corpus_manager_ && !force_stop_.load()) {
        std::cout << "[DEBUG] Saving corpus..." << std::endl;
        corpus_manager_->saveCorpus();
        std::cout << "[DEBUG] Corpus saved" << std::endl;
    } else if (force_stop_.load()) {
        std::cout << "[DEBUG] Skipping corpus save due to forced stop" << std::endl;
    }

    // added: print optimization stats (with safety checks)
    try {
        printOptimizationStats();
    } catch (const std::exception& e) {
        std::cout << "[WARNING] Failed to print optimization stats: " << e.what() << std::endl;
    }

    // Print final tiered scheduler statistics
    if (use_tiered_scheduler_ && tiered_scheduler_ && tiered_scheduler_->getTotalExecutions() > 0) {
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << tiered_scheduler_->getStatisticsReport() << std::endl;
        std::cout << std::string(80, '=') << "\n" << std::endl;
    }

    std::cout << "Fuzzing Engine stopped successfully" << std::endl;
}

void FuzzingEngine::shutdown() {
    std::cout << "Shutting down Fuzzing Engine..." << std::endl;

    // Stop performance monitoring
    if (performance_monitor_) {
        performance_monitor_->stopMonitoring();
    }

    // Generate final report
    if (performance_monitor_) {
        auto report = performance_monitor_->generateReport();
        // Save report
    }
}

void FuzzingEngine::registerAlgorithm(const std::string& name, AlgorithmFactory factory) {
    // TODO: More complex registration logic is needed here (register by algorithm type)
    std::cout << "Registering algorithm: " << name << std::endl;
    
    // Simple implementation: store the factory in the algorithm registry
    if (algorithm_registry_) {
        algorithm_registry_->registerAlgorithm(name, std::move(factory));
    }
}

void FuzzingEngine::addSeed(const std::vector<uint8_t>& data) {
    Seed seed;
    seed.data = data;
    seed.created_time = std::chrono::system_clock::now();
    seed.energy = 1.0;
    
    // Current coverage info would go here (commented out: no global_coverage_ member)
    // Seed coverage should be populated by executeInput after execution
    // if (global_coverage_) {
    //     seed.coverage = global_coverage_->getCurrentCoverage();
    // }
    
    corpus_manager_->addSeed(std::move(seed));
}

namespace {

static inline void trimAsciiWhitespace(std::string& s) {
    auto is_ws = [](unsigned char c) { return std::isspace(c) != 0; };
    size_t begin = 0;
    while (begin < s.size() && is_ws(static_cast<unsigned char>(s[begin]))) begin++;
    size_t end = s.size();
    while (end > begin && is_ws(static_cast<unsigned char>(s[end - 1]))) end--;
    if (begin == 0 && end == s.size()) return;
    s = s.substr(begin, end - begin);
}

static inline bool containsAnySqlKeywordCaseInsensitive(const std::string& s) {
    static const std::array<const char*, 12> kKeywords = {
        "select", "create", "insert", "update", "delete", "pragma",
        "with", "explain", "drop", "alter", "vacuum", "attach"
    };

    std::string lower;
    lower.reserve(s.size());
    for (unsigned char c : s) {
        lower.push_back(static_cast<char>(std::tolower(c)));
    }
    for (const char* kw : kKeywords) {
        if (lower.find(kw) != std::string::npos) return true;
    }
    return false;
}

static inline size_t findMatchingBrace(const std::string& s, size_t open_pos) {
    if (open_pos >= s.size() || s[open_pos] != '{') return std::string::npos;
    int depth = 1;
    for (size_t i = open_pos + 1; i < s.size(); ++i) {
        char c = s[i];
        if (c == '{') {
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0) return i;
        }
    }
    return std::string::npos;
}

static std::optional<std::vector<uint8_t>> maybeExtractSqlFromSqliteTclTest(
    const std::filesystem::path& path,
    const std::vector<uint8_t>& data,
    size_t max_blocks,
    size_t max_bytes) {

    if (path.extension() != ".test") return std::nullopt;
    if (data.empty()) return std::nullopt;

    std::string text(data.begin(), data.end());
    if (text.find("do_execsql_test") == std::string::npos &&
        text.find("do_catchsql_test") == std::string::npos) {
        return std::nullopt;
    }

    std::vector<std::string> blocks;
    blocks.reserve(max_blocks);

    auto extract_after = [&](const char* marker) {
        size_t pos = 0;
        while (blocks.size() < max_blocks) {
            pos = text.find(marker, pos);
            if (pos == std::string::npos) break;

            size_t brace = text.find('{', pos);
            if (brace == std::string::npos) break;

            size_t end = findMatchingBrace(text, brace);
            if (end == std::string::npos) break;

            std::string block = text.substr(brace + 1, end - brace - 1);
            trimAsciiWhitespace(block);

            // Heuristic filter: keep only blocks that look like SQL.
            if (block.size() >= 16 && block.size() <= 16384 && containsAnySqlKeywordCaseInsensitive(block)) {
                blocks.push_back(std::move(block));
            }

            pos = end + 1;
        }
    };

    extract_after("do_execsql_test");
    if (blocks.size() < max_blocks) {
        extract_after("do_catchsql_test");
    }

    if (blocks.empty()) return std::nullopt;

    // Build one SQL script seed per Tcl file to avoid exploding the corpus.
    std::string out;
    for (size_t i = 0; i < blocks.size(); ++i) {
        std::string block = blocks[i];
        trimAsciiWhitespace(block);
        if (block.empty()) continue;

        // Ensure there's a statement terminator at the end of each block so
        // sqlite3_exec keeps going even if the next block starts immediately.
        size_t last_non_ws = block.find_last_not_of(" \t\r\n");
        if (last_non_ws != std::string::npos && block[last_non_ws] != ';') {
            block.push_back(';');
        }
        out.append(block);
        out.push_back('\n');
    }

    if (out.empty()) return std::nullopt;
    if (out.size() > max_bytes) out.resize(max_bytes);

    return std::vector<uint8_t>(out.begin(), out.end());
}

} // namespace

void FuzzingEngine::addSeedFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open seed file: " + filename);
    }
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());

    // Some corpora use scripting wrappers around the actual input language.
    // When the harness expects raw input (e.g. SQL), extract the relevant
    // blocks from wrapper scripts to keep seeds syntactically meaningful.
    if (!data.empty()) {
        auto extracted = maybeExtractSqlFromSqliteTclTest(
            std::filesystem::path(filename),
            data,
            /*max_blocks=*/3,
            /*max_bytes=*/config_.max_input_size);
        if (extracted.has_value() && !extracted->empty()) {
            addSeed(*extracted);
            return;
        }
    }

    addSeed(data);
}

void FuzzingEngine::enableAlgorithm(const std::string& name) {
    if (algorithm_registry_) {
        algorithm_registry_->enableAlgorithm(name);
    }
}

void FuzzingEngine::disableAlgorithm(const std::string& name) {
    if (algorithm_registry_) {
        algorithm_registry_->disableAlgorithm(name);
    }
}

std::vector<std::string> FuzzingEngine::getEnabledAlgorithms() const {
    if (algorithm_registry_) {
        // Get all algorithms, then filter down to the enabled ones
        std::vector<std::string> all_algorithms = algorithm_registry_->getAllAlgorithms();
        std::vector<std::string> enabled_algorithms;
        
        for (const auto& algo : all_algorithms) {
            if (algorithm_registry_->isEnabled(algo)) {
                enabled_algorithms.push_back(algo);
            }
        }
        return enabled_algorithms;
    }
    return {};
}

std::vector<AlgorithmCombination> FuzzingEngine::getActiveCombinations() const {
    // Simplified implementation
    return {};
}

// TUI support method implementations
size_t FuzzingEngine::getCorpusSize() const {
    if (corpus_manager_) {
        return corpus_manager_->getCurrentCorpusSize();
    }
    return 0;
}

std::optional<AlgorithmCombination> FuzzingEngine::getCurrentAlgorithmCombination() const {
    // Get current algorithm combination from batch_selector
    if (batch_selector_) {
        // Get current combination from batch_selector
        // TODO: batch_selector should provide an API; for now, construct a default combination
        AlgorithmCombination combo;

        // Infer the currently most-used algorithm from stats
        if (!stats_.algorithm_usage.empty()) {
            // Find the most-used algorithm
            auto max_it = std::max_element(stats_.algorithm_usage.begin(),
                                          stats_.algorithm_usage.end(),
                                          [](const auto& a, const auto& b) {
                                              return a.second < b.second;
                                          });
            if (max_it != stats_.algorithm_usage.end()) {
                combo.algorithm_names = {max_it->first};
                combo.combination_mode = "active";
                return combo;
            }
        }

        // Default combination: use the first 3 algorithms from AlgorithmConfig
        combo.algorithm_names = {
            AlgoConfig::ENABLED_MUTATIONS[0],
            AlgoConfig::ENABLED_MUTATIONS.size() > 1 ? AlgoConfig::ENABLED_MUTATIONS[1] : AlgoConfig::ENABLED_MUTATIONS[0],
            AlgoConfig::ENABLED_MUTATIONS.size() > 2 ? AlgoConfig::ENABLED_MUTATIONS[2] : AlgoConfig::ENABLED_MUTATIONS[0]
        };
        combo.combination_mode = "sequential";
        return combo;
    }
    return std::nullopt;
}

std::optional<FuzzingEngine::BatchInfo> FuzzingEngine::getBatchInfo() const {
    BatchInfo info;

    // Get actual batch info from batch_executor (if available)
    if (batch_executor_) {
        // TODO: batch_executor needs to provide an API
        // For now, use estimated values
    }

    // Compute batch info
    const size_t batch_size = 500;
    info.batch_size = batch_size;
    info.executions_in_batch = stats_.total_executions.load() % batch_size;
    info.total_switches = stats_.total_executions.load() / batch_size;

    // Compute average reward (based on coverage growth)
    if (stats_.new_coverage_found.load() > 0) {
        info.average_reward = static_cast<double>(stats_.new_coverage_found.load()) /
                             static_cast<double>(stats_.total_executions.load() + 1);
    } else {
        info.average_reward = 0.0;
    }

    return info;
}

std::map<std::string, size_t> FuzzingEngine::getAlgorithmUsageHistory() const {
    // Return algorithm usage stats
    return stats_.algorithm_usage;
}

void FuzzingEngine::loadInitialSeeds(const std::string& dir) {
    if (!std::filesystem::exists(dir)) {
        return;
    }
    
    size_t loaded = 0;
    
    // Recursively traverse subdirectories with recursive_directory_iterator
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            // Treat all file types as seed inputs
            // Do not filter by extension; let the fuzzer handle all input types

            try {
                addSeedFromFile(entry.path().string());
                loaded++;
                    
                    if (loaded <= 10) {  // Print only the first 10 paths to avoid excessive output
                        std::cout << "[INFO] Loading seed: " << entry.path().string() << std::endl;
                    } else if (loaded == 11) {
                        std::cout << "[INFO] Loading more seeds..." << std::endl;
                    }
            } catch (const std::exception& e) {
                std::cerr << "Failed to load seed " << entry.path() << ": " << e.what() << std::endl;
            }
        }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error walking directory " << dir << ": " << e.what() << std::endl;
    }
    
    std::cout << "Loaded " << loaded << " initial seeds" << std::endl;

    // Execute all initial seeds to collect baseline coverage (seed calibration / dry-run phase)
    // Execute directly from the directory to avoid corpus selection logic causing duplicates
    if (loaded > 0 && std::filesystem::exists(dir)) {
        std::cout << "[Calibration] Executing initial seeds to collect baseline coverage..." << std::endl;

        std::vector<std::filesystem::path> seed_files;

        // Collect all seed file paths
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
                if (entry.is_regular_file()) {
                    seed_files.push_back(entry.path());
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[Calibration] Error reading seed directory: " << e.what() << std::endl;
        }

        size_t executed = 0;
        size_t total_seeds = seed_files.size();

        for (const auto& seed_path : seed_files) {
            try {
                // Read seed file
                std::ifstream file(seed_path, std::ios::binary);
                if (!file) continue;

                std::vector<uint8_t> seed_data((std::istreambuf_iterator<char>(file)),
                                                std::istreambuf_iterator<char>());

                // Execute seed (apply script-to-input extraction if needed, avoiding syntax errors during calibration)
                std::vector<uint8_t> exec_data = seed_data;
                if (!seed_data.empty()) {
                    auto extracted = maybeExtractSqlFromSqliteTclTest(
                        seed_path,
                        seed_data,
                        /*max_blocks=*/3,
                        /*max_bytes=*/config_.max_input_size);
                    if (extracted.has_value() && !extracted->empty()) {
                        exec_data = *extracted;
                    }
                }

                ExecutionResult result = executeInput(exec_data);

                // Debug: print coverage info for the first few seeds
                if (executed < 3) {
                    std::cout << "[DEBUG] Seed #" << executed << " (" << seed_path.filename() << ") coverage:" << std::endl;
                    std::cout << "  covered_edges.size() = " << result.coverage.covered_edges.size() << std::endl;
                    std::cout << "  new_edges.size() = " << result.coverage.new_edges.size() << std::endl;
                    std::cout << "  bitmap.count() = " << result.coverage.bitmap.count() << std::endl;
                    std::cout << "  First 10 edges: ";
                    for (size_t i = 0; i < std::min(size_t(10), result.coverage.covered_edges.size()); ++i) {
                        std::cout << result.coverage.covered_edges[i] << " ";
                    }
                    std::cout << std::endl;
                }

                // Update global coverage: use covered_edges as new_edges
                if (coverage_collector_) {
                    if (!result.coverage.covered_edges.empty()) {
                        CoverageInfo calibration_coverage = result.coverage;
                        calibration_coverage.new_edges = result.coverage.covered_edges;
                        coverage_collector_->updateCoverageWithEdges(calibration_coverage);
                    }
                }

                executed++;

                // Print progress every 500 seeds
                if (executed % 500 == 0 || executed == total_seeds) {
                    size_t current_edges = coverage_collector_ ? coverage_collector_->getUniqueEdgesCount() : 0;
                    std::cout << "[Calibration] Executed " << executed << "/" << total_seeds
                              << " seeds, edges: " << current_edges << std::endl;
                }

            } catch (const std::exception& e) {
                std::cerr << "[Calibration] Failed to execute seed " << seed_path << ": " << e.what() << std::endl;
            }
        }

        // Get coverage stats
        size_t total_edges = coverage_collector_ ? coverage_collector_->getUniqueEdgesCount() : 0;

        std::cout << "[Calibration] Completed! Executed " << executed << " seeds" << std::endl;
        std::cout << "[Calibration] Initial coverage: " << total_edges << " edges discovered" << std::endl;
    }
}

void FuzzingEngine::workerLoop(size_t thread_id) {
    std::cout << "[Worker " << thread_id << "] Starting worker thread" << std::endl;
    
    // Register this thread
    registerWorkerThread(thread_id);
    
    // Create thread-local context
    ThreadLocalContext local_context(global_context_.get());
    
    // Thread cleanup handler
    auto cleanup_handler = [&]() {
        cleanupWorkerThreadData(thread_id);
        unregisterWorkerThread(thread_id);
        std::cout << "[Worker " << thread_id << "] Thread cleanup completed" << std::endl;
    };
    
    // Use RAII for cleanup
    struct ThreadCleanup {
        std::function<void()> cleanup_func;
        ~ThreadCleanup() { cleanup_func(); }
    } thread_cleanup{cleanup_handler};
    
    // Get fixed combination if needed
    AlgorithmCombination fixed_combination;
    bool use_fixed_combination = !config_.enable_dynamic_combination && 
                                !config_.fixed_combination.thread_algorithm_combinations.empty();
    
    if (use_fixed_combination) {
        size_t combination_index = thread_id % config_.fixed_combination.thread_algorithm_combinations.size();
        fixed_combination.algorithm_names = config_.fixed_combination.thread_algorithm_combinations[combination_index];
        fixed_combination.combination_mode = config_.fixed_combination.fixed_combination_mode;
        
        std::cout << "[Worker " << thread_id << "] Using fixed combination: ";
        for (size_t i = 0; i < fixed_combination.algorithm_names.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << fixed_combination.algorithm_names[i];
        }
        std::cout << " (mode: " << fixed_combination.combination_mode << ")" << std::endl;
    }
    
    // Performance monitoring
    size_t executions_in_worker = 0;
    auto worker_start_time = std::chrono::steady_clock::now();
    
    // Main worker loop with improved termination checks
    while (running_.load() && !force_stop_.load()) {
        try {
            // Check for force stop more frequently
            if (force_stop_.load()) {
                break;
            }

            // Check time limit if configured
            if (max_total_time_ > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - global_start_time_).count();
                if (elapsed >= max_total_time_) {
                    running_.store(false);
                    break;
                }
            }

            // Check execution limit if configured
            if (max_executions_ > 0) {
                if (stats_.total_executions.load() >= max_executions_) {
                    running_.store(false);
                    break;
                }
            }
            
            // Layer 0: Select complete pipeline combination (Scheduler + Mutation + Feedback)
            AlgorithmCombination combination;
            if (use_fixed_combination) {
                combination = fixed_combination;
            } else {
                if (batch_selector_) {
                    combination = batch_selector_->getCurrentCombination();
                } else {
                    combination = selectAlgorithmCombination();  // Thompson Sampling chooses full pipeline
                }
            }

            // Layer 1: Select seed (using scheduler if specified in combination)
            Seed seed = selectSeedWithScheduler(combination);
            seed.execution_count++;  // Track execution count for power scheduling

            // Layer 2: Apply mutation algorithm combination
            std::vector<uint8_t> mutated_input = applyAlgorithmCombination(
                seed.data, combination, local_context
            );

            // Layer 3: Execute mutated input
            // CmpLog sampling: enable trace-cmp recording only for a subset of executions to
            // bound overhead, but collect aggressively for analysis-style combinations.
            thread_local uint64_t tls_exec_counter = 0;
            tls_exec_counter++;
            const uint32_t sample_rate = std::max<uint32_t>(1, getenv_u32("TRIOFUZZ_CMPLOG_SAMPLE_RATE", 8));
            bool is_analysis_combo = false;
            for (const auto& op : combination.algorithm_names) {
                const bool is_aflpp_op =
                    (op.rfind("mut_", 0) == 0) || (op.rfind("mopt_", 0) == 0);
                if (!is_aflpp_op) { is_analysis_combo = true; break; }
            }
            const bool collect_cmplog =
                is_analysis_combo ||
                (auto_dictionary_epoch_.load(std::memory_order_relaxed) < 8) ||
                (sample_rate == 1) ||
                ((tls_exec_counter % sample_rate) == 0);
            cmplog::setEnabled(collect_cmplog);
            cmplog::setFullEnabled(collect_cmplog && is_analysis_combo);

            ExecutionResult result = executeInput(mutated_input);

            // Layer 4: Process result with feedback analyzer (if specified in combination)
            if (!combination.feedback_analyzer.empty()) {
                processFeedbackWithAnalyzer(result, seed, combination);
            } else {
                processResultFast(result, seed, combination);  // Default processing
            }

            // 6. Record performance (reduced frequency)
            static thread_local size_t perf_counter = 0;
            if (performance_monitor_ && (++perf_counter % 100 == 0)) {
                performance_monitor_->recordExecution(combination, result);
            }

            // Update statistics
            stats_.total_executions.fetch_add(1, std::memory_order_relaxed);
            executions_in_worker++;

            // Call periodic tasks every 1000 executions (only from thread 0 to avoid race conditions)
            // if (thread_id == 0 && executions_in_worker % 1000 == 0) {
            //     periodicTasks();
            // }
            
        } catch (const std::exception& e) {
            std::cerr << "[Worker " << thread_id << "] Error: " << e.what() << std::endl;
            
            // Check if we should stop due to repeated errors
            if (force_stop_.load()) {
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    auto worker_end_time = std::chrono::steady_clock::now();
    auto worker_duration = std::chrono::duration_cast<std::chrono::seconds>(worker_end_time - worker_start_time);
    
    std::cout << "[Worker " << thread_id << "] Finished. Executed " << executions_in_worker 
              << " iterations in " << worker_duration.count() << " seconds" << std::endl;
    
    // ThreadCleanup destructor will handle cleanup automatically
}

void FuzzingEngine::fuzzingIteration(ThreadLocalContext& local_context) {
    // Adjust corpus update strategy based on strict mode
    static size_t corpus_update_counter = 0;
    
    // Further simplify corpus handling in strict mode
    if (config_.strict_algorithm_isolation && config_.disable_system_algorithms) {
        // LibFuzzer-like mode: minimize corpus interactions; update only every 50,000 iterations
        if (++corpus_update_counter % 50000 == 0) {
            try {
                auto corpus_data = corpus_manager_->getAllCorpusData();
                local_context.setCorpusSafe(corpus_data);     // Update only the local context
            } catch (const std::exception& e) {
                // Ignore corpus update errors; do not affect the main loop
            }
        }
    } else {
        // Standard strict mode or normal mode: update every 10,000 iterations
        if (++corpus_update_counter % 10000 == 0) {
            try {
                auto corpus_data = corpus_manager_->getAllCorpusData();
                global_context_->setCorpusSafe(corpus_data);  // Use thread-safe methods
                local_context.setCorpusSafe(corpus_data);     // Use thread-safe methods
            } catch (const std::exception& e) {
                // Ignore corpus update errors; do not affect the main loop
            }
        }
    }
    
    // 1. Seed selection: use different strategies based on strict mode
    auto seed_opt = std::optional<Seed>{};
    
    if (config_.strict_algorithm_isolation && config_.disable_system_algorithms) {
        // LibFuzzer-like mode: use plain random seed selection (no smart strategy)
        seed_opt = corpus_manager_->getRandomSeed(); // fully random
    } else {
        // Standard mode: use smart seed selection
        seed_opt = corpus_manager_->getNextSeed();
    }
    
    if (!seed_opt.has_value()) {
        // Simplified random seed generation to reduce strategy overhead
        static thread_local std::mt19937 fast_gen(std::random_device{}());
        static thread_local std::uniform_int_distribution<size_t> size_dist(4, 256); // Fixed reasonable range
        static thread_local std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        
        Seed random_seed;
        size_t seed_size = size_dist(fast_gen);
        random_seed.data.reserve(seed_size); // Pre-allocate to avoid repeated allocations
        
        // Generate random bytes directly; avoid complex pattern selection
        for (size_t i = 0; i < seed_size; ++i) {
            random_seed.data.push_back(byte_dist(fast_gen));
        }
        
        random_seed.energy = 1.0;
        random_seed.created_time = std::chrono::system_clock::now();
        seed_opt = random_seed;
        
        // Add to corpus asynchronously; don't block the main loop
        corpus_manager_->addSeed(std::move(random_seed));
    }
    
    const Seed& seed = seed_opt.value();
    
    // 2. Fetch algorithm combination quickly to reduce call overhead
    AlgorithmCombination combination;
    if (batch_selector_ && config_.enable_dynamic_combination) {
        combination = batch_selector_->getCurrentCombination();
    } else {
        // Use a cached default combination to avoid repeated construction
        static const AlgorithmCombination default_combo = []() {
            AlgorithmCombination combo;
            combo.algorithm_names = {"havoc"};
            combo.combination_mode = "sequential";
            return combo;
        }();
        combination = default_combo;
    }
    
    // 3. Mutate starting from the original data to reduce memory copies
    std::vector<uint8_t> mutated_input;
    mutated_input.reserve(seed.data.size() + 64); // Reserve space for mutations
    mutated_input = seed.data; // Only one copy
    
    // Apply mutation inline to avoid function call overhead
    mutated_input = applyAlgorithmCombination(mutated_input, combination, local_context);
    
    // 4. Execute input
    ExecutionResult result = executeInput(mutated_input);
    
    // 5. Result handling: choose path based on strict mode
    if (config_.strict_algorithm_isolation && config_.disable_system_algorithms) {
        // LibFuzzer-like mode: minimal result handling; focus only on new coverage
        if (result.coverage.hasNewCoverage() && !result.coverage.new_edges.empty()) {
            // Add a seed only when new coverage is found; skip expensive analysis
            Seed new_seed;
            new_seed.data = mutated_input;  // Fix: use mutated input instead of the original seed
            new_seed.coverage = result.coverage;
            new_seed.created_time = std::chrono::system_clock::now();
            new_seed.generation = seed.generation + 1;
            
            // Compute energy dynamically (improvement: based on coverage contribution)
            double coverage_bonus = result.coverage.new_edges.size() * 0.2;
            double gain_bonus = result.coverage.coverage_gain * 10.0;
            new_seed.energy = 1.0 + coverage_bonus + gain_bonus;
            
            if (corpus_manager_) {
                corpus_manager_->addSeed(std::move(new_seed));
            }
            
            stats_.new_coverage_found.fetch_add(1, std::memory_order_relaxed);
        }
    } else {
        // Standard mode: use full result handling
        processResultFast(result, seed, combination);
    }
    
    // Dynamically update seed energy (improvement: based on execution outcome)
    if (corpus_manager_ && !config_.strict_algorithm_isolation) {
        double new_energy = seed.energy;
        
        if (result.coverage.hasNewCoverage()) {
            new_energy *= 2.0;  // New coverage found: double energy
        } else if (result.status == ExecutionResult::Status::Crash) {
            new_energy *= 1.5;  // Crash found: increase energy by 50%
        } else if (result.performance.execution_time_ms < 10) {
            new_energy *= 1.1;  // Fast execution: increase energy by 10%
        } else {
            new_energy *= 0.95; // No new findings: decay energy by 5%
        }
        
        corpus_manager_->updateSeedEnergy(seed, new_energy);
    }
    
    // 6. Performance logging: adjust frequency by mode
    static size_t perf_counter = 0;
    if (performance_monitor_) {
        if (config_.strict_algorithm_isolation && config_.disable_system_algorithms) {
            // LibFuzzer-like mode: greatly reduce performance monitoring frequency
            if (++perf_counter % 1000 == 0) {
                performance_monitor_->recordExecution(combination, result);
            }
        } else if (++perf_counter % 100 == 0) {
            // Standard mode: normal frequency
            performance_monitor_->recordExecution(combination, result);
        }
    }
    
    // Atomic operation to avoid lock overhead
    stats_.total_executions.fetch_add(1, std::memory_order_relaxed);
}

AlgorithmCombination FuzzingEngine::selectAlgorithmCombination() {
    // added: prefer tiered scheduler (cost-aware probabilistic scheduling)
    if (use_tiered_scheduler_ && tiered_scheduler_ && tiered_scheduler_->hasAlgorithms()) {
        // Select an algorithm via the tiered scheduler
        std::string selected_algo = tiered_scheduler_->selectAlgorithm();

        // Create a single-algorithm combination
        AlgorithmCombination combo;
        combo.algorithm_names = {selected_algo};
        combo.combination_mode = "sequential";
        return combo;
    }

    // added: prefer optimized Thompson Sampling (preserves dynamic combination)
    if (use_optimized_thompson_ && optimized_thompson_) {
        return optimized_thompson_->selectNext();
    }

    // Get current context state
    auto coverage_info = global_context_->getCoverageInfo();
    auto performance_info = global_context_->getPerformanceInfo();

    // Forced diversity check: ensure all algorithms get a chance to run
    static size_t diversity_counter = 0;
    static constexpr size_t DIVERSITY_INTERVAL = 50; // Force diversity once every 50 selections

    diversity_counter++;
    if (diversity_counter % DIVERSITY_INTERVAL == 0) {
        return selectDiversityForcedCombination();
    }

    // Removed: TS/MCTS dynamic combination selection

    // Fallback to adaptive selection strategy
    return selectAdaptiveCombination();
}

// Removed: selectWithThompsonSampling (replaced by optimized unified path)

// Removed: selectWithMCTS (replaced by optimized unified path)

// Simplified adaptive combination selection
AlgorithmCombination FuzzingEngine::selectAdaptiveCombination() {
    auto enabled_algorithms = getEnabledAlgorithms();
    if (enabled_algorithms.empty()) {
        AlgorithmCombination default_combo;
        default_combo.algorithm_names = {"havoc"};
        default_combo.combination_mode = "sequential";
        return default_combo;
    }
    
    // Simplified decision: directly use an efficient algorithm combination
    AlgorithmCombination combo;
    combo.algorithm_names = {"havoc"};  // Directly use the most efficient algorithm
    combo.combination_mode = "sequential";
    return combo;
}

// Generate candidate combinations (optimized): cap combination count for performance
std::vector<AlgorithmCombination> FuzzingEngine::generateCandidateCombinations() {
    std::vector<AlgorithmCombination> candidates;

    // Performance: adjust the max combination count based on the number of algorithms
    size_t MAX_COMBINATIONS = 200;

    // Get all available algorithms (from registry, enabled only)
    // Use AlgoConfig::isEnabled() for centralized filtering
    std::vector<std::string> available_algorithms;

    try {
        auto& registry = (*algorithm_registry_);
        std::vector<std::string> all_algorithms = registry.getAllAlgorithms();
        for (const auto& algo : all_algorithms) {
            // Filter: only include algorithms enabled in AlgorithmConfig (automatically excluding schedulers/feedback analyzers, etc.)
            if (registry.isEnabled(algo) && AlgoConfig::isEnabled(algo)) {
                available_algorithms.push_back(algo);
            }
        }
    } catch (const std::exception& e) {
        std::cout << "[WARNING] Failed to get algorithms from registry: " << e.what() << std::endl;
    }

    // If the registry is empty, fall back to configured algorithms
    if (available_algorithms.empty()) {
        available_algorithms = config_.enabled_algorithms;
    }

    // If still empty, choose a default algorithm set based on strict mode
    if (available_algorithms.empty()) {
        if (config_.strict_algorithm_isolation) {
            // Strict mode: use only the basic havoc algorithm as a fallback
            available_algorithms = {"havoc"};
            std::cout << "[STRICT MODE] No algorithms specified, using minimal fallback: havoc only" << std::endl;
        } else {
            // Standard mode: get all algorithms from the registry
            try {
                auto& registry = (*algorithm_registry_);
                available_algorithms = registry.getAllAlgorithms();
                std::cout << "[INFO] Using all registered algorithms: " << available_algorithms.size() << " algorithms" << std::endl;
            } catch (const std::exception& e) {
                std::cout << "[WARNING] Failed to get algorithms from registry: " << e.what() << std::endl;
                // Use AlgorithmConfig as fallback
                available_algorithms = AlgoConfig::ENABLED_MUTATIONS;
            }
        }
    }

    // Optimization: if there are few algorithms (user-limited), reduce the number of combinations
    if (available_algorithms.size() <= 5) {
        MAX_COMBINATIONS = 10;  // With 5 algorithms, cap at 10 combinations
    }

    // 1. Add all single-algorithm combinations (most important)
    for (const auto& algo : available_algorithms) {
        AlgorithmCombination combo;
        combo.algorithm_names = {algo};
        combo.combination_mode = "sequential";
        candidates.push_back(combo);
        if (candidates.size() >= MAX_COMBINATIONS) return candidates;
    }
    
    // 2. If there are few algorithms, add only simple two-algorithm combinations
    if (available_algorithms.size() <= 5) {
        // With a limited set, generate only the most effective 2-algorithm combos
        if (std::find(available_algorithms.begin(), available_algorithms.end(), "havoc") != available_algorithms.end() &&
            std::find(available_algorithms.begin(), available_algorithms.end(), "bitflip") != available_algorithms.end()) {
            AlgorithmCombination combo;
            combo.algorithm_names = {"havoc", "bitflip"};
            combo.combination_mode = "sequential";  // sequential is more stable performance-wise
            candidates.push_back(combo);
        }
        if (candidates.size() >= MAX_COMBINATIONS) return candidates;
    } else {
        // With many algorithms, use predefined combinations
        static const std::vector<std::pair<std::vector<std::string>, std::string>> predefined_combos = {
            // Classic combos
            {{"havoc", "bitflip"}, "sequential"},
            {{"havoc", "arithmetic"}, "sequential"},
            // {{"afl_plus_plus", "rare_branch"}, "sequential"}, // rare_branch archived
            // CmpLog combos: solve comparison constraints (archived: extremely slow)
            // {{"cmplog", "havoc"}, "sequential"},
            // {{"cmplog", "gradient_descent"}, "sequential"}, // gradient_descent archived
            // {{"cmplog", "arithmetic"}, "sequential"},
            // Rare-branch optimization (archived)
            // {{"rare_branch", "rare_edge_scheduler"}, "sequential"}, // rare_edge_scheduler archived
            // Fast exploration (use sequential for performance)
            {{"havoc", "splice"}, "sequential"},
            {{"bitflip", "arithmetic"}, "sequential"},
            // Gradient-guided
            // {{"gradient_descent", "havoc"}, "sequential"}, // gradient_descent archived
        };

        for (const auto& [algo_names, mode] : predefined_combos) {
            bool all_available = true;
            for (const auto& algo : algo_names) {
                if (std::find(available_algorithms.begin(), available_algorithms.end(), algo) == available_algorithms.end()) {
                    all_available = false;
                    break;
                }
            }
            if (all_available) {
                AlgorithmCombination combo;
                combo.algorithm_names = algo_names;
                combo.combination_mode = mode;
                candidates.push_back(combo);
                if (candidates.size() >= MAX_COMBINATIONS) return candidates;
            }
        }
    }

    // 3. Adaptive combinations based on current state (simplified)
    auto coverage_info = global_context_->getCoverageInfo();
    if (coverage_info.has_value() && candidates.size() < MAX_COMBINATIONS) {
        double coverage_gain = coverage_info->coverage_gain;

        // If coverage stalls, add a more aggressive strategy
        if (coverage_gain < 0.001) {
            // Try adding "breakthrough" algorithms (using AlgorithmConfig defaults)
            std::vector<std::string> breakthrough_algos;
            if (AlgoConfig::ENABLED_MUTATIONS.size() >= 2) {
                breakthrough_algos = {AlgoConfig::ENABLED_MUTATIONS[0], AlgoConfig::ENABLED_MUTATIONS[3]};  // havoc, splice
            } else {
                breakthrough_algos = {AlgoConfig::ENABLED_MUTATIONS[0]};
            }
            for (const auto& algo : breakthrough_algos) {
                if (std::find(available_algorithms.begin(), available_algorithms.end(), algo) != available_algorithms.end()) {
                    AlgorithmCombination combo;
                    combo.algorithm_names = {algo};
                    combo.combination_mode = "sequential";
                    candidates.push_back(combo);
                    if (candidates.size() >= MAX_COMBINATIONS) break;
                }
            }
        }
    }

    // Ensure at least one candidate combination exists
    if (candidates.empty()) {
        AlgorithmCombination default_combo;
        default_combo.algorithm_names = {"havoc"};
        default_combo.combination_mode = "sequential";
        candidates.push_back(default_combo);
    }

    // Assign a scheduler and feedback analyzer to each combination (build a full fuzzing pipeline)
    std::vector<std::string> schedulers = {
        "",  // Default (use CorpusManager)
        "rare_edge_scheduler",
        "fast_scheduler",
        "mopt_scheduler",
        "energy_scheduler"
    };

    std::vector<std::string> feedback_analyzers = AlgoConfig::ENABLED_FEEDBACKS.empty()
        ? std::vector<std::string>{""}
        : AlgoConfig::ENABLED_FEEDBACKS;

    // Build full pipeline combinations for each mutation combo
    std::vector<AlgorithmCombination> full_pipeline_candidates;
    static std::random_device rd;
    static std::mt19937 gen(rd());

    for (auto& combo : candidates) {
        // Randomly pick one scheduler and one feedback analyzer for each mutation combo
        std::uniform_int_distribution<> scheduler_dist(0, schedulers.size() - 1);
        std::uniform_int_distribution<> feedback_dist(0, feedback_analyzers.size() - 1);

        combo.scheduler_name = schedulers[scheduler_dist(gen)];
        combo.feedback_analyzer = feedback_analyzers[feedback_dist(gen)];
        full_pipeline_candidates.push_back(combo);

        // Cap total count
        if (full_pipeline_candidates.size() >= MAX_COMBINATIONS) {
            break;
        }
    }

    std::cout << "[BATCH] Generated " << full_pipeline_candidates.size() << " complete pipeline combinations:" << std::endl;
    for (size_t i = 0; i < std::min(full_pipeline_candidates.size(), size_t(5)); ++i) {
        std::cout << "  [" << i << "] " << full_pipeline_candidates[i].toString() << std::endl;
    }

    return full_pipeline_candidates;
}

// Calculate context adjustment value
double FuzzingEngine::calculateContextAdjustment(const AlgorithmCombination& combo) {
    double adjustment = 0.0;
    
    auto coverage_info = global_context_->getCoverageInfo();
    auto performance_info = global_context_->getPerformanceInfo();
    
    // === Smart adjustment based on coverage state ===
    if (coverage_info.has_value()) {
        double coverage_gain = coverage_info->coverage_gain;
        
        if (coverage_gain < 0.001) {
            // Coverage stagnation: bias toward exploratory and AI-driven algorithms
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "neuzz") != combo.algorithm_names.end()) {
            //     adjustment += 0.3; // NEUZZ is effective during stagnation
            // } // neuzz archived
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "rare_branch") != combo.algorithm_names.end()) {
            //     adjustment += 0.25; // FairFuzz specializes in rare branches
            // } // rare_branch archived
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "zest") != combo.algorithm_names.end()) {
            //     adjustment += 0.2; // ZEST's structured approach can help break through
            // } // zest archived
            if (combo.combination_mode == "parallel") {
                adjustment += 0.15; // Try multiple strategies in parallel
            }
        } else if (coverage_gain > 0.01) {
            // Rapid coverage growth: bias toward exploiting the currently effective strategy
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "gradient_descent") != combo.algorithm_names.end()) {
            //     adjustment += 0.2; // Gradient descent optimizes the current direction
            // } // gradient_descent archived
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "binary_pso") != combo.algorithm_names.end()) {
            //     adjustment += 0.15; // PSO optimizes the search space
            // } // binary_pso archived
            if (combo.combination_mode == "sequential") {
                adjustment += 0.1; // Sequential execution preserves continuity
            }
        }
    }
    
    // === Adjustment based on performance state ===
    if (performance_info.has_value()) {
        double exec_time = performance_info->execution_time_ms;
        
        if (exec_time > 100) {
            // Slow execution: bias toward lightweight algorithms
            if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "bitflip") != combo.algorithm_names.end() ||
                std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "arithmetic") != combo.algorithm_names.end()) {
                adjustment += 0.2;
            }
            // Reduce the weight of heavy AI algorithms
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "neuzz") != combo.algorithm_names.end()) {
            //     adjustment -= 0.1;
            // } // neuzz archived
        } else if (exec_time < 10) {
            // Fast execution: can afford more complex algorithms
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "neuzz") != combo.algorithm_names.end()) {
            //     adjustment += 0.25; // NEUZZ has higher compute cost but can be effective
            // } // neuzz archived
            // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "libfuzzer_structured") != combo.algorithm_names.end()) {
            //     adjustment += 0.2; // Structured mutation has higher overhead
            // } // libfuzzer_structured archived
        }
    }
    
    // === Adjustment based on execution history ===
    size_t total_executions = stats_.total_executions.load();
    
    if (total_executions < 1000) {
        // Early phase: bias toward exploration and diversity
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "havoc") != combo.algorithm_names.end()) {
            adjustment += 0.2; // Havoc provides good initial exploration
        }
        // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "deterministic") != combo.algorithm_names.end()) {
        //     adjustment += 0.15; // Deterministic mutation builds baseline coverage
        // } // deterministic archived
    } else if (total_executions > 10000) {
        // Late phase: bias toward refinement and optimization
        // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "rare_branch") != combo.algorithm_names.end()) {
        //     adjustment += 0.3; // FairFuzz finds rare paths in later stages
        // } // rare_branch archived
        // if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "neuzz") != combo.algorithm_names.end()) {
        //     adjustment += 0.25; // NEUZZ performs better once there is enough training data
        // } // neuzz archived
    }
    
    // === Adjustment based on crash discovery state ===
    if (stats_.total_executions > 500 && stats_.unique_crashes == 0) {
        // No crashes for a long time: bias toward crash-oriented strategies
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "crash_analyzer") != combo.algorithm_names.end()) {
            adjustment += 0.3; // Crash analyzer guidance
        }
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "arithmetic") != combo.algorithm_names.end()) {
            adjustment += 0.2; // Arithmetic mutations can trigger boundary bugs
        }
        if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "havoc") != combo.algorithm_names.end()) {
            adjustment += 0.25; // Havoc's randomness can help find crashes
        }
    }
    
    // === Adjustment based on algorithm synergy ===
    
    // Synergy bonus: AI + traditional algorithms
    bool has_ai_algo = false; // rare_branch, zest, neuzz archived
    
    bool has_traditional_algo = std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "havoc") != combo.algorithm_names.end() ||
                               std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "bitflip") != combo.algorithm_names.end() ||
                               std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "arithmetic") != combo.algorithm_names.end();
    
    if (has_ai_algo && has_traditional_algo) {
        adjustment += 0.15; // Synergy bonus for AI + traditional algorithms
    }
    
    // Synergy bonus: analyzer + mutator
    bool has_analyzer = std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "coverage_analyzer") != combo.algorithm_names.end() ||
                       std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "crash_analyzer") != combo.algorithm_names.end(); // performance_analyzer archived

    bool has_mutator = std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), "havoc") != combo.algorithm_names.end(); // gradient_descent archived
    
    if (has_analyzer && has_mutator) {
        adjustment += 0.1; // Reward for analyzer-guided mutation
    }
    
    // Synergy bonus: optimization algorithms
    bool has_optimizer = false; // binary_pso, gradient_descent archived
    
    if (has_optimizer && combo.algorithm_names.size() > 1) {
        adjustment += 0.12; // Bonus for combining optimization algorithms with others
    }
    
    return adjustment;
}

// Select exploratory algorithms
std::vector<std::string> FuzzingEngine::selectExploratoryAlgorithms(const std::vector<std::string>& enabled_algorithms) {
    std::vector<std::string> exploratory = {"splice", "havoc"}; // gradient_descent archived
    std::vector<std::string> result;
    
    for (const auto& algo : exploratory) {
        if (std::find(enabled_algorithms.begin(), enabled_algorithms.end(), algo) != enabled_algorithms.end()) {
            result.push_back(algo);
            if (result.size() >= 2) break; // Limit combination size
        }
    }
    
    if (result.empty() && !enabled_algorithms.empty()) {
        result.push_back(enabled_algorithms[0]);
    }
    
    return result;
}

// Select fast algorithms
std::vector<std::string> FuzzingEngine::selectFastAlgorithms(const std::vector<std::string>& enabled_algorithms) {
    std::vector<std::string> fast = {"bitflip", "arithmetic"};
    std::vector<std::string> result;
    
    for (const auto& algo : fast) {
        if (std::find(enabled_algorithms.begin(), enabled_algorithms.end(), algo) != enabled_algorithms.end()) {
            result.push_back(algo);
        }
    }
    
    if (result.empty() && !enabled_algorithms.empty()) {
        result.push_back(enabled_algorithms[0]);
    }
    
    return result;
}

// Select crash-focused algorithms
std::vector<std::string> FuzzingEngine::selectCrashFocusedAlgorithms(const std::vector<std::string>& enabled_algorithms) {
    std::vector<std::string> crash_focused = AlgoConfig::ENABLED_MUTATIONS;
    std::vector<std::string> result;
    
    for (const auto& algo : crash_focused) {
        if (std::find(enabled_algorithms.begin(), enabled_algorithms.end(), algo) != enabled_algorithms.end()) {
            result.push_back(algo);
        }
    }
    
    if (result.empty() && !enabled_algorithms.empty()) {
        result.push_back(enabled_algorithms[0]);
    }
    
    return result;
}

// Forced diversity selection: prefer algorithms with low usage
AlgorithmCombination FuzzingEngine::selectDiversityForcedCombination() {
    auto enabled_algorithms = getEnabledAlgorithms();
    if (enabled_algorithms.empty()) {
        AlgorithmCombination default_combo;
        default_combo.algorithm_names = {"havoc"};
        default_combo.combination_mode = "sequential";
        return default_combo;
    }
    
    // Find the lowest-usage algorithms
    std::vector<std::pair<std::string, double>> algo_usage_rates;
    {
        std::lock_guard<std::mutex> lock(diversity_stats_mutex_);
        for (const auto& algo : enabled_algorithms) {
            auto it = algorithm_usage_stats_.find(algo);
            double usage_rate = 0.0;
            if (it != algorithm_usage_stats_.end() && total_algorithm_uses_ > 0) {
                usage_rate = static_cast<double>(it->second) / total_algorithm_uses_;
            }
            algo_usage_rates.emplace_back(algo, usage_rate);
        }
    }
    
    // Sort by usage rate (ascending)
    std::sort(algo_usage_rates.begin(), algo_usage_rates.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    // Select the 1-3 lowest-usage algorithms to form a combination
    AlgorithmCombination diversity_combo;
    diversity_combo.combination_mode = "sequential";
    
    size_t num_algos = std::min(static_cast<size_t>(3), algo_usage_rates.size());
    for (size_t i = 0; i < num_algos; ++i) {
        diversity_combo.algorithm_names.push_back(algo_usage_rates[i].first);
    }
    
    // Add some randomness to avoid over-determinism
    static std::random_device rd;
    static std::mt19937 gen(rd());
    if (diversity_combo.algorithm_names.size() > 1) {
        std::shuffle(diversity_combo.algorithm_names.begin(), 
                    diversity_combo.algorithm_names.end(), gen);
    }
    
    std::cout << "[DIVERSITY] Forced selection: " << diversity_combo.toString() << std::endl;
    return diversity_combo;
}

// Print algorithm usage statistics
void FuzzingEngine::printAlgorithmUsageStats() {
    std::lock_guard<std::mutex> lock(diversity_stats_mutex_);
    
    if (total_algorithm_uses_ == 0) {
        std::cout << "[ALGORITHM_STATS] No algorithm usage data yet." << std::endl;
        return;
    }
    
    std::cout << "\n========== Algorithm Usage Statistics ==========" << std::endl;
    std::cout << "[ALGORITHM_STATS] Total algorithm uses: " << total_algorithm_uses_ << std::endl;
    
    // Sort algorithms by usage rate
    std::vector<std::pair<std::string, size_t>> sorted_usage(
        algorithm_usage_stats_.begin(), algorithm_usage_stats_.end());
    std::sort(sorted_usage.begin(), sorted_usage.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::cout << "\nAlgorithm Usage Breakdown:" << std::endl;
    for (const auto& [algo, count] : sorted_usage) {
        double percentage = (static_cast<double>(count) / total_algorithm_uses_) * 100.0;
        std::cout << "  " << std::setw(30) << std::left << algo 
                  << ": " << std::setw(6) << count 
                  << " (" << std::fixed << std::setprecision(2) << percentage << "%)" << std::endl;
    }
    
    // Count unused algorithms
    auto enabled_algorithms = getEnabledAlgorithms();
    std::vector<std::string> unused_algorithms;
    for (const auto& algo : enabled_algorithms) {
        if (algorithm_usage_stats_.find(algo) == algorithm_usage_stats_.end() ||
            algorithm_usage_stats_[algo] == 0) {
            unused_algorithms.push_back(algo);
        }
    }
    
    if (!unused_algorithms.empty()) {
        std::cout << "\nUnused Algorithms (" << unused_algorithms.size() << "):" << std::endl;
        for (const auto& algo : unused_algorithms) {
            std::cout << "  - " << algo << std::endl;
        }
    }
    
    // Compute diversity metrics
    double shannon_entropy = 0.0;
    for (const auto& [algo, count] : algorithm_usage_stats_) {
        if (count > 0) {
            double prob = static_cast<double>(count) / total_algorithm_uses_;
            shannon_entropy -= prob * std::log2(prob);
        }
    }
    
    std::cout << "\nDiversity Metrics:" << std::endl;
    std::cout << "  Shannon Entropy: " << std::fixed << std::setprecision(3) << shannon_entropy << std::endl;
    std::cout << "  Algorithms Used: " << algorithm_usage_stats_.size() << "/" << enabled_algorithms.size() << std::endl;
    std::cout << "================================================\n" << std::endl;
}

// Apply reward smoothing to avoid over-optimizing a specific combination
double FuzzingEngine::applyRewardSmoothing(double raw_reward, const AlgorithmCombination& combination) {
    std::string combo_key = combination.toString();
    
    // Get the combination's historical performance
    std::lock_guard<std::mutex> thompson_lock(thompson_sampling_mutex_);
    auto history_it = combination_history_.find(combo_key);
    if (history_it == combination_history_.end()) {
        // New combination: no smoothing needed
        return raw_reward;
    }
    
    auto& [uses, total_reward] = history_it->second;
    if (uses == 0) {
        return raw_reward;
    }
    
    double avg_historical_reward = total_reward / uses;
    
    // If the current reward is significantly higher than the historical average, reduce it moderately
    double reward_ratio = raw_reward / (avg_historical_reward + 0.01); // Avoid divide-by-zero
    
    if (reward_ratio > 2.0) {
        // If current reward is >2x historical average, apply logarithmic scaling
        double scaling_factor = 1.0 + std::log(reward_ratio) / std::log(2.0);
        raw_reward = avg_historical_reward * scaling_factor * 0.8; // Extra 0.8 factor for additional smoothing
        
        // Debug output
        if (uses % 100 == 0) { // Print once per 100 uses to avoid log spam
            std::cout << "[REWARD_SMOOTHING] " << combo_key 
                      << " reward smoothed from " << std::fixed << std::setprecision(3) 
                      << (raw_reward / 0.8 / scaling_factor) 
                      << " to " << raw_reward << std::endl;
        }
    }
    
    // Add a diversity bonus for combinations with multiple algorithms
    if (combination.algorithm_names.size() > 1) {
        // Compute algorithm diversity score
        std::set<std::string> unique_algorithms(combination.algorithm_names.begin(), 
                                               combination.algorithm_names.end());
        double diversity_factor = static_cast<double>(unique_algorithms.size()) / combination.algorithm_names.size();
        raw_reward += 0.05 * diversity_factor; // Up to 5% diversity bonus
    }
    
    return raw_reward;
}

// Select balanced algorithms
std::vector<std::string> FuzzingEngine::selectBalancedAlgorithms(const std::vector<std::string>& enabled_algorithms) {
    std::vector<std::string> balanced = {"havoc", "bitflip"};
    std::vector<std::string> result;
    
    for (const auto& algo : balanced) {
        if (std::find(enabled_algorithms.begin(), enabled_algorithms.end(), algo) != enabled_algorithms.end()) {
            result.push_back(algo);
        }
    }
    
    if (result.empty() && !enabled_algorithms.empty()) {
        result.push_back(enabled_algorithms[0]);
    }
    
    return result;
}

ExecutionResult FuzzingEngine::executeInput(const std::vector<uint8_t>& input) {
    // Use custom executor if provided
    if (custom_executor_) {
        // std::cout << "[DEBUG] Using custom executor" << std::endl;
        return custom_executor_->execute(input, config_.timeout);
    }
    
    // Use the default executor instance to avoid recreating it each time
    if (!default_executor_) {
        std::cerr << "[ERROR] Default executor not initialized!" << std::endl;
        throw std::runtime_error("Default executor not initialized");
    }
    
    // std::cout << "[DEBUG] Using default SimpleExecutor" << std::endl;
    return default_executor_->execute(input, config_.timeout);
}

void FuzzingEngine::updatePreferredLengthOnNewCoverage(size_t input_len) {
    if (input_len == 0) return;
    uint64_t sum = preferred_length_sum_.fetch_add(input_len, std::memory_order_relaxed) + input_len;
    uint64_t cnt = preferred_length_count_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (cnt == 0) return;
    preferred_length_.store(static_cast<uint32_t>(sum / cnt), std::memory_order_relaxed);
}

bool FuzzingEngine::publishCmpLogFromLastExecution() {
    if (!global_context_) return false;
    if (!__collafuzz_cmplog_enabled() || !cmplog::isEnabled()) return false;

    auto recs = cmplog::drain();
    if (recs.empty()) return false;

    // Keep overhead bounded even if the target is very comparison-heavy.
    const size_t max_recs_per_exec = cmplog::isFullEnabled() ? 1024 : 256;
    if (recs.size() > max_recs_per_exec) recs.resize(max_recs_per_exec);

    using ComparisonInfo = triofuzz::CmpLogInstrumentation::ComparisonInfo;
    using ComparisonType = triofuzz::CmpLogInstrumentation::ComparisonType;

    std::vector<ComparisonInfo> infos;
    infos.reserve(recs.size());

    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> new_pairs;
    new_pairs.reserve(recs.size());

    for (const auto& r : recs) {
        ComparisonInfo info{};
        info.instruction_address = r.pc;
        info.hit_count = 1;
        info.comparison_result = false; // unknown

        switch (r.kind) {
            case cmplog::CmpKind::Int:
                info.type = ComparisonType::INTEGER_EQ;
                break;
            case cmplog::CmpKind::ConstInt:
                info.type = ComparisonType::INTEGER_EQ;
                info.right_operand.is_constant = true;
                break;
            case cmplog::CmpKind::Mem:
                info.type = ComparisonType::MEMCMP;
                break;
            case cmplog::CmpKind::Str:
            case cmplog::CmpKind::StrN:
                info.type = ComparisonType::STRING_CMP;
                break;
            case cmplog::CmpKind::Switch:
                info.type = ComparisonType::INTEGER_EQ;
                info.right_operand.is_constant = true;
                break;
        }

        size_t l = std::min<size_t>(r.lhs_len, sizeof(r.lhs));
        size_t rr = std::min<size_t>(r.rhs_len, sizeof(r.rhs));
        size_t use = std::min(l, rr);
        if (use == 0) use = std::max(l, rr);
        if (use == 0) use = r.size;
        if (use == 0) use = 1;
        if (use > 32) use = 32;

        info.operand_size = use;
        info.left_operand.value.assign(r.lhs, r.lhs + use);
        info.right_operand.value.assign(r.rhs, r.rhs + use);

        new_pairs.emplace_back(info.left_operand.value, info.right_operand.value);
        infos.push_back(std::move(info));
    }

    // 1) Accumulate cmplog comparison infos (for CmpLogMutation).
    constexpr size_t MAX_CMPLOG_ENTRIES = 8192;
    {
        auto existing = global_context_->get<std::vector<ComparisonInfo>>("cmplog_comparison_infos");
        if (existing.has_value()) {
            auto vec = std::move(existing.value());
            vec.insert(vec.end(), infos.begin(), infos.end());
            if (vec.size() > MAX_CMPLOG_ENTRIES) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - MAX_CMPLOG_ENTRIES));
            }
            global_context_->set("cmplog_comparison_infos", std::move(vec));
        } else {
            global_context_->set("cmplog_comparison_infos", infos);
        }
    }

    // 2) Publish simple operand pairs (for SmartDictionary/RuntimeDictionary).
    {
        auto existing_pairs =
            global_context_->get<std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>>(
                "cmplog_comparisons");

        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> simple_pairs;
        if (existing_pairs.has_value()) {
            simple_pairs = std::move(existing_pairs.value());
        }

        simple_pairs.insert(simple_pairs.end(), new_pairs.begin(), new_pairs.end());
        if (simple_pairs.size() > MAX_CMPLOG_ENTRIES) {
            simple_pairs.erase(simple_pairs.begin(),
                               simple_pairs.begin() + (simple_pairs.size() - MAX_CMPLOG_ENTRIES));
        }
        global_context_->set("cmplog_comparisons", std::move(simple_pairs));
    }

    // 3) Auto-dictionary: extract likely constants/tokens from cmplog (feeds EXTRA_AUTO_* and MOpt *_extra).
    bool added_any = false;
    {
        auto is_useful_token = [](const std::vector<uint8_t>& tok) {
            if (tok.size() < 2 || tok.size() > 32) return false;
            uint8_t first = tok[0];
            bool all_same = true;
            for (uint8_t b : tok) {
                if (b != first) { all_same = false; break; }
            }
            return !all_same;
        };

        std::vector<std::vector<uint8_t>> auto_dict;
        auto existing_dict = global_context_->get<std::vector<std::vector<uint8_t>>>("auto_dictionary");
        if (existing_dict.has_value()) {
            auto_dict = std::move(existing_dict.value());
        }

        auto try_add = [&](const std::vector<uint8_t>& tok) {
            if (!is_useful_token(tok)) return;
            if (std::find(auto_dict.begin(), auto_dict.end(), tok) != auto_dict.end()) return;
            auto_dict.push_back(tok);
            added_any = true;
        };

        for (const auto& info : infos) {
            // Const-int: keep the constant side (2-8 bytes).
            if (info.right_operand.is_constant && info.right_operand.value.size() >= 2 &&
                info.right_operand.value.size() <= 8) {
                try_add(info.right_operand.value);
            }
            // 4-byte values are often magic numbers.
            if (info.operand_size == 4) {
                try_add(info.left_operand.value);
                try_add(info.right_operand.value);
            }
            // Mem/string comparisons often carry format tokens (e.g., headers).
            if (info.type == ComparisonType::MEMCMP || info.type == ComparisonType::STRING_CMP ||
                info.type == ComparisonType::STRING_EQ || info.type == ComparisonType::STRING_NE) {
                try_add(info.left_operand.value);
                try_add(info.right_operand.value);
            }
        }

        constexpr size_t MAX_AUTO_DICT_SIZE = 512;
        if (auto_dict.size() > MAX_AUTO_DICT_SIZE) {
            auto_dict.erase(auto_dict.begin(), auto_dict.begin() + (auto_dict.size() - MAX_AUTO_DICT_SIZE));
        }

        if (added_any) {
            global_context_->set("auto_dictionary", std::move(auto_dict));
            auto_dictionary_epoch_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    return added_any;
}

void FuzzingEngine::processResult(const ExecutionResult& result, const Seed& original_seed, const AlgorithmCombination& combination) {
    try {
        // 1) Drain this-thread cmplog records and publish to shared context (cmplog + auto_dict).
        publishCmpLogFromLastExecution();

        // 2) Coverage processing
        // Fixed: Only use global coverage collector to determine if coverage is truly new
        bool has_new_coverage = false;

        // Check with the global coverage collector if we have truly new coverage
        bool global_new_coverage = false;
        try {
            if (coverage_collector_) {
                // This now properly checks if edges are globally new
                global_new_coverage = coverage_collector_->updateCoverageWithEdges(result.coverage);
                has_new_coverage = global_new_coverage;
            } else {
                // Fallback: if no global collector, trust the execution result
                has_new_coverage = result.coverage.hasNewCoverage();
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Coverage collector error: " << e.what() << std::endl;
            // Continue execution, don't let coverage errors interrupt the flow
            // Fallback to execution result
            has_new_coverage = result.coverage.hasNewCoverage();
        }
        
        // Compute the combination reward score (based on corrected coverage info)
        double combination_reward = 0.0;
        try {
            combination_reward = calculateCombinationReward(result, original_seed);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Calculate reward error: " << e.what() << std::endl;
            combination_reward = 0.1; // default value
        }
        double exec_time_ms = result.performance.execution_time_ms;
        bool decoder_success = (result.status == ExecutionResult::Status::Success);
        if (!has_new_coverage) {
            double penalty = -0.02;
            if (exec_time_ms > 0.0 && exec_time_ms < 5.0) {
                penalty -= 0.03;
            }
            if (result.status == ExecutionResult::Status::Error ||
                result.status == ExecutionResult::Status::Timeout) {
                penalty -= 0.05;
            }
            if (!decoder_success) {
                penalty -= 0.05;
            }
            combination_reward = penalty;
        }
        if (result.status == ExecutionResult::Status::Crash) {
            combination_reward += 0.3;
        }
        if (!decoder_success) {
            combination_reward = std::min(combination_reward, -0.1);
        }
        combination_reward = std::clamp(combination_reward, -0.2, 1.0);
        
        // Record reward to the batch selector (with safety checks)
        try {
            if (batch_selector_) {
                bool crashed = (result.status == ExecutionResult::Status::Crash);
                batch_selector_->recordExecution(combination_reward, has_new_coverage, crashed, decoder_success);

                // If new coverage is found, force-end the current batch to quickly adapt to strong strategies
                if (has_new_coverage && result.coverage.new_edges.size() > 0) {
                    batch_selector_->forceEndBatch();
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Batch selector error: " << e.what() << std::endl;
        }
        
        // Update algorithm usage stats (for diversity tracking)
        updateAlgorithmUsageStats(combination);
        
        // Update algorithm-combination performance stats
        try {
            updateCombinationPerformance(combination, combination_reward, result);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Update performance error: " << e.what() << std::endl;
        }

        // Removed: anti-convergence Thompson Sampling statistics update

        // Removed: standard Thompson Sampling Beta distribution update

        // Improved debug output - using unified incrementing counter
        size_t current_count = global_debug_counter.fetch_add(1, std::memory_order_relaxed);
        if (current_count % 10000000 == 0 || has_new_coverage || result.coverage.new_edges.size() > 5) {
            std::cout << "[DEBUG] processResult #" << current_count
                      << ": total_edges=" << result.coverage.total_edges
                      << ", coverage_gain=" << std::fixed << std::setprecision(4) << result.coverage.coverage_gain
                      << ", has_new=" << (has_new_coverage ? "YES" : "NO")
                      << ", reward=" << std::setprecision(3) << combination_reward
                      << ", combo=" << combination.toString() << std::endl;
        }
        
        // Create a new seed only when truly new coverage is found (with full error handling)
        if (has_new_coverage && result.coverage.new_edges.size() > 0) {
            std::stringstream ss;
            ss << "[+] New coverage found! " << result.coverage.new_edges.size()
               << " new edges, combination: " << combination.toString()
               << " (reward: " << std::fixed << std::setprecision(3) << combination_reward << ")\n";
            ThreadSafeLogger::getInstance().logImmediate(ss.str());
            
            try {
                // Safely create a new seed: use deep copies to avoid reference issues
                Seed new_seed;
                // new_seed.data = original_seed.data; // deep copy
                new_seed.data = result.input_data; // deep copy
                new_seed.coverage = result.coverage; // deep copy
                new_seed.performance = result.performance; // deep copy
                new_seed.created_time = std::chrono::system_clock::now();
                new_seed.generation = original_seed.generation + 1;
                
                // Safely copy algorithm history
                new_seed.algorithm_history = original_seed.algorithm_history;
                new_seed.algorithm_history.push_back(combination.toString());
                
                // Set seed energy (based on new edge count and coverage gain)
                double coverage_bonus = result.coverage.new_edges.size() * 0.2;
                double gain_bonus = result.coverage.coverage_gain * 10.0;
                new_seed.energy = 1.0 + coverage_bonus + gain_bonus;
                
                // Add to corpus: use move semantics and ensure exception safety
                if (corpus_manager_) {
                    corpus_manager_->addSeed(std::move(new_seed));
                } else {
                    std::cerr << "[ERROR] Corpus manager is null!" << std::endl;
                }
                
                // Update stats
                stats_.new_coverage_found++;
                stats_.last_coverage_time = std::chrono::system_clock::now();
                
                // Safely fire callback, passing algorithm-combination info
                if (on_new_coverage_) {
                    try {
                        // Create a seed for the callback to avoid accessing after move
                        Seed callback_seed;
                        callback_seed.data = original_seed.data;
                        callback_seed.coverage = result.coverage;
                        callback_seed.performance = result.performance;
                        callback_seed.created_time = std::chrono::system_clock::now();
                        callback_seed.generation = original_seed.generation + 1;
                        callback_seed.algorithm_history = original_seed.algorithm_history;
                        callback_seed.algorithm_history.push_back(combination.toString());
                        callback_seed.energy = new_seed.energy; // Use the same energy calculation
                        
                        on_new_coverage_(callback_seed, combination);
                    } catch (const std::exception& e) {
                        std::cerr << "[ERROR] New coverage callback error: " << e.what() << std::endl;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to create new seed: " << e.what() << std::endl;
            }
        }
        
        // Handle crash (with full error handling)
        if (result.status == ExecutionResult::Status::Crash) {
            try {
                bool is_unique = true; // crash_analyzer archived; conservatively treat all crashes as unique
                
                if (is_unique) {
                    try {
                        // Create crash seed safely
                        Seed crash_seed;
                        crash_seed.data = original_seed.data; // Use original input
                        crash_seed.coverage = result.coverage;
                        crash_seed.performance = result.performance;
                        crash_seed.created_time = std::chrono::system_clock::now();
                        crash_seed.generation = original_seed.generation + 1;
                        crash_seed.energy = 2.0; // Crash seeds have higher energy
                        
                        if (corpus_manager_) {
                            corpus_manager_->addCrashSeed(std::move(crash_seed));
                        }
                        
                        // Update stats
                        stats_.unique_crashes++;
                        stats_.last_crash_time = std::chrono::system_clock::now();
                        
                        // Safely fire callback, passing algorithm-combination info
                        if (on_crash_) {
                            try {
                                on_crash_(result, combination);
                            } catch (const std::exception& e) {
                                std::cerr << "[ERROR] Crash callback error: " << e.what() << std::endl;
                            }
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "[ERROR] Failed to create crash seed: " << e.what() << std::endl;
                    }
                }
                
                stats_.total_crashes++;
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Crash processing error: " << e.what() << std::endl;
            }
        }
        
        // Update execution stats
        stats_.total_executions++;
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] processResult fatal error: " << e.what() << std::endl;
        // Even on error, update basic stats to avoid a hard failure
        stats_.total_executions++;
    } catch (...) {
        std::cerr << "[ERROR] processResult unknown fatal error" << std::endl;
        // Even on error, update basic stats to avoid a hard failure
        stats_.total_executions++;
    }
}

// Compute combination reward score
double FuzzingEngine::calculateCombinationReward(const ExecutionResult& result, const Seed& original_seed) {
    double reward = 0.0;
    
    // Fix: more precise coverage reward calculation (weight: 0.5)
    if (result.coverage.hasNewCoverage() && result.coverage.new_edges.size() > 0) {
        // Reward based on number of new edges (log growth to avoid over-rewarding)
        double new_edges_score = std::min(1.0, std::log(result.coverage.new_edges.size() + 1) / std::log(10.0));
        
        // Reward based on coverage gain
        double gain_score = std::min(1.0, result.coverage.coverage_gain * 10.0);
        
        // Combined coverage reward
        reward += 0.5 * (0.7 * new_edges_score + 0.3 * gain_score);
    }
    
    // Crash reward (weight: 0.3)
    if (result.status == ExecutionResult::Status::Crash) {
        reward += 0.5; // crash_analyzer archived; grant crash reward directly (0.3 + 0.2)
    }
    
    // Performance reward (weight: 0.1) - further reduced weight
    double execution_speed = 1000.0 / std::max(1.0, static_cast<double>(result.performance.execution_time_ms));
    double speed_score = std::min(1.0, execution_speed / 200.0);
    reward += 0.1 * speed_score;
    
    // Size-exploration reward (weight: 0.1) - encourage exploring different input sizes
    double size_exploration_bonus = 0.0;
    size_t input_size = result.input_data.size();
    
    // Adjust reward strategy to more strongly encourage exploration of large inputs
    if (input_size > 4) {
        if (input_size >= 10 && input_size < 20) {
            size_exploration_bonus = 0.2;  // medium-size bonus
        } else if (input_size >= 20 && input_size < 50) {
            size_exploration_bonus = 0.3;  // larger-size bonus
        } else if (input_size >= 50 && input_size < 100) {
            size_exploration_bonus = 0.4;  // large-size bonus
        } else if (input_size >= 100 && input_size < 500) {
            size_exploration_bonus = 0.5;  // extra-large bonus
        } else if (input_size >= 500 && input_size < 1024) {
            size_exploration_bonus = 0.6;  // huge-size bonus
        } else if (input_size >= 1024 && input_size < 2048) {
            size_exploration_bonus = 0.7;  // very-large bonus
        } else if (input_size >= 2048) {
            size_exploration_bonus = 0.8;  // maximum-size bonus
        } else if (input_size > 4 && input_size < 10) {
            size_exploration_bonus = 0.1;  // small growth bonus
        }
    }
    
    // For very small inputs (1-3 bytes), give a small bonus to preserve diversity
    if (input_size <= 3 && input_size > 0) {
        size_exploration_bonus = 0.05;  // reduced small-input bonus
    }
    
    // Increase the weight of the size-exploration bonus
    reward += 0.15 * size_exploration_bonus;  // from 0.1 to 0.15
    
    // Keep reward within a reasonable range
    reward = std::max(0.0, std::min(1.0, reward));
    
    return reward;
}

// Update algorithm usage stats (for diversity tracking)
void FuzzingEngine::updateAlgorithmUsageStats(const AlgorithmCombination& combination) {
    std::string combo_key = combination.toString();
    
    std::lock_guard<std::mutex> lock(diversity_stats_mutex_);
    
    // Update last-used time for the combination
    last_combo_usage_[combo_key] = std::chrono::steady_clock::now();
    
    // Update usage stats for each algorithm
    for (const auto& algo_name : combination.algorithm_names) {
        algorithm_usage_stats_[algo_name]++;
        total_algorithm_uses_++;
    }
    
    // Periodically print usage stats and clean up data (every 1000 uses)
    if (total_algorithm_uses_ % 1000 == 0) {
        printAlgorithmUsageStats();
        
        // Prevent overflow: halve all counts
        for (auto& [algo, count] : algorithm_usage_stats_) {
            count /= 2;
        }
        total_algorithm_uses_ /= 2;
        
        // Clean up stale combination usage timestamps (older than 30 minutes)
        auto current_time = std::chrono::steady_clock::now();
        auto cutoff_time = current_time - std::chrono::minutes(30);
        
        for (auto it = last_combo_usage_.begin(); it != last_combo_usage_.end();) {
            if (it->second < cutoff_time) {
                it = last_combo_usage_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// Update combination performance stats
void FuzzingEngine::updateCombinationPerformance(const AlgorithmCombination& combination, double reward, const ExecutionResult& result) {
    // added: update performance via tiered scheduler (cost-aware adaptive scheduling)
    if (use_tiered_scheduler_ && tiered_scheduler_ && !combination.algorithm_names.empty()) {
        std::string algorithm_name = combination.algorithm_names[0];
        double execution_time_ms = result.performance.execution_time_ms;
        bool found_new_coverage = !result.coverage.new_edges.empty();
        tiered_scheduler_->updatePerformance(algorithm_name, execution_time_ms, found_new_coverage, reward);
    }

    // added: update performance stats via optimized Thompson Sampling (preserve dynamic learning)
    if (use_optimized_thompson_ && optimized_thompson_) {
        optimized_thompson_->updatePerformance(combination, reward);
    }

    std::string combo_key = combination.toString();

    // Record execution results via the batch algorithm selector
    // Batch selector handles Thompson Sampling updates automatically
    if (batch_selector_) {
        bool has_new_coverage = !result.coverage.new_edges.empty();
        bool crashed = (result.status == ExecutionResult::Status::Crash);
        bool decoder_success = (result.status == ExecutionResult::Status::Success);
        batch_selector_->recordExecution(reward, has_new_coverage, crashed, decoder_success);
    }
    
    // Removed: MCTS node statistics update

    // Update performance monitor statistics if available
    if (performance_monitor_) {
        try {
            performance_monitor_->recordExecution(combination, result);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Performance monitor error: " << e.what() << std::endl;
        }
    }
}

void FuzzingEngine::periodicTasks() {
    // Perform periodic maintenance tasks
    static auto last_minimization_time = std::chrono::steady_clock::now();
    static auto last_stats_print_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();

    // Periodic corpus minimization (every 5 minutes)
    auto minimization_interval = std::chrono::minutes(5);
    if (corpus_manager_ &&  // Only if corpus manager exists
        std::chrono::duration_cast<std::chrono::minutes>(now - last_minimization_time) >= minimization_interval) {

        std::cout << "[CORPUS] Starting periodic corpus minimization..." << std::endl;

        // Get current corpus stats before minimization
        auto stats_before = corpus_manager_->getCorpusStats();
        size_t corpus_size_before = stats_before.total_seeds;

        // Perform minimization
        try {
            // Use the AFL++ style minimization
            corpus_manager_->optimizeCorpusAFLStyle();

            // Get stats after minimization
            auto stats_after = corpus_manager_->getCorpusStats();
            size_t corpus_size_after = stats_after.total_seeds;

            if (corpus_size_before > corpus_size_after) {
                std::cout << "[CORPUS] Minimization complete: "
                         << corpus_size_before << " -> " << corpus_size_after
                         << " seeds (removed " << (corpus_size_before - corpus_size_after) << ")" << std::endl;
            } else {
                std::cout << "[CORPUS] Corpus already optimal, no seeds removed" << std::endl;
            }

        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Corpus minimization failed: " << e.what() << std::endl;
        }

        last_minimization_time = now;
    }

    // Periodic stats printing (every 30 seconds)
    static bool verbose_stats = false;  // Can be configured separately if needed
    if (verbose_stats &&
        std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_print_time) >= std::chrono::seconds(30)) {
        printAlgorithmUsageStats();

        // Print tiered scheduler statistics
        if (use_tiered_scheduler_ && tiered_scheduler_) {
            std::cout << tiered_scheduler_->getStatisticsReport() << std::endl;
        }

        last_stats_print_time = now;
    }
}

void FuzzingEngine::updateStats() {
    // Compute execution speed
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
    
    if (duration.count() > 0) {
        stats_.executions_per_second = stats_.total_executions / duration.count();
    }
    
    // Use RealCoverageCollector directly for accurate coverage data
    auto& real_collector = RealCoverageCollector::getInstance();
    size_t total_guards = real_collector.getTotalGuards();
    size_t covered_edges = real_collector.getCoveredEdges();
    
    // Get branch coverage info
    auto current_coverage_info = real_collector.getCurrentCoverage();
    size_t total_branches = current_coverage_info.total_branches;
    size_t covered_branches = current_coverage_info.covered_branch_count;
    
    // Remove frequent debug output to improve performance
    // Only output in verbose mode or when coverage changes
    static size_t last_covered_edges = 0;
    static size_t debug_counter = 0;
    // if ((++debug_counter % 100 == 0) ||  // Print once every 100 times
    //     (covered_edges != last_covered_edges)) {  // or when coverage changes
    //     if (covered_edges != last_covered_edges) {
    //         last_covered_edges = covered_edges;
    //         // Simplify output; remove verbose check
    //         std::cout << "[INFO] Coverage update: " << covered_edges << "/" << total_guards
    //                   << " edges covered" << std::endl;
    //     }
    // }
    
    if (total_guards > 0) {
        // Use the real coverage calculation
        double current_coverage = static_cast<double>(covered_edges) / total_guards * 100.0;
        stats_.coverage_percentage = current_coverage;
        stats_.total_coverage = covered_edges;
        
        // Add branch coverage stats using the fetched data
        stats_.total_branches = total_branches;
        stats_.covered_branches = covered_branches;
        stats_.branch_coverage_percentage = current_coverage_info.getBranchCoveragePercentage();
        
        // Debug output removed
    } else {
        // If there is no instrumentation data, use a fallback
        if (coverage_collector_) {
            stats_.coverage_percentage = coverage_collector_->getCoveragePercentage();
            stats_.total_coverage = coverage_collector_->getUniqueEdgesCount();
            std::cout << "[DEBUG] updateStats: Using backup coverage collector" << std::endl;
        } else {
            // Keep the previous coverage value; don't reset to 0
            static bool warned = false;
            if (!warned) {
                std::cout << "[WARNING] updateStats: No instrumentation data available, keeping previous coverage value" << std::endl;
                warned = true;
            }
        }
    }
}

Seed FuzzingEngine::selectSeed() {
    // AFL++-style power scheduling for better seed selection
    if (corpus_manager_) {
        // Use energy-based selection which implements power scheduling
        auto selected_seed = corpus_manager_->getNextSeed();
        if (selected_seed.has_value()) {
            auto& seed = selected_seed.value();

            // Update seed energy based on performance (power scheduling)
            updateSeedPowerSchedule(seed);

            return seed;
        }
    }

    // If the corpus manager is unavailable or has no seeds, create a default seed
    // Use a larger initial seed to explore more code paths and boundary conditions
    Seed default_seed;

    // Create a 512-byte initial seed with multiple meaningful patterns
    default_seed.data.resize(512);

    // Fill strategy: mix different data patterns to improve initial coverage
    // First 64 bytes: ASCII printable characters
    for (size_t i = 0; i < 64 && i < default_seed.data.size(); ++i) {
        default_seed.data[i] = static_cast<uint8_t>(' ' + (i % 95)); // ASCII 32-126
    }

    // Bytes 64-128: zeros and boundary values
    for (size_t i = 64; i < 128 && i < default_seed.data.size(); ++i) {
        if (i % 4 == 0) default_seed.data[i] = 0x00;
        else if (i % 4 == 1) default_seed.data[i] = 0xFF;
        else if (i % 4 == 2) default_seed.data[i] = 0x7F;
        else default_seed.data[i] = 0x80;
    }

    // Bytes 128-256: incremental sequence
    for (size_t i = 128; i < 256 && i < default_seed.data.size(); ++i) {
        default_seed.data[i] = static_cast<uint8_t>(i);
    }

    // Bytes 256-512: random but reproducible data
    std::mt19937 rng(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (size_t i = 256; i < default_seed.data.size(); ++i) {
        default_seed.data[i] = dist(rng);
    }

    default_seed.energy = 1.0;
    default_seed.generation = 0;
    default_seed.created_time = std::chrono::system_clock::now();

    return default_seed;
}

void FuzzingEngine::updateSeedPowerSchedule(Seed& seed) {
    // AFL++ power scheduling implementation
    // Adjust energy based on seed performance characteristics

    // Factor 1: Execution speed (faster seeds get more energy)
    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - seed.created_time).count();
    if (age > 0 && seed.execution_count > 0) {
        double exec_speed = static_cast<double>(seed.execution_count) / age;
        if (exec_speed > 100.0) {  // High speed seeds
            seed.energy *= 1.2;
        }
    }

    // Factor 2: Coverage contribution (seeds finding new coverage get bonus)
    if (!seed.coverage.new_edges.empty()) {
        seed.energy *= 1.5;  // Boost seeds that found new coverage
    }

    // Factor 3: Rare edge discovery (seeds covering rare edges get more energy)
    // Simplified: reward only seeds with many new edges to avoid expensive hash computation
    if (seed.coverage.new_edges.size() > 5) {
        seed.energy *= 1.3;  // 30% boost for seeds with many new edges
    } else if (seed.coverage.new_edges.size() > 2) {
        seed.energy *= 1.15;  // 15% boost for seeds with some new edges
    }

    // Factor 4: Depth factor (deeper seeds in mutation chain get less energy)
    if (seed.generation > 10) {
        seed.energy *= std::pow(0.95, seed.generation - 10);  // Decay after generation 10
    }

    // Factor 5: Size penalty (very large seeds get less energy)
    if (seed.data.size() > 10000) {
        seed.energy *= 0.8;
    } else if (seed.data.size() < 100) {
        seed.energy *= 1.1;  // Prefer smaller seeds
    }

    // Cap energy to reasonable bounds
    seed.energy = std::min(100.0, std::max(0.1, seed.energy));

    // Note: do not update energy in CorpusManager here to avoid deadlocks
    // Energy updates happen after a seed is used or during batching
}

void FuzzingEngine::registerDefaultAlgorithms() {
    // In strict algorithm-isolation mode, register only algorithms specified in the config
    if (config_.strict_algorithm_isolation) {
        std::cout << "[STRICT MODE] Only registering specified algorithms for strict isolation" << std::endl;
        
        // Collect the algorithms to register (deduplicated)
        std::set<std::string> algorithms_to_register;
        for (const auto& algo : config_.enabled_algorithms) {
            algorithms_to_register.insert(algo);
        }
        
        std::cout << "[STRICT MODE] Algorithms to register: ";
        for (const auto& algo : algorithms_to_register) {
            std::cout << algo << " ";
        }
        std::cout << std::endl;
        
        // Define the algorithm factory map
        std::map<std::string, std::function<std::shared_ptr<AlgorithmBase>()>> algorithm_factories = {
            // Active mutation algorithms (used in unified path)
            {"smart_dictionary", [this]() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<SmartDictionaryMutation>(config_.dictionary_file); }},
            {"format_aware", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<FormatAwareMutation>(); }},
            {"redqueen", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<REDQUEENMutation>(); }},
            {"cmplog", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<CmpLogMutation>(); }},
            {"runtime_dictionary", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<RuntimeDictionaryMutation>(); }},
            {"format_overflow", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<FormatOverflowMutation>(); }},
            {"structure_aware", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<StructureAwareMutation>(); }},

            // Scheduling algorithms
            {"mab_scheduler", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<MABScheduler>(); }},
            {"rl_scheduler", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<RLScheduler>(); }},
            {"round_robin_scheduler", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<RoundRobinScheduler>(); }},
            {"random_scheduler", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<RandomScheduler>(); }},

            // Optimization algorithms
            {"binary_pso", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<BinaryPSO>(); }},

            // Multi-armed bandit algorithms
            {"ucb_bandit", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<UCBBandit>(); }},
            {"epsilon_greedy", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<EpsilonGreedyBandit>(); }},
            {"contextual_ucb", []() -> std::shared_ptr<AlgorithmBase> { return std::make_shared<ContextualUCB>(); }}
        };
        
        // Register only the specified algorithms
        for (const auto& algo_name : algorithms_to_register) {
            auto it = algorithm_factories.find(algo_name);
            if (it != algorithm_factories.end()) {
                registerAlgorithm(algo_name, it->second);
                std::cout << "[STRICT MODE] Registered algorithm: " << algo_name << std::endl;
            } else {
                std::cerr << "[WARNING] Algorithm '" << algo_name << "' not found in factory map" << std::endl;
            }
        }
    } else {
        // Standard mode: register active algorithms only
        std::cout << "[Standard Mode] Registering available algorithms" << std::endl;

        // Active mutation algorithms (used in unified path)
        registerAlgorithm("smart_dictionary", [this]() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<SmartDictionaryMutation>(config_.dictionary_file);
        });
        registerAlgorithm("format_aware", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<FormatAwareMutation>();
        });
        registerAlgorithm("redqueen", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<REDQUEENMutation>();
        });
        registerAlgorithm("cmplog", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<CmpLogMutation>();
        });
        registerAlgorithm("runtime_dictionary", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<RuntimeDictionaryMutation>();
        });
        registerAlgorithm("format_overflow", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<FormatOverflowMutation>();
        });
        registerAlgorithm("structure_aware", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<StructureAwareMutation>();
        });

        // Scheduler algorithms (archived)
        // Multi-armed bandit algorithms
        registerAlgorithm("ucb_bandit", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<UCBBandit>();
        });
        registerAlgorithm("epsilon_greedy", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<EpsilonGreedyBandit>();
        });
        registerAlgorithm("contextual_ucb", []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<ContextualUCB>();
        });
    }
    
    // Enable algorithms specified in the config (filtering out schedulers and feedback analyzers)
    std::cout << "[INFO] Enabling configured algorithms..." << std::endl;
    std::cout << "[DEBUG] config_.enabled_algorithms.size() = " << config_.enabled_algorithms.size() << std::endl;
    std::cout << "[DEBUG] config_.enable_dynamic_combination = " << config_.enable_dynamic_combination << std::endl;

    for (const auto& algo_name : config_.enabled_algorithms) {
        // Use AlgoConfig::isEnabled() for centralized filtering (automatically excludes schedulers/feedback analyzers, etc.)
        if (!AlgoConfig::isEnabled(algo_name)) {
            // std::cout << "[INFO] Skipping " << algo_name << " (not enabled in AlgorithmConfig)" << std::endl;
            continue;
        }
        std::cout << "[INFO] Enabling algorithm: " << algo_name << std::endl;
        enableAlgorithm(algo_name);
    }
    
    // Enable all registered algorithms only when none are specified AND dynamic combination is enabled
    // If dynamic combination is disabled (i.e., fixed combinations), do not enable all algorithms
    if (config_.enabled_algorithms.empty() && config_.enable_dynamic_combination) {
        std::cout << "[INFO] No algorithms specified in config and dynamic combination enabled, enabling all registered algorithms" << std::endl;

        // Enable all registered algorithms (from AlgorithmConfig)
        std::vector<std::string> all_registered_algorithms = AlgoConfig::getAllEnabled();

        for (const auto& algo_name : all_registered_algorithms) {
            enableAlgorithm(algo_name);
        }
    } else if (config_.enabled_algorithms.empty() && !config_.enable_dynamic_combination) {
        std::cout << "[WARNING] No algorithms specified in config and dynamic combination disabled. This may indicate a configuration error." << std::endl;
        std::cout << "[WARNING] Fixed combination mode requires explicit algorithm specification." << std::endl;
    } else {
        std::cout << "[INFO] Algorithm enablement completed. Total enabled: " << config_.enabled_algorithms.size() << std::endl;
    }
}

// Forward declaration for enhanced combination executor
std::vector<uint8_t> applyEnhancedAlgorithmCombination(
    FuzzingEngine* engine,
    const std::vector<uint8_t>& input,
    const AlgorithmCombination& combination,
    ThreadLocalContext& local_context);

std::vector<uint8_t> FuzzingEngine::applyAlgorithmCombination(
    const std::vector<uint8_t>& input,
    const AlgorithmCombination& combination,
    ThreadLocalContext& local_context) {

    // Always try to use enhanced version first
    static bool use_enhanced = true;
    static bool enhanced_available = true;

	    if (use_enhanced && enhanced_available) {
	        try {
	            auto result = applyEnhancedAlgorithmCombination(this, input, combination, local_context);
	            postProcessMutatedInput(input, result, local_context);
	            return result;
	        } catch (const std::exception& e) {
	            std::cerr << "[WARNING] Enhanced combination failed, falling back to standard: " << e.what() << std::endl;
	            enhanced_available = false;
	        }
	    }

    // Fallback to original implementation
    std::vector<uint8_t> result = input;

    try {
        if (combination.combination_mode == "sequential") {
            // Execute the algorithm combination sequentially
            for (const auto& algorithm_name : combination.algorithm_names) {
                result = applySingleAlgorithm(result, algorithm_name, local_context);
            }
        } else if (combination.combination_mode == "parallel") {
            // "Parallel" mode degrades to quickly selecting a single algorithm at random to avoid overhead from multiple mutations
            if (!combination.algorithm_names.empty()) {
                static thread_local std::mt19937 gen(std::random_device{}());
                std::uniform_int_distribution<size_t> algo_dist(
                    0, combination.algorithm_names.size() - 1);
                size_t selected_idx = algo_dist(gen);
                result = applySingleAlgorithm(result, combination.algorithm_names[selected_idx], local_context);
            }
        } else if (combination.combination_mode == "weighted") {
            // Choose one algorithm to execute using weights
            if (!combination.algorithm_names.empty()) {
                double total_weight = 0.0;
                for (const auto& [algo, weight] : combination.weights) {
                    total_weight += weight;
                }
                
                if (total_weight > 0.0) {
                    std::uniform_real_distribution<double> weight_dist(0.0, total_weight);
                    static std::random_device rd;
                    static std::mt19937 gen(rd());
                    double random_value = weight_dist(gen);
                    
                    double cumulative_weight = 0.0;
                    for (const auto& algorithm_name : combination.algorithm_names) {
                        auto weight_it = combination.weights.find(algorithm_name);
                        double weight = weight_it != combination.weights.end() ? weight_it->second : 1.0;
                        cumulative_weight += weight;
                        
                        if (random_value <= cumulative_weight) {
                            result = applySingleAlgorithm(result, algorithm_name, local_context);
                            break;
                        }
                    }
                } else {
                    // If there are no weights, pick one at random
                    std::uniform_int_distribution<size_t> algo_dist(0, combination.algorithm_names.size() - 1);
                    static std::random_device rd;
                    static std::mt19937 gen(rd());
                    size_t selected_idx = algo_dist(gen);
                    result = applySingleAlgorithm(result, combination.algorithm_names[selected_idx], local_context);
                }
            }
        } else {
            // Default: pick one algorithm at random
            if (!combination.algorithm_names.empty()) {
                std::uniform_int_distribution<size_t> algo_dist(0, combination.algorithm_names.size() - 1);
                static std::random_device rd;
                static std::mt19937 gen(rd());
                size_t selected_idx = algo_dist(gen);
                result = applySingleAlgorithm(result, combination.algorithm_names[selected_idx], local_context);
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to apply algorithm combination: " << e.what() << std::endl;
        // On error, apply at least one basic mutation
        result = applySingleAlgorithm(result, "havoc", local_context);
    }
    
		    postProcessMutatedInput(input, result, local_context);
		    return result;
		}

void FuzzingEngine::postProcessMutatedInput(
    const std::vector<uint8_t>& original_input,
    std::vector<uint8_t>& mutated_input,
    ThreadLocalContext& local_context) {

    if (original_input.empty()) return;

    // Clamp to configured hard limit (safety + keeps execution stable across benchmarks).
    if (config_.max_input_size > 0 && mutated_input.size() > config_.max_input_size) {
        mutated_input.resize(config_.max_input_size);
    }

    // Avoid runaway growth relative to the seed (helps parsers progress).
    {
        const size_t rel_cap = std::max<size_t>(4096, original_input.size() * 4);
        if (mutated_input.size() > rel_cap) {
            mutated_input.resize(rel_cap);
        }
    }

    const bool original_is_text = looks_text(original_input);

    // Soft pull towards globally "productive" lengths (online learning).
    if (uint32_t preferred = preferred_length_.load(std::memory_order_relaxed); preferred != 0) {
        const size_t p = static_cast<size_t>(preferred);
        if (p > 0) {
            if (mutated_input.size() > p * 8 && mutated_input.size() > 8192) {
                const size_t target = std::max<size_t>(p * 4, 4096);
                if (target < mutated_input.size()) mutated_input.resize(target);
            } else if (mutated_input.size() < p / 8 && mutated_input.size() < 32) {
                const size_t target = std::min<size_t>(p, 4096);
                if (target > mutated_input.size()) {
                    const std::vector<uint8_t>& src = mutated_input.empty() ? original_input : mutated_input;
                    if (!src.empty()) {
                        mutated_input.reserve(target);
                        while (mutated_input.size() < target) {
                            const size_t remaining = target - mutated_input.size();
                            const size_t to_copy = std::min(remaining, src.size());
                            mutated_input.insert(mutated_input.end(), src.begin(), src.begin() + to_copy);
                        }
                    }
                }
            }
        }
    }

    // Lightweight "repair":
    // - For binary-ish inputs: preserve a small protected prefix from the seed to keep magic bytes stable.
    // - For text-ish inputs: reduce NUL/control-byte spam to keep parsers making progress.
    if (!original_is_text) {
        const uint32_t protect_pct = std::min<uint32_t>(100, getenv_u32("TRIOFUZZ_PROTECT_PREFIX_PCT", 90));
        thread_local std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<int> protect_pick(0, 99);
        if (protect_pct == 0 || protect_pick(gen) >= static_cast<int>(protect_pct)) {
            return;
        }

        auto hb_opt = local_context.getHintBus();
        if (hb_opt.has_value() && !hb_opt->protected_mask.empty()) {
            const auto& mask = hb_opt->protected_mask;
            if (mutated_input.size() < mask.size()) {
                mutated_input.resize(mask.size(), 0);
            }
            const size_t n = std::min({mutated_input.size(), original_input.size(), mask.size()});
            for (size_t i = 0; i < n; ++i) {
                if (mask[i]) mutated_input[i] = original_input[i];
            }
        } else {
            const size_t protect_len = std::min<size_t>(
                std::max<uint32_t>(1, getenv_u32("TRIOFUZZ_PROTECT_PREFIX_LEN", 8)),
                original_input.size());
            if (mutated_input.size() < protect_len) {
                mutated_input.resize(protect_len, 0);
            }
            for (size_t i = 0; i < protect_len; ++i) {
                mutated_input[i] = original_input[i];
            }
        }
    } else if (!mutated_input.empty()) {
        const size_t sample = std::min<size_t>(mutated_input.size(), 256);
        size_t printable = 0;
        size_t nul = 0;
        for (size_t i = 0; i < sample; ++i) {
            unsigned char c = static_cast<unsigned char>(mutated_input[i]);
            if (c == 0) nul++;
            if (std::isprint(c) || std::isspace(c)) printable++;
        }
        const bool degraded = (printable * 100 < sample * 70) || (nul * 10 >= sample);
        if (degraded) {
            thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<int> p(0, 99);
            // Apply only sometimes to keep diversity.
            if (p(gen) < 50) {
                static constexpr char kRepl[] =
                    " \t\r\n"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789_-=+*/<>(){}[];,:.\"'";
                std::uniform_int_distribution<size_t> rep(0, sizeof(kRepl) - 2);
                for (size_t i = 0; i < sample; ++i) {
                    unsigned char c = static_cast<unsigned char>(mutated_input[i]);
                    if (c == 0 || (c < 0x20 && !std::isspace(c)) || c >= 0x80) {
                        mutated_input[i] = static_cast<uint8_t>(kRepl[rep(gen)]);
                    }
                }
            }
        }
    }
}

	std::vector<uint8_t> FuzzingEngine::applySingleAlgorithm(
	    const std::vector<uint8_t>& input,
	    const std::string& algorithm_name,
	    ThreadLocalContext& local_context) {

    // Fast path: start from the input directly to avoid unnecessary copies
    std::vector<uint8_t> result = input;

    // Parse algorithm name (ignore parameters for performance)
    std::string base_algorithm_name = algorithm_name;
    size_t colon_pos = algorithm_name.find(':');
    if (colon_pos != std::string::npos) {
        base_algorithm_name = algorithm_name.substr(0, colon_pos);
    }

    try {
        // === High-performance algorithm execution: use a thread-local object pool ===

        // Thread-local pool of algorithm objects (pre-allocate common algorithms)
        thread_local struct AlgorithmPool {
            // Active mutation algorithms used in the unified path
            FormatAwareMutation format_aware;
            SmartDictionaryMutation smart_dictionary{""};

            // Lazy-initialized analysis algorithms
            std::unique_ptr<REDQUEENMutation> redqueen;
            std::unique_ptr<CmpLogMutation> cmplog;
            std::unique_ptr<RuntimeDictionaryMutation> runtime_dictionary;
            std::unique_ptr<FormatOverflowMutation> format_overflow;

            // AFL++ Individual Mutations (37 operators for Thompson Sampling comparison)
            MutFlipbit mut_flipbit;
            MutInteresting8 mut_interesting8;
            MutInteresting16 mut_interesting16;
            MutInteresting16BE mut_interesting16be;
            MutInteresting32 mut_interesting32;
            MutInteresting32BE mut_interesting32be;
            MutArith8Sub mut_arith8_sub;
            MutArith8Add mut_arith8_add;
            MutArith16Sub mut_arith16_sub;
            MutArith16BESub mut_arith16be_sub;
            MutArith16Add mut_arith16_add;
            MutArith16BEAdd mut_arith16be_add;
            MutArith32Sub mut_arith32_sub;
            MutArith32BESub mut_arith32be_sub;
            MutArith32Add mut_arith32_add;
            MutArith32BEAdd mut_arith32be_add;
            MutRand8 mut_rand8;
            MutCloneCopy mut_clone_copy;
            MutCloneFixed mut_clone_fixed;
            MutOverwriteCopy mut_overwrite_copy;
            MutOverwriteFixed mut_overwrite_fixed;
            MutByteAdd mut_byteadd;
            MutByteSub mut_bytesub;
            MutFlip8 mut_flip8;
            MutSwitch mut_switch;
            MutDel mut_del;
            MutShuffle mut_shuffle;
            MutDelOne mut_delone;
            MutInsertOne mut_insertone;
            MutAsciiNum mut_asciinum;
            MutInsertAsciiNum mut_insertasciinum;
            MutExtraOverwrite mut_extra_overwrite;
            MutExtraInsert mut_extra_insert;
            MutAutoExtraOverwrite mut_auto_extra_overwrite;
            MutAutoExtraInsert mut_auto_extra_insert;
            MutSpliceOverwrite mut_splice_overwrite;
            MutSpliceInsert mut_splice_insert;

            // NEW: Advanced mutation operators for bug finding
            MutArith32Large mut_arith32_large;      // Large-step arithmetic for overflow
            MutOverflow32 mut_overflow32;            // Integer overflow boundary values
            StructureAwareMutation structure_aware;  // Structure-aware with PNG CRC fix

            // AFL++ MOpt stage mutations (operator_num=19)
            MOptFlip1 mopt_flip1;
            MOptFlip2 mopt_flip2;
            MOptFlip4 mopt_flip4;
            MOptFlip8 mopt_flip8;
            MOptFlip16 mopt_flip16;
            MOptFlip32 mopt_flip32;
            MOptArith8 mopt_arith8;
            MOptArith16 mopt_arith16;
            MOptArith32 mopt_arith32;
            MOptInterest8 mopt_interest8;
            MOptInterest16 mopt_interest16;
            MOptInterest32 mopt_interest32;
            MOptRand8 mopt_rand8;
            MOptDeleteByte mopt_deletebyte;
            MOptClone75 mopt_clone75;
            MOptOverwrite75 mopt_overwrite75;
            MOptOverwriteExtra mopt_overwrite_extra;
            MOptInsertExtra mopt_insert_extra;
            MOptSplice mopt_splice;
        } pool;

        // If an external dictionary file is provided, load it once before this thread's first use
        {
            static thread_local bool smart_dict_initialized = false;
            if (!smart_dict_initialized) {
                try {
                    if (!config_.dictionary_file.empty()) {
                        pool.smart_dictionary.setDictionaryFile(config_.dictionary_file);

                        // Parse AFL-style dictionary entries so EXTRA_* mutations
                        // (both TS-style and MOpt-stage) have real tokens.
                        std::vector<std::vector<uint8_t>> dict_tokens;
                        std::ifstream dict_file(config_.dictionary_file);
                        if (dict_file.is_open()) {
                            std::function<std::vector<uint8_t>(const std::string&)> parse_line;
                            parse_line = [&](const std::string& line) -> std::vector<uint8_t> {
                                std::vector<uint8_t> result_bytes;

                                std::string trimmed = line;
                                trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                                if (!trimmed.empty()) {
                                    trimmed.erase(trimmed.find_last_not_of(" \t") + 1);
                                }
                                if (trimmed.empty() || trimmed[0] == '#') return result_bytes;

                                if ((trimmed.front() == '"' && trimmed.back() == '"') ||
                                    (trimmed.front() == '\'' && trimmed.back() == '\'')) {
                                    std::string content = trimmed.substr(1, trimmed.length() - 2);
                                    for (size_t i = 0; i < content.length(); ++i) {
                                        if (content[i] == '\\' && i + 1 < content.length()) {
                                            switch (content[i + 1]) {
                                                case 'n': result_bytes.push_back('\n'); i++; break;
                                                case 't': result_bytes.push_back('\t'); i++; break;
                                                case 'r': result_bytes.push_back('\r'); i++; break;
                                                case '\\': result_bytes.push_back('\\'); i++; break;
                                                case '"': result_bytes.push_back('"'); i++; break;
                                                case '\'': result_bytes.push_back('\''); i++; break;
                                                case 'x': {
                                                    if (i + 3 < content.length()) {
                                                        std::string hex_str = content.substr(i + 2, 2);
                                                        try {
                                                            uint8_t hex_value = static_cast<uint8_t>(
                                                                std::stoi(hex_str, nullptr, 16));
                                                            result_bytes.push_back(hex_value);
                                                            i += 3;
                                                        } catch (...) {
                                                            result_bytes.push_back(static_cast<uint8_t>(content[i]));
                                                        }
                                                    } else {
                                                        result_bytes.push_back(static_cast<uint8_t>(content[i]));
                                                    }
                                                    break;
                                                }
                                                default:
                                                    result_bytes.push_back(static_cast<uint8_t>(content[i]));
                                                    break;
                                            }
                                        } else {
                                            result_bytes.push_back(static_cast<uint8_t>(content[i]));
                                        }
                                    }
                                    return result_bytes;
                                }

                                size_t eq_pos = trimmed.find('=');
                                if (eq_pos != std::string::npos && eq_pos + 1 < trimmed.length()) {
                                    std::string value_part = trimmed.substr(eq_pos + 1);
                                    return parse_line(value_part);
                                }

                                for (char c : trimmed) result_bytes.push_back(static_cast<uint8_t>(c));
                                return result_bytes;
                            };

                            std::string line;
                            while (std::getline(dict_file, line)) {
                                auto token = parse_line(line);
                                if (!token.empty()) dict_tokens.push_back(std::move(token));
                            }
                        }

                        if (!dict_tokens.empty()) {
                            pool.mut_extra_overwrite.setExtras(dict_tokens);
                            pool.mut_extra_insert.setExtras(dict_tokens);
                            pool.mopt_overwrite_extra.setExtras(dict_tokens);
                            pool.mopt_insert_extra.setExtras(dict_tokens);
                        }
                    }
                } catch (...) {
                    // Dictionary load failure should not break the mutation flow; degrade silently
                }
                smart_dict_initialized = true;
            }
	        }

	        // Refresh auto-dictionary-backed tokens for EXTRA_AUTO_* and MOpt *_extra operators.
	        {
	            static thread_local uint64_t last_epoch = 0;
	            uint64_t epoch = auto_dictionary_epoch_.load(std::memory_order_relaxed);
	            if (epoch != last_epoch) {
	                std::vector<std::vector<uint8_t>> auto_tokens;
	                if (global_context_) {
	                    global_context_->withData<std::vector<std::vector<uint8_t>>>(
	                        "auto_dictionary",
	                        [&](const std::vector<std::vector<uint8_t>>& dict) {
	                            auto_tokens = dict;
	                            return 0;
	                        });
	                }
	                pool.mut_auto_extra_overwrite.setAutoExtras(auto_tokens);
	                pool.mut_auto_extra_insert.setAutoExtras(auto_tokens);
	                pool.mopt_overwrite_extra.setAutoExtras(auto_tokens);
	                pool.mopt_insert_extra.setAutoExtras(auto_tokens);
	                last_epoch = epoch;
	            }
	        }

		        // Use switch/case instead of an if-else chain (compiler can optimize into a jump table)
	        static const std::unordered_map<std::string, int> algo_map = {
            // Active algorithms used in unified path
            {"format_aware", 21},
            {"smart_dictionary", 7},
            {"runtime_dictionary", 47},
            {"format_overflow", 48},
            {"redqueen", 14},
            {"cmplog", 15}, {"cmplog_mutation", 15},

            // AFL++ Individual Mutations (37 operators, IDs 100-136)
            {"mut_flipbit", 100}, {"mut_interesting8", 101}, {"mut_interesting16", 102},
            {"mut_interesting16be", 103}, {"mut_interesting32", 104}, {"mut_interesting32be", 105},
            {"mut_arith8_sub", 106}, {"mut_arith8_add", 107}, {"mut_arith16_sub", 108},
            {"mut_arith16be_sub", 109}, {"mut_arith16_add", 110}, {"mut_arith16be_add", 111},
            {"mut_arith32_sub", 112}, {"mut_arith32be_sub", 113}, {"mut_arith32_add", 114},
            {"mut_arith32be_add", 115}, {"mut_rand8", 116}, {"mut_clone_copy", 117},
            {"mut_clone_fixed", 118}, {"mut_overwrite_copy", 119}, {"mut_overwrite_fixed", 120},
            {"mut_byteadd", 121}, {"mut_bytesub", 122}, {"mut_flip8", 123},
            {"mut_switch", 124}, {"mut_del", 125}, {"mut_shuffle", 126},
            {"mut_delone", 127}, {"mut_insertone", 128}, {"mut_asciinum", 129},
            {"mut_insertasciinum", 130}, {"mut_extra_overwrite", 131}, {"mut_extra_insert", 132},
            {"mut_auto_extra_overwrite", 133}, {"mut_auto_extra_insert", 134},
            {"mut_splice_overwrite", 135}, {"mut_splice_insert", 136},

            // NEW: Advanced mutation operators for bug finding (IDs 137-139)
            {"mut_arith32_large", 137}, {"mut_overflow32", 138}, {"structure_aware", 139},

            // AFL++ MOpt stage mutations (19 operators, IDs 200-218)
            {"mopt_flip1", 200}, {"mopt_flip2", 201}, {"mopt_flip4", 202},
            {"mopt_flip8", 203}, {"mopt_flip16", 204}, {"mopt_flip32", 205},
            {"mopt_arith8", 206}, {"mopt_arith16", 207}, {"mopt_arith32", 208},
            {"mopt_interest8", 209}, {"mopt_interest16", 210}, {"mopt_interest32", 211},
            {"mopt_rand8", 212}, {"mopt_deletebyte", 213}, {"mopt_clone75", 214},
            {"mopt_overwrite75", 215}, {"mopt_overwrite_extra", 216}, {"mopt_insert_extra", 217},
            {"mopt_splice", 218}
        };

        auto it = algo_map.find(base_algorithm_name);
        if (it != algo_map.end()) {
            switch (it->second) {
                // Active algorithms used in unified path
                case 7: result = pool.smart_dictionary.execute(result, *global_context_); break;
                case 14: // redqueen
                    if (!pool.redqueen) pool.redqueen = std::make_unique<REDQUEENMutation>();
                    result = pool.redqueen->execute(result, *global_context_);
                    break;
                case 15: // cmplog
                    if (!pool.cmplog) pool.cmplog = std::make_unique<CmpLogMutation>();
                    result = pool.cmplog->execute(result, *global_context_);
                    break;
                case 21: // format_aware
                    result = pool.format_aware.execute(result, *global_context_);
                    break;
                case 47: // runtime_dictionary
                    if (!pool.runtime_dictionary) pool.runtime_dictionary = std::make_unique<RuntimeDictionaryMutation>();
                    result = pool.runtime_dictionary->execute(result, *global_context_);
                    break;
                case 48: // format_overflow
                    if (!pool.format_overflow) pool.format_overflow = std::make_unique<FormatOverflowMutation>();
                    result = pool.format_overflow->execute(result, *global_context_);
                    break;

                // AFL++ Individual Mutations (37 operators, IDs 100-136)
                case 100: result = pool.mut_flipbit.execute(result, *global_context_); break;
                case 101: result = pool.mut_interesting8.execute(result, *global_context_); break;
                case 102: result = pool.mut_interesting16.execute(result, *global_context_); break;
                case 103: result = pool.mut_interesting16be.execute(result, *global_context_); break;
                case 104: result = pool.mut_interesting32.execute(result, *global_context_); break;
                case 105: result = pool.mut_interesting32be.execute(result, *global_context_); break;
                case 106: result = pool.mut_arith8_sub.execute(result, *global_context_); break;
                case 107: result = pool.mut_arith8_add.execute(result, *global_context_); break;
                case 108: result = pool.mut_arith16_sub.execute(result, *global_context_); break;
                case 109: result = pool.mut_arith16be_sub.execute(result, *global_context_); break;
                case 110: result = pool.mut_arith16_add.execute(result, *global_context_); break;
                case 111: result = pool.mut_arith16be_add.execute(result, *global_context_); break;
                case 112: result = pool.mut_arith32_sub.execute(result, *global_context_); break;
                case 113: result = pool.mut_arith32be_sub.execute(result, *global_context_); break;
                case 114: result = pool.mut_arith32_add.execute(result, *global_context_); break;
                case 115: result = pool.mut_arith32be_add.execute(result, *global_context_); break;
                case 116: result = pool.mut_rand8.execute(result, *global_context_); break;
                case 117: result = pool.mut_clone_copy.execute(result, *global_context_); break;
                case 118: result = pool.mut_clone_fixed.execute(result, *global_context_); break;
                case 119: result = pool.mut_overwrite_copy.execute(result, *global_context_); break;
                case 120: result = pool.mut_overwrite_fixed.execute(result, *global_context_); break;
                case 121: result = pool.mut_byteadd.execute(result, *global_context_); break;
                case 122: result = pool.mut_bytesub.execute(result, *global_context_); break;
                case 123: result = pool.mut_flip8.execute(result, *global_context_); break;
                case 124: result = pool.mut_switch.execute(result, *global_context_); break;
                case 125: result = pool.mut_del.execute(result, *global_context_); break;
                case 126: result = pool.mut_shuffle.execute(result, *global_context_); break;
                case 127: result = pool.mut_delone.execute(result, *global_context_); break;
                case 128: result = pool.mut_insertone.execute(result, *global_context_); break;
                case 129: result = pool.mut_asciinum.execute(result, *global_context_); break;
                case 130: result = pool.mut_insertasciinum.execute(result, *global_context_); break;
                case 131: result = pool.mut_extra_overwrite.execute(result, *global_context_); break;
                case 132: result = pool.mut_extra_insert.execute(result, *global_context_); break;
                case 133: result = pool.mut_auto_extra_overwrite.execute(result, *global_context_); break;
                case 134: result = pool.mut_auto_extra_insert.execute(result, *global_context_); break;
                case 135: result = pool.mut_splice_overwrite.execute(result, *global_context_); break;
                case 136: result = pool.mut_splice_insert.execute(result, *global_context_); break;

                // NEW: Advanced mutation operators for bug finding (IDs 137-139)
                case 137: result = pool.mut_arith32_large.execute(result, *global_context_); break;
                case 138: result = pool.mut_overflow32.execute(result, *global_context_); break;
                case 139: result = pool.structure_aware.execute(result, *global_context_); break;

                // AFL++ MOpt stage mutations (19 operators, IDs 200-218)
                case 200: result = pool.mopt_flip1.execute(result, *global_context_); break;
                case 201: result = pool.mopt_flip2.execute(result, *global_context_); break;
                case 202: result = pool.mopt_flip4.execute(result, *global_context_); break;
                case 203: result = pool.mopt_flip8.execute(result, *global_context_); break;
                case 204: result = pool.mopt_flip16.execute(result, *global_context_); break;
                case 205: result = pool.mopt_flip32.execute(result, *global_context_); break;
                case 206: result = pool.mopt_arith8.execute(result, *global_context_); break;
                case 207: result = pool.mopt_arith16.execute(result, *global_context_); break;
                case 208: result = pool.mopt_arith32.execute(result, *global_context_); break;
                case 209: result = pool.mopt_interest8.execute(result, *global_context_); break;
                case 210: result = pool.mopt_interest16.execute(result, *global_context_); break;
                case 211: result = pool.mopt_interest32.execute(result, *global_context_); break;
                case 212: result = pool.mopt_rand8.execute(result, *global_context_); break;
                case 213: result = pool.mopt_deletebyte.execute(result, *global_context_); break;
                case 214: result = pool.mopt_clone75.execute(result, *global_context_); break;
                case 215: result = pool.mopt_overwrite75.execute(result, *global_context_); break;
                case 216: result = pool.mopt_overwrite_extra.execute(result, *global_context_); break;
                case 217: result = pool.mopt_insert_extra.execute(result, *global_context_); break;
                case 218: result = pool.mopt_splice.execute(result, *global_context_); break;

                default:
                    // fallback: apply a single bit flip
                    if (!result.empty()) {
                        thread_local std::mt19937 fb_gen(std::random_device{}());
                        std::uniform_int_distribution<size_t> fb_pos(0, result.size() - 1);
                        result[fb_pos(fb_gen)] ^= (1 << (fb_gen() & 7));
                    }
                    break;
            }
        } else {
            // Unknown algorithm name - log once and apply minimal mutation
            bool should_log = false;
            {
                std::lock_guard<std::mutex> lock(logged_algorithms_mutex_);
                if (logged_unknown_algorithms_.find(base_algorithm_name) == logged_unknown_algorithms_.end() && !base_algorithm_name.empty()) {
                    logged_unknown_algorithms_.insert(base_algorithm_name);
                    should_log = true;
                }
            }
            if (should_log) {
                std::cerr << "[WARNING] Unknown algorithm: " << base_algorithm_name << std::endl;
            }
            if (!result.empty()) {
                thread_local std::mt19937 fb_gen(std::random_device{}());
                std::uniform_int_distribution<size_t> fb_pos(0, result.size() - 1);
                result[fb_pos(fb_gen)] ^= (1 << (fb_gen() & 7));
            }
        }
        
    } catch (const std::exception& e) {
        // Handle errors silently to avoid logging overhead
        // Return a lightly mutated input
        if (!result.empty()) {
            thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
            result[pos_dist(gen)] ^= (1 << (gen() & 7));  // fast bit flip
        }
    }
    
    return result;
}

// Detect whether the target needs structured inputs (by analyzing seed characteristics)
bool triofuzz::FuzzingEngine::detectStructuredInputTarget() const {
    // Inspect seed characteristics to decide whether it is a structured format
    if (!corpus_manager_) return false;

    // Try to grab a few seeds for analysis
    std::vector<Seed> seeds;
    for (size_t i = 0; i < 5; ++i) {
        auto seed_opt = corpus_manager_->getRandomSeed();
        if (seed_opt.has_value()) {
            seeds.push_back(seed_opt.value());
        }
    }
    if (seeds.empty()) return false;

    // Analyze the first few seeds
    size_t structured_count = 0;
    size_t check_limit = seeds.size();

    for (size_t i = 0; i < check_limit; ++i) {
        const auto& data = seeds[i].data;
        if (data.size() < 4) continue;

        // Check common file-format magic numbers
        bool is_structured = false;

        // Image formats
        if ((data[0] == 0xFF && data[1] == 0xD8) || // JPEG
            (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) || // PNG
            (data[0] == 'G' && data[1] == 'I' && data[2] == 'F') || // GIF
            (data[0] == 'B' && data[1] == 'M')) { // BMP
            is_structured = true;
        }

        // Document formats
        if ((data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) || // PDF
            (data[0] == 0x50 && data[1] == 0x4B) || // ZIP/DOCX/XLSX
            (data[0] == 0xD0 && data[1] == 0xCF)) { // DOC/XLS
            is_structured = true;
        }

        // ICC Profile (acsp signature at offset 36)
        if (data.size() >= 40 && data[36] == 'a' && data[37] == 'c' &&
            data[38] == 's' && data[39] == 'p') {
            is_structured = true;
        }

        // Audio/video formats
        if ((data[0] == 'O' && data[1] == 'g' && data[2] == 'g' && data[3] == 'S') || // OGG
            (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 &&
             (data[3] == 0x18 || data[3] == 0x20) && data[4] == 'f' && data[5] == 't' &&
             data[6] == 'y' && data[7] == 'p') || // MP4
            (data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F')) { // RIFF/WAV/AVI
            is_structured = true;
        }

        // Check for many printable characters (likely text format)
        size_t printable_count = 0;
        size_t check_bytes = std::min(size_t(100), data.size());
        for (size_t j = 0; j < check_bytes; ++j) {
            if (std::isprint(data[j]) || std::isspace(data[j])) {
                printable_count++;
            }
        }
        if (printable_count > check_bytes * 0.8) {
            // Check if it's structured text (JSON, XML, HTML, etc.)
            std::string start(data.begin(), data.begin() + std::min(size_t(20), data.size()));
            if (start.find("{") != std::string::npos ||
                start.find("<") != std::string::npos ||
                start.find("[") != std::string::npos) {
                is_structured = true;
            }
        }

        if (is_structured) structured_count++;
    }

    // If more than 60% of seeds are structured, assume the target needs structured inputs
    return structured_count > check_limit * 0.6;
}

// Smart seed initialization for FuzzingEngine
void triofuzz::FuzzingEngine::initializeSmartSeeds() {
    static bool smart_seeds_disabled = (std::getenv("triofuzz_DISABLE_SMART_SEEDS") != nullptr);
    if (smart_seeds_disabled) {
        static bool logged = false;
        if (!logged) {
            std::cout << "[INFO] Smart seed initialization disabled (triofuzz_DISABLE_SMART_SEEDS=1)" << std::endl;
            logged = true;
        }
        return;
    }

    std::cout << "[INFO] Initializing smart seeds with comprehensive size coverage..." << std::endl;

    std::vector<std::vector<uint8_t>> basic_seeds;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);

    // Helper: generate a random seed of a given size with multiple patterns
    auto generate_seed = [&](size_t size, const std::string& pattern = "mixed") -> std::vector<uint8_t> {
        std::vector<uint8_t> seed(size);

        if (pattern == "zero") {
            std::fill(seed.begin(), seed.end(), 0x00);
        } else if (pattern == "one") {
            std::fill(seed.begin(), seed.end(), 0xFF);
        } else if (pattern == "ascii") {
            for (size_t i = 0; i < size; ++i) {
                seed[i] = static_cast<uint8_t>(' ' + (i % 95)); // ASCII 32-126
            }
        } else if (pattern == "inc") {
            for (size_t i = 0; i < size; ++i) {
                seed[i] = static_cast<uint8_t>(i % 256);
            }
        } else { // "mixed" - mixed mode
            for (size_t i = 0; i < size; ++i) {
                seed[i] = byte_dist(gen);
            }
        }

        return seed;
    };

    // 1. Tiny sizes (1-16 bytes) - cover all possibilities
    for (size_t size = 1; size <= 16; ++size) {
        basic_seeds.push_back(generate_seed(size, "mixed"));
    }

    // 2. Power-of-two boundaries and neighbors (important alignment boundaries)
    std::vector<size_t> power_of_two_sizes = {
        16, 31, 32, 33,        // 32-byte boundary
        63, 64, 65,            // 64-byte boundary (cache line)
        127, 128, 129,         // 128 bytes
        255, 256, 257,         // 256 bytes
        511, 512, 513,         // 512 bytes
        1023, 1024, 1025,      // 1KB
        2047, 2048, 2049,      // 2KB
        4095, 4096, 4097,      // 4KB (page size)
        8191, 8192, 8193,      // 8KB
        16383, 16384, 16385    // 16KB
    };

    for (size_t size : power_of_two_sizes) {
        if (size <= config_.max_input_size) {
            basic_seeds.push_back(generate_seed(size, "mixed"));
        }
    }

    // 3. Special boundary sizes (common length checkpoints)
    std::vector<size_t> special_sizes = {
        3, 7, 15, 17, 24, 31, 47, 63, 95, 127, 191, 250, 255, 300, 500,
        600, 700, 800, 900, 1000, 1100, 1200, 1500, 1800, 2500, 3000,
        3500, 5000, 6000, 7000, 10000, 12000, 15000, 20000
    };

    for (size_t size : special_sizes) {
        if (size <= config_.max_input_size) {
            basic_seeds.push_back(generate_seed(size, "mixed"));
        }
    }

    // 4. Patterned seeds (a few representative sizes per pattern)
    std::vector<size_t> pattern_sizes = {1, 8, 64, 256, 1024, 4096};
    std::vector<std::string> patterns = {"zero", "one", "ascii", "inc"};

    for (size_t size : pattern_sizes) {
        if (size <= config_.max_input_size) {
            for (const auto& pattern : patterns) {
                basic_seeds.push_back(generate_seed(size, pattern));
            }
        }
    }

    // 5. Randomly distributed sizes (fill gaps)
    std::uniform_int_distribution<size_t> size_dist(1, std::min<size_t>(config_.max_input_size, 32768));
    for (int i = 0; i < 20; ++i) {
        size_t random_size = size_dist(gen);
        basic_seeds.push_back(generate_seed(random_size, "mixed"));
    }

    // 6. Structured seeds (common formats)
    // JSON
    std::string json_small = R"({"key":"value"})";
    basic_seeds.emplace_back(json_small.begin(), json_small.end());

    std::string json_large = R"({"users":[{"id":1,"name":"test","data":")" + std::string(500, 'x') +
                             R"("}],"config":{"timeout":1000,"size":)" + std::to_string(1000 + gen() % 1000) + R"(}})";
    basic_seeds.emplace_back(json_large.begin(), json_large.end());

    // XML
    std::string xml = "<root><item>test</item></root>";
    basic_seeds.emplace_back(xml.begin(), xml.end());

    // Common file headers
    basic_seeds.push_back({0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}); // PNG
    basic_seeds.push_back({0xFF, 0xD8, 0xFF}); // JPEG
    basic_seeds.push_back({0x50, 0x4B, 0x03, 0x04}); // ZIP
    basic_seeds.push_back({'G', 'I', 'F', '8', '9', 'a'}); // GIF89a
    
    // Add basic diverse seeds (across different sizes)
    for (const auto& seed_data : basic_seeds) {
        Seed basic_seed;
        basic_seed.data = seed_data;
        basic_seed.energy = 1.0; // normal energy
        basic_seed.generation = 0;
        basic_seed.created_time = std::chrono::system_clock::now();
        basic_seed.algorithm_history.push_back("basic_initialization");

        corpus_manager_->addSeed(std::move(basic_seed));
    }

    std::cout << "[INFO] Added " << basic_seeds.size() << " diverse seeds (ranging from 1 byte to 4KB) for algorithm exploration" << std::endl;
}

// Helper to create algorithm combinations
AlgorithmCombination FuzzingEngine::createCombination(const std::vector<std::string>& algorithms, const std::string& mode) {
    AlgorithmCombination combo;
    combo.algorithm_names = algorithms;
    combo.combination_mode = mode;
    
    // Set smarter weights for weighted mode
    if (mode == "weighted") {
        double total_weight = 0.0;
        
        // Assign a weight to each algorithm
        for (const auto& algo : algorithms) {
            double weight = 0.15; // lower default weight

            // Basic efficient mutation algorithms get the highest weight (checked via AlgorithmConfig)
            if (AlgoConfig::isEnabled(algo)) {
                weight = 0.6;
            }
            // Dictionary and format-aware algorithms get higher weight
            else if (algo == "smart_dictionary" || algo == "format_aware" || algo == "smart_format") {
                weight = 0.5;
            }
            // AI optimization algorithms get medium weight (rare_branch, zest, neuzz archived)
            // else if (algo == "rare_branch") {
            //     weight = 0.35;
            // }
            // Optimization algorithms like gradient descent get medium weight
            // else if (algo == "binary_pso" || algo == "gradient_descent") { // archived
            //     weight = 0.3;
            // }
            // Analyzer algorithms get lower weight (reduce analysis overhead)
            else if (algo.find("analyzer") != std::string::npos) {
                weight = 0.2;
            }
            // Structured algorithms get medium weight
            // else if (algo == "libfuzzer_structured") { // archived
            //     weight = 0.25;
            // } // archived

            combo.weights[algo] = weight;
            total_weight += weight;
        }
        
        // Normalize weights
        if (total_weight > 0.0) {
            for (auto& [algo, weight] : combo.weights) {
                weight /= total_weight;
            }
        }
    }
    
    return combo;
}

// Simplified result processing: focus on critical-path performance
void triofuzz::FuzzingEngine::processResultFast(const ExecutionResult& result, const Seed& original_seed, const AlgorithmCombination& combination) {
    try {
        // Drain/publish this-thread CmpLog records and update shared context
        // (cmplog mutation + auto-dictionary). This is a no-op when cmplog is
        // disabled for the current execution.
        publishCmpLogFromLastExecution();

        // Fixed: Check with global coverage collector for truly new coverage
        bool has_new_coverage = false;

        // Check with the global coverage collector if we have truly new coverage
        if (coverage_collector_) {
            has_new_coverage = coverage_collector_->updateCoverageWithEdges(result.coverage);
        } else {
            // Fallback if no global collector
            has_new_coverage = result.coverage.hasNewCoverage() && !result.coverage.new_edges.empty();
        }
        
        // Improved reward calculation based on whether new coverage is found
        double reward = 0.0;
        double exec_time_ms = result.performance.execution_time_ms;
        bool decoder_success = (result.status == ExecutionResult::Status::Success);
        if (has_new_coverage) {
            // Fix: simplify reward mechanism since we only know new coverage exists, not the exact count
            reward = 0.6;  // base new-coverage reward

            // If coverage gain is large, give an extra reward
            if (result.coverage.coverage_gain > 0.01) {
                reward = 0.7;  // high coverage gain
            } else if (result.coverage.coverage_gain > 0.001) {
                reward = 0.65;  // medium coverage gain
            }
        } else {
            double penalty = -0.02;
            if (exec_time_ms > 0.0 && exec_time_ms < 5.0) {
                penalty -= 0.03;
            }
            if (result.status == ExecutionResult::Status::Error ||
                result.status == ExecutionResult::Status::Timeout) {
                penalty -= 0.05;
            }
            if (!decoder_success) {
                penalty -= 0.05;
            }
            reward = penalty;
        }
        if (result.status == ExecutionResult::Status::Crash) {
            reward += 0.3; // crash bonus
        }

        // Keep reward within a reasonable range
        if (!decoder_success) {
            reward = std::min(reward, -0.1);
        }
        reward = std::clamp(reward, -0.2, 1.0);
        
        // Quickly record to the batch selector (dynamic mode only)
        if (batch_selector_ && config_.enable_dynamic_combination) {
            bool crashed = (result.status == ExecutionResult::Status::Crash);
            batch_selector_->recordExecution(reward, has_new_coverage, crashed, decoder_success);
            if (has_new_coverage) {
                batch_selector_->forceEndBatch(); // Switch quickly on new coverage
            }
        }

        // Even outside dynamic mode, record important findings when new coverage is found
        // if (has_new_coverage && result.coverage.new_edges.size() > 10) {
        //     // Lots of new coverage found; record this combination's success
        //     std::cout << "[!] Major coverage breakthrough with "
        //               << result.coverage.new_edges.size() << " new edges using "
        //               << combination.toString() << std::endl;
        // }
        
        // Reduced debug output - only log every 50000 executions for performance
        size_t current_count = global_debug_counter.fetch_add(1, std::memory_order_relaxed);
        if (current_count % 50000 == 0) {  // Removed has_new_coverage to reduce output
            std::cout << "[DEBUG] processResult #" << current_count
                      << ": total_edges=" << result.coverage.total_edges
                      << ", has_new=" << (has_new_coverage ? "YES" : "NO")
                      << ", reward=" << std::fixed << std::setprecision(3) << reward
                      << ", combo=" << combination.toString() << std::endl;
        }
        
        // Handle seed creation only when new coverage is found
        if (has_new_coverage && decoder_success) {
            // Adaptive Havoc internal op weights: apply EMA reward to ops used this run
            try {
                if (global_context_) {
                    auto ops_opt = global_context_->get<std::vector<int>>("havoc_last_ops");
                    if (ops_opt.has_value()) {
                        // Get/initialize EMA array
                        std::array<double, 12> ema{}; ema.fill(0.0);
                        auto ema_opt = global_context_->get<std::array<double, 12>>("havoc_op_ema");
                        if (ema_opt.has_value()) ema = ema_opt.value();
                        // Update EMA for the ops used
                        constexpr double alpha = 0.2; // learning rate
                        for (int id : ops_opt.value()) {
                            if (id >= 0 && id < 12) {
                                ema[id] = (1.0 - alpha) * ema[id] + alpha * 1.0;
                            }
                        }
                        // Lightweight global decay (avoid long-term starvation): slight decay on each success
                        for (int i = 0; i < 12; ++i) ema[i] *= 0.995;
                        // Generate weights (add a minimum baseline)
                        std::array<double, 12> weights;
                        for (int i = 0; i < 12; ++i) weights[i] = 0.1 + ema[i];
                        global_context_->set("havoc_op_ema", ema);
                        global_context_->set("havoc_op_weights", weights);
                        // Clear this run's record to avoid double-counting
                        global_context_->set("havoc_last_ops", std::vector<int>{});
                    }
                }
            } catch (...) { /* ignore */ }
            // Lightweight byte-impact update: positions that changed and led to new coverage
            try {
                const auto& orig = original_seed.data;
                const auto& mutated = result.input_data;
                size_t len = std::min(orig.size(), mutated.size());
                if (len > 0 && global_context_) {
                    if (!global_context_->has("byte_impact_scores")) {
                        global_context_->set("byte_impact_scores", std::unordered_map<size_t, size_t>{});
                    }
                    global_context_->update<std::unordered_map<size_t, size_t>>("byte_impact_scores", [&](auto& m) {
                        for (size_t i = 0; i < len; ++i) {
                            if (orig[i] != mutated[i]) {
                                m[i] += 1;
                            }
                        }
                        // prune if too large
                        constexpr size_t kMaxTracked = 10000;
                        if (m.size() > kMaxTracked) {
                            // keep top half by score
                            std::vector<std::pair<size_t, size_t>> items(m.begin(), m.end());
                            std::sort(items.begin(), items.end(), [](const auto& a, const auto& b){return a.second > b.second;});
                            items.resize(items.size()/2);
                            m.clear();
                            for (auto& p : items) m.emplace(p.first, p.second);
                        }
                    });
                }
            } catch (...) { /* ignore impact updates on error */ }
            // Only log if we truly have globally new coverage
            // Note: result.coverage.new_edges.size() might not reflect truly new edges globally
            // So we log that new coverage was found without specific edge count
            std::stringstream ss;
            // ss << "[+] New coverage found by " << combination.toString()
            //    << " (reward: " << std::fixed << std::setprecision(3) << reward << ")\n";
            ThreadSafeLogger::getInstance().logImmediate(ss.str());
            
            // Fast path: create new seed with minimal object creation overhead
            Seed new_seed;
            new_seed.data = result.input_data; // Use mutated input instead of the original seed
            new_seed.coverage = result.coverage;
            new_seed.created_time = std::chrono::system_clock::now();
            new_seed.generation = original_seed.generation + 1;
            // Fix: set energy based on coverage gain rather than new_edges count
            if (result.coverage.coverage_gain > 0.01) {
                new_seed.energy = 2.0;  // high-value seed
            } else if (result.coverage.coverage_gain > 0.001) {
                new_seed.energy = 1.5;  // medium-value seed
            } else {
                new_seed.energy = 1.2;  // baseline new-coverage seed
            }
            
            // Add directly without complex history tracking
            if (corpus_manager_) {
                corpus_manager_->addSeed(std::move(new_seed));
            }
            
            // Atomically update stats
            stats_.new_coverage_found.fetch_add(1, std::memory_order_relaxed);
            stats_.last_coverage_time = std::chrono::system_clock::now();
        }
        
        // Simplified crash handling
        if (result.status == ExecutionResult::Status::Crash) {
            // Simple uniqueness check to avoid expensive crash analysis
            static thread_local std::unordered_set<size_t> seen_crash_hashes;
            
            // Use a simple hash to check uniqueness
            std::hash<std::string> hasher;
            std::string crash_sig;
            for (const auto& info : result.crash_info) {
                crash_sig += info;
            }
            size_t crash_hash = hasher(crash_sig + std::to_string(result.input_data.size()));
            
            if (seen_crash_hashes.find(crash_hash) == seen_crash_hashes.end()) {
                seen_crash_hashes.insert(crash_hash);
                
                // Fast path: create crash seed using mutated input instead of the original seed
                Seed crash_seed;
                crash_seed.data = result.input_data;  // Fix: use the actual input that triggered the crash
                crash_seed.created_time = std::chrono::system_clock::now();
                crash_seed.energy = 2.0;
                
                if (corpus_manager_) {
                    corpus_manager_->addCrashSeed(std::move(crash_seed));
                }
                
                // Atomically update stats
                stats_.unique_crashes.fetch_add(1, std::memory_order_relaxed);
                stats_.last_crash_time = std::chrono::system_clock::now();
            }
            
            stats_.total_crashes.fetch_add(1, std::memory_order_relaxed);
        }
        
    } catch (...) {
        // Handle errors silently to avoid impacting fuzzing performance
    }
}

void triofuzz::FuzzingEngine::forceStopAllThreads() {
    std::cout << "[FuzzingEngine] Force stopping all threads..." << std::endl;
    
    force_stop_.store(true);
    running_.store(false);
    stats_running_.store(false);
    
    // Notify all waiting threads
    {
        std::lock_guard<std::mutex> lock(thread_stop_mutex_);
        thread_stop_cv_.notify_all();
    }
    
    // Force join all worker threads
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    // Force join stats thread
    if (stats_thread_.joinable()) {
        stats_thread_.join();
    }
}

bool triofuzz::FuzzingEngine::waitForThreadsToStop(std::chrono::milliseconds timeout) {
    auto start_time = std::chrono::steady_clock::now();

    // First, set the stop flags
    running_.store(false);
    force_stop_.store(true);

    // Notify all threads multiple times to ensure they wake up
    for (int i = 0; i < 3; i++) {
        {
            std::lock_guard<std::mutex> lock(thread_stop_mutex_);
            thread_stop_cv_.notify_all();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Simple approach: try to join each thread with a short timeout
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            // Check if we've exceeded the total timeout
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed >= timeout) {
                // Timeout - detach remaining threads
                std::cout << "[WARNING] Timeout waiting for threads, detaching remaining..." << std::endl;
                thread.detach();
                continue;
            }

            // Calculate remaining time for this thread
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(timeout - elapsed);
            auto thread_timeout = (remaining.count() < 100) ? remaining : std::chrono::milliseconds(100);

            // Try to join for a short time, then detach if it doesn't work
            // Since std::thread::join() doesn't support timeout, we just detach after checking
            thread.detach();
        }
    }

    return true; // Always return true since we handle everything
}

void triofuzz::FuzzingEngine::cleanupThreadLocalData() {
    std::cout << "[FuzzingEngine] Cleaning up thread-local data..." << std::endl;
    
    // Cleanup RandomUtils thread-local storage
    utils::RandomUtils::cleanupAllThreads();
    
    // Clear any thread-local caches or data structures
    {
        std::lock_guard<std::mutex> lock(worker_threads_mutex_);
        active_worker_threads_.clear();
    }
}

void triofuzz::FuzzingEngine::registerWorkerThread(size_t thread_id) {
    std::lock_guard<std::mutex> lock(worker_threads_mutex_);
    active_worker_threads_.insert(thread_id);
}

void triofuzz::FuzzingEngine::unregisterWorkerThread(size_t thread_id) {
    std::lock_guard<std::mutex> lock(worker_threads_mutex_);
    active_worker_threads_.erase(thread_id);
}

void triofuzz::FuzzingEngine::cleanupWorkerThreadData(size_t thread_id) {
    // Cleanup thread-local storage for this specific worker
    utils::RandomUtils::cleanupThreadLocalStorage();
}

// Removed: dedicated algorithm thread functions (startDedicatedAlgorithmThreads, stopDedicatedAlgorithmThreads, dedicatedAlgorithmLoop)

// ==================== Checkpoint / Crash Recovery ====================

bool FuzzingEngine::saveCheckpoint() {
    if (!checkpoint_manager_ || !checkpoint_manager_->isEnabled()) {
        return false;
    }

    CheckpointData data;

    // Set timestamp
    auto now = std::chrono::system_clock::now();
    data.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();

    // Save execution statistics
    data.total_executions = stats_.total_executions.load();
    data.total_crashes = stats_.total_crashes.load();
    data.total_new_coverage = stats_.new_coverage_found.load();

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - global_start_time_);
    data.elapsed_seconds = static_cast<double>(elapsed.count());

    // Save Thompson Sampling state (combination performance)
    {
        std::lock_guard<std::mutex> lock(thompson_sampling_mutex_);
        for (const auto& [combo_str, history] : combination_history_) {
            CheckpointData::CombinationStats cs;
            cs.combination_str = combo_str;
            cs.combination_hash = std::hash<std::string>{}(combo_str);
            cs.executions = history.first;
            cs.total_reward = history.second;
            cs.avg_reward = (history.first > 0) ? history.second / history.first : 0.0;
            data.combination_stats.push_back(cs);
        }
    }

    // triofuzz-Mini: Save coverage stats from AFLCompatibleCoverage
    auto& afl_cov = triofuzz::AFLCompatibleCoverage::getInstance();
    data.total_edges = afl_cov.getTotalEdges();
    // Note: We don't save the full bitmap here as it's large and profraw files handle this

    // Save corpus metadata
    if (corpus_manager_) {
        data.corpus_size = corpus_manager_->getTotalSeeds();
        // Corpus seeds are already saved to disk, we just record the count
    }

    // Save tiered scheduler state if enabled
    if (tiered_scheduler_) {
        // Note: TieredAlgorithmScheduler stats could be added here if needed
    }

    return checkpoint_manager_->saveCheckpoint(data);
}

bool FuzzingEngine::loadCheckpoint() {
    if (!checkpoint_manager_ || !checkpoint_manager_->hasCheckpoint()) {
        return false;
    }

    CheckpointData data;
    if (!checkpoint_manager_->loadCheckpoint(data)) {
        return false;
    }

    // Restore execution statistics
    stats_.total_executions.store(data.total_executions);
    stats_.total_crashes.store(data.total_crashes);
    stats_.new_coverage_found.store(data.total_new_coverage);

    // Note: elapsed_seconds is informational, we track time from new start

    // Restore Thompson Sampling state
    {
        std::lock_guard<std::mutex> lock(thompson_sampling_mutex_);
        for (const auto& cs : data.combination_stats) {
            combination_history_[cs.combination_str] = std::make_pair(cs.executions, cs.total_reward);

            // Restore beta distribution parameters
            // Simple approach: alpha = successes + 1, beta = failures + 1
            double successes = cs.avg_reward * cs.executions;
            double failures = cs.executions - successes;
            beta_distributions_[cs.combination_str] = std::make_pair(
                successes + 1.0,
                failures + 1.0
            );
        }
    }

    std::cout << "[FuzzingEngine] Restored Thompson Sampling state: "
              << data.combination_stats.size() << " combinations" << std::endl;
    std::cout << "[FuzzingEngine] Previous executions: " << data.total_executions
              << ", crashes: " << data.total_crashes
              << ", elapsed: " << data.elapsed_seconds << "s" << std::endl;

    return true;
}

void FuzzingEngine::maybeCheckpoint() {
    if (!checkpoint_manager_ || !checkpoint_manager_->isEnabled()) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_checkpoint_time_);

    if (elapsed.count() >= static_cast<long>(config_.checkpoint_interval_sec)) {
        if (saveCheckpoint()) {
            last_checkpoint_time_ = now;
        }
    }
}

} // namespace triofuzz

// Interface functions for collafuzz_interface.cpp (outside the namespace)
void resetRealCoverage() {
    triofuzz::RealCoverageCollector::getInstance().resetCoverage();
}

void clearRealCoverageState() {
    triofuzz::RealCoverageCollector::getInstance().clearCoverageState();
}

// added: safely shut down the coverage collector
void shutdownRealCoverageCollector() {
    triofuzz::RealCoverageCollector::getInstance().shutdown();
}

triofuzz::CoverageInfo getCurrentRealCoverage() {
    return triofuzz::RealCoverageCollector::getInstance().getCurrentCoverage();
}

// Save covered edges to a file (for complementarity experiments)
bool saveRealCoverageEdges(const std::string& output_path) {
    return triofuzz::RealCoverageCollector::getInstance().saveCoveredEdgesToFile(output_path);
}

// Strict-mode validation method implementation
bool triofuzz::FuzzingEngine::validateStrictAlgorithmIsolation() const {
    if (!config_.strict_algorithm_isolation) {
        return true; // Non-strict mode: always passes validation
    }
    
    std::cout << "[STRICT MODE VALIDATION] Checking algorithm isolation..." << std::endl;
    
    // Get currently enabled algorithms
    auto enabled_algorithms = getEnabledAlgorithms();
    
    // Get algorithms specified by the fixed combinations
    std::set<std::string> authorized_algorithms;
    if (!config_.fixed_combination.thread_algorithm_combinations.empty()) {
        for (const auto& thread_combo : config_.fixed_combination.thread_algorithm_combinations) {
            for (const auto& algo : thread_combo) {
                authorized_algorithms.insert(algo);
            }
        }
    }
    
    // Check for unauthorized enabled algorithms
    std::vector<std::string> unauthorized;
    for (const auto& algo : enabled_algorithms) {
        if (authorized_algorithms.find(algo) == authorized_algorithms.end()) {
            // Exclude required combination-strategy algorithms
            if (algo != "thompson_sampling") { // angora_strategy archived
                unauthorized.push_back(algo);
            }
        }
    }
    
    if (!unauthorized.empty()) {
        std::cout << "[STRICT MODE VIOLATION] Unauthorized algorithms detected: ";
        for (size_t i = 0; i < unauthorized.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << unauthorized[i];
        }
        std::cout << std::endl;
        return false;
    }
    
    // Verify system algorithms are disabled
    if (config_.disable_system_algorithms) {
        std::vector<std::string> system_algorithms = {
            "coverage_analyzer", "crash_analyzer", // performance_analyzer archived
            "corpus_minimizer", "energy_scheduler"
        };
        
        for (const auto& sys_algo : system_algorithms) {
            if (std::find(enabled_algorithms.begin(), enabled_algorithms.end(), sys_algo) != enabled_algorithms.end()) {
                std::cout << "[STRICT MODE VIOLATION] System algorithm " << sys_algo << " is still enabled" << std::endl;
                return false;
            }
        }
    }
    
    std::cout << "[STRICT MODE VALIDATION] Algorithm isolation verified successfully" << std::endl;
    return true;
}

void triofuzz::FuzzingEngine::logAlgorithmUsage() const {
    std::cout << "\n=== ALGORITHM USAGE REPORT ===" << std::endl;
    std::cout << "Strict Algorithm Isolation: " << (config_.strict_algorithm_isolation ? "ENABLED" : "DISABLED") << std::endl;
    
    auto enabled_algorithms = getEnabledAlgorithms();
    std::cout << "Enabled Algorithms (" << enabled_algorithms.size() << " total):" << std::endl;
    for (size_t i = 0; i < enabled_algorithms.size(); ++i) {
        std::cout << "  " << (i+1) << ". " << enabled_algorithms[i] << std::endl;
    }
    
    if (config_.strict_algorithm_isolation) {
        std::cout << "Fixed Combinations:" << std::endl;
        for (size_t i = 0; i < config_.fixed_combination.thread_algorithm_combinations.size(); ++i) {
            std::cout << "  Thread " << i << ": ";
            const auto& combo = config_.fixed_combination.thread_algorithm_combinations[i];
            for (size_t j = 0; j < combo.size(); ++j) {
                if (j > 0) std::cout << " -> ";
                std::cout << combo[j];
            }
            std::cout << std::endl;
        }
        
        auto unauthorized = getUnauthorizedAlgorithms();
        if (!unauthorized.empty()) {
            std::cout << "WARNINGS - Unauthorized algorithms detected:" << std::endl;
            for (const auto& algo : unauthorized) {
                std::cout << "  * " << algo << std::endl;
            }
        }
        
        std::cout << "System Algorithms: " << (config_.disable_system_algorithms ? "DISABLED" : "ENABLED") << std::endl;
        std::cout << "Corpus Optimization: " << (config_.disable_corpus_optimization ? "DISABLED" : "ENABLED") << std::endl;
        std::cout << "Feedback Optimization: " << (config_.disable_feedback_optimization ? "DISABLED" : "ENABLED") << std::endl;
    }
    
    std::cout << "==========================\n" << std::endl;
}

std::vector<std::string> triofuzz::FuzzingEngine::getUnauthorizedAlgorithms() const {
    std::vector<std::string> unauthorized;
    
    if (!config_.strict_algorithm_isolation) {
        return unauthorized; // Non-strict mode: no unauthorized algorithms
    }
    
    auto enabled_algorithms = getEnabledAlgorithms();
    
    // Get the authorized algorithm list
    std::set<std::string> authorized_algorithms;
    if (!config_.fixed_combination.thread_algorithm_combinations.empty()) {
        for (const auto& thread_combo : config_.fixed_combination.thread_algorithm_combinations) {
            for (const auto& algo : thread_combo) {
                authorized_algorithms.insert(algo);
            }
        }
    }
    
    // Add required combination-strategy algorithms to the authorized list
    authorized_algorithms.insert("thompson_sampling");
    // authorized_algorithms.insert("angora_strategy"); // archived
    
    // Find unauthorized algorithms
    for (const auto& algo : enabled_algorithms) {
        if (authorized_algorithms.find(algo) == authorized_algorithms.end()) {
            unauthorized.push_back(algo);
        }
    }
    
    return unauthorized;
}

// added: print optimization statistics
void triofuzz::FuzzingEngine::printOptimizationStats() {
    if (use_optimized_thompson_ && optimized_thompson_) {
        std::cout << "\n=========================================" << std::endl;
        std::cout << "   Optimization Statistics" << std::endl;
        std::cout << "=========================================" << std::endl;
        // Simplified stats output (printStats may be undefined; use basic output for now)
        std::cout << "OptimizedThompsonSampling is enabled" << std::endl;
        std::cout << "Using 80% fast path + 20% exploration" << std::endl;
        std::cout << "=========================================" << std::endl;
    }
}
