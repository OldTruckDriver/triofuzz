#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <vector>
#include <algorithm>
#include <cstdio>

namespace triofuzz {

/**
 * @brief Inline 8-bit counters coverage collector
 *
 * This implements the same coverage mechanism as libFuzzer:
 * - Compiler inserts __sanitizer_cov_8bit_counters_init() call at startup
 * - Each edge has an 8-bit counter in a contiguous array
 * - Counters are incremented inline by instrumented code
 * - We only need to scan the array to detect new coverage
 *
 * Performance characteristics:
 * - Completely lock-free for edge recording (done by instrumentation)
 * - O(1) fast path - no function calls during execution
 * - Only scanning overhead to detect new coverage
 * - Compatible with libFuzzer-instrumented targets (-fsanitize=fuzzer-no-link)
 */
class Inline8BitCoverage {
public:
    static constexpr size_t MAX_COUNTERS = 1 << 20;  // 1M counters max

    static Inline8BitCoverage& getInstance() {
        static Inline8BitCoverage instance;
        return instance;
    }

    /**
     * @brief Called by __sanitizer_cov_8bit_counters_init from instrumentation
     *
     * The compiler-inserted instrumentation will call this function at startup
     * to register the counter array region.
     */
    void registerCounters(uint8_t* start, uint8_t* end) {
        size_t num_counters = end - start;
        if (num_counters == 0 || num_counters > MAX_COUNTERS) {
            return;
        }

        // Store the counter array pointer
        counters_start_ = start;
        counters_end_ = end;
        num_counters_ = num_counters;

        // Initialize our tracking arrays
        if (!prev_counters_) {
            prev_counters_ = new uint8_t[MAX_COUNTERS];
            std::fill_n(prev_counters_, MAX_COUNTERS, 0);
        }

        // Initialize virgin_bits (like AFL) - tracks which edges we've seen
        if (!virgin_bits_) {
            virgin_bits_ = new uint8_t[MAX_COUNTERS];
            std::fill_n(virgin_bits_, MAX_COUNTERS, 0xFF);  // All bits virgin initially
        }

        initialized_.store(true, std::memory_order_release);
    }

    /**
     * @brief Fast check if this execution has new coverage
     *
     * CRITICAL OPTIMIZATION: Use inline assembly or compiler intrinsics for vectorization!
     * This is the HOT PATH - called after EVERY execution!
     *
     * @return true if new coverage was found
     */
    bool hasNewCoverage() {
        if (!initialized_.load(std::memory_order_acquire)) {
            return false;
        }

        bool found_new = false;
        uint8_t* current = counters_start_;

        // OPTIMIZATION: Early exit using cumulative OR
        // If no counters changed, we can skip the detailed check
        bool any_change = false;

        // Process in 64-byte chunks for cache efficiency
        const size_t chunk_size = 64;
        size_t i = 0;

        for (; i + chunk_size <= num_counters_; i += chunk_size) {
            // Quick check: any non-zero counters in this chunk?
            bool chunk_has_data = false;
            for (size_t j = 0; j < chunk_size; ++j) {
                if (current[i + j] != 0) {
                    chunk_has_data = true;
                    break;
                }
            }

            if (!chunk_has_data) continue;

            // Detailed check for new coverage in this chunk
            for (size_t j = 0; j < chunk_size; ++j) {
                size_t idx = i + j;
                uint8_t cur_count = current[idx];

                if (cur_count == 0) continue;

                // Check if this is a truly new edge
                if (virgin_bits_[idx] == 0xFF) {
                    virgin_bits_[idx] = 0;
                    found_new = true;
                    total_edges_.fetch_add(1, std::memory_order_relaxed);
                }

                prev_counters_[idx] = cur_count;
            }
        }

        // Handle remaining counters
        for (; i < num_counters_; ++i) {
            uint8_t cur_count = current[i];
            if (cur_count == 0) continue;

            if (virgin_bits_[i] == 0xFF) {
                virgin_bits_[i] = 0;
                found_new = true;
                total_edges_.fetch_add(1, std::memory_order_relaxed);
            }

            prev_counters_[i] = cur_count;
        }

        if (found_new) {
            new_coverage_count_.fetch_add(1, std::memory_order_relaxed);
        }

        return found_new;
    }

    /**
     * @brief Get total number of unique edges covered
     */
    size_t getTotalEdges() const {
        return total_edges_.load(std::memory_order_relaxed);
    }

    /**
     * @brief Get number of times new coverage was found
     */
    size_t getNewCoverageCount() const {
        return new_coverage_count_.load(std::memory_order_relaxed);
    }

    /**
     * @brief Get current coverage bitmap for deduplication
     *
     * Returns a hash of the current coverage state.
     */
    uint64_t getCoverageHash() const {
        if (!initialized_.load(std::memory_order_acquire)) {
            return 0;
        }

        uint64_t hash = 0;
        uint8_t* current = counters_start_;

        for (size_t i = 0; i < num_counters_; ++i) {
            if (current[i] > 0) {
                // Simple hash combining edge ID and hit count class
                hash ^= (i * 0x9e3779b9) + classifyCount(current[i]);
            }
        }

        return hash;
    }

    /**
     * @brief Reset coverage for new test case
     *
     * NOTE: This is VERY fast - just memset the counters to zero.
     * No locks, no atomic operations, no iteration.
     */
    void resetCoverage() {
        if (!initialized_.load(std::memory_order_acquire)) {
            return;
        }

        // Fast bulk reset - compiler/OS optimized memset
        std::fill_n(counters_start_, num_counters_, 0);
    }

    /**
     * @brief Get coverage statistics
     */
    struct Stats {
        size_t num_counters = 0;
        size_t total_edges = 0;
        size_t new_coverage_events = 0;
        bool initialized = false;
    };

    Stats getStats() const {
        Stats stats;
        stats.num_counters = num_counters_;
        stats.total_edges = total_edges_.load(std::memory_order_relaxed);
        stats.new_coverage_events = new_coverage_count_.load(std::memory_order_relaxed);
        stats.initialized = initialized_.load(std::memory_order_relaxed);
        return stats;
    }

    /**
     * @brief Sampled check for bucket upgrades (AFL-style) without full scan
     *
     * To keep overhead low, we stride through the counter array with a step
     * derived from the requested sample size. If any counter's classified
     * bucket increases versus the previous snapshot, we report true and update
     * the previous snapshot for that position.
     */
    bool hasBucketUpgradeSampled(size_t sample_size = 256) {
        if (!initialized_.load(std::memory_order_acquire) || num_counters_ == 0) return false;
        if (sample_size == 0) sample_size = 256;
        size_t step = num_counters_ / sample_size;
        if (step == 0) step = 1;

        bool upgraded = false;
        for (size_t i = 0; i < num_counters_; i += step) {
            uint8_t cur = counters_start_[i];
            if (cur == 0) continue;
            uint8_t prev = prev_counters_[i];
            uint8_t cb = classifyCount(cur);
            uint8_t pb = classifyCount(prev);
            if (cb > pb) {
                prev_counters_[i] = cur; // update snapshot for this position
                upgraded = true;
                break; // one upgrade is enough as a signal
            }
        }
        return upgraded;
    }

private:
    Inline8BitCoverage() = default;
    ~Inline8BitCoverage() {
        delete[] prev_counters_;
        delete[] virgin_bits_;
    }

    // Prevent copying
    Inline8BitCoverage(const Inline8BitCoverage&) = delete;
    Inline8BitCoverage& operator=(const Inline8BitCoverage&) = delete;

    /**
     * @brief Classify hit count into buckets (AFL-style)
     *
     * Maps hit counts to classes:
     * 0 -> 0
     * 1 -> 1
     * 2 -> 2
     * 3 -> 4
     * 4-7 -> 8
     * 8-15 -> 16
     * 16-31 -> 32
     * 32-127 -> 64
     * 128-255 -> 128
     */
    static uint8_t classifyCount(uint8_t count) {
        static const uint8_t count_class_lookup[256] = {
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
        return count_class_lookup[count];
    }

    // Counter array registered by instrumentation
    uint8_t* counters_start_ = nullptr;
    uint8_t* counters_end_ = nullptr;
    size_t num_counters_ = 0;

    // Tracking arrays
    uint8_t* prev_counters_ = nullptr;  // Previous execution's counters
    uint8_t* virgin_bits_ = nullptr;     // AFL-style virgin bits tracking

    // Statistics
    std::atomic<bool> initialized_{false};
    std::atomic<size_t> total_edges_{0};
    std::atomic<size_t> new_coverage_count_{0};
};

} // namespace triofuzz

// Extern C interface for compiler instrumentation to call
extern "C" {

/**
 * @brief Called by instrumentation at startup to register counter array
 *
 * The compiler inserts a call to this function in a module constructor.
 * This is the standard libFuzzer interface.
 */
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* end) {
    // Register counters silently for performance
    // Only print on first initialization (use C stdio to avoid iostream init-order issues)
    static std::atomic<bool> first_init{true};

    triofuzz::Inline8BitCoverage::getInstance().registerCounters(start, end);

    if (first_init.exchange(false)) {
        // Safe to use fprintf here; avoids dependency on C++ iostream globals
        auto stats = triofuzz::Inline8BitCoverage::getInstance().getStats();
        std::fprintf(stderr,
                     "[Inline8BitCoverage] Initialized with %zu counters at %p\n",
                     stats.num_counters,
                     (void*)start);
        std::fflush(stderr);
    }
}

/**
 * @brief Optional: Called to reset coverage (if needed)
 */
void __sanitizer_cov_reset_edgeguards() {
    triofuzz::Inline8BitCoverage::getInstance().resetCoverage();
}

} // extern "C"
