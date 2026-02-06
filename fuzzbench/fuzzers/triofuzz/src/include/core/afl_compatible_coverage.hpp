#pragma once

#include <cstdint>
#include <cstring>
#include <bitset>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <iostream>
#include <iomanip>

namespace triofuzz {

/**
 * AFL++-compatible coverage collector
 *
 * Key improvements:
 * 1. Use XOR edge hashing (cur_loc ^ prev_loc) - distinguish A→B vs B→A
 * 2. Shared memory bitmap - zero-copy
 * 3. 8-bit saturating counter - matches AFL++
 * 4. Count classification lookup table - precise bucketing
 * 5. Virgin bits tracking - efficient new-coverage detection
 */
class AFLCompatibleCoverage {
public:
    static constexpr size_t MAP_SIZE = 65536;  // 64KB bitmap

private:
    // Thread-local bitmap (per-execution trace).
    //
    // NOTE: The fuzzer executes inputs concurrently across multiple threads.
    // Using a single shared trace bitmap and calling reset() before each
    // execution causes cross-thread races that drop coverage and can prevent
    // coverage-increasing inputs from being persisted to the on-disk corpus.
    //
    // We keep per-thread trace bits, while keeping the global "virgin bits"
    // shared (and updated atomically) so new-coverage detection remains global.
    static inline std::vector<uint8_t>& threadTraceBits() {
        static thread_local std::vector<uint8_t> trace_bits(MAP_SIZE);
        return trace_bits;
    }

    static inline uint8_t* threadTraceBitsData() {
        return threadTraceBits().data();
    }

    // Thread-local "previous location" for AFL-style edge hashing.
    //
    // IMPORTANT: This must be reset for each *input execution*. If it carries
    // over between inputs in persistent/in-process mode, the first edge of an
    // input will be "chained" with the last edge of the previous input,
    // polluting the bitmap and quickly exhausting virgin bits. That can cause
    // true coverage-increasing inputs to not be recognized as new coverage
    // (and therefore not persisted to disk), widening the dynamic vs snapshot
    // coverage gap.
    static inline uint32_t& threadPrevLoc() {
        static thread_local uint32_t prev_loc = 0;
        return prev_loc;
    }

    uint8_t* virgin_bits_ = nullptr;        // Never-seen edges

    // Count classification lookup table (from AFL++)
    static constexpr uint8_t count_class_lookup8_[256] = {
        // Bucket 0: count = 0 (never hit)
        0,
        // Bucket 1: count = 1
        1,
        // Bucket 2: count = 2
        2,
        // Bucket 3: count = 3
        4,
        // Bucket 4: count = 4-7
        8, 8, 8, 8,
        // Bucket 5: count = 8-15
        16, 16, 16, 16, 16, 16, 16, 16,
        // Bucket 6: count = 16-31
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        // Bucket 7: count = 32-127
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        // Bucket 8: count = 128+
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
        128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128
    };

    // Statistics
    std::atomic<size_t> total_edges_{0};
    std::atomic<size_t> total_execs_{0};

    // Global coverage bitmap (for stats)
    std::bitset<MAP_SIZE> global_coverage_;
    mutable std::mutex global_mutex_;

    // ⚠️ Singleton removed; use instances instead.
    // static AFLCompatibleCoverage* instance_;  // removed
    // static std::mutex instance_mutex_;  // removed

public:
    // ⚠️ Keep getInstance() for backward compatibility, but mark as deprecated.
    [[deprecated("Use FuzzingEngine::getCoverage() instead")]]
    static AFLCompatibleCoverage& getInstance() {
        static AFLCompatibleCoverage legacy_instance;
        return legacy_instance;
    }

    AFLCompatibleCoverage() {
        virgin_bits_ = new uint8_t[MAP_SIZE];

        // Initialize
        reset();
        std::memset(virgin_bits_, 255, MAP_SIZE);  // All virgin initially

        // Note: Don't use std::cout here - may not be initialized during global construction
        // std::cout << "[AFLCoverage] Initialized with " << MAP_SIZE << " byte bitmap\n";
    }

    ~AFLCompatibleCoverage() {
        delete[] virgin_bits_;
    }

    /**
     * Reset coverage bitmap for new execution
     */
    void reset() {
        std::memset(threadTraceBitsData(), 0, MAP_SIZE);
        threadPrevLoc() = 0;
    }

    /**
     * Get trace bitmap pointer (for direct access from instrumentation)
     */
    uint8_t* getTraceBits() {
        return threadTraceBitsData();
    }

    /**
     * Record edge hit (AFL++-style with XOR hashing)
     *
     * This should be called from __sanitizer_cov_trace_pc_guard with:
     * static __thread uint32_t prev_loc = 0;
     * uint32_t cur_loc = *guard;
     * uint32_t edge_id = cur_loc ^ prev_loc;
     * prev_loc = cur_loc >> 1;
     * recordEdge(edge_id);
     */
    inline void recordEdge(uint32_t edge_id) {
        edge_id &= (MAP_SIZE - 1);  // Ensure within bounds

        // 8-bit saturating counter
        auto* trace_bits = threadTraceBitsData();
        if (trace_bits[edge_id] < 255) {
            trace_bits[edge_id]++;
        }
    }

    /**
     * Compute AFL-style edge id and update per-thread prev_loc.
     *
     * Intended to be used from __sanitizer_cov_trace_pc_guard.
     */
    static inline uint32_t computeEdgeId(uint32_t cur_loc) {
        uint32_t& prev_loc = threadPrevLoc();
        uint32_t edge_id = cur_loc ^ prev_loc;
        prev_loc = cur_loc >> 1;
        return edge_id;
    }

    /**
     * Check if current execution has new coverage
     * Returns: true if new coverage found
     */
    bool hasNewCoverage() {
        bool new_coverage = false;

        auto* trace_bits = threadTraceBitsData();
        for (size_t i = 0; i < MAP_SIZE; ++i) {
            if (trace_bits[i] == 0) continue;

            // Classify counts
            uint8_t cur_class = count_class_lookup8_[trace_bits[i]];
            if (!cur_class) continue;

            // Atomically clear newly observed count-class bits.
            // This is monotonic (bits only go from 1 -> 0) and safe across
            // concurrent threads.
            uint8_t prev = __atomic_fetch_and(&virgin_bits_[i],
                                              static_cast<uint8_t>(~cur_class),
                                              __ATOMIC_RELAXED);
            if ((prev & cur_class) != 0) {
                new_coverage = true;
            }
        }

        if (new_coverage) {
            total_edges_.fetch_add(1, std::memory_order_relaxed);

            // Update global coverage
            std::lock_guard<std::mutex> lock(global_mutex_);
            for (size_t i = 0; i < MAP_SIZE; ++i) {
                if (trace_bits[i] > 0) {
                    global_coverage_.set(i);
                }
            }
        }

        total_execs_.fetch_add(1, std::memory_order_relaxed);
        return new_coverage;
    }

    /**
     * Classify counts in bitmap (AFL++-style)
     */
    void classifyCounts() {
        auto* trace_bits = threadTraceBitsData();
        for (size_t i = 0; i < MAP_SIZE; ++i) {
            if (trace_bits[i]) {
                trace_bits[i] = count_class_lookup8_[trace_bits[i]];
            }
        }
    }

    /**
     * Get coverage percentage
     */
    double getCoveragePercentage() const {
        std::lock_guard<std::mutex> lock(global_mutex_);
        return (global_coverage_.count() * 100.0) / MAP_SIZE;
    }

    /**
     * Get total unique edges
     */
    size_t getTotalEdges() const {
        return total_edges_.load(std::memory_order_relaxed);
    }

    /**
     * Get total executions
     */
    size_t getTotalExecutions() const {
        return total_execs_.load(std::memory_order_relaxed);
    }

    /**
     * Get virgin bits (for advanced analysis)
     */
    const uint8_t* getVirginBits() const {
        return virgin_bits_;
    }

    /**
     * Save current bitmap to vector (for seed storage)
     */
    std::vector<uint8_t> getCurrentBitmap() const {
        const auto& bits = threadTraceBits();
        return bits;
    }

    /**
     * Calculate hamming distance between two bitmaps
     */
    static size_t hammingDistance(const std::vector<uint8_t>& a,
                                  const std::vector<uint8_t>& b) {
        size_t distance = 0;
        size_t len = std::min(a.size(), b.size());
        for (size_t i = 0; i < len; ++i) {
            uint8_t xor_val = a[i] ^ b[i];
            distance += __builtin_popcount(xor_val);
        }
        return distance;
    }

    /**
     * Print statistics
     */
    void printStats() const {
        std::cout << "[AFLCoverage] Total edges: " << total_edges_.load()
                  << ", Execs: " << total_execs_.load()
                  << ", Coverage: " << std::fixed << std::setprecision(2)
                  << getCoveragePercentage() << "%\n";
    }
};

// Static members removed - using instance-based pattern instead

} // namespace triofuzz
