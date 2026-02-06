#pragma once

#include <atomic>
#include <vector>
#include <bitset>
#include <cstring>
#include <memory>
#include <array>
#include <unordered_set>
#include "../core/context.hpp"

// Only include intrinsics if available
#ifdef __x86_64__
    #ifdef __AVX2__
        #include <immintrin.h>
    #endif
#endif

namespace triofuzz {

// High-performance lock-free coverage collector
class LockFreeCoverageCollector {
public:
    static constexpr size_t MAP_SIZE = 65536;  // AFL-standard size
    static constexpr size_t CACHE_LINE_SIZE = 64;

    // Ensure cache-line alignment to avoid false sharing.
    struct alignas(CACHE_LINE_SIZE) CoverageData {
        std::atomic<uint8_t> bitmap[MAP_SIZE];
        std::atomic<uint64_t> edge_discovery_count;
        std::atomic<uint64_t> total_edges;

        CoverageData() {
            reset();
        }

        void reset() {
            // Bulk initialize with memset.
            std::memset((void*)bitmap, 0, sizeof(bitmap));
            edge_discovery_count = 0;
            total_edges = 0;
        }
    };

private:
    // Thread-local storage to reduce contention.
    struct ThreadLocalData {
        std::array<uint8_t, MAP_SIZE> local_bitmap{};
        std::vector<uint32_t> new_edges;
        uint64_t hits = 0;

        void reset() {
            local_bitmap.fill(0);
            new_edges.clear();
            hits = 0;
        }
    };

    // Main coverage data
    std::unique_ptr<CoverageData> coverage_data_;

    // Thread-local cache
    static thread_local ThreadLocalData tls_data_;

    // Batch update threshold
    static constexpr size_t BATCH_UPDATE_THRESHOLD = 100;

    // SIMD-optimized bitmap comparison
    bool hasNewCoverageSSE(const uint8_t* current, const uint8_t* new_coverage) const;

public:
    LockFreeCoverageCollector();
    ~LockFreeCoverageCollector() = default;

    // Disable copy/move (contains atomic members).
    LockFreeCoverageCollector(const LockFreeCoverageCollector&) = delete;
    LockFreeCoverageCollector& operator=(const LockFreeCoverageCollector&) = delete;
    LockFreeCoverageCollector(LockFreeCoverageCollector&&) = delete;
    LockFreeCoverageCollector& operator=(LockFreeCoverageCollector&&) = delete;

    // Core API - lock-free edge recording
    inline bool recordEdge(uint32_t edge_id) {
        if (edge_id >= MAP_SIZE) {
            edge_id %= MAP_SIZE;  // Simple hash
        }

        // Update thread-local cache first.
        uint8_t& local_val = tls_data_.local_bitmap[edge_id];
        if (local_val == 0) {
            local_val = 1;
            tls_data_.new_edges.push_back(edge_id);
            tls_data_.hits++;

            // When the batch threshold is reached, update the global bitmap.
            if (tls_data_.hits >= BATCH_UPDATE_THRESHOLD) {
                flushThreadLocal();
            }
            return true;
        }

        // Check global bitmap (read-only, lock-free).
        uint8_t global_val = coverage_data_->bitmap[edge_id].load(std::memory_order_relaxed);
        return global_val == 0;
    }

    // Record coverage in batch
    size_t recordCoverageBatch(const std::vector<uint32_t>& edges);

    // Fast check for new coverage
    bool hasNewCoverage(const std::bitset<MAP_SIZE>& test_coverage) const;

    // Get current coverage stats
    struct CoverageStats {
        size_t total_edges;
        size_t unique_edges;
        double coverage_percentage;
        size_t new_edges_this_round;
    };

    CoverageStats getStats() const;

    // Get coverage bitmap snapshot (for seed dedup).
    std::bitset<MAP_SIZE> getCoverageBitmap() const;

    // Merge coverage from another collector (for multi-thread merge).
    void merge(const LockFreeCoverageCollector& other);

    // Reset coverage
    void reset();

    // Force flush thread-local cache to global.
    void flushThreadLocal();

    // Get rare edges (low hit counts).
    std::vector<uint32_t> getRareEdges(uint8_t threshold = 3) const;

    // Get list of all covered edge IDs (for complementarity analysis).
    std::vector<uint32_t> getCoveredEdges() const;

    // Save covered edges to file (for complementarity analysis).
    bool saveCoveredEdgesToFile(const std::string& output_path) const;

    // SIMD-accelerated coverage comparison
    size_t compareAndUpdateCoverage(const uint8_t* new_coverage, size_t size);

    // Performance monitoring
    struct PerformanceMetrics {
        std::atomic<uint64_t> edge_updates{0};
        std::atomic<uint64_t> batch_updates{0};
        std::atomic<uint64_t> cache_hits{0};
        std::atomic<uint64_t> cache_misses{0};

        void reset() {
            edge_updates = 0;
            batch_updates = 0;
            cache_hits = 0;
            cache_misses = 0;
        }
    };

    PerformanceMetrics metrics;

    // Get performance report
    std::string getPerformanceReport() const;

private:
    // Atomically update global bitmap
    bool updateGlobalBitmap(uint32_t edge_id);

    // Batch atomic update
    void batchUpdateGlobalBitmap(const std::vector<uint32_t>& edges);

    // Safe update using CAS
    bool compareAndSwapEdge(uint32_t edge_id, uint8_t expected, uint8_t desired);
};

// Global instance accessor
LockFreeCoverageCollector& getGlobalCoverageCollector();

} // namespace triofuzz
