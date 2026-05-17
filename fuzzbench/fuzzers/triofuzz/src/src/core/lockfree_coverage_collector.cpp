#include "../../include/core/lockfree_coverage_collector.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <fstream>
#include <iostream>

namespace triofuzz {

// Thread-local storage definition
thread_local LockFreeCoverageCollector::ThreadLocalData LockFreeCoverageCollector::tls_data_;

LockFreeCoverageCollector::LockFreeCoverageCollector()
    : coverage_data_(std::make_unique<CoverageData>()) {
    metrics.reset();
}

bool LockFreeCoverageCollector::updateGlobalBitmap(uint32_t edge_id) {
    if (edge_id >= MAP_SIZE) return false;

    uint8_t expected = 0;
    uint8_t desired = 1;

    // Atomically update using CAS
    bool success = coverage_data_->bitmap[edge_id].compare_exchange_weak(
        expected, desired,
        std::memory_order_acq_rel,
        std::memory_order_relaxed
    );

    if (success) {
        coverage_data_->total_edges.fetch_add(1, std::memory_order_relaxed);
        coverage_data_->edge_discovery_count.fetch_add(1, std::memory_order_relaxed);
        metrics.edge_updates.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    return false;
}

void LockFreeCoverageCollector::flushThreadLocal() {
    if (tls_data_.new_edges.empty()) return;

    // Batch-update the global bitmap
    for (uint32_t edge_id : tls_data_.new_edges) {
        updateGlobalBitmap(edge_id);
    }

    metrics.batch_updates.fetch_add(1, std::memory_order_relaxed);

    // Clear thread-local data
    tls_data_.reset();
}

size_t LockFreeCoverageCollector::recordCoverageBatch(const std::vector<uint32_t>& edges) {
    size_t new_edges = 0;

    // Process in chunks to avoid long-running work
    const size_t CHUNK_SIZE = 64;  // Cache-friendly size

    for (size_t i = 0; i < edges.size(); i += CHUNK_SIZE) {
        size_t end = std::min(i + CHUNK_SIZE, edges.size());

        // Pre-check to reduce atomic operations
        std::vector<uint32_t> candidates;
        candidates.reserve(CHUNK_SIZE);

        for (size_t j = i; j < end; j++) {
            uint32_t edge_id = edges[j] % MAP_SIZE;

            // Quickly check the global bitmap (read-only)
            if (coverage_data_->bitmap[edge_id].load(std::memory_order_relaxed) == 0) {
                candidates.push_back(edge_id);
            }
        }

        // Batch-update candidate edges
        for (uint32_t edge_id : candidates) {
            if (updateGlobalBitmap(edge_id)) {
                new_edges++;
            }
        }
    }

    return new_edges;
}

bool LockFreeCoverageCollector::hasNewCoverage(const std::bitset<MAP_SIZE>& test_coverage) const {
    // SIMD-optimized comparison
    const uint64_t* test_data = reinterpret_cast<const uint64_t*>(&test_coverage);
    const size_t chunks = MAP_SIZE / 64;

    for (size_t i = 0; i < chunks; i++) {
        uint64_t test_chunk = test_data[i];
        if (test_chunk == 0) continue;

        // Check each bit in this chunk
        for (size_t bit = 0; bit < 64; bit++) {
            if (test_chunk & (1ULL << bit)) {
                size_t edge_id = i * 64 + bit;
                if (coverage_data_->bitmap[edge_id].load(std::memory_order_relaxed) == 0) {
                    const_cast<PerformanceMetrics&>(metrics).cache_misses.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
            }
        }
    }

    const_cast<PerformanceMetrics&>(metrics).cache_hits.fetch_add(1, std::memory_order_relaxed);
    return false;
}

LockFreeCoverageCollector::CoverageStats LockFreeCoverageCollector::getStats() const {
    CoverageStats stats;

    // Ensure thread-local data has been flushed
    const_cast<LockFreeCoverageCollector*>(this)->flushThreadLocal();

    // Count covered edges
    size_t covered_edges = 0;
    for (size_t i = 0; i < MAP_SIZE; i++) {
        if (coverage_data_->bitmap[i].load(std::memory_order_relaxed) > 0) {
            covered_edges++;
        }
    }

    stats.total_edges = coverage_data_->total_edges.load(std::memory_order_relaxed);
    stats.unique_edges = covered_edges;
    stats.coverage_percentage = (covered_edges * 100.0) / MAP_SIZE;
    stats.new_edges_this_round = tls_data_.new_edges.size();

    return stats;
}

std::bitset<LockFreeCoverageCollector::MAP_SIZE> LockFreeCoverageCollector::getCoverageBitmap() const {
    std::bitset<MAP_SIZE> bitmap;

    for (size_t i = 0; i < MAP_SIZE; i++) {
        if (coverage_data_->bitmap[i].load(std::memory_order_relaxed) > 0) {
            bitmap.set(i);
        }
    }

    return bitmap;
}

void LockFreeCoverageCollector::merge(const LockFreeCoverageCollector& other) {
    // Merge coverage from two collectors
    for (size_t i = 0; i < MAP_SIZE; i++) {
        uint8_t other_val = other.coverage_data_->bitmap[i].load(std::memory_order_relaxed);
        if (other_val > 0) {
            uint8_t expected = 0;
            coverage_data_->bitmap[i].compare_exchange_weak(
                expected, other_val,
                std::memory_order_acq_rel,
                std::memory_order_relaxed
            );
        }
    }
}

void LockFreeCoverageCollector::reset() {
    coverage_data_->reset();
    tls_data_.reset();
    metrics.reset();
}

std::vector<uint32_t> LockFreeCoverageCollector::getRareEdges(uint8_t threshold) const {
    std::vector<uint32_t> rare_edges;

    for (uint32_t i = 0; i < MAP_SIZE; i++) {
        uint8_t count = coverage_data_->bitmap[i].load(std::memory_order_relaxed);
        if (count > 0 && count <= threshold) {
            rare_edges.push_back(i);
        }
    }

    return rare_edges;
}

size_t LockFreeCoverageCollector::compareAndUpdateCoverage(const uint8_t* new_coverage, size_t size) {
    size_t new_edges = 0;
    size_t check_size = std::min(size, MAP_SIZE);

    // Batch-compare using SIMD instructions (if available)
    #ifdef __AVX2__
    const size_t simd_size = 32;  // AVX2 processes 32 bytes
    size_t simd_iterations = check_size / simd_size;

    for (size_t i = 0; i < simd_iterations; i++) {
        size_t offset = i * simd_size;

        // Load new coverage data
        __m256i new_vec = _mm256_loadu_si256((__m256i*)(new_coverage + offset));

        // Load current coverage (requires per-byte atomic loads)
        uint8_t current[32];
        for (size_t j = 0; j < 32; j++) {
            current[j] = coverage_data_->bitmap[offset + j].load(std::memory_order_relaxed);
        }
        __m256i current_vec = _mm256_loadu_si256((__m256i*)current);

        // Find newly covered edges (new & ~current)
        __m256i new_edges_vec = _mm256_andnot_si256(current_vec, new_vec);

        // Update coverage
        uint8_t new_edges_array[32];
        _mm256_storeu_si256((__m256i*)new_edges_array, new_edges_vec);

        for (size_t j = 0; j < 32; j++) {
            if (new_edges_array[j]) {
                if (updateGlobalBitmap(offset + j)) {
                    new_edges++;
                }
            }
        }
    }

    // Handle remainder
    for (size_t i = simd_iterations * simd_size; i < check_size; i++) {
        if (new_coverage[i] && coverage_data_->bitmap[i].load(std::memory_order_relaxed) == 0) {
            if (updateGlobalBitmap(i)) {
                new_edges++;
            }
        }
    }
    #else
    // Non-SIMD fallback implementation
    for (size_t i = 0; i < check_size; i++) {
        if (new_coverage[i] && coverage_data_->bitmap[i].load(std::memory_order_relaxed) == 0) {
            if (updateGlobalBitmap(i)) {
                new_edges++;
            }
        }
    }
    #endif

    return new_edges;
}

std::string LockFreeCoverageCollector::getPerformanceReport() const {
    std::stringstream ss;

    ss << "=== Coverage Collector Performance Report ===" << std::endl;
    ss << std::fixed << std::setprecision(2);

    uint64_t total_updates = metrics.edge_updates.load(std::memory_order_relaxed);
    uint64_t batch_updates = metrics.batch_updates.load(std::memory_order_relaxed);
    uint64_t cache_hits = metrics.cache_hits.load(std::memory_order_relaxed);
    uint64_t cache_misses = metrics.cache_misses.load(std::memory_order_relaxed);

    ss << "Edge updates: " << total_updates << std::endl;
    ss << "Batch updates: " << batch_updates << std::endl;
    ss << "Avg batch size: " << (batch_updates > 0 ? total_updates / batch_updates : 0) << std::endl;

    uint64_t total_cache_ops = cache_hits + cache_misses;
    if (total_cache_ops > 0) {
        double hit_rate = (cache_hits * 100.0) / total_cache_ops;
        ss << "Cache hit rate: " << hit_rate << "%" << std::endl;
    }

    auto stats = getStats();
    ss << "Unique edges: " << stats.unique_edges << "/" << MAP_SIZE << std::endl;
    ss << "Coverage: " << stats.coverage_percentage << "%" << std::endl;

    return ss.str();
}

bool LockFreeCoverageCollector::compareAndSwapEdge(uint32_t edge_id, uint8_t expected, uint8_t desired) {
    if (edge_id >= MAP_SIZE) return false;

    return coverage_data_->bitmap[edge_id].compare_exchange_strong(
        expected, desired,
        std::memory_order_acq_rel,
        std::memory_order_relaxed
    );
}

// Get list of all covered edge IDs (for complementarity experiment analysis)
std::vector<uint32_t> LockFreeCoverageCollector::getCoveredEdges() const {
    std::vector<uint32_t> covered_edges;
    covered_edges.reserve(MAP_SIZE / 10);  // Preallocate space

    // Scan bitmap and collect all non-zero edges
    for (uint32_t i = 0; i < MAP_SIZE; ++i) {
        uint8_t val = coverage_data_->bitmap[i].load(std::memory_order_relaxed);
        if (val > 0) {
            covered_edges.push_back(i);
        }
    }

    return covered_edges;
}

// Save covered edges to a file (for complementarity experiment analysis)
bool LockFreeCoverageCollector::saveCoveredEdgesToFile(const std::string& output_path) const {
    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::cerr << "[LockFreeCoverageCollector] Failed to open file for writing: "
                  << output_path << std::endl;
        return false;
    }

    // Get all covered edges
    auto covered_edges = getCoveredEdges();

    // Write to file
    out << "# Covered Edges - Total: " << covered_edges.size() << "\n";
    out << "# Format: one edge ID per line\n";
    for (uint32_t edge_id : covered_edges) {
        out << edge_id << "\n";
    }

    out.close();

    std::cout << "[LockFreeCoverageCollector] Saved " << covered_edges.size()
              << " covered edges to " << output_path << std::endl;

    return true;
}

// Global instance
LockFreeCoverageCollector& getGlobalCoverageCollector() {
    static LockFreeCoverageCollector instance;
    return instance;
}

} // namespace triofuzz
