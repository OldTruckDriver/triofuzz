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

// 高性能无锁覆盖率收集器
class LockFreeCoverageCollector {
public:
    static constexpr size_t MAP_SIZE = 65536;  // AFL标准大小
    static constexpr size_t CACHE_LINE_SIZE = 64;

    // 确保缓存行对齐，避免false sharing
    struct alignas(CACHE_LINE_SIZE) CoverageData {
        std::atomic<uint8_t> bitmap[MAP_SIZE];
        std::atomic<uint64_t> edge_discovery_count;
        std::atomic<uint64_t> total_edges;

        CoverageData() {
            reset();
        }

        void reset() {
            // 使用memset批量初始化
            std::memset((void*)bitmap, 0, sizeof(bitmap));
            edge_discovery_count = 0;
            total_edges = 0;
        }
    };

private:
    // 线程本地存储，减少竞争
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

    // 主覆盖率数据
    std::unique_ptr<CoverageData> coverage_data_;

    // 线程本地缓存
    static thread_local ThreadLocalData tls_data_;

    // 批量更新阈值
    static constexpr size_t BATCH_UPDATE_THRESHOLD = 100;

    // SIMD优化的位图比较
    bool hasNewCoverageSSE(const uint8_t* current, const uint8_t* new_coverage) const;

public:
    LockFreeCoverageCollector();
    ~LockFreeCoverageCollector() = default;

    // 禁止拷贝和移动（因为包含atomic成员）
    LockFreeCoverageCollector(const LockFreeCoverageCollector&) = delete;
    LockFreeCoverageCollector& operator=(const LockFreeCoverageCollector&) = delete;
    LockFreeCoverageCollector(LockFreeCoverageCollector&&) = delete;
    LockFreeCoverageCollector& operator=(LockFreeCoverageCollector&&) = delete;

    // 核心接口 - 无锁记录边覆盖
    inline bool recordEdge(uint32_t edge_id) {
        if (edge_id >= MAP_SIZE) {
            edge_id %= MAP_SIZE;  // 简单哈希
        }

        // 先更新线程本地缓存
        uint8_t& local_val = tls_data_.local_bitmap[edge_id];
        if (local_val == 0) {
            local_val = 1;
            tls_data_.new_edges.push_back(edge_id);
            tls_data_.hits++;

            // 达到批量更新阈值时，更新全局位图
            if (tls_data_.hits >= BATCH_UPDATE_THRESHOLD) {
                flushThreadLocal();
            }
            return true;
        }

        // 检查全局位图（只读，无锁）
        uint8_t global_val = coverage_data_->bitmap[edge_id].load(std::memory_order_relaxed);
        return global_val == 0;
    }

    // 批量记录覆盖率
    size_t recordCoverageBatch(const std::vector<uint32_t>& edges);

    // 快速检查是否有新覆盖
    bool hasNewCoverage(const std::bitset<MAP_SIZE>& test_coverage) const;

    // 获取当前覆盖率统计
    struct CoverageStats {
        size_t total_edges;
        size_t unique_edges;
        double coverage_percentage;
        size_t new_edges_this_round;
    };

    CoverageStats getStats() const;

    // 获取覆盖率位图快照（用于种子去重）
    std::bitset<MAP_SIZE> getCoverageBitmap() const;

    // 合并其他收集器的覆盖率（用于多线程合并）
    void merge(const LockFreeCoverageCollector& other);

    // 重置覆盖率
    void reset();

    // 强制刷新线程本地缓存到全局
    void flushThreadLocal();

    // 获取稀有边（命中次数少的边）
    std::vector<uint32_t> getRareEdges(uint8_t threshold = 3) const;

    // 获取所有已覆盖的边ID列表 (用于互补性实验分析)
    std::vector<uint32_t> getCoveredEdges() const;

    // 保存已覆盖的边到文件 (用于互补性实验分析)
    bool saveCoveredEdgesToFile(const std::string& output_path) const;

    // 使用SIMD加速的覆盖率比较
    size_t compareAndUpdateCoverage(const uint8_t* new_coverage, size_t size);

    // 性能监控
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

    // 获取性能报告
    std::string getPerformanceReport() const;

private:
    // 原子更新全局位图
    bool updateGlobalBitmap(uint32_t edge_id);

    // 批量原子更新
    void batchUpdateGlobalBitmap(const std::vector<uint32_t>& edges);

    // 使用CAS操作的安全更新
    bool compareAndSwapEdge(uint32_t edge_id, uint8_t expected, uint8_t desired);
};

// 全局实例获取
LockFreeCoverageCollector& getGlobalCoverageCollector();

} // namespace triofuzz