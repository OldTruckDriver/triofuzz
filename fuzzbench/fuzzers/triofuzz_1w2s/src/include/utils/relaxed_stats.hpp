#pragma once

#include <atomic>
#include <chrono>
#include <thread>

namespace triofuzz {

// Relaxed stats collector to reduce atomic overhead.
class RelaxedStatsCollector {
private:
    // Thread-local cache to reduce atomic operations.
    struct ThreadLocalStats {
        size_t executions = 0;
        size_t new_coverage = 0;
        size_t crashes = 0;
        double total_time = 0;

        // Flush in batches to global counters.
        void flush(RelaxedStatsCollector& global) {
            if (executions > 0) {
                global.global_executions_.fetch_add(executions, std::memory_order_relaxed);
                executions = 0;
            }
            if (new_coverage > 0) {
                global.global_new_coverage_.fetch_add(new_coverage, std::memory_order_relaxed);
                new_coverage = 0;
            }
            if (crashes > 0) {
                global.global_crashes_.fetch_add(crashes, std::memory_order_relaxed);
                crashes = 0;
            }
            if (total_time > 0) {
                // Use relaxed updates for time statistics.
                double current = global.global_time_.load(std::memory_order_relaxed);
                global.global_time_.compare_exchange_weak(current, current + total_time);
                total_time = 0;
            }
        }
    };

    // Global stats
    std::atomic<size_t> global_executions_{0};
    std::atomic<size_t> global_new_coverage_{0};
    std::atomic<size_t> global_crashes_{0};
    std::atomic<double> global_time_{0};

    // Thread-local storage
    static thread_local ThreadLocalStats local_stats_;
    static thread_local size_t update_counter_;

    static constexpr size_t FLUSH_THRESHOLD = 100;  // Flush every 100 updates.

public:
    // Hot-path update functions: thread-local only.
    __attribute__((always_inline))
    inline void recordExecution() {
        local_stats_.executions++;
        maybeFlush();
    }

    __attribute__((always_inline))
    inline void recordNewCoverage() {
        local_stats_.new_coverage++;
    }

    __attribute__((always_inline))
    inline void recordCrash() {
        local_stats_.crashes++;
    }

    __attribute__((always_inline))
    inline void recordTime(double time) {
        local_stats_.total_time += time;
    }

    // Batch record
    __attribute__((always_inline))
    inline void recordBatch(size_t executions, size_t new_coverage, size_t crashes, double time) {
        local_stats_.executions += executions;
        local_stats_.new_coverage += new_coverage;
        local_stats_.crashes += crashes;
        local_stats_.total_time += time;
        maybeFlush();
    }

    // Read global stats (not called frequently).
    size_t getTotalExecutions() {
        flushAll();
        return global_executions_.load(std::memory_order_acquire);
    }

    size_t getTotalNewCoverage() {
        flushAll();
        return global_new_coverage_.load(std::memory_order_acquire);
    }

    double getExecPerSec() {
        flushAll();
        double time = global_time_.load(std::memory_order_acquire);
        if (time > 0) {
            return global_executions_.load(std::memory_order_acquire) / time;
        }
        return 0;
    }

    // Force flush of thread-local cache.
    void flushAll() {
        local_stats_.flush(*this);
    }

private:
    __attribute__((always_inline))
    inline void maybeFlush() {
        if (++update_counter_ >= FLUSH_THRESHOLD) {
            local_stats_.flush(*this);
            update_counter_ = 0;
        }
    }
};

// Global stats collector instance
inline RelaxedStatsCollector& getGlobalStatsCollector() {
    static RelaxedStatsCollector instance;
    return instance;
}

} // namespace triofuzz
