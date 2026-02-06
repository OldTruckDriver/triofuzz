#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <fstream>
#include <filesystem>

namespace triofuzz {

// Forward declarations
struct AlgorithmCombination;

/**
 * @brief Checkpoint data structure for crash recovery
 *
 * Contains all the state needed to resume fuzzing after a crash.
 */
struct CheckpointData {
    // Version for compatibility checking
    static constexpr uint32_t CURRENT_VERSION = 1;
    uint32_t version = CURRENT_VERSION;

    // Timestamp
    uint64_t timestamp_ns = 0;

    // Execution statistics
    uint64_t total_executions = 0;
    uint64_t total_crashes = 0;
    uint64_t total_new_coverage = 0;
    double elapsed_seconds = 0.0;

    // Thompson Sampling state - combination performance
    struct CombinationStats {
        size_t combination_hash = 0;
        std::string combination_str;  // For debugging/logging
        uint64_t executions = 0;
        uint64_t new_coverage_count = 0;
        uint64_t crash_count = 0;
        double total_reward = 0.0;
        double avg_reward = 0.0;
        double total_execution_time_ms = 0.0;
        double avg_execution_time_ms = 0.0;
    };
    std::vector<CombinationStats> combination_stats;

    // Coverage bitmap snapshot (optional, for faster recovery)
    std::vector<uint8_t> coverage_bitmap;
    size_t total_edges = 0;

    // Corpus metadata (seeds are on disk, just track which ones)
    std::vector<std::string> corpus_seed_files;
    size_t corpus_size = 0;

    // Tiered scheduler state (if enabled)
    struct TieredAlgorithmStats {
        std::string algorithm_name;
        uint64_t executions = 0;
        double total_time_ms = 0.0;
        uint64_t coverage_hits = 0;
        double total_reward = 0.0;
    };
    std::vector<TieredAlgorithmStats> tiered_stats;
};

/**
 * @brief Manages checkpoint creation and restoration for crash recovery
 */
class CheckpointManager {
public:
    struct Config {
        bool enabled = false;
        std::string checkpoint_dir = "./checkpoints";
        std::string checkpoint_file = "fuzzing_checkpoint.bin";
        std::chrono::seconds checkpoint_interval{60};  // Default: every 60 seconds
        bool atomic_write = true;  // Use atomic write (temp file + rename)
    };

    explicit CheckpointManager(const Config& config);
    ~CheckpointManager();

    // Enable/disable checkpointing
    void setEnabled(bool enabled) { config_.enabled = enabled; }
    bool isEnabled() const { return config_.enabled; }

    // Save checkpoint
    bool saveCheckpoint(const CheckpointData& data);

    // Load checkpoint (returns true if successful)
    bool loadCheckpoint(CheckpointData& data);

    // Check if a checkpoint exists
    bool hasCheckpoint() const;

    // Get checkpoint file path
    std::string getCheckpointPath() const;

    // Delete checkpoint (after successful completion)
    void deleteCheckpoint();

    // Get last checkpoint time
    std::chrono::system_clock::time_point getLastCheckpointTime() const {
        return last_checkpoint_time_;
    }

    // Check if it's time for a new checkpoint
    bool shouldCheckpoint() const;

    // Update last checkpoint time
    void markCheckpointDone();

    // Get statistics
    size_t getCheckpointCount() const { return checkpoint_count_; }

private:
    Config config_;
    mutable std::mutex mutex_;
    std::chrono::system_clock::time_point last_checkpoint_time_;
    std::atomic<size_t> checkpoint_count_{0};

    // Serialization helpers
    bool serializeToFile(const std::string& path, const CheckpointData& data);
    bool deserializeFromFile(const std::string& path, CheckpointData& data);

    // Atomic file write (write to temp, then rename)
    bool atomicWrite(const std::string& target_path, const std::vector<uint8_t>& data);
};

} // namespace triofuzz
