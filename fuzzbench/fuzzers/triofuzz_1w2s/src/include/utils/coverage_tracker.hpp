#pragma once

#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <thread>
#include <condition_variable>

namespace triofuzz {

struct LLVMCoverageData {
    std::string experiment_name;
    std::chrono::system_clock::time_point time_started;
    std::chrono::system_clock::time_point time_ended;
    
    // LLVM coverage metrics
    size_t regions = 0;
    size_t missed_regions = 0;
    double region_cover = 0.0;
    size_t functions = 0;
    size_t missed_functions = 0;
    double function_executed = 0.0;
    size_t lines = 0;
    size_t missed_lines = 0;
    double line_cover = 0.0;
    size_t branches = 0;
    size_t missed_branches = 0;
    double branch_cover = 0.0;
    // Time since start in seconds (supports sub-minute precision for sync).
    double time_seconds = 0.0;
};

class CoverageTracker {
public:
    struct Config {
        bool enabled = false;
        std::string output_dir = "./output";
        std::string data_file = "llvm_coverage_data.csv";
        // Use seconds granularity to better align with external snapshotting.
        std::chrono::seconds recording_interval = std::chrono::seconds(900);
        std::string experiment_name = "collafuzz_experiment";
        std::string target_binary = ""; // Path to the fuzzer binary for llvm-cov
        std::string profraw_pattern = "default.profraw";
        std::string profdata_file = "default.profdata";

        // Crash recovery: merge all historical profraw files
        bool merge_all_profraw = true;  // Default: merge all *.profraw files in output_dir
        bool use_unique_profraw_name = true;  // Use timestamp/pid in profraw filename
    };

    explicit CoverageTracker(const Config& config);
    ~CoverageTracker();

    // Start tracking - sets the LLVM_PROFILE_FILE environment variable.
    void start();

    // Stop tracking and generate the final report.
    void stop();

    // Manually trigger a coverage check and record.
    void recordCurrentCoverage();

    // Get configuration
    const Config& getConfig() const { return config_; }

    // Enable/disable
    void setEnabled(bool enabled) { config_.enabled = enabled; }
    bool isEnabled() const { return config_.enabled; }

private:
    Config config_;
    std::vector<LLVMCoverageData> coverage_records_;
    std::chrono::system_clock::time_point start_time_;
    std::chrono::system_clock::time_point last_record_time_;
    mutable std::mutex data_mutex_;
    std::atomic<bool> is_running_{false};
    
    // Periodic recording thread
    std::thread recording_thread_;
    std::atomic<bool> recording_active_{false};
    std::condition_variable recording_cv_;
    std::mutex recording_mutex_;

    // Internal helpers
    std::string getDataFilePath() const;
    std::string getProfrawPath() const;
    std::string getProfdataPath() const;

    // Generate unique profraw filename with timestamp and pid
    std::string generateUniqueProfrawName() const;

    // LLVM coverage toolchain operations
    bool mergeProfrawFiles();
    bool mergeAllProfrawFiles();  // Merge all *.profraw files in output_dir
    LLVMCoverageData extractCoverageData();
    bool exportToCSV();
    void createCSVHeader();

    // Parse `llvm-cov report` output
    LLVMCoverageData parseLLVMCovOutput(const std::string& output);

    // Periodic recording loop
    void recordingLoop();

    // Unique profraw filename for this process
    std::string unique_profraw_name_;
};

} // namespace triofuzz 
