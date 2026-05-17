// CollaFuzz Main Interface - Framework Implementation
// This file provides the main entry point and will be part of the pre-compiled library
// The framework itself is NOT instrumented, only the target code is instrumented

#include "../../include/collafuzz.h"
#include "../../include/core/engine.hpp"
#include "../../include/core/lockfree_coverage_collector.hpp"
#include "../../include/utils/random_utils.hpp"
#include "../../include/utils/algorithm_registry.hpp"
#include "../../include/utils/algorithm_config.hpp"  // Centralized algorithm configuration
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <future>
#include <sstream>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <queue>
#include <condition_variable>
#include <mutex>
#include <functional>
#include <algorithm>
#include "../core/enhanced_crash_tracker.h"

// External function declarations
extern "C" __attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

// LLVM profile writing function (weak symbol for when not using coverage)
extern "C" __attribute__((weak)) void __llvm_profile_write_file(void);

// Global variable declaration, used by crash handler
extern thread_local std::vector<uint8_t> g_current_fuzzing_input;

// Coverage collection interface - implemented in fuzzing_engine.cpp
void resetRealCoverage();
void clearRealCoverageState();
void shutdownRealCoverageCollector();  // Safe shutdown interface
triofuzz::CoverageInfo getCurrentRealCoverage();
bool saveRealCoverageEdges(const std::string& output_path);  // Save coverage edges to file

// Prevent framework from being instrumented - this file is compiled as a library without instrumentation
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(coverage_sanitizer) || defined(__SANITIZE_ADDRESS__)
#warning "CollaFuzz framework should NOT be compiled with sanitizers"
#endif

namespace {

// Default configuration
struct triofuzzConfig default_config = {
    64 * 1024,        // max_len
    1000,             // timeout_ms
    0,                // max_total_time
    0,                // max_executions
    "./output", // output_dir
    1,                // verbose
    0,                // threads (auto-detect)
    "./seeds",        // seeds_dir
    "",               // dict_file
    2048              // memory_limit_mb - default 2GB
};

// Check user-defined functions
extern "C" {
    // Declare optional configuration
    extern struct triofuzzConfig triofuzz_config __attribute__((weak));
}

// Global configuration - user can override
struct triofuzzConfig triofuzz_config __attribute__((weak)) = {
    64 * 1024,        // max_len
    1000,             // timeout_ms
    0,                // max_total_time
    0,                // max_executions
    "./output", // output_dir
    1,                // verbose
    0,                // threads
    "./seeds",        // seeds_dir
    "",               // dict_file
    2048              // memory_limit_mb - increased to 2GB for decompression workloads
};

// Global variables storing CLI parameter overrides
static struct {
    int max_total_time = -1;  // -1 means not set
    int max_executions = -1;  // -1 means not set
    int verbose = -1;         // -1 means not set
    int timeout_ms = -1;      // -1 means not set
    int max_len = -1;         // -1 means not set
    int threads = -1;         // -1 means not set
    int memory_limit_mb = -1; // -1 means not set, memory limit (MB)
    std::string output_dir;   // Empty string means not set
    std::string seeds_dir;    // Empty string means not set
    std::string dict_file;    // Dictionary file path
    bool enable_dynamic_combination = true;  // Enable dynamic combination by default
    std::vector<std::vector<std::string>> thread_algorithm_combinations;  // Fixed thread combinations
    bool disable_corpus_optimization = false; // Enable corpus optimization by default (used in unified mode)
    int mopt_update_period = 500000;          // Used in unified mode
    int ts_update_period = 50000;          // Used in unified mode
    double ts_decay = 0.95;             // Used in unified mode
    int ts_havoc_stack_pow2 = 4;           // Used in unified mode

    // TrioFuzz Unified: Three-layer learning architecture
    bool use_triofuzz_unified = false;        // Enable unified learning mode
    bool enable_ts = true;              // Layer 1: Thompson Sampling
    bool enable_ecofuzz = true;               // Allow EcoFuzz power schedule in unified learner
    bool enable_mopt_pso = true;              // Layer 2: MOpt PSO
    bool enable_muofuzz_markov = true;        // Layer 3: MuoFuzz Markov

    // Hybrid period configuration for non-stationary adaptation
    int ts_time_period_sec = 30;           // TS time period (default: 30s)
    int mopt_time_period_sec = 30;            // MOpt PSO time period (default: 30s)
    int markov_time_period_sec = 5;           // Markov time period (default: 5s)
    int ts_min_samples = 100;              // TS minimum samples
    int mopt_min_samples = 500;               // MOpt PSO minimum samples
    int markov_min_samples = 50;              // Markov minimum samples
} cli_overrides;

// Helper function: get effective configuration
const triofuzzConfig& getEffectiveConfig() {
    static triofuzzConfig effective_config = triofuzz_config;

    // Check mutual exclusivity of max_total_time and max_executions
    if (cli_overrides.max_total_time >= 0 && cli_overrides.max_executions >= 0) {
        std::cerr << "[ERROR] -max_total_time and -max_executions are mutually exclusive. Please use only one.\n";
        exit(1);
    }

    // Apply CLI overrides
    if (cli_overrides.max_total_time >= 0) {
        effective_config.max_total_time = cli_overrides.max_total_time;
        effective_config.max_executions = 0; // Ensure the other is 0
    }
    if (cli_overrides.max_executions >= 0) {
        effective_config.max_executions = cli_overrides.max_executions;
        effective_config.max_total_time = 0; // Ensure the other is 0
    }
    if (cli_overrides.verbose >= 0) {
        effective_config.verbose = cli_overrides.verbose;
    }
    if (cli_overrides.timeout_ms >= 0) {
        effective_config.timeout_ms = cli_overrides.timeout_ms;
    }
    if (cli_overrides.max_len >= 0) {
        effective_config.max_len = cli_overrides.max_len;
    }
    if (cli_overrides.threads >= 0) {
        effective_config.threads = cli_overrides.threads;
    }
    if (cli_overrides.memory_limit_mb >= 0) {
        effective_config.memory_limit_mb = cli_overrides.memory_limit_mb;
    }
    if (!cli_overrides.output_dir.empty()) {
        effective_config.output_dir = cli_overrides.output_dir.c_str();
    }
    if (!cli_overrides.seeds_dir.empty()) {
        effective_config.seeds_dir = cli_overrides.seeds_dir.c_str();
    }
    if (!cli_overrides.dict_file.empty()) {
        effective_config.dict_file = cli_overrides.dict_file.c_str();
    }

    return effective_config;
}

// Test function wrapper
class TestFunctionWrapper {
private:
    typedef int (*TestFunc)(const uint8_t*, size_t);
    TestFunc test_func_;

public:
    TestFunctionWrapper() : test_func_(nullptr) {
        if (LLVMFuzzerTestOneInput) {
            test_func_ = LLVMFuzzerTestOneInput;
            if (getEffectiveConfig().verbose) {
                std::cout << "[TrioFuzz] Using LLVMFuzzerTestOneInput function" << std::endl;
            }
        } else {
            std::cerr << "[TrioFuzz] ERROR: No LLVMFuzzerTestOneInput function found!" << std::endl;
            std::cerr << "[TrioFuzz] Please define:" << std::endl;
            std::cerr << "[TrioFuzz]   int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);" << std::endl;
            exit(1);
        }
    }

    int execute(const std::vector<uint8_t>& input) {
        if (!test_func_) return -1;

        try {
            return test_func_(input.data(), input.size());
        } catch (const std::exception& e) {
            if (getEffectiveConfig().verbose) {
                std::cerr << "[TrioFuzz] Exception in LLVMFuzzerTestOneInput: " << e.what() << std::endl;
            }
            return -1; // Treat as crash
        } catch (...) {
            if (getEffectiveConfig().verbose) {
                std::cerr << "[TrioFuzz] Unknown exception in LLVMFuzzerTestOneInput" << std::endl;
            }
            return -1; // Treat as crash
        }
    }
};

// In-process executor - optimized: direct call, no thread pool overhead
class InProcessExecutor : public triofuzz::Executor {
private:
    TestFunctionWrapper& wrapper_;
    std::chrono::milliseconds timeout_;

public:
    explicit InProcessExecutor(TestFunctionWrapper& wrapper)
        : wrapper_(wrapper), timeout_(1000) {
        // No thread pool created; execute directly to reduce overhead
    }

    ~InProcessExecutor() {
        // No thread pool to clean up
    }

    triofuzz::ExecutionResult execute(
        const std::vector<uint8_t>& input,
        const std::chrono::milliseconds& timeout) override {

        // Set current input in crash tracker
        auto& crash_tracker = collafuzz::crash_tracker::EnhancedCrashTracker::getInstance();
        crash_tracker.setCurrentInput(input);

        triofuzz::ExecutionResult result;
        auto start_time = std::chrono::high_resolution_clock::now();

        // Update global current input variable for crash handler
        g_current_fuzzing_input = input;

        try {
            // Direct execution, no thread pool overhead
            int ret = wrapper_.execute(input);

            auto end_time = std::chrono::high_resolution_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();

            // Set execution status
            if (ret == 0) {
                result.status = triofuzz::ExecutionResult::Status::Success;
            } else {
                result.status = triofuzz::ExecutionResult::Status::Crash;
                result.crash_info.push_back("LLVMFuzzerTestOneInput returned non-zero: " + std::to_string(ret));
            }

            // Fill in performance info
            result.performance.execution_time_ms = static_cast<double>(us) / 1000.0;
            result.performance.memory_usage_bytes = input.size();

            // Get coverage info (collected automatically by instrumentation)
            // Coverage collection already has caching, no extra optimization needed
            result.coverage = getCurrentRealCoverage();

            result.output = input;
            result.input_data = input;

        } catch (const std::exception& e) {
            result.status = triofuzz::ExecutionResult::Status::Error;
            result.error_message = e.what();

            auto end_time = std::chrono::high_resolution_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
            result.performance.execution_time_ms = static_cast<double>(us) / 1000.0;
            result.performance.memory_usage_bytes = input.size();
        } catch (...) {
            result.status = triofuzz::ExecutionResult::Status::Error;
            result.error_message = "Unknown exception in test function";

            auto end_time = std::chrono::high_resolution_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
            result.performance.execution_time_ms = static_cast<double>(us) / 1000.0;
            result.performance.memory_usage_bytes = input.size();
        }

        return result;
    }

    void setEnvironment(const std::map<std::string, std::string>& env) override {
        // In-process execution doesn't need environment setup
    }

    void setMemoryLimit(size_t limit_mb) override {
        // In-process execution uses the same memory space
    }

    void setTimeLimit(std::chrono::milliseconds limit) override {
        timeout_ = limit;
    }
};

void print_usage(const char* program_name) {
    std::cout << "CollaFuzz - Collaborative Fuzzing Framework\n\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -max_len=N                      Maximum input length (default: " << default_config.max_len << ")\n";
    std::cout << "  -timeout=N                      Timeout in milliseconds (default: " << default_config.timeout_ms << ")\n";
    std::cout << "  -memory_limit_mb=N              Memory limit in MB (default: 2048)\n";
    std::cout << "  -max_total_time=N               Maximum total runtime in seconds (default: unlimited)\n";
    std::cout << "  -max_executions=N               Maximum total executions (default: unlimited, mutually exclusive with -max_total_time)\n";
    std::cout << "  -output=DIR                     Output directory for results\n";
    std::cout << "  -seeds=DIR                      Seeds directory\n";
    std::cout << "  -dict=FILE                      Dictionary file for smart_dictionary algorithm\n";
    std::cout << "  -verbose=N                      Verbosity level (0=quiet, 1=normal)\n";
    std::cout << "  -threads=N                      Number of threads to use\n";
    std::cout << "  --worker-threads=N               Number of worker threads (specialized mode)\n";
    std::cout << "  --explorer-threads=N             Number of explorer threads (specialized mode)\n";
    std::cout << "  --algorithms=LIST               Comma-separated algorithm list\n";
    std::cout << "                                  Performance mode: havoc,bitflip,arithmetic,splice,magic_byte\n";
    std::cout << "                                  Full mode: (default, all 20+ algorithms enabled)\n  --enable-cmplog                  Enable CmpLog recording (default)\n  --disable-cmplog                 Disable CmpLog recording (set triofuzz_DISABLE_CMPLOG=1)\n";
    std::cout << "  --enable-dynamic-combination    Enable dynamic algorithm combination (default)\n";
    std::cout << "  --disable-dynamic-combination   Disable dynamic combination and use fixed combinations\n";

    std::cout << "\nTrioFuzz Unified Mode (three-layer learning):\n";
    std::cout << "  --use-triofuzz-unified              Enable unified three-layer learner\n";
    std::cout << "  --enable-ecofuzz                    Include EcoFuzz power schedule arm (default)\n";
    std::cout << "  --disable-ecofuzz                   Exclude EcoFuzz power schedule arm\n";
    std::cout << "  --enable-mopt-pso                   Enable Layer 2 (MOpt PSO)\n";
    std::cout << "  --disable-mopt-pso                  Disable Layer 2 (MOpt PSO)\n";
    std::cout << "  --enable-muofuzz-markov             Enable Layer 3 (MuoFuzz Markov)\n";
    std::cout << "  --disable-muofuzz-markov            Disable Layer 3 (MuoFuzz Markov)\n";

    std::cout << "\nHybrid Period Configuration (for non-stationary adaptation):\n";
    std::cout << "  --ts-time-period=N              TS time period in seconds (default: 30)\n";
    std::cout << "  --mopt-time-period=N               MOpt PSO time period in seconds (default: 30)\n";
    std::cout << "  --markov-time-period=N             Markov time period in seconds (default: 5)\n";
    std::cout << "  --ts-min-samples=N              TS minimum samples for time trigger (default: 100)\n";
    std::cout << "  --mopt-min-samples=N               MOpt PSO minimum samples for time trigger (default: 500)\n";
    std::cout << "  --markov-min-samples=N             Markov minimum samples for time trigger (default: 50)\n";
    std::cout << "\nCoverage Signal Options:\n";
    std::cout << "  --include-guard-coverage              Also record guard IDs (basic-block coverage) into the AFL-style bitmap\n";
    std::cout << "\nCorpus Optimization Options:\n";
    std::cout << "  --disable-corpus-optimization       Disable automatic corpus optimization\n";
    std::cout << "\nCollaFuzz Features:\n";
    std::cout << "  - Multi-algorithm collaboration (PSO, Thompson Sampling, MCTS)\n";
    std::cout << "  - Real-time coverage feedback\n";
    std::cout << "  - Adaptive algorithm selection\n";
    std::cout << "  - Automatic stagnation recovery\n";
    std::cout << "  - Coverage growth tracking and visualization\n";
    std::cout << "Required:\n";
    std::cout << "  - Define: int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)\n";
    std::cout << "  - Compile target with: -fsanitize-coverage=trace-pc-guard\n";
    std::cout << "  - Link with: -lcollafuzz\n\n";
}

triofuzz::FuzzingConfig create_fuzzing_config(int argc, char* argv[]) {
    triofuzz::FuzzingConfig config;

    // Use user config or default config
    // If the user set memory_limit_mb, use it; otherwise use the configured value or compute default
    if (cli_overrides.memory_limit_mb > 0) {
        config.memory_limit_mb = cli_overrides.memory_limit_mb;
    } else if (getEffectiveConfig().memory_limit_mb > 0) {
        config.memory_limit_mb = getEffectiveConfig().memory_limit_mb;
    } else {
        config.memory_limit_mb = std::max(size_t(2048), getEffectiveConfig().max_len / 1024);  // At least 2GB
    }
    config.timeout = std::chrono::milliseconds(getEffectiveConfig().timeout_ms);
    config.output_dir = getEffectiveConfig().output_dir ? getEffectiveConfig().output_dir : default_config.output_dir;

    // Thread count configuration
    config.thread_count = getEffectiveConfig().threads > 0 ?
        getEffectiveConfig().threads : std::thread::hardware_concurrency();

    config.max_input_size = getEffectiveConfig().max_len;
    config.combination_strategy = "thompson_sampling";
    config.enable_performance_monitoring = true;
    config.enable_crash_analysis = true;
    config.stats_interval = std::chrono::seconds(60);

    // Enable collaborative algorithms by default - unless overridden via command line
    std::vector<std::string> specified_algorithms;
    bool algorithms_specified = false;

    // Parse command line arguments first to check if algorithms were specified
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.substr(0, 13) == "--algorithms=") {
            algorithms_specified = true;
            std::string algorithms_str = arg.substr(13);
            std::stringstream ss(algorithms_str);
            std::string algorithm;
            while (std::getline(ss, algorithm, ',')) {
                // Trim whitespace
                algorithm.erase(algorithm.find_last_not_of(" \t") + 1);
                algorithm.erase(0, algorithm.find_first_not_of(" \t"));
                if (!algorithm.empty()) {
                    specified_algorithms.push_back(algorithm);
                }
            }
            break;
        }
    }

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-help" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        } else if (arg.rfind("--worker-threads=", 0) == 0) {
            const size_t worker_threads = std::stoul(arg.substr(strlen("--worker-threads=")));
            config.worker_threads_override = worker_threads;
            std::cout << "[CLI] Worker threads set to: " << worker_threads << std::endl;
        } else if (arg.rfind("--explorer-threads=", 0) == 0) {
            const size_t explorer_threads = std::stoul(arg.substr(strlen("--explorer-threads=")));
            config.explorer_threads = explorer_threads;
            config.explorer_threads_override = explorer_threads;
            std::cout << "[CLI] Explorer threads set to: " << explorer_threads << std::endl;
        } else if (arg.substr(0, 21) == "--mopt-update-period=") {
            cli_overrides.mopt_update_period = std::stoi(arg.substr(21));
            if (cli_overrides.mopt_update_period <= 0) cli_overrides.mopt_update_period = 1;
            std::cout << "[CLI] MOpt update period: " << cli_overrides.mopt_update_period << std::endl;
        } else if (arg.substr(0, 19) == "--ts-update-period=") {
            cli_overrides.ts_update_period = std::stoi(arg.substr(19));
            if (cli_overrides.ts_update_period <= 0) cli_overrides.ts_update_period = 1;
            std::cout << "[CLI] TS update period: " << cli_overrides.ts_update_period << std::endl;
        } else if (arg.substr(0, 11) == "--ts-decay=") {
            try {
                cli_overrides.ts_decay = std::stod(arg.substr(11));
            } catch (...) {
                cli_overrides.ts_decay = 0.95;
            }
            if (cli_overrides.ts_decay < 0.0) cli_overrides.ts_decay = 0.0;
            if (cli_overrides.ts_decay > 1.0) cli_overrides.ts_decay = 1.0;
            std::cout << "[CLI] TS decay: " << cli_overrides.ts_decay << std::endl;
        } else if (arg.substr(0, 22) == "--ts-havoc-stack-pow2=") {
            cli_overrides.ts_havoc_stack_pow2 = std::stoi(arg.substr(22));
            if (cli_overrides.ts_havoc_stack_pow2 <= 0) cli_overrides.ts_havoc_stack_pow2 = 1;
            std::cout << "[CLI] TS havoc stack pow2: " << cli_overrides.ts_havoc_stack_pow2 << std::endl;
        } else if (arg == "--use-triofuzz-unified") {
            cli_overrides.use_triofuzz_unified = true;
            std::cout << "[CLI] TrioFuzz Unified three-layer learning enabled" << std::endl;
        } else if (arg == "--enable-ecofuzz") {
            cli_overrides.enable_ecofuzz = true;
            std::cout << "[CLI] EcoFuzz power schedule enabled" << std::endl;
        } else if (arg == "--disable-ecofuzz") {
            cli_overrides.enable_ecofuzz = false;
            std::cout << "[CLI] EcoFuzz power schedule disabled" << std::endl;
        } else if (arg == "--enable-mopt-pso") {
            cli_overrides.enable_mopt_pso = true;
            std::cout << "[CLI] TrioFuzz Layer 2 (MOpt PSO) enabled" << std::endl;
        } else if (arg == "--disable-mopt-pso") {
            cli_overrides.enable_mopt_pso = false;
            std::cout << "[CLI] TrioFuzz Layer 2 (MOpt PSO) disabled" << std::endl;
        } else if (arg == "--enable-muofuzz-markov") {
            cli_overrides.enable_muofuzz_markov = true;
            std::cout << "[CLI] TrioFuzz Layer 3 (MuoFuzz Markov) enabled" << std::endl;
        } else if (arg == "--disable-muofuzz-markov") {
            cli_overrides.enable_muofuzz_markov = false;
            std::cout << "[CLI] TrioFuzz Layer 3 (MuoFuzz Markov) disabled" << std::endl;
        // Hybrid period configuration
        } else if (arg.substr(0, 17) == "--ts-time-period=") {
            cli_overrides.ts_time_period_sec = std::stoi(arg.substr(17));
            if (cli_overrides.ts_time_period_sec <= 0) cli_overrides.ts_time_period_sec = 1;
            std::cout << "[CLI] TS time period: " << cli_overrides.ts_time_period_sec << "s" << std::endl;
        } else if (arg.substr(0, 19) == "--mopt-time-period=") {
            cli_overrides.mopt_time_period_sec = std::stoi(arg.substr(19));
            if (cli_overrides.mopt_time_period_sec <= 0) cli_overrides.mopt_time_period_sec = 1;
            std::cout << "[CLI] MOpt time period: " << cli_overrides.mopt_time_period_sec << "s" << std::endl;
        } else if (arg.substr(0, 21) == "--markov-time-period=") {
            cli_overrides.markov_time_period_sec = std::stoi(arg.substr(21));
            if (cli_overrides.markov_time_period_sec <= 0) cli_overrides.markov_time_period_sec = 1;
            std::cout << "[CLI] Markov time period: " << cli_overrides.markov_time_period_sec << "s" << std::endl;
        } else if (arg.substr(0, 17) == "--ts-min-samples=") {
            cli_overrides.ts_min_samples = std::stoi(arg.substr(17));
            if (cli_overrides.ts_min_samples <= 0) cli_overrides.ts_min_samples = 1;
            std::cout << "[CLI] TS min samples: " << cli_overrides.ts_min_samples << std::endl;
        } else if (arg.substr(0, 19) == "--mopt-min-samples=") {
            cli_overrides.mopt_min_samples = std::stoi(arg.substr(19));
            if (cli_overrides.mopt_min_samples <= 0) cli_overrides.mopt_min_samples = 1;
            std::cout << "[CLI] MOpt min samples: " << cli_overrides.mopt_min_samples << std::endl;
        } else if (arg.substr(0, 21) == "--markov-min-samples=") {
            cli_overrides.markov_min_samples = std::stoi(arg.substr(21));
            if (cli_overrides.markov_min_samples <= 0) cli_overrides.markov_min_samples = 1;
            std::cout << "[CLI] Markov min samples: " << cli_overrides.markov_min_samples << std::endl;
        } else if (arg.substr(0, 13) == "--algorithms=") {
            // Already handled above
            continue;
        } else if (arg.substr(0, 9) == "-max_len=") {
            config.max_input_size = std::stoul(arg.substr(9));
            cli_overrides.max_len = std::stoul(arg.substr(9));
        } else if (arg.substr(0, 17) == "-memory_limit_mb=") {
            cli_overrides.memory_limit_mb = std::stoi(arg.substr(17));
        } else if (arg.substr(0, 9) == "-timeout=") {
            config.timeout = std::chrono::milliseconds(std::stoul(arg.substr(9)));
            cli_overrides.timeout_ms = std::stoul(arg.substr(9));
        } else if (arg.substr(0, 16) == "-max_total_time=") {
            cli_overrides.max_total_time = std::stoul(arg.substr(16));
        } else if (arg.substr(0, 16) == "-max_executions=") {
            cli_overrides.max_executions = std::stoul(arg.substr(16));
        } else if (arg.substr(0, 8) == "-output=") {
            config.output_dir = arg.substr(8);
            cli_overrides.output_dir = arg.substr(8);
        } else if (arg.substr(0, 7) == "-seeds=") {
            cli_overrides.seeds_dir = arg.substr(7);
        } else if (arg.substr(0, 6) == "-dict=") {
            cli_overrides.dict_file = arg.substr(6);
        } else if (arg.substr(0, 9) == "-verbose=") {
            cli_overrides.verbose = std::stoul(arg.substr(9));
        } else if (arg.substr(0, 9) == "-threads=") {
            config.thread_count = std::stoul(arg.substr(9));
            cli_overrides.threads = std::stoul(arg.substr(9));
        } else if (arg == "--tui" || arg == "--no-tui") {
            // TUI archived - ignored
        } else if (arg == "--include-guard-coverage") {
            ::setenv("TRIOFUZZ_INCLUDE_GUARD_COVERAGE", "1", 1);
            std::cout << "[CLI] Including guard IDs in the AFL bitmap (TRIOFUZZ_INCLUDE_GUARD_COVERAGE=1)" << std::endl;
        } else if (arg == "--disable-corpus-optimization") {
            cli_overrides.disable_corpus_optimization = true;
        }
    }

    // After parsing command line arguments, apply algorithm combination mode settings
    config.enable_dynamic_combination = cli_overrides.enable_dynamic_combination;

    // If dynamic combination is disabled and fixed combinations are configured, use fixed combinations
    if (!cli_overrides.enable_dynamic_combination && !cli_overrides.thread_algorithm_combinations.empty()) {
        config.fixed_combination.thread_algorithm_combinations = cli_overrides.thread_algorithm_combinations;
        config.fixed_combination.fixed_combination_mode = "sequential";  // Default to sequential mode
    }

    // Configure enabled algorithms - after all cli_overrides are set
    if (algorithms_specified && !specified_algorithms.empty()) {
        // Use user-specified algorithms
        config.enabled_algorithms = specified_algorithms;
        std::cout << "[DEBUG] Using user-specified algorithms, count=" << specified_algorithms.size() << std::endl;
    } else if (!cli_overrides.enable_dynamic_combination && !cli_overrides.thread_algorithm_combinations.empty()) {
        // When using fixed combinations, only enable the algorithms specified in them
        std::cout << "[DEBUG] Using fixed combination path - enable_dynamic=" << cli_overrides.enable_dynamic_combination << ", combinations_size=" << cli_overrides.thread_algorithm_combinations.size() << std::endl;
        std::set<std::string> unique_algorithms;
        for (const auto& thread_combo : cli_overrides.thread_algorithm_combinations) {
            for (const auto& algorithm : thread_combo) {
                unique_algorithms.insert(algorithm);
            }
        }
        config.enabled_algorithms = std::vector<std::string>(unique_algorithms.begin(), unique_algorithms.end());
        std::cout << "[INFO] Using fixed combinations, only enabling algorithms: ";
        for (size_t i = 0; i < config.enabled_algorithms.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << config.enabled_algorithms[i];
        }
        std::cout << std::endl;
    } else {
        std::cout << "[DEBUG] Using default algorithms path - enable_dynamic=" << cli_overrides.enable_dynamic_combination << ", combinations_size=" << cli_overrides.thread_algorithm_combinations.size() << std::endl;
        // Enable all available algorithms by default
        // Users can select specific algorithms via --algorithms
        // Recommended high-performance config: --algorithms=havoc,bitflip,arithmetic,afl_plus_plus,fairfuzz
        // Use centralized algorithm configuration
        config.enabled_algorithms = triofuzz::AlgorithmConfig::ENABLED_MUTATIONS;
    }

    // Set dictionary file path
    if (!cli_overrides.dict_file.empty()) {
        config.dictionary_file = cli_overrides.dict_file;
    } else if (getEffectiveConfig().dict_file && strlen(getEffectiveConfig().dict_file) > 0) {
        config.dictionary_file = getEffectiveConfig().dict_file;
    }

    config.disable_corpus_optimization = cli_overrides.disable_corpus_optimization;

    // MOpt update period (used in unified mode)
    config.mopt_update_period = static_cast<size_t>(std::max(1, cli_overrides.mopt_update_period));

    // TS params (used in unified mode)
    config.ts_update_period = static_cast<size_t>(std::max(1, cli_overrides.ts_update_period));
    config.ts_decay = std::min(1.0, std::max(0.0, cli_overrides.ts_decay));
    config.ts_havoc_stack_pow2 = static_cast<uint32_t>(std::max(1, cli_overrides.ts_havoc_stack_pow2));

    // TrioFuzz Unified: Three-layer learning architecture configuration
    config.use_triofuzz_unified = cli_overrides.use_triofuzz_unified;
    config.enable_ts = cli_overrides.enable_ts;
    config.enable_ecofuzz = cli_overrides.enable_ecofuzz;
    config.enable_mopt_pso = cli_overrides.enable_mopt_pso;
    config.enable_muofuzz_markov = cli_overrides.enable_muofuzz_markov;

    // Hybrid period configuration for non-stationary adaptation
    config.ts_time_period_sec = static_cast<uint32_t>(cli_overrides.ts_time_period_sec);
    config.mopt_time_period_sec = static_cast<uint32_t>(cli_overrides.mopt_time_period_sec);
    config.markov_time_period_sec = static_cast<uint32_t>(cli_overrides.markov_time_period_sec);
    config.ts_min_samples = static_cast<size_t>(cli_overrides.ts_min_samples);
    config.mopt_min_samples = static_cast<size_t>(cli_overrides.mopt_min_samples);
    config.markov_min_samples = static_cast<size_t>(cli_overrides.markov_min_samples);

    if (config.use_triofuzz_unified) {
        config.combination_strategy = "triofuzz_unified";
        std::cout << "[INFO] TrioFuzz Unified Mode (with Hybrid Period Strategy):\n";
        std::cout << "  EcoFuzz schedule:        " << (config.enable_ecofuzz ? "ON" : "OFF") << "\n";
        std::cout << "  Layer 1 (TS):            " << (config.enable_ts ? "ON" : "OFF")
                  << " (exec=" << config.ts_update_period
                  << ", time=" << config.ts_time_period_sec << "s"
                  << ", min=" << config.ts_min_samples << ")\n";
        std::cout << "  Layer 2 (MOpt PSO):      " << (config.enable_mopt_pso ? "ON" : "OFF")
                  << " (exec=" << config.mopt_update_period
                  << ", time=" << config.mopt_time_period_sec << "s"
                  << ", min=" << config.mopt_min_samples << ")\n";
        std::cout << "  Layer 3 (MuoFuzz Markov):" << (config.enable_muofuzz_markov ? "ON" : "OFF")
                  << " (time=" << config.markov_time_period_sec << "s"
                  << ", min=" << config.markov_min_samples << ")\n";
    }

    // Normalize total thread count when explicit split is provided.
    // In specialized-thread mode, total threads = 1 scheduler + workers + explorers.
    if (config.worker_threads_override && config.explorer_threads_override) {
        const size_t workers = *config.worker_threads_override;
        const size_t explorers = *config.explorer_threads_override;
        const size_t normalized_total = 1 + workers + explorers;
        if (config.thread_count != normalized_total) {
            std::cout << "[WARNING] -threads=" << config.thread_count
                      << " does not match (1 + --worker-threads + --explorer-threads)="
                      << normalized_total << ". Using " << normalized_total << " threads." << std::endl;
        }
        config.thread_count = normalized_total;
    }

    return config;
}

// Global crash handling variables
thread_local std::vector<uint8_t> g_current_fuzzing_input;
static std::atomic<bool> g_crash_handler_installed{false};

// Global crash handler - uses the enhanced crash tracker
void global_crash_handler(int sig, siginfo_t* info, void* context) {
    // Avoid complex operations in signal handler
    static std::atomic<bool> crash_in_progress{false};

    // Prevent recursive crashes
    if (crash_in_progress.exchange(true)) {
        _exit(1);
    }

    try {
        // Use enhanced crash tracker to handle crash
        auto& tracker = collafuzz::crash_tracker::EnhancedCrashTracker::getInstance();
        tracker.handleCrash(sig, info, context);

        // Output simple message to stderr
        char crash_msg[256];
        std::snprintf(crash_msg, sizeof(crash_msg),
                     "[TrioFuzz] Enhanced crash handler: Signal %d, comprehensive report generated\n",
                     sig);
        write(STDERR_FILENO, crash_msg, strlen(crash_msg));

    } catch (...) {
        // If enhanced tracker fails, fall back to simple handling
        char fallback_msg[] = "[TrioFuzz] Enhanced crash handler failed, signal caught\n";
        write(STDERR_FILENO, fallback_msg, strlen(fallback_msg));
    }

    // Restore default handler and re-raise the signal
    signal(sig, SIG_DFL);
    raise(sig);
}

// Install global crash handler
void install_global_crash_handler() {
    if (g_crash_handler_installed.exchange(true)) {
        return;  // Already installed
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = global_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);

    // Install handlers for multiple signals
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
}

} // anonymous namespace

// Main entry point - framework-provided main function, not instrumented
extern "C" int main(int argc, char* argv[]) {
    // Add signal handler to capture Ctrl+C, etc.
    bool should_stop = false;

    // Global stop flag
    static std::atomic<bool>* g_stop_fuzzing = nullptr;

    // Register signal handlers
    signal(SIGINT, [](int sig) {
        std::cout << "\n[TrioFuzz] Received SIGINT, shutting down..." << std::endl;

        // Write LLVM profile data on signal
        try {
            if (__llvm_profile_write_file) {
                __llvm_profile_write_file();
                std::cout << "[TrioFuzz] Coverage profile data written on SIGINT" << std::endl;
            }
        } catch (...) {
            // Ignore errors
        }

        // Set global stop flag to let the main loop exit naturally
        if (g_stop_fuzzing) {
            *g_stop_fuzzing = true;
        }
    });
    signal(SIGTERM, [](int sig) {
        std::cout << "\n[TrioFuzz] Received SIGTERM, shutting down..." << std::endl;

        // Write LLVM profile data on signal
        try {
            if (__llvm_profile_write_file) {
                __llvm_profile_write_file();
                std::cout << "[TrioFuzz] Coverage profile data written on SIGTERM" << std::endl;
            }
        } catch (...) {
            // Ignore errors
        }

        // Set global stop flag to let the main loop exit naturally
        if (g_stop_fuzzing) {
            *g_stop_fuzzing = true;
        }
    });

    // Check for help request first
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-help" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (getEffectiveConfig().verbose) {
        std::cout << "CollaFuzz - Collaborative Fuzzing Framework v1.0" << std::endl;
    }

    // Initialize enhanced crash tracker
    std::cout << "[TrioFuzz] Initializing enhanced crash tracker..." << std::endl;
    auto& crash_tracker = collafuzz::crash_tracker::EnhancedCrashTracker::getInstance();
    crash_tracker.initialize();
    crash_tracker.setCommandLineArgs(argc, argv);
    crash_tracker.setBinaryPath(argv[0]);
    crash_tracker.setWorkingDirectory(std::filesystem::current_path().string());

    // Install crash handler
    std::cout << "[TrioFuzz] Installing enhanced crash handler..." << std::endl;
    install_global_crash_handler();

    // Call user initialization function (if available)
    auto init_func = LLVMFuzzerInitialize;
    if (init_func != nullptr) {
        std::cout << "[TrioFuzz] Calling user initialization function..." << std::endl;
        init_func(&argc, &argv);
    }

    // Create test function wrapper
    std::cout << "[TrioFuzz] Creating test function wrapper..." << std::endl;
    TestFunctionWrapper wrapper;

    // Create fuzzing configuration
    std::cout << "[TrioFuzz] Creating fuzzing configuration..." << std::endl;
    auto config = create_fuzzing_config(argc, argv);

    if (getEffectiveConfig().verbose) {
        std::cout << "[TrioFuzz] Configuration:" << std::endl;
        std::cout << "  Max input length: " << config.max_input_size << " bytes" << std::endl;
        std::cout << "  Threads: " << config.thread_count << std::endl;
        std::cout << "  Output directory: " << config.output_dir << std::endl;
        std::cout << "  Seeds directory: " << (getEffectiveConfig().seeds_dir ? getEffectiveConfig().seeds_dir : "./seeds") << std::endl;
        if (!config.dictionary_file.empty()) {
            std::cout << "  Dictionary file: " << config.dictionary_file << std::endl;
        }
        std::cout << "  Dynamic Combination: " << (config.enable_dynamic_combination ? "Enabled" : "Disabled") << std::endl;

        if (!config.enable_dynamic_combination && !config.fixed_combination.thread_algorithm_combinations.empty()) {
            std::cout << "  Fixed Thread Combinations:" << std::endl;
            for (size_t i = 0; i < config.fixed_combination.thread_algorithm_combinations.size(); ++i) {
                std::cout << "    Thread " << i << ": ";
                for (size_t j = 0; j < config.fixed_combination.thread_algorithm_combinations[i].size(); ++j) {
                    if (j > 0) std::cout << ", ";
                    std::cout << config.fixed_combination.thread_algorithm_combinations[i][j];
                }
                std::cout << std::endl;
            }

            // Show cyclic assignment when thread count exceeds number of combinations
            if (config.thread_count > config.fixed_combination.thread_algorithm_combinations.size()) {
                for (size_t i = config.fixed_combination.thread_algorithm_combinations.size(); i < config.thread_count; ++i) {
                    size_t combo_index = i % config.fixed_combination.thread_algorithm_combinations.size();
                    std::cout << "    Thread " << i << ": ";
                    for (size_t j = 0; j < config.fixed_combination.thread_algorithm_combinations[combo_index].size(); ++j) {
                        if (j > 0) std::cout << ", ";
                        std::cout << config.fixed_combination.thread_algorithm_combinations[combo_index][j];
                    }
                    std::cout << " (cycling back to thread " << combo_index << "'s combination)" << std::endl;
                }
            }
        }

        if (getEffectiveConfig().max_total_time > 0) {
            std::cout << "  Max total time: " << getEffectiveConfig().max_total_time << " seconds" << std::endl;
        }

        if (getEffectiveConfig().max_executions > 0) {
            std::cout << "  Max executions: " << getEffectiveConfig().max_executions << std::endl;
        }

        std::cout << std::endl;
    }

    try {
        std::cout << "[TrioFuzz] Initializing fuzzing engine..." << std::endl;
        // Initialize fuzzing engine
        triofuzz::FuzzingEngine engine(config);

        // Set up executor
        std::shared_ptr<triofuzz::Executor> executor;
        std::cout << "[TrioFuzz] Setting up in-process executor..." << std::endl;
        executor = std::make_shared<InProcessExecutor>(wrapper);
        engine.setCustomExecutor(executor);

        std::cout << "[TrioFuzz] Resetting real coverage..." << std::endl;
        // Initialize coverage collection
        resetRealCoverage();

        std::cout << "[TrioFuzz] Clearing previous coverage state..." << std::endl;
        // Clear coverage state from previous runs to ensure fresh statistics
        clearRealCoverageState();

        if (getEffectiveConfig().verbose) {
            std::cout << "[TrioFuzz] Starting collaborative fuzzing..." << std::endl;
        }

        std::cout << "[TrioFuzz] Initializing engine..." << std::endl;
        // Initialize engine
        engine.initialize();

        // Set execution limits from CLI overrides
        if (cli_overrides.max_total_time > 0) {
            engine.setMaxTotalTime(cli_overrides.max_total_time);
            std::cout << "[TrioFuzz] Set max total time: " << cli_overrides.max_total_time << " seconds" << std::endl;
        }
        if (cli_overrides.max_executions > 0) {
            engine.setMaxExecutions(cli_overrides.max_executions);
            std::cout << "[TrioFuzz] Set max executions: " << cli_overrides.max_executions << std::endl;
        }

        // Validate fixed combinations and strict mode after engine initialization
        if (!cli_overrides.enable_dynamic_combination && !cli_overrides.thread_algorithm_combinations.empty()) {
            std::cout << "[TrioFuzz] Validating fixed algorithm combinations..." << std::endl;

            // If strict algorithm isolation mode is active, perform extra validation
            if (config.strict_algorithm_isolation) {
                std::cout << "[TrioFuzz] Strict algorithm isolation mode is active - performing enhanced validation..." << std::endl;

                // Validate strict algorithm isolation
                if (engine.validateStrictAlgorithmIsolation()) {
                    std::cout << "[INFO] ✓ Strict algorithm isolation validation passed" << std::endl;
                } else {
                    std::cout << "[WARNING] ✗ Strict algorithm isolation validation failed - some unauthorized algorithms may be active" << std::endl;

                    auto unauthorized = engine.getUnauthorizedAlgorithms();
                    if (!unauthorized.empty()) {
                        std::cout << "[WARNING] Unauthorized algorithms detected: ";
                        for (size_t i = 0; i < unauthorized.size(); ++i) {
                            if (i > 0) std::cout << ", ";
                            std::cout << unauthorized[i];
                        }
                        std::cout << std::endl;
                    }
                }

                // Log current algorithm usage
                engine.logAlgorithmUsage();
            }
            std::vector<std::string> invalid_algorithms;
            std::vector<std::string> valid_algorithms;

            // Use centralized algorithm configuration
            auto known_algorithms_vec = triofuzz::AlgorithmConfig::getAllEnabled();
            std::set<std::string> known_algorithms(known_algorithms_vec.begin(), known_algorithms_vec.end());

            for (const auto& thread_combo : cli_overrides.thread_algorithm_combinations) {
                for (const auto& algorithm : thread_combo) {
                    if (known_algorithms.find(algorithm) != known_algorithms.end()) {
                        valid_algorithms.push_back(algorithm);
                    } else {
                        invalid_algorithms.push_back(algorithm);
                    }
                }
            }

            if (!invalid_algorithms.empty()) {
                std::cout << "[ERROR] Found " << invalid_algorithms.size() << " invalid algorithm(s): ";
                for (size_t i = 0; i < invalid_algorithms.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << "'" << invalid_algorithms[i] << "'";
                }
                std::cout << std::endl;

                // Show available algorithms (using centralized config)
                auto common_algorithms = triofuzz::AlgorithmConfig::ENABLED_MUTATIONS;
                std::cout << "[INFO] Available algorithms: ";
                for (size_t i = 0; i < common_algorithms.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << common_algorithms[i];
                }
                std::cout << std::endl;
                std::cout << "[INFO] For full list, see registerDefaultAlgorithms() in fuzzing_engine.cpp" << std::endl;

                std::cout << "[ERROR] Please check your algorithm names and try again." << std::endl;
                exit(1);
            }

            std::cout << "[INFO] All fixed algorithm combinations validated successfully!" << std::endl;
            std::cout << "[INFO] Valid algorithms found: ";
            for (size_t i = 0; i < valid_algorithms.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << valid_algorithms[i];
            }
            std::cout << std::endl;
        }

        std::cout << "[TrioFuzz] Adding initial seeds..." << std::endl;

        // Load seed files from the configured seeds directory
        std::string seeds_dir = getEffectiveConfig().seeds_dir ? getEffectiveConfig().seeds_dir : "./seeds";
        std::cout << "[TrioFuzz] Loading seeds from " << seeds_dir << " directory..." << std::endl;
        engine.loadInitialSeeds(seeds_dir);

        // Add diverse base seeds of different sizes
        std::vector<std::vector<uint8_t>> initial_seeds = {
        };

        for (const auto& seed : initial_seeds) {
            engine.addSeed(seed);
        }

        std::cout << "[TrioFuzz] Setting up callbacks..." << std::endl;

        // Set up callbacks
        engine.setOnCrash([](const triofuzz::ExecutionResult& result, const triofuzz::AlgorithmCombination& combo) {
            std::cout << "[!] CRASH found by " << combo.toString()
                      << " (input size: " << result.input_data.size() << ")" << std::endl;

            // Save crash input to file
            try {
                // Ensure crashes directory exists
                std::filesystem::create_directories("output/crashes");

                // Generate unique crash filename
                auto now = std::chrono::system_clock::now();
                auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count();

                std::string crash_filename = "output/crashes/crash_" +
                                           std::to_string(timestamp) + "_" +
                                           std::to_string(result.input_data.size()) + "bytes.bin";

                // Save crash input
                std::ofstream crash_file(crash_filename, std::ios::binary);
                if (crash_file.is_open()) {
                    crash_file.write(reinterpret_cast<const char*>(result.input_data.data()),
                                   result.input_data.size());
                    crash_file.close();
                    std::cout << "[!] Crash input saved to: " << crash_filename << std::endl;
                } else {
                    std::cerr << "[ERROR] Failed to create crash file: " << crash_filename << std::endl;
                }

                // Save crash info report
                std::string report_filename = "output/crashes/crash_" +
                                           std::to_string(timestamp) + "_report.txt";
                std::ofstream report_file(report_filename);
                if (report_file.is_open()) {
                    report_file << "=== Crash Report ===" << std::endl;
                    report_file << "Timestamp: " << timestamp << std::endl;
                    report_file << "Algorithm Combination: " << combo.toString() << std::endl;
                    report_file << "Input Size: " << result.input_data.size() << " bytes" << std::endl;
                    report_file << "Exit Code: " << (result.exit_code ? std::to_string(*result.exit_code) : "N/A") << std::endl;
                    report_file << "Status: ";
                    switch (result.status) {
                        case triofuzz::ExecutionResult::Status::Crash:
                            report_file << "Crash";
                            break;
                        case triofuzz::ExecutionResult::Status::Error:
                            report_file << "Error";
                            break;
                        default:
                            report_file << "Unknown";
                            break;
                    }
                    report_file << std::endl;

                    if (!result.crash_info.empty()) {
                        report_file << "Crash Information:" << std::endl;
                        for (const auto& info : result.crash_info) {
                            report_file << "  " << info << std::endl;
                        }
                    }

                    if (!result.error_message.empty()) {
                        report_file << "Error Message: " << result.error_message << std::endl;
                    }

                    report_file << "Performance Data:" << std::endl;
                    report_file << "  Execution Time: " << result.performance.execution_time_ms << " ms" << std::endl;
                    report_file << "  Memory Usage: " << result.performance.memory_usage_bytes << " bytes" << std::endl;

                    report_file.close();
                    std::cout << "[!] Crash report saved to: " << report_filename << std::endl;
                }

            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to save crash: " << e.what() << std::endl;
            }
        });

        engine.setOnStatsUpdate([](const triofuzz::FuzzingStats& stats) {
            if (getEffectiveConfig().verbose && stats.total_executions % 1000 == 0) {
                std::cout << "[Stats] Execs: " << stats.total_executions.load()
                          << ", Coverage: " << std::fixed << std::setprecision(2) << stats.coverage_percentage.load() << "%"
                          << ", Speed: " << stats.executions_per_second.load() << " exec/s"
                          << std::endl;
            }
        });

        std::cout << "[TrioFuzz] Starting fuzzing engine..." << std::endl;
        // Start fuzzing
        engine.start();

        // Wait for completion (Ctrl+C or time limit reached)
        if (getEffectiveConfig().verbose) {
            std::cout << "[TrioFuzz] Fuzzing started. Press Ctrl+C to stop." << std::endl;
        }

        // Setup cleanup handler for library mode
        static std::atomic<bool> library_cleanup_done{false};

        auto library_cleanup = []() {
            if (!library_cleanup_done.exchange(true)) {
                std::cout << "[TrioFuzz] Performing library cleanup..." << std::endl;

                // Cleanup thread-local storage
                try {
                    triofuzz::utils::RandomUtils::cleanupAllThreads();
                } catch (const std::exception& e) {
                    std::cerr << "[TrioFuzz] Cleanup warning: " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "[TrioFuzz] Unknown cleanup error" << std::endl;
                }

                std::cout << "[TrioFuzz] Library cleanup completed" << std::endl;
            }
        };

        // Register cleanup for normal exit
        std::atexit([]() {
            if (!library_cleanup_done.load()) {
                triofuzz::utils::RandomUtils::cleanupAllThreads();
            }
        });

        std::cout << "[TrioFuzz] Entering main fuzzing loop..." << std::endl;

        // Main loop with proper loop control

        // Set global stop flag pointer for signal handling
        std::atomic<bool> stop_flag(false);
        g_stop_fuzzing = &stop_flag;

        auto start_time = std::chrono::system_clock::now();

        size_t loop_count = 0;
        size_t last_total_executions = 0;

        while (!should_stop && !stop_flag) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            loop_count++;

            // Get current statistics
            const auto& stats = engine.getStats();

            // Check time limit
            if (cli_overrides.max_total_time > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now() - start_time).count();
                if (elapsed >= cli_overrides.max_total_time) {
                    std::cout << "[TrioFuzz] Time limit reached" << std::endl;
                    should_stop = true;
                    break;
                }
            }

            // Check execution count limit
            if (cli_overrides.max_executions > 0) {
                size_t current_executions = stats.total_executions.load();
                if (current_executions >= cli_overrides.max_executions) {
                    std::cout << "[TrioFuzz] Execution limit reached (" << current_executions << " executions)" << std::endl;
                    should_stop = true;
                    break;
                }
            }

            // Periodically print statistics (every 300 seconds)
            if (loop_count % 300 == 0) {
                size_t current_executions = stats.total_executions.load();
                double exec_per_sec = 0.0;
                if (loop_count >= 30) {
                    exec_per_sec = (current_executions - last_total_executions) / 300.0;
                }
                last_total_executions = current_executions;

                std::cout << "[triofuzz] Stats - Executions: " << current_executions
                          << ", Exec/sec: " << std::fixed << std::setprecision(1) << exec_per_sec
                          << ", Coverage: " << std::fixed << std::setprecision(1)
                          << stats.coverage_percentage.load() << "%" << std::endl;
            }
        }

        std::cout << "[TrioFuzz] Stopping engine..." << std::endl;
        engine.stop();

        // Perform library cleanup
        library_cleanup();

        std::cout << "[TrioFuzz] Main fuzzing loop completed" << std::endl;

        // Shut down enhanced crash tracker
        std::cout << "[TrioFuzz] Shutting down enhanced crash tracker..." << std::endl;
        crash_tracker.shutdown();

    } catch (const std::exception& e) {
        std::cerr << "[TrioFuzz] EXCEPTION: " << e.what() << std::endl;
        std::cerr << "[TrioFuzz] Stack trace would be helpful here" << std::endl;

        // Safely shut down crash tracker even on exception
        try {
            auto& crash_tracker = collafuzz::crash_tracker::EnhancedCrashTracker::getInstance();
            crash_tracker.shutdown();
        } catch (...) {
            // Ignore shutdown errors
        }

        return 1;
    } catch (...) {
        std::cerr << "[TrioFuzz] UNKNOWN EXCEPTION occurred!" << std::endl;

        // Safely shut down crash tracker even on exception
        try {
            auto& crash_tracker = collafuzz::crash_tracker::EnhancedCrashTracker::getInstance();
            crash_tracker.shutdown();
        } catch (...) {
            // Ignore shutdown errors
        }

        return 1;
    }

    std::cout << "[TrioFuzz] Main function exiting normally." << std::endl;
    return 0;
}
