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
#include <unordered_map>
#include <cstdio>
#include <sys/mman.h>
#include <sys/wait.h>
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

// ============================================================================
// Fork-based crash arbitration (supervisor + single-thread replay oracle)
// ----------------------------------------------------------------------------
// TrioFuzz runs LLVMFuzzerTestOneInput in-process across several worker/explorer
// threads with no lock. A thread-UNSAFE target (mutable global/static state) can
// then be data-raced by that concurrency, producing SIGSEGV/SIGABRT that do NOT
// occur under a single-threaded execution -- i.e. false-positive crashes -- and,
// worse, the crash takes down the whole in-process engine, ending the campaign.
//
// To keep the fast in-process multi-threaded engine while eliminating those
// false positives, main() runs as a single-threaded SUPERVISOR that forks the
// engine into a WORKER child. On a worker crash the supervisor re-runs the
// captured input single-threaded in a fresh REPLAY child forked from the
// pristine supervisor; only crashes that reproduce single-threaded are treated
// as real (matching FuzzBench's own single-threaded crash reproduction). The
// supervisor then restarts the engine within the remaining budget, so a
// thread-unsafe target no longer terminates the campaign.
//
// Opt out (exact legacy single-process behavior): TRIOFUZZ_NO_ARBITER=1 or
// pass --no-arbiter.
// ============================================================================

// Signals we treat as a genuine crash when reproduced single-threaded.
inline bool is_crash_signal(int sig) {
    switch (sig) {
        case SIGSEGV: case SIGABRT: case SIGFPE:
        case SIGILL:  case SIGBUS:  case SIGTRAP:
            return true;
        default:
            return false;
    }
}

inline uint32_t getenv_u32_or(const char* name, uint32_t defval) {
    const char* v = std::getenv(name);
    if (!v || !*v) return defval;
    char* end = nullptr;
    unsigned long r = std::strtoul(v, &end, 10);
    if (end == v) return defval;
    return static_cast<uint32_t>(r);
}

inline uint64_t fnv1a64(const uint8_t* p, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// CLOCK_MONOTONIC in nanoseconds. Shared by the worker heartbeat and the
// supervisor's staleness check; both sides read the same system-wide clock,
// so the value survives fork() unchanged in meaning.
inline uint64_t monotonic_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// -- Faulting-thread input snapshot (async-signal-safe capture) --------------
// Set by InProcessExecutor::execute() immediately before each target call, as
// raw POD (NOT std::vector internals) so the crash handler can read the exact
// input of the faulting thread even if the heap/vector control block is
// corrupted. initial-exec TLS model keeps the access a direct offset load with
// no __tls_get_addr/malloc (safe: the engine is statically linked into the exe).
static thread_local const uint8_t* g_tls_input_data
    __attribute__((tls_model("initial-exec"))) = nullptr;
static thread_local size_t g_tls_input_size
    __attribute__((tls_model("initial-exec"))) = 0;
// True only while this thread is inside a target call. Kept separate from the
// length so that "armed with a zero-length input" (a legitimate crash
// candidate) and "not inside the target at all" (an engine-side fault) do not
// collapse into the same len==0 encoding.
static thread_local bool g_tls_input_armed
    __attribute__((tls_model("initial-exec"))) = false;

// -- Adaptive serialization for thread-unsafe targets ------------------------
// When the supervisor detects repeated fast crashes it sets this before forking
// the next worker (inherited via copy-on-write), making InProcessExecutor
// serialize the target call so no two executions run concurrently -- trading
// throughput for stability instead of crash-looping.
static std::atomic<bool> g_serialize_target{false};
static std::mutex g_target_exec_mutex;

// -- Shared crash slot (worker -> supervisor candidate handoff) --------------
static constexpr uint32_t kCrashMagic = 0x54524643u;  // 'TRFC'
struct CrashSlot {
    uint32_t magic;         // 0 = empty, kCrashMagic = published
    uint32_t signal;        // terminating signal captured by the worker
    uint64_t len;           // number of valid bytes in data[]
    // Worker liveness. Every engine thread stores monotonic_ns() here right
    // before it calls the target; the supervisor kills a worker whose value
    // stops advancing. This bounds the supervisor's wait -- the in-process
    // executor has no per-execution timeout -- but it is PROCESS-wide
    // liveness, not per-thread: it fires when NO thread has entered the target
    // for the deadline (all threads wedged, a hang before the first execution,
    // or the serialized path where one stuck thread blocks the rest). A single
    // thread stuck inside the target while others keep executing is not
    // detected; that costs one thread of throughput for the worker's lifetime,
    // not the campaign.
    uint64_t heartbeat_ns;
    // Worker phase: 0 = starting (engine init, corpus reload, seed calibration),
    // 1 = fuzzing (stored by the worker right after engine.start()). Selects
    // which liveness deadline applies and anchors the escalation "fast crash"
    // clock, so that neither startup cost nor a slow calibration pass is
    // mistaken for a crash-looping fuzzing loop.
    uint32_t phase;
    uint32_t armed;         // 1 = the faulting thread was inside a target call
    uint64_t fuzz_start_ns;
    uint8_t  data[1];       // capacity = g_crash_slot_cap (over-allocated via mmap)
};
static CrashSlot* g_crash_slot = nullptr;
static size_t g_crash_slot_cap = 0;

// Supervisor termination forwarding.
static std::atomic<pid_t> g_active_child{-1};
static std::atomic<bool>  g_supervisor_terminating{false};

// One-time user init (LLVMFuzzerInitialize). In arbiter mode this runs ONCE in
// the pristine supervisor; worker and replay children inherit the initialized
// state via COW (matching libFuzzer's init-once model). Idempotent so the legacy
// path (no supervisor) still initializes.
static std::atomic<bool> g_user_init_done{false};
static void ensure_user_initialized(int* argc, char*** argv) {
    bool expected = false;
    if (g_user_init_done.compare_exchange_strong(expected, true)) {
        if (LLVMFuzzerTestOneInput && LLVMFuzzerInitialize) {
            LLVMFuzzerInitialize(argc, argv);
        }
    }
}

// Async-signal-safe worker crash handler. Runs on the faulting thread: copies
// that thread's current input into the shared slot, publishes it, then dies via
// the default disposition so the supervisor's waitpid() sees WIFSIGNALED(signal).
static void worker_capture_handler(int sig, siginfo_t* /*info*/, void* /*ctx*/) {
    static std::atomic<int> one_shot{0};
    if (one_shot.exchange(1, std::memory_order_acq_rel) != 0) {
        // A second thread faulted concurrently: park so it cannot steal the exit
        // status from the winner's re-raise. The winner's death (SIG_DFL) takes
        // the whole process -- and this parked thread -- down.
        for (;;) pause();
    }
    if (g_crash_slot) {
        const bool armed = g_tls_input_armed;
        const uint8_t* p = g_tls_input_data;
        size_t n = g_tls_input_size;
        if (armed && p && n) {
            size_t m = (n < g_crash_slot_cap) ? n : g_crash_slot_cap;
            for (size_t i = 0; i < m; ++i) g_crash_slot->data[i] = p[i];
            g_crash_slot->len = m;
        } else {
            g_crash_slot->len = 0;  // armed && empty input, or not armed at all
        }
        g_crash_slot->armed = armed ? 1u : 0u;
        g_crash_slot->signal = static_cast<uint32_t>(sig);
        __atomic_store_n(&g_crash_slot->magic, kCrashMagic, __ATOMIC_RELEASE);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

// Install a per-thread alternate signal stack so a stack-overflow SIGSEGV can
// still be delivered to worker_capture_handler on THIS thread. The alt stack is
// a per-thread attribute (not inherited across thread creation), so every engine
// pool thread that runs the target must install its own before its first target
// call (see InProcessExecutor::execute). Idempotent per thread.
static void install_thread_altstack() {
    static thread_local char alt_stack[65536];  // one buffer per thread, lives for its lifetime
    stack_t ss;
    ss.ss_sp = alt_stack;
    ss.ss_size = sizeof(alt_stack);
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);
}

static void install_worker_capture_handler() {
    install_thread_altstack();  // covers the worker's main thread

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = worker_capture_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    // Block all crash signals during the handler so that a SECONDARY synchronous
    // fault while copying the (possibly corrupted/dangling) input pointer is
    // force-delivered as SIG_DFL and kills the process deterministically, rather
    // than re-entering the handler and parking the winner thread in pause()
    // forever (which would hang the worker and the supervisor's waitpid).
    sigemptyset(&sa.sa_mask);
    const int sigs[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP};
    for (int s : sigs) sigaddset(&sa.sa_mask, s);
    for (int s : sigs) sigaction(s, &sa, nullptr);
}

// Single-threaded replay oracle: run the candidate once in a fresh child forked
// from the pristine supervisor. Returns true iff it reproduces a crash signal.
static bool replay_reproduces(const std::vector<uint8_t>& input, int timeout_ms) {
    pid_t pid = fork();
    if (pid < 0) return false;  // cannot verify -> conservative: not reproduced
    if (pid == 0) {
        // Fresh, single-threaded, post-LLVMFuzzerInitialize (inherited via COW).
        // Reset crash handlers to default so the exit status reflects the target.
        const int sigs[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP,
                            SIGINT, SIGTERM};
        for (int s : sigs) signal(s, SIG_DFL);
        // Wall-clock backstop. Deliberately NO RLIMIT_AS: it would break ASan
        // builds and turn a benign OOM into a false "crash".
        unsigned alarm_s = static_cast<unsigned>((timeout_ms + 999) / 1000) + 2u;
        alarm(alarm_s);
        if (LLVMFuzzerTestOneInput) {
            try {
                LLVMFuzzerTestOneInput(input.data(), input.size());
            } catch (...) {
                _exit(0);  // a caught C++ exception is what the engine swallows too
            }
        }
        _exit(0);
    }
    int status = 0;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(std::max(1000, timeout_ms * 4));
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0) { if (errno == EINTR) continue; return false; }
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return false;  // hang -> not a reproduced crash signal
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return WIFSIGNALED(status) && is_crash_signal(WTERMSIG(status));
}

// Persist a single-thread-confirmed crash where FuzzBench will archive+re-run it
// (output_dir/crashes, inside the monitored /out/corpus tree but NOT the dir the
// engine reloads) plus a non-.bin copy in output_dir/corpus (the .bin-only corpus
// reload skips it, so no re-seed loop) to maximize the chance the measurer counts
// the bug.
static void save_confirmed_crash(const std::vector<uint8_t>& input, int sig,
                                 const std::string& output_dir) {
    uint64_t h = fnv1a64(input.data(), input.size());
    char hexh[17];
    std::snprintf(hexh, sizeof(hexh), "%016llx", static_cast<unsigned long long>(h));

    const std::string crashes_dir = output_dir + "/crashes";
    const std::string corpus_dir  = output_dir + "/corpus";
    try { std::filesystem::create_directories(crashes_dir); } catch (...) {}
    try {
        const std::string bin = crashes_dir + "/crash-" + hexh + "-sig" +
                                std::to_string(sig) + ".bin";
        std::ofstream f(bin, std::ios::binary);
        if (f) f.write(reinterpret_cast<const char*>(input.data()), input.size());
    } catch (...) {}
    try {
        std::filesystem::create_directories(corpus_dir);
        const std::string cc = corpus_dir + "/crash-" + hexh;  // NON-.bin on purpose
        if (!std::filesystem::exists(cc)) {
            std::ofstream cf(cc, std::ios::binary);
            if (cf) cf.write(reinterpret_cast<const char*>(input.data()), input.size());
        }
    } catch (...) {}
}

// Manual single-input replay/repro mode: `<binary> --replay-verify=FILE`.
// Runs init + exactly one LLVMFuzzerTestOneInput, single-threaded, then exits.
// A crash kills this process with the target's signal (useful for humans/CI).
static int run_replay_verify_mode(const std::string& file, int argc, char* argv[]) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "[replay-verify] cannot open %s\n", file.c_str());
        return 2;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    ensure_user_initialized(&argc, &argv);
    if (LLVMFuzzerTestOneInput) {
        try { LLVMFuzzerTestOneInput(data.data(), data.size()); }
        catch (...) { return 0; }
    }
    return 0;
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

        // Ensure THIS engine pool thread has an alternate signal stack, so a
        // stack-overflow SIGSEGV in the target can still enter the capture
        // handler (the alt stack is per-thread and not inherited from the worker
        // main thread). One-shot per thread; harmless outside arbiter mode.
        static thread_local bool altstack_installed = false;
        if (!altstack_installed) { install_thread_altstack(); altstack_installed = true; }

        // Async-signal-safe faulting-thread snapshot for the arbiter's crash
        // handler (raw ptr/len; valid for the duration of this call).
        g_tls_input_data = input.data();
        g_tls_input_size = input.size();
        g_tls_input_armed = true;
        // Disarm on every exit path (normal return, exception). A fault on this
        // thread outside a target call must then publish armed==0 rather than
        // copy from a pointer into a buffer that may since have been freed.
        // Plain RAII is safe here: nothing longjmps in this design, so the
        // destructor always runs.
        struct TlsInputDisarm {
            ~TlsInputDisarm() {
                g_tls_input_armed = false;
                g_tls_input_data = nullptr;
                g_tls_input_size = 0;
            }
        } tls_input_disarm;

        // Liveness heartbeat for the supervisor (arbiter mode only; the slot is
        // null in legacy mode). One relaxed store of the monotonic clock per
        // execution -- no RMW, so no cache-line contention between threads.
        if (g_crash_slot) {
            __atomic_store_n(&g_crash_slot->heartbeat_ns, monotonic_ns(), __ATOMIC_RELAXED);
        }

        try {
            // Direct execution, no thread pool overhead. Under adaptive
            // serialization (thread-unsafe target detected by the supervisor),
            // only one execution enters the target at a time.
            int ret;
            if (g_serialize_target.load(std::memory_order_relaxed)) {
                std::lock_guard<std::mutex> exec_lock(g_target_exec_mutex);
                ret = wrapper_.execute(input);
            } else {
                ret = wrapper_.execute(input);
            }

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

// Runs the full multi-threaded engine lifecycle. In arbiter mode this executes
// in a forked WORKER child of the supervisor; in legacy mode it is called
// directly by main(). Returns 0 on normal completion (or dies WIFSIGNALED on a
// target crash, which the supervisor reaps).
static int run_fuzzing_engine_child(int argc, char* argv[], bool arbiter_mode) {
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

    // Install crash handler. In arbiter mode use the minimal async-signal-safe
    // capture handler (dumps the faulting thread's input, then re-raises so the
    // supervisor can verify it single-threaded). In legacy mode keep the original
    // heavy handler for exact backward-compatible behavior.
    if (arbiter_mode) {
        std::cout << "[TrioFuzz] Installing arbiter crash-capture handler..." << std::endl;
        install_worker_capture_handler();
    } else {
        std::cout << "[TrioFuzz] Installing enhanced crash handler..." << std::endl;
        install_global_crash_handler();
    }

    // Call user initialization once (idempotent). In arbiter mode LLVMFuzzerInitialize
    // already ran in the supervisor and is inherited via COW, so this is a no-op.
    ensure_user_initialized(&argc, &argv);

    // Create test function wrapper
    std::cout << "[TrioFuzz] Creating test function wrapper..." << std::endl;
    TestFunctionWrapper wrapper;

    // Create fuzzing configuration
    std::cout << "[TrioFuzz] Creating fuzzing configuration..." << std::endl;
    auto config = create_fuzzing_config(argc, argv);

    // Arbiter: honor the supervisor's remaining wall-clock budget across restarts
    // (create_fuzzing_config just re-parsed argv and reset cli_overrides, so apply
    // the supervisor-provided remaining time here).
    if (arbiter_mode) {
        const char* rt = std::getenv("TRIOFUZZ_REMAINING_TIME");
        if (rt && *rt) {
            int v = std::atoi(rt);
            if (v > 0) cli_overrides.max_total_time = v;
        }
    }

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
        engine.setOnCrash([output_dir = config.output_dir](const triofuzz::ExecutionResult& result, const triofuzz::AlgorithmCombination& combo) {
            std::cout << "[!] CRASH found by " << combo.toString()
                      << " (input size: " << result.input_data.size() << ")" << std::endl;

            // Soft crash (non-signal, e.g. LLVMFuzzerTestOneInput returned nonzero).
            // Write under the -output corpus tree so it is archived by FuzzBench,
            // not the old hardcoded relative "output/crashes" (which is outside it).
            const std::string crashes_dir = output_dir + "/crashes";

            // Save crash input to file
            try {
                // Ensure crashes directory exists
                std::filesystem::create_directories(crashes_dir);

                // Generate unique crash filename
                auto now = std::chrono::system_clock::now();
                auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count();

                std::string crash_filename = crashes_dir + "/crash_" +
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
                std::string report_filename = crashes_dir + "/crash_" +
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
        // Tell the supervisor the engine is now fuzzing: the startup grace ends
        // and the escalation "fast crash" clock starts here, not at fork.
        if (g_crash_slot) {
            __atomic_store_n(&g_crash_slot->fuzz_start_ns, monotonic_ns(), __ATOMIC_RELAXED);
            __atomic_store_n(&g_crash_slot->phase, 1u, __ATOMIC_RELEASE);
        }

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

namespace {

// Supervisor SIGINT/SIGTERM forwarder: relay to the active child and mark the
// campaign for shutdown.
static void supervisor_term_handler(int sig) {
    g_supervisor_terminating.store(true);
    pid_t c = g_active_child.load();
    if (c > 0) kill(c, sig);
}

// Single-threaded supervisor: forks the multi-threaded engine into a WORKER
// child, and on a crash verifies the captured input single-threaded before
// deciding whether it is a real bug. Restarts the worker within the remaining
// budget so a thread-unsafe target no longer ends the campaign.
static int run_supervisor(int argc, char* argv[]) {
    // Parse config once in the pristine supervisor (no engine is constructed).
    triofuzz::FuzzingConfig config = create_fuzzing_config(argc, argv);
    const std::string output_dir = config.output_dir.empty()
                                        ? std::string("./output") : config.output_dir;

    // Initialize the target ONCE; worker and replay children inherit it via COW.
    ensure_user_initialized(&argc, &argv);

    // Allocate the shared crash slot (visible across fork via MAP_SHARED).
    // Floor at 1MB so a larger-than-max_len input is not truncated on capture
    // (a truncated candidate would fail to reproduce and be misjudged a false
    // positive); cap at 16MB to bound the shared mapping.
    g_crash_slot_cap = std::min<size_t>(
        std::max<size_t>(config.max_input_size, 1u * 1024u * 1024u),
        16u * 1024u * 1024u);
    const size_t slot_bytes = sizeof(CrashSlot) + g_crash_slot_cap;
    void* m = mmap(nullptr, slot_bytes, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        std::fprintf(stderr,
                     "[arbiter] mmap failed (%s); running without arbitration\n",
                     std::strerror(errno));
        return run_fuzzing_engine_child(argc, argv, /*arbiter_mode=*/false);
    }
    g_crash_slot = static_cast<CrashSlot*>(m);

    signal(SIGINT, supervisor_term_handler);
    signal(SIGTERM, supervisor_term_handler);
    // Restore default SIGCHLD in case the target's LLVMFuzzerInitialize set it to
    // SIG_IGN (which would make waitpid() fail with ECHILD here and in the replay
    // oracle, causing a reaped worker to be misread as a clean exit).
    signal(SIGCHLD, SIG_DFL);

    const int timeout_ms = static_cast<int>(std::max<long long>(1, config.timeout.count()));
    const int budget_s = cli_overrides.max_total_time;  // <= 0 => unbounded
    const auto t0 = std::chrono::steady_clock::now();
    // All knobs stay unsigned (see escalate_after below for why).
    const uint32_t max_restarts   = getenv_u32_or("TRIOFUZZ_ARBITER_MAX_RESTARTS", 10000);
    const uint32_t fast_crash_sec = getenv_u32_or("TRIOFUZZ_ARBITER_FAST_CRASH_SEC", 10);
    // Kept unsigned on purpose: a static_cast<int> of a large "disable it"
    // value wraps negative and makes the comparison below fire on the first
    // worker death. 0 means never escalate.
    const uint32_t escalate_after = getenv_u32_or("TRIOFUZZ_ARBITER_ESCALATE_AFTER", 3);
    // Worker liveness deadlines (seconds; 0 disables the check). Until the
    // worker reports phase==1 (set right after engine.start()) it is still
    // initializing, reloading the on-disk corpus and calibrating every initial
    // seed -- work that can take minutes on large seed sets -- so that phase
    // gets its own, longer allowance.
    const uint32_t worker_hang_sec    = getenv_u32_or("TRIOFUZZ_ARBITER_WORKER_HANG_SEC", 300);
    const uint32_t startup_grace_sec  = getenv_u32_or("TRIOFUZZ_ARBITER_STARTUP_GRACE_SEC", 1800);
    // Backoff after this many consecutive fast deaths of ANY kind (OOM loop,
    // engine fault, ...). Decoupled from escalation: it guards CPU spin, not
    // thread-safety, and must keep working when escalation is disabled.
    constexpr int kBackoffAfterFastDeaths = 3;

    struct Verdict { bool reproduced; uint32_t hits; };
    std::unordered_map<uint64_t, Verdict> verdicts;  // input hash -> verdict + hits
    uint32_t restarts = 0;
    int consecutive_fast = 0;
    // Consecutive worker deaths that were BOTH fast AND judged a concurrency
    // artifact (candidate captured, did not reproduce single-threaded). Only
    // that signature indicates a thread-unsafe target; a fast death from a
    // genuine reproducible bug, an OOM SIGKILL or an engine fault must not
    // trip serialization, since serializing helps with none of those.
    uint32_t consecutive_fast_artifacts = 0;
    size_t confirmed = 0, false_pos = 0;

    std::fprintf(stderr,
                 "[arbiter] supervisor active (pid=%d); crash arbitration ON "
                 "(set TRIOFUZZ_NO_ARBITER=1 to disable).\n", static_cast<int>(getpid()));

    while (!g_supervisor_terminating.load()) {
        if (budget_s > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - t0).count();
            int remaining_s = budget_s - static_cast<int>(elapsed);
            if (remaining_s <= 1) break;
            setenv("TRIOFUZZ_REMAINING_TIME", std::to_string(remaining_s).c_str(), 1);
        }

        // Reset the slot before forking the next worker.
        __atomic_store_n(&g_crash_slot->magic, 0u, __ATOMIC_RELEASE);
        g_crash_slot->len = 0;
        g_crash_slot->armed = 0;
        // Prime the heartbeat with the fork time so a worker that wedges before
        // its first target call is still measured (against startup_grace_sec).
        const uint64_t hb_at_fork = monotonic_ns();
        __atomic_store_n(&g_crash_slot->heartbeat_ns, hb_at_fork, __ATOMIC_RELAXED);
        __atomic_store_n(&g_crash_slot->fuzz_start_ns, 0ull, __ATOMIC_RELAXED);
        __atomic_store_n(&g_crash_slot->phase, 0u, __ATOMIC_RELEASE);

        auto worker_start = std::chrono::steady_clock::now();
        pid_t pid = fork();
        if (pid < 0) {
            std::fprintf(stderr, "[arbiter] fork failed (%s); retrying\n", std::strerror(errno));
            std::this_thread::sleep_for(std::chrono::seconds(1));
            // Same cap policy as the main restart path: only hard-stop bounded
            // runs; on the unbounded (FuzzBench) path a transient fork failure
            // must NOT end the campaign (the counter can accumulate over hours).
            ++restarts;
            if (budget_s > 0 && restarts > max_restarts) break;
            continue;
        }
        if (pid == 0) {
            // WORKER: run the full multi-threaded engine.
            _exit(run_fuzzing_engine_child(argc, argv, /*arbiter_mode=*/true));
        }

        g_active_child.store(pid);
        int status = 0;
        bool reaped = false, hung = false, budget_hit = false;
        // Poll rather than block: the worker cannot bound its own execution
        // time, so the supervisor enforces two deadlines while it waits --
        // heartbeat staleness (worker wedged) and the campaign budget.
        for (;;) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) { reaped = true; break; }
            if (r < 0) { if (errno == EINTR) continue; break; }  // ECHILD/other

            // Still running. Decide whether it has to be stopped.
            const uint64_t now_ns = monotonic_ns();
            const char* why = nullptr;
            const uint64_t hb = __atomic_load_n(&g_crash_slot->heartbeat_ns, __ATOMIC_RELAXED);
            const bool started = (__atomic_load_n(&g_crash_slot->phase, __ATOMIC_ACQUIRE) == 1u);
            const uint32_t limit_s = started ? worker_hang_sec : startup_grace_sec;
            if (limit_s > 0 && now_ns > hb && (now_ns - hb) >= limit_s * 1000000000ull) {
                hung = true;
                why = started ? "no target execution for" : "still starting up after";
                std::fprintf(stderr, "[arbiter] worker pid=%d: %s %us; killing it.\n",
                             static_cast<int>(pid), why, limit_s);
            } else if (budget_s > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - t0).count();
                if (elapsed >= budget_s) {
                    budget_hit = true;
                    why = "campaign budget exhausted";
                    std::fprintf(stderr, "[arbiter] %s; stopping worker pid=%d.\n",
                                 why, static_cast<int>(pid));
                }
            }
            if (!why && g_supervisor_terminating.load()) why = "termination requested";

            if (why) {
                // SIGTERM first so a healthy engine can flush; a wedged one will
                // not react, hence the bounded wait and the SIGKILL.
                kill(pid, SIGTERM);
                for (int i = 0; i < 50 && !reaped; ++i) {  // up to ~5s
                    r = waitpid(pid, &status, WNOHANG);
                    if (r == pid) { reaped = true; break; }
                    if (r < 0 && errno != EINTR) break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (!reaped) {
                    kill(pid, SIGKILL);
                    for (;;) {
                        r = waitpid(pid, &status, 0);
                        if (r == pid) { reaped = true; break; }
                        if (r < 0 && errno == EINTR) continue;
                        break;
                    }
                }
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        g_active_child.store(-1);
        if (budget_hit) break;  // campaign over; do not restart

        // The ONLY conditions that stop the campaign are: the orchestrator asked
        // us to stop (g_supervisor_terminating, set by SIGINT/SIGTERM delivered to
        // the supervisor), or the worker completed cleanly with exit(0). Anything
        // else -- a crash signal, an OOM-killer SIGKILL, an engine-exception
        // nonzero exit, or a failed reap -- must RESTART within the remaining
        // budget; otherwise the arbiter would itself cause the campaign death it
        // exists to prevent.
        if (g_supervisor_terminating.load()) break;

        int sig = 0;  // nonzero => worker died by this signal
        if (reaped && WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0) {
                // Exit 0 means the campaign is over ONLY when the worker stopped
                // on its own (budget/exec limit). A worker we SIGTERMed after a
                // heartbeat timeout may also shut down cleanly inside the grace
                // window and exit 0; that is a stall we chose to end, so restart.
                if (!hung) break;
                std::fprintf(stderr,
                    "[arbiter] worker stopped cleanly after heartbeat timeout; restarting.\n");
            } else {
                std::fprintf(stderr, "[arbiter] worker exited status=%d (anomalous); restarting.\n",
                             WEXITSTATUS(status));
            }
        } else if (reaped && WIFSIGNALED(status)) {
            sig = WTERMSIG(status);
        } else {
            std::fprintf(stderr, "[arbiter] waitpid gave no clean status (%s); restarting.\n",
                         std::strerror(errno));
        }

        auto dur = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - worker_start).count();
        // Two clocks, two purposes. `fast_death` (since fork) drives the CPU-spin
        // backoff and must catch a worker that dies instantly in init.
        // `fast_fuzzing_death` (since engine.start()) drives escalation: a death
        // before the engine started fuzzing is a startup fault, never a "fast
        // crash" of the fuzzing loop, and a target with a long calibration pass
        // must still be able to meet the thread-unsafety signature.
        const bool fast_death = (dur < static_cast<long long>(fast_crash_sec));
        consecutive_fast = fast_death ? (consecutive_fast + 1) : 0;
        const uint64_t death_ns = monotonic_ns();
        const bool fuzzing_started =
            (__atomic_load_n(&g_crash_slot->phase, __ATOMIC_ACQUIRE) == 1u);
        const uint64_t fuzz_start = __atomic_load_n(&g_crash_slot->fuzz_start_ns, __ATOMIC_RELAXED);
        const bool fast_fuzzing_death = fuzzing_started && death_ns > fuzz_start &&
            (death_ns - fuzz_start) < static_cast<uint64_t>(fast_crash_sec) * 1000000000ull;
        bool fast_artifact = false;  // set below iff this death was a fast, non-reproducing crash

        if (sig != 0 && is_crash_signal(sig)) {
            // The handler publishes unconditionally, so a fault on a thread
            // that was NOT inside a target call (engine-side) also fills the
            // slot. Such a slot carries nothing to replay: feeding the target
            // (nullptr, 0) would be a spurious CONFIRMED with an empty crash
            // file, or a spurious FALSE POSITIVE counted toward escalation.
            // Only an armed slot is a candidate; an armed slot with len==0 is a
            // genuine zero-length-input crash and is replayed like any other.
            const bool have_candidate =
                (__atomic_load_n(&g_crash_slot->magic, __ATOMIC_ACQUIRE) == kCrashMagic) &&
                (g_crash_slot->armed != 0u);
            if (have_candidate) {
                const size_t n = static_cast<size_t>(g_crash_slot->len);
                std::vector<uint8_t> cand(g_crash_slot->data, g_crash_slot->data + n);
                const uint64_t h = fnv1a64(cand.data(), cand.size());
                bool reproduced;
                auto it = verdicts.find(h);
                if (it != verdicts.end()) {
                    it->second.hits++;
                    if (it->second.reproduced) {
                        reproduced = true;  // a real bug stays real
                    } else if ((it->second.hits % 8u) == 0u) {
                        // Periodically re-verify negative-cached inputs so a
                        // marginally-flaky REAL bug is not permanently missed;
                        // genuine thread-race artifacts keep reproducing 0x.
                        reproduced = replay_reproduces(cand, timeout_ms);
                        if (reproduced) it->second.reproduced = true;
                    } else {
                        reproduced = false;
                    }
                } else {
                    reproduced = replay_reproduces(cand, timeout_ms);
                    if (!reproduced) {
                        // One retry recovers allocator/ASLR-flaky real bugs;
                        // concurrency artifacts reproduce on neither attempt.
                        reproduced = replay_reproduces(cand, timeout_ms);
                    }
                    if (verdicts.size() < 200000) verdicts.emplace(h, Verdict{reproduced, 1});
                }
                if (reproduced) {
                    save_confirmed_crash(cand, sig, output_dir);
                    ++confirmed;
                    std::fprintf(stderr,
                        "[arbiter] CONFIRMED crash sig=%d (reproduced single-threaded); "
                        "saved. total_confirmed=%zu\n", sig, confirmed);
                } else {
                    ++false_pos;
                    if (fast_fuzzing_death) fast_artifact = true;
                    std::fprintf(stderr,
                        "[arbiter] FALSE POSITIVE sig=%d (did NOT reproduce single-threaded); "
                        "discarded. total_false_positives=%zu\n", sig, false_pos);
                }
            } else {
                std::fprintf(stderr,
                    "[arbiter] worker died sig=%d with no target input armed (engine-side "
                    "fault or capture failure); nothing to verify, restarting.\n", sig);
            }
        } else if (sig == SIGKILL) {
            std::fprintf(stderr, hung
                ? "[arbiter] worker killed by supervisor after heartbeat timeout; restarting.\n"
                : "[arbiter] worker SIGKILLed (likely OOM killer); restarting.\n");
        } else if (sig != 0) {
            std::fprintf(stderr, "[arbiter] worker died sig=%d (non-crash); restarting.\n", sig);
        }

        consecutive_fast_artifacts = fast_artifact ? (consecutive_fast_artifacts + 1) : 0;

        ++restarts;
        // The restart cap is a fork-bomb guard. Only hard-stop BOUNDED runs at the
        // cap; on the unbounded (FuzzBench) path keep the campaign alive until the
        // orchestrator terminates us -- dying early would waste the remaining budget.
        if (budget_s > 0 && restarts > max_restarts) {
            std::fprintf(stderr, "[arbiter] restart cap reached (%u); stopping.\n", max_restarts);
            break;
        }

        // Adaptive escalation: repeated fast crashes that do NOT reproduce
        // single-threaded are the signature of a thread-unsafe target. Serialize
        // target execution for subsequent workers so coverage keeps progressing
        // instead of crash-looping. Gated on that signature only (see
        // consecutive_fast_artifacts); 0 disables.
        if (escalate_after > 0 && consecutive_fast_artifacts >= escalate_after &&
            !g_serialize_target.load()) {
            g_serialize_target.store(true);
            std::fprintf(stderr,
                "[arbiter] thread-unsafe target detected (%u consecutive fast non-reproducing "
                "crashes); serializing target execution for subsequent workers.\n",
                consecutive_fast_artifacts);
        }
        if (consecutive_fast >= kBackoffAfterFastDeaths) {
            // Backoff grows with consecutive fast deaths (capped) so a target that
            // dies instantly cannot spin the CPU, while the process stays alive.
            int backoff_ms = std::min(2000, 100 * consecutive_fast);
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
        }
    }

    std::fprintf(stderr,
        "[arbiter] supervisor exiting: confirmed=%zu false_positives=%zu restarts=%u\n",
        confirmed, false_pos, restarts);
    return 0;
}

} // anonymous namespace

// Main entry point - framework-provided main function, not instrumented.
extern "C" int main(int argc, char* argv[]) {
    // Manual single-input replay/repro mode (also a human/CI crash checker).
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.rfind("--replay-verify=", 0) == 0) {
            return run_replay_verify_mode(a.substr(std::strlen("--replay-verify=")), argc, argv);
        }
        if (a == "-help" || a == "--help") {
            // create_fuzzing_config() prints usage and exits; reach it via the
            // engine path without spinning up the supervisor.
            return run_fuzzing_engine_child(argc, argv, /*arbiter_mode=*/false);
        }
    }

    // Opt-out: exact legacy single-process behavior.
    bool no_arbiter = (std::getenv("TRIOFUZZ_NO_ARBITER") != nullptr);
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--no-arbiter") no_arbiter = true;
    }
    if (no_arbiter) {
        return run_fuzzing_engine_child(argc, argv, /*arbiter_mode=*/false);
    }

    return run_supervisor(argc, argv);
}
