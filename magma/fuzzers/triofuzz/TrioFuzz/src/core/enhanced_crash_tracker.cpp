#include "enhanced_crash_tracker.h"
#include <execinfo.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <cstdio>
#include <cerrno>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <cstring>
#include <set>
#include <mutex>
#include <thread>
#include <chrono>

namespace collafuzz {
namespace crash_tracker {

// Signal name mapping
static const std::map<int, std::string> signal_names = {
    {SIGSEGV, "SIGSEGV (Segmentation fault)"},
    {SIGABRT, "SIGABRT (Abort - likely sanitizer)"},
    {SIGFPE, "SIGFPE (Floating point exception)"},
    {SIGILL, "SIGILL (Illegal instruction)"},
    {SIGBUS, "SIGBUS (Bus error)"},
    {SIGTRAP, "SIGTRAP (Trace/breakpoint trap)"},
    {SIGKILL, "SIGKILL (Killed)"},
    {SIGTERM, "SIGTERM (Terminated)"}
};

// Static instance pointer and signal handler
static EnhancedCrashTracker* g_tracker_instance = nullptr;

// In-process crash recovery: when set, signal handlers siglongjmp here
// instead of letting the signal kill the process. See header for the protocol.
thread_local sigjmp_buf tls_target_jmp_buf;
thread_local bool tls_in_target_execution = false;

// Optional: magma-compatible findings/crashes/ dir. When set, crashing
// inputs are saved here so the magma harness can count and reproduce bugs.
// The plain C buffer is what the signal handler reads — std::string here
// is just for the public API and not async-signal-safe.
static std::mutex g_findings_dir_mutex;
static std::string g_findings_crashes_dir;
static char g_findings_crashes_dir_c[512] = {0};
static std::atomic<uint64_t> g_findings_crash_counter{0};

void setFindingsCrashesDir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(g_findings_dir_mutex);
    g_findings_crashes_dir = dir;
    // Mirror to a plain C buffer so the signal handler can use it safely
    // without locking or std::string allocation.
    std::snprintf(g_findings_crashes_dir_c, sizeof(g_findings_crashes_dir_c),
                  "%s", dir.c_str());
}

void saveCrashingInputForMagma(const std::vector<uint8_t>& input, int sig) {
    if (g_findings_crashes_dir_c[0] == 0 || input.empty()) return;

    uint64_t n = g_findings_crash_counter.fetch_add(1) + 1;
    char path[640];
    std::snprintf(path, sizeof(path),
                  "%s/crash-sig%d-%06llu-%d-%lu",
                  g_findings_crashes_dir_c, sig,
                  (unsigned long long)n,
                  (int)getpid(),
                  (unsigned long)pthread_self());

    int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    size_t written = 0;
    while (written < input.size()) {
        ssize_t r = ::write(fd, input.data() + written, input.size() - written);
        if (r <= 0) break;
        written += (size_t)r;
    }
    ::close(fd);
}

static void enhanced_signal_handler(int sig, siginfo_t* info, void* context) {
    // If the crash happened inside the target (LLVMFuzzerTestOneInput),
    // record it and longjmp back to the executor so we keep fuzzing.
    // Crashes outside the target (engine itself) fall through to the
    // legacy die-and-restart path.
    if (tls_in_target_execution) {
        // Best-effort crash report + magma save. Both are guarded against
        // recursion / shutdown internally.
        if (g_tracker_instance) {
            g_tracker_instance->handleCrash(sig, info, context);
        }
        // Reset flag *before* longjmp; control returns to sigsetjmp call site
        // with `sig` as the return value.
        tls_in_target_execution = false;
        siglongjmp(tls_target_jmp_buf, sig);
        // unreachable
    }

    if (g_tracker_instance) {
        g_tracker_instance->handleCrash(sig, info, context);
    }

    // Fall back to the default signal handler
    signal(sig, SIG_DFL);
    raise(sig);
}

// Singleton accessor
EnhancedCrashTracker& EnhancedCrashTracker::getInstance() {
    static EnhancedCrashTracker instance;
    return instance;
}

// Safe shutdown
void EnhancedCrashTracker::shutdown() {
    std::lock_guard<std::mutex> lock(shutdown_mutex_);
    shutting_down_ = true;
    
    // Wait for any in-progress signal handling to complete
    while (in_signal_handler_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    // Clean up resources
    {
        std::lock_guard<std::mutex> input_lock(input_mutex_);
        current_input_.clear();
        current_input_file_.clear();
    }
    
    {
        std::lock_guard<std::mutex> history_lock(history_mutex_);
        crash_history_.clear();
    }
}

bool EnhancedCrashTracker::isShuttingDown() const {
    return shutting_down_.load();
}

// Safe access to input data
std::vector<uint8_t> EnhancedCrashTracker::getCurrentInputSafe() const {
    if (shutting_down_.load()) {
        return {};
    }
    
    std::lock_guard<std::mutex> lock(input_mutex_);
    return current_input_;
}

std::string EnhancedCrashTracker::getCurrentInputFileSafe() const {
    if (shutting_down_.load()) {
        return "";
    }
    
    std::lock_guard<std::mutex> lock(input_mutex_);
    return current_input_file_;
}

// Initialize crash tracker
void EnhancedCrashTracker::initialize() {
    if (initialized_) return;
    
    g_tracker_instance = this;
    output_directory_ = "output/crashes";
    
    // Create output directory
    system(("mkdir -p " + output_directory_).c_str());
    
    // Set up signal handler
    struct sigaction sa;
    sa.sa_sigaction = enhanced_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    
    // Register signal handlers
    int signals[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP};
    for (int sig : signals) {
        sigaction(sig, &sa, &old_sigaction_[sig]);
    }
    
    initialized_ = true;
}

// Set current input data
void EnhancedCrashTracker::setCurrentInput(const std::vector<uint8_t>& input) {
    if (shutting_down_.load()) {
        return; // If shutting down, ignore the request
    }
    
    std::lock_guard<std::mutex> lock(input_mutex_);
    if (!shutting_down_.load()) { // Double-check
        current_input_ = input;
        current_input_file_.clear();
    }
}

void EnhancedCrashTracker::setCurrentInputFile(const std::string& file_path) {
    if (shutting_down_.load()) {
        return; // If shutting down, ignore the request
    }
    
    std::lock_guard<std::mutex> lock(input_mutex_);
    if (!shutting_down_.load()) { // Double-check
        current_input_file_ = file_path;
        
        // Read file contents
        std::ifstream file(file_path, std::ios::binary);
        if (file) {
            current_input_ = std::vector<uint8_t>(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>()
            );
        }
    }
}

// Set runtime environment
void EnhancedCrashTracker::setCommandLineArgs(int argc, char* argv[]) {
    command_line_args_.clear();
    for (int i = 0; i < argc; ++i) {
        command_line_args_.push_back(argv[i]);
    }
}

void EnhancedCrashTracker::setBinaryPath(const std::string& path) {
    binary_path_ = path;
}

void EnhancedCrashTracker::setWorkingDirectory(const std::string& dir) {
    working_directory_ = dir;
}

// Main crash handling function
void EnhancedCrashTracker::handleCrash(int signal, siginfo_t* info, void* context) {
    // Avoid handling crashes during shutdown
    if (shutting_down_.load()) {
        return;
    }
    
    // Set signal-handling state flag to prevent reentrancy
    bool expected = false;
    if (!in_signal_handler_.compare_exchange_strong(expected, true)) {
        // Already handling a signal; avoid recursion
        return;
    }
    
    // Use RAII to ensure the flag is cleared on exit
    struct SignalHandlerGuard {
        std::atomic<bool>& flag;
        SignalHandlerGuard(std::atomic<bool>& f) : flag(f) {}
        ~SignalHandlerGuard() { flag = false; }
    } guard(in_signal_handler_);
    
    CrashInfo crash;
    
    // Basic information
    crash.signal_number = signal;
    auto it = signal_names.find(signal);
    crash.signal_name = (it != signal_names.end()) ? it->second : "Unknown signal";
    crash.timestamp = time(nullptr);
    crash.process_id = getpid();
    crash.binary_path = binary_path_;
    
    // Fault details
    crash.fault_address = info->si_addr;
    crash.instruction_pointer = nullptr;
    
    #ifdef __x86_64__
    if (context) {
        ucontext_t* uc = static_cast<ucontext_t*>(context);
        crash.instruction_pointer = (void*)uc->uc_mcontext.gregs[REG_RIP];
    }
    #endif
    
    // Analyze fault type
    if (crash.fault_address == nullptr) {
        crash.fault_type = "NULL pointer dereference";
    } else if ((uintptr_t)crash.fault_address < 0x1000) {
        crash.fault_type = "Near-NULL pointer dereference";
    } else if ((uintptr_t)crash.fault_address > 0x7fffffffffff) {
        crash.fault_type = "High value address (possible corruption)";
    } else {
        crash.fault_type = "Memory access violation";
    }
    
    // Input data - use safe access method
    std::vector<uint8_t> input_copy = getCurrentInputSafe();
    crash.crash_input = input_copy;
    crash.input_size = input_copy.size();
    crash.input_hash = calculateInputHash(input_copy);
    
    // Stack trace
    crash.stack_trace = getStackTrace(context);
    crash.symbolized_trace = ""; // Filled in getStackTrace
    
    // System environment
    crash.command_line_args = command_line_args_;
    crash.environment_vars = getEnvironmentVariables();
    crash.working_directory = working_directory_;
    
    // Memory information
    crash.memory_maps = getMemoryMaps();
    crash.registers_dump = getRegistersDump(context);
    crash.loaded_libraries = getLoadedLibraries();
    
    // Build information
    crash.build_version = getBuildInformation();
    
    // Analyze crash
    crash.crash_category = categorizeCrash(crash);
    crash.exploitability = assessExploitability(crash);
    crash.is_unique_crash = isUniqueCrash(crash);
    
    // Security analysis
    crash.potential_cve = checkForKnownCVEs(crash);
    crash.security_impact = analyzeSecurityImpact(crash);
    
    // Save crash report
    saveCrashReport(crash);
    
    // Generate reproduction helpers
    generateReproductionScript(crash);
    generateGdbScript(crash);
    
    // Add to history
    if (!shutting_down_.load()) {
        std::lock_guard<std::mutex> lock(history_mutex_);
        if (!shutting_down_.load()) { // Double-check
            crash_history_.push_back(crash);
        }
    }
}

// Get stack trace
std::vector<std::string> EnhancedCrashTracker::getStackTrace(void* context) {
    std::vector<std::string> trace;
    void* array[256];
    size_t size;
    
    // Get stack addresses
    size = backtrace(array, 256);
    char** messages = backtrace_symbols(array, size);
    
    if (messages) {
        for (size_t i = 0; i < size; ++i) {
            std::string frame = messages[i];
            
            // Try to symbolize the address
            std::string symbolized = symbolizeAddress(array[i]);
            if (!symbolized.empty()) {
                frame += " -> " + symbolized;
            }
            
            trace.push_back(frame);
        }
        free(messages);
    }
    
    return trace;
}

// Symbolize address
std::string EnhancedCrashTracker::symbolizeAddress(void* addr) {
    Dl_info info;
    if (dladdr(addr, &info) && info.dli_sname) {
        int status;
        char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
        
        std::string result;
        if (status == 0 && demangled) {
            result = demangled;
            free(demangled);
        } else {
            result = info.dli_sname;
        }
        
        // Append offset
        if (info.dli_saddr) {
            uintptr_t offset = (uintptr_t)addr - (uintptr_t)info.dli_saddr;
            result += "+0x" + std::to_string(offset);
        }
        
        return result;
    }
    
    return "";
}

// Get memory maps
std::string EnhancedCrashTracker::getMemoryMaps() {
    std::ifstream maps("/proc/self/maps");
    std::stringstream ss;
    std::string line;
    
    while (std::getline(maps, line)) {
        ss << line << "\n";
    }
    
    return ss.str();
}

// Get register dump
std::string EnhancedCrashTracker::getRegistersDump(void* context) {
    std::stringstream ss;
    
    #ifdef __x86_64__
    if (context) {
        ucontext_t* uc = static_cast<ucontext_t*>(context);
        ss << "RAX: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RAX] << "\n";
        ss << "RBX: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RBX] << "\n";
        ss << "RCX: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RCX] << "\n";
        ss << "RDX: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RDX] << "\n";
        ss << "RSI: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RSI] << "\n";
        ss << "RDI: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RDI] << "\n";
        ss << "RBP: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RBP] << "\n";
        ss << "RSP: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RSP] << "\n";
        ss << "RIP: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RIP] << "\n";
    }
    #else
    ss << "Register dump not available for this architecture\n";
    #endif
    
    return ss.str();
}

// Get loaded libraries
std::vector<std::string> EnhancedCrashTracker::getLoadedLibraries() {
    std::vector<std::string> libraries;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    std::set<std::string> seen_libs;
    
    while (std::getline(maps, line)) {
        size_t pos = line.find_last_of(' ');
        if (pos != std::string::npos) {
            std::string lib_path = line.substr(pos + 1);
            if (lib_path.find(".so") != std::string::npos && 
                seen_libs.find(lib_path) == seen_libs.end()) {
                libraries.push_back(lib_path);
                seen_libs.insert(lib_path);
            }
        }
    }
    
    return libraries;
}

// Get build information
std::string EnhancedCrashTracker::getBuildInformation() {
    std::stringstream ss;
    ss << "Compiler: " << __VERSION__ << "\n";
    ss << "Build Date: " << __DATE__ << " " << __TIME__ << "\n";
    
    #ifdef CVE_2025_27363_MITIGATION
    ss << "CVE-2025-27363 Mitigation: ACTIVE\n";
    #endif
    
    #ifdef __SANITIZE_ADDRESS__
    ss << "AddressSanitizer: ENABLED\n";
    #endif
    
    return ss.str();
}

// Compute input hash (FNV-1a; no external dependencies)
std::string EnhancedCrashTracker::calculateInputHash(const std::vector<uint8_t>& input) {
    if (input.empty()) return "empty_input";

    // FNV-1a 64-bit hash - fast and well-distributed; suitable for fingerprinting
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;

    uint64_t hash = FNV_OFFSET_BASIS;
    for (uint8_t byte : input) {
        hash ^= byte;
        hash *= FNV_PRIME;
    }

    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hash;

    return ss.str();
}

// Get environment variables
std::map<std::string, std::string> EnhancedCrashTracker::getEnvironmentVariables() {
    std::map<std::string, std::string> env_vars;
    
    // Only keep important environment variables
    const char* important_vars[] = {
        "PATH", "LD_LIBRARY_PATH", "HOME", "USER", "SHELL",
        "ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS"
    };
    
    for (const char* var : important_vars) {
        const char* value = getenv(var);
        if (value) {
            env_vars[var] = value;
        }
    }
    
    return env_vars;
}

// Save input to file
std::string EnhancedCrashTracker::saveInputToFile(const std::vector<uint8_t>& input) {
    std::string filename = output_directory_ + "/crash_input_" + 
                          std::to_string(time(nullptr)) + "_" + 
                          calculateInputHash(input).substr(0, 8) + ".bin";
    
    std::ofstream file(filename, std::ios::binary);
    if (file && !input.empty()) {
        file.write(reinterpret_cast<const char*>(input.data()), input.size());
    }
    
    return filename;
}

// Categorize crash
std::string EnhancedCrashTracker::categorizeCrash(const CrashInfo& crash) {
    if (crash.signal_number == SIGSEGV) {
        if (crash.fault_address == nullptr) {
            return "NULL_DEREF";
        } else if ((uintptr_t)crash.fault_address < 0x1000) {
            return "NEAR_NULL_DEREF";
        } else {
            return "MEMORY_CORRUPTION";
        }
    } else if (crash.signal_number == SIGABRT) {
        // Check whether the stack trace contains sanitizer frames
        for (const auto& frame : crash.stack_trace) {
            if (frame.find("__asan") != std::string::npos ||
                frame.find("__ubsan") != std::string::npos) {
                return "SANITIZER_ABORT";
            }
        }
        return "ABORT";
    }
    
    return "UNKNOWN";
}

// Assess exploitability
std::string EnhancedCrashTracker::assessExploitability(const CrashInfo& crash) {
    int score = 0;
    
    // Based on signal type
    if (crash.signal_number == SIGSEGV) score += 3;
    else if (crash.signal_number == SIGABRT) score += 1;
    
    // Based on fault address
    if (crash.fault_address != nullptr && (uintptr_t)crash.fault_address > 0x1000) {
        score += 2; // Possible memory corruption
    }
    
    // Check whether the crash occurred in critical functions
    for (const auto& frame : crash.stack_trace) {
        if (frame.find("memcpy") != std::string::npos ||
            frame.find("strcpy") != std::string::npos ||
            frame.find("malloc") != std::string::npos) {
            score += 2;
            break;
        }
    }
    
    // Input-size factor
    if (crash.input_size > 0) score += 1;
    
    if (score >= 5) return "HIGH";
    else if (score >= 3) return "MEDIUM";
    else return "LOW";
}

// Check whether the crash is unique
bool EnhancedCrashTracker::isUniqueCrash(const CrashInfo& crash) {
    if (shutting_down_.load()) {
        return true; // During shutdown, assume uniqueness to avoid expensive checks
    }
    
    std::lock_guard<std::mutex> lock(history_mutex_);
    if (shutting_down_.load()) {
        return true; // Double-check
    }
    
    for (const auto& prev_crash : crash_history_) {
        if (prev_crash.signal_number == crash.signal_number &&
            prev_crash.fault_address == crash.fault_address &&
            prev_crash.input_hash == crash.input_hash) {
            return false;
        }
    }
    return true;
}

// Check known CVEs
std::string EnhancedCrashTracker::checkForKnownCVEs(const CrashInfo& crash) {
    // Check for FreeType-related crashes
    for (const auto& frame : crash.stack_trace) {
        if (frame.find("FT_") != std::string::npos ||
            frame.find("freetype") != std::string::npos) {
            return "Possible CVE-2025-27363 (FreeType Out-of-bounds Write)";
        }
    }
    
    return "No known CVE detected";
}

// Analyze security impact
std::string EnhancedCrashTracker::analyzeSecurityImpact(const CrashInfo& crash) {
    std::stringstream ss;
    
    if (crash.exploitability == "HIGH") {
        ss << "HIGH RISK: Potential remote code execution\n";
        ss << "Immediate patching recommended\n";
    } else if (crash.exploitability == "MEDIUM") {
        ss << "MEDIUM RISK: Possible denial of service\n";
        ss << "Investigation and patching recommended\n";
    } else {
        ss << "LOW RISK: Likely local crash only\n";
        ss << "Monitor for similar patterns\n";
    }
    
    return ss.str();
}

// Generate crash report
std::string EnhancedCrashTracker::generateCrashReport(const CrashInfo& crash) {
    std::stringstream ss;
    
    ss << "=== Enhanced CollaFuzz Crash Report ===\n";
    ss << "Timestamp: " << ctime(&crash.timestamp);
    ss << "Process ID: " << crash.process_id << "\n";
    ss << "Binary: " << crash.binary_path << "\n\n";
    
    ss << "=== Signal Information ===\n";
    ss << "Signal: " << crash.signal_number << " (" << crash.signal_name << ")\n";
    ss << "Fault Address: " << crash.fault_address << "\n";
    ss << "Fault Type: " << crash.fault_type << "\n";
    ss << "Instruction Pointer: " << crash.instruction_pointer << "\n\n";
    
    ss << "=== Input Information ===\n";
    ss << "Input Size: " << crash.input_size << " bytes\n";
    ss << "Input Hash: " << crash.input_hash << "\n";
    std::string input_file = getCurrentInputFileSafe();
    if (!input_file.empty()) {
        ss << "Input File: " << input_file << "\n";
    }
    ss << "\n";
    
    ss << "=== Stack Trace ===\n";
    for (size_t i = 0; i < crash.stack_trace.size(); ++i) {
        ss << "#" << i << " " << crash.stack_trace[i] << "\n";
    }
    ss << "\n";
    
    ss << "=== Registers ===\n";
    ss << crash.registers_dump << "\n";
    
    ss << "=== Analysis ===\n";
    ss << "Category: " << crash.crash_category << "\n";
    ss << "Exploitability: " << crash.exploitability << "\n";
    ss << "Unique Crash: " << (crash.is_unique_crash ? "Yes" : "No") << "\n";
    ss << "Security Impact:\n" << crash.security_impact << "\n";
    
    if (!crash.potential_cve.empty()) {
        ss << "=== Security Alert ===\n";
        ss << crash.potential_cve << "\n\n";
    }
    
    ss << "=== Build Information ===\n";
    ss << crash.build_version << "\n";
    
    ss << "=== Environment ===\n";
    ss << "Working Directory: " << crash.working_directory << "\n";
    ss << "Command Line: ";
    for (const auto& arg : crash.command_line_args) {
        ss << arg << " ";
    }
    ss << "\n\n";
    
    ss << "=== Reproduction Instructions ===\n";
    ss << "See accompanying reproduction script and GDB commands\n";
    
    return ss.str();
}

// Save crash report
void EnhancedCrashTracker::saveCrashReport(const CrashInfo& crash) {
    std::string base_filename = output_directory_ + "/crash_enhanced_" + 
                               std::to_string(crash.signal_number) + "_" + 
                               std::to_string(crash.timestamp);
    
    // Save main report
    std::ofstream report_file(base_filename + "_report.txt");
    report_file << generateCrashReport(crash);
    
    // Save input data
    std::string input_file = saveInputToFile(crash.crash_input);
    
    // Save memory maps
    std::ofstream maps_file(base_filename + "_maps.txt");
    maps_file << crash.memory_maps;
    
    // Create a quick reproduction info file
    std::ofstream quick_file(base_filename + "_quick.txt");
    quick_file << "=== Quick Reproduction Info ===\n";
    quick_file << "Input file: " << input_file << "\n";
    quick_file << "Command: " << crash.reproduction_command << "\n";
    quick_file << "Category: " << crash.crash_category << "\n";
    quick_file << "Exploitability: " << crash.exploitability << "\n";
    if (!crash.potential_cve.empty()) {
        quick_file << "CVE: " << crash.potential_cve << "\n";
    }
}

// Generate reproduction script
void EnhancedCrashTracker::generateReproductionScript(const CrashInfo& crash) {
    std::string script_filename = output_directory_ + "/reproduce_crash_" + 
                                 std::to_string(crash.timestamp) + ".sh";
    
    std::ofstream script(script_filename);
    script << "#!/bin/bash\n";
    script << "# Crash Reproduction Script\n";
    script << "# Generated by Enhanced CollaFuzz Crash Tracker\n";
    script << "# Signal: " << crash.signal_number << " (" << crash.signal_name << ")\n";
    script << "# Category: " << crash.crash_category << "\n";
    script << "# Exploitability: " << crash.exploitability << "\n\n";
    
    if (!crash.potential_cve.empty()) {
        script << "# SECURITY ALERT: " << crash.potential_cve << "\n\n";
    }
    
    script << "set -e\n\n";
    
    script << "echo \"🔍 Reproducing crash...\"\n";
    script << "echo \"Signal: " << crash.signal_number << "\"\n";
    script << "echo \"Category: " << crash.crash_category << "\"\n\n";
    
    std::string input_filename = saveInputToFile(crash.crash_input);
    
    script << "# Original reproduction command\n";
    script << "echo \"Running original command...\"\n";
    for (const auto& arg : crash.command_line_args) {
        script << "\"" << arg << "\" ";
    }
    script << "\"" << input_filename << "\"\n\n";
    
    script << "# With GDB for debugging\n";
    script << "echo \"To debug with GDB, run:\"\n";
    script << "echo \"gdb --batch --ex run --ex bt --ex quit --args ";
    for (const auto& arg : crash.command_line_args) {
        script << arg << " ";
    }
    script << input_filename << "\"\n\n";
    
    script << "# With Valgrind for memory analysis\n";
    script << "echo \"To analyze with Valgrind, run:\"\n";
    script << "echo \"valgrind --tool=memcheck --leak-check=full ";
    for (const auto& arg : crash.command_line_args) {
        script << arg << " ";
    }
    script << input_filename << "\"\n\n";
    
    script << "echo \"📋 Input hash: " << crash.input_hash << "\"\n";
    script << "echo \"📋 Input size: " << crash.input_size << " bytes\"\n";
    script << "echo \"📋 Input file: " << input_filename << "\"\n";
    
    // Add execute permission
    system(("chmod +x " + script_filename).c_str());
}

// Generate GDB script
void EnhancedCrashTracker::generateGdbScript(const CrashInfo& crash) {
    std::string gdb_filename = output_directory_ + "/gdb_crash_" + 
                              std::to_string(crash.timestamp) + ".gdb";
    
    std::ofstream gdb_script(gdb_filename);
    gdb_script << "# GDB script for crash analysis\n";
    gdb_script << "# Generated by Enhanced CollaFuzz Crash Tracker\n\n";
    
    gdb_script << "set pagination off\n";
    gdb_script << "set logging file gdb_output_" << crash.timestamp << ".txt\n";
    gdb_script << "set logging on\n\n";
    
    gdb_script << "echo === Crash Analysis ===\\n\n";
    gdb_script << "run " << saveInputToFile(crash.crash_input) << "\n\n";
    
    gdb_script << "echo === Backtrace ===\\n\n";
    gdb_script << "bt\n";
    gdb_script << "bt full\n\n";
    
    gdb_script << "echo === Registers ===\\n\n";
    gdb_script << "info registers\n\n";
    
    gdb_script << "echo === Memory around crash ===\\n\n";
    gdb_script << "x/16xw $rip-32\n";
    gdb_script << "x/16xw $rsp-32\n\n";
    
    gdb_script << "echo === Disassembly ===\\n\n";
    gdb_script << "disas $rip-32, $rip+32\n\n";
    
    gdb_script << "set logging off\n";
    gdb_script << "quit\n";
}

} // namespace crash_tracker
} // namespace collafuzz 
