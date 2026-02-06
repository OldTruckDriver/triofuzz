#include "enhanced_crash_tracker.h"
#include <execinfo.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <unistd.h>
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

// 信号名称映射
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

// 静态实例指针和信号处理函数
static EnhancedCrashTracker* g_tracker_instance = nullptr;

static void enhanced_signal_handler(int sig, siginfo_t* info, void* context) {
    if (g_tracker_instance) {
        g_tracker_instance->handleCrash(sig, info, context);
    }
    
    // 调用原始信号处理器
    signal(sig, SIG_DFL);
    raise(sig);
}

// 单例获取
EnhancedCrashTracker& EnhancedCrashTracker::getInstance() {
    static EnhancedCrashTracker instance;
    return instance;
}

// 安全关闭
void EnhancedCrashTracker::shutdown() {
    std::lock_guard<std::mutex> lock(shutdown_mutex_);
    shutting_down_ = true;
    
    // 等待任何正在进行的信号处理完成
    while (in_signal_handler_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    // 清理资源
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

// 安全的输入数据访问
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

// 初始化crash追踪器
void EnhancedCrashTracker::initialize() {
    if (initialized_) return;
    
    g_tracker_instance = this;
    output_directory_ = "output/crashes";
    
    // 创建输出目录
    system(("mkdir -p " + output_directory_).c_str());
    
    // 设置信号处理器
    struct sigaction sa;
    sa.sa_sigaction = enhanced_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    
    // 注册信号处理器
    int signals[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP};
    for (int sig : signals) {
        sigaction(sig, &sa, &old_sigaction_[sig]);
    }
    
    initialized_ = true;
}

// 设置当前输入数据
void EnhancedCrashTracker::setCurrentInput(const std::vector<uint8_t>& input) {
    if (shutting_down_.load()) {
        return; // 如果正在关闭，忽略设置请求
    }
    
    std::lock_guard<std::mutex> lock(input_mutex_);
    if (!shutting_down_.load()) { // 双重检查
        current_input_ = input;
        current_input_file_.clear();
    }
}

void EnhancedCrashTracker::setCurrentInputFile(const std::string& file_path) {
    if (shutting_down_.load()) {
        return; // 如果正在关闭，忽略设置请求
    }
    
    std::lock_guard<std::mutex> lock(input_mutex_);
    if (!shutting_down_.load()) { // 双重检查
        current_input_file_ = file_path;
        
        // 读取文件内容
        std::ifstream file(file_path, std::ios::binary);
        if (file) {
            current_input_ = std::vector<uint8_t>(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>()
            );
        }
    }
}

// 设置运行环境
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

// 主要的crash处理函数
void EnhancedCrashTracker::handleCrash(int signal, siginfo_t* info, void* context) {
    // 防止在程序退出时处理crash
    if (shutting_down_.load()) {
        return;
    }
    
    // 设置信号处理状态标志，防止重入
    bool expected = false;
    if (!in_signal_handler_.compare_exchange_strong(expected, true)) {
        // 已经在处理信号，避免递归
        return;
    }
    
    // RAII方式确保退出时清理标志
    struct SignalHandlerGuard {
        std::atomic<bool>& flag;
        SignalHandlerGuard(std::atomic<bool>& f) : flag(f) {}
        ~SignalHandlerGuard() { flag = false; }
    } guard(in_signal_handler_);
    
    CrashInfo crash;
    
    // 基本信息
    crash.signal_number = signal;
    auto it = signal_names.find(signal);
    crash.signal_name = (it != signal_names.end()) ? it->second : "Unknown signal";
    crash.timestamp = time(nullptr);
    crash.process_id = getpid();
    crash.binary_path = binary_path_;
    
    // 故障详情
    crash.fault_address = info->si_addr;
    crash.instruction_pointer = nullptr;
    
    #ifdef __x86_64__
    if (context) {
        ucontext_t* uc = static_cast<ucontext_t*>(context);
        crash.instruction_pointer = (void*)uc->uc_mcontext.gregs[REG_RIP];
    }
    #endif
    
    // 分析故障类型
    if (crash.fault_address == nullptr) {
        crash.fault_type = "NULL pointer dereference";
    } else if ((uintptr_t)crash.fault_address < 0x1000) {
        crash.fault_type = "Near-NULL pointer dereference";
    } else if ((uintptr_t)crash.fault_address > 0x7fffffffffff) {
        crash.fault_type = "High value address (possible corruption)";
    } else {
        crash.fault_type = "Memory access violation";
    }
    
    // 输入数据 - 使用安全的访问方法
    std::vector<uint8_t> input_copy = getCurrentInputSafe();
    crash.crash_input = input_copy;
    crash.input_size = input_copy.size();
    crash.input_hash = calculateInputHash(input_copy);
    
    // 堆栈跟踪
    crash.stack_trace = getStackTrace(context);
    crash.symbolized_trace = ""; // 将在getStackTrace中填充
    
    // 系统环境
    crash.command_line_args = command_line_args_;
    crash.environment_vars = getEnvironmentVariables();
    crash.working_directory = working_directory_;
    
    // 内存信息
    crash.memory_maps = getMemoryMaps();
    crash.registers_dump = getRegistersDump(context);
    crash.loaded_libraries = getLoadedLibraries();
    
    // 构建信息
    crash.build_version = getBuildInformation();
    
    // 分析crash
    crash.crash_category = categorizeCrash(crash);
    crash.exploitability = assessExploitability(crash);
    crash.is_unique_crash = isUniqueCrash(crash);
    
    // 安全分析
    crash.potential_cve = checkForKnownCVEs(crash);
    crash.security_impact = analyzeSecurityImpact(crash);
    
    // 保存crash报告
    saveCrashReport(crash);
    
    // 生成复现工具
    generateReproductionScript(crash);
    generateGdbScript(crash);
    
    // 添加到历史记录
    if (!shutting_down_.load()) {
        std::lock_guard<std::mutex> lock(history_mutex_);
        if (!shutting_down_.load()) { // 双重检查
            crash_history_.push_back(crash);
        }
    }
}

// 获取堆栈跟踪
std::vector<std::string> EnhancedCrashTracker::getStackTrace(void* context) {
    std::vector<std::string> trace;
    void* array[256];
    size_t size;
    
    // 获取堆栈地址
    size = backtrace(array, 256);
    char** messages = backtrace_symbols(array, size);
    
    if (messages) {
        for (size_t i = 0; i < size; ++i) {
            std::string frame = messages[i];
            
            // 尝试解析符号名
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

// 符号化地址
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
        
        // 添加偏移量
        if (info.dli_saddr) {
            uintptr_t offset = (uintptr_t)addr - (uintptr_t)info.dli_saddr;
            result += "+0x" + std::to_string(offset);
        }
        
        return result;
    }
    
    return "";
}

// 获取内存映射
std::string EnhancedCrashTracker::getMemoryMaps() {
    std::ifstream maps("/proc/self/maps");
    std::stringstream ss;
    std::string line;
    
    while (std::getline(maps, line)) {
        ss << line << "\n";
    }
    
    return ss.str();
}

// 获取寄存器转储
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

// 获取加载的库
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

// 获取构建信息
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

// 计算输入哈希 (使用 FNV-1a 算法，无需外部依赖)
std::string EnhancedCrashTracker::calculateInputHash(const std::vector<uint8_t>& input) {
    if (input.empty()) return "empty_input";

    // FNV-1a 64-bit hash - 快速且分布均匀，适合 fingerprinting
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

// 获取环境变量
std::map<std::string, std::string> EnhancedCrashTracker::getEnvironmentVariables() {
    std::map<std::string, std::string> env_vars;
    
    // 只保存重要的环境变量
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

// 保存输入到文件
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

// 分类crash
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
        // 检查堆栈中是否有sanitizer信息
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

// 评估可利用性
std::string EnhancedCrashTracker::assessExploitability(const CrashInfo& crash) {
    int score = 0;
    
    // 基于信号类型
    if (crash.signal_number == SIGSEGV) score += 3;
    else if (crash.signal_number == SIGABRT) score += 1;
    
    // 基于故障地址
    if (crash.fault_address != nullptr && (uintptr_t)crash.fault_address > 0x1000) {
        score += 2; // 可能的内存损坏
    }
    
    // 检查是否在关键函数中
    for (const auto& frame : crash.stack_trace) {
        if (frame.find("memcpy") != std::string::npos ||
            frame.find("strcpy") != std::string::npos ||
            frame.find("malloc") != std::string::npos) {
            score += 2;
            break;
        }
    }
    
    // 输入大小影响
    if (crash.input_size > 0) score += 1;
    
    if (score >= 5) return "HIGH";
    else if (score >= 3) return "MEDIUM";
    else return "LOW";
}

// 检查是否为唯一crash
bool EnhancedCrashTracker::isUniqueCrash(const CrashInfo& crash) {
    if (shutting_down_.load()) {
        return true; // 在关闭时假设是唯一的，避免复杂检查
    }
    
    std::lock_guard<std::mutex> lock(history_mutex_);
    if (shutting_down_.load()) {
        return true; // 双重检查
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

// 检查已知CVE
std::string EnhancedCrashTracker::checkForKnownCVEs(const CrashInfo& crash) {
    // 检查FreeType相关crash
    for (const auto& frame : crash.stack_trace) {
        if (frame.find("FT_") != std::string::npos ||
            frame.find("freetype") != std::string::npos) {
            return "Possible CVE-2025-27363 (FreeType Out-of-bounds Write)";
        }
    }
    
    return "No known CVE detected";
}

// 分析安全影响
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

// 生成crash报告
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

// 保存crash报告
void EnhancedCrashTracker::saveCrashReport(const CrashInfo& crash) {
    std::string base_filename = output_directory_ + "/crash_enhanced_" + 
                               std::to_string(crash.signal_number) + "_" + 
                               std::to_string(crash.timestamp);
    
    // 保存主报告
    std::ofstream report_file(base_filename + "_report.txt");
    report_file << generateCrashReport(crash);
    
    // 保存输入数据
    std::string input_file = saveInputToFile(crash.crash_input);
    
    // 保存内存映射
    std::ofstream maps_file(base_filename + "_maps.txt");
    maps_file << crash.memory_maps;
    
    // 创建快速复现信息文件
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

// 生成复现脚本
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
    
    // 添加执行权限
    system(("chmod +x " + script_filename).c_str());
}

// 生成GDB脚本
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