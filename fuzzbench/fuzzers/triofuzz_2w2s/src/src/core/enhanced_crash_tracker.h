#ifndef ENHANCED_CRASH_TRACKER_H
#define ENHANCED_CRASH_TRACKER_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <ctime>
#include <signal.h>
#include <mutex>
#include <atomic>

namespace collafuzz {
namespace crash_tracker {

// 增强的crash信息结构
struct CrashInfo {
    // 基本信息
    int signal_number;
    std::string signal_name;
    time_t timestamp;
    pid_t process_id;
    std::string binary_path;
    
    // 故障详情
    void* fault_address;
    std::string fault_type;
    void* instruction_pointer;
    std::string crash_description;
    
    // 输入数据
    std::vector<uint8_t> crash_input;
    std::string input_hash;
    size_t input_size;
    
    // 堆栈跟踪
    std::vector<std::string> stack_trace;
    std::vector<void*> stack_addresses;
    std::string symbolized_trace;
    
    // 系统环境
    std::vector<std::string> command_line_args;
    std::map<std::string, std::string> environment_vars;
    std::string working_directory;
    
    // 内存信息
    std::string memory_maps;
    std::string registers_dump;
    std::vector<std::string> loaded_libraries;
    
    // 构建信息
    std::string build_version;
    std::string build_flags;
    std::string compiler_version;
    std::string commit_hash;
    
    // 复现信息
    std::string reproduction_command;
    std::string reproduction_script;
    std::string gdb_commands;
    
    // 分类和优先级
    std::string crash_category;
    std::string exploitability;
    int severity_score;
    bool is_unique_crash;
    
    // CVE相关
    std::string potential_cve;
    std::string security_impact;
    std::vector<std::string> related_vulnerabilities;
};

// 增强的crash追踪器类
class EnhancedCrashTracker {
public:
    static EnhancedCrashTracker& getInstance();
    
    // 初始化crash追踪器
    void initialize();
    
    // 安全关闭和清理
    void shutdown();
    bool isShuttingDown() const;
    
    // 设置当前输入数据
    void setCurrentInput(const std::vector<uint8_t>& input);
    void setCurrentInputFile(const std::string& file_path);
    
    // 设置运行环境
    void setCommandLineArgs(int argc, char* argv[]);
    void setBinaryPath(const std::string& path);
    void setWorkingDirectory(const std::string& dir);
    
    // crash处理
    void handleCrash(int signal, siginfo_t* info, void* context);
    
    // 生成crash报告
    std::string generateCrashReport(const CrashInfo& crash);
    void saveCrashReport(const CrashInfo& crash);
    
    // 生成复现工具
    void generateReproductionScript(const CrashInfo& crash);
    void generateGdbScript(const CrashInfo& crash);
    void generateValgrindScript(const CrashInfo& crash);
    
    // 分析功能
    std::string categorizeCrash(const CrashInfo& crash);
    std::string assessExploitability(const CrashInfo& crash);
    bool isUniqueCrash(const CrashInfo& crash);
    
    // 安全分析
    std::string checkForKnownCVEs(const CrashInfo& crash);
    std::string analyzeSecurityImpact(const CrashInfo& crash);
    
private:
    EnhancedCrashTracker() = default;
    ~EnhancedCrashTracker() = default;
    
    // 禁止复制和赋值
    EnhancedCrashTracker(const EnhancedCrashTracker&) = delete;
    EnhancedCrashTracker& operator=(const EnhancedCrashTracker&) = delete;
    
    // 数据收集辅助函数
    std::vector<std::string> getStackTrace(void* context);
    std::string symbolizeAddress(void* addr);
    std::string getMemoryMaps();
    std::string getRegistersDump(void* context);
    std::vector<std::string> getLoadedLibraries();
    std::string getBuildInformation();
    
    // 输入数据管理
    std::string saveInputToFile(const std::vector<uint8_t>& input);
    std::string calculateInputHash(const std::vector<uint8_t>& input);
    
    // 环境信息收集
    std::map<std::string, std::string> getEnvironmentVariables();
    std::string getSystemInformation();
    
    // 安全的输入数据访问
    std::vector<uint8_t> getCurrentInputSafe() const;
    std::string getCurrentInputFileSafe() const;
    
    // 成员变量
    std::vector<uint8_t> current_input_;
    std::string current_input_file_;
    std::vector<std::string> command_line_args_;
    std::string binary_path_;
    std::string working_directory_;
    std::vector<CrashInfo> crash_history_;
    std::string output_directory_;
    
    // 线程同步
    mutable std::mutex input_mutex_;
    mutable std::mutex history_mutex_;
    mutable std::mutex shutdown_mutex_;
    
    // 状态标志
    std::atomic<bool> shutting_down_{false};
    std::atomic<bool> in_signal_handler_{false};
    
    // 信号处理相关
    struct sigaction old_sigaction_[32];
    bool initialized_{false};
};

// 便利的宏定义
#define CRASH_TRACKER_INIT() \
    collafuzz::crash_tracker::EnhancedCrashTracker::getInstance().initialize()

#define CRASH_TRACKER_SET_INPUT(input) \
    collafuzz::crash_tracker::EnhancedCrashTracker::getInstance().setCurrentInput(input)

#define CRASH_TRACKER_SET_INPUT_FILE(file) \
    collafuzz::crash_tracker::EnhancedCrashTracker::getInstance().setCurrentInputFile(file)

#define CRASH_TRACKER_SET_ARGS(argc, argv) \
    collafuzz::crash_tracker::EnhancedCrashTracker::getInstance().setCommandLineArgs(argc, argv)

} // namespace crash_tracker
} // namespace collafuzz

#endif // ENHANCED_CRASH_TRACKER_H 