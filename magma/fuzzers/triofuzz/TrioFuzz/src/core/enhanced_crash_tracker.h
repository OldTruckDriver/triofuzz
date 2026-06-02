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

// Enhanced crash information structure
struct CrashInfo {
    // Basic information
    int signal_number;
    std::string signal_name;
    time_t timestamp;
    pid_t process_id;
    std::string binary_path;
    
    // Fault details
    void* fault_address;
    std::string fault_type;
    void* instruction_pointer;
    std::string crash_description;
    
    // Input data
    std::vector<uint8_t> crash_input;
    std::string input_hash;
    size_t input_size;
    
    // Stack trace
    std::vector<std::string> stack_trace;
    std::vector<void*> stack_addresses;
    std::string symbolized_trace;
    
    // System environment
    std::vector<std::string> command_line_args;
    std::map<std::string, std::string> environment_vars;
    std::string working_directory;
    
    // Memory information
    std::string memory_maps;
    std::string registers_dump;
    std::vector<std::string> loaded_libraries;
    
    // Build information
    std::string build_version;
    std::string build_flags;
    std::string compiler_version;
    std::string commit_hash;
    
    // Reproduction information
    std::string reproduction_command;
    std::string reproduction_script;
    std::string gdb_commands;
    
    // Classification and priority
    std::string crash_category;
    std::string exploitability;
    int severity_score;
    bool is_unique_crash;
    
    // CVE-related
    std::string potential_cve;
    std::string security_impact;
    std::vector<std::string> related_vulnerabilities;
};

// Enhanced crash tracker class
class EnhancedCrashTracker {
public:
    static EnhancedCrashTracker& getInstance();
    
    // Initialize crash tracker
    void initialize();
    
    // Safe shutdown and cleanup
    void shutdown();
    bool isShuttingDown() const;
    
    // Set current input data
    void setCurrentInput(const std::vector<uint8_t>& input);
    void setCurrentInputFile(const std::string& file_path);
    
    // Set runtime environment
    void setCommandLineArgs(int argc, char* argv[]);
    void setBinaryPath(const std::string& path);
    void setWorkingDirectory(const std::string& dir);
    
    // Crash handling
    void handleCrash(int signal, siginfo_t* info, void* context);
    
    // Generate crash report
    std::string generateCrashReport(const CrashInfo& crash);
    void saveCrashReport(const CrashInfo& crash);
    
    // Generate reproduction helpers
    void generateReproductionScript(const CrashInfo& crash);
    void generateGdbScript(const CrashInfo& crash);
    void generateValgrindScript(const CrashInfo& crash);
    
    // Analysis
    std::string categorizeCrash(const CrashInfo& crash);
    std::string assessExploitability(const CrashInfo& crash);
    bool isUniqueCrash(const CrashInfo& crash);
    
    // Security analysis
    std::string checkForKnownCVEs(const CrashInfo& crash);
    std::string analyzeSecurityImpact(const CrashInfo& crash);
    
private:
    EnhancedCrashTracker() = default;
    ~EnhancedCrashTracker() = default;
    
    // Disable copy and assignment
    EnhancedCrashTracker(const EnhancedCrashTracker&) = delete;
    EnhancedCrashTracker& operator=(const EnhancedCrashTracker&) = delete;
    
    // Data collection helper functions
    std::vector<std::string> getStackTrace(void* context);
    std::string symbolizeAddress(void* addr);
    std::string getMemoryMaps();
    std::string getRegistersDump(void* context);
    std::vector<std::string> getLoadedLibraries();
    std::string getBuildInformation();
    
    // Input data management
    std::string saveInputToFile(const std::vector<uint8_t>& input);
    std::string calculateInputHash(const std::vector<uint8_t>& input);
    
    // Environment information collection
    std::map<std::string, std::string> getEnvironmentVariables();
    std::string getSystemInformation();
    
    // Safe access to current input
    std::vector<uint8_t> getCurrentInputSafe() const;
    std::string getCurrentInputFileSafe() const;
    
    // Member variables
    std::vector<uint8_t> current_input_;
    std::string current_input_file_;
    std::vector<std::string> command_line_args_;
    std::string binary_path_;
    std::string working_directory_;
    std::vector<CrashInfo> crash_history_;
    std::string output_directory_;
    
    // Thread synchronization
    mutable std::mutex input_mutex_;
    mutable std::mutex history_mutex_;
    mutable std::mutex shutdown_mutex_;
    
    // Status flags
    std::atomic<bool> shutting_down_{false};
    std::atomic<bool> in_signal_handler_{false};
    
    // Signal handling
    struct sigaction old_sigaction_[32];
    bool initialized_{false};
};

// Convenience macros
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
