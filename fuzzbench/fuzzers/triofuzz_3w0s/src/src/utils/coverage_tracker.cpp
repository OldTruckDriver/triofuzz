#include "../../include/utils/coverage_tracker.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <regex>
#include <thread>
#include <signal.h> // For signal handling
#include <pthread.h> // For pthread_sigmask
#include <unistd.h> // For getpid()

// LLVM运行时函数声明 - 用于强制写入profile数据
// 使用弱符号，如果不可用则返回NULL
extern "C" {
    int __llvm_profile_write_file(void) __attribute__((weak));
}

namespace triofuzz {

CoverageTracker::CoverageTracker(const Config& config) : config_(config) {
    // 确保输出目录存在
    std::filesystem::create_directories(config_.output_dir);

    // Generate unique profraw name if enabled
    if (config_.use_unique_profraw_name) {
        unique_profraw_name_ = generateUniqueProfrawName();
    }
}

std::string CoverageTracker::generateUniqueProfrawName() const {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    pid_t pid = getpid();

    std::ostringstream ss;
    ss << "coverage_" << timestamp << "_" << pid << ".profraw";
    return ss.str();
}

CoverageTracker::~CoverageTracker() {
    if (is_running_) {
        stop();
    }
}

void CoverageTracker::start() {
    if (!config_.enabled) return;

    std::lock_guard<std::mutex> lock(data_mutex_);
    start_time_ = std::chrono::system_clock::now();
    last_record_time_ = start_time_;
    is_running_ = true;
    coverage_records_.clear();

    // 设置 LLVM_PROFILE_FILE 环境变量
    // Use unique name if configured, otherwise use the pattern
    std::string profraw_name = config_.use_unique_profraw_name ? unique_profraw_name_ : config_.profraw_pattern;
    std::string profile_file = config_.output_dir + "/" + profraw_name;
    if (setenv("LLVM_PROFILE_FILE", profile_file.c_str(), 1) != 0) {
        std::cerr << "[CoverageTracker] Failed to set LLVM_PROFILE_FILE environment variable" << std::endl;
        return;
    }

    // 启动定时记录线程
    recording_active_ = true;
    recording_thread_ = std::thread(&CoverageTracker::recordingLoop, this);

    // 立即创建CSV文件头部，即使没有数据
    // Check if CSV already exists (for crash recovery - append mode)
    bool csv_exists = std::filesystem::exists(getDataFilePath());
    if (!csv_exists) {
        createCSVHeader();
    } else {
        std::cout << "[CoverageTracker] CSV file exists, will append new records" << std::endl;
    }

    std::cout << "[CoverageTracker] Started LLVM coverage tracking" << std::endl;
    std::cout << "[CoverageTracker] Output directory: " << config_.output_dir << std::endl;
    std::cout << "[CoverageTracker] Recording interval: " << config_.recording_interval.count() << " seconds" << std::endl;
    std::cout << "[CoverageTracker] LLVM_PROFILE_FILE: " << profile_file << std::endl;
    if (config_.merge_all_profraw) {
        std::cout << "[CoverageTracker] Merge all profraw: ENABLED (crash recovery mode)" << std::endl;
    }
    if (csv_exists) {
        std::cout << "[CoverageTracker] Appending to existing CSV: " << getDataFilePath() << std::endl;
    } else {
        std::cout << "[CoverageTracker] CSV file initialized: " << getDataFilePath() << std::endl;
    }
}

void CoverageTracker::stop() {
    if (!config_.enabled || !is_running_) return;
    
    std::cout << "[CoverageTracker] Stopping LLVM coverage tracking..." << std::endl;
    
    is_running_ = false;
    recording_active_ = false;
    recording_cv_.notify_all();
    
    // 等待记录线程结束
    if (recording_thread_.joinable()) {
        std::cout << "[CoverageTracker] Waiting for recording thread to finish..." << std::endl;
        recording_thread_.join();
    }
    
    // 记录最终的覆盖率数据
    std::cout << "[CoverageTracker] Recording final coverage data..." << std::endl;
    recordCurrentCoverage();
    
    std::cout << "[CoverageTracker] ✓ Final coverage data recorded and exported successfully" << std::endl;
    
    std::cout << "[CoverageTracker] Coverage tracking completed. Data saved to " << getDataFilePath() << std::endl;
}

void CoverageTracker::recordCurrentCoverage() {
    if (!config_.enabled) return;
    
    LLVMCoverageData data;
    bool csv_success = false;
    
    {
        std::lock_guard<std::mutex> lock(data_mutex_);
        
        auto current_time = std::chrono::system_clock::now();
        
        // 强制写入LLVM profile数据到磁盘
        if (__llvm_profile_write_file != nullptr) {
            if (__llvm_profile_write_file() != 0) {
                std::cout << "[CoverageTracker] Warning: Failed to force write profile data" << std::endl;
            } else {
                std::cout << "[CoverageTracker] Successfully forced profile data write" << std::endl;
            }
        } else {
            std::cout << "[CoverageTracker] LLVM profile write function not available, relying on automatic writes" << std::endl;
        }
        
        // 添加短暂延迟确保文件系统写入完成
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // 合并 profraw 文件
        // Use mergeAllProfrawFiles if crash recovery mode is enabled
        bool merge_success = false;
        if (config_.merge_all_profraw) {
            merge_success = mergeAllProfrawFiles();
        } else {
            merge_success = mergeProfrawFiles();
        }

        if (!merge_success) {
            std::cerr << "[CoverageTracker] Failed to merge profraw files" << std::endl;
            // 仍然更新last_record_time_以避免无限循环
            last_record_time_ = current_time;
            return;
        }
        
        // 提取覆盖率数据
        data = extractCoverageData();
        if (data.regions == 0 && data.functions == 0 && data.lines == 0) {
            std::cout << "[CoverageTracker] Warning: No coverage data extracted (profraw files may be empty or not yet written)" << std::endl;
            // 不直接返回，而是记录一个空数据点，这样可以看到时间进展
            data.experiment_name = config_.experiment_name;
            data.time_started = start_time_;
            data.time_ended = current_time;
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(data.time_ended - start_time_);
            data.time_seconds = static_cast<double>(duration.count());
        }
        
        coverage_records_.push_back(data);
        last_record_time_ = data.time_ended;
        
        std::cout << "[CoverageTracker] Recorded coverage (#" << coverage_records_.size() << "): " 
                  << std::fixed << std::setprecision(2)
                  << "Regions: " << data.region_cover << "% (" << data.regions - data.missed_regions << "/" << data.regions << "), "
                  << "Functions: " << data.function_executed << "% (" << data.functions - data.missed_functions << "/" << data.functions << "), "
                  << "Lines: " << data.line_cover << "% (" << data.lines - data.missed_lines << "/" << data.lines << "), "
                  << "Branches: " << data.branch_cover << "% (" << data.branches - data.missed_branches << "/" << data.branches << "), "
                  << "Time: " << std::fixed << std::setprecision(1) << (data.time_seconds / 60.0) << "min"
                  << std::endl;
        
        std::cout << "[CoverageTracker] DEBUG: About to call exportToCSV, records count: " << coverage_records_.size() << std::endl;
        std::cout.flush(); // 强制刷新输出缓冲区
    } // 释放互斥锁
    
    // 在CSV写入过程中暂时屏蔽信号
    sigset_t old_mask, new_mask;
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);
    
    // 立即保存CSV文件（每次记录后都保存）
    csv_success = exportToCSV();
    
    // 恢复信号处理
    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
    
    if (!csv_success) {
        std::cerr << "[CoverageTracker] Warning: Failed to save CSV after recording" << std::endl;
    } else {
        std::cout << "[CoverageTracker] DEBUG: exportToCSV completed successfully" << std::endl;
    }
    
    // 强制同步文件系统
    std::system("sync");
    std::cout << "[CoverageTracker] DEBUG: File system sync completed" << std::endl;
}

std::string CoverageTracker::getDataFilePath() const {
    return config_.output_dir + "/" + config_.data_file;
}

std::string CoverageTracker::getProfrawPath() const {
    return config_.output_dir + "/" + config_.profraw_pattern;
}

std::string CoverageTracker::getProfdataPath() const {
    return config_.output_dir + "/" + config_.profdata_file;
}

bool CoverageTracker::mergeProfrawFiles() {
    // 构建 llvm-profdata merge 命令
    std::string profraw_path = getProfrawPath();
    std::string profdata_path = getProfdataPath();
    
    // 首先检查是否有profraw文件
    std::string check_command = "ls " + profraw_path + " 2>/dev/null | wc -l";
    FILE* check_pipe = popen(check_command.c_str(), "r");
    if (!check_pipe) {
        std::cerr << "[CoverageTracker] Failed to check for profraw files" << std::endl;
        return false;
    }
    
    char count_str[32];
    fgets(count_str, sizeof(count_str), check_pipe);
    pclose(check_pipe);
    
    int file_count = std::atoi(count_str);
    if (file_count == 0) {
        std::cout << "[CoverageTracker] No profraw files found yet (pattern: " << profraw_path << ")" << std::endl;
        return false;
    }
    
    // 检查profraw文件是否不为空
    std::string size_check = "find " + config_.output_dir + " -name '*.profraw' -size +0c | wc -l";
    FILE* size_pipe = popen(size_check.c_str(), "r");
    if (size_pipe) {
        char size_count_str[32];
        fgets(size_count_str, sizeof(size_count_str), size_pipe);
        pclose(size_pipe);
        
        int non_empty_count = std::atoi(size_count_str);
        if (non_empty_count == 0) {
            std::cout << "[CoverageTracker] Found " << file_count << " profraw files but all are empty" << std::endl;
            return false;
        }
        
        std::cout << "[CoverageTracker] Found " << file_count << " profraw file(s) (" << non_empty_count << " non-empty), merging..." << std::endl;
    } else {
        std::cout << "[CoverageTracker] Found " << file_count << " profraw file(s), merging..." << std::endl;
    }
    
    std::string command = "llvm-profdata merge -sparse " + profraw_path + " -o " + profdata_path + " 2>&1";
    
    // 执行命令并捕获输出
    FILE* cmd_pipe = popen(command.c_str(), "r");
    if (!cmd_pipe) {
        // 尝试备用命令路径
        command = "/usr/bin/llvm-profdata merge -sparse " + profraw_path + " -o " + profdata_path + " 2>&1";
        cmd_pipe = popen(command.c_str(), "r");
        
        if (!cmd_pipe) {
            std::cerr << "[CoverageTracker] Failed to execute llvm-profdata command" << std::endl;
            return false;
        }
    }
    
    // 读取命令输出
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), cmd_pipe) != nullptr) {
        output += buffer;
    }
    
    int result = pclose(cmd_pipe);
    if (result != 0) {
        std::cerr << "[CoverageTracker] llvm-profdata command failed with exit code: " << result << std::endl;
        std::cerr << "[CoverageTracker] Command output: " << output << std::endl;
        std::cerr << "[CoverageTracker] Command was: " << command << std::endl;
        return false;
    }
    
    // 验证输出文件是否创建成功
    if (!std::filesystem::exists(profdata_path)) {
        std::cerr << "[CoverageTracker] Failed to create profdata file: " << profdata_path << std::endl;
        return false;
    }
    
    std::cout << "[CoverageTracker] Successfully merged profraw files into " << profdata_path << std::endl;
    return true;
}

bool CoverageTracker::mergeAllProfrawFiles() {
    // Merge ALL *.profraw files in output_dir (for crash recovery)
    // This ensures coverage from previous runs is accumulated
    std::string profdata_path = getProfdataPath();

    // Find all profraw files in output directory
    std::vector<std::string> profraw_files;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(config_.output_dir)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename.size() > 8 && filename.substr(filename.size() - 8) == ".profraw") {
                    // Check if file is non-empty
                    if (std::filesystem::file_size(entry.path()) > 0) {
                        profraw_files.push_back(entry.path().string());
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[CoverageTracker] Error scanning for profraw files: " << e.what() << std::endl;
        return false;
    }

    if (profraw_files.empty()) {
        std::cout << "[CoverageTracker] No profraw files found in " << config_.output_dir << std::endl;
        return false;
    }

    std::cout << "[CoverageTracker] Found " << profraw_files.size()
              << " profraw file(s) to merge (crash recovery mode)" << std::endl;

    // Build merge command with all files
    std::ostringstream cmd_ss;
    cmd_ss << "llvm-profdata merge -sparse";
    for (const auto& file : profraw_files) {
        cmd_ss << " \"" << file << "\"";
    }
    cmd_ss << " -o \"" << profdata_path << "\" 2>&1";

    std::string command = cmd_ss.str();

    // Execute merge command
    FILE* cmd_pipe = popen(command.c_str(), "r");
    if (!cmd_pipe) {
        // Try with full path
        cmd_ss.str("");
        cmd_ss << "/usr/bin/llvm-profdata merge -sparse";
        for (const auto& file : profraw_files) {
            cmd_ss << " \"" << file << "\"";
        }
        cmd_ss << " -o \"" << profdata_path << "\" 2>&1";
        command = cmd_ss.str();
        cmd_pipe = popen(command.c_str(), "r");

        if (!cmd_pipe) {
            std::cerr << "[CoverageTracker] Failed to execute llvm-profdata command" << std::endl;
            return false;
        }
    }

    // Read command output
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), cmd_pipe) != nullptr) {
        output += buffer;
    }

    int result = pclose(cmd_pipe);
    if (result != 0) {
        std::cerr << "[CoverageTracker] llvm-profdata merge failed with exit code: " << result << std::endl;
        std::cerr << "[CoverageTracker] Command output: " << output << std::endl;
        return false;
    }

    // Verify output file
    if (!std::filesystem::exists(profdata_path)) {
        std::cerr << "[CoverageTracker] Failed to create profdata file: " << profdata_path << std::endl;
        return false;
    }

    std::cout << "[CoverageTracker] Successfully merged " << profraw_files.size()
              << " profraw files into " << profdata_path << std::endl;
    return true;
}

LLVMCoverageData CoverageTracker::extractCoverageData() {
    LLVMCoverageData data;
    data.experiment_name = config_.experiment_name;
    data.time_started = start_time_;
    data.time_ended = std::chrono::system_clock::now();
    
    // 计算时间间隔（秒）
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(data.time_ended - data.time_started);
    data.time_seconds = static_cast<double>(duration.count());
    
    // 构建 llvm-cov report 命令
    std::string profdata_path = getProfdataPath();
    std::string target_binary = config_.target_binary;
    
    if (target_binary.empty()) {
        std::cerr << "[CoverageTracker] Target binary not specified for llvm-cov" << std::endl;
        return data;
    }
    
    std::string command = "llvm-cov report " + target_binary + " -instr-profile=" + profdata_path + " 2>/dev/null";
    
    // 执行命令并捕获输出
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        // 尝试备用命令路径
        command = "/usr/bin/llvm-cov report " + target_binary + " -instr-profile=" + profdata_path + " 2>/dev/null";
        pipe = std::unique_ptr<FILE, decltype(&pclose)>(popen(command.c_str(), "r"), pclose);
        
        if (!pipe) {
            std::cerr << "[CoverageTracker] Failed to execute llvm-cov command" << std::endl;
            return data;
        }
    }
    
    // 读取命令输出
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        output += buffer;
    }
    
    // 添加调试输出
    std::cout << "[CoverageTracker] DEBUG: llvm-cov command output:" << std::endl;
    std::cout << "--- OUTPUT START ---" << std::endl;
    std::cout << output << std::endl;
    std::cout << "--- OUTPUT END ---" << std::endl;
    
    // 解析输出
    return parseLLVMCovOutput(output);
}

LLVMCoverageData CoverageTracker::parseLLVMCovOutput(const std::string& output) {
    LLVMCoverageData data;
    data.experiment_name = config_.experiment_name;
    data.time_started = start_time_;
    data.time_ended = std::chrono::system_clock::now();
    
    // 计算时间间隔（秒）
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(data.time_ended - data.time_started);
    data.time_seconds = static_cast<double>(duration.count());
    
    std::istringstream stream(output);
    std::string line;
    bool found_total = false;
    
    // 查找 TOTAL 行，它包含汇总的覆盖率信息
    // 格式通常类似：TOTAL    123    45    63.41%    89    12    86.52%    234    67    71.37%    456    123    73.03%
    while (std::getline(stream, line)) {
        if (line.find("TOTAL") != std::string::npos) {
            found_total = true;
            
            // 使用正则表达式解析TOTAL行
            // 期望格式：TOTAL regions missed_regions region_cover% functions missed_functions function_cover% lines missed_lines line_cover% branches missed_branches branch_cover%
            std::regex total_regex(R"(TOTAL\s+(\d+)\s+(\d+)\s+([\d.]+)%\s+(\d+)\s+(\d+)\s+([\d.]+)%\s+(\d+)\s+(\d+)\s+([\d.]+)%(?:\s+(\d+)\s+(\d+)\s+([\d.]+)%)?)", 
                                 std::regex_constants::icase);
            std::smatch match;
            
            if (std::regex_search(line, match, total_regex)) {
                // Regions (第1-3个匹配组)
                data.regions = std::stoull(match[1].str());
                data.missed_regions = std::stoull(match[2].str());
                data.region_cover = std::stod(match[3].str());
                
                // Functions (第4-6个匹配组)
                data.functions = std::stoull(match[4].str());
                data.missed_functions = std::stoull(match[5].str());
                data.function_executed = std::stod(match[6].str());
                
                // Lines (第7-9个匹配组)
                data.lines = std::stoull(match[7].str());
                data.missed_lines = std::stoull(match[8].str());
                data.line_cover = std::stod(match[9].str());
                
                // Branches (第10-12个匹配组，可选)
                if (match[10].matched) {
                    data.branches = std::stoull(match[10].str());
                    data.missed_branches = std::stoull(match[11].str());
                    data.branch_cover = std::stod(match[12].str());
                }
                
                break;
            } else {
                // 尝试简化的解析方式
                std::istringstream line_stream(line);
                std::string token;
                std::vector<std::string> tokens;
                
                while (line_stream >> token) {
                    tokens.push_back(token);
                }
                
                // 至少需要10个token才能包含基本的region、function、line信息
                if (tokens.size() >= 10) {
                    try {
                        data.regions = std::stoull(tokens[1]);
                        data.missed_regions = std::stoull(tokens[2]);
                        data.region_cover = std::stod(tokens[3].substr(0, tokens[3].length() - 1)); // 移除%号
                        
                        data.functions = std::stoull(tokens[4]);
                        data.missed_functions = std::stoull(tokens[5]);
                        data.function_executed = std::stod(tokens[6].substr(0, tokens[6].length() - 1));
                        
                        data.lines = std::stoull(tokens[7]);
                        data.missed_lines = std::stoull(tokens[8]);
                        data.line_cover = std::stod(tokens[9].substr(0, tokens[9].length() - 1));
                        
                        // 如果有分支信息
                        if (tokens.size() >= 13) {
                            data.branches = std::stoull(tokens[10]);
                            data.missed_branches = std::stoull(tokens[11]);
                            data.branch_cover = std::stod(tokens[12].substr(0, tokens[12].length() - 1));
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "[CoverageTracker] Error parsing TOTAL line: " << e.what() << std::endl;
                    }
                }
            }
            break;
        }
    }
    
    if (!found_total) {
        std::cout << "[CoverageTracker] Could not find TOTAL line in llvm-cov output" << std::endl;
        std::cout << "[CoverageTracker] DEBUG: Trying to parse each line individually..." << std::endl;
        
        // 尝试从最后几行中找到汇总数据
        std::istringstream stream2(output);
        std::string line2;
        std::vector<std::string> all_lines;
        while (std::getline(stream2, line2)) {
            all_lines.push_back(line2);
        }
        
        // 检查最后几行是否包含汇总信息
        for (int i = std::max(0, (int)all_lines.size() - 5); i < (int)all_lines.size(); ++i) {
            std::cout << "[CoverageTracker] Line " << i << ": '" << all_lines[i] << "'" << std::endl;
            
            // 检查是否包含数字和百分号
            if (all_lines[i].find('%') != std::string::npos && 
                all_lines[i].find_first_of("0123456789") != std::string::npos) {
                
                std::cout << "[CoverageTracker] Attempting to parse line: " << all_lines[i] << std::endl;
                
                // 尝试简单的token解析
                std::istringstream line_stream(all_lines[i]);
                std::string token;
                std::vector<std::string> tokens;
                
                while (line_stream >> token) {
                    tokens.push_back(token);
                }
                
                if (tokens.size() >= 10) {
                    std::cout << "[CoverageTracker] Found " << tokens.size() << " tokens:" << std::endl;
                    for (size_t j = 0; j < tokens.size(); ++j) {
                        std::cout << "  [" << j << "] = '" << tokens[j] << "'" << std::endl;
                    }
                    
                    try {
                        // 尝试解析数据
                        data.regions = std::stoull(tokens[1]);
                        data.missed_regions = std::stoull(tokens[2]);
                        data.region_cover = std::stod(tokens[3].substr(0, tokens[3].length() - 1));
                        
                        data.functions = std::stoull(tokens[4]);
                        data.missed_functions = std::stoull(tokens[5]);
                        data.function_executed = std::stod(tokens[6].substr(0, tokens[6].length() - 1));
                        
                        data.lines = std::stoull(tokens[7]);
                        data.missed_lines = std::stoull(tokens[8]);
                        data.line_cover = std::stod(tokens[9].substr(0, tokens[9].length() - 1));
                        
                        if (tokens.size() >= 13) {
                            data.branches = std::stoull(tokens[10]);
                            data.missed_branches = std::stoull(tokens[11]);
                            data.branch_cover = std::stod(tokens[12].substr(0, tokens[12].length() - 1));
                        }
                        
                        std::cout << "[CoverageTracker] Successfully parsed alternative format!" << std::endl;
                        found_total = true;
                        break;
                        
                    } catch (const std::exception& e) {
                        std::cout << "[CoverageTracker] Parse error for line: " << e.what() << std::endl;
                    }
                }
            }
        }
        
        if (!found_total) {
            std::cout << "[CoverageTracker] Still could not parse coverage data" << std::endl;
        }
    }
    
    return data;
}

void CoverageTracker::createCSVHeader() {
    std::string file_path = getDataFilePath();
    std::ofstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "[CoverageTracker] Failed to create CSV header file: " << file_path << std::endl;
        return;
    }
    
    // 写入CSV头部
    file << "experiment_name,time_started,time_ended,regions,missed_regions,region_cover,"
         << "functions,missed_functions,function_executed,lines,missed_lines,line_cover,"
         << "branches,missed_branches,branch_cover,time_seconds,time_interval\n";
    
    file.close();
    std::cout << "[CoverageTracker] CSV header created: " << file_path << std::endl;
}

bool CoverageTracker::exportToCSV() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    if (coverage_records_.empty()) {
        return false;
    }
    
    std::string file_path = getDataFilePath();
    
    // 直接以追加模式打开文件（文件应该已经存在且有header）
    std::ofstream file(file_path, std::ios::app);
    if (!file.is_open()) {
        return false;
    }
    
    // 只写入最新的记录（最后一个）
    const auto& record = coverage_records_.back();
    
    // 快速时间格式化
    auto start_time_t = std::chrono::system_clock::to_time_t(record.time_started);
    auto end_time_t = std::chrono::system_clock::to_time_t(record.time_ended);
    
    char start_time_str[32], end_time_str[32];
    std::strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&start_time_t));
    std::strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&end_time_t));
    
    // 一次性写入整行
    file << record.experiment_name << ","
         << start_time_str << ","
         << end_time_str << ","
         << record.regions << ","
         << record.missed_regions << ","
         << std::fixed << std::setprecision(2) << record.region_cover << ","
         << record.functions << ","
         << record.missed_functions << ","
         << std::fixed << std::setprecision(2) << record.function_executed << ","
         << record.lines << ","
         << record.missed_lines << ","
         << std::fixed << std::setprecision(2) << record.line_cover << ","
         << record.branches << ","
         << record.missed_branches << ","
         << std::fixed << std::setprecision(2) << record.branch_cover << ","
         << std::fixed << std::setprecision(1) << record.time_seconds << ","
         // Keep minutes for backward compatibility in consumers.
         << std::fixed << std::setprecision(1) << (record.time_seconds / 60.0) << "\n";
    
    // 立即强制写入
    file.flush();
    file.close();
    
    return true;
}

void CoverageTracker::recordingLoop() {
    std::cout << "[CoverageTracker] DEBUG: Recording loop started" << std::endl;
    
    while (true) {
        std::cout << "[CoverageTracker] DEBUG: Recording loop iteration, recording_active=" << recording_active_.load() << std::endl;
        
        if (!recording_active_) {
            std::cout << "[CoverageTracker] DEBUG: Recording inactive at loop entry, breaking loop" << std::endl;
            break;
        }
        
        // 等待记录间隔（秒）
        std::chrono::system_clock::time_point wait_until;
        {
            std::lock_guard<std::mutex> lock(data_mutex_);
            wait_until = last_record_time_ + config_.recording_interval;
        }
        auto now = std::chrono::system_clock::now();
        
        auto time_to_wait = std::chrono::duration_cast<std::chrono::seconds>(wait_until - now);
        std::cout << "[CoverageTracker] DEBUG: Time to wait: " << time_to_wait.count() << " seconds" << std::endl;
        
        bool should_stop = false;
        if (now < wait_until) {
            std::cout << "[CoverageTracker] DEBUG: Sleeping until next recording time..." << std::endl;
            std::unique_lock<std::mutex> wait_lock(recording_mutex_);
            if (recording_cv_.wait_until(wait_lock, wait_until, [this]() { return !recording_active_.load(); })) {
                should_stop = true;
            }
            std::cout << "[CoverageTracker] DEBUG: Woke up from sleep" << std::endl;
        }
        
        // 检查是否仍然活跃
        if (!recording_active_ || should_stop) {
            std::cout << "[CoverageTracker] DEBUG: Recording no longer active, breaking loop" << std::endl;
            break;
        }
        
        std::cout << "[CoverageTracker] DEBUG: About to record current coverage..." << std::endl;
        
        try {
            // 记录当前覆盖率
            recordCurrentCoverage();
            std::cout << "[CoverageTracker] DEBUG: Successfully recorded coverage" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[CoverageTracker] ERROR in recordCurrentCoverage: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[CoverageTracker] UNKNOWN ERROR in recordCurrentCoverage" << std::endl;
        }
    }
    
    std::cout << "[CoverageTracker] DEBUG: Recording loop ended" << std::endl;
}

} // namespace triofuzz 
