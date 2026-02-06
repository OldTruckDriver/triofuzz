#pragma once

#include "../core/algorithm.hpp"
#include "../core/engine.hpp"
#include "../utils/performance_monitor.hpp"
#include <chrono>
#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <cmath>
#include <cstdlib>
#include <optional>
#include <random>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include <algorithm>
#include <unordered_map>
#include <functional>
#include <iomanip>
#include <set>
#include <array>
#include <numeric>

namespace triofuzz {

// 改进的种子哈希函数
class SeedHasher {
public:
    static uint64_t computeHash(const std::vector<uint8_t>& data) {
        // 使用xxHash或类似的强哈希算法
        uint64_t hash = 0x9e3779b97f4a7c15ULL; // 黄金比例常数
        
        for (size_t i = 0; i < data.size(); ++i) {
            hash ^= static_cast<uint64_t>(data[i]) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        
        // 添加长度信息防止不同长度的相同前缀产生冲突
        hash ^= static_cast<uint64_t>(data.size()) << 32;
        
        return hash;
    }
    
    static bool areEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
    }
};

// CorpusManager类实现
class CorpusManager {
public:
    // 配置结构
    struct Config {
        size_t max_corpus_size = 10000;
        std::string corpus_dir = "./corpus";
        std::string crash_dir = "./crashes";
        bool enable_minimization = true;
        bool enable_prioritization = true;
        bool enable_deduplication = true;  // 新增去重开关
        double energy_update_rate = 0.1;
        size_t max_seed_size = 2048 * 2048; // 1MB max seed size
        bool enable_lifecycle_management = true;
        
        // 新增 AFL++ 风格的 corpus 优化配置
        bool enable_auto_optimization = true;           // 启用自动优化
        size_t optimization_interval_seconds = 60;      // 1分钟优化一次（改进：从5分钟缩短）
        double corpus_bloat_threshold = 0.5;            // corpus 膨胀阈值（50%）（改进：从80%降低）
        size_t min_corpus_size = 100;                   // 最小保留种子数
        size_t target_corpus_size = 5000;               // 目标 corpus 大小
        bool enable_coverage_based_optimization = true; // 基于覆盖率的优化
        double performance_degradation_threshold = 0.1; // 性能下降10%时触发优化（改进：从30%降低）
        bool enable_aggressive_cleanup = false;         // 激进清理模式
        size_t max_daily_corpus_growth = 2000;         // 每日最大 corpus 增长
    };

    CorpusManager() = default;
    
    ~CorpusManager() {
        saveCorpus();
    }
    
    // 添加种子
    void addSeed(Seed seed) {
        // Saving to disk can be slow and should not block other threads that
        // need corpus access. Decide what to save under lock, but perform the
        // actual file I/O after releasing the corpus lock.
        Seed seed_to_save;
        bool should_save_to_disk = false;
        static bool enable_disk_save = std::getenv("triofuzz_DISABLE_DISK_SAVE") == nullptr;

        try {
            std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
            
            // 验证种子数据完整性
            if (seed.data.empty()) {
                std::cerr << "[WARNING] Attempting to add empty seed, skipping" << std::endl;
                return;
            }
            
            // 限制种子大小
            if (seed.data.size() > config_.max_seed_size) {
                std::cerr << "[WARNING] Seed too large (" << seed.data.size() 
                         << " bytes), truncating to " << config_.max_seed_size << " bytes" << std::endl;
                seed.data.resize(config_.max_seed_size);
            }
            
            // 改进的去重检查（优化：使用hash索引加速）
            if (config_.enable_deduplication) {
                uint64_t seed_hash = SeedHasher::computeHash(seed.data);
                seed.data_hash = seed_hash;
                
                // 检查哈希是否已存在（处理潜在碰撞）
                auto range = hash_to_indices_.equal_range(seed_hash);
                bool is_duplicate = false;
                
                // 遍历所有具有相同hash的种子
                for (auto it = range.first; it != range.second; ++it) {
                    size_t idx = it->second;
                    if (idx < corpus_.size() && 
                        SeedHasher::areEqual(corpus_[idx].data, seed.data)) {
                        // 确实是重复种子，更新能量和覆盖率
                        corpus_[idx].energy = std::max(corpus_[idx].energy, seed.energy);
                        // 合并覆盖率信息
                        if (seed.coverage.hasNewCoverage()) {
                            corpus_[idx].coverage.merge(seed.coverage);
                        }
                        is_duplicate = true;
                        break;
                    }
                }
                
                if (!is_duplicate) {
                    // 添加新的哈希值和索引
                    seed_hashes_.insert(seed_hash);
                    hash_to_indices_.insert({seed_hash, corpus_.size()});  // 将要添加到末尾
                } else {
                    return;
                }
            }

            if (seed.data_hash == 0) {
                seed.data_hash = SeedHasher::computeHash(seed.data);
            }

            // If deduplication is disabled, still maintain indices for fast lookup.
            if (!config_.enable_deduplication) {
                seed_hashes_.insert(seed.data_hash);
                hash_to_indices_.insert({seed.data_hash, corpus_.size()});  // 将要添加到末尾
            }
            
            // 更新种子统计
            total_seeds_++;
            if (seed.coverage.hasNewCoverage()) {
                interesting_seeds_++;
            }
            
            // 添加到语料库
            corpus_.push_back(std::move(seed));
            
            if (enable_disk_save) {
                const auto& added_seed = corpus_.back();
                // Only persist seeds that actually contribute new coverage to
                // the on-disk corpus. Persisting non-coverage seeds bloats the
                // corpus and hurts both fuzzing throughput and snapshot replay.
                should_save_to_disk = added_seed.coverage.hasNewCoverage();
                if (should_save_to_disk) {
                    seed_to_save = added_seed; // copy outside lock for safe I/O
                }
            }
            
            // 改进的语料库大小管理 - 提前触发优化
            // 当达到90%容量时就开始优化，避免corpus膨胀
            if (corpus_.size() >= config_.max_corpus_size * 0.9 && config_.enable_prioritization) {
                try {
                    // 更激进的清理策略
                    size_t target_size = config_.max_corpus_size * 0.75;  // 清理到75%容量
                    size_t to_remove = corpus_.size() > target_size ? corpus_.size() - target_size : 0;
                    
                    if (to_remove > 0) {
                        removeLowQualitySeedsAdvanced(to_remove);
                        rebuildHashIndex();  // 移除种子后重建索引
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Failed to optimize corpus: " << e.what() << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to add seed to corpus: " << e.what() << std::endl;
            // 回滚统计更新
            if (total_seeds_.load() > 0) {
                total_seeds_--;
            }
        }

        // Perform disk I/O after releasing corpus lock.
        if (enable_disk_save && should_save_to_disk) {
            try {
                saveSingleSeed(seed_to_save);
            } catch (const std::exception&) {
                // Best-effort: don't let save failures impact fuzzing.
            }
        }
    }
    
    // 添加崩溃种子
    void addCrashSeed(Seed seed) {
        try {
            // 验证崩溃种子数据
            if (seed.data.empty()) {
                std::cerr << "[WARNING] Attempting to add empty crash seed, skipping" << std::endl;
                return;
            }
            
            // 智能调整崩溃种子大小
            const size_t max_crash_seed_size = 64 * 1024; // 64KB
            const size_t min_useful_size = 4; // 最小有用大小
            
            if (seed.data.size() > max_crash_seed_size) {
                // 智能截断：保留开头和结尾的重要部分
                std::vector<uint8_t> truncated_data;
                truncated_data.reserve(max_crash_seed_size);
                
                size_t head_size = max_crash_seed_size * 3 / 4; // 75%保留开头
                size_t tail_size = max_crash_seed_size - head_size; // 25%保留结尾
                
                // 复制开头部分
                truncated_data.insert(truncated_data.end(), 
                                    seed.data.begin(), 
                                    seed.data.begin() + head_size);
                
                // 复制结尾部分
                if (seed.data.size() > head_size + tail_size) {
                    truncated_data.insert(truncated_data.end(),
                                        seed.data.end() - tail_size,
                                        seed.data.end());
                }
                
                seed.data = std::move(truncated_data);
                std::cerr << "[INFO] Crash seed truncated intelligently from large size" << std::endl;
            } else if (seed.data.size() < min_useful_size) {
                // 过小的崩溃种子可能不太有用
                std::cerr << "[WARNING] Crash seed too small (" << seed.data.size() 
                         << " bytes), but keeping for analysis" << std::endl;
            }
            
            std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
            
            // 崩溃种子去重检查
            if (config_.enable_deduplication) {
                uint64_t crash_hash = SeedHasher::computeHash(seed.data);
                
                for (const auto& existing_crash : crashes_) {
                    if (SeedHasher::computeHash(existing_crash.data) == crash_hash &&
                        SeedHasher::areEqual(existing_crash.data, seed.data)) {
                        // 重复的崩溃种子，更新元数据但不重复存储
                        return;
                    }
                }
            }
            
            // 智能的崩溃种子容量管理
            const size_t max_crash_seeds = 150; // 适度增加到150
            if (crashes_.size() >= max_crash_seeds) {
                // 按质量移除崩溃种子，而不是简单的FIFO
                removeLowQualityCrashes();
            }
            
            crashes_.push_back(std::move(seed));
            total_crashes_++;
            
            // 保存崩溃（在锁外进行）
            try {
                // 创建副本用于保存，避免引用已移动的对象
                const Seed& crash_ref = crashes_.back();
                lock.unlock(); // 释放锁进行文件操作
                saveCrash(crash_ref);
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to save crash to file: " << e.what() << std::endl;
                // 文件保存失败不影响内存中的存储
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to add crash seed: " << e.what() << std::endl;
            // 回滚统计更新
            if (total_crashes_.load() > 0) {
                total_crashes_--;
            }
        }
    }
    
    // 获取下一个种子 - 性能优化版本
    std::optional<Seed> getNextSeed() {
        // 使用环境变量控制是否使用简单选择
        static bool use_simple_selection = std::getenv("triofuzz_SIMPLE_SELECT") != nullptr;

        // 快速路径：简单轮询，无能量计算
        if (use_simple_selection || !config_.enable_prioritization) {
            std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
            if (corpus_.empty()) {
                return std::nullopt;
            }

            // 使用thread-local索引减少竞争
            thread_local size_t thread_idx = std::hash<std::thread::id>{}(std::this_thread::get_id());
            size_t idx = (thread_idx++) % corpus_.size();
            return corpus_[idx];
        }

        // 慢路径：能量选择
        // 先检查corpus是否为空
        {
            std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
            if (corpus_.empty()) {
                return std::nullopt;
            }
        }

        return selectSeedByEnergy();
    }
    
    // 获取随机种子（用于splice等需要其他种子的变异）
    std::optional<Seed> getRandomSeed() {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        
        if (corpus_.empty()) {
            return std::nullopt;
        }
        
        // 均匀随机选择
        std::uniform_int_distribution<size_t> dist(0, corpus_.size() - 1);
        return corpus_[dist(random_)];
    }
    
    // 更新种子能量（优化：减少锁竞争，批量更新）
    void updateSeedEnergy(const Seed& seed, double new_energy) {
        // 使用try_lock尝试获取锁，避免阻塞
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_, std::defer_lock);

        // 尝试获取锁，如果失败则延迟更新
        if (!lock.try_lock()) {
            // 将更新请求加入队列，稍后批量处理
            // 为了简化，这里直接跳过更新（能量更新不是关键路径）
            return;
        }

        // 使用哈希查找种子（如果启用去重）
        if (config_.enable_deduplication) {
            uint64_t target_hash = SeedHasher::computeHash(seed.data);

            // 使用hash索引快速定位（处理碰撞）
            auto range = hash_to_indices_.equal_range(target_hash);
            for (auto it = range.first; it != range.second; ++it) {
                size_t idx = it->second;
                if (idx < corpus_.size() &&
                    SeedHasher::areEqual(corpus_[idx].data, seed.data)) {
                    // 平滑更新能量
                    corpus_[idx].energy = corpus_[idx].energy * (1.0 - config_.energy_update_rate) +
                                         new_energy * config_.energy_update_rate;
                    // 延迟缓存失效，减少频繁重建
                    // 只在必要时才失效缓存
                    if (std::abs(corpus_[idx].energy - new_energy) > 0.1) {
                        invalidateEnergyCache();
                    }
                    return;
                }
            }
        } else {
            // 回退到原始的逐字节比较
            for (auto& s : corpus_) {
                if (SeedHasher::areEqual(s.data, seed.data)) {
                    double old_energy = s.energy;
                    // 平滑更新能量
                    s.energy = s.energy * (1.0 - config_.energy_update_rate) +
                              new_energy * config_.energy_update_rate;
                    // 只在能量变化较大时才失效缓存
                    if (std::abs(old_energy - s.energy) > 0.1) {
                        invalidateEnergyCache();
                    }
                    break;
                }
            }
        }
    }
    
    // 保存语料库 - 优化版本，只保存重要种子
    void saveCorpus() {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        
        // 创建目录
        std::filesystem::create_directories(config_.corpus_dir);
        
        // 限制保存的种子数量，避免磁盘膨胀
        // 最多保存1000个最重要的种子
        size_t max_to_save = std::min(corpus_.size(), size_t(1000));
        
        // 如果corpus很小，全部保存
        if (corpus_.size() <= 100) {
            size_t idx = 0;
            for (const auto& seed : corpus_) {
                std::string filename = config_.corpus_dir + "/seed_" + 
                                      std::to_string(idx++) + ".bin";
                
                std::ofstream file(filename, std::ios::binary);
                if (file) {
                    file.write(reinterpret_cast<const char*>(seed.data.data()), 
                              seed.data.size());
                }
            }
        } else {
            // corpus很大时，只保存最重要的种子
            std::vector<std::pair<double, size_t>> seed_scores;
            for (size_t i = 0; i < corpus_.size(); ++i) {
                double score = calculateSeedQuality(corpus_[i]);
                seed_scores.emplace_back(score, i);
            }
            
            // 按质量排序
            std::partial_sort(seed_scores.begin(),
                            seed_scores.begin() + max_to_save,
                            seed_scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first > b.first;
                            });
            
            // 保存最好的种子
            for (size_t i = 0; i < max_to_save; ++i) {
                const auto& seed = corpus_[seed_scores[i].second];
                std::string filename = config_.corpus_dir + "/seed_" + 
                                      std::to_string(i) + ".bin";
                
                std::ofstream file(filename, std::ios::binary);
                if (file) {
                    file.write(reinterpret_cast<const char*>(seed.data.data()), 
                              seed.data.size());
                }
            }
        }
    }
    
    // **改进**: 保存单个种子（使用更好的文件命名）
    void saveSingleSeed(const Seed& seed) {
        try {
            // 创建目录
            std::filesystem::create_directories(config_.corpus_dir);
            
            // 使用强哈希和更好的文件命名策略
            uint64_t seed_hash = SeedHasher::computeHash(seed.data);
            auto timestamp = std::chrono::system_clock::to_time_t(seed.created_time);
            
            // 格式: seed_<timestamp>_<hash>_<size>.bin
            std::string filename = config_.corpus_dir + "/seed_" + 
                                  std::to_string(timestamp) + "_" + 
                                  std::to_string(seed_hash) + "_" +
                                  std::to_string(seed.data.size()) + ".bin";
            
            // 检查文件是否已存在，避免重复保存
            if (!std::filesystem::exists(filename)) {
                std::ofstream file(filename, std::ios::binary);
                if (file) {
                    file.write(reinterpret_cast<const char*>(seed.data.data()), 
                              seed.data.size());
                    // 只为真正重要的种子保存元数据，减少文件数量
                    // 条件更严格：能量 > 3.0 并且有新边
                    if (seed.energy > 3.0 && !seed.coverage.new_edges.empty()) {
                        saveMetadata(filename + ".meta", seed);
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to save single seed: " << e.what() << std::endl;
        }
    }
    
    // 保存种子元数据
    void saveMetadata(const std::string& filename, const Seed& seed) {
        try {
            std::ofstream meta_file(filename);
            if (meta_file) {
                meta_file << "energy=" << seed.energy << std::endl;
                meta_file << "generation=" << seed.generation << std::endl;
                meta_file << "coverage_gain=" << seed.coverage.coverage_gain << std::endl;
                meta_file << "new_edges=" << seed.coverage.new_edges.size() << std::endl;
                meta_file << "rare_edges=" << seed.coverage.rare_edges.size() << std::endl;
                
                if (!seed.algorithm_history.empty()) {
                    meta_file << "algorithms=";
                    for (size_t i = 0; i < seed.algorithm_history.size(); ++i) {
                        if (i > 0) meta_file << ",";
                        meta_file << seed.algorithm_history[i];
                    }
                    meta_file << std::endl;
                }
            }
        } catch (const std::exception& e) {
            // 元数据保存失败不影响主流程
        }
    }
    
    // 加载语料库
    void loadCorpus(const std::string& dir) {
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
        
        // 不清空现有corpus，而是追加加载
        // corpus_.clear();  // 注释掉这行，保留现有种子
        
        std::vector<std::pair<std::filesystem::path, size_t>> seed_files;
        size_t loaded_count = 0;
        size_t skipped_count = 0;
        
        try {
            // 首先收集所有种子文件信息
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                    try {
                        size_t file_size = std::filesystem::file_size(entry.path());
                        seed_files.emplace_back(entry.path(), file_size);
                    } catch (const std::exception& e) {
                        // 忽略无法访问的文件
                        continue;
                    }
                }
            }
            
            // 对种子文件进行智能排序（优先加载中等大小、可能更有用的种子）
            std::sort(seed_files.begin(), seed_files.end(), 
                [](const auto& a, const auto& b) {
                    // 优先级策略：
                    // 1. 中等大小的种子（256-4KB）优先
                    // 2. 然后是小种子
                    // 3. 最后是大种子
                    size_t size_a = a.second, size_b = b.second;
                    
                    bool a_medium = (size_a >= 256 && size_a <= 4096);
                    bool b_medium = (size_b >= 256 && size_b <= 4096);
                    
                    if (a_medium && !b_medium) return true;
                    if (!a_medium && b_medium) return false;
                    
                    // 在同一类别内，按文件名排序（包含时间戳信息）
                    return a.first.filename().string() > b.first.filename().string();
                });
            
            // 智能加载策略：限制加载数量以避免内存过载
            size_t max_load_count = std::min(seed_files.size(), size_t(5000)); // 最多加载5000个
            std::cout << "[CorpusManager] Loading up to " << max_load_count 
                     << " seeds from " << seed_files.size() << " available files" << std::endl;
            
            for (size_t i = 0; i < max_load_count; ++i) {
                const auto& [file_path, file_size] = seed_files[i];
                
                // 跳过过大的文件
                if (file_size > config_.max_seed_size) {
                    skipped_count++;
                    continue;
                }
                
                try {
                    std::ifstream file(file_path, std::ios::binary);
                    if (file) {
                        // 读取文件内容
                        std::vector<uint8_t> data(
                            (std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
                        
                        // 创建种子
                        Seed seed;
                        seed.data = std::move(data);
                        seed.data_hash = SeedHasher::computeHash(seed.data);
                        
                        // 根据文件名中的时间戳和哈希设置能量
                        std::string filename = file_path.filename().string();
                        seed.energy = calculateSeedEnergyFromFilename(filename);
                        
                        // 使用当前时间，避免时间类型转换问题
                        seed.created_time = std::chrono::system_clock::now();
                        
                        // 尝试从元数据文件加载更多信息
                        std::string meta_file = file_path.string() + ".meta";
                        if (std::filesystem::exists(meta_file)) {
                            loadSeedMetadata(seed, meta_file);
                        }
                        
                        // Maintain hash indices for fast lookup (used by schedulers / energy updates).
                        seed_hashes_.insert(seed.data_hash);
                        hash_to_indices_.insert({seed.data_hash, corpus_.size()});  // 即将添加到末尾

                        corpus_.push_back(std::move(seed));
                        loaded_count++;
                        total_seeds_++;
                        
                        // 显示进度（每1000个文件显示一次）
                        if (loaded_count % 1000 == 0) {
                            std::cout << "[CorpusManager] Loaded " << loaded_count << " seeds..." << std::endl;
                        }
                    }
                } catch (const std::exception& e) {
                    skipped_count++;
                    // 继续处理其他文件
                }
            }
            
            std::cout << "[CorpusManager] Corpus loading completed: " 
                     << loaded_count << " loaded, " << skipped_count << " skipped" << std::endl;
            
        } catch (const std::filesystem::filesystem_error& e) {
            // 目录不存在或无法访问
            std::cerr << "[ERROR] Error loading corpus: " << e.what() << std::endl;
        }
    }
    
    // 从文件名计算种子能量
    double calculateSeedEnergyFromFilename(const std::string& filename) {
        // 文件名格式: seed_<timestamp>_<hash>_<size>.bin
        // 较新的文件通常有更高的能量
        try {
            size_t first_underscore = filename.find('_');
            size_t second_underscore = filename.find('_', first_underscore + 1);
            
            if (first_underscore != std::string::npos && second_underscore != std::string::npos) {
                std::string timestamp_str = filename.substr(first_underscore + 1, 
                                                          second_underscore - first_underscore - 1);
                
                // 尝试解析时间戳
                uint64_t timestamp = std::stoull(timestamp_str);
                uint64_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                
                // 较新的种子获得更高能量（最近7天内的种子）
                uint64_t age_seconds = current_time - timestamp;
                if (age_seconds < 7 * 24 * 3600) {  // 7天
                    return 1.5;  // 高能量
                } else if (age_seconds < 30 * 24 * 3600) {  // 30天
                    return 1.2;  // 中等能量
                }
            }
        } catch (const std::exception& e) {
            // 解析失败，使用默认能量
        }
        
        return 1.0;  // 默认能量
    }
    
    // 从元数据文件加载种子信息
    void loadSeedMetadata(Seed& seed, const std::string& meta_file) {
        try {
            std::ifstream meta(meta_file);
            std::string line;
            
            while (std::getline(meta, line)) {
                if (line.find("energy=") == 0) {
                    seed.energy = std::stod(line.substr(7));
                } else if (line.find("generation=") == 0) {
                    seed.generation = std::stoull(line.substr(11));
                } else if (line.find("algorithms=") == 0) {
                    std::string algos = line.substr(11);
                    std::stringstream ss(algos);
                    std::string algo;
                    while (std::getline(ss, algo, ',')) {
                        seed.algorithm_history.push_back(algo);
                    }
                }
            }
        } catch (const std::exception& e) {
            // 元数据加载失败不影响主流程
        }
    }
    
    // 统计信息
    size_t getTotalSeeds() const {
        return total_seeds_.load();
    }
    
    size_t getTotalCrashes() const {
        return total_crashes_.load();
    }
    
    size_t getInterestingSeeds() const {
        return interesting_seeds_.load();
    }
    
    size_t getCurrentCorpusSize() const {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        return corpus_.size();
    }
    
    // 配置更新
    void updateConfig(const Config& config) {
        config_ = config;
    }
    
    // **新增**: 获取所有corpus数据供变异算法使用
    std::vector<std::vector<uint8_t>> getAllCorpusData() const {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        
        std::vector<std::vector<uint8_t>> corpus_data;
        corpus_data.reserve(corpus_.size());
        
        for (const auto& seed : corpus_) {
            corpus_data.push_back(seed.data);
        }
        
        return corpus_data;
    }

    // 获取所有种子的哈希（避免拷贝完整种子内容）
    std::vector<uint64_t> getAllSeedHashes() const {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        std::vector<uint64_t> hashes;
        hashes.reserve(corpus_.size());
        for (const auto& seed : corpus_) {
            if (seed.data_hash != 0) {
                hashes.push_back(seed.data_hash);
            } else {
                hashes.push_back(SeedHasher::computeHash(seed.data));
            }
        }
        return hashes;
    }

    // 通过hash快速获取种子副本（用于EcoFuzz等需要按hash选择种子的调度器）
    std::optional<Seed> getSeedByHash(uint64_t seed_hash) const {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        auto range = hash_to_indices_.equal_range(seed_hash);
        for (auto it = range.first; it != range.second; ++it) {
            size_t idx = it->second;
            if (idx < corpus_.size()) {
                return corpus_[idx];
            }
        }
        return std::nullopt;
    }
    
    // **新增**: 种子生命周期管理
    struct SeedLifecycle {
        size_t usage_count = 0;
        size_t mutation_attempts = 0;
        size_t successful_mutations = 0;
        std::chrono::system_clock::time_point last_used;
        std::chrono::system_clock::time_point last_productive;
        double productivity_score = 1.0;
        bool is_stagnant = false;
        
        double getEfficiency() const {
            if (mutation_attempts == 0) return 1.0;
            return static_cast<double>(successful_mutations) / mutation_attempts;
        }
        
        bool shouldRetire(const Config& config) const {
            auto now = std::chrono::system_clock::now();
            auto days_since_productive = std::chrono::duration_cast<std::chrono::hours>(
                now - last_productive).count() / 24.0;
            
            // 如果7天内没有产生结果且效率低于10%，考虑淘汰
            return days_since_productive > 7.0 && getEfficiency() < 0.1;
        }
    };
    
    // 种子生命周期追踪
    std::unordered_map<uint64_t, SeedLifecycle> seed_lifecycles_;
    
    // 更新种子使用统计
    void updateSeedUsage(const Seed& seed, bool was_productive) {
        if (!config_.enable_lifecycle_management) return;
        
        uint64_t seed_hash = SeedHasher::computeHash(seed.data);
        auto& lifecycle = seed_lifecycles_[seed_hash];
        
        lifecycle.usage_count++;
        lifecycle.mutation_attempts++;
        lifecycle.last_used = std::chrono::system_clock::now();
        
        if (was_productive) {
            lifecycle.successful_mutations++;
            lifecycle.last_productive = std::chrono::system_clock::now();
            lifecycle.productivity_score = lifecycle.productivity_score * 0.9 + 0.1; // 增加分数
        } else {
            lifecycle.productivity_score *= 0.99; // 缓慢衰减
        }
        
        // 标记停滞种子
        auto hours_since_productive = std::chrono::duration_cast<std::chrono::hours>(
            lifecycle.last_used - lifecycle.last_productive).count();
        lifecycle.is_stagnant = hours_since_productive > 48; // 48小时无产出视为停滞
    }
    
    // 清理老化种子
    void cleanupAgedSeeds() {
        if (!config_.enable_lifecycle_management) return;
        
        std::vector<size_t> indices_to_remove;
        
        for (size_t i = 0; i < corpus_.size(); ++i) {
            const auto& seed = corpus_[i];
            uint64_t seed_hash = SeedHasher::computeHash(seed.data);
            
            auto it = seed_lifecycles_.find(seed_hash);
            if (it != seed_lifecycles_.end() && it->second.shouldRetire(config_)) {
                indices_to_remove.push_back(i);
            }
        }
        
        // 从后往前移除
        std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
        for (size_t idx : indices_to_remove) {
            uint64_t hash = SeedHasher::computeHash(corpus_[idx].data);
            seed_hashes_.erase(hash);
            seed_lifecycles_.erase(hash);
            corpus_.erase(corpus_.begin() + idx);
        }
        
        if (!indices_to_remove.empty()) {
            std::cout << "[CORPUS] Cleaned up " << indices_to_remove.size() 
                     << " aged seeds" << std::endl;
            invalidateEnergyCache();
        }
    }
    
    // **新增**: 种子最小化器
    class SeedMinimizer {
    public:
        struct MinimizationResult {
            std::vector<uint8_t> minimized_data;
            size_t original_size;
            size_t minimized_size;
            double compression_ratio;
            bool coverage_preserved;
            std::chrono::milliseconds time_taken;
        };
        
        // 二分法最小化
        static MinimizationResult minimizeBinary(
            const std::vector<uint8_t>& original_data,
            std::function<bool(const std::vector<uint8_t>&)> test_coverage) {
            
            auto start_time = std::chrono::steady_clock::now();
            MinimizationResult result;
            result.original_size = original_data.size();
            
            if (original_data.empty() || original_data.size() < 4) {
                result.minimized_data = original_data;
                result.minimized_size = result.original_size;
                result.compression_ratio = 1.0;
                result.coverage_preserved = true;
                result.time_taken = std::chrono::milliseconds(0);
                return result;
            }
            
            std::vector<uint8_t> current_data = original_data;
            
            // 逐步削减，直到无法保持覆盖率
            while (current_data.size() > 1) {
                // 尝试移除前半部分
                std::vector<uint8_t> candidate(current_data.begin() + current_data.size()/2, 
                                             current_data.end());
                if (test_coverage(candidate)) {
                    current_data = candidate;
                    continue;
                }
                
                // 尝试移除后半部分
                candidate.assign(current_data.begin(), current_data.begin() + current_data.size()/2);
                if (test_coverage(candidate)) {
                    current_data = candidate;
                    continue;
                }
                
                // 尝试移除中间部分
                if (current_data.size() > 8) {
                    size_t quarter = current_data.size() / 4;
                    candidate.clear();
                    candidate.insert(candidate.end(), current_data.begin(), current_data.begin() + quarter);
                    candidate.insert(candidate.end(), current_data.end() - quarter, current_data.end());
                    if (test_coverage(candidate)) {
                        current_data = candidate;
                        continue;
                    }
                }
                
                break; // 无法进一步削减
            }
            
            auto end_time = std::chrono::steady_clock::now();
            
            result.minimized_data = current_data;
            result.minimized_size = current_data.size();
            result.compression_ratio = static_cast<double>(result.minimized_size) / result.original_size;
            result.coverage_preserved = test_coverage(current_data);
            result.time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            return result;
        }
        
        // 字节级最小化（更精细）
        static MinimizationResult minimizeByteLevel(
            const std::vector<uint8_t>& original_data,
            std::function<bool(const std::vector<uint8_t>&)> test_coverage) {
            
            auto start_time = std::chrono::steady_clock::now();
            MinimizationResult result;
            result.original_size = original_data.size();
            
            std::vector<uint8_t> current_data = original_data;
            
            // 逐字节测试移除
            for (size_t i = 0; i < current_data.size(); ) {
                std::vector<uint8_t> candidate;
                candidate.reserve(current_data.size() - 1);
                candidate.insert(candidate.end(), current_data.begin(), current_data.begin() + i);
                candidate.insert(candidate.end(), current_data.begin() + i + 1, current_data.end());
                
                if (test_coverage(candidate)) {
                    current_data = candidate;
                    // 不递增i，因为数组大小已经变化
                } else {
                    i++;
                }
            }
            
            auto end_time = std::chrono::steady_clock::now();
            
            result.minimized_data = current_data;
            result.minimized_size = current_data.size();
            result.compression_ratio = static_cast<double>(result.minimized_size) / result.original_size;
            result.coverage_preserved = test_coverage(current_data);
            result.time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            return result;
        }
    };
    
    // 应用种子最小化（改进：添加执行器接口）
    void minimizeLargeSeeds(std::function<bool(const std::vector<uint8_t>&)> execute_and_check = nullptr) {
        if (!config_.enable_minimization) return;
        
        const size_t large_seed_threshold = 4096; // 4KB以上的种子进行最小化
        size_t minimized_count = 0;
        size_t total_saved_bytes = 0;
        
        for (auto& seed : corpus_) {
            if (seed.data.size() > large_seed_threshold) {
                // 保存原始覆盖率信息
                auto original_coverage = seed.coverage;
                
                // 创建覆盖率测试函数
                auto test_func = [&](const std::vector<uint8_t>& test_data) -> bool {
                    if (execute_and_check) {
                        // 使用提供的执行器检查覆盖率
                        return execute_and_check(test_data);
                    } else {
                        // 回退到简单的长度检查
                        return test_data.size() >= 16;
                    }
                };
                
                auto result = SeedMinimizer::minimizeBinary(seed.data, test_func);
                
                if (result.coverage_preserved && result.compression_ratio < 0.8) {
                    size_t saved = seed.data.size() - result.minimized_data.size();
                    seed.data = result.minimized_data;
                    minimized_count++;
                    total_saved_bytes += saved;
                    
                    std::cout << "[MINIMIZER] Seed reduced from " << result.original_size 
                             << " to " << result.minimized_size << " bytes (ratio: " 
                             << std::fixed << std::setprecision(2) << result.compression_ratio << ")" << std::endl;
                }
            }
        }
        
        if (minimized_count > 0) {
            std::cout << "[MINIMIZER] Minimized " << minimized_count << " seeds, saved " 
                     << total_saved_bytes << " bytes total" << std::endl;
        }
    }
    
    // **新增**: 种子多样性管理器
    class SeedDiversityManager {
    public:
        struct DiversityMetrics {
            double structural_diversity = 0.0;  // 结构多样性
            double content_diversity = 0.0;     // 内容多样性
            double size_diversity = 0.0;        // 大小多样性
            double coverage_diversity = 0.0;    // 覆盖率多样性
            double overall_diversity = 0.0;     // 综合多样性
        };
        
        // 计算两个种子间的相似度
        static double calculateSimilarity(const std::vector<uint8_t>& seed1, 
                                        const std::vector<uint8_t>& seed2) {
            if (seed1.empty() || seed2.empty()) return 0.0;
            
            // 长度相似度
            double size_ratio = static_cast<double>(std::min(seed1.size(), seed2.size())) /
                               std::max(seed1.size(), seed2.size());
            
            // 内容相似度（改进的编辑距离）
            double content_similarity = calculateContentSimilarity(seed1, seed2);
            
            // 结构相似度（字节分布）
            double structural_similarity = calculateStructuralSimilarity(seed1, seed2);
            
            // 加权平均
            return 0.3 * size_ratio + 0.4 * content_similarity + 0.3 * structural_similarity;
        }
        
        // 计算语料库的整体多样性
        static DiversityMetrics calculateCorpusDiversity(const std::deque<Seed>& corpus) {
            DiversityMetrics metrics;
            
            if (corpus.size() <= 1) {
                metrics.overall_diversity = 1.0;
                return metrics;
            }
            
            // 大小多样性（种子大小的方差）
            std::vector<double> sizes;
            for (const auto& seed : corpus) {
                sizes.push_back(static_cast<double>(seed.data.size()));
            }
            metrics.size_diversity = calculateVariance(sizes) / (calculateMean(sizes) + 1.0);
            
            // 内容多样性（平均相似度的倒数）
            double total_similarity = 0.0;
            size_t comparison_count = 0;
            
            size_t sample_size = std::min(corpus.size(), size_t(100)); // 采样避免O(n²)复杂度
            for (size_t i = 0; i < sample_size; ++i) {
                for (size_t j = i + 1; j < sample_size; ++j) {
                    total_similarity += calculateSimilarity(corpus[i].data, corpus[j].data);
                    comparison_count++;
                }
            }
            
            double avg_similarity = comparison_count > 0 ? total_similarity / comparison_count : 0.0;
            metrics.content_diversity = 1.0 - avg_similarity;
            
            // 覆盖率多样性
            std::set<uint64_t> all_edges;
            for (const auto& seed : corpus) {
                for (auto edge : seed.coverage.new_edges) {
                    all_edges.insert(edge);
                }
            }
            
            if (!all_edges.empty()) {
                double unique_coverage = 0.0;
                for (const auto& seed : corpus) {
                    std::set<uint64_t> unique_to_seed;
                    for (auto edge : seed.coverage.new_edges) {
                        if (std::count_if(corpus.begin(), corpus.end(), 
                            [edge](const Seed& s) { 
                                return std::find(s.coverage.new_edges.begin(), 
                                               s.coverage.new_edges.end(), edge) != 
                                       s.coverage.new_edges.end();
                            }) == 1) {
                            unique_to_seed.insert(edge);
                        }
                    }
                    unique_coverage += static_cast<double>(unique_to_seed.size()) / all_edges.size();
                }
                metrics.coverage_diversity = unique_coverage / corpus.size();
            }
            
            // 综合多样性
            metrics.overall_diversity = (metrics.size_diversity + metrics.content_diversity + 
                                       metrics.coverage_diversity) / 3.0;
            
            return metrics;
        }
        
    private:
        static double calculateContentSimilarity(const std::vector<uint8_t>& s1, 
                                                const std::vector<uint8_t>& s2) {
            // 使用快速近似编辑距离
            size_t min_size = std::min(s1.size(), s2.size());
            if (min_size == 0) return 0.0;
            
            size_t common_bytes = 0;
            for (size_t i = 0; i < min_size; ++i) {
                if (s1[i] == s2[i]) common_bytes++;
            }
            
            return static_cast<double>(common_bytes) / std::max(s1.size(), s2.size());
        }
        
        static double calculateStructuralSimilarity(const std::vector<uint8_t>& s1,
                                                  const std::vector<uint8_t>& s2) {
            // 字节频率分布相似度
            std::array<size_t, 256> freq1 = {}, freq2 = {};
            
            for (uint8_t byte : s1) freq1[byte]++;
            for (uint8_t byte : s2) freq2[byte]++;
            
            double correlation = 0.0;
            for (size_t i = 0; i < 256; ++i) {
                double f1 = static_cast<double>(freq1[i]) / (s1.size() + 1);
                double f2 = static_cast<double>(freq2[i]) / (s2.size() + 1);
                correlation += f1 * f2;
            }
            
            return correlation;
        }
        
        static double calculateMean(const std::vector<double>& values) {
            if (values.empty()) return 0.0;
            return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
        }
        
        static double calculateVariance(const std::vector<double>& values) {
            if (values.size() <= 1) return 0.0;
            
            double mean = calculateMean(values);
            double variance = 0.0;
            
            for (double val : values) {
                variance += (val - mean) * (val - mean);
            }
            
            return variance / (values.size() - 1);
        }
    };
    
    // 应用多样性优化
    void optimizeDiversity() {
        auto metrics = SeedDiversityManager::calculateCorpusDiversity(corpus_);
        
        std::cout << "[DIVERSITY] Current diversity metrics:" << std::endl;
        std::cout << "  - Content: " << std::fixed << std::setprecision(3) << metrics.content_diversity << std::endl;
        std::cout << "  - Size: " << metrics.size_diversity << std::endl;
        std::cout << "  - Coverage: " << metrics.coverage_diversity << std::endl;
        std::cout << "  - Overall: " << metrics.overall_diversity << std::endl;
        
        // 如果多样性过低，移除相似种子
        if (metrics.overall_diversity < 0.5) {
            removeRedundantSeeds();
        }
    }
    
    // 移除冗余种子
    void removeRedundantSeeds() {
        if (corpus_.size() <= 2) return;
        
        const double similarity_threshold = 0.85; // 85%相似度视为冗余
        std::vector<bool> to_remove(corpus_.size(), false);
        size_t removed_count = 0;
        
        for (size_t i = 0; i < corpus_.size() && removed_count < corpus_.size() / 4; ++i) {
            if (to_remove[i]) continue;
            
            for (size_t j = i + 1; j < corpus_.size(); ++j) {
                if (to_remove[j]) continue;
                
                double similarity = SeedDiversityManager::calculateSimilarity(
                    corpus_[i].data, corpus_[j].data);
                
                if (similarity > similarity_threshold) {
                    // 保留质量更高的种子
                    double quality_i = calculateSeedQuality(corpus_[i]);
                    double quality_j = calculateSeedQuality(corpus_[j]);
                    
                    if (quality_i >= quality_j) {
                        to_remove[j] = true;
                    } else {
                        to_remove[i] = true;
                        break;
                    }
                    removed_count++;
                }
            }
        }
        
        // 从后往前移除
        for (size_t i = corpus_.size(); i > 0; --i) {
            size_t idx = i - 1;
            if (to_remove[idx]) {
                if (config_.enable_deduplication) {
                    uint64_t hash = SeedHasher::computeHash(corpus_[idx].data);
                    seed_hashes_.erase(hash);
                }
                corpus_.erase(corpus_.begin() + idx);
            }
        }
        
        if (removed_count > 0) {
            std::cout << "[DIVERSITY] Removed " << removed_count << " redundant seeds" << std::endl;
            invalidateEnergyCache();
        }
    }
    
    // **新增**: AFL++ 风格的 corpus 优化器
    class AFLPlusPlusOptimizer {
    public:
        struct OptimizationStats {
            size_t original_size = 0;
            size_t optimized_size = 0;
            size_t removed_duplicates = 0;
            size_t removed_low_quality = 0;
            size_t removed_redundant = 0;
            size_t minimized_seeds = 0;
            double coverage_preserved = 0.0;
            std::chrono::milliseconds optimization_time{0};
            double performance_improvement = 0.0;
        };
        
        struct CoverageMap {
            std::unordered_set<uint64_t> critical_edges;    // 关键边
            std::unordered_set<uint64_t> rare_edges;        // 稀有边  
            std::unordered_set<uint64_t> all_covered_edges; // 所有覆盖的边
            std::map<uint64_t, size_t> edge_frequency;      // 边的出现频率
        };
        
        // 主要的 corpus 优化函数（AFL++ 风格）
        static OptimizationStats optimizeCorpus(
            std::deque<Seed>& corpus,
            std::unordered_set<uint64_t>& seed_hashes,
            const Config& config) {
            
            auto start_time = std::chrono::steady_clock::now();
            OptimizationStats stats;
            stats.original_size = corpus.size();
            
            if (corpus.empty()) {
                return stats;
            }
            
            std::cout << "[AFL++ Optimizer] Starting corpus optimization with " 
                     << corpus.size() << " seeds..." << std::endl;
            
            // 1. 构建覆盖率映射
            CoverageMap coverage_map = buildCoverageMap(corpus);
            stats.coverage_preserved = calculateCoverageRatio(coverage_map.all_covered_edges);
            
            // 2. 去重 - AFL++ 风格的快速去重
            if (config.enable_deduplication) {
                stats.removed_duplicates = removeDuplicatesAFL(corpus, seed_hashes);
            }
            
            // 3. 移除冗余种子 - 基于覆盖率相似性
            if (config.enable_coverage_based_optimization) {
                stats.removed_redundant = removeRedundantByCoverage(corpus, coverage_map, config);
            }
            
            // 4. 保留关键种子 - 确保不丢失重要覆盖
            preserveCriticalSeeds(corpus, coverage_map, config);
            
            // 5. 质量评分和排序
            stats.removed_low_quality = removeByQualityScore(corpus, config);
            
            // 6. 种子最小化（如果启用）
            if (config.enable_minimization) {
                stats.minimized_seeds = minimizeSeedsInPlace(corpus);
            }
            
            // 7. 最终大小控制
            if (corpus.size() > config.target_corpus_size) {
                truncateToTargetSize(corpus, config.target_corpus_size, coverage_map);
            }
            
            stats.optimized_size = corpus.size();
            
            auto end_time = std::chrono::steady_clock::now();
            stats.optimization_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            
            // 计算性能改进估算
            stats.performance_improvement = estimatePerformanceImprovement(
                stats.original_size, stats.optimized_size);
            
            std::cout << "[AFL++ Optimizer] Optimization completed:" << std::endl;
            std::cout << "  - Original size: " << stats.original_size << std::endl;
            std::cout << "  - Optimized size: " << stats.optimized_size << std::endl;
            std::cout << "  - Removed duplicates: " << stats.removed_duplicates << std::endl;
            std::cout << "  - Removed low quality: " << stats.removed_low_quality << std::endl;
            std::cout << "  - Removed redundant: " << stats.removed_redundant << std::endl;
            std::cout << "  - Coverage preserved: " << std::fixed << std::setprecision(2) 
                     << stats.coverage_preserved * 100 << "%" << std::endl;
            std::cout << "  - Estimated performance improvement: " 
                     << stats.performance_improvement * 100 << "%" << std::endl;
            std::cout << "  - Time taken: " << stats.optimization_time.count() << "ms" << std::endl;
            
            return stats;
        }
        
        // **新增**: 可中断的优化方法
        static OptimizationStats optimizeCorpusInterruptible(
            std::deque<Seed>& corpus,
            std::unordered_set<uint64_t>& seed_hashes,
            const Config& config,
            const std::atomic<bool>& should_stop) {
            
            auto start_time = std::chrono::steady_clock::now();
            OptimizationStats stats;
            stats.original_size = corpus.size();
            
            if (corpus.empty() || should_stop) {
                return stats;
            }
            
            std::cout << "[AFL++ Optimizer] Starting corpus optimization with " 
                     << corpus.size() << " seeds..." << std::endl;
            
            // 1. 构建覆盖率映射
            if (should_stop) return stats;
            CoverageMap coverage_map = buildCoverageMap(corpus);
            stats.coverage_preserved = calculateCoverageRatio(coverage_map.all_covered_edges);
            
            // 2. 去重 - AFL++ 风格的快速去重
            if (should_stop) return stats;
            if (config.enable_deduplication) {
                stats.removed_duplicates = removeDuplicatesAFLInterruptible(corpus, seed_hashes, should_stop);
                if (should_stop) return stats;
            }
            
            // 3. 移除冗余种子 - 基于覆盖率相似性
            if (should_stop) return stats;
            if (config.enable_coverage_based_optimization) {
                stats.removed_redundant = removeRedundantByCoverageInterruptible(corpus, coverage_map, config, should_stop);
                if (should_stop) return stats;
            }
            
            // 4. 保留关键种子 - 确保不丢失重要覆盖
            if (should_stop) return stats;
            preserveCriticalSeeds(corpus, coverage_map, config);
            
            // 5. 质量评分和排序
            if (should_stop) return stats;
            stats.removed_low_quality = removeByQualityScoreInterruptible(corpus, config, should_stop);
            
            // 6. 种子最小化（如果启用）
            if (should_stop) return stats;
            if (config.enable_minimization) {
                stats.minimized_seeds = minimizeSeedsInPlaceInterruptible(corpus, should_stop);
                if (should_stop) return stats;
            }
            
            // 7. 最终大小控制
            if (should_stop) return stats;
            if (corpus.size() > config.target_corpus_size) {
                truncateToTargetSizeInterruptible(corpus, config.target_corpus_size, coverage_map, should_stop);
            }
            
            stats.optimized_size = corpus.size();
            
            auto end_time = std::chrono::steady_clock::now();
            stats.optimization_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            
            // 计算性能改进估算
            stats.performance_improvement = estimatePerformanceImprovement(
                stats.original_size, stats.optimized_size);
            
            if (!should_stop) {
                std::cout << "[AFL++ Optimizer] Optimization completed:" << std::endl;
                std::cout << "  - Original size: " << stats.original_size << std::endl;
                std::cout << "  - Optimized size: " << stats.optimized_size << std::endl;
                std::cout << "  - Removed duplicates: " << stats.removed_duplicates << std::endl;
                std::cout << "  - Removed low quality: " << stats.removed_low_quality << std::endl;
                std::cout << "  - Removed redundant: " << stats.removed_redundant << std::endl;
                std::cout << "  - Coverage preserved: " << std::fixed << std::setprecision(2) 
                         << stats.coverage_preserved * 100 << "%" << std::endl;
                std::cout << "  - Estimated performance improvement: " 
                         << stats.performance_improvement * 100 << "%" << std::endl;
                std::cout << "  - Time taken: " << stats.optimization_time.count() << "ms" << std::endl;
            } else {
                std::cout << "[AFL++ Optimizer] Optimization interrupted by stop signal" << std::endl;
            }
            
            return stats;
        }
        
    private:
        // 构建覆盖率映射
        static CoverageMap buildCoverageMap(const std::deque<Seed>& corpus) {
            CoverageMap map;
            
            for (const auto& seed : corpus) {
                // 收集所有边
                for (auto edge : seed.coverage.new_edges) {
                    map.all_covered_edges.insert(edge);
                    map.edge_frequency[edge]++;
                }
                
                // 识别稀有边（出现频率低的边）
                for (auto edge : seed.coverage.rare_edges) {
                    map.rare_edges.insert(edge);
                }
            }
            
            // 识别关键边（高价值的边）
            for (const auto& [edge, freq] : map.edge_frequency) {
                // 稀有边或者是新发现的边都被视为关键
                if (freq <= 3 || map.rare_edges.count(edge)) {
                    map.critical_edges.insert(edge);
                }
            }
            
            return map;
        }
        
        // AFL++ 风格的去重
        static size_t removeDuplicatesAFL(std::deque<Seed>& corpus, 
                                        std::unordered_set<uint64_t>& seed_hashes) {
            size_t removed = 0;
            std::unordered_set<uint64_t> seen_hashes;
            
            for (auto it = corpus.begin(); it != corpus.end();) {
                uint64_t hash = SeedHasher::computeHash(it->data);
                
                if (seen_hashes.count(hash)) {
                    seed_hashes.erase(hash);
                    it = corpus.erase(it);
                    removed++;
                } else {
                    seen_hashes.insert(hash);
                    ++it;
                }
            }
            
            return removed;
        }
        
        // **新增**: 可中断的AFL++风格去重
        static size_t removeDuplicatesAFLInterruptible(std::deque<Seed>& corpus, 
                                        std::unordered_set<uint64_t>& seed_hashes,
                                        const std::atomic<bool>& should_stop) {
            size_t removed = 0;
            std::unordered_set<uint64_t> seen_hashes;
            size_t processed = 0;
            
            for (auto it = corpus.begin(); it != corpus.end() && !should_stop;) {
                // 每处理100个种子检查一次停止信号
                if (++processed % 100 == 0 && should_stop) {
                    break;
                }
                
                uint64_t hash = SeedHasher::computeHash(it->data);
                
                if (seen_hashes.count(hash)) {
                    seed_hashes.erase(hash);
                    it = corpus.erase(it);
                    removed++;
                } else {
                    seen_hashes.insert(hash);
                    ++it;
                }
            }
            
            return removed;
        }
        
        // 基于覆盖率移除冗余种子
        static size_t removeRedundantByCoverage(std::deque<Seed>& corpus,
                                               const CoverageMap& coverage_map,
                                               const Config& config) {
            if (corpus.size() <= config.min_corpus_size) {
                return 0;
            }
            
            size_t removed = 0;
            std::vector<bool> to_remove(corpus.size(), false);
            
            // 构建边到种子的映射
            std::map<uint64_t, std::vector<size_t>> edge_to_seeds;
            for (size_t i = 0; i < corpus.size(); ++i) {
                for (auto edge : corpus[i].coverage.new_edges) {
                    edge_to_seeds[edge].push_back(i);
                }
            }
            
            // 对于每条边，只保留最高质量的种子
            for (const auto& [edge, seed_indices] : edge_to_seeds) {
                if (seed_indices.size() <= 1) continue;
                
                // 如果是关键边，保留所有覆盖它的种子
                if (coverage_map.critical_edges.count(edge)) {
                    continue;
                }
                
                // 找到质量最高的种子
                size_t best_seed_idx = seed_indices[0];
                double best_quality = calculateSeedQualityStatic(corpus[best_seed_idx]);
                
                for (size_t idx : seed_indices) {
                    double quality = calculateSeedQualityStatic(corpus[idx]);
                    if (quality > best_quality) {
                        best_quality = quality;
                        best_seed_idx = idx;
                    }
                }
                
                // 标记其他种子为待删除（但要检查它们是否覆盖其他重要边）
                for (size_t idx : seed_indices) {
                    if (idx != best_seed_idx && !hasUniqueImportantCoverage(corpus[idx], coverage_map)) {
                        to_remove[idx] = true;
                    }
                }
            }
            
            // 从后往前删除
            for (size_t i = corpus.size(); i > 0; --i) {
                size_t idx = i - 1;
                if (to_remove[idx]) {
                    corpus.erase(corpus.begin() + idx);
                    removed++;
                }
            }
            
            return removed;
        }
        
        // **新增**: 可中断的基于覆盖率移除冗余种子
        static size_t removeRedundantByCoverageInterruptible(std::deque<Seed>& corpus,
                                               const CoverageMap& coverage_map,
                                               const Config& config,
                                               const std::atomic<bool>& should_stop) {
            if (corpus.size() <= config.min_corpus_size || should_stop) {
                return 0;
            }
            
            size_t removed = 0;
            std::vector<bool> to_remove(corpus.size(), false);
            
            // 构建边到种子的映射
            std::map<uint64_t, std::vector<size_t>> edge_to_seeds;
            for (size_t i = 0; i < corpus.size() && !should_stop; ++i) {
                for (auto edge : corpus[i].coverage.new_edges) {
                    edge_to_seeds[edge].push_back(i);
                }
            }
            
            if (should_stop) return removed;
            
            // 对于每条边，只保留最高质量的种子
            size_t processed_edges = 0;
            for (const auto& [edge, seed_indices] : edge_to_seeds) {
                if (++processed_edges % 50 == 0 && should_stop) break;
                
                if (seed_indices.size() <= 1) continue;
                
                // 如果是关键边，保留所有覆盖它的种子
                if (coverage_map.critical_edges.count(edge)) {
                    continue;
                }
                
                // 找到质量最高的种子
                size_t best_seed_idx = seed_indices[0];
                double best_quality = calculateSeedQualityStatic(corpus[best_seed_idx]);
                
                for (size_t idx : seed_indices) {
                    double quality = calculateSeedQualityStatic(corpus[idx]);
                    if (quality > best_quality) {
                        best_quality = quality;
                        best_seed_idx = idx;
                    }
                }
                
                // 标记其他种子为待删除（但要检查它们是否覆盖其他重要边）
                for (size_t idx : seed_indices) {
                    if (idx != best_seed_idx && !hasUniqueImportantCoverage(corpus[idx], coverage_map)) {
                        to_remove[idx] = true;
                    }
                }
            }
            
            if (should_stop) return removed;
            
            // 从后往前删除
            for (size_t i = corpus.size(); i > 0 && !should_stop; --i) {
                size_t idx = i - 1;
                if (to_remove[idx]) {
                    corpus.erase(corpus.begin() + idx);
                    removed++;
                }
            }
            
            return removed;
        }
        
        // 检查种子是否有独特的重要覆盖
        static bool hasUniqueImportantCoverage(const Seed& seed, const CoverageMap& coverage_map) {
            for (auto edge : seed.coverage.new_edges) {
                if (coverage_map.critical_edges.count(edge) || coverage_map.rare_edges.count(edge)) {
                    return true;
                }
            }
            return false;
        }
        
        // 保留关键种子
        static void preserveCriticalSeeds(std::deque<Seed>& corpus,
                                        const CoverageMap& coverage_map,
                                        const Config& config) {
            // 确保覆盖关键边的种子不被删除
            std::set<size_t> critical_seed_indices;
            
            for (size_t i = 0; i < corpus.size(); ++i) {
                const auto& seed = corpus[i];
                
                // 检查是否覆盖关键边
                for (auto edge : seed.coverage.new_edges) {
                    if (coverage_map.critical_edges.count(edge)) {
                        critical_seed_indices.insert(i);
                        break;
                    }
                }
                
                // 检查是否是高质量的种子（有显著覆盖率增益）
                if (seed.coverage.coverage_gain > 0.5) {  // 阈值调整为0.5，表示有意义的覆盖率增益
                    critical_seed_indices.insert(i);
                }
            }
            
            // 标记关键种子（可以通过修改种子属性来标记）
            for (size_t idx : critical_seed_indices) {
                // 可以给关键种子更高的能量
                corpus[idx].energy = std::max(corpus[idx].energy, 10.0);
            }
        }
        
        // 基于质量评分移除种子
        static size_t removeByQualityScore(std::deque<Seed>& corpus, const Config& config) {
            if (corpus.size() <= config.min_corpus_size) {
                return 0;
            }
            
            size_t target_removal = corpus.size() - config.min_corpus_size;
            if (target_removal == 0) return 0;
            
            // 计算所有种子的质量分数
            std::vector<std::pair<double, size_t>> quality_scores;
            quality_scores.reserve(corpus.size());
            
            for (size_t i = 0; i < corpus.size(); ++i) {
                double score = calculateSeedQualityStatic(corpus[i]);
                quality_scores.emplace_back(score, i);
            }
            
            // 按分数排序（升序，低分的先删除）
            std::partial_sort(quality_scores.begin(),
                            quality_scores.begin() + target_removal,
                            quality_scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first < b.first;
                            });
            
            // 收集要删除的索引
            std::vector<size_t> to_remove;
            for (size_t i = 0; i < target_removal; ++i) {
                to_remove.push_back(quality_scores[i].second);
            }
            
            // 按降序排序索引以便从后往前删除
            std::sort(to_remove.rbegin(), to_remove.rend());
            
            // 删除种子
            for (size_t idx : to_remove) {
                corpus.erase(corpus.begin() + idx);
            }
            
            return target_removal;
        }
        
        // **新增**: 可中断的质量评分移除
        static size_t removeByQualityScoreInterruptible(std::deque<Seed>& corpus, const Config& config, const std::atomic<bool>& should_stop) {
            if (corpus.size() <= config.min_corpus_size || should_stop) {
                return 0;
            }
            
            size_t target_removal = corpus.size() - config.min_corpus_size;
            if (target_removal == 0) return 0;
            
            // 计算所有种子的质量分数
            std::vector<std::pair<double, size_t>> quality_scores;
            quality_scores.reserve(corpus.size());
            
            for (size_t i = 0; i < corpus.size() && !should_stop; ++i) {
                if (i % 100 == 0 && should_stop) break;
                double score = calculateSeedQualityStatic(corpus[i]);
                quality_scores.emplace_back(score, i);
            }
            
            if (should_stop) return 0;
            
            // 按分数排序（升序，低分的先删除）
            std::partial_sort(quality_scores.begin(),
                            quality_scores.begin() + target_removal,
                            quality_scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first < b.first;
                            });
            
            // 收集要删除的索引
            std::vector<size_t> to_remove;
            for (size_t i = 0; i < target_removal && !should_stop; ++i) {
                to_remove.push_back(quality_scores[i].second);
            }
            
            if (should_stop) return 0;
            
            // 按降序排序索引以便从后往前删除
            std::sort(to_remove.rbegin(), to_remove.rend());
            
            // 删除种子
            for (size_t idx : to_remove) {
                if (should_stop) break;
                corpus.erase(corpus.begin() + idx);
            }
            
            return to_remove.size();
        }
        
        static size_t minimizeSeedsInPlace(std::deque<Seed>& corpus) {
            size_t minimized_count = 0;
            
            for (auto& seed : corpus) {
                if (seed.data.size() > 1024) { // 只最小化大于1KB的种子
                    // 简化的最小化：移除尾部的零字节
                    while (!seed.data.empty() && seed.data.back() == 0) {
                        seed.data.pop_back();
                        minimized_count++;
                    }
                }
            }
            
            return minimized_count;
        }
        
        // **新增**: 可中断的种子最小化
        static size_t minimizeSeedsInPlaceInterruptible(std::deque<Seed>& corpus, const std::atomic<bool>& should_stop) {
            size_t minimized_count = 0;
            
            for (auto& seed : corpus) {
                if (should_stop) break;
                
                if (seed.data.size() > 1024) { // 只最小化大于1KB的种子
                    // 简化的最小化：移除尾部的零字节
                    while (!seed.data.empty() && seed.data.back() == 0) {
                        seed.data.pop_back();
                        minimized_count++;
                    }
                }
            }
            
            return minimized_count;
        }
        
        static void truncateToTargetSize(std::deque<Seed>& corpus, size_t target_size,
                                       const CoverageMap& coverage_map) {
            if (corpus.size() <= target_size) return;
            
            size_t to_remove = corpus.size() - target_size;
            
            // 计算每个种子的综合分数（质量 + 覆盖率重要性）
            std::vector<std::pair<double, size_t>> scores;
            scores.reserve(corpus.size());
            
            for (size_t i = 0; i < corpus.size(); ++i) {
                double base_score = calculateSeedQualityStatic(corpus[i]);
                
                // 如果种子覆盖关键边，提高分数
                bool covers_critical = false;
                for (auto edge : corpus[i].coverage.new_edges) {
                    if (coverage_map.critical_edges.count(edge)) {
                        covers_critical = true;
                        break;
                    }
                }
                
                if (covers_critical) {
                    base_score *= 2.0; // 关键种子分数翻倍
                }
                
                scores.emplace_back(base_score, i);
            }
            
            // 按分数排序（升序），移除最低分的
            std::partial_sort(scores.begin(), scores.begin() + to_remove, scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first < b.first;
                            });
            
            // 从后往前删除
            std::vector<size_t> indices_to_remove;
            for (size_t i = 0; i < to_remove; ++i) {
                indices_to_remove.push_back(scores[i].second);
            }
            std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
            
            for (size_t idx : indices_to_remove) {
                corpus.erase(corpus.begin() + idx);
            }
        }
        
        // **新增**: 可中断的截断到目标大小
        static void truncateToTargetSizeInterruptible(std::deque<Seed>& corpus, size_t target_size,
                                       const CoverageMap& coverage_map, const std::atomic<bool>& should_stop) {
            if (corpus.size() <= target_size || should_stop) return;
            
            size_t to_remove = corpus.size() - target_size;
            
            // 计算每个种子的综合分数（质量 + 覆盖率重要性）
            std::vector<std::pair<double, size_t>> scores;
            scores.reserve(corpus.size());
            
            for (size_t i = 0; i < corpus.size() && !should_stop; ++i) {
                if (i % 100 == 0 && should_stop) break;
                
                double base_score = calculateSeedQualityStatic(corpus[i]);
                
                // 如果种子覆盖关键边，提高分数
                bool covers_critical = false;
                for (auto edge : corpus[i].coverage.new_edges) {
                    if (coverage_map.critical_edges.count(edge)) {
                        covers_critical = true;
                        break;
                    }
                }
                
                if (covers_critical) {
                    base_score *= 2.0; // 关键种子分数翻倍
                }
                
                scores.emplace_back(base_score, i);
            }
            
            if (should_stop) return;
            
            // 按分数排序（升序），移除最低分的
            std::partial_sort(scores.begin(), scores.begin() + to_remove, scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first < b.first;
                            });
            
            // 从后往前删除
            std::vector<size_t> indices_to_remove;
            for (size_t i = 0; i < to_remove && !should_stop; ++i) {
                indices_to_remove.push_back(scores[i].second);
            }
            
            if (should_stop) return;
            
            std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
            
            for (size_t idx : indices_to_remove) {
                if (should_stop) break;
                corpus.erase(corpus.begin() + idx);
            }
        }
        
        // 计算覆盖率比例
        static double calculateCoverageRatio(const std::unordered_set<uint64_t>& covered_edges) {
            // 简化的覆盖率计算
            return covered_edges.empty() ? 0.0 : 1.0;
        }
        
        // 估算性能改进
        static double estimatePerformanceImprovement(size_t original_size, size_t optimized_size) {
            if (original_size <= optimized_size) return 0.0;
            
            // 简单的线性估算：corpus 大小减少 X%，性能提升约 0.5*X%
            double reduction_ratio = 1.0 - (static_cast<double>(optimized_size) / original_size);
            return reduction_ratio * 0.5;
        }
        
        // 静态质量计算函数
        static double calculateSeedQualityStatic(const Seed& seed) {
            double score = 0.0;
            
            // 基础能量权重
            score += seed.energy * 0.3;
            
            // 覆盖率权重
            score += seed.coverage.coverage_gain * 0.4;
            
            // 稀有边权重
            score += seed.coverage.rare_edges.size() * 0.2;
            
            // 种子年龄权重（新种子优先）
            auto age = std::chrono::duration_cast<std::chrono::hours>(
                std::chrono::system_clock::now() - seed.created_time).count();
            score += std::max(0.0, 1.0 - age / 24.0) * 0.1;
            
            return score;
        }
    };
    
    // **新增**: 自动优化管理器
    class AutoOptimizationManager {
    private:
        std::thread optimization_thread_;
        std::atomic<bool> should_stop_{false};
        std::atomic<bool> force_optimization_{false};
        Config config_;
        
        // 性能监控
        std::atomic<size_t> recent_corpus_size_{0};
        std::atomic<double> recent_performance_metric_{1.0};
        std::chrono::steady_clock::time_point last_optimization_;
        
    public:
        AutoOptimizationManager(const Config& config) : config_(config) {
            last_optimization_ = std::chrono::steady_clock::now();
        }
        
        ~AutoOptimizationManager() {
            stop();
        }
        
        void start(CorpusManager* corpus_manager) {
            if (!config_.enable_auto_optimization) return;
            
            optimization_thread_ = std::thread([this, corpus_manager]() {
                this->optimizationLoop(corpus_manager);
            });
        }
        
        void stop() {
            should_stop_ = true;
            if (optimization_thread_.joinable()) {
                // 给优化线程一个合理的时间来完成当前操作
                optimization_thread_.join();
            }
        }
        
        void triggerOptimization() {
            force_optimization_ = true;
        }
        
        void updatePerformanceMetric(double metric) {
            recent_performance_metric_ = metric;
        }
        
    private:
        void optimizationLoop(CorpusManager* corpus_manager) {
            while (!should_stop_) {
                // 减少睡眠时间，增加响应性
                for (int i = 0; i < 30 && !should_stop_; ++i) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                if (should_stop_) break;

                bool should_optimize = false;

                // 检查优化触发条件
                auto now = std::chrono::steady_clock::now();
                auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
                    now - last_optimization_).count();

                // 1. 定期优化 (转换为相同类型比较)
                if (static_cast<size_t>(time_since_last) >= config_.optimization_interval_seconds) {
                    should_optimize = true;
                }

                // 2. 强制优化
                if (force_optimization_.exchange(false)) {
                    should_optimize = true;
                }

                // 3. corpus 过大触发 - 避免在循环中频繁获取锁
                // 只在接近优化时间时才检查corpus大小
                if (!should_optimize && static_cast<size_t>(time_since_last) >= config_.optimization_interval_seconds / 2) {
                    size_t current_size = corpus_manager->getCurrentCorpusSize();
                    if (current_size > config_.max_corpus_size * config_.corpus_bloat_threshold) {
                        should_optimize = true;
                    }
                }

                // 4. 性能下降触发
                if (recent_performance_metric_ < (1.0 - config_.performance_degradation_threshold)) {
                    should_optimize = true;
                }

                // 检查停止信号，如果需要停止则不执行优化
                if (should_optimize && !should_stop_) {
                    performOptimization(corpus_manager);
                    last_optimization_ = now;
                }
            }
            std::cout << "[AutoOptimizer] Optimization thread stopped" << std::endl;
        }
        
        void performOptimization(CorpusManager* corpus_manager) {
            // 再次检查停止信号
            if (should_stop_) return;
            
            try {
                std::cout << "[AutoOptimizer] Starting automatic corpus optimization..." << std::endl;
                
                // 调用 AFL++ 优化器，并传递停止信号检查
                auto stats = corpus_manager->optimizeCorpusAFLStyleInterruptible(should_stop_);
                
                std::cout << "[AutoOptimizer] Optimization completed. "
                         << "Size reduced from " << stats.original_size 
                         << " to " << stats.optimized_size << std::endl;
                
                // 同时清理磁盘上的corpus文件
                corpus_manager->cleanupDiskCorpus();
                
            } catch (const std::exception& e) {
                std::cerr << "[AutoOptimizer] Optimization failed: " << e.what() << std::endl;
            }
        }
    };

    // **新增**: AFL++ 风格的 corpus 优化接口
    typename AFLPlusPlusOptimizer::OptimizationStats optimizeCorpusAFLStyle() {
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
        
        auto stats = AFLPlusPlusOptimizer::optimizeCorpus(corpus_, seed_hashes_, config_);
        
        // 更新统计
        if (stats.optimized_size < stats.original_size) {
            invalidateEnergyCache();
        }
        
        return stats;
    }
    
    // **新增**: 可中断的 AFL++ 风格的 corpus 优化接口
    typename AFLPlusPlusOptimizer::OptimizationStats optimizeCorpusAFLStyleInterruptible(const std::atomic<bool>& should_stop) {
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
        
        auto stats = AFLPlusPlusOptimizer::optimizeCorpusInterruptible(corpus_, seed_hashes_, config_, should_stop);
        
        // 更新统计
        if (stats.optimized_size < stats.original_size) {
            invalidateEnergyCache();
        }
        
        return stats;
    }
    
    // 清理磁盘上的旧corpus文件
    void cleanupDiskCorpus() {
        try {
            if (!std::filesystem::exists(config_.corpus_dir)) {
                return;
            }
            
            // 收集所有corpus文件
            std::vector<std::filesystem::path> corpus_files;
            for (const auto& entry : std::filesystem::directory_iterator(config_.corpus_dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                    corpus_files.push_back(entry.path());
                }
            }
            
            // 如果文件数量超过限制，删除旧文件
            const size_t max_disk_files = 2000; // 磁盘上最多保留2000个文件
            if (corpus_files.size() > max_disk_files) {
                // 按修改时间排序
                std::sort(corpus_files.begin(), corpus_files.end(),
                    [](const auto& a, const auto& b) {
                        return std::filesystem::last_write_time(a) < 
                               std::filesystem::last_write_time(b);
                    });
                
                // 删除最旧的文件
                size_t to_delete = corpus_files.size() - max_disk_files;
                for (size_t i = 0; i < to_delete; ++i) {
                    std::filesystem::remove(corpus_files[i]);
                    // 同时删除对应的meta文件（如果存在）
                    std::filesystem::path meta_path = corpus_files[i];
                    meta_path.replace_extension(".bin.meta");
                    if (std::filesystem::exists(meta_path)) {
                        std::filesystem::remove(meta_path);
                    }
                }
                
                std::cout << "[CorpusManager] Cleaned up " << to_delete 
                         << " old corpus files from disk" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to cleanup disk corpus: " << e.what() << std::endl;
        }
    }
    
    // **新增**: 启动自动优化
    void startAutoOptimization() {
        if (!auto_optimizer_) {
            auto_optimizer_ = std::make_unique<AutoOptimizationManager>(config_);
            auto_optimizer_->start(this);
        }
    }
    
    // **新增**: 停止自动优化
    void stopAutoOptimization() {
        if (auto_optimizer_) {
            auto_optimizer_->stop();
            auto_optimizer_.reset();
        }
    }
    
    // **新增**: 手动触发优化
    void triggerOptimization() {
        if (auto_optimizer_) {
            auto_optimizer_->triggerOptimization();
        } else {
            // 如果没有自动优化器，直接执行优化
            optimizeCorpusAFLStyle();
        }
    }
    
    // **新增**: 更新性能指标
    void updatePerformanceMetric(double metric) {
        if (auto_optimizer_) {
            auto_optimizer_->updatePerformanceMetric(metric);
        }
    }
    
    // **新增**: 获取corpus质量统计
    struct CorpusStats {
        size_t total_seeds = 0;
        size_t unique_seeds = 0;
        double average_energy = 0.0;
        double diversity_score = 0.0;
        size_t total_coverage = 0;
        size_t total_size_bytes = 0;
        double average_seed_size = 0.0;
        size_t seeds_with_new_coverage = 0;
        std::chrono::seconds corpus_age{0};
    };
    
    CorpusStats getCorpusStats() const {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        CorpusStats stats;
        
        stats.total_seeds = corpus_.size();
        stats.unique_seeds = seed_hashes_.size();
        
        if (corpus_.empty()) return stats;
        
        // 计算平均能量
        double total_energy = 0.0;
        std::set<uint64_t> all_edges;
        size_t total_bytes = 0;
        
        for (const auto& seed : corpus_) {
            total_energy += seed.energy;
            total_bytes += seed.data.size();
            
            // 收集所有覆盖的边
            for (auto edge : seed.coverage.new_edges) {
                all_edges.insert(edge);
            }
            
            if (seed.coverage.hasNewCoverage()) {
                stats.seeds_with_new_coverage++;
            }
        }
        
        stats.average_energy = total_energy / corpus_.size();
        stats.total_coverage = all_edges.size();
        stats.total_size_bytes = total_bytes;
        stats.average_seed_size = static_cast<double>(total_bytes) / corpus_.size();
        
        // 计算多样性分数
        auto diversity_metrics = SeedDiversityManager::calculateCorpusDiversity(corpus_);
        stats.diversity_score = diversity_metrics.overall_diversity;
        
        // 计算corpus年龄
        if (!corpus_.empty()) {
            auto oldest_seed = std::min_element(corpus_.begin(), corpus_.end(),
                [](const Seed& a, const Seed& b) {
                    return a.created_time < b.created_time;
                });
            
            auto age = std::chrono::system_clock::now() - oldest_seed->created_time;
            stats.corpus_age = std::chrono::duration_cast<std::chrono::seconds>(age);
        }
        
        return stats;
    }
    
    // **新增**: 从另一个corpus选择性导入种子（只导入有新覆盖率的）
    struct MergeStats {
        size_t total_seeds_examined = 0;
        size_t seeds_with_new_coverage = 0;
        size_t seeds_imported = 0;
        size_t new_edges_discovered = 0;
        size_t duplicate_seeds_skipped = 0;
    };
    
    MergeStats mergeCorpusSelectively(const std::vector<Seed>& external_corpus) {
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
        MergeStats stats;
        
        // 收集当前corpus的所有覆盖边
        std::unordered_set<uint64_t> current_edges;
        for (const auto& seed : corpus_) {
            for (auto edge : seed.coverage.covered_edges) {
                current_edges.insert(edge);
            }
            for (auto edge : seed.coverage.new_edges) {
                current_edges.insert(edge);
            }
        }
        
        std::cout << "[CORPUS MERGE] Current corpus has " << current_edges.size() 
                  << " unique edges" << std::endl;
        
        // 检查external corpus中的每个种子
        for (const auto& ext_seed : external_corpus) {
            stats.total_seeds_examined++;
            
            // 检查是否有新的覆盖率
            bool has_new_coverage = false;
            std::vector<uint64_t> new_edges;
            
            // 检查covered_edges
            for (auto edge : ext_seed.coverage.covered_edges) {
                if (current_edges.find(edge) == current_edges.end()) {
                    has_new_coverage = true;
                    new_edges.push_back(edge);
                    current_edges.insert(edge);  // 添加到当前边集合
                }
            }
            
            // 检查new_edges
            for (auto edge : ext_seed.coverage.new_edges) {
                if (current_edges.find(edge) == current_edges.end()) {
                    has_new_coverage = true;
                    new_edges.push_back(edge);
                    current_edges.insert(edge);  // 添加到当前边集合
                }
            }
            
            if (has_new_coverage) {
                stats.seeds_with_new_coverage++;
                stats.new_edges_discovered += new_edges.size();
                
                // 检查是否是重复种子（基于数据内容）
                if (config_.enable_deduplication) {
                    uint64_t seed_hash = SeedHasher::computeHash(ext_seed.data);
                    auto range = hash_to_indices_.equal_range(seed_hash);
                    bool found = false;
                    for (auto it = range.first; it != range.second; ++it) {
                        size_t idx = it->second;
                        if (idx < corpus_.size() && SeedHasher::areEqual(corpus_[idx].data, ext_seed.data)) {
                            corpus_[idx].coverage.merge(ext_seed.coverage);
                            // 提升能量，因为发现了新路径
                            corpus_[idx].energy = std::max(corpus_[idx].energy * 1.5, ext_seed.energy);
                            found = true;
                            break;
                        }
                    }
                    if (found) {
                        stats.duplicate_seeds_skipped++;
                        continue;
                    }
                }
                
                // 创建新种子并导入
                Seed new_seed = ext_seed;  // 深拷贝
                new_seed.created_time = std::chrono::system_clock::now();
                // 给有新覆盖率的种子更高的初始能量
                new_seed.energy = std::max(1.5, ext_seed.energy);
                
                // 更新种子的new_edges为真正的新边
                new_seed.coverage.new_edges = new_edges;
                
                // 添加到corpus（不使用addSeed以避免重复的去重检查）
                if (config_.enable_deduplication) {
                    uint64_t hash = SeedHasher::computeHash(new_seed.data);
                    seed_hashes_.insert(hash);
                    hash_to_indices_.insert({hash, corpus_.size()});
                }
                corpus_.push_back(std::move(new_seed));
                stats.seeds_imported++;
                
                // 保存到磁盘
                try {
                    saveSingleSeed(corpus_.back());
                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Failed to save imported seed: " << e.what() << std::endl;
                }
            }
        }
        
        // 如果导入了新种子，可能需要触发corpus优化
        if (stats.seeds_imported > 0 && corpus_.size() > config_.max_corpus_size) {
            removeLowQualitySeeds();
            rebuildHashIndex();
        }
        
        // 打印合并统计
        std::cout << "[CORPUS MERGE] Merge completed:" << std::endl;
        std::cout << "  - Seeds examined: " << stats.total_seeds_examined << std::endl;
        std::cout << "  - Seeds with new coverage: " << stats.seeds_with_new_coverage << std::endl;
        std::cout << "  - Seeds imported: " << stats.seeds_imported << std::endl;
        std::cout << "  - New edges discovered: " << stats.new_edges_discovered << std::endl;
        std::cout << "  - Duplicate seeds updated: " << stats.duplicate_seeds_skipped << std::endl;
        std::cout << "  - Final corpus size: " << corpus_.size() << std::endl;
        
        return stats;
    }
    
    // **新增**: 从recovery进程合并corpus（只导入发现新路径的种子）
    MergeStats mergeFromRecoveryProcess(const std::string& recovery_corpus_dir, 
                                       bool cleanup_after_merge = false) {
        std::cout << "[RECOVERY MERGE] Starting selective merge from recovery process: " 
                  << recovery_corpus_dir << std::endl;
        
        auto stats = mergeCorpusFromDirectory(recovery_corpus_dir);
        
        // 可选：合并后清理recovery corpus目录
        if (cleanup_after_merge && stats.seeds_imported > 0) {
            try {
                std::cout << "[RECOVERY MERGE] Cleaning up recovery corpus directory..." << std::endl;
                for (const auto& entry : std::filesystem::directory_iterator(recovery_corpus_dir)) {
                    if (entry.is_regular_file() && 
                        (entry.path().extension() == ".bin" || entry.path().extension() == ".meta")) {
                        std::filesystem::remove(entry.path());
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[WARNING] Failed to cleanup recovery corpus: " << e.what() << std::endl;
            }
        }
        
        // 记录recovery贡献的统计信息
        if (stats.seeds_imported > 0) {
            std::cout << "[RECOVERY MERGE] Recovery process contributed " 
                      << stats.seeds_imported << " seeds with " 
                      << stats.new_edges_discovered << " new edges" << std::endl;
            
            // 触发一次corpus优化（如果需要）
            if (corpus_.size() > config_.target_corpus_size) {
                std::cout << "[RECOVERY MERGE] Triggering corpus optimization..." << std::endl;
                if (auto_optimizer_) {
                    auto_optimizer_->triggerOptimization();
                }
            }
        } else {
            std::cout << "[RECOVERY MERGE] No new coverage found in recovery corpus" << std::endl;
        }
        
        return stats;
    }
    
    // 从文件/目录选择性导入corpus（只导入有新路径的）
    MergeStats mergeCorpusFromDirectory(const std::string& dir) {
        std::vector<Seed> external_corpus;
        
        try {
            // 加载外部corpus
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                    try {
                        std::ifstream file(entry.path(), std::ios::binary);
                        if (file) {
                            std::vector<uint8_t> data(
                                (std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
                            
                            Seed seed;
                            seed.data = std::move(data);
                            seed.energy = 1.0;
                            seed.created_time = std::chrono::system_clock::now();
                            
                            // 尝试加载元数据
                            std::string meta_file = entry.path().string() + ".meta";
                            if (std::filesystem::exists(meta_file)) {
                                loadSeedMetadata(seed, meta_file);
                            }
                            
                            external_corpus.push_back(std::move(seed));
                        }
                    } catch (const std::exception& e) {
                        // 忽略无法加载的文件
                        continue;
                    }
                }
            }
            
            std::cout << "[CORPUS MERGE] Loaded " << external_corpus.size() 
                      << " seeds from " << dir << std::endl;
            
            // 执行选择性合并
            return mergeCorpusSelectively(external_corpus);
            
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[ERROR] Failed to access directory " << dir << ": " << e.what() << std::endl;
            return MergeStats{};
        }
    }
    
    // **新增**: 打印corpus质量报告
    void printCorpusQualityReport() const {
        auto stats = getCorpusStats();
        
        std::cout << "\n[CORPUS QUALITY REPORT]" << std::endl;
        std::cout << "┌─────────────────────────────────────────┐" << std::endl;
        std::cout << "│ Total Seeds:        " << std::setw(18) << stats.total_seeds << " │" << std::endl;
        std::cout << "│ Unique Seeds:       " << std::setw(18) << stats.unique_seeds << " │" << std::endl;
        std::cout << "│ Coverage Seeds:     " << std::setw(18) << stats.seeds_with_new_coverage << " │" << std::endl;
        std::cout << "│ Total Coverage:     " << std::setw(18) << stats.total_coverage << " │" << std::endl;
        std::cout << "│ Avg Energy:         " << std::setw(18) << std::fixed << std::setprecision(2) << stats.average_energy << " │" << std::endl;
        std::cout << "│ Diversity Score:    " << std::setw(18) << std::fixed << std::setprecision(3) << stats.diversity_score << " │" << std::endl;
        std::cout << "│ Total Size (KB):    " << std::setw(18) << (stats.total_size_bytes / 1024) << " │" << std::endl;
        std::cout << "│ Avg Seed Size (B):  " << std::setw(18) << static_cast<size_t>(stats.average_seed_size) << " │" << std::endl;
        std::cout << "│ Corpus Age (min):   " << std::setw(18) << (stats.corpus_age.count() / 60) << " │" << std::endl;
        std::cout << "└─────────────────────────────────────────┘" << std::endl;
        
        // 质量评估
        if (stats.diversity_score < 0.3) {
            std::cout << "[WARNING] Low diversity score - consider enabling more mutation algorithms" << std::endl;
        }
        if (stats.average_energy < 0.5) {
            std::cout << "[WARNING] Low average energy - corpus may be stagnating" << std::endl;
        }
        if (stats.total_seeds > config_.max_corpus_size * 0.9) {
            std::cout << "[WARNING] Corpus near maximum size - optimization recommended" << std::endl;
        }
    }

private:
    // 配置实例
    Config config_;
    
    // 种子存储
    std::deque<Seed> corpus_;
    std::vector<Seed> crashes_;
    mutable std::shared_mutex corpus_mutex_;
    
    // 种子去重（改进：使用multimap处理hash碰撞）
    std::unordered_set<uint64_t> seed_hashes_;
    std::unordered_multimap<uint64_t, size_t> hash_to_indices_;  // 改进：使用multimap处理碰撞
    
    // 种子统计
    std::atomic<size_t> total_seeds_{0};
    std::atomic<size_t> total_crashes_{0};
    std::atomic<size_t> interesting_seeds_{0};
    
    // 能量分配和缓存
    std::map<std::string, double> algorithm_energy_;
    mutable double cached_total_energy_{0.0};
    mutable bool energy_cache_valid_{false};
    mutable std::vector<double> cumulative_energy_cache_;
    mutable std::mutex energy_cache_mutex_;  // Separate mutex for energy cache
    
    // 随机数生成器
    std::mt19937 random_{std::random_device{}()};
    
    // **新增**: 自动优化管理器
    std::unique_ptr<AutoOptimizationManager> auto_optimizer_;
    
    // **新增**: 重建hash索引（优化版：增量更新）
    void rebuildHashIndex() {
        // 使用临时map来构建新索引
        std::unordered_map<uint64_t, size_t> new_index;
        new_index.reserve(corpus_.size());
        
        for (size_t i = 0; i < corpus_.size(); ++i) {
            uint64_t hash = SeedHasher::computeHash(corpus_[i].data);
            // 处理潜在的hash碰撞
            if (new_index.find(hash) != new_index.end()) {
                // 如果发生碰撞，使用链表或其他策略
                // 这里暂时保留最新的索引
                std::cerr << "[WARNING] Hash collision detected during index rebuild" << std::endl;
            }
            new_index[hash] = i;
        }
        
        // 原子性替换索引
        hash_to_indices_.clear();
        for (const auto& [hash, idx] : new_index) {
            hash_to_indices_.insert({hash, idx});
        }
    }

    // 更激进的种子移除函数
    void removeLowQualitySeedsAdvanced(size_t target_removal_count) {
        if (corpus_.empty() || target_removal_count == 0) return;
        
        try {
            // 确保不会移除过多种子
            size_t actual_remove_count = std::min(target_removal_count, 
                                                  corpus_.size() - config_.min_corpus_size);
            if (actual_remove_count == 0) return;
            
            // 根据多个因素评分种子质量
            std::vector<std::pair<double, size_t>> seed_scores;
            seed_scores.reserve(corpus_.size());
            
            for (size_t i = 0; i < corpus_.size(); ++i) {
                try {
                    const auto& seed = corpus_[i];
                    double score = calculateSeedQualityEnhanced(seed);
                    seed_scores.emplace_back(score, i);
                } catch (const std::exception& e) {
                    // 如果某个种子评分失败，给予最低分
                    std::cerr << "[WARNING] Failed to score seed " << i << ": " << e.what() << std::endl;
                    seed_scores.emplace_back(0.0, i);
                }
            }
            
            // 按分数排序，移除分数最低的种子
            std::partial_sort(seed_scores.begin(), 
                             seed_scores.begin() + actual_remove_count,
                             seed_scores.end(),
                             [](const auto& a, const auto& b) {
                                 return a.first < b.first; // 升序，低分的在前
                             });
            
            // 从后往前移除（保持索引有效性）
            std::vector<size_t> indices_to_remove;
            for (size_t i = 0; i < actual_remove_count; ++i) {
                indices_to_remove.push_back(seed_scores[i].second);
            }
            std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
            
            // 批量移除，提高效率并减少锁的持有时间
            size_t removed_count = 0;
            for (size_t idx : indices_to_remove) {
                try {
                    // 移除对应的哈希值
                    if (config_.enable_deduplication && idx < corpus_.size()) {
                        uint64_t hash = SeedHasher::computeHash(corpus_[idx].data);
                        seed_hashes_.erase(hash);
                        // 从multimap中移除对应索引
                        auto range = hash_to_indices_.equal_range(hash);
                        for (auto it = range.first; it != range.second; ) {
                            if (it->second == idx) {
                                it = hash_to_indices_.erase(it);
                            } else {
                                ++it;
                            }
                        }
                    }
                    corpus_.erase(corpus_.begin() + idx);
                    removed_count++;
                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Failed to remove seed at index " << idx 
                             << ": " << e.what() << std::endl;
                }
            }
            
            // 标记能量缓存无效
            energy_cache_valid_ = false;
            
            std::cout << "[CORPUS] Removed " << removed_count 
                     << " low-quality seeds, corpus size: " << corpus_.size() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Critical error in removeLowQualitySeedsAdvanced: " 
                     << e.what() << std::endl;
            // 确保索引一致性
            rebuildHashIndex();
        }
    }
    
    // 移除低质量的种子（保留原函数以兼容）
    void removeLowQualitySeeds() {
        if (corpus_.empty()) return;
        
        // 计算要移除的种子数量（10%或至少1个）
        size_t remove_count = std::max(size_t(1), corpus_.size() / 10);
        
        // 根据多个因素评分种子质量
        std::vector<std::pair<double, size_t>> seed_scores;
        seed_scores.reserve(corpus_.size());
        
        for (size_t i = 0; i < corpus_.size(); ++i) {
            const auto& seed = corpus_[i];
            double score = calculateSeedQuality(seed);
            seed_scores.emplace_back(score, i);
        }
        
        // 按分数排序，移除分数最低的种子
        std::partial_sort(seed_scores.begin(), 
                         seed_scores.begin() + remove_count,
                         seed_scores.end(),
                         [](const auto& a, const auto& b) {
                             return a.first < b.first; // 升序，低分的在前
                         });
        
        // 从后往前移除（保持索引有效性）
        std::vector<size_t> indices_to_remove;
        for (size_t i = 0; i < remove_count; ++i) {
            indices_to_remove.push_back(seed_scores[i].second);
        }
        std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
        
        for (size_t idx : indices_to_remove) {
            // 移除对应的哈希值
            if (config_.enable_deduplication && idx < corpus_.size()) {
                uint64_t hash = SeedHasher::computeHash(corpus_[idx].data);
                seed_hashes_.erase(hash);
            }
            corpus_.erase(corpus_.begin() + idx);
        }
        
        // 标记能量缓存无效
        energy_cache_valid_ = false;
    }
    
    // 增强版种子质量评分算法
    double calculateSeedQualityEnhanced(const Seed& seed) const {
        double score = 0.0;
        
        // 1. 覆盖率贡献 (35%)
        double coverage_score = 0.0;
        coverage_score += seed.coverage.coverage_gain * 0.5;  // 覆盖率增益
        coverage_score += (seed.coverage.new_edges.size() / 100.0) * 0.3;  // 新边数量
        coverage_score += (seed.coverage.rare_edges.size() / 10.0) * 0.2;  // 稀有边
        score += std::min(1.0, coverage_score) * 0.35;
        
        // 2. 能量和执行效率 (25%)
        double efficiency_score = seed.energy * 0.6;
        // 考虑种子大小（较小的种子执行更快）
        double size_factor = 1.0 / (1.0 + std::log10(seed.data.size() + 1) / 5.0);
        efficiency_score += size_factor * 0.4;
        score += std::min(1.0, efficiency_score) * 0.25;
        
        // 3. 多样性贡献 (20%)
        // 基于算法历史和代数评估多样性
        double diversity_score = 0.5;  // 基础多样性分数
        // 使用算法历史的多样性
        if (!seed.algorithm_history.empty()) {
            // 算法历史越多，说明经过的变异越多，多样性越高
            diversity_score += (1.0 - std::exp(-seed.algorithm_history.size() / 10.0)) * 0.3;
        }
        // 使用代数信息
        if (seed.generation > 0) {
            diversity_score += (1.0 - std::exp(-seed.generation / 20.0)) * 0.2;
        }
        score += std::min(1.0, diversity_score) * 0.20;
        
        // 4. 时效性 (15%)
        auto age_hours = std::chrono::duration_cast<std::chrono::hours>(
            std::chrono::system_clock::now() - seed.created_time).count();
        double freshness = 0.0;
        if (age_hours < 1) {
            freshness = 1.0;  // 1小时内的种子满分
        } else if (age_hours < 24) {
            freshness = 0.8 - (age_hours - 1) * 0.03;  // 24小时内线性递减
        } else if (age_hours < 168) {  // 一周内
            freshness = 0.3 - (age_hours - 24) * 0.002;
        } else {
            freshness = 0.05;  // 超过一周的老种子基础分
        }
        score += freshness * 0.15;
        
        // 5. 历史表现 (5%)
        // 基于种子的性能和覆盖率增益
        double historical_score = 0.3;  // 基础历史分
        // 使用执行速度作为历史表现的一部分
        if (seed.performance.execution_time_ms > 0) {
            // 执行越快，分数越高
            double speed_factor = 1.0 / (1.0 + std::log10(seed.performance.execution_time_ms + 1) / 3.0);
            historical_score = std::max(historical_score, speed_factor);
        }
        // 如果有显著的覆盖率增益，也提高分数
        if (seed.coverage.coverage_gain > 0.1) {
            historical_score = std::min(1.0, historical_score + seed.coverage.coverage_gain * 0.5);
        }
        score += historical_score * 0.05;
        
        return score;
    }
    
    // 计算种子质量分数（保留原函数以兼容）
    double calculateSeedQuality(const Seed& seed) const {
        return calculateSeedQualityEnhanced(seed);
    }
    
    // 无效化能量缓存
    void invalidateEnergyCache() const {
        std::lock_guard<std::mutex> lock(energy_cache_mutex_);
        energy_cache_valid_ = false;
        cumulative_energy_cache_.clear();
    }
    
    // 构建能量缓存
    void buildEnergyCache() const {
        std::lock_guard<std::mutex> cache_lock(energy_cache_mutex_);
        if (energy_cache_valid_) return;

        // Need read access to corpus
        std::shared_lock<std::shared_mutex> corpus_lock(corpus_mutex_);

        cumulative_energy_cache_.clear();
        cumulative_energy_cache_.reserve(corpus_.size());

        cached_total_energy_ = 0.0;
        for (const auto& seed : corpus_) {
            cached_total_energy_ += seed.energy;
            cumulative_energy_cache_.push_back(cached_total_energy_);
        }

        energy_cache_valid_ = true;
    }
    
    // 基于能量选择种子（优化版本 - 减少锁竞争）
    std::optional<Seed> selectSeedByEnergy() {
        // 首先尝试使用缓存，如果缓存有效就不需要获取corpus锁
        {
            std::lock_guard<std::mutex> cache_lock(energy_cache_mutex_);
            if (energy_cache_valid_ && !cumulative_energy_cache_.empty()) {
                // 使用缓存的数据选择，不需要corpus锁
                if (cached_total_energy_ <= 0.0) {
                    std::uniform_int_distribution<size_t> dist(0, cumulative_energy_cache_.size() - 1);
                    size_t index = dist(random_);

                    // 现在需要获取corpus锁来返回种子
                    std::shared_lock<std::shared_mutex> corpus_lock(corpus_mutex_);
                    if (index < corpus_.size()) {
                        return corpus_[index];
                    }
                }

                std::uniform_real_distribution<double> dist(0.0, cached_total_energy_);
                double r = dist(random_);
                auto it = std::lower_bound(cumulative_energy_cache_.begin(),
                                         cumulative_energy_cache_.end(), r);
                size_t index = std::distance(cumulative_energy_cache_.begin(), it);
                if (index >= cumulative_energy_cache_.size()) {
                    index = cumulative_energy_cache_.size() - 1;
                }

                // 获取corpus锁来返回种子
                std::shared_lock<std::shared_mutex> corpus_lock(corpus_mutex_);
                if (index < corpus_.size()) {
                    return corpus_[index];
                }
            }
        }

        // 缓存无效，需要重建
        std::shared_lock<std::shared_mutex> corpus_lock(corpus_mutex_);
        if (corpus_.empty()) {
            return std::nullopt;
        }

        // 重建缓存
        {
            std::lock_guard<std::mutex> cache_lock(energy_cache_mutex_);
            // 双重检查，避免多线程重复构建
            if (!energy_cache_valid_) {
                cumulative_energy_cache_.clear();
                cumulative_energy_cache_.reserve(corpus_.size());

                cached_total_energy_ = 0.0;
                for (const auto& seed : corpus_) {
                    cached_total_energy_ += seed.energy;
                    cumulative_energy_cache_.push_back(cached_total_energy_);
                }
                energy_cache_valid_ = true;
            }
        }

        // 使用新缓存选择种子
        std::lock_guard<std::mutex> cache_lock(energy_cache_mutex_);
        if (cached_total_energy_ <= 0.0) {
            std::uniform_int_distribution<size_t> dist(0, corpus_.size() - 1);
            return corpus_[dist(random_)];
        }

        std::uniform_real_distribution<double> dist(0.0, cached_total_energy_);
        double r = dist(random_);
        auto it = std::lower_bound(cumulative_energy_cache_.begin(),
                                 cumulative_energy_cache_.end(), r);
        size_t index = std::distance(cumulative_energy_cache_.begin(), it);
        if (index >= corpus_.size()) {
            index = corpus_.size() - 1;
        }
        return corpus_[index];
    }
    
    // 保存崩溃
    void saveCrash(const Seed& crash) {
        // 创建目录
        std::filesystem::create_directories(config_.crash_dir);
        
        // 生成唯一文件名
        std::string timestamp = std::to_string(
            std::chrono::system_clock::to_time_t(crash.created_time));
        
        std::string filename = config_.crash_dir + "/crash_" + 
                              timestamp + ".bin";
        
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(crash.data.data()), 
                      crash.data.size());
        }
    }
    
    // 移除低质量的崩溃种子
    void removeLowQualityCrashes() {
        if (crashes_.empty()) return;
        
        // 移除25%的低质量崩溃种子
        size_t remove_count = std::max(size_t(1), crashes_.size() / 4);
        
        // 评估崩溃种子质量
        std::vector<std::pair<double, size_t>> crash_scores;
        crash_scores.reserve(crashes_.size());
        
        for (size_t i = 0; i < crashes_.size(); ++i) {
            const auto& crash = crashes_[i];
            double score = calculateCrashQuality(crash);
            crash_scores.emplace_back(score, i);
        }
        
        // 按分数排序，移除分数最低的
        std::partial_sort(crash_scores.begin(), 
                         crash_scores.begin() + remove_count,
                         crash_scores.end(),
                         [](const auto& a, const auto& b) {
                             return a.first < b.first;
                         });
        
        // 从后往前移除
        std::vector<size_t> indices_to_remove;
        for (size_t i = 0; i < remove_count; ++i) {
            indices_to_remove.push_back(crash_scores[i].second);
        }
        std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
        
        for (size_t idx : indices_to_remove) {
            crashes_.erase(crashes_.begin() + idx);
        }
    }
    
    // 计算崩溃种子质量
    double calculateCrashQuality(const Seed& crash) const {
        double score = 0.0;
        
        // 崩溃种子的基础价值
        score += 2.0; // 基础分数
        
        // 大小合理性（太小或太大都降低价值）
        if (crash.data.size() >= 8 && crash.data.size() <= 1024) {
            score += 1.0; // 合理大小加分
        } else if (crash.data.size() < 4) {
            score -= 0.5; // 过小减分
        }
        
        // 新崩溃种子优先
        auto age = std::chrono::duration_cast<std::chrono::hours>(
            std::chrono::system_clock::now() - crash.created_time).count();
        score += std::max(0.0, 2.0 - age / 12.0); // 12小时内的崩溃有额外分数
        
        // 如果有覆盖率信息，优先保留有新覆盖率的崩溃
        if (crash.coverage.hasNewCoverage()) {
            score += 1.5;
        }
        
        return score;
    }
};

} // namespace triofuzz
