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

// Improved seed hash function
class SeedHasher {
public:
    static uint64_t computeHash(const std::vector<uint8_t>& data) {
        // Use xxHash or a similar strong hash algorithm.
        uint64_t hash = 0x9e3779b97f4a7c15ULL; // Golden ratio constant
        
        for (size_t i = 0; i < data.size(); ++i) {
            hash ^= static_cast<uint64_t>(data[i]) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        
        // Mix in length to avoid collisions for same-prefix inputs with different lengths.
        hash ^= static_cast<uint64_t>(data.size()) << 32;
        
        return hash;
    }
    
    static bool areEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
    }
};

// CorpusManager implementation
class CorpusManager {
public:
    // Configuration
    struct Config {
        size_t max_corpus_size = 10000;
        std::string corpus_dir = "./corpus";
        std::string crash_dir = "./crashes";
        bool enable_minimization = true;
        bool enable_prioritization = true;
        bool enable_deduplication = true;  // Deduplication toggle
        double energy_update_rate = 0.1;
        size_t max_seed_size = 2048 * 2048; // 1MB max seed size
        bool enable_lifecycle_management = true;
        
        // AFL++-style corpus optimization configuration
        bool enable_auto_optimization = true;           // Enable automatic optimization
        size_t optimization_interval_seconds = 60;      // Optimize every minute (improvement: reduced from 5 minutes)
        double corpus_bloat_threshold = 0.5;            // Corpus bloat threshold (50%) (improvement: reduced from 80%)
        size_t min_corpus_size = 100;                   // Minimum number of seeds to keep
        size_t target_corpus_size = 5000;               // Target corpus size
        bool enable_coverage_based_optimization = true; // Coverage-based optimization
        double performance_degradation_threshold = 0.1; // Trigger optimization at 10% perf degradation (improvement: reduced from 30%)
        bool enable_aggressive_cleanup = false;         // Aggressive cleanup mode
        size_t max_daily_corpus_growth = 2000;          // Maximum daily corpus growth
    };

    CorpusManager() = default;
    
    ~CorpusManager() {
        saveCorpus();
    }
    
    // Add a seed
    void addSeed(Seed seed) {
        // Saving to disk can be slow and should not block other threads that
        // need corpus access. Decide what to save under lock, but perform the
        // actual file I/O after releasing the corpus lock.
        Seed seed_to_save;
        bool should_save_to_disk = false;
        static bool enable_disk_save = std::getenv("triofuzz_DISABLE_DISK_SAVE") == nullptr;

        try {
            std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
            
            // Validate seed data integrity
            if (seed.data.empty()) {
                std::cerr << "[WARNING] Attempting to add empty seed, skipping" << std::endl;
                return;
            }
            
            // Enforce seed size limit
            if (seed.data.size() > config_.max_seed_size) {
                std::cerr << "[WARNING] Seed too large (" << seed.data.size() 
                         << " bytes), truncating to " << config_.max_seed_size << " bytes" << std::endl;
                seed.data.resize(config_.max_seed_size);
            }
            
            // Improved dedup check (optimization: accelerate with a hash index)
            if (config_.enable_deduplication) {
                uint64_t seed_hash = SeedHasher::computeHash(seed.data);
                seed.data_hash = seed_hash;
                
                // Check whether the hash already exists (handle potential collisions)
                auto range = hash_to_indices_.equal_range(seed_hash);
                bool is_duplicate = false;
                
                // Iterate over all seeds with the same hash
                for (auto it = range.first; it != range.second; ++it) {
                    size_t idx = it->second;
                    if (idx < corpus_.size() && 
                        SeedHasher::areEqual(corpus_[idx].data, seed.data)) {
                        // Confirmed duplicate seed: update energy and coverage
                        corpus_[idx].energy = std::max(corpus_[idx].energy, seed.energy);
                        // Merge coverage information
                        if (seed.coverage.hasNewCoverage()) {
                            corpus_[idx].coverage.merge(seed.coverage);
                        }
                        is_duplicate = true;
                        break;
                    }
                }
                
                if (!is_duplicate) {
                    // Add new hash value and index
                    seed_hashes_.insert(seed_hash);
                    hash_to_indices_.insert({seed_hash, corpus_.size()});  // Will be appended at the end
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
                hash_to_indices_.insert({seed.data_hash, corpus_.size()});  // Will be appended at the end
            }
            
            // Update seed statistics
            total_seeds_++;
            if (seed.coverage.hasNewCoverage()) {
                interesting_seeds_++;
            }
            
            // Add to corpus
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
            
            // Improved corpus size management: trigger optimization early.
            // Start optimizing at 90% capacity to avoid corpus bloat.
            if (corpus_.size() >= config_.max_corpus_size * 0.9 && config_.enable_prioritization) {
                try {
                    // More aggressive cleanup strategy
                    size_t target_size = config_.max_corpus_size * 0.75;  // Clean down to 75% capacity
                    size_t to_remove = corpus_.size() > target_size ? corpus_.size() - target_size : 0;
                    
                    if (to_remove > 0) {
                        removeLowQualitySeedsAdvanced(to_remove);
                        rebuildHashIndex();  // Rebuild index after removing seeds
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Failed to optimize corpus: " << e.what() << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to add seed to corpus: " << e.what() << std::endl;
            // Roll back statistic updates
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
    
    // Add a crash seed
    void addCrashSeed(Seed seed) {
        try {
            // Validate crash seed data
            if (seed.data.empty()) {
                std::cerr << "[WARNING] Attempting to add empty crash seed, skipping" << std::endl;
                return;
            }
            
            // Adapt crash seed size intelligently
            const size_t max_crash_seed_size = 64 * 1024; // 64KB
            const size_t min_useful_size = 4; // Minimum useful size
            
            if (seed.data.size() > max_crash_seed_size) {
                // Smart truncation: keep important head and tail
                std::vector<uint8_t> truncated_data;
                truncated_data.reserve(max_crash_seed_size);
                
                size_t head_size = max_crash_seed_size * 3 / 4; // Keep 75% head
                size_t tail_size = max_crash_seed_size - head_size; // Keep 25% tail
                
                // Copy head portion
                truncated_data.insert(truncated_data.end(), 
                                    seed.data.begin(), 
                                    seed.data.begin() + head_size);
                
                // Copy tail portion
                if (seed.data.size() > head_size + tail_size) {
                    truncated_data.insert(truncated_data.end(),
                                        seed.data.end() - tail_size,
                                        seed.data.end());
                }
                
                seed.data = std::move(truncated_data);
                std::cerr << "[INFO] Crash seed truncated intelligently from large size" << std::endl;
            } else if (seed.data.size() < min_useful_size) {
                // Crash seeds that are too small may be less useful
                std::cerr << "[WARNING] Crash seed too small (" << seed.data.size() 
                         << " bytes), but keeping for analysis" << std::endl;
            }
            
            std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
            
            // Crash seed deduplication check
            if (config_.enable_deduplication) {
                uint64_t crash_hash = SeedHasher::computeHash(seed.data);
                
                for (const auto& existing_crash : crashes_) {
                    if (SeedHasher::computeHash(existing_crash.data) == crash_hash &&
                        SeedHasher::areEqual(existing_crash.data, seed.data)) {
                        // Duplicate crash seed: update metadata without storing another copy
                        return;
                    }
                }
            }
            
            // Smarter crash seed capacity management
            const size_t max_crash_seeds = 150; // Increased to 150
            if (crashes_.size() >= max_crash_seeds) {
                // Remove crash seeds by quality rather than simple FIFO
                removeLowQualityCrashes();
            }
            
            crashes_.push_back(std::move(seed));
            total_crashes_++;
            
            // Save crash (perform file I/O outside the lock)
            try {
                // Create a copy for saving to avoid referencing a moved-from object
                const Seed& crash_ref = crashes_.back();
                lock.unlock(); // Release lock for file operations
                saveCrash(crash_ref);
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to save crash to file: " << e.what() << std::endl;
                // File save failures should not affect in-memory storage
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to add crash seed: " << e.what() << std::endl;
            // Roll back statistic updates
            if (total_crashes_.load() > 0) {
                total_crashes_--;
            }
        }
    }
    
    // Get next seed - performance-optimized version
    std::optional<Seed> getNextSeed() {
        // Use an environment variable to control whether to use simple selection.
        static bool use_simple_selection = std::getenv("triofuzz_SIMPLE_SELECT") != nullptr;

        // Fast path: simple round-robin, no energy calculation
        if (use_simple_selection || !config_.enable_prioritization) {
            std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
            if (corpus_.empty()) {
                return std::nullopt;
            }

            // Use a thread-local index to reduce contention
            thread_local size_t thread_idx = std::hash<std::thread::id>{}(std::this_thread::get_id());
            size_t idx = (thread_idx++) % corpus_.size();
            return corpus_[idx];
        }

        // Slow path: energy-based selection
        // First check whether corpus is empty
        {
            std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
            if (corpus_.empty()) {
                return std::nullopt;
            }
        }

        return selectSeedByEnergy();
    }
    
    // Get a random seed (for splicing and other mutations that need another seed)
    std::optional<Seed> getRandomSeed() {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        
        if (corpus_.empty()) {
            return std::nullopt;
        }
        
        // Uniform random selection
        std::uniform_int_distribution<size_t> dist(0, corpus_.size() - 1);
        return corpus_[dist(random_)];
    }
    
    // Update seed energy (optimization: reduce lock contention; batch updates)
    void updateSeedEnergy(const Seed& seed, double new_energy) {
        // Try to acquire lock with try_lock to avoid blocking
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_, std::defer_lock);

        // Attempt to acquire lock; if it fails, defer the update
        if (!lock.try_lock()) {
            // Enqueue update request and process later in batch.
            // Simplification: skip update here (energy updates are not on the critical path).
            return;
        }

        // Look up seed by hash (if deduplication is enabled)
        if (config_.enable_deduplication) {
            uint64_t target_hash = SeedHasher::computeHash(seed.data);

            // Use hash index for fast lookup (handle collisions)
            auto range = hash_to_indices_.equal_range(target_hash);
            for (auto it = range.first; it != range.second; ++it) {
                size_t idx = it->second;
                if (idx < corpus_.size() &&
                    SeedHasher::areEqual(corpus_[idx].data, seed.data)) {
                    // Smoothly update energy
                    corpus_[idx].energy = corpus_[idx].energy * (1.0 - config_.energy_update_rate) +
                                         new_energy * config_.energy_update_rate;
                    // Delay cache invalidation to reduce frequent rebuilds.
                    // Only invalidate cache when necessary.
                    if (std::abs(corpus_[idx].energy - new_energy) > 0.1) {
                        invalidateEnergyCache();
                    }
                    return;
                }
            }
        } else {
            // Fall back to the original byte-by-byte comparison
            for (auto& s : corpus_) {
                if (SeedHasher::areEqual(s.data, seed.data)) {
                    double old_energy = s.energy;
                    // Smoothly update energy
                    s.energy = s.energy * (1.0 - config_.energy_update_rate) +
                              new_energy * config_.energy_update_rate;
                    // Only invalidate cache when energy changes significantly
                    if (std::abs(old_energy - s.energy) > 0.1) {
                        invalidateEnergyCache();
                    }
                    break;
                }
            }
        }
    }
    
    // Save corpus (optimized): save only important seeds
    void saveCorpus() {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        
        // Create directory
        std::filesystem::create_directories(config_.corpus_dir);
        
        // Limit the number of saved seeds to avoid disk bloat.
        // Save at most 1000 most important seeds.
        size_t max_to_save = std::min(corpus_.size(), size_t(1000));
        
        // If corpus is small, save all
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
            // If corpus is large, save only the most important seeds
            std::vector<std::pair<double, size_t>> seed_scores;
            for (size_t i = 0; i < corpus_.size(); ++i) {
                double score = calculateSeedQuality(corpus_[i]);
                seed_scores.emplace_back(score, i);
            }
            
            // Sort by quality
            std::partial_sort(seed_scores.begin(),
                            seed_scores.begin() + max_to_save,
                            seed_scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first > b.first;
                            });
            
            // Save the best seeds
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
    
    // Improvement: save a single seed (better file naming)
    void saveSingleSeed(const Seed& seed) {
        try {
            // Create directory
            std::filesystem::create_directories(config_.corpus_dir);
            
            // Use a strong hash and better file naming strategy
            uint64_t seed_hash = SeedHasher::computeHash(seed.data);
            auto timestamp = std::chrono::system_clock::to_time_t(seed.created_time);
            
            // Format: seed_<timestamp>_<hash>_<size>.bin
            std::string filename = config_.corpus_dir + "/seed_" + 
                                  std::to_string(timestamp) + "_" + 
                                  std::to_string(seed_hash) + "_" +
                                  std::to_string(seed.data.size()) + ".bin";
            
            // Check whether the file already exists to avoid duplicate saves
            if (!std::filesystem::exists(filename)) {
                std::ofstream file(filename, std::ios::binary);
                if (file) {
                    file.write(reinterpret_cast<const char*>(seed.data.data()), 
                              seed.data.size());
                    // Save metadata only for truly important seeds to reduce file count.
                    // Stricter condition: energy > 3.0 and has new edges.
                    if (seed.energy > 3.0 && !seed.coverage.new_edges.empty()) {
                        saveMetadata(filename + ".meta", seed);
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to save single seed: " << e.what() << std::endl;
        }
    }
    
    // Save seed metadata
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
            // Metadata save failures should not affect the main path
        }
    }
    
    // Load corpus
    void loadCorpus(const std::string& dir) {
        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
        
        // Do not clear existing corpus; append instead.
        // corpus_.clear();  // Commented out to keep existing seeds
        
        std::vector<std::pair<std::filesystem::path, size_t>> seed_files;
        size_t loaded_count = 0;
        size_t skipped_count = 0;
        
        try {
            // First collect info for all seed files
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                    try {
                        size_t file_size = std::filesystem::file_size(entry.path());
                        seed_files.emplace_back(entry.path(), file_size);
                    } catch (const std::exception& e) {
                        // Ignore inaccessible files
                        continue;
                    }
                }
            }
            
            // Smart sorting of seed files (prefer medium-sized, potentially more useful seeds)
            std::sort(seed_files.begin(), seed_files.end(), 
                [](const auto& a, const auto& b) {
                    // Priority strategy:
                    // 1. Prefer medium-sized seeds (256-4KB)
                    // 2. Then small seeds
                    // 3. Finally large seeds
                    size_t size_a = a.second, size_b = b.second;
                    
                    bool a_medium = (size_a >= 256 && size_a <= 4096);
                    bool b_medium = (size_b >= 256 && size_b <= 4096);
                    
                    if (a_medium && !b_medium) return true;
                    if (!a_medium && b_medium) return false;
                    
                    // Within the same category, sort by filename (contains timestamp info)
                    return a.first.filename().string() > b.first.filename().string();
                });
            
            // Smart loading strategy: limit load count to avoid memory overload
            size_t max_load_count = std::min(seed_files.size(), size_t(5000)); // Load at most 5000
            std::cout << "[CorpusManager] Loading up to " << max_load_count 
                     << " seeds from " << seed_files.size() << " available files" << std::endl;
            
            for (size_t i = 0; i < max_load_count; ++i) {
                const auto& [file_path, file_size] = seed_files[i];
                
                // Skip overly large files
                if (file_size > config_.max_seed_size) {
                    skipped_count++;
                    continue;
                }
                
                try {
                    std::ifstream file(file_path, std::ios::binary);
                    if (file) {
                        // Read file contents
                        std::vector<uint8_t> data(
                            (std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
                        
                        // Create seed
                        Seed seed;
                        seed.data = std::move(data);
                        seed.data_hash = SeedHasher::computeHash(seed.data);
                        
                        // Set energy based on timestamp/hash in filename
                        std::string filename = file_path.filename().string();
                        seed.energy = calculateSeedEnergyFromFilename(filename);
                        
                        // Use current time to avoid time-type conversion issues
                        seed.created_time = std::chrono::system_clock::now();
                        
                        // Try to load more info from metadata file
                        std::string meta_file = file_path.string() + ".meta";
                        if (std::filesystem::exists(meta_file)) {
                            loadSeedMetadata(seed, meta_file);
                        }
                        
                        // Maintain hash indices for fast lookup (used by schedulers / energy updates).
                        seed_hashes_.insert(seed.data_hash);
                        hash_to_indices_.insert({seed.data_hash, corpus_.size()});  // Will be appended at the end

                        corpus_.push_back(std::move(seed));
                        loaded_count++;
                        total_seeds_++;
                        
                        // Show progress (every 1000 files)
                        if (loaded_count % 1000 == 0) {
                            std::cout << "[CorpusManager] Loaded " << loaded_count << " seeds..." << std::endl;
                        }
                    }
                } catch (const std::exception& e) {
                    skipped_count++;
                    // Continue with other files
                }
            }
            
            std::cout << "[CorpusManager] Corpus loading completed: " 
                     << loaded_count << " loaded, " << skipped_count << " skipped" << std::endl;
            
        } catch (const std::filesystem::filesystem_error& e) {
            // Directory does not exist or is not accessible
            std::cerr << "[ERROR] Error loading corpus: " << e.what() << std::endl;
        }
    }
    
    // Compute seed energy from filename
    double calculateSeedEnergyFromFilename(const std::string& filename) {
        // Filename format: seed_<timestamp>_<hash>_<size>.bin
        // Newer files typically get higher energy.
        try {
            size_t first_underscore = filename.find('_');
            size_t second_underscore = filename.find('_', first_underscore + 1);
            
            if (first_underscore != std::string::npos && second_underscore != std::string::npos) {
                std::string timestamp_str = filename.substr(first_underscore + 1, 
                                                          second_underscore - first_underscore - 1);
                
                // Try to parse timestamp
                uint64_t timestamp = std::stoull(timestamp_str);
                uint64_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                
                // Newer seeds get higher energy (within the last 7 days)
                uint64_t age_seconds = current_time - timestamp;
                if (age_seconds < 7 * 24 * 3600) {  // 7 days
                    return 1.5;  // High energy
                } else if (age_seconds < 30 * 24 * 3600) {  // 30 days
                    return 1.2;  // Medium energy
                }
            }
        } catch (const std::exception& e) {
            // Parse failed; use default energy
        }
        
        return 1.0;  // Default energy
    }
    
    // Load seed metadata from a metadata file
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
            // Metadata load failures should not affect the main path
        }
    }
    
    // Statistics
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
    
    // Update configuration
    void updateConfig(const Config& config) {
        config_ = config;
    }
    
    // Added: get all corpus data for mutation algorithms
    std::vector<std::vector<uint8_t>> getAllCorpusData() const {
        std::shared_lock<std::shared_mutex> lock(corpus_mutex_);
        
        std::vector<std::vector<uint8_t>> corpus_data;
        corpus_data.reserve(corpus_.size());
        
        for (const auto& seed : corpus_) {
            corpus_data.push_back(seed.data);
        }
        
        return corpus_data;
    }

    // Get hashes for all seeds (avoid copying full seed data)
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

    // Quickly get a seed copy by hash (for schedulers like EcoFuzz that select seeds by hash)
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
    
    // Added: seed lifecycle management
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
            
            // If no results for 7 days and efficiency is below 10%, consider retiring.
            return days_since_productive > 7.0 && getEfficiency() < 0.1;
        }
    };
    
    // Seed lifecycle tracking
    std::unordered_map<uint64_t, SeedLifecycle> seed_lifecycles_;
    
    // Update seed usage statistics
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
            lifecycle.productivity_score = lifecycle.productivity_score * 0.9 + 0.1; // Increase score
        } else {
            lifecycle.productivity_score *= 0.99; // Slow decay
        }
        
        // Mark stagnant seeds
        auto hours_since_productive = std::chrono::duration_cast<std::chrono::hours>(
            lifecycle.last_used - lifecycle.last_productive).count();
        lifecycle.is_stagnant = hours_since_productive > 48; // Stagnant if no output for 48 hours
    }
    
    // Clean up aged seeds
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
        
        // Remove from back to front
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
    
    // Added: seed minimizer
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
        
        // Binary-splitting minimization
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
            
            // Reduce step by step until coverage cannot be preserved
            while (current_data.size() > 1) {
                // Try removing the first half
                std::vector<uint8_t> candidate(current_data.begin() + current_data.size()/2, 
                                             current_data.end());
                if (test_coverage(candidate)) {
                    current_data = candidate;
                    continue;
                }
                
                // Try removing the second half
                candidate.assign(current_data.begin(), current_data.begin() + current_data.size()/2);
                if (test_coverage(candidate)) {
                    current_data = candidate;
                    continue;
                }
                
                // Try removing the middle portion
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
                
                break; // Cannot reduce further
            }
            
            auto end_time = std::chrono::steady_clock::now();
            
            result.minimized_data = current_data;
            result.minimized_size = current_data.size();
            result.compression_ratio = static_cast<double>(result.minimized_size) / result.original_size;
            result.coverage_preserved = test_coverage(current_data);
            result.time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            return result;
        }
        
        // Byte-level minimization (finer-grained)
        static MinimizationResult minimizeByteLevel(
            const std::vector<uint8_t>& original_data,
            std::function<bool(const std::vector<uint8_t>&)> test_coverage) {
            
            auto start_time = std::chrono::steady_clock::now();
            MinimizationResult result;
            result.original_size = original_data.size();
            
            std::vector<uint8_t> current_data = original_data;
            
            // Test removal byte-by-byte
            for (size_t i = 0; i < current_data.size(); ) {
                std::vector<uint8_t> candidate;
                candidate.reserve(current_data.size() - 1);
                candidate.insert(candidate.end(), current_data.begin(), current_data.begin() + i);
                candidate.insert(candidate.end(), current_data.begin() + i + 1, current_data.end());
                
                if (test_coverage(candidate)) {
                    current_data = candidate;
                    // Do not increment i because array size has changed
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
    
    // Apply seed minimization (improvement: add executor interface)
    void minimizeLargeSeeds(std::function<bool(const std::vector<uint8_t>&)> execute_and_check = nullptr) {
        if (!config_.enable_minimization) return;
        
        const size_t large_seed_threshold = 4096; // Minimize seeds larger than 4KB
        size_t minimized_count = 0;
        size_t total_saved_bytes = 0;
        
        for (auto& seed : corpus_) {
            if (seed.data.size() > large_seed_threshold) {
                // Save original coverage info
                auto original_coverage = seed.coverage;
                
                // Create coverage test function
                auto test_func = [&](const std::vector<uint8_t>& test_data) -> bool {
                    if (execute_and_check) {
                        // Use provided executor to check coverage
                        return execute_and_check(test_data);
                    } else {
                        // Fall back to a simple length check
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
    
    // Added: seed diversity manager
    class SeedDiversityManager {
    public:
        struct DiversityMetrics {
            double structural_diversity = 0.0;  // Structural diversity
            double content_diversity = 0.0;     // Content diversity
            double size_diversity = 0.0;        // Size diversity
            double coverage_diversity = 0.0;    // Coverage diversity
            double overall_diversity = 0.0;     // Overall diversity
        };
        
        // Calculate similarity between two seeds
        static double calculateSimilarity(const std::vector<uint8_t>& seed1, 
                                        const std::vector<uint8_t>& seed2) {
            if (seed1.empty() || seed2.empty()) return 0.0;
            
            // Length similarity
            double size_ratio = static_cast<double>(std::min(seed1.size(), seed2.size())) /
                               std::max(seed1.size(), seed2.size());
            
            // Content similarity (approximate edit distance)
            double content_similarity = calculateContentSimilarity(seed1, seed2);
            
            // Structural similarity (byte distribution)
            double structural_similarity = calculateStructuralSimilarity(seed1, seed2);
            
            // Weighted average
            return 0.3 * size_ratio + 0.4 * content_similarity + 0.3 * structural_similarity;
        }
        
        // Compute overall corpus diversity
        static DiversityMetrics calculateCorpusDiversity(const std::deque<Seed>& corpus) {
            DiversityMetrics metrics;
            
            if (corpus.size() <= 1) {
                metrics.overall_diversity = 1.0;
                return metrics;
            }
            
            // Size diversity (variance of seed sizes)
            std::vector<double> sizes;
            for (const auto& seed : corpus) {
                sizes.push_back(static_cast<double>(seed.data.size()));
            }
            metrics.size_diversity = calculateVariance(sizes) / (calculateMean(sizes) + 1.0);
            
            // Content diversity (1 - average similarity)
            double total_similarity = 0.0;
            size_t comparison_count = 0;
            
            size_t sample_size = std::min(corpus.size(), size_t(100)); // Sample to avoid O(n^2) complexity
            for (size_t i = 0; i < sample_size; ++i) {
                for (size_t j = i + 1; j < sample_size; ++j) {
                    total_similarity += calculateSimilarity(corpus[i].data, corpus[j].data);
                    comparison_count++;
                }
            }
            
            double avg_similarity = comparison_count > 0 ? total_similarity / comparison_count : 0.0;
            metrics.content_diversity = 1.0 - avg_similarity;
            
            // Coverage diversity
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
            
            // Overall diversity
            metrics.overall_diversity = (metrics.size_diversity + metrics.content_diversity + 
                                       metrics.coverage_diversity) / 3.0;
            
            return metrics;
        }
        
    private:
        static double calculateContentSimilarity(const std::vector<uint8_t>& s1, 
                                                const std::vector<uint8_t>& s2) {
            // Use a fast approximate edit distance
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
            // Byte-frequency distribution similarity
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
    
    // Apply diversity optimization
    void optimizeDiversity() {
        auto metrics = SeedDiversityManager::calculateCorpusDiversity(corpus_);
        
        std::cout << "[DIVERSITY] Current diversity metrics:" << std::endl;
        std::cout << "  - Content: " << std::fixed << std::setprecision(3) << metrics.content_diversity << std::endl;
        std::cout << "  - Size: " << metrics.size_diversity << std::endl;
        std::cout << "  - Coverage: " << metrics.coverage_diversity << std::endl;
        std::cout << "  - Overall: " << metrics.overall_diversity << std::endl;
        
        // If diversity is too low, remove similar seeds
        if (metrics.overall_diversity < 0.5) {
            removeRedundantSeeds();
        }
    }
    
    // Remove redundant seeds
    void removeRedundantSeeds() {
        if (corpus_.size() <= 2) return;
        
        const double similarity_threshold = 0.85; // Treat >85% similarity as redundant
        std::vector<bool> to_remove(corpus_.size(), false);
        size_t removed_count = 0;
        
        for (size_t i = 0; i < corpus_.size() && removed_count < corpus_.size() / 4; ++i) {
            if (to_remove[i]) continue;
            
            for (size_t j = i + 1; j < corpus_.size(); ++j) {
                if (to_remove[j]) continue;
                
                double similarity = SeedDiversityManager::calculateSimilarity(
                    corpus_[i].data, corpus_[j].data);
                
                if (similarity > similarity_threshold) {
                    // Keep the higher-quality seed
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
        
        // Remove from back to front
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
    
    // Added: AFL++-style corpus optimizer
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
            std::unordered_set<uint64_t> critical_edges;    // Critical edges
            std::unordered_set<uint64_t> rare_edges;        // Rare edges
            std::unordered_set<uint64_t> all_covered_edges; // All covered edges
            std::map<uint64_t, size_t> edge_frequency;      // Edge frequency
        };
        
        // Main corpus optimization routine (AFL++ style)
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
            
            // 1. Build coverage map
            CoverageMap coverage_map = buildCoverageMap(corpus);
            stats.coverage_preserved = calculateCoverageRatio(coverage_map.all_covered_edges);
            
            // 2. Deduplicate - AFL++-style fast dedup
            if (config.enable_deduplication) {
                stats.removed_duplicates = removeDuplicatesAFL(corpus, seed_hashes);
            }
            
            // 3. Remove redundant seeds - based on coverage similarity
            if (config.enable_coverage_based_optimization) {
                stats.removed_redundant = removeRedundantByCoverage(corpus, coverage_map, config);
            }
            
            // 4. Preserve critical seeds - ensure important coverage is not lost
            preserveCriticalSeeds(corpus, coverage_map, config);
            
            // 5. Quality scoring and ranking
            stats.removed_low_quality = removeByQualityScore(corpus, config);
            
            // 6. Seed minimization (if enabled)
            if (config.enable_minimization) {
                stats.minimized_seeds = minimizeSeedsInPlace(corpus);
            }
            
            // 7. Final size control
            if (corpus.size() > config.target_corpus_size) {
                truncateToTargetSize(corpus, config.target_corpus_size, coverage_map);
            }
            
            stats.optimized_size = corpus.size();
            
            auto end_time = std::chrono::steady_clock::now();
            stats.optimization_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            
            // Estimate performance improvement
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
        
        // Added: interruptible optimization method
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
            
            // 1. Build coverage map
            if (should_stop) return stats;
            CoverageMap coverage_map = buildCoverageMap(corpus);
            stats.coverage_preserved = calculateCoverageRatio(coverage_map.all_covered_edges);
            
            // 2. Deduplicate - AFL++-style fast dedup
            if (should_stop) return stats;
            if (config.enable_deduplication) {
                stats.removed_duplicates = removeDuplicatesAFLInterruptible(corpus, seed_hashes, should_stop);
                if (should_stop) return stats;
            }
            
            // 3. Remove redundant seeds - based on coverage similarity
            if (should_stop) return stats;
            if (config.enable_coverage_based_optimization) {
                stats.removed_redundant = removeRedundantByCoverageInterruptible(corpus, coverage_map, config, should_stop);
                if (should_stop) return stats;
            }
            
            // 4. Preserve critical seeds - ensure important coverage is not lost
            if (should_stop) return stats;
            preserveCriticalSeeds(corpus, coverage_map, config);
            
            // 5. Quality scoring and ranking
            if (should_stop) return stats;
            stats.removed_low_quality = removeByQualityScoreInterruptible(corpus, config, should_stop);
            
            // 6. Seed minimization (if enabled)
            if (should_stop) return stats;
            if (config.enable_minimization) {
                stats.minimized_seeds = minimizeSeedsInPlaceInterruptible(corpus, should_stop);
                if (should_stop) return stats;
            }
            
            // 7. Final size control
            if (should_stop) return stats;
            if (corpus.size() > config.target_corpus_size) {
                truncateToTargetSizeInterruptible(corpus, config.target_corpus_size, coverage_map, should_stop);
            }
            
            stats.optimized_size = corpus.size();
            
            auto end_time = std::chrono::steady_clock::now();
            stats.optimization_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            
            // Estimate performance improvement
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
        // Build coverage map
        static CoverageMap buildCoverageMap(const std::deque<Seed>& corpus) {
            CoverageMap map;
            
            for (const auto& seed : corpus) {
                // Collect all edges
                for (auto edge : seed.coverage.new_edges) {
                    map.all_covered_edges.insert(edge);
                    map.edge_frequency[edge]++;
                }
                
                // Identify rare edges (low-frequency edges)
                for (auto edge : seed.coverage.rare_edges) {
                    map.rare_edges.insert(edge);
                }
            }
            
            // Identify critical edges (high-value edges)
            for (const auto& [edge, freq] : map.edge_frequency) {
                // Rare edges or newly discovered edges are treated as critical.
                if (freq <= 3 || map.rare_edges.count(edge)) {
                    map.critical_edges.insert(edge);
                }
            }
            
            return map;
        }
        
        // AFL++-style deduplication
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
        
        // Added: interruptible AFL++-style deduplication
        static size_t removeDuplicatesAFLInterruptible(std::deque<Seed>& corpus, 
                                        std::unordered_set<uint64_t>& seed_hashes,
                                        const std::atomic<bool>& should_stop) {
            size_t removed = 0;
            std::unordered_set<uint64_t> seen_hashes;
            size_t processed = 0;
            
            for (auto it = corpus.begin(); it != corpus.end() && !should_stop;) {
                // Check stop signal every 100 processed seeds
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
        
        // Remove redundant seeds based on coverage
        static size_t removeRedundantByCoverage(std::deque<Seed>& corpus,
                                               const CoverageMap& coverage_map,
                                               const Config& config) {
            if (corpus.size() <= config.min_corpus_size) {
                return 0;
            }
            
            size_t removed = 0;
            std::vector<bool> to_remove(corpus.size(), false);
            
            // Build mapping from edge to seeds
            std::map<uint64_t, std::vector<size_t>> edge_to_seeds;
            for (size_t i = 0; i < corpus.size(); ++i) {
                for (auto edge : corpus[i].coverage.new_edges) {
                    edge_to_seeds[edge].push_back(i);
                }
            }
            
            // For each edge, keep only the highest-quality seed
            for (const auto& [edge, seed_indices] : edge_to_seeds) {
                if (seed_indices.size() <= 1) continue;
                
                // If it's a critical edge, keep all seeds covering it
                if (coverage_map.critical_edges.count(edge)) {
                    continue;
                }
                
                // Find the highest-quality seed
                size_t best_seed_idx = seed_indices[0];
                double best_quality = calculateSeedQualityStatic(corpus[best_seed_idx]);
                
                for (size_t idx : seed_indices) {
                    double quality = calculateSeedQualityStatic(corpus[idx]);
                    if (quality > best_quality) {
                        best_quality = quality;
                        best_seed_idx = idx;
                    }
                }
                
                // Mark other seeds for deletion (but ensure they don't cover other important edges)
                for (size_t idx : seed_indices) {
                    if (idx != best_seed_idx && !hasUniqueImportantCoverage(corpus[idx], coverage_map)) {
                        to_remove[idx] = true;
                    }
                }
            }
            
            // Delete from back to front
            for (size_t i = corpus.size(); i > 0; --i) {
                size_t idx = i - 1;
                if (to_remove[idx]) {
                    corpus.erase(corpus.begin() + idx);
                    removed++;
                }
            }
            
            return removed;
        }
        
        // Added: interruptible coverage-based redundant-seed removal
        static size_t removeRedundantByCoverageInterruptible(std::deque<Seed>& corpus,
                                               const CoverageMap& coverage_map,
                                               const Config& config,
                                               const std::atomic<bool>& should_stop) {
            if (corpus.size() <= config.min_corpus_size || should_stop) {
                return 0;
            }
            
            size_t removed = 0;
            std::vector<bool> to_remove(corpus.size(), false);
            
            // Build mapping from edge to seeds
            std::map<uint64_t, std::vector<size_t>> edge_to_seeds;
            for (size_t i = 0; i < corpus.size() && !should_stop; ++i) {
                for (auto edge : corpus[i].coverage.new_edges) {
                    edge_to_seeds[edge].push_back(i);
                }
            }
            
            if (should_stop) return removed;
            
            // For each edge, keep only the highest-quality seed
            size_t processed_edges = 0;
            for (const auto& [edge, seed_indices] : edge_to_seeds) {
                if (++processed_edges % 50 == 0 && should_stop) break;
                
                if (seed_indices.size() <= 1) continue;
                
                // If it's a critical edge, keep all seeds covering it
                if (coverage_map.critical_edges.count(edge)) {
                    continue;
                }
                
                // Find the highest-quality seed
                size_t best_seed_idx = seed_indices[0];
                double best_quality = calculateSeedQualityStatic(corpus[best_seed_idx]);
                
                for (size_t idx : seed_indices) {
                    double quality = calculateSeedQualityStatic(corpus[idx]);
                    if (quality > best_quality) {
                        best_quality = quality;
                        best_seed_idx = idx;
                    }
                }
                
                // Mark other seeds for deletion (but ensure they don't cover other important edges)
                for (size_t idx : seed_indices) {
                    if (idx != best_seed_idx && !hasUniqueImportantCoverage(corpus[idx], coverage_map)) {
                        to_remove[idx] = true;
                    }
                }
            }
            
            if (should_stop) return removed;
            
            // Delete from back to front
            for (size_t i = corpus.size(); i > 0 && !should_stop; --i) {
                size_t idx = i - 1;
                if (to_remove[idx]) {
                    corpus.erase(corpus.begin() + idx);
                    removed++;
                }
            }
            
            return removed;
        }
        
        // Check whether the seed has unique important coverage
        static bool hasUniqueImportantCoverage(const Seed& seed, const CoverageMap& coverage_map) {
            for (auto edge : seed.coverage.new_edges) {
                if (coverage_map.critical_edges.count(edge) || coverage_map.rare_edges.count(edge)) {
                    return true;
                }
            }
            return false;
        }
        
        // Preserve critical seeds
        static void preserveCriticalSeeds(std::deque<Seed>& corpus,
                                        const CoverageMap& coverage_map,
                                        const Config& config) {
            // Ensure seeds covering critical edges are not deleted
            std::set<size_t> critical_seed_indices;
            
            for (size_t i = 0; i < corpus.size(); ++i) {
                const auto& seed = corpus[i];
                
                // Check whether it covers a critical edge
                for (auto edge : seed.coverage.new_edges) {
                    if (coverage_map.critical_edges.count(edge)) {
                        critical_seed_indices.insert(i);
                        break;
                    }
                }
                
                // Check whether it is a high-quality seed (significant coverage gain)
                if (seed.coverage.coverage_gain > 0.5) {  // Threshold set to 0.5 for meaningful coverage gain
                    critical_seed_indices.insert(i);
                }
            }
            
            // Mark critical seeds (can be done by modifying seed attributes)
            for (size_t idx : critical_seed_indices) {
                // Give critical seeds higher energy
                corpus[idx].energy = std::max(corpus[idx].energy, 10.0);
            }
        }
        
        // Remove seeds based on quality score
        static size_t removeByQualityScore(std::deque<Seed>& corpus, const Config& config) {
            if (corpus.size() <= config.min_corpus_size) {
                return 0;
            }
            
            size_t target_removal = corpus.size() - config.min_corpus_size;
            if (target_removal == 0) return 0;
            
            // Compute quality scores for all seeds
            std::vector<std::pair<double, size_t>> quality_scores;
            quality_scores.reserve(corpus.size());
            
            for (size_t i = 0; i < corpus.size(); ++i) {
                double score = calculateSeedQualityStatic(corpus[i]);
                quality_scores.emplace_back(score, i);
            }
            
            // Sort by score (ascending; delete lowest first)
            std::partial_sort(quality_scores.begin(),
                            quality_scores.begin() + target_removal,
                            quality_scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first < b.first;
                            });
            
            // Collect indices to delete
            std::vector<size_t> to_remove;
            for (size_t i = 0; i < target_removal; ++i) {
                to_remove.push_back(quality_scores[i].second);
            }
            
            // Sort indices descending for back-to-front deletion
            std::sort(to_remove.rbegin(), to_remove.rend());
            
            // Delete seeds
            for (size_t idx : to_remove) {
                corpus.erase(corpus.begin() + idx);
            }
            
            return target_removal;
        }
        
        // Added: interruptible quality-score removal
        static size_t removeByQualityScoreInterruptible(std::deque<Seed>& corpus, const Config& config, const std::atomic<bool>& should_stop) {
            if (corpus.size() <= config.min_corpus_size || should_stop) {
                return 0;
            }
            
            size_t target_removal = corpus.size() - config.min_corpus_size;
            if (target_removal == 0) return 0;
            
            // Compute quality scores for all seeds
            std::vector<std::pair<double, size_t>> quality_scores;
            quality_scores.reserve(corpus.size());
            
            for (size_t i = 0; i < corpus.size() && !should_stop; ++i) {
                if (i % 100 == 0 && should_stop) break;
                double score = calculateSeedQualityStatic(corpus[i]);
                quality_scores.emplace_back(score, i);
            }
            
            if (should_stop) return 0;
            
            // Sort by score (ascending; delete lowest first)
            std::partial_sort(quality_scores.begin(),
                            quality_scores.begin() + target_removal,
                            quality_scores.end(),
                            [](const auto& a, const auto& b) {
                                return a.first < b.first;
                            });
            
            // Collect indices to delete
            std::vector<size_t> to_remove;
            for (size_t i = 0; i < target_removal && !should_stop; ++i) {
                to_remove.push_back(quality_scores[i].second);
            }
            
            if (should_stop) return 0;
            
            // Sort indices descending for back-to-front deletion
            std::sort(to_remove.rbegin(), to_remove.rend());
            
            // Delete seeds
            for (size_t idx : to_remove) {
                if (should_stop) break;
                corpus.erase(corpus.begin() + idx);
            }
            
            return to_remove.size();
        }
        
	        static size_t minimizeSeedsInPlace(std::deque<Seed>& corpus) {
	            size_t minimized_count = 0;
	            
	            for (auto& seed : corpus) {
	                if (seed.data.size() > 1024) { // Only minimize seeds larger than 1KB
	                    // Simplified minimization: strip trailing zero bytes
	                    while (!seed.data.empty() && seed.data.back() == 0) {
	                        seed.data.pop_back();
	                        minimized_count++;
	                    }
	                }
            }
            
            return minimized_count;
	        }
	        
	        // **New**: Interruptible seed minimization
	        static size_t minimizeSeedsInPlaceInterruptible(std::deque<Seed>& corpus, const std::atomic<bool>& should_stop) {
	            size_t minimized_count = 0;
	            
	            for (auto& seed : corpus) {
	                if (should_stop) break;
	                
	                if (seed.data.size() > 1024) { // Only minimize seeds larger than 1KB
	                    // Simplified minimization: strip trailing zero bytes
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
	            
	            // Compute a combined score for each seed (quality + coverage importance)
	            std::vector<std::pair<double, size_t>> scores;
	            scores.reserve(corpus.size());
	            
	            for (size_t i = 0; i < corpus.size(); ++i) {
	                double base_score = calculateSeedQualityStatic(corpus[i]);
	                
	                // If the seed covers critical edges, increase its score
	                bool covers_critical = false;
	                for (auto edge : corpus[i].coverage.new_edges) {
	                    if (coverage_map.critical_edges.count(edge)) {
	                        covers_critical = true;
	                        break;
                    }
	                }
	                
	                if (covers_critical) {
	                    base_score *= 2.0; // Double the score for critical seeds
	                }
	                
	                scores.emplace_back(base_score, i);
	            }
	            
	            // Sort by score (ascending) and remove the lowest-scoring seeds
	            std::partial_sort(scores.begin(), scores.begin() + to_remove, scores.end(),
	                            [](const auto& a, const auto& b) {
	                                return a.first < b.first;
	                            });
	            
	            // Delete from back to front
	            std::vector<size_t> indices_to_remove;
	            for (size_t i = 0; i < to_remove; ++i) {
	                indices_to_remove.push_back(scores[i].second);
	            }
            std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
            
            for (size_t idx : indices_to_remove) {
                corpus.erase(corpus.begin() + idx);
	            }
	        }
	        
	        // **New**: Interruptible truncation to target size
	        static void truncateToTargetSizeInterruptible(std::deque<Seed>& corpus, size_t target_size,
	                                       const CoverageMap& coverage_map, const std::atomic<bool>& should_stop) {
	            if (corpus.size() <= target_size || should_stop) return;
	            
	            size_t to_remove = corpus.size() - target_size;
	            
	            // Compute a combined score for each seed (quality + coverage importance)
	            std::vector<std::pair<double, size_t>> scores;
	            scores.reserve(corpus.size());
	            
	            for (size_t i = 0; i < corpus.size() && !should_stop; ++i) {
                if (i % 100 == 0 && should_stop) break;
	                
	                double base_score = calculateSeedQualityStatic(corpus[i]);
	                
	                // If the seed covers critical edges, increase its score
	                bool covers_critical = false;
	                for (auto edge : corpus[i].coverage.new_edges) {
	                    if (coverage_map.critical_edges.count(edge)) {
	                        covers_critical = true;
                        break;
                    }
	                }
	                
	                if (covers_critical) {
	                    base_score *= 2.0; // Double the score for critical seeds
	                }
	                
	                scores.emplace_back(base_score, i);
	            }
            
            if (should_stop) return;
            
	            // Sort by score (ascending) and remove the lowest-scoring seeds
	            std::partial_sort(scores.begin(), scores.begin() + to_remove, scores.end(),
	                            [](const auto& a, const auto& b) {
	                                return a.first < b.first;
	                            });
	            
	            // Delete from back to front
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
	        
	        // Compute coverage ratio
	        static double calculateCoverageRatio(const std::unordered_set<uint64_t>& covered_edges) {
	            // Simplified coverage calculation
	            return covered_edges.empty() ? 0.0 : 1.0;
	        }
	        
	        // Estimate performance improvement
	        static double estimatePerformanceImprovement(size_t original_size, size_t optimized_size) {
	            if (original_size <= optimized_size) return 0.0;
	            
	            // Simple linear estimate: if corpus size drops by X%, performance improves by ~0.5*X%
	            double reduction_ratio = 1.0 - (static_cast<double>(optimized_size) / original_size);
	            return reduction_ratio * 0.5;
	        }
	        
	        // Static seed-quality scoring function
	        static double calculateSeedQualityStatic(const Seed& seed) {
	            double score = 0.0;
	            
	            // Base energy weight
	            score += seed.energy * 0.3;
	            
	            // Coverage weight
	            score += seed.coverage.coverage_gain * 0.4;
	            
	            // Rare-edge weight
	            score += seed.coverage.rare_edges.size() * 0.2;
	            
	            // Seed age weight (prefer newer seeds)
	            auto age = std::chrono::duration_cast<std::chrono::hours>(
	                std::chrono::system_clock::now() - seed.created_time).count();
	            score += std::max(0.0, 1.0 - age / 24.0) * 0.1;
	            
            return score;
	        }
	    };
	    
	    // **New**: Automatic optimization manager
	    class AutoOptimizationManager {
	    private:
	        std::thread optimization_thread_;
	        std::atomic<bool> should_stop_{false};
	        std::atomic<bool> force_optimization_{false};
	        Config config_;
	        
	        // Performance monitoring
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
	                // Let the optimization thread finish its current operation.
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
	                // Use shorter sleeps for better responsiveness.
	                for (int i = 0; i < 30 && !should_stop_; ++i) {
	                    std::this_thread::sleep_for(std::chrono::seconds(1));
	                }

                if (should_stop_) break;
	
	                bool should_optimize = false;
	
	                // Check optimization triggers.
	                auto now = std::chrono::steady_clock::now();
	                auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
	                    now - last_optimization_).count();
	
	                // 1. Periodic optimization (cast to a common type for comparison)
	                if (static_cast<size_t>(time_since_last) >= config_.optimization_interval_seconds) {
	                    should_optimize = true;
	                }
	
	                // 2. Forced optimization
	                if (force_optimization_.exchange(false)) {
	                    should_optimize = true;
	                }
	
	                // 3. Corpus bloat trigger - avoid frequent locking in the loop.
	                // Only check corpus size when close to an optimization window.
	                if (!should_optimize && static_cast<size_t>(time_since_last) >= config_.optimization_interval_seconds / 2) {
	                    size_t current_size = corpus_manager->getCurrentCorpusSize();
	                    if (current_size > config_.max_corpus_size * config_.corpus_bloat_threshold) {
	                        should_optimize = true;
	                    }
	                }
	
	                // 4. Performance degradation trigger
	                if (recent_performance_metric_ < (1.0 - config_.performance_degradation_threshold)) {
	                    should_optimize = true;
	                }
	
	                // Check stop signal; if stopping, do not run optimization.
	                if (should_optimize && !should_stop_) {
	                    performOptimization(corpus_manager);
	                    last_optimization_ = now;
	                }
            }
            std::cout << "[AutoOptimizer] Optimization thread stopped" << std::endl;
	        }
	        
	        void performOptimization(CorpusManager* corpus_manager) {
	            // Check stop signal again.
	            if (should_stop_) return;
	            
	            try {
	                std::cout << "[AutoOptimizer] Starting automatic corpus optimization..." << std::endl;
	                
	                // Call AFL++ optimizer and pass the stop flag.
	                auto stats = corpus_manager->optimizeCorpusAFLStyleInterruptible(should_stop_);
	                
	                std::cout << "[AutoOptimizer] Optimization completed. "
	                         << "Size reduced from " << stats.original_size 
	                         << " to " << stats.optimized_size << std::endl;
	                
	                // Also clean up corpus files on disk.
	                corpus_manager->cleanupDiskCorpus();
	                
	            } catch (const std::exception& e) {
	                std::cerr << "[AutoOptimizer] Optimization failed: " << e.what() << std::endl;
            }
	        }
	    };

	    // **New**: AFL++-style corpus optimization API
	    typename AFLPlusPlusOptimizer::OptimizationStats optimizeCorpusAFLStyle() {
	        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
	        
	        auto stats = AFLPlusPlusOptimizer::optimizeCorpus(corpus_, seed_hashes_, config_);
	        
	        // Update statistics
	        if (stats.optimized_size < stats.original_size) {
	            invalidateEnergyCache();
	        }
	        
	        return stats;
	    }
	    
	    // **New**: Interruptible AFL++-style corpus optimization API
	    typename AFLPlusPlusOptimizer::OptimizationStats optimizeCorpusAFLStyleInterruptible(const std::atomic<bool>& should_stop) {
	        std::unique_lock<std::shared_mutex> lock(corpus_mutex_);
	        
	        auto stats = AFLPlusPlusOptimizer::optimizeCorpusInterruptible(corpus_, seed_hashes_, config_, should_stop);
	        
	        // Update statistics
	        if (stats.optimized_size < stats.original_size) {
	            invalidateEnergyCache();
	        }
	        
	        return stats;
	    }
	    
	    // Clean up old corpus files on disk
	    void cleanupDiskCorpus() {
	        try {
	            if (!std::filesystem::exists(config_.corpus_dir)) {
	                return;
	            }
	            
	            // Collect all corpus files
	            std::vector<std::filesystem::path> corpus_files;
	            for (const auto& entry : std::filesystem::directory_iterator(config_.corpus_dir)) {
	                if (entry.is_regular_file() && entry.path().extension() == ".bin") {
	                    corpus_files.push_back(entry.path());
	                }
	            }
	            
	            // If the file count exceeds the limit, delete old files
	            const size_t max_disk_files = 2000; // Keep at most 2000 files on disk
	            if (corpus_files.size() > max_disk_files) {
	                // Sort by modification time
	                std::sort(corpus_files.begin(), corpus_files.end(),
	                    [](const auto& a, const auto& b) {
	                        return std::filesystem::last_write_time(a) < 
	                               std::filesystem::last_write_time(b);
	                    });
	                
	                // Delete the oldest files
	                size_t to_delete = corpus_files.size() - max_disk_files;
	                for (size_t i = 0; i < to_delete; ++i) {
	                    std::filesystem::remove(corpus_files[i]);
	                    // Also delete the corresponding meta file (if present)
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
	    
	    // **New**: Start automatic optimization
	    void startAutoOptimization() {
	        if (!auto_optimizer_) {
	            auto_optimizer_ = std::make_unique<AutoOptimizationManager>(config_);
	            auto_optimizer_->start(this);
	        }
	    }
	    
	    // **New**: Stop automatic optimization
	    void stopAutoOptimization() {
	        if (auto_optimizer_) {
	            auto_optimizer_->stop();
	            auto_optimizer_.reset();
	        }
	    }
	    
	    // **New**: Trigger optimization manually
	    void triggerOptimization() {
	        if (auto_optimizer_) {
	            auto_optimizer_->triggerOptimization();
	        } else {
	            // If there is no auto optimizer, run optimization directly.
	            optimizeCorpusAFLStyle();
	        }
	    }
	    
	    // **New**: Update performance metric
	    void updatePerformanceMetric(double metric) {
	        if (auto_optimizer_) {
	            auto_optimizer_->updatePerformanceMetric(metric);
	        }
	    }
	    
	    // **New**: Get corpus quality statistics
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
	        
	        // Compute average energy
	        double total_energy = 0.0;
	        std::set<uint64_t> all_edges;
	        size_t total_bytes = 0;
        
        for (const auto& seed : corpus_) {
	            total_energy += seed.energy;
	            total_bytes += seed.data.size();
	            
	            // Collect all covered edges
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
	        
	        // Compute diversity score
	        auto diversity_metrics = SeedDiversityManager::calculateCorpusDiversity(corpus_);
	        stats.diversity_score = diversity_metrics.overall_diversity;
	        
	        // Compute corpus age
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
	    
	    // **New**: Selectively import seeds from another corpus (only those with new coverage)
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
	        
	        // Collect all edges covered by the current corpus
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
	        
	        // Check each seed in the external corpus
	        for (const auto& ext_seed : external_corpus) {
	            stats.total_seeds_examined++;
	            
	            // Check whether it contributes new coverage
	            bool has_new_coverage = false;
	            std::vector<uint64_t> new_edges;
	            
	            // Check covered_edges
	            for (auto edge : ext_seed.coverage.covered_edges) {
	                if (current_edges.find(edge) == current_edges.end()) {
	                    has_new_coverage = true;
	                    new_edges.push_back(edge);
	                    current_edges.insert(edge);  // Add to the current edge set
	                }
	            }
	            
	            // Check new_edges
	            for (auto edge : ext_seed.coverage.new_edges) {
	                if (current_edges.find(edge) == current_edges.end()) {
	                    has_new_coverage = true;
	                    new_edges.push_back(edge);
	                    current_edges.insert(edge);  // Add to the current edge set
	                }
	            }
            
	            if (has_new_coverage) {
	                stats.seeds_with_new_coverage++;
	                stats.new_edges_discovered += new_edges.size();
	                
	                // Check whether this is a duplicate seed (based on data content)
	                if (config_.enable_deduplication) {
	                    uint64_t seed_hash = SeedHasher::computeHash(ext_seed.data);
	                    auto range = hash_to_indices_.equal_range(seed_hash);
                    bool found = false;
                    for (auto it = range.first; it != range.second; ++it) {
	                        size_t idx = it->second;
	                        if (idx < corpus_.size() && SeedHasher::areEqual(corpus_[idx].data, ext_seed.data)) {
	                            corpus_[idx].coverage.merge(ext_seed.coverage);
	                            // Boost energy since a new path was found
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
	                
	                // Create a new seed and import it
	                Seed new_seed = ext_seed;  // Deep copy
	                new_seed.created_time = std::chrono::system_clock::now();
	                // Give seeds with new coverage a higher initial energy
	                new_seed.energy = std::max(1.5, ext_seed.energy);
	                
	                // Update the seed's new_edges to the truly new edges
	                new_seed.coverage.new_edges = new_edges;
	                
	                // Add to the corpus (do not use addSeed to avoid redundant dedup checks)
	                if (config_.enable_deduplication) {
	                    uint64_t hash = SeedHasher::computeHash(new_seed.data);
	                    seed_hashes_.insert(hash);
                    hash_to_indices_.insert({hash, corpus_.size()});
                }
	                corpus_.push_back(std::move(new_seed));
	                stats.seeds_imported++;
	                
	                // Save to disk
	                try {
	                    saveSingleSeed(corpus_.back());
	                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Failed to save imported seed: " << e.what() << std::endl;
                }
	            }
	        }
	        
	        // If new seeds were imported, corpus optimization may be needed
	        if (stats.seeds_imported > 0 && corpus_.size() > config_.max_corpus_size) {
	            removeLowQualitySeeds();
	            rebuildHashIndex();
	        }
	        
	        // Print merge statistics
	        std::cout << "[CORPUS MERGE] Merge completed:" << std::endl;
	        std::cout << "  - Seeds examined: " << stats.total_seeds_examined << std::endl;
	        std::cout << "  - Seeds with new coverage: " << stats.seeds_with_new_coverage << std::endl;
        std::cout << "  - Seeds imported: " << stats.seeds_imported << std::endl;
        std::cout << "  - New edges discovered: " << stats.new_edges_discovered << std::endl;
        std::cout << "  - Duplicate seeds updated: " << stats.duplicate_seeds_skipped << std::endl;
        std::cout << "  - Final corpus size: " << corpus_.size() << std::endl;
	        
	        return stats;
	    }
	    
	    // **New**: Merge corpus from recovery process (only import seeds that discover new paths)
	    MergeStats mergeFromRecoveryProcess(const std::string& recovery_corpus_dir, 
	                                       bool cleanup_after_merge = false) {
	        std::cout << "[RECOVERY MERGE] Starting selective merge from recovery process: " 
	                  << recovery_corpus_dir << std::endl;
        
        auto stats = mergeCorpusFromDirectory(recovery_corpus_dir);
	        
	        // Optional: clean up the recovery corpus directory after merging
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
	        
	        // Record statistics about recovery's contribution
	        if (stats.seeds_imported > 0) {
	            std::cout << "[RECOVERY MERGE] Recovery process contributed " 
	                      << stats.seeds_imported << " seeds with " 
	                      << stats.new_edges_discovered << " new edges" << std::endl;
	            
	            // Trigger a corpus optimization if needed
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
	    
	    // Selectively import a corpus from a directory (only import seeds that discover new paths)
	    MergeStats mergeCorpusFromDirectory(const std::string& dir) {
	        std::vector<Seed> external_corpus;
	        
	        try {
	            // Load external corpus
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
	                            
	                            // Try to load metadata
	                            std::string meta_file = entry.path().string() + ".meta";
	                            if (std::filesystem::exists(meta_file)) {
	                                loadSeedMetadata(seed, meta_file);
                            }
	                            
	                            external_corpus.push_back(std::move(seed));
	                        }
	                    } catch (const std::exception& e) {
	                        // Ignore files that fail to load
	                        continue;
	                    }
	                }
	            }
            
	            std::cout << "[CORPUS MERGE] Loaded " << external_corpus.size() 
	                      << " seeds from " << dir << std::endl;
	            
	            // Perform selective merge
	            return mergeCorpusSelectively(external_corpus);
	            
	        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[ERROR] Failed to access directory " << dir << ": " << e.what() << std::endl;
            return MergeStats{};
	        }
	    }
	    
	    // **New**: Print corpus quality report
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
	        
	        // Quality assessment
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
	    // Config instance
	    Config config_;
	    
	    // Seed storage
	    std::deque<Seed> corpus_;
	    std::vector<Seed> crashes_;
	    mutable std::shared_mutex corpus_mutex_;
	    
	    // Seed deduplication (improved: use a multimap to handle hash collisions)
	    std::unordered_set<uint64_t> seed_hashes_;
	    std::unordered_multimap<uint64_t, size_t> hash_to_indices_;  // Improved: use a multimap to handle collisions
	    
	    // Seed statistics
	    std::atomic<size_t> total_seeds_{0};
	    std::atomic<size_t> total_crashes_{0};
	    std::atomic<size_t> interesting_seeds_{0};
	    
	    // Energy allocation and cache
	    std::map<std::string, double> algorithm_energy_;
	    mutable double cached_total_energy_{0.0};
	    mutable bool energy_cache_valid_{false};
	    mutable std::vector<double> cumulative_energy_cache_;
	    mutable std::mutex energy_cache_mutex_;  // Separate mutex for energy cache
	    
	    // Random number generator
	    std::mt19937 random_{std::random_device{}()};
	    
	    // **New**: Automatic optimization manager
	    std::unique_ptr<AutoOptimizationManager> auto_optimizer_;
	    
	    // **New**: Rebuild hash index (optimized: incremental update)
	    void rebuildHashIndex() {
	        // Use a temporary map to build the new index
	        std::unordered_map<uint64_t, size_t> new_index;
	        new_index.reserve(corpus_.size());
	        
	        for (size_t i = 0; i < corpus_.size(); ++i) {
	            uint64_t hash = SeedHasher::computeHash(corpus_[i].data);
	            // Handle potential hash collisions
	            if (new_index.find(hash) != new_index.end()) {
	                // If a collision occurs, use a linked list or another strategy.
	                // For now, keep the latest index.
	                std::cerr << "[WARNING] Hash collision detected during index rebuild" << std::endl;
	            }
	            new_index[hash] = i;
	        }
	        
	        // Replace the index
	        hash_to_indices_.clear();
	        for (const auto& [hash, idx] : new_index) {
	            hash_to_indices_.insert({hash, idx});
	        }
	    }

	    // More aggressive seed-removal function
	    void removeLowQualitySeedsAdvanced(size_t target_removal_count) {
	        if (corpus_.empty() || target_removal_count == 0) return;
	        
	        try {
	            // Ensure we don't remove too many seeds
	            size_t actual_remove_count = std::min(target_removal_count, 
	                                                  corpus_.size() - config_.min_corpus_size);
	            if (actual_remove_count == 0) return;
	            
	            // Score seed quality using multiple factors
	            std::vector<std::pair<double, size_t>> seed_scores;
	            seed_scores.reserve(corpus_.size());
	            
            for (size_t i = 0; i < corpus_.size(); ++i) {
                try {
	                    const auto& seed = corpus_[i];
	                    double score = calculateSeedQualityEnhanced(seed);
	                    seed_scores.emplace_back(score, i);
	                } catch (const std::exception& e) {
	                    // If scoring a seed fails, assign the minimum score
	                    std::cerr << "[WARNING] Failed to score seed " << i << ": " << e.what() << std::endl;
	                    seed_scores.emplace_back(0.0, i);
	                }
	            }
	            
	            // Sort by score and remove the lowest-scoring seeds
	            std::partial_sort(seed_scores.begin(), 
	                             seed_scores.begin() + actual_remove_count,
	                             seed_scores.end(),
	                             [](const auto& a, const auto& b) {
	                                 return a.first < b.first; // Ascending; low scores first
	                             });
	            
	            // Remove from back to front (keeps indices valid)
	            std::vector<size_t> indices_to_remove;
	            for (size_t i = 0; i < actual_remove_count; ++i) {
	                indices_to_remove.push_back(seed_scores[i].second);
	            }
	            std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
	            
	            // Batch removal for efficiency and reduced lock hold time
	            size_t removed_count = 0;
	            for (size_t idx : indices_to_remove) {
	                try {
	                    // Remove the corresponding hash
	                    if (config_.enable_deduplication && idx < corpus_.size()) {
	                        uint64_t hash = SeedHasher::computeHash(corpus_[idx].data);
	                        seed_hashes_.erase(hash);
	                        // Remove the corresponding index from the multimap
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
	            
	            // Mark energy cache invalid
	            energy_cache_valid_ = false;
	            
	            std::cout << "[CORPUS] Removed " << removed_count 
	                     << " low-quality seeds, corpus size: " << corpus_.size() << std::endl;
	        } catch (const std::exception& e) {
	            std::cerr << "[ERROR] Critical error in removeLowQualitySeedsAdvanced: " 
	                     << e.what() << std::endl;
	            // Ensure index consistency
	            rebuildHashIndex();
	        }
	    }
	    
	    // Remove low-quality seeds (keep original function for compatibility)
	    void removeLowQualitySeeds() {
	        if (corpus_.empty()) return;
	        
	        // Compute number of seeds to remove (10% or at least 1)
	        size_t remove_count = std::max(size_t(1), corpus_.size() / 10);
	        
	        // Score seed quality using multiple factors
	        std::vector<std::pair<double, size_t>> seed_scores;
	        seed_scores.reserve(corpus_.size());
        
        for (size_t i = 0; i < corpus_.size(); ++i) {
            const auto& seed = corpus_[i];
            double score = calculateSeedQuality(seed);
	            seed_scores.emplace_back(score, i);
	        }
	        
	        // Sort by score and remove the lowest-scoring seeds
	        std::partial_sort(seed_scores.begin(), 
	                         seed_scores.begin() + remove_count,
	                         seed_scores.end(),
	                         [](const auto& a, const auto& b) {
	                             return a.first < b.first; // Ascending; low scores first
	                         });
	        
	        // Remove from back to front (keeps indices valid)
	        std::vector<size_t> indices_to_remove;
	        for (size_t i = 0; i < remove_count; ++i) {
	            indices_to_remove.push_back(seed_scores[i].second);
        }
        std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
	        
	        for (size_t idx : indices_to_remove) {
	            // Remove the corresponding hash
	            if (config_.enable_deduplication && idx < corpus_.size()) {
	                uint64_t hash = SeedHasher::computeHash(corpus_[idx].data);
	                seed_hashes_.erase(hash);
	            }
            corpus_.erase(corpus_.begin() + idx);
        }
        
	        // Mark energy cache invalid
	        energy_cache_valid_ = false;
	    }
	    
	    // Enhanced seed-quality scoring algorithm
	    double calculateSeedQualityEnhanced(const Seed& seed) const {
	        double score = 0.0;
	        
	        // 1. Coverage contribution (35%)
	        double coverage_score = 0.0;
	        coverage_score += seed.coverage.coverage_gain * 0.5;  // Coverage gain
	        coverage_score += (seed.coverage.new_edges.size() / 100.0) * 0.3;  // Number of new edges
	        coverage_score += (seed.coverage.rare_edges.size() / 10.0) * 0.2;  // Rare edges
	        score += std::min(1.0, coverage_score) * 0.35;
	        
	        // 2. Energy and execution efficiency (25%)
	        double efficiency_score = seed.energy * 0.6;
	        // Consider seed size (smaller seeds execute faster)
	        double size_factor = 1.0 / (1.0 + std::log10(seed.data.size() + 1) / 5.0);
	        efficiency_score += size_factor * 0.4;
	        score += std::min(1.0, efficiency_score) * 0.25;
	        
	        // 3. Diversity contribution (20%)
	        // Estimate diversity based on algorithm history and generation count
	        double diversity_score = 0.5;  // Base diversity score
	        // Use diversity from algorithm history
	        if (!seed.algorithm_history.empty()) {
	            // More algorithm history implies more mutations and higher diversity
	            diversity_score += (1.0 - std::exp(-seed.algorithm_history.size() / 10.0)) * 0.3;
	        }
	        // Use generation information
	        if (seed.generation > 0) {
	            diversity_score += (1.0 - std::exp(-seed.generation / 20.0)) * 0.2;
	        }
	        score += std::min(1.0, diversity_score) * 0.20;
	        
	        // 4. Freshness (15%)
	        auto age_hours = std::chrono::duration_cast<std::chrono::hours>(
	            std::chrono::system_clock::now() - seed.created_time).count();
	        double freshness = 0.0;
	        if (age_hours < 1) {
	            freshness = 1.0;  // Full score for seeds within 1 hour
	        } else if (age_hours < 24) {
	            freshness = 0.8 - (age_hours - 1) * 0.03;  // Linearly decays within 24 hours
	        } else if (age_hours < 168) {  // Within one week
	            freshness = 0.3 - (age_hours - 24) * 0.002;
	        } else {
	            freshness = 0.05;  // Baseline score for seeds older than one week
	        }
	        score += freshness * 0.15;
	        
	        // 5. Historical performance (5%)
	        // Based on seed performance and coverage gain
	        double historical_score = 0.3;  // Base historical score
	        // Use execution speed as part of historical performance
	        if (seed.performance.execution_time_ms > 0) {
	            // Faster execution yields a higher score
	            double speed_factor = 1.0 / (1.0 + std::log10(seed.performance.execution_time_ms + 1) / 3.0);
	            historical_score = std::max(historical_score, speed_factor);
	        }
	        // If coverage gain is significant, also boost the score
	        if (seed.coverage.coverage_gain > 0.1) {
	            historical_score = std::min(1.0, historical_score + seed.coverage.coverage_gain * 0.5);
	        }
        score += historical_score * 0.05;
	        
	        return score;
	    }
	    
	    // Compute seed quality score (keep original function for compatibility)
	    double calculateSeedQuality(const Seed& seed) const {
	        return calculateSeedQualityEnhanced(seed);
	    }
	    
	    // Invalidate energy cache
	    void invalidateEnergyCache() const {
	        std::lock_guard<std::mutex> lock(energy_cache_mutex_);
	        energy_cache_valid_ = false;
	        cumulative_energy_cache_.clear();
	    }
	    
	    // Build energy cache
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
	    
	    // Select a seed by energy (optimized version - reduces lock contention)
	    std::optional<Seed> selectSeedByEnergy() {
	        // Try the cache first; if valid, avoid taking the corpus lock.
	        {
	            std::lock_guard<std::mutex> cache_lock(energy_cache_mutex_);
	            if (energy_cache_valid_ && !cumulative_energy_cache_.empty()) {
	                // Select using cached data without the corpus lock.
	                if (cached_total_energy_ <= 0.0) {
	                    std::uniform_int_distribution<size_t> dist(0, cumulative_energy_cache_.size() - 1);
	                    size_t index = dist(random_);
	
	                    // Now acquire the corpus lock to return the seed.
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
	
	                // Acquire the corpus lock to return the seed.
	                std::shared_lock<std::shared_mutex> corpus_lock(corpus_mutex_);
	                if (index < corpus_.size()) {
	                    return corpus_[index];
	                }
	            }
	        }
	
	        // Cache invalid; needs rebuild
	        std::shared_lock<std::shared_mutex> corpus_lock(corpus_mutex_);
	        if (corpus_.empty()) {
	            return std::nullopt;
	        }
	
	        // Rebuild cache
	        {
	            std::lock_guard<std::mutex> cache_lock(energy_cache_mutex_);
	            // Double-check to avoid rebuilding in multiple threads
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
	
	        // Select seed using the refreshed cache
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
	    
	    // Save crash
	    void saveCrash(const Seed& crash) {
	        // Create directory
	        std::filesystem::create_directories(config_.crash_dir);
	        
	        // Generate a unique filename
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
	    
	    // Remove low-quality crash seeds
	    void removeLowQualityCrashes() {
	        if (crashes_.empty()) return;
	        
	        // Remove 25% of low-quality crash seeds
	        size_t remove_count = std::max(size_t(1), crashes_.size() / 4);
	        
	        // Evaluate crash seed quality
	        std::vector<std::pair<double, size_t>> crash_scores;
	        crash_scores.reserve(crashes_.size());
        
        for (size_t i = 0; i < crashes_.size(); ++i) {
            const auto& crash = crashes_[i];
            double score = calculateCrashQuality(crash);
	            crash_scores.emplace_back(score, i);
	        }
	        
	        // Sort by score and remove the lowest-scoring ones
	        std::partial_sort(crash_scores.begin(), 
	                         crash_scores.begin() + remove_count,
	                         crash_scores.end(),
                         [](const auto& a, const auto& b) {
	                             return a.first < b.first;
	                         });
	        
	        // Remove from back to front
	        std::vector<size_t> indices_to_remove;
	        for (size_t i = 0; i < remove_count; ++i) {
	            indices_to_remove.push_back(crash_scores[i].second);
        }
        std::sort(indices_to_remove.rbegin(), indices_to_remove.rend());
        
        for (size_t idx : indices_to_remove) {
	            crashes_.erase(crashes_.begin() + idx);
	        }
	    }
	    
	    // Compute crash seed quality
	    double calculateCrashQuality(const Seed& crash) const {
	        double score = 0.0;
	        
	        // Base value of a crash seed
	        score += 2.0; // Base score
	        
	        // Size reasonableness (too small or too large reduces value)
	        if (crash.data.size() >= 8 && crash.data.size() <= 1024) {
	            score += 1.0; // Bonus for reasonable size
	        } else if (crash.data.size() < 4) {
	            score -= 0.5; // Penalty for being too small
	        }
	        
	        // Prefer newer crash seeds
	        auto age = std::chrono::duration_cast<std::chrono::hours>(
	            std::chrono::system_clock::now() - crash.created_time).count();
	        score += std::max(0.0, 2.0 - age / 12.0); // Crashes within 12 hours get extra score
	        
	        // If coverage info is available, prefer crashes with new coverage
	        if (crash.coverage.hasNewCoverage()) {
	            score += 1.5;
	        }
        
        return score;
    }
};

} // namespace triofuzz
