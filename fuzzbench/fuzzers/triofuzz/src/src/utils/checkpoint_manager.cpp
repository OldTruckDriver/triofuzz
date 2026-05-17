#include "../../include/utils/checkpoint_manager.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <random>

namespace triofuzz {

// Magic bytes for checkpoint file validation
static constexpr uint32_t CHECKPOINT_MAGIC = 0x434B5054;  // "CKPT"

CheckpointManager::CheckpointManager(const Config& config) : config_(config) {
    if (config_.enabled) {
        // Ensure checkpoint directory exists
        std::filesystem::create_directories(config_.checkpoint_dir);
        last_checkpoint_time_ = std::chrono::system_clock::now();

        std::cout << "[CheckpointManager] Initialized with:" << std::endl;
        std::cout << "  - Directory: " << config_.checkpoint_dir << std::endl;
        std::cout << "  - Interval: " << config_.checkpoint_interval.count() << " seconds" << std::endl;
        std::cout << "  - Atomic write: " << (config_.atomic_write ? "enabled" : "disabled") << std::endl;
    }
}

CheckpointManager::~CheckpointManager() {
    // Nothing special to clean up
}

std::string CheckpointManager::getCheckpointPath() const {
    return config_.checkpoint_dir + "/" + config_.checkpoint_file;
}

bool CheckpointManager::hasCheckpoint() const {
    return std::filesystem::exists(getCheckpointPath());
}

bool CheckpointManager::shouldCheckpoint() const {
    if (!config_.enabled) return false;

    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_checkpoint_time_);
    return elapsed >= config_.checkpoint_interval;
}

void CheckpointManager::markCheckpointDone() {
    last_checkpoint_time_ = std::chrono::system_clock::now();
    checkpoint_count_++;
}

void CheckpointManager::deleteCheckpoint() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string path = getCheckpointPath();
    if (std::filesystem::exists(path)) {
        std::filesystem::remove(path);
        std::cout << "[CheckpointManager] Deleted checkpoint: " << path << std::endl;
    }
}

bool CheckpointManager::saveCheckpoint(const CheckpointData& data) {
    if (!config_.enabled) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    std::string target_path = getCheckpointPath();

    if (!serializeToFile(target_path, data)) {
        std::cerr << "[CheckpointManager] Failed to save checkpoint" << std::endl;
        return false;
    }

    markCheckpointDone();

    std::cout << "[CheckpointManager] Checkpoint saved (#" << checkpoint_count_
              << "): " << data.total_executions << " executions, "
              << data.combination_stats.size() << " combinations tracked" << std::endl;

    return true;
}

bool CheckpointManager::loadCheckpoint(CheckpointData& data) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string path = getCheckpointPath();

    if (!std::filesystem::exists(path)) {
        std::cout << "[CheckpointManager] No checkpoint found at: " << path << std::endl;
        return false;
    }

    if (!deserializeFromFile(path, data)) {
        std::cerr << "[CheckpointManager] Failed to load checkpoint from: " << path << std::endl;
        return false;
    }

    std::cout << "[CheckpointManager] Checkpoint loaded successfully:" << std::endl;
    std::cout << "  - Executions: " << data.total_executions << std::endl;
    std::cout << "  - Elapsed time: " << data.elapsed_seconds << " seconds" << std::endl;
    std::cout << "  - Combinations tracked: " << data.combination_stats.size() << std::endl;
    std::cout << "  - Total edges: " << data.total_edges << std::endl;
    std::cout << "  - Corpus seeds: " << data.corpus_size << std::endl;

    return true;
}

bool CheckpointManager::serializeToFile(const std::string& path, const CheckpointData& data) {
    std::vector<uint8_t> buffer;

    // Reserve some initial space
    buffer.reserve(1024 * 1024);  // 1MB initial

    auto write_uint32 = [&buffer](uint32_t val) {
        buffer.push_back(val & 0xFF);
        buffer.push_back((val >> 8) & 0xFF);
        buffer.push_back((val >> 16) & 0xFF);
        buffer.push_back((val >> 24) & 0xFF);
    };

    auto write_uint64 = [&buffer](uint64_t val) {
        for (int i = 0; i < 8; ++i) {
            buffer.push_back((val >> (i * 8)) & 0xFF);
        }
    };

    auto write_double = [&buffer](double val) {
        uint64_t bits;
        std::memcpy(&bits, &val, sizeof(bits));
        for (int i = 0; i < 8; ++i) {
            buffer.push_back((bits >> (i * 8)) & 0xFF);
        }
    };

    auto write_string = [&](const std::string& str) {
        write_uint32(static_cast<uint32_t>(str.size()));
        buffer.insert(buffer.end(), str.begin(), str.end());
    };

    // Write header
    write_uint32(CHECKPOINT_MAGIC);
    write_uint32(data.version);
    write_uint64(data.timestamp_ns);

    // Write execution statistics
    write_uint64(data.total_executions);
    write_uint64(data.total_crashes);
    write_uint64(data.total_new_coverage);
    write_double(data.elapsed_seconds);

    // Write combination stats
    write_uint32(static_cast<uint32_t>(data.combination_stats.size()));
    for (const auto& cs : data.combination_stats) {
        write_uint64(cs.combination_hash);
        write_string(cs.combination_str);
        write_uint64(cs.executions);
        write_uint64(cs.new_coverage_count);
        write_uint64(cs.crash_count);
        write_double(cs.total_reward);
        write_double(cs.avg_reward);
        write_double(cs.total_execution_time_ms);
        write_double(cs.avg_execution_time_ms);
    }

    // Write coverage bitmap
    write_uint64(data.total_edges);
    write_uint32(static_cast<uint32_t>(data.coverage_bitmap.size()));
    buffer.insert(buffer.end(), data.coverage_bitmap.begin(), data.coverage_bitmap.end());

    // Write corpus metadata
    write_uint64(data.corpus_size);
    write_uint32(static_cast<uint32_t>(data.corpus_seed_files.size()));
    for (const auto& file : data.corpus_seed_files) {
        write_string(file);
    }

    // Write tiered stats
    write_uint32(static_cast<uint32_t>(data.tiered_stats.size()));
    for (const auto& ts : data.tiered_stats) {
        write_string(ts.algorithm_name);
        write_uint64(ts.executions);
        write_double(ts.total_time_ms);
        write_uint64(ts.coverage_hits);
        write_double(ts.total_reward);
    }

    // Write to file (atomic if configured)
    if (config_.atomic_write) {
        return atomicWrite(path, buffer);
    } else {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        return file.good();
    }
}

bool CheckpointManager::deserializeFromFile(const std::string& path, CheckpointData& data) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(file_size);
    file.read(reinterpret_cast<char*>(buffer.data()), file_size);
    if (!file.good()) return false;

    size_t pos = 0;

    auto read_uint32 = [&buffer, &pos]() -> uint32_t {
        if (pos + 4 > buffer.size()) throw std::runtime_error("Buffer underflow");
        uint32_t val = buffer[pos] | (buffer[pos+1] << 8) |
                       (buffer[pos+2] << 16) | (buffer[pos+3] << 24);
        pos += 4;
        return val;
    };

    auto read_uint64 = [&buffer, &pos]() -> uint64_t {
        if (pos + 8 > buffer.size()) throw std::runtime_error("Buffer underflow");
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val |= static_cast<uint64_t>(buffer[pos + i]) << (i * 8);
        }
        pos += 8;
        return val;
    };

    auto read_double = [&buffer, &pos]() -> double {
        if (pos + 8 > buffer.size()) throw std::runtime_error("Buffer underflow");
        uint64_t bits = 0;
        for (int i = 0; i < 8; ++i) {
            bits |= static_cast<uint64_t>(buffer[pos + i]) << (i * 8);
        }
        pos += 8;
        double val;
        std::memcpy(&val, &bits, sizeof(val));
        return val;
    };

    auto read_string = [&]() -> std::string {
        uint32_t len = read_uint32();
        if (pos + len > buffer.size()) throw std::runtime_error("Buffer underflow");
        std::string str(buffer.begin() + pos, buffer.begin() + pos + len);
        pos += len;
        return str;
    };

    try {
        // Read and validate header
        uint32_t magic = read_uint32();
        if (magic != CHECKPOINT_MAGIC) {
            std::cerr << "[CheckpointManager] Invalid magic number" << std::endl;
            return false;
        }

        data.version = read_uint32();
        if (data.version > CheckpointData::CURRENT_VERSION) {
            std::cerr << "[CheckpointManager] Unsupported checkpoint version: " << data.version << std::endl;
            return false;
        }

        data.timestamp_ns = read_uint64();

        // Read execution statistics
        data.total_executions = read_uint64();
        data.total_crashes = read_uint64();
        data.total_new_coverage = read_uint64();
        data.elapsed_seconds = read_double();

        // Read combination stats
        uint32_t num_combinations = read_uint32();
        data.combination_stats.resize(num_combinations);
        for (auto& cs : data.combination_stats) {
            cs.combination_hash = read_uint64();
            cs.combination_str = read_string();
            cs.executions = read_uint64();
            cs.new_coverage_count = read_uint64();
            cs.crash_count = read_uint64();
            cs.total_reward = read_double();
            cs.avg_reward = read_double();
            cs.total_execution_time_ms = read_double();
            cs.avg_execution_time_ms = read_double();
        }

        // Read coverage bitmap
        data.total_edges = read_uint64();
        uint32_t bitmap_size = read_uint32();
        if (pos + bitmap_size > buffer.size()) throw std::runtime_error("Buffer underflow");
        data.coverage_bitmap.assign(buffer.begin() + pos, buffer.begin() + pos + bitmap_size);
        pos += bitmap_size;

        // Read corpus metadata
        data.corpus_size = read_uint64();
        uint32_t num_seed_files = read_uint32();
        data.corpus_seed_files.resize(num_seed_files);
        for (auto& file : data.corpus_seed_files) {
            file = read_string();
        }

        // Read tiered stats
        uint32_t num_tiered = read_uint32();
        data.tiered_stats.resize(num_tiered);
        for (auto& ts : data.tiered_stats) {
            ts.algorithm_name = read_string();
            ts.executions = read_uint64();
            ts.total_time_ms = read_double();
            ts.coverage_hits = read_uint64();
            ts.total_reward = read_double();
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "[CheckpointManager] Deserialization error: " << e.what() << std::endl;
        return false;
    }
}

bool CheckpointManager::atomicWrite(const std::string& target_path, const std::vector<uint8_t>& data) {
    // Generate temporary file path
    std::random_device rd;
    std::string temp_path = target_path + ".tmp." + std::to_string(rd());

    // Write to temporary file
    {
        std::ofstream file(temp_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[CheckpointManager] Failed to create temp file: " << temp_path << std::endl;
            return false;
        }
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        if (!file.good()) {
            std::cerr << "[CheckpointManager] Failed to write temp file: " << temp_path << std::endl;
            std::filesystem::remove(temp_path);
            return false;
        }
        file.flush();
    }

    // Atomic rename
    try {
        std::filesystem::rename(temp_path, target_path);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[CheckpointManager] Failed to rename temp file: " << e.what() << std::endl;
        std::filesystem::remove(temp_path);
        return false;
    }
}

} // namespace triofuzz
