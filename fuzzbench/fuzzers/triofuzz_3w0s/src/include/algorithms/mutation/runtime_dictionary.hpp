#pragma once

#include <vector>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <cstdint>
#include <algorithm>
#include <mutex>
#include <chrono>
#include <string>
#include <cstring>

namespace triofuzz {

// Custom hash function - conditionally compiled to avoid redefinition.
#ifndef COLLAFUZZ_VECTOR_HASH_DEFINED
#define COLLAFUZZ_VECTOR_HASH_DEFINED
struct VectorHash {
    size_t operator()(const std::vector<uint8_t>& v) const {
        size_t seed = v.size();
        for (auto& i : v) {
            seed ^= i + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};
#endif // COLLAFUZZ_VECTOR_HASH_DEFINED

/**
 * Runtime dictionary learner.
 * Automatically extracts valuable constants and strings from comparisons.
 * Dynamically maintains and optimizes the dictionary.
 */
class RuntimeDictionary {
public:
    // Dictionary entry
    struct DictionaryEntry {
        std::vector<uint8_t> data;
        size_t hit_count = 0;           // Hit count
        size_t success_count = 0;        // Times it produced new coverage
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_used;
        double score = 0.0;              // Value score
        
        bool operator<(const DictionaryEntry& other) const {
            return score > other.score;  // Sort by score descending
        }
    };
    
    // Configuration
    struct Config {
        size_t max_dict_size = 1000;          // Maximum dictionary size
        size_t max_entry_len = 128;           // Max entry length
        size_t min_entry_len = 2;             // Min entry length
        bool auto_extract = true;             // Auto-extract
        bool filter_boring = true;            // Filter uninteresting values
        bool extract_strings = true;          // Extract strings
        bool extract_integers = true;         // Extract integers
        bool extract_floats = true;           // Extract floats
        double min_score_threshold = 0.1;     // Minimum score threshold
        size_t aging_interval_minutes = 30;   // Aging interval
    };
    
private:
    Config config_;
    std::unordered_map<std::vector<uint8_t>, DictionaryEntry, VectorHash> dictionary_;
    std::mutex dict_mutex_;
    
    // Statistics
    size_t total_extractions_ = 0;
    size_t successful_uses_ = 0;
    std::chrono::steady_clock::time_point last_cleanup_;
    
    // Common uninteresting values (for filtering)
    std::unordered_set<std::vector<uint8_t>, VectorHash> boring_values_;
    
public:
    RuntimeDictionary() : RuntimeDictionary(Config{}) {}
    
    explicit RuntimeDictionary(const Config& config) : config_(config) {
        last_cleanup_ = std::chrono::steady_clock::now();
        initializeBoringValues();
    }
    
    /**
     * Extract constants from comparisons.
     */
    void extractFromComparison(
        const std::vector<uint8_t>& operand1,
        const std::vector<uint8_t>& operand2,
        bool comparison_succeeded = false) {
        
        if (!config_.auto_extract) return;
        
        std::lock_guard<std::mutex> lock(dict_mutex_);
        
        // Extract both operands
        if (isInteresting(operand1)) {
            addEntry(operand1, comparison_succeeded);
        }
        if (isInteresting(operand2)) {
            addEntry(operand2, comparison_succeeded);
        }
        
        // Try extracting substrings
        extractSubstrings(operand1);
        extractSubstrings(operand2);
        
        total_extractions_++;
        
        // Periodic cleanup
        if (shouldCleanup()) {
            cleanup();
        }
    }
    
    /**
     * Extract constants from memory (e.g., from strcmp).
     */
    void extractFromMemory(const uint8_t* data, size_t len) {
        if (!config_.auto_extract || len < config_.min_entry_len || 
            len > config_.max_entry_len) {
            return;
        }
        
        std::vector<uint8_t> entry(data, data + len);
        
        if (isInteresting(entry)) {
            std::lock_guard<std::mutex> lock(dict_mutex_);
            addEntry(entry, false);
        }
    }
    
    /**
     * Extract integer constants.
     */
    template<typename T>
    void extractInteger(T value) {
        if (!config_.extract_integers) return;
        
        std::vector<uint8_t> entry(sizeof(T));
        std::memcpy(entry.data(), &value, sizeof(T));
        
        if (isInteresting(entry)) {
            std::lock_guard<std::mutex> lock(dict_mutex_);
            addEntry(entry, false);
            
            // Also add a version with the opposite endianness.
            if (sizeof(T) > 1) {
                std::reverse(entry.begin(), entry.end());
                addEntry(entry, false);
            }
        }
    }
    
    /**
     * Extract floating-point constants.
     */
    void extractFloat(float value) {
        if (!config_.extract_floats) return;
        
        // Filter special values
        if (std::isnan(value) || std::isinf(value)) return;
        
        std::vector<uint8_t> entry(sizeof(float));
        std::memcpy(entry.data(), &value, sizeof(float));
        
        if (isInteresting(entry)) {
            std::lock_guard<std::mutex> lock(dict_mutex_);
            addEntry(entry, false);
        }
    }
    
    /**
     * Get dictionary entries (for mutation).
     */
    std::vector<std::vector<uint8_t>> getTopEntries(size_t count = 100) {
        std::lock_guard<std::mutex> lock(dict_mutex_);
        
        // Sort by score
        std::vector<DictionaryEntry> sorted_entries;
        for (const auto& [key, entry] : dictionary_) {
            if (entry.score >= config_.min_score_threshold) {
                sorted_entries.push_back(entry);
            }
        }
        
        std::sort(sorted_entries.begin(), sorted_entries.end());
        
        // Return top entries
        std::vector<std::vector<uint8_t>> result;
        size_t n = std::min(count, sorted_entries.size());
        
        for (size_t i = 0; i < n; ++i) {
            result.push_back(sorted_entries[i].data);
            // Update last-used time
            dictionary_[sorted_entries[i].data].last_used = 
                std::chrono::steady_clock::now();
        }
        
        return result;
    }
    
    /**
     * Get a random entry.
     */
    std::vector<uint8_t> getRandomEntry() {
        std::lock_guard<std::mutex> lock(dict_mutex_);
        
        if (dictionary_.empty()) {
            return {};
        }
        
        // Weighted random selection (by score)
        double total_score = 0.0;
        for (const auto& [key, entry] : dictionary_) {
            total_score += entry.score;
        }
        
        double r = (static_cast<double>(rand()) / RAND_MAX) * total_score;
        double cumulative = 0.0;
        
        for (auto& [key, entry] : dictionary_) {
            cumulative += entry.score;
            if (cumulative >= r) {
                entry.last_used = std::chrono::steady_clock::now();
                return entry.data;
            }
        }
        
        // Fallback: return the first entry
        return dictionary_.begin()->second.data;
    }
    
    /**
     * Update entry statistics (feedback).
     */
    void updateEntrySuccess(const std::vector<uint8_t>& entry) {
        std::lock_guard<std::mutex> lock(dict_mutex_);
        
        auto it = dictionary_.find(entry);
        if (it != dictionary_.end()) {
            it->second.success_count++;
            it->second.hit_count++;
            updateScore(it->second);
            successful_uses_++;
        }
    }
    
    /**
     * Get dictionary size.
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(
            const_cast<std::mutex&>(dict_mutex_));
        return dictionary_.size();
    }
    
    /**
     * Get statistics.
     */
    void getStatistics(size_t& total_entries, size_t& total_uses, 
                       double& avg_score) const {
        std::lock_guard<std::mutex> lock(
            const_cast<std::mutex&>(dict_mutex_));
        
        total_entries = dictionary_.size();
        total_uses = successful_uses_;
        
        if (total_entries > 0) {
            double sum = 0.0;
            for (const auto& [key, entry] : dictionary_) {
                sum += entry.score;
            }
            avg_score = sum / total_entries;
        } else {
            avg_score = 0.0;
        }
    }
    
	private:
    /**
     * Initialize the boring-values list.
     */
    void initializeBoringValues() {
        // All zeros / all ones
        boring_values_.insert({0x00});
        boring_values_.insert({0xFF});
        boring_values_.insert({0x00, 0x00});
        boring_values_.insert({0xFF, 0xFF});
        boring_values_.insert({0x00, 0x00, 0x00, 0x00});
        boring_values_.insert({0xFF, 0xFF, 0xFF, 0xFF});
        
        // Common boundary values
        boring_values_.insert({0x7F});  // INT8_MAX
        boring_values_.insert({0x80});  // INT8_MIN
        boring_values_.insert({0x7F, 0xFF});  // INT16_MAX
        boring_values_.insert({0x80, 0x00});  // INT16_MIN
        
        // Empty value
        boring_values_.insert({});
    }
    
    /**
     * Determine whether a value is interesting.
     */
    bool isInteresting(const std::vector<uint8_t>& data) {
        // Length check
        if (data.size() < config_.min_entry_len || 
            data.size() > config_.max_entry_len) {
            return false;
        }
        
        // Filter uninteresting values
        if (config_.filter_boring) {
            // Check if it's in the boring-values list
            if (boring_values_.find(data) != boring_values_.end()) {
                return false;
            }
            
            // Check if all bytes are the same
            if (data.size() > 1) {
                bool all_same = std::all_of(data.begin() + 1, data.end(),
                    [&data](uint8_t b) { return b == data[0]; });
                if (all_same) {
                    return false;
                }
            }
        }
        
        // Check if it's a printable string
        if (config_.extract_strings && data.size() >= 4) {
            size_t printable_count = 0;
            for (uint8_t b : data) {
                if (b >= 32 && b <= 126) {
                    printable_count++;
                }
            }
            // If >=80% are printable characters, treat it as a string.
            if (printable_count >= data.size() * 0.8) {
                return true;
            }
        }
        
        return true;
    }
    
    /**
     * Add a dictionary entry.
     */
    void addEntry(const std::vector<uint8_t>& data, bool immediate_success) {
        auto it = dictionary_.find(data);
        
        if (it != dictionary_.end()) {
            // Update existing entry
            it->second.hit_count++;
            if (immediate_success) {
                it->second.success_count++;
            }
            it->second.last_used = std::chrono::steady_clock::now();
            updateScore(it->second);
        } else {
            // Add new entry
            if (dictionary_.size() >= config_.max_dict_size) {
                // Need to remove the worst entry first.
                removeWorstEntry();
            }
            
            DictionaryEntry entry;
            entry.data = data;
            entry.hit_count = 1;
            entry.success_count = immediate_success ? 1 : 0;
            entry.first_seen = std::chrono::steady_clock::now();
            entry.last_used = entry.first_seen;
            updateScore(entry);
            
            dictionary_[data] = entry;
        }
    }
    
    /**
     * Extract substrings.
     */
    void extractSubstrings(const std::vector<uint8_t>& data) {
        if (!config_.extract_strings || data.size() < 8) {
            return;
        }
        
        // Find printable strings
        size_t start = 0;
        bool in_string = false;
        
        for (size_t i = 0; i < data.size(); ++i) {
            bool is_printable = (data[i] >= 32 && data[i] <= 126);
            
            if (is_printable && !in_string) {
                start = i;
                in_string = true;
            } else if (!is_printable && in_string) {
                size_t len = i - start;
                if (len >= config_.min_entry_len && len <= config_.max_entry_len) {
                    std::vector<uint8_t> substr(data.begin() + start, 
                                               data.begin() + i);
                    if (isInteresting(substr)) {
                        addEntry(substr, false);
                    }
                }
                in_string = false;
            }
        }
        
        // Handle a trailing string at the end
        if (in_string) {
            size_t len = data.size() - start;
            if (len >= config_.min_entry_len && len <= config_.max_entry_len) {
                std::vector<uint8_t> substr(data.begin() + start, data.end());
                if (isInteresting(substr)) {
                    addEntry(substr, false);
                }
            }
        }
    }
    
    /**
     * Update entry score.
     */
    void updateScore(DictionaryEntry& entry) {
        double score = 0.0;
        
        // Success rate (most important)
        if (entry.hit_count > 0) {
            double success_rate = static_cast<double>(entry.success_count) / 
                                entry.hit_count;
            score += success_rate * 100.0;
        }
        
        // Usage frequency
        score += std::log2(entry.hit_count + 1) * 10.0;
        
        // Time factor (boost new entries)
        auto age = std::chrono::duration_cast<std::chrono::minutes>(
            std::chrono::steady_clock::now() - entry.first_seen).count();
        if (age < 10) {
            score += (10 - age);  // Extra boost for entries newer than 10 minutes
        }
        
        // Recency
        auto last_use = std::chrono::duration_cast<std::chrono::minutes>(
            std::chrono::steady_clock::now() - entry.last_used).count();
        if (last_use < 5) {
            score += 5.0;  // Used within the last 5 minutes
        }
        
        // Length penalty (penalize overly long entries)
        if (entry.data.size() > 32) {
            score *= (32.0 / entry.data.size());
        }
        
        entry.score = score;
    }
    
    /**
     * Remove the worst entry.
     */
    void removeWorstEntry() {
        if (dictionary_.empty()) return;
        
        auto worst_it = dictionary_.begin();
        double worst_score = worst_it->second.score;
        
        for (auto it = dictionary_.begin(); it != dictionary_.end(); ++it) {
            if (it->second.score < worst_score) {
                worst_score = it->second.score;
                worst_it = it;
            }
        }
        
        dictionary_.erase(worst_it);
    }
    
    /**
     * Decide whether cleanup is needed.
     */
    bool shouldCleanup() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
            now - last_cleanup_).count();
        return static_cast<size_t>(elapsed) >= config_.aging_interval_minutes;
    }
    
    /**
     * Cleanup aged entries.
     */
    void cleanup() {
        auto now = std::chrono::steady_clock::now();
        
        // Recompute all scores
        for (auto& [key, entry] : dictionary_) {
            updateScore(entry);
        }
        
        // Remove low-scoring entries
        auto it = dictionary_.begin();
        while (it != dictionary_.end()) {
            if (it->second.score < config_.min_score_threshold) {
                it = dictionary_.erase(it);
            } else {
                ++it;
            }
        }
        
        last_cleanup_ = now;
    }
};

} // namespace triofuzz
