#pragma once

#include "base_mutation.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace triofuzz {

// Vector hash function for unordered_set
#ifndef COLLAFUZZ_VECTOR_HASH_DEFINED
#define COLLAFUZZ_VECTOR_HASH_DEFINED
struct VectorHash {
    std::size_t operator()(const std::vector<uint8_t>& v) const {
        std::size_t hash_value = 0;
        // Only hash the first 32 bytes to improve performance.
        size_t hash_len = std::min(v.size(), size_t(32));
        for (size_t i = 0; i < hash_len; ++i) {
            hash_value = hash_value * 31 + v[i];
        }
        return hash_value;
    }
};
#endif // COLLAFUZZ_VECTOR_HASH_DEFINED

// Smart dictionary mutation algorithm
class SmartDictionaryMutation : public MutationAlgorithm {
private:
    std::vector<std::vector<uint8_t>> static_dictionary_;
    std::vector<std::vector<uint8_t>> dynamic_dictionary_;
    std::vector<std::vector<uint8_t>> external_dictionary_; // External dictionary file contents
    size_t max_dynamic_entries_ = 1000;
    std::string dictionary_file_path_; // Dictionary file path

    // Static cache to avoid reloading the same dictionary file.
    static std::unordered_map<std::string, std::vector<std::vector<uint8_t>>> dictionary_cache_;
    static std::mutex cache_mutex_;

    // Optimization: use a hash set for fast duplicate checks.
    std::unordered_set<std::vector<uint8_t>, VectorHash> dynamic_dictionary_set_;

    // Optimization: control dictionary extraction frequency.
    size_t executions_since_extract_ = 0;
    size_t extract_interval_ = 1000;  // Extract once every 1000 executions
    
public:
    SmartDictionaryMutation() {
        initializeStaticDictionary();
    }
    
    // Constructor with dictionary file support
    SmartDictionaryMutation(const std::string& dict_file_path) 
        : dictionary_file_path_(dict_file_path) {
        initializeStaticDictionary();
        if (!dict_file_path.empty()) {
            loadDictionaryFromFile(dict_file_path);
        }
    }
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "smart_dictionary";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
    // Extract dictionary from input
    void extractDictionaryFromInput(const std::vector<uint8_t>& input);
    
    // Load dictionary from external file
    bool loadDictionaryFromFile(const std::string& file_path);
    
    // Set dictionary file path
    void setDictionaryFile(const std::string& file_path);
    
private:
    void initializeStaticDictionary();
    
    // Load dictionaries from shared context
    void loadDictionariesFromContext(SharedContext& ctx);
    
    // Smart dictionary entry selection
    std::vector<uint8_t> selectDictionaryEntry(
        const std::vector<std::vector<uint8_t>>& dictionary,
        const MutationInput& input);
    
    // Check if entry has interesting patterns
    bool hasInterestingPattern(const std::vector<uint8_t>& entry);
    
    // Check if entry is relevant to input
    bool isRelevantToInput(const std::vector<uint8_t>& entry, 
                          const MutationInput& input);
    
    // Find potential tokens
    std::vector<std::vector<uint8_t>> findPotentialTokens(const std::vector<uint8_t>& input);
    
    // Apply dictionary mutation (enhanced)
    MutationOutput applyDictionaryMutation(const MutationInput& input, 
                                         const std::vector<uint8_t>& dict_entry,
                                         int strategy);
    
    // Parse a dictionary file line
    std::vector<uint8_t> parseDictionaryLine(const std::string& line);
};

} // namespace triofuzz 
