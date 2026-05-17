#pragma once

#include "base_mutation.hpp"
#include <unordered_map>
#include <vector>
#include <string>
#include <set>

namespace triofuzz {

// CmpLog entry types
enum class CmpType {
    INT8, INT16, INT32, INT64,
    FP32, FP64,
    STRING, MEMORY
};

// Comparison operation types
enum class CmpOp {
    EQUAL, NOT_EQUAL,
    LESS_THAN, LESS_EQUAL,
    GREATER_THAN, GREATER_EQUAL,
    UNKNOWN
};

// CmpLog entry
struct CmpLogEntry {
    uint64_t instruction_address;    // Comparison instruction address
    uint64_t context_hash;           // Context hash
    CmpType type;                    // Comparison type
    CmpOp operation;                 // Comparison operation
    
    std::vector<uint8_t> operand1;   // Operand 1
    std::vector<uint8_t> operand2;   // Operand 2
    
    uint32_t hit_count;              // Hit count
    bool is_constant;                // Is constant comparison
    size_t input_offset;             // Corresponding input offset (if known)
    
    // Statistics
    uint32_t true_count = 0;         // Times comparison was true
    uint32_t false_count = 0;        // Times comparison was false
};

// CmpLog database
class CmpLogDatabase {
private:
    std::vector<CmpLogEntry> entries_;
    std::unordered_map<uint64_t, std::vector<size_t>> address_to_entries_;
    std::unordered_map<uint64_t, std::vector<size_t>> context_to_entries_;
    std::set<std::vector<uint8_t>> discovered_constants_;
    
public:
    void addEntry(const CmpLogEntry& entry);
    std::vector<CmpLogEntry> getEntriesForAddress(uint64_t address) const;
    std::vector<CmpLogEntry> getEntriesForContext(uint64_t context) const;
    
    const std::vector<CmpLogEntry>& getAllEntries() const { return entries_; }
    const std::set<std::vector<uint8_t>>& getDiscoveredConstants() const { return discovered_constants_; }
    
    void clear();
    size_t size() const { return entries_.size(); }
};

// CmpLog mutation strategies
enum class CmpLogStrategy {
    REPLACE_OPERANDS,        // Replace operands directly
    ARITHMETIC_PROGRESSION,  // Arithmetic progression
    DICTIONARY_BASED,        // Dictionary-based
    SUBSTRING_MATCHING,      // Substring matching
    ENDIANNESS_SWAP,        // Endianness swap
    TYPE_CONFUSION,         // Type confusion
    GRADIENT_DESCENT        // Gradient descent (REDQUEEN-like)
};

// CmpLog mutation algorithm
class CmpLogMutation : public MutationAlgorithm {
private:
    CmpLogDatabase cmplog_db_;
    
    // Configuration
    struct Config {
        bool enable_string_mutations = true;
        bool enable_integer_mutations = true;
        bool enable_float_mutations = true;
        bool enable_endianness_swap = true;
        bool enable_type_confusion = true;
        
        size_t max_string_length = 256;
        size_t max_mutation_attempts = 1000;
        double constant_replacement_probability = 0.8;
        size_t arithmetic_progression_steps = 16;
    } config_;
    
    // Runtime stats
    struct CmpLogStats {
        size_t total_entries = 0;
        size_t successful_mutations = 0;
        size_t string_mutations = 0;
        size_t integer_mutations = 0;
        size_t float_mutations = 0;
        size_t constants_discovered = 0;
        
        std::unordered_map<CmpLogStrategy, size_t> strategy_usage;
    } stats_;

public:
    CmpLogMutation();
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "cmplog";
        info.description = "AFL++ CmpLog comparison instruction logging and mutation";
        info.type = AlgorithmType::Mutation;
        info.provided_info = {InfoType::Coverage};
        info.required_info = {};
        info.metadata["source"] = "AFL++";
        info.metadata["tags"] = "mutation,cmplog,comparison_instructions,constants,afl_plus_plus";
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    // CmpLog-specific methods
    void processCmpLogData(const std::vector<uint8_t>& cmplog_data);
    void addCmpLogEntry(const CmpLogEntry& entry);
    
    std::vector<std::vector<uint8_t>> generateMutationCandidates(
        const CmpLogEntry& entry, CmpLogStrategy strategy);
    
    // Different mutation strategies
    MutationOutput applyReplaceOperands(const MutationInput& input, 
                                       const CmpLogEntry& entry, SharedContext& ctx);
    MutationOutput applyArithmeticProgression(const MutationInput& input,
                                             const CmpLogEntry& entry, SharedContext& ctx);
    MutationOutput applyDictionaryBased(const MutationInput& input,
                                       const CmpLogEntry& entry, SharedContext& ctx);
    MutationOutput applySubstringMatching(const MutationInput& input,
                                         const CmpLogEntry& entry, SharedContext& ctx);
    MutationOutput applyEndiannesSwap(const MutationInput& input,
                                     const CmpLogEntry& entry, SharedContext& ctx);
    MutationOutput applyTypeConfusion(const MutationInput& input,
                                     const CmpLogEntry& entry, SharedContext& ctx);
    
    // Stats and configuration
    const CmpLogStats& getStats() const { return stats_; }
    void updateConfig(const Config& new_config) { config_ = new_config; }
    const CmpLogDatabase& getDatabase() const { return cmplog_db_; }

private:
    void synchronizeDatabase(const SharedContext& ctx);
    // Helper methods
    std::vector<size_t> findInputOffsets(const std::vector<uint8_t>& input,
                                        const std::vector<uint8_t>& target) const;
    
    bool isInterestingConstant(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> convertType(const std::vector<uint8_t>& data, 
                                    CmpType from, CmpType to) const;
    
    // String handling
    std::vector<std::string> generateStringMutations(const std::string& original) const;
    bool isValidString(const std::vector<uint8_t>& data) const;
    
    // Numeric handling
    std::vector<uint64_t> generateIntegerProgression(uint64_t base, size_t steps) const;
    std::vector<double> generateFloatProgression(double base, size_t steps) const;
    
    // Endianness handling
    std::vector<uint8_t> swapEndianness(const std::vector<uint8_t>& data) const;
    
    // Input modifications
    bool replaceInInput(std::vector<uint8_t>& input, 
                       const std::vector<uint8_t>& old_value,
                       const std::vector<uint8_t>& new_value) const;
    
    std::vector<size_t> findAllOccurrences(const std::vector<uint8_t>& input,
                                          const std::vector<uint8_t>& pattern) const;
};

// CmpLog parser - parses CmpLog data produced by instrumentation
class CmpLogParser {
public:
    // Parse CmpLog entries from raw data
    static std::vector<CmpLogEntry> parseRawData(const std::vector<uint8_t>& raw_data);
    
    // Parse different comparison types
    static CmpLogEntry parseIntegerComparison(const uint8_t* data, size_t size);
    static CmpLogEntry parseFloatComparison(const uint8_t* data, size_t size);
    static CmpLogEntry parseStringComparison(const uint8_t* data, size_t size);
    static CmpLogEntry parseMemoryComparison(const uint8_t* data, size_t size);
    
    // Opcode parsing
    static CmpOp parseComparisonOperation(uint8_t opcode);
    static CmpType inferDataType(const std::vector<uint8_t>& data);
};

// CmpLog constant extractor
class CmpLogConstantExtractor {
private:
    std::set<std::vector<uint8_t>> integer_constants_;
    std::set<std::string> string_constants_;
    std::set<std::vector<uint8_t>> magic_numbers_;
    
public:
    void extractFromEntry(const CmpLogEntry& entry);
    void extractMagicNumbers(const std::vector<uint8_t>& data);
    
    const std::set<std::vector<uint8_t>>& getIntegerConstants() const { return integer_constants_; }
    const std::set<std::string>& getStringConstants() const { return string_constants_; }
    const std::set<std::vector<uint8_t>>& getMagicNumbers() const { return magic_numbers_; }
    
    // Check if it's a known magic number
    bool isMagicNumber(const std::vector<uint8_t>& data) const;
    bool isInterestingString(const std::string& str) const;
};

// CmpLog optimizer - optimizes strategy selection
class CmpLogOptimizer {
private:
    std::unordered_map<CmpLogStrategy, double> strategy_success_rates_;
    std::unordered_map<uint64_t, CmpLogStrategy> best_strategy_for_address_;
    
public:
    void recordStrategyResult(CmpLogStrategy strategy, bool success);
    CmpLogStrategy selectBestStrategy(uint64_t instruction_address) const;
    
    void updateStrategyForAddress(uint64_t address, CmpLogStrategy strategy);
    double getStrategySuccessRate(CmpLogStrategy strategy) const;
};

// CmpLog utilities
class CmpLogUtils {
public:
    // Data conversion
    static uint64_t bytesToInteger(const std::vector<uint8_t>& bytes, bool little_endian = true);
    static std::vector<uint8_t> integerToBytes(uint64_t value, size_t size, bool little_endian = true);
    
    static double bytesToFloat(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> floatToBytes(double value, bool single_precision = false);
    
    // String handling
    static std::string bytesToString(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> stringToBytes(const std::string& str);
    
    // Data analysis
    static bool isLikelyInteger(const std::vector<uint8_t>& data);
    static bool isLikelyFloat(const std::vector<uint8_t>& data);
    static bool isLikelyString(const std::vector<uint8_t>& data);
    
    // Hashing and comparison
    static uint64_t hashBytes(const std::vector<uint8_t>& data);
    static bool compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
};

} // namespace triofuzz 
