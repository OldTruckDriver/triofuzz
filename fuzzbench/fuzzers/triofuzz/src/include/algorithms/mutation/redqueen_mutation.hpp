#pragma once

#include "base_mutation.hpp"
#include "../../core/context.hpp"
#include <unordered_map>
#include <set>
#include <vector>
#include <string>
#include <regex>
#include <memory>
#include "../../utils/execution_tracer.hpp"

// Forward declaration
namespace triofuzz {
struct ComparisonEntry;
}

namespace triofuzz {

// Data structures for REDQUEEN
struct ColoringEntry {
    uint64_t address;           // Instruction address
    uint64_t context;           // Context info
    std::vector<uint8_t> input_bytes;  // Corresponding input bytes
    std::vector<uint8_t> cmp_bytes;    // Compared bytes
    uint32_t hit_count;         // Hit count
    bool is_string_compare;     // String comparison?
};

struct InputToStateMapping {
    size_t input_offset;        // Offset in the input
    size_t length;              // Length
    uint64_t state_address;     // Program state address
    std::vector<uint8_t> target_value;  // Target value
    double confidence;          // Confidence
};

// REDQUEEN coloring result
struct ColoringResult {
    std::vector<ColoringEntry> entries;
    std::unordered_map<uint64_t, std::vector<size_t>> address_to_entries;
    bool has_new_mappings;
};

// REDQUEEN magic-byte extractor
class RedqueenMagicByteExtractor {
private:
    std::set<std::vector<uint8_t>> extracted_constants_;
    std::unordered_map<std::string, std::vector<uint8_t>> string_constants_;
    
public:
    // Extract magic bytes from comparison instructions.
    std::vector<std::vector<uint8_t>> extractFromComparison(
        const std::vector<uint8_t>& cmp_operand1,
        const std::vector<uint8_t>& cmp_operand2
    );
    
    // Extract string constants.
    std::vector<std::string> extractStringConstants(const std::vector<uint8_t>& data);
    
    // Extract numeric constants.
    std::vector<std::vector<uint8_t>> extractNumericConstants(const std::vector<uint8_t>& data);
    
    // Get all extracted constants.
    const std::set<std::vector<uint8_t>>& getExtractedConstants() const {
        return extracted_constants_;
    }
};

// REDQUEEN mutation algorithm
class REDQUEENMutation : public MutationAlgorithm {
private:
    RedqueenMagicByteExtractor extractor_;
    std::unordered_map<size_t, InputToStateMapping> input_mappings_;
    std::vector<ColoringEntry> coloring_database_;
    
    // Execution tracer
    std::unique_ptr<ExecutionTracer> tracer_;
    
    // Runtime stats
    struct REDQUEENStats {
        size_t total_colorings = 0;
        size_t successful_mappings = 0;
        size_t magic_bytes_found = 0;
        size_t patches_applied = 0;
        double avg_confidence = 0.0;
    } stats_;
    
    // REDQUEEN configuration
    struct Config {
        bool enable_string_extraction = true;
        bool enable_numeric_extraction = true;
        bool enable_automatic_patching = true;
        size_t max_coloring_attempts = 1000;
        double min_confidence_threshold = 0.7;
        size_t max_patch_size = 64;
    } config_;

public:
    REDQUEENMutation();
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "redqueen";
        info.description = "REDQUEEN non-intrusive input-to-state correspondence";
        info.type = AlgorithmType::Mutation;
        info.provided_info = {InfoType::Coverage, InfoType::Structure};
        info.required_info = {InfoType::Trace};
        info.metadata["paper"] = "REDQUEEN: Fuzzing with Input-to-State Correspondence";
        info.metadata["year"] = "2019";
        info.metadata["tags"] = "mutation,redqueen,input_state_mapping,magic_bytes,non_intrusive";
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    // REDQUEEN-specific methods
    ColoringResult performColoring(const std::vector<uint8_t>& input, SharedContext& ctx);
    std::vector<InputToStateMapping> extractMappings(const ColoringResult& coloring);
    MutationOutput applyInputPatches(const MutationInput& input, 
                                   const std::vector<InputToStateMapping>& mappings);
    
    // Statistics
    const REDQUEENStats& getStats() const { return stats_; }
    void updateConfig(const Config& new_config) { config_ = new_config; }

private:
    // Advanced methods based on execution tracing
    ColoringResult performAdvancedColoring(const std::vector<uint8_t>& input, 
                                          const std::vector<ComparisonEntry>& comparisons,
                                          SharedContext& ctx);
    
	    MutationOutput applyMagicBytesMutation(const MutationInput& input,
	                                          const std::vector<ComparisonEntry>& comparisons);
	    
	    MutationOutput fallbackMutation(const MutationInput& input, SharedContext& ctx);
    
    // Core REDQUEEN methods
    std::vector<uint8_t> flipInputBits(const std::vector<uint8_t>& input, size_t offset, size_t length);
    bool checkStateChange(const std::vector<uint8_t>& original_input,
                         const std::vector<uint8_t>& modified_input,
                         SharedContext& ctx);
    
    double calculateMappingConfidence(const ColoringEntry& entry,
                                    const std::vector<uint8_t>& input);
    
    // String and numeric handling
    std::vector<std::vector<uint8_t>> generateStringReplacements(const std::string& original);
    std::vector<std::vector<uint8_t>> generateNumericReplacements(const std::vector<uint8_t>& original);
    
    // Automatic patch application
    bool applyAutomaticPatch(std::vector<uint8_t>& input, const InputToStateMapping& mapping);
    std::vector<std::vector<uint8_t>> generatePatchCandidates(const InputToStateMapping& mapping);
    
    // Coloring-related
    void updateColoringDatabase(const ColoringResult& result);
    std::vector<ColoringEntry> queryColoringDatabase(const std::vector<uint8_t>& input);
};

// REDQUEEN strategy scheduler
class REDQUEENScheduler {
private:
    const REDQUEENMutation* redqueen_;
    std::unordered_map<size_t, double> seed_mapping_scores_;
    std::unordered_map<size_t, size_t> seed_coloring_attempts_;
    
public:
    REDQUEENScheduler(const REDQUEENMutation* redqueen) : redqueen_(redqueen) {}
    
    // Seed priority evaluation
    double evaluateSeedPriority(const std::vector<uint8_t>& seed, SharedContext& ctx);
    void updateSeedMappingScore(size_t seed_hash, double score);
    
    // Get the most promising seeds
    std::vector<size_t> getPromisingSeeds(size_t max_count = 10);
};

// REDQUEEN utilities
class REDQUEENUtils {
public:
    // Input analysis
    static std::vector<size_t> findPotentialMagicOffsets(const std::vector<uint8_t>& input);
    static bool isLikelyStringData(const std::vector<uint8_t>& data, size_t offset, size_t length);
    static bool isLikelyNumericData(const std::vector<uint8_t>& data, size_t offset, size_t length);
    
    // Comparison-instruction analysis
    static std::vector<uint8_t> extractComparisonOperand(const std::vector<uint8_t>& trace_data, 
                                                        uint64_t instruction_address);
    
    // Endianness conversion
    static std::vector<uint8_t> toBytes(uint64_t value, bool little_endian = true);
    static uint64_t fromBytes(const std::vector<uint8_t>& bytes, bool little_endian = true);
};

} // namespace triofuzz 
