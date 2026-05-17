#include "../../../include/algorithms/mutation/cmplog_mutation.hpp"
#include "../../../include/algorithms/instrumentation/cmplog_instrumentation.hpp"
#include <algorithm>
#include <random>
#include <cstring>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <limits>
#include <unordered_map>
#include <set>
#include <cstdlib>
#include <numeric>

namespace triofuzz {
namespace {

using ComparisonInfo = CmpLogInstrumentation::ComparisonInfo;
using ComparisonType = CmpLogInstrumentation::ComparisonType;

CmpType inferCmpType(const ComparisonInfo& info) {
    switch (info.type) {
        case ComparisonType::INTEGER_EQ:
        case ComparisonType::INTEGER_NE:
        case ComparisonType::INTEGER_LT:
        case ComparisonType::INTEGER_LE:
        case ComparisonType::INTEGER_GT:
        case ComparisonType::INTEGER_GE: {
            switch (info.operand_size) {
                case 1: return CmpType::INT8;
                case 2: return CmpType::INT16;
                case 4: return CmpType::INT32;
                case 8: return CmpType::INT64;
                default: return CmpType::MEMORY;
            }
        }
        case ComparisonType::FLOATING_EQ:
        case ComparisonType::FLOATING_LT:
            return (info.operand_size == 4) ? CmpType::FP32 : CmpType::FP64;
        case ComparisonType::STRING_EQ:
        case ComparisonType::STRING_NE:
        case ComparisonType::STRING_CMP:
            return CmpType::STRING;
        case ComparisonType::MEMCMP:
            return CmpType::MEMORY;
        case ComparisonType::CUSTOM:
        default:
            return CmpType::MEMORY;
    }
}

CmpOp inferCmpOp(const ComparisonInfo& info) {
    switch (info.type) {
        case ComparisonType::INTEGER_EQ:
        case ComparisonType::STRING_EQ:
        case ComparisonType::FLOATING_EQ:
            return CmpOp::EQUAL;
        case ComparisonType::INTEGER_NE:
        case ComparisonType::STRING_NE:
            return CmpOp::NOT_EQUAL;
        case ComparisonType::INTEGER_LT:
        case ComparisonType::FLOATING_LT:
            return CmpOp::LESS_THAN;
        case ComparisonType::INTEGER_LE:
            return CmpOp::LESS_EQUAL;
        case ComparisonType::INTEGER_GT:
            return CmpOp::GREATER_THAN;
        case ComparisonType::INTEGER_GE:
            return CmpOp::GREATER_EQUAL;
        case ComparisonType::MEMCMP:
            return info.comparison_result ? CmpOp::EQUAL : CmpOp::NOT_EQUAL;
        case ComparisonType::STRING_CMP:
        case ComparisonType::CUSTOM:
        default:
            return CmpOp::UNKNOWN;
    }
}

CmpLogEntry convertToEntry(const ComparisonInfo& info) {
    CmpLogEntry entry{};
    entry.instruction_address = info.instruction_address;
    entry.context_hash = CmpLogUtils::hashBytes(info.left_operand.value) ^
                         (CmpLogUtils::hashBytes(info.right_operand.value) << 1);
    entry.type = inferCmpType(info);
    entry.operation = inferCmpOp(info);
    entry.operand1 = info.left_operand.value;
    entry.operand2 = info.right_operand.value;
    entry.hit_count = static_cast<uint32_t>(std::min<uint64_t>(info.hit_count, std::numeric_limits<uint32_t>::max()));
    entry.is_constant = info.right_operand.is_constant;
    entry.input_offset = info.left_operand.input_offset;
    entry.true_count = static_cast<uint32_t>(std::min<uint64_t>(info.true_count, std::numeric_limits<uint32_t>::max()));
    entry.false_count = static_cast<uint32_t>(std::min<uint64_t>(info.false_count, std::numeric_limits<uint32_t>::max()));
    return entry;
}

} // namespace

CmpLogMutation::CmpLogMutation() {
    // Initialize configuration
    config_.enable_string_mutations = true;
    config_.enable_integer_mutations = true;
    config_.enable_float_mutations = true;
    config_.enable_endianness_swap = true;
    config_.enable_type_confusion = true;
    config_.max_string_length = 256;
    config_.max_mutation_attempts = 1000;
    config_.constant_replacement_probability = 0.8;
    config_.arithmetic_progression_steps = 16;
}

MutationOutput CmpLogMutation::execute(const MutationInput& input, SharedContext& ctx) {
    MutationOutput output = input;  // Start with a copy of the input
    synchronizeDatabase(ctx);

    const auto& entries = cmplog_db_.getAllEntries();
    if (entries.empty()) {
        // If no CmpLog data available, perform basic random mutation
        if (!output.empty()) {
            std::uniform_int_distribution<size_t> pos_dist(0, output.size() - 1);
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            size_t pos = pos_dist(random_gen_);
            output[pos] ^= byte_dist(random_gen_);
        }
        return output;
    }

    bool prioritize = (std::getenv("triofuzz_CMPLOG_PRIORITY") != nullptr);
    // Priority selection: constant comparisons > small-width integers (2/4/8) > memcmp/short string comparisons > high failure rate > hotspots
    auto score = [](const CmpLogEntry& e) {
        double s = 0.0;
        // Prefer constant-side comparisons
        if (e.is_constant) s += 3.0;
        // Prefer small integral widths
        size_t w = e.operand1.size();
        if (w==2||w==4||w==8) s += 1.0;
        // Prefer short memory/string compares (<=16)
        if ((e.type==CmpType::MEMORY || e.type==CmpType::STRING) && w>0 && w<=16) s += 0.8;
        // Prefer failing comparisons (more false than true)
        if (e.false_count > e.true_count) s += 2.0;
        // Light preference for hot PCs
        s += std::min<uint32_t>(e.hit_count, 10) * 0.05;
        return s;
    };
    // Select best among top-K to keep diversity
    size_t n = entries.size();
    std::vector<size_t> idx(n);
    std::iota(idx.begin(), idx.end(), 0);
    std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b){return score(entries[a])>score(entries[b]);});
    size_t topk = std::min<size_t>(n, 8);
    std::uniform_int_distribution<size_t> top_pick(0, topk-1);
    const CmpLogEntry& entry = entries[idx[top_pick(random_gen_)]];
    
    // Strategy selection
    CmpLogStrategy selected_strategy = CmpLogStrategy::REPLACE_OPERANDS;
    if (prioritize) {
        // Strategy priority: constants/integers -> REPLACE/ARITH; strings/memory -> SUBSTRING/DICT; otherwise random
        if (entry.type == CmpType::INT8 || entry.type == CmpType::INT16 || entry.type == CmpType::INT32 || entry.type == CmpType::INT64) {
            if ((random_gen_() & 3) == 0) selected_strategy = CmpLogStrategy::ARITHMETIC_PROGRESSION; else selected_strategy = CmpLogStrategy::REPLACE_OPERANDS;
        } else if (entry.type == CmpType::STRING || entry.type == CmpType::MEMORY) {
            selected_strategy = (entry.operand1.size() <= 16) ? CmpLogStrategy::SUBSTRING_MATCHING : CmpLogStrategy::DICTIONARY_BASED;
        } else {
            std::vector<CmpLogStrategy> strategies = { CmpLogStrategy::REPLACE_OPERANDS, CmpLogStrategy::ARITHMETIC_PROGRESSION, CmpLogStrategy::DICTIONARY_BASED, CmpLogStrategy::SUBSTRING_MATCHING, CmpLogStrategy::ENDIANNESS_SWAP, CmpLogStrategy::TYPE_CONFUSION };
            std::uniform_int_distribution<size_t> strategy_dist(0, strategies.size() - 1);
            selected_strategy = strategies[strategy_dist(random_gen_)];
        }
    } else {
        std::vector<CmpLogStrategy> strategies = { CmpLogStrategy::REPLACE_OPERANDS, CmpLogStrategy::ARITHMETIC_PROGRESSION, CmpLogStrategy::DICTIONARY_BASED, CmpLogStrategy::SUBSTRING_MATCHING, CmpLogStrategy::ENDIANNESS_SWAP, CmpLogStrategy::TYPE_CONFUSION };
        std::uniform_int_distribution<size_t> strategy_dist(0, strategies.size() - 1);
        selected_strategy = strategies[strategy_dist(random_gen_)];
    }
    stats_.strategy_usage[selected_strategy]++;
    
    // Apply selected strategy
    switch (selected_strategy) {
        case CmpLogStrategy::REPLACE_OPERANDS:
            output = applyReplaceOperands(input, entry, ctx);
            break;
        case CmpLogStrategy::ARITHMETIC_PROGRESSION:
            output = applyArithmeticProgression(input, entry, ctx);
            break;
        case CmpLogStrategy::DICTIONARY_BASED:
            output = applyDictionaryBased(input, entry, ctx);
            break;
        case CmpLogStrategy::SUBSTRING_MATCHING:
            output = applySubstringMatching(input, entry, ctx);
            break;
        case CmpLogStrategy::ENDIANNESS_SWAP:
            output = applyEndiannesSwap(input, entry, ctx);
            break;
        case CmpLogStrategy::TYPE_CONFUSION:
            output = applyTypeConfusion(input, entry, ctx);
            break;
        default:
            break;
    }

    if (output != input) {
        stats_.successful_mutations++;
    }

    return output;
}

void CmpLogMutation::addCmpLogEntry(const CmpLogEntry& entry) {
    cmplog_db_.addEntry(entry);
    stats_.total_entries++;
    
    // Extract constants
    if (entry.is_constant) {
        stats_.constants_discovered++;
    }
}

void CmpLogMutation::synchronizeDatabase(const SharedContext& ctx) {
    ctx.withData<std::vector<ComparisonInfo>>(
        "cmplog_comparison_infos",
        [this](const std::vector<ComparisonInfo>& comparisons) {
            // Smart merge instead of clearing: accumulate unique PC+operand combinations
            std::unordered_map<uint64_t, std::set<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>> pc_to_operands;

            // First, collect existing entries by PC
            for (const auto& existing : cmplog_db_.getAllEntries()) {
                pc_to_operands[existing.instruction_address].insert(
                    std::make_pair(existing.operand1, existing.operand2)
                );
            }

            // Merge new comparisons
            for (const auto& info : comparisons) {
                auto entry = convertToEntry(info);
                auto& operand_set = pc_to_operands[entry.instruction_address];
                auto operand_pair = std::make_pair(entry.operand1, entry.operand2);

                // Add if this PC+operand combination is new
                if (operand_set.find(operand_pair) == operand_set.end()) {
                    cmplog_db_.addEntry(entry);
                    operand_set.insert(operand_pair);
                    stats_.total_entries++;
                    if (entry.is_constant) {
                        stats_.constants_discovered++;
                    }
                }
            }
            return 0;
        });
}

void CmpLogMutation::processCmpLogData(const std::vector<uint8_t>& cmplog_data) {
    (void)cmplog_data;
    // TODO: Implement raw CmpLog data parsing and database population logic
    cmplog_db_.clear();
    stats_.total_entries = 0;
    stats_.constants_discovered = 0;
}

MutationOutput CmpLogMutation::applyReplaceOperands(const MutationInput& input,
                                                   const CmpLogEntry& entry, SharedContext& ctx) {
    MutationOutput output = input;

    // Select operand to replace
    std::uniform_int_distribution<int> coin_flip(0, 1);
    const std::vector<uint8_t>& target_operand = (coin_flip(random_gen_) == 0) ? entry.operand1 : entry.operand2;
    const std::vector<uint8_t>& replacement_operand = (target_operand == entry.operand1) ? entry.operand2 : entry.operand1;

    if (target_operand.empty() || replacement_operand.empty()) {
        return output;
    }

    // Strategy 1: Try to find exact match first (original behavior)
    std::vector<size_t> offsets = findInputOffsets(input, target_operand);
    if (!offsets.empty()) {
        std::uniform_int_distribution<size_t> offset_dist(0, offsets.size() - 1);
        size_t chosen_offset = offsets[offset_dist(random_gen_)];

        if (chosen_offset + replacement_operand.size() <= output.size()) {
            std::copy(replacement_operand.begin(), replacement_operand.end(),
                     output.begin() + chosen_offset);
            return output;
        }
    }

    // Strategy 2 (RedQueen-style): Scan all aligned positions and replace similar values
    // This helps fix broken magic numbers even when exact match is not found
    if (entry.type == CmpType::INT32 || entry.type == CmpType::INT16 ||
        entry.type == CmpType::INT8 || entry.type == CmpType::INT64) {

        size_t operand_size = replacement_operand.size();
        if (operand_size > 0 && operand_size <= 8 && output.size() >= operand_size) {

            // Try random offset (RedQueen-style blind replacement)
            std::uniform_int_distribution<size_t> pos_dist(0, output.size() - operand_size);
            size_t random_offset = pos_dist(random_gen_);

            std::copy(replacement_operand.begin(), replacement_operand.end(),
                     output.begin() + random_offset);
        }
    }

    return output;
}

MutationOutput CmpLogMutation::applyArithmeticProgression(const MutationInput& input,
                                                         const CmpLogEntry& entry, SharedContext& ctx) {
    MutationOutput output = input;
    
    if (entry.type != CmpType::INT8 && entry.type != CmpType::INT16 && 
        entry.type != CmpType::INT32 && entry.type != CmpType::INT64) {
        return output; // Only effective for integer types
    }
    
    // Extract integer value
    uint64_t base_value = CmpLogUtils::bytesToInteger(entry.operand1);
    auto progression = generateIntegerProgression(base_value, config_.arithmetic_progression_steps);
    
    if (progression.empty()) {
        return output;
    }
    
    // Select a progression value
    std::uniform_int_distribution<size_t> prog_dist(0, progression.size() - 1);
    uint64_t new_value = progression[prog_dist(random_gen_)];
    std::vector<uint8_t> new_bytes = CmpLogUtils::integerToBytes(new_value, entry.operand1.size());
    
    // Replace in input
    std::vector<size_t> offsets = findInputOffsets(input, entry.operand1);
    if (!offsets.empty()) {
        std::uniform_int_distribution<size_t> offset_dist(0, offsets.size() - 1);
        size_t chosen_offset = offsets[offset_dist(random_gen_)];
        if (chosen_offset + new_bytes.size() <= output.size()) {
            std::copy(new_bytes.begin(), new_bytes.end(),
                     output.begin() + chosen_offset);
            stats_.integer_mutations++;
        }
    }

    return output;
}

MutationOutput CmpLogMutation::applyDictionaryBased(const MutationInput& input,
                                                   const CmpLogEntry& entry, SharedContext& ctx) {
    MutationOutput output = input;
    
    // Use discovered constants as dictionary entries
    const auto& constants = cmplog_db_.getDiscoveredConstants();
    if (constants.empty()) {
        return output;
    }
    
    // Randomly select a constant
    auto it = constants.begin();
    std::uniform_int_distribution<size_t> const_dist(0, constants.size() - 1);
    std::advance(it, const_dist(random_gen_));
    const std::vector<uint8_t>& chosen_constant = *it;
    
    // Insert constant at random position in input
    if (!chosen_constant.empty() && chosen_constant.size() <= output.size()) {
        std::uniform_int_distribution<size_t> offset_dist(0, output.size() - chosen_constant.size());
        size_t offset = offset_dist(random_gen_);
        std::copy(chosen_constant.begin(), chosen_constant.end(),
                 output.begin() + offset);
    }

    return output;
}

MutationOutput CmpLogMutation::applySubstringMatching(const MutationInput& input,
                                                     const CmpLogEntry& entry, SharedContext& ctx) {
    MutationOutput output = input;
    
    if (entry.type != CmpType::STRING && entry.type != CmpType::MEMORY) {
        return output;
    }
    
    // Handle string comparison
    std::string operand1_str = CmpLogUtils::bytesToString(entry.operand1);
    std::string operand2_str = CmpLogUtils::bytesToString(entry.operand2);
    
    if (operand1_str.empty() && operand2_str.empty()) {
        return output;
    }
    
    // Generate string mutations
    std::vector<std::string> mutations;
    if (!operand1_str.empty()) {
        auto muts1 = generateStringMutations(operand1_str);
        mutations.insert(mutations.end(), muts1.begin(), muts1.end());
    }
    if (!operand2_str.empty()) {
        auto muts2 = generateStringMutations(operand2_str);
        mutations.insert(mutations.end(), muts2.begin(), muts2.end());
    }
    
    if (!mutations.empty()) {
        std::uniform_int_distribution<size_t> mut_dist(0, mutations.size() - 1);
        const std::string& chosen_mutation = mutations[mut_dist(random_gen_)];
        std::vector<uint8_t> mutation_bytes = CmpLogUtils::stringToBytes(chosen_mutation);

        // Find a suitable position in the input to replace
        if (!mutation_bytes.empty() && mutation_bytes.size() <= output.size()) {
            std::uniform_int_distribution<size_t> offset_dist(0, output.size() - mutation_bytes.size());
            size_t offset = offset_dist(random_gen_);
            std::copy(mutation_bytes.begin(), mutation_bytes.end(),
                     output.begin() + offset);
            stats_.string_mutations++;
        }
    }

    return output;
}

MutationOutput CmpLogMutation::applyEndiannesSwap(const MutationInput& input,
                                                 const CmpLogEntry& entry, SharedContext& ctx) {
    MutationOutput output = input;
    
    if (entry.operand1.size() < 2) {
        return output; // Endianness swap requires at least 2 bytes
    }
    
    std::vector<uint8_t> swapped = swapEndianness(entry.operand1);
    
    // Find and replace in input
    std::vector<size_t> offsets = findInputOffsets(input, entry.operand1);
    if (!offsets.empty()) {
        std::uniform_int_distribution<size_t> offset_dist(0, offsets.size() - 1);
        size_t chosen_offset = offsets[offset_dist(random_gen_)];
        if (chosen_offset + swapped.size() <= output.size()) {
            std::copy(swapped.begin(), swapped.end(),
                     output.begin() + chosen_offset);
        }
    }

    return output;
}

MutationOutput CmpLogMutation::applyTypeConfusion(const MutationInput& input,
                                                 const CmpLogEntry& entry, SharedContext& ctx) {
    MutationOutput output = input;
    
    // Try interpreting data as different types
    std::vector<CmpType> target_types = {CmpType::INT32, CmpType::INT64, CmpType::FP32, CmpType::FP64};
    std::uniform_int_distribution<size_t> type_dist(0, target_types.size() - 1);
    CmpType new_type = target_types[type_dist(random_gen_)];
    
    if (new_type == entry.type) {
        return output; // Avoid meaningless conversion
    }
    
    std::vector<uint8_t> converted = convertType(entry.operand1, entry.type, new_type);
    if (!converted.empty()) {
        std::vector<size_t> offsets = findInputOffsets(input, entry.operand1);
        if (!offsets.empty()) {
            std::uniform_int_distribution<size_t> offset_dist(0, offsets.size() - 1);
            size_t chosen_offset = offsets[offset_dist(random_gen_)];
            size_t copy_size = std::min(converted.size(), output.size() - chosen_offset);
            std::copy(converted.begin(), converted.begin() + copy_size,
                     output.begin() + chosen_offset);
        }
    }

    return output;
}

// Helper method implementations
std::vector<size_t> CmpLogMutation::findInputOffsets(const std::vector<uint8_t>& input,
                                                    const std::vector<uint8_t>& target) const {
    std::vector<size_t> offsets;
    
    if (target.empty() || target.size() > input.size()) {
        return offsets;
    }
    
    for (size_t i = 0; i <= input.size() - target.size(); ++i) {
        if (std::equal(target.begin(), target.end(), input.begin() + i)) {
            offsets.push_back(i);
        }
    }
    
    return offsets;
}

bool CmpLogMutation::isInterestingConstant(const std::vector<uint8_t>& data) const {
    if (data.empty()) return false;
    
    // Check for common interesting values
    if (data.size() == 4) {
        uint32_t value = 0;
        std::memcpy(&value, data.data(), sizeof(uint32_t));
        return (value == 0 || value == 0xFFFFFFFF || value == 0x80000000 || 
                value == 0x7FFFFFFF || (value & 0xFFFF) == 0 || (value & 0xFF) == 0);
    }
    
    return true;
}

std::vector<uint8_t> CmpLogMutation::convertType(const std::vector<uint8_t>& data, 
                                                CmpType from, CmpType to) const {
    if (data.empty()) return {};
    
    // Simplified type conversion implementation
    if (from == CmpType::INT32 && to == CmpType::FP32 && data.size() == 4) {
        uint32_t int_val = 0;
        std::memcpy(&int_val, data.data(), sizeof(uint32_t));
        float float_val = static_cast<float>(int_val);
        std::vector<uint8_t> result(4);
        std::memcpy(result.data(), &float_val, 4);
        return result;
    }
    
    if (from == CmpType::FP32 && to == CmpType::INT32 && data.size() == 4) {
        float float_val = 0.0f;
        std::memcpy(&float_val, data.data(), sizeof(float));
        uint32_t int_val = static_cast<uint32_t>(float_val);
        std::vector<uint8_t> result(4);
        std::memcpy(result.data(), &int_val, 4);
        return result;
    }
    
    return data; // Default: return original data
}

std::vector<std::string> CmpLogMutation::generateStringMutations(const std::string& original) const {
    std::vector<std::string> mutations;
    
    if (original.empty()) return mutations;
    
    // Common string mutations
    mutations.push_back(original + "x");
    mutations.push_back("x" + original);
    mutations.push_back(original.substr(0, original.length() / 2));
    mutations.push_back(original + original);
    
    // Case mutations
    std::string upper = original;
    std::string lower = original;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    mutations.push_back(upper);
    mutations.push_back(lower);
    
    // Character replacement
    for (size_t i = 0; i < original.length(); ++i) {
        std::string mutated = original;
        mutated[i] = 'X';
        mutations.push_back(mutated);
        
        if (std::isalpha(original[i])) {
            mutated[i] = std::islower(original[i]) ? std::toupper(original[i]) : std::tolower(original[i]);
            mutations.push_back(mutated);
        }
    }
    
    return mutations;
}

bool CmpLogMutation::isValidString(const std::vector<uint8_t>& data) const {
    if (data.empty()) return false;
    
    size_t printable_count = 0;
    for (uint8_t byte : data) {
        if (std::isprint(byte) || byte == ' ' || byte == '\t' || byte == '\n') {
            printable_count++;
        }
    }
    
    return printable_count >= data.size() * 0.8; // At least 80% printable characters
}

std::vector<uint64_t> CmpLogMutation::generateIntegerProgression(uint64_t base, size_t steps) const {
    std::vector<uint64_t> progression;

    // Arithmetic progression
    for (size_t i = 1; i <= steps; ++i) {
        progression.push_back(base + i);
        if (base >= i) progression.push_back(base - i);
        progression.push_back(base * (i + 1));
        if (i > 1 && base % i == 0) progression.push_back(base / i);
    }

    // Bitwise operations
    progression.push_back(base << 1);
    progression.push_back(base >> 1);
    progression.push_back(~base);
    progression.push_back(base ^ 0xFFFFFFFF);

    // Special values - 32-bit boundaries
    progression.push_back(0);
    progression.push_back(0xFFFFFFFF);
    progression.push_back(0x80000000);
    progression.push_back(0x7FFFFFFF);

    // ========================================================================
    // Integer overflow boundary values for image dimension calculations
    // ========================================================================

    // 64-bit overflow boundaries (for size_t calculations)
    progression.push_back(0x100000000ULL);           // 2^32 - key overflow point
    progression.push_back(0x100000000ULL - 1);       // 2^32 - 1
    progression.push_back(0x100000000ULL + 1);       // 2^32 + 1
    progression.push_back(0xFFFFFFFFFFFFFFFFULL);    // 2^64 - 1
    progression.push_back(0x8000000000000000ULL);    // 2^63
    progression.push_back(0x7FFFFFFFFFFFFFFFULL);    // 2^63 - 1

    // Common multiplication overflow trigger values (width * height * channels scenarios)
    // Possible values of A when A * B = 2^32
    progression.push_back(65536);                    // 2^16, 65536 * 65536 = 2^32
    progression.push_back(65535);                    // 2^16 - 1
    progression.push_back(65537);                    // 2^16 + 1
    progression.push_back(32768);                    // 2^15
    progression.push_back(16384);                    // 2^14
    progression.push_back(8192);                     // 2^13
    progression.push_back(4096);                     // 2^12
    progression.push_back(2048);                     // 2^11
    progression.push_back(1024);                     // 2^10

    // Image dimension boundaries (width/height limits)
    progression.push_back(0x7FFFFFFF);               // PNG max dimension
    progression.push_back(0x80000000);               // Exceeds PNG max
    progression.push_back(1000000);                  // Common large image dimension
    progression.push_back(100000);
    progression.push_back(10000);

    // Common bit-depth multipliers (bit_depth: 1, 2, 4, 8, 16)
    // channels: 1, 2, 3, 4
    // row_bytes = width * channels * (bit_depth / 8)
    progression.push_back(0x40000000);               // 2^30
    progression.push_back(0x20000000);               // 2^29
    progression.push_back(0x10000000);               // 2^28
    progression.push_back(0x08000000);               // 2^27

    // Try to find overflow multipliers based on base value
    if (base > 0 && base < 0x100000000ULL) {
        // Try to find x such that base * x ~ 2^32
        uint64_t target = 0x100000000ULL;
        uint64_t multiplier = target / base;
        if (multiplier > 1) {
            progression.push_back(multiplier);
            progression.push_back(multiplier - 1);
            progression.push_back(multiplier + 1);
        } else if (multiplier == 1) {
            progression.push_back(1);
            progression.push_back(2);
        }
        // Try to find x such that base * x ~ 2^31
        target = 0x80000000ULL;
        multiplier = target / base;
        if (multiplier > 1) {
            progression.push_back(multiplier);
            progression.push_back(multiplier - 1);
            progression.push_back(multiplier + 1);
        } else if (multiplier == 1) {
            progression.push_back(1);
            progression.push_back(2);
        }
    }

    // Small integer boundaries (for 8/16-bit truncation)
    progression.push_back(255);                      // 2^8 - 1
    progression.push_back(256);                      // 2^8
    progression.push_back(257);                      // 2^8 + 1
    progression.push_back(127);                      // 2^7 - 1 (signed byte max)
    progression.push_back(128);                      // 2^7 (signed byte overflow)

    return progression;
}

std::vector<double> CmpLogMutation::generateFloatProgression(double base, size_t steps) const {
    std::vector<double> progression;
    
    for (size_t i = 1; i <= steps; ++i) {
        progression.push_back(base + i);
        progression.push_back(base - i);
        progression.push_back(base * (i + 1));
        if (i > 1) progression.push_back(base / i);
    }
    
    // Special floating-point values
    progression.push_back(0.0);
    progression.push_back(-0.0);
    progression.push_back(std::numeric_limits<double>::infinity());
    progression.push_back(-std::numeric_limits<double>::infinity());
    progression.push_back(std::numeric_limits<double>::quiet_NaN());
    
    return progression;
}

std::vector<uint8_t> CmpLogMutation::swapEndianness(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> swapped = data;
    std::reverse(swapped.begin(), swapped.end());
    return swapped;
}

bool CmpLogMutation::replaceInInput(std::vector<uint8_t>& input, 
                                   const std::vector<uint8_t>& old_value,
                                   const std::vector<uint8_t>& new_value) const {
    auto offsets = findAllOccurrences(input, old_value);
    if (offsets.empty()) return false;
    
    // Replace first match
    size_t offset = offsets[0];
    size_t copy_size = std::min(new_value.size(), input.size() - offset);
    std::copy(new_value.begin(), new_value.begin() + copy_size,
              input.begin() + offset);
    
    return true;
}

std::vector<size_t> CmpLogMutation::findAllOccurrences(const std::vector<uint8_t>& input,
                                                      const std::vector<uint8_t>& pattern) const {
    return findInputOffsets(input, pattern);
}

// CmpLogDatabase implementation
void CmpLogDatabase::addEntry(const CmpLogEntry& entry) {
    size_t index = entries_.size();
    entries_.push_back(entry);
    
    address_to_entries_[entry.instruction_address].push_back(index);
    context_to_entries_[entry.context_hash].push_back(index);
    
    // Add discovered constants
    if (!entry.operand1.empty()) {
        discovered_constants_.insert(entry.operand1);
    }
    if (!entry.operand2.empty()) {
        discovered_constants_.insert(entry.operand2);
    }
}

std::vector<CmpLogEntry> CmpLogDatabase::getEntriesForAddress(uint64_t address) const {
    std::vector<CmpLogEntry> result;
    auto it = address_to_entries_.find(address);
    if (it != address_to_entries_.end()) {
        for (size_t index : it->second) {
            result.push_back(entries_[index]);
        }
    }
    return result;
}

std::vector<CmpLogEntry> CmpLogDatabase::getEntriesForContext(uint64_t context) const {
    std::vector<CmpLogEntry> result;
    auto it = context_to_entries_.find(context);
    if (it != context_to_entries_.end()) {
        for (size_t index : it->second) {
            result.push_back(entries_[index]);
        }
    }
    return result;
}

void CmpLogDatabase::clear() {
    entries_.clear();
    address_to_entries_.clear();
    context_to_entries_.clear();
    discovered_constants_.clear();
}

// CmpLogUtils implementation
uint64_t CmpLogUtils::bytesToInteger(const std::vector<uint8_t>& bytes, bool little_endian) {
    uint64_t result = 0;
    size_t size = std::min(bytes.size(), size_t(8));
    
    if (little_endian) {
        for (size_t i = 0; i < size; ++i) {
            result |= (static_cast<uint64_t>(bytes[i]) << (i * 8));
        }
    } else {
        for (size_t i = 0; i < size; ++i) {
            result |= (static_cast<uint64_t>(bytes[size - 1 - i]) << (i * 8));
        }
    }
    
    return result;
}

std::vector<uint8_t> CmpLogUtils::integerToBytes(uint64_t value, size_t size, bool little_endian) {
    std::vector<uint8_t> bytes(size);
    
    if (little_endian) {
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = (value >> (i * 8)) & 0xFF;
        }
    } else {
        for (size_t i = 0; i < size; ++i) {
            bytes[size - 1 - i] = (value >> (i * 8)) & 0xFF;
        }
    }
    
    return bytes;
}

double CmpLogUtils::bytesToFloat(const std::vector<uint8_t>& bytes) {
    if (bytes.size() == 4) {
        float f;
        std::memcpy(&f, bytes.data(), 4);
        return static_cast<double>(f);
    } else if (bytes.size() == 8) {
        double d;
        std::memcpy(&d, bytes.data(), 8);
        return d;
    }
    return 0.0;
}

std::vector<uint8_t> CmpLogUtils::floatToBytes(double value, bool single_precision) {
    if (single_precision) {
        float f = static_cast<float>(value);
        std::vector<uint8_t> bytes(4);
        std::memcpy(bytes.data(), &f, 4);
        return bytes;
    } else {
        std::vector<uint8_t> bytes(8);
        std::memcpy(bytes.data(), &value, 8);
        return bytes;
    }
}

std::string CmpLogUtils::bytesToString(const std::vector<uint8_t>& bytes) {
    std::string result;
    for (uint8_t byte : bytes) {
        if (byte == 0) break; // Stop at null terminator
        result += static_cast<char>(byte);
    }
    return result;
}

std::vector<uint8_t> CmpLogUtils::stringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

bool CmpLogUtils::isLikelyInteger(const std::vector<uint8_t>& data) {
    return data.size() == 1 || data.size() == 2 || data.size() == 4 || data.size() == 8;
}

bool CmpLogUtils::isLikelyFloat(const std::vector<uint8_t>& data) {
    return data.size() == 4 || data.size() == 8;
}

bool CmpLogUtils::isLikelyString(const std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    
    size_t printable_count = 0;
    for (uint8_t byte : data) {
        if (std::isprint(byte) || byte == 0) {
            printable_count++;
        }
    }
    
    return printable_count >= data.size() * 0.8;
}

uint64_t CmpLogUtils::hashBytes(const std::vector<uint8_t>& data) {
    uint64_t hash = 0;
    for (uint8_t byte : data) {
        hash = hash * 31 + byte;
    }
    return hash;
}

bool CmpLogUtils::compareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

} // namespace triofuzz 
