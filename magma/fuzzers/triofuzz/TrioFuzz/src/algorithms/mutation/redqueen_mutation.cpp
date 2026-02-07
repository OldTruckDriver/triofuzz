#include "../../../include/algorithms/mutation/redqueen_mutation.hpp"
#include "../../../include/utils/execution_tracer.hpp"
#include <algorithm>
#include <random>
#include <cstring>
#include <regex>
#include <iomanip>
#include <sstream>

namespace triofuzz {

REDQUEENMutation::REDQUEENMutation() {
    // Initialize default configuration
    config_.enable_string_extraction = true;
    config_.enable_numeric_extraction = true;
    config_.enable_automatic_patching = true;
    config_.max_coloring_attempts = 1000;
    config_.min_confidence_threshold = 0.7;
    config_.max_patch_size = 64;
    
    // Create execution tracer
    tracer_ = TracerFactory::createBestAvailableTracer();
    if (tracer_) {
        tracer_->initialize();
        tracer_->enableTaintTracking(true);
    }
}

MutationOutput REDQUEENMutation::execute(const MutationInput& input, SharedContext& ctx) {
    MutationOutput output = input;  // Copy input data directly
    
    if (!tracer_) {
        // If no tracer is available, fall back to simple mutation
        return fallbackMutation(input, ctx);
    }
    
    // Get target program information
    auto target_info = ctx.getTargetInfo();
    if (target_info.has_value()) {
        tracer_->setTarget(target_info->target_path, target_info->args);
    }
    
    // Phase 1: execute and collect comparison-instruction information
    bool trace_success = tracer_->executeWithTracing(input, std::chrono::milliseconds(5000));
    stats_.total_colorings++;
    
    if (!trace_success) {
        tracer_->clearTraceData();
        return fallbackMutation(input, ctx);
    }
    
    // Get comparison-instruction records
    const auto& comparisons = tracer_->getComparisons();
    if (comparisons.empty()) {
        tracer_->clearTraceData();
        return fallbackMutation(input, ctx);
    }
    
    // Phase 2: perform coloring analysis
    ColoringResult coloring = performAdvancedColoring(input, comparisons, ctx);
    
    if (!coloring.has_new_mappings && coloring.entries.empty()) {
        tracer_->clearTraceData();
        return fallbackMutation(input, ctx);
    }
    
    // Phase 3: extract input-to-state mappings
    std::vector<InputToStateMapping> mappings = extractMappings(coloring);
    if (!mappings.empty()) {
        stats_.successful_mappings++;
        updateColoringDatabase(coloring);
    }
    
    // Phase 4: apply smart patches
    if (!mappings.empty()) {
        output = applyInputPatches(input, mappings);
        if (output != input) {
            stats_.patches_applied++;
        }
    } else {
        // Use magic-byte mutation based on actual comparison instructions
        output = applyMagicBytesMutation(input, comparisons);
    }
    
    tracer_->clearTraceData();
    return output;
}

ColoringResult REDQUEENMutation::performAdvancedColoring(const std::vector<uint8_t>& input, 
                                                        const std::vector<ComparisonEntry>& comparisons,
                                                        SharedContext& ctx) {
    ColoringResult result;
    result.has_new_mappings = false;
    
    // Coloring analysis based on real comparison-instruction traces
    for (const auto& cmp : comparisons) {
        if (!cmp.is_input_dependent || cmp.taint_offsets.empty()) {
            continue;
        }
        
        ColoringEntry entry;
        entry.address = cmp.pc;
        entry.context = cmp.basic_block_id;
        entry.hit_count = cmp.hit_count;
        entry.is_string_compare = (cmp.type == triofuzz::ComparisonType::STRING_EQ || 
                                  cmp.type == triofuzz::ComparisonType::STRING_CMP);
        
        // Map input bytes to comparison operands
        entry.input_bytes = cmp.operand1;
        entry.cmp_bytes = cmp.operand2;
        
        // Check whether this is a new mapping
        bool is_new_mapping = true;
        for (const auto& existing : coloring_database_) {
            if (existing.address == entry.address && 
                existing.input_bytes == entry.input_bytes &&
                existing.cmp_bytes == entry.cmp_bytes) {
                is_new_mapping = false;
                break;
            }
        }
        
        if (is_new_mapping) {
            result.has_new_mappings = true;
        }
        
        result.entries.push_back(entry);
        result.address_to_entries[entry.address].push_back(result.entries.size() - 1);
    }
    
    return result;
}

MutationOutput REDQUEENMutation::applyMagicBytesMutation(const MutationInput& input,
                                                        const std::vector<ComparisonEntry>& comparisons) {
    MutationOutput output = input;
    
    if (comparisons.empty()) {
        return output;
    }
    
    // Select an interesting comparison instruction
    std::uniform_int_distribution<size_t> cmp_dist(0, comparisons.size() - 1);
    const auto& selected_cmp = comparisons[cmp_dist(random_gen_)];
    
    if (!selected_cmp.is_input_dependent || selected_cmp.taint_offsets.empty()) {
        return output;
    }
    
    // Try applying magic bytes
    for (size_t taint_offset : selected_cmp.taint_offsets) {
        if (taint_offset >= output.size()) continue;
        
        // Strategy 1: replace directly with the target operand
        if (!selected_cmp.operand2.empty() && 
            taint_offset + selected_cmp.operand2.size() <= output.size()) {
            
            std::copy(selected_cmp.operand2.begin(), selected_cmp.operand2.end(),
                     output.begin() + taint_offset);
            stats_.magic_bytes_found++;
            break;
        }
        
        // Strategy 2: type-aware mutation based on comparison type
        switch (selected_cmp.type) {
            case triofuzz::ComparisonType::INT8_EQ:
            case triofuzz::ComparisonType::INT8_NE:
                if (taint_offset < output.size()) {
                    output[taint_offset] = selected_cmp.operand2.empty() ? 
                                          static_cast<uint8_t>(random_gen_() % 256) :
                                          selected_cmp.operand2[0];
                }
                break;
                
            case triofuzz::ComparisonType::INT16_EQ:
            case triofuzz::ComparisonType::INT16_NE:
                if (taint_offset + 1 < output.size() && selected_cmp.operand2.size() >= 2) {
                    output[taint_offset] = selected_cmp.operand2[0];
                    output[taint_offset + 1] = selected_cmp.operand2[1];
                }
                break;
                
            case triofuzz::ComparisonType::INT32_EQ:
            case triofuzz::ComparisonType::INT32_NE:
                if (taint_offset + 3 < output.size() && selected_cmp.operand2.size() >= 4) {
                    for (size_t i = 0; i < 4; ++i) {
                        output[taint_offset + i] = selected_cmp.operand2[i];
                    }
                }
                break;
                
            case triofuzz::ComparisonType::STRING_EQ:
            case triofuzz::ComparisonType::STRING_CMP:
                // Special handling for string comparisons
                if (!selected_cmp.operand2.empty()) {
                    size_t copy_len = std::min(selected_cmp.operand2.size(), 
                                              output.size() - taint_offset);
                    std::copy(selected_cmp.operand2.begin(), 
                             selected_cmp.operand2.begin() + copy_len,
                             output.begin() + taint_offset);
                }
                break;
                
            default:
                // For other types, try direct replacement
                if (!selected_cmp.operand2.empty() && taint_offset < output.size()) {
                    output[taint_offset] = selected_cmp.operand2[0];
                }
                break;
        }
        
        stats_.magic_bytes_found++;
        break;  // Only apply a single magic byte
    }
    
    return output;
}

MutationOutput REDQUEENMutation::fallbackMutation(const MutationInput& input, SharedContext& ctx) {
    MutationOutput output = input;
    
    if (output.empty()) {
        return output;
    }

    // Prefer a lightweight cmplog-guided patch if available (works without external tracers).
    {
        auto pairs_opt =
            ctx.get<std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>>("cmplog_comparisons");
        if (pairs_opt.has_value() && !pairs_opt->empty()) {
            thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<size_t> pick_pair(0, pairs_opt->size() - 1);
            const auto& pr = (*pairs_opt)[pick_pair(gen)];

            auto patch_from_to = [&](const std::vector<uint8_t>& from,
                                     const std::vector<uint8_t>& to) -> bool {
                if (from.empty() || to.empty()) return false;
                if (from.size() > output.size()) return false;

                // Try exact match replacement first.
                std::vector<size_t> offsets;
                for (size_t i = 0; i + from.size() <= output.size(); ++i) {
                    if (std::memcmp(output.data() + i, from.data(), from.size()) == 0) {
                        offsets.push_back(i);
                    }
                }
                size_t off = 0;
                if (!offsets.empty()) {
                    std::uniform_int_distribution<size_t> pick_off(0, offsets.size() - 1);
                    off = offsets[pick_off(gen)];
                } else {
                    // Fall back: overwrite at a random aligned offset.
                    std::uniform_int_distribution<size_t> pick_off(0, output.size() - 1);
                    off = pick_off(gen);
                    if (off + to.size() > output.size()) {
                        off = (to.size() <= output.size()) ? (output.size() - to.size()) : 0;
                    }
                }

                const size_t copy_len = std::min(to.size(), output.size() - off);
                if (copy_len == 0) return false;
                std::memcpy(output.data() + off, to.data(), copy_len);
                return true;
            };

            // Try both directions to maximize chances.
            if (patch_from_to(pr.first, pr.second) || patch_from_to(pr.second, pr.first)) {
                return output;
            }
        }
    }

    // Fallback: try injecting an auto-dictionary token.
    {
        auto dict_opt = ctx.get<std::vector<std::vector<uint8_t>>>("auto_dictionary");
        if (dict_opt.has_value() && !dict_opt->empty()) {
            thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<size_t> pick_tok(0, dict_opt->size() - 1);
            const auto& tok = (*dict_opt)[pick_tok(gen)];
            if (!tok.empty() && tok.size() <= output.size()) {
                std::uniform_int_distribution<size_t> pick_off(0, output.size() - tok.size());
                size_t off = pick_off(gen);
                std::memcpy(output.data() + off, tok.data(), tok.size());
                return output;
            }
        }
    }
    
    // Simple random mutation as a fallback strategy
    std::uniform_int_distribution<size_t> pos_dist(0, output.size() - 1);
    std::uniform_int_distribution<int> mutation_type(0, 3);
    
    size_t pos = pos_dist(random_gen_);
    
    switch (mutation_type(random_gen_)) {
        case 0: {
            // Bit flip
            std::uniform_int_distribution<int> bit_dist(0, 7);
            int bit = bit_dist(random_gen_);
            output[pos] ^= (1 << bit);
            break;
        }
        case 1: {
            // Byte flip
            output[pos] ^= 0xFF;
            break;
        }
        case 2: {
            // Random byte
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            output[pos] = byte_dist(random_gen_);
            break;
        }
        case 3: {
            // Arithmetic mutation
            std::uniform_int_distribution<int> delta_dist(-16, 16);
            int delta = delta_dist(random_gen_);
            output[pos] = static_cast<uint8_t>(
                std::clamp(static_cast<int>(output[pos]) + delta, 0, 255));
            break;
        }
    }
    
    return output;
}

ColoringResult REDQUEENMutation::performColoring(const std::vector<uint8_t>& input, SharedContext& ctx) {
    ColoringResult result;
    result.has_new_mappings = false;
    
    // Perform bit flipping for each possible offset
    for (size_t offset = 0; offset < input.size() && offset < config_.max_coloring_attempts; ++offset) {
        for (size_t bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> flipped_input = flipInputBits(input, offset, 1);
            flipped_input[offset] ^= (1 << bit);
            
                if (checkStateChange(input, flipped_input, ctx)) {
                    ColoringEntry entry;
                    entry.address = 0; // Should be obtained from execution trace
                    entry.context = offset;
                entry.input_bytes = {input[offset]};
                entry.cmp_bytes = {flipped_input[offset]};
                entry.hit_count = 1;
                entry.is_string_compare = REDQUEENUtils::isLikelyStringData(input, offset, 1);
                
                result.entries.push_back(entry);
                result.has_new_mappings = true;
            }
        }
    }
    
    // Build mapping from address to entries
    for (size_t i = 0; i < result.entries.size(); ++i) {
        result.address_to_entries[result.entries[i].address].push_back(i);
    }
    
    return result;
}

std::vector<InputToStateMapping> REDQUEENMutation::extractMappings(const ColoringResult& coloring) {
    std::vector<InputToStateMapping> mappings;
    
    for (const auto& entry : coloring.entries) {
        InputToStateMapping mapping;
        mapping.input_offset = entry.context; // Simplified: use context as offset
        mapping.length = entry.input_bytes.size();
        mapping.state_address = entry.address;
        mapping.target_value = entry.cmp_bytes;
        mapping.confidence = calculateMappingConfidence(entry, {});
        
        if (mapping.confidence >= config_.min_confidence_threshold) {
            mappings.push_back(mapping);
        }
    }
    
    return mappings;
}

MutationOutput REDQUEENMutation::applyInputPatches(const MutationInput& input, 
                                                  const std::vector<InputToStateMapping>& mappings) {
    MutationOutput output = input;  // Copy input data directly
    
    // Sort mappings by confidence
    auto sorted_mappings = mappings;
    std::sort(sorted_mappings.begin(), sorted_mappings.end(),
              [](const InputToStateMapping& a, const InputToStateMapping& b) {
                  return a.confidence > b.confidence;
              });
    
    // Apply the most confident mapping
    for (const auto& mapping : sorted_mappings) {
        if (applyAutomaticPatch(output, mapping)) {
            break; // Only apply one patch
        }
    }
    
    return output;
}

std::vector<uint8_t> REDQUEENMutation::flipInputBits(const std::vector<uint8_t>& input, 
                                                     size_t offset, size_t length) {
    std::vector<uint8_t> result = input;
    for (size_t i = 0; i < length && (offset + i) < result.size(); ++i) {
        result[offset + i] ^= 0xFF; // Flip all bits
    }
    return result;
}

bool REDQUEENMutation::checkStateChange(const std::vector<uint8_t>& original_input,
                                       const std::vector<uint8_t>& modified_input,
                                       SharedContext& ctx) {
    // Simplified: check whether the input actually differs
    if (original_input.size() != modified_input.size()) {
        return true;
    }
    
    for (size_t i = 0; i < original_input.size(); ++i) {
        if (original_input[i] != modified_input[i]) {
            return true;
        }
    }
    
    return false;
}

double REDQUEENMutation::calculateMappingConfidence(const ColoringEntry& entry,
                                                   const std::vector<uint8_t>& input) {
    double confidence = 0.5; // Base confidence
    
    // Adjust based on hit count
    if (entry.hit_count > 1) {
        confidence += 0.2;
    }
    
    // Adjust based on data type
    if (entry.is_string_compare) {
        confidence += 0.1;
    }
    
    // Adjust based on data length
    if (entry.input_bytes.size() > 1) {
        confidence += 0.1;
    }
    
    return std::min(1.0, confidence);
}

std::vector<std::vector<uint8_t>> REDQUEENMutation::generateStringReplacements(const std::string& original) {
    std::vector<std::vector<uint8_t>> replacements;
    
    // Common string mutations
    std::vector<std::string> mutations = {
        original + "x",
        "x" + original,
        original.substr(0, original.length() / 2),
        original + original,
        ""
    };
    
    for (const auto& mutation : mutations) {
        replacements.push_back(std::vector<uint8_t>(mutation.begin(), mutation.end()));
    }
    
    return replacements;
}

std::vector<std::vector<uint8_t>> REDQUEENMutation::generateNumericReplacements(const std::vector<uint8_t>& original) {
    std::vector<std::vector<uint8_t>> replacements;
    
    if (original.size() == 4) { // 32-bit integer
        uint32_t value = *reinterpret_cast<const uint32_t*>(original.data());
        std::vector<uint32_t> mutations = {
            value + 1, value - 1, value * 2, value / 2,
            0, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF
        };
        
        for (uint32_t mut : mutations) {
            std::vector<uint8_t> bytes(4);
            std::memcpy(bytes.data(), &mut, 4);
            replacements.push_back(bytes);
        }
    }
    
    return replacements;
}

bool REDQUEENMutation::applyAutomaticPatch(std::vector<uint8_t>& input, const InputToStateMapping& mapping) {
    if (mapping.input_offset + mapping.length > input.size() ||
        mapping.target_value.size() != mapping.length ||
        mapping.length > config_.max_patch_size) {
        return false;
    }
    
    // Directly replace target bytes
    std::copy(mapping.target_value.begin(), mapping.target_value.end(),
              input.begin() + mapping.input_offset);
    
    return true;
}

std::vector<std::vector<uint8_t>> REDQUEENMutation::generatePatchCandidates(const InputToStateMapping& mapping) {
    std::vector<std::vector<uint8_t>> candidates;
    candidates.push_back(mapping.target_value);
    
    // Generate similar patch candidates
    if (mapping.target_value.size() == 4) {
        // Numeric-type mutations
        auto numeric_mutations = generateNumericReplacements(mapping.target_value);
        candidates.insert(candidates.end(), numeric_mutations.begin(), numeric_mutations.end());
    } else if (mapping.target_value.size() > 4) {
        // Likely string type
        std::string str(mapping.target_value.begin(), mapping.target_value.end());
        auto string_mutations = generateStringReplacements(str);
        candidates.insert(candidates.end(), string_mutations.begin(), string_mutations.end());
    }
    
    return candidates;
}

void REDQUEENMutation::updateColoringDatabase(const ColoringResult& result) {
    coloring_database_.insert(coloring_database_.end(), 
                             result.entries.begin(), result.entries.end());
    
    // Limit database size
    if (coloring_database_.size() > 10000) {
        coloring_database_.erase(coloring_database_.begin(), 
                                coloring_database_.begin() + 1000);
    }
}

std::vector<ColoringEntry> REDQUEENMutation::queryColoringDatabase(const std::vector<uint8_t>& input) {
    std::vector<ColoringEntry> relevant_entries;
    
    for (const auto& entry : coloring_database_) {
        // Simple match: check whether input contains the relevant bytes
        bool found = false;
        for (size_t i = 0; i <= input.size() - entry.input_bytes.size(); ++i) {
            if (std::equal(entry.input_bytes.begin(), entry.input_bytes.end(),
                          input.begin() + i)) {
                found = true;
                break;
            }
        }
        
        if (found) {
            relevant_entries.push_back(entry);
        }
    }
    
    return relevant_entries;
}

// MagicByteExtractor implementation
std::vector<std::vector<uint8_t>> RedqueenMagicByteExtractor::extractFromComparison(
    const std::vector<uint8_t>& cmp_operand1,
    const std::vector<uint8_t>& cmp_operand2) {
    
    std::vector<std::vector<uint8_t>> magic_bytes;
    
    // Add both operands as magic bytes
    if (!cmp_operand1.empty()) {
        magic_bytes.push_back(cmp_operand1);
        extracted_constants_.insert(cmp_operand1);
    }
    
    if (!cmp_operand2.empty() && cmp_operand2 != cmp_operand1) {
        magic_bytes.push_back(cmp_operand2);
        extracted_constants_.insert(cmp_operand2);
    }
    
    return magic_bytes;
}

std::vector<std::string> RedqueenMagicByteExtractor::extractStringConstants(const std::vector<uint8_t>& data) {
    std::vector<std::string> strings;
    std::string current_string;
    
    for (uint8_t byte : data) {
        if (std::isprint(byte) && byte != 0) {
            current_string += static_cast<char>(byte);
        } else {
            if (current_string.length() >= 4) { // At least 4 characters
                strings.push_back(current_string);
                string_constants_[current_string] = std::vector<uint8_t>(current_string.begin(), current_string.end());
            }
            current_string.clear();
        }
    }
    
    // Handle trailing string
    if (current_string.length() >= 4) {
        strings.push_back(current_string);
        string_constants_[current_string] = std::vector<uint8_t>(current_string.begin(), current_string.end());
    }
    
    return strings;
}

std::vector<std::vector<uint8_t>> RedqueenMagicByteExtractor::extractNumericConstants(const std::vector<uint8_t>& data) {
    std::vector<std::vector<uint8_t>> constants;
    
    // Extract numeric constants of 2, 4, and 8 bytes
    std::vector<size_t> sizes = {2, 4, 8};
    
    for (size_t size : sizes) {
        for (size_t i = 0; i <= data.size() - size; i += size) {
            std::vector<uint8_t> constant(data.begin() + i, data.begin() + i + size);
            constants.push_back(constant);
            extracted_constants_.insert(constant);
        }
    }
    
    return constants;
}

// REDQUEENUtils implementation
std::vector<size_t> REDQUEENUtils::findPotentialMagicOffsets(const std::vector<uint8_t>& input) {
    std::vector<size_t> offsets;
    
    // Find potential magic-byte offsets
    for (size_t i = 0; i < input.size(); ++i) {
        // Look for patterns that look like magic bytes
        if (i + 4 <= input.size()) {
            uint32_t value = *reinterpret_cast<const uint32_t*>(&input[i]);
            if (value == 0x464C457F || // ELF magic
                value == 0x00905A4D || // PE magic
                value == 0x474E5089 || // PNG magic
                (value & 0xFFFF) == 0x5A4D) { // MZ magic
                offsets.push_back(i);
            }
        }
    }
    
    return offsets;
}

bool REDQUEENUtils::isLikelyStringData(const std::vector<uint8_t>& data, size_t offset, size_t length) {
    if (offset + length > data.size()) return false;
    
    size_t printable_count = 0;
    for (size_t i = offset; i < offset + length; ++i) {
        if (std::isprint(data[i]) || data[i] == ' ') {
            printable_count++;
        }
    }
    
    return printable_count >= length * 0.8; // >= 80% printable characters
}

bool REDQUEENUtils::isLikelyNumericData(const std::vector<uint8_t>& data, size_t offset, size_t length) {
    if (offset + length > data.size()) return false;
    
    // Check for common numeric sizes
    return length == 1 || length == 2 || length == 4 || length == 8;
}

std::vector<uint8_t> REDQUEENUtils::extractComparisonOperand(const std::vector<uint8_t>& trace_data, 
                                                           uint64_t instruction_address) {
    // Simplified: return fixed-size data
    return std::vector<uint8_t>(4, 0); // Placeholder implementation
}

std::vector<uint8_t> REDQUEENUtils::toBytes(uint64_t value, bool little_endian) {
    std::vector<uint8_t> bytes(8);
    
    if (little_endian) {
        for (int i = 0; i < 8; ++i) {
            bytes[i] = (value >> (i * 8)) & 0xFF;
        }
    } else {
        for (int i = 0; i < 8; ++i) {
            bytes[7 - i] = (value >> (i * 8)) & 0xFF;
        }
    }
    
    return bytes;
}

uint64_t REDQUEENUtils::fromBytes(const std::vector<uint8_t>& bytes, bool little_endian) {
    uint64_t value = 0;
    size_t size = std::min(bytes.size(), size_t(8));
    
    if (little_endian) {
        for (size_t i = 0; i < size; ++i) {
            value |= (static_cast<uint64_t>(bytes[i]) << (i * 8));
        }
    } else {
        for (size_t i = 0; i < size; ++i) {
            value |= (static_cast<uint64_t>(bytes[size - 1 - i]) << (i * 8));
        }
    }
    
    return value;
}

} // namespace triofuzz 
