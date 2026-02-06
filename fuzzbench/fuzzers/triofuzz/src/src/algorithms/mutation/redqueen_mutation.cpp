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
    // 初始化默认配置
    config_.enable_string_extraction = true;
    config_.enable_numeric_extraction = true;
    config_.enable_automatic_patching = true;
    config_.max_coloring_attempts = 1000;
    config_.min_confidence_threshold = 0.7;
    config_.max_patch_size = 64;
    
    // 创建执行跟踪器
    tracer_ = TracerFactory::createBestAvailableTracer();
    if (tracer_) {
        tracer_->initialize();
        tracer_->enableTaintTracking(true);
    }
}

MutationOutput REDQUEENMutation::execute(const MutationInput& input, SharedContext& ctx) {
    MutationOutput output = input;  // 直接复制输入数据
    
    if (!tracer_) {
        // 如果没有跟踪器，回退到简单变异
        return fallbackMutation(input, ctx);
    }
    
    // 获取目标程序信息
    auto target_info = ctx.getTargetInfo();
    if (target_info.has_value()) {
        tracer_->setTarget(target_info->target_path, target_info->args);
    }
    
    // 第一阶段：执行程序并收集比较指令信息
    bool trace_success = tracer_->executeWithTracing(input, std::chrono::milliseconds(5000));
    stats_.total_colorings++;
    
    if (!trace_success) {
        tracer_->clearTraceData();
        return fallbackMutation(input, ctx);
    }
    
    // 获取比较指令记录
    const auto& comparisons = tracer_->getComparisons();
    if (comparisons.empty()) {
        tracer_->clearTraceData();
        return fallbackMutation(input, ctx);
    }
    
    // 第二阶段：执行coloring分析
    ColoringResult coloring = performAdvancedColoring(input, comparisons, ctx);
    
    if (!coloring.has_new_mappings && coloring.entries.empty()) {
        tracer_->clearTraceData();
        return fallbackMutation(input, ctx);
    }
    
    // 第三阶段：提取输入到状态的映射
    std::vector<InputToStateMapping> mappings = extractMappings(coloring);
    if (!mappings.empty()) {
        stats_.successful_mappings++;
        updateColoringDatabase(coloring);
    }
    
    // 第四阶段：应用智能补丁
    if (!mappings.empty()) {
        output = applyInputPatches(input, mappings);
        if (output != input) {
            stats_.patches_applied++;
        }
    } else {
        // 使用基于实际比较指令的魔法字节变异
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
    
    // 基于真实的比较指令记录进行coloring分析
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
        
        // 映射输入字节到比较操作数
        entry.input_bytes = cmp.operand1;
        entry.cmp_bytes = cmp.operand2;
        
        // 检查是否为新的映射
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
    
    // 选择一个有趣的比较指令
    std::uniform_int_distribution<size_t> cmp_dist(0, comparisons.size() - 1);
    const auto& selected_cmp = comparisons[cmp_dist(random_gen_)];
    
    if (!selected_cmp.is_input_dependent || selected_cmp.taint_offsets.empty()) {
        return output;
    }
    
    // 尝试应用魔法字节
    for (size_t taint_offset : selected_cmp.taint_offsets) {
        if (taint_offset >= output.size()) continue;
        
        // 策略1：直接替换为目标操作数
        if (!selected_cmp.operand2.empty() && 
            taint_offset + selected_cmp.operand2.size() <= output.size()) {
            
            std::copy(selected_cmp.operand2.begin(), selected_cmp.operand2.end(),
                     output.begin() + taint_offset);
            stats_.magic_bytes_found++;
            break;
        }
        
        // 策略2：基于比较类型的智能变异
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
                // 字符串比较的特殊处理
                if (!selected_cmp.operand2.empty()) {
                    size_t copy_len = std::min(selected_cmp.operand2.size(), 
                                              output.size() - taint_offset);
                    std::copy(selected_cmp.operand2.begin(), 
                             selected_cmp.operand2.begin() + copy_len,
                             output.begin() + taint_offset);
                }
                break;
                
            default:
                // 对于其他类型，尝试直接替换
                if (!selected_cmp.operand2.empty() && taint_offset < output.size()) {
                    output[taint_offset] = selected_cmp.operand2[0];
                }
                break;
        }
        
        stats_.magic_bytes_found++;
        break;  // 只应用一个魔法字节
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
    
    // 简单的随机变异作为回退策略
    std::uniform_int_distribution<size_t> pos_dist(0, output.size() - 1);
    std::uniform_int_distribution<int> mutation_type(0, 3);
    
    size_t pos = pos_dist(random_gen_);
    
    switch (mutation_type(random_gen_)) {
        case 0: {
            // 位翻转
            std::uniform_int_distribution<int> bit_dist(0, 7);
            int bit = bit_dist(random_gen_);
            output[pos] ^= (1 << bit);
            break;
        }
        case 1: {
            // 字节翻转
            output[pos] ^= 0xFF;
            break;
        }
        case 2: {
            // 随机字节
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            output[pos] = byte_dist(random_gen_);
            break;
        }
        case 3: {
            // 算术变异
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
    
    // 为每个可能的offset执行bit flipping
    for (size_t offset = 0; offset < input.size() && offset < config_.max_coloring_attempts; ++offset) {
        for (size_t bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> flipped_input = flipInputBits(input, offset, 1);
            flipped_input[offset] ^= (1 << bit);
            
            if (checkStateChange(input, flipped_input, ctx)) {
                ColoringEntry entry;
                entry.address = 0; // 需要从执行跟踪中获取
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
    
    // 构建地址到条目的映射
    for (size_t i = 0; i < result.entries.size(); ++i) {
        result.address_to_entries[result.entries[i].address].push_back(i);
    }
    
    return result;
}

std::vector<InputToStateMapping> REDQUEENMutation::extractMappings(const ColoringResult& coloring) {
    std::vector<InputToStateMapping> mappings;
    
    for (const auto& entry : coloring.entries) {
        InputToStateMapping mapping;
        mapping.input_offset = entry.context; // 简化：使用context作为offset
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
    MutationOutput output = input;  // 直接复制输入数据
    
    // 按置信度排序映射
    auto sorted_mappings = mappings;
    std::sort(sorted_mappings.begin(), sorted_mappings.end(),
              [](const InputToStateMapping& a, const InputToStateMapping& b) {
                  return a.confidence > b.confidence;
              });
    
    // 应用最有信心的映射
    for (const auto& mapping : sorted_mappings) {
        if (applyAutomaticPatch(output, mapping)) {
            break; // 只应用一个补丁
        }
    }
    
    return output;
}

std::vector<uint8_t> REDQUEENMutation::flipInputBits(const std::vector<uint8_t>& input, 
                                                     size_t offset, size_t length) {
    std::vector<uint8_t> result = input;
    for (size_t i = 0; i < length && (offset + i) < result.size(); ++i) {
        result[offset + i] ^= 0xFF; // 翻转所有位
    }
    return result;
}

bool REDQUEENMutation::checkStateChange(const std::vector<uint8_t>& original_input,
                                       const std::vector<uint8_t>& modified_input,
                                       SharedContext& ctx) {
    // 简化实现：检查输入是否真的不同
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
    double confidence = 0.5; // 基础置信度
    
    // 基于命中次数调整
    if (entry.hit_count > 1) {
        confidence += 0.2;
    }
    
    // 基于数据类型调整
    if (entry.is_string_compare) {
        confidence += 0.1;
    }
    
    // 基于数据长度调整
    if (entry.input_bytes.size() > 1) {
        confidence += 0.1;
    }
    
    return std::min(1.0, confidence);
}

std::vector<std::vector<uint8_t>> REDQUEENMutation::generateStringReplacements(const std::string& original) {
    std::vector<std::vector<uint8_t>> replacements;
    
    // 常见字符串变异
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
    
    if (original.size() == 4) { // 32位整数
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
    
    // 直接替换目标字节
    std::copy(mapping.target_value.begin(), mapping.target_value.end(),
              input.begin() + mapping.input_offset);
    
    return true;
}

std::vector<std::vector<uint8_t>> REDQUEENMutation::generatePatchCandidates(const InputToStateMapping& mapping) {
    std::vector<std::vector<uint8_t>> candidates;
    candidates.push_back(mapping.target_value);
    
    // 生成相似的补丁候选
    if (mapping.target_value.size() == 4) {
        // 数值类型的变异
        auto numeric_mutations = generateNumericReplacements(mapping.target_value);
        candidates.insert(candidates.end(), numeric_mutations.begin(), numeric_mutations.end());
    } else if (mapping.target_value.size() > 4) {
        // 可能是字符串类型
        std::string str(mapping.target_value.begin(), mapping.target_value.end());
        auto string_mutations = generateStringReplacements(str);
        candidates.insert(candidates.end(), string_mutations.begin(), string_mutations.end());
    }
    
    return candidates;
}

void REDQUEENMutation::updateColoringDatabase(const ColoringResult& result) {
    coloring_database_.insert(coloring_database_.end(), 
                             result.entries.begin(), result.entries.end());
    
    // 限制数据库大小
    if (coloring_database_.size() > 10000) {
        coloring_database_.erase(coloring_database_.begin(), 
                                coloring_database_.begin() + 1000);
    }
}

std::vector<ColoringEntry> REDQUEENMutation::queryColoringDatabase(const std::vector<uint8_t>& input) {
    std::vector<ColoringEntry> relevant_entries;
    
    for (const auto& entry : coloring_database_) {
        // 简单匹配：检查输入是否包含相关字节
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
    
    // 添加两个操作数作为魔法字节
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
            if (current_string.length() >= 4) { // 至少4个字符
                strings.push_back(current_string);
                string_constants_[current_string] = std::vector<uint8_t>(current_string.begin(), current_string.end());
            }
            current_string.clear();
        }
    }
    
    // 处理末尾的字符串
    if (current_string.length() >= 4) {
        strings.push_back(current_string);
        string_constants_[current_string] = std::vector<uint8_t>(current_string.begin(), current_string.end());
    }
    
    return strings;
}

std::vector<std::vector<uint8_t>> RedqueenMagicByteExtractor::extractNumericConstants(const std::vector<uint8_t>& data) {
    std::vector<std::vector<uint8_t>> constants;
    
    // 提取2、4、8字节的数值常量
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
    
    // 查找可能的魔法字节位置
    for (size_t i = 0; i < input.size(); ++i) {
        // 查找看起来像魔法字节的模式
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
    
    return printable_count >= length * 0.8; // 80%以上是可打印字符
}

bool REDQUEENUtils::isLikelyNumericData(const std::vector<uint8_t>& data, size_t offset, size_t length) {
    if (offset + length > data.size()) return false;
    
    // 检查是否是常见的数值大小
    return length == 1 || length == 2 || length == 4 || length == 8;
}

std::vector<uint8_t> REDQUEENUtils::extractComparisonOperand(const std::vector<uint8_t>& trace_data, 
                                                           uint64_t instruction_address) {
    // 简化实现：返回固定大小的数据
    return std::vector<uint8_t>(4, 0); // 占位符实现
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
