#include "../../include/utils/execution_tracer.hpp"
#include <random>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <regex>
#include <cmath>
#include <unistd.h>

namespace triofuzz {

// =============================================================================
// MockTracer Implementation - for testing and development
// =============================================================================

MockTracer::MockTracer() : random_gen_(std::random_device{}()) {}

bool MockTracer::executeWithTracing(const std::vector<uint8_t>& input,
                                   std::chrono::milliseconds timeout) {
    clearTraceData();
    generateMockTraceData(input);
    return true;
}

const std::vector<ComparisonEntry>& MockTracer::getComparisons() const {
    return mock_comparisons_;
}

const std::vector<MemoryAccess>& MockTracer::getMemoryAccesses() const {
    return mock_memory_accesses_;
}

const std::vector<ControlFlowTransfer>& MockTracer::getControlFlowTransfers() const {
    return mock_control_flow_transfers_;
}

std::vector<TaintTag> MockTracer::getTaintInfo(const std::vector<uint8_t>& input) {
    std::vector<TaintTag> taint_tags;
    
    // Create a taint tag for each input byte
    for (size_t i = 0; i < input.size(); ++i) {
        TaintTag tag;
        tag.input_offset = i;
        tag.length = 1;
        tag.tag_id = static_cast<uint32_t>(i);
        tag.is_active = true;
        taint_tags.push_back(tag);
    }
    
    return taint_tags;
}

std::vector<uint64_t> MockTracer::getCoveredBasicBlocks() const {
    std::vector<uint64_t> blocks;
    std::uniform_int_distribution<uint64_t> addr_dist(0x400000, 0x500000);
    
    size_t num_blocks = std::min<size_t>(100, mock_comparisons_.size() * 2);
    for (size_t i = 0; i < num_blocks; ++i) {
        blocks.push_back(addr_dist(random_gen_));
    }
    
    return blocks;
}

std::vector<std::pair<uint64_t, uint64_t>> MockTracer::getCoveredEdges() const {
    std::vector<std::pair<uint64_t, uint64_t>> edges;
    auto blocks = getCoveredBasicBlocks();
    
    for (size_t i = 1; i < blocks.size(); ++i) {
        edges.emplace_back(blocks[i-1], blocks[i]);
    }
    
    return edges;
}

void MockTracer::clearTraceData() {
    mock_comparisons_.clear();
    mock_memory_accesses_.clear();
    mock_control_flow_transfers_.clear();
}

void MockTracer::generateMockTraceData(const std::vector<uint8_t>& input) {
    if (input.empty()) return;
    
    std::uniform_int_distribution<uint64_t> pc_dist(0x400000, 0x500000);
    std::uniform_int_distribution<size_t> offset_dist(0, input.size() - 1);
    std::uniform_int_distribution<int> comparison_types(0, 7); // Only use basic comparison types
    
    // Generate comparison-instruction records
    size_t num_comparisons = std::min<size_t>(20, input.size() * 2);
    for (size_t i = 0; i < num_comparisons; ++i) {
        ComparisonEntry entry;
        entry.pc = pc_dist(random_gen_);
        entry.type = static_cast<ComparisonType>(comparison_types(random_gen_));
        entry.timestamp = i;
        entry.hit_count = 1;
        entry.is_input_dependent = true;
        entry.function_id = entry.pc & 0xFFF000;
        entry.basic_block_id = static_cast<uint32_t>(entry.pc & 0xFFF);
        
        // Generate operands
        size_t offset = offset_dist(random_gen_);
        entry.operand1 = {input[offset]};
        
        // Generate a related second operand
        uint8_t op2_val = input[offset];
        std::uniform_int_distribution<int> mutation_dist(-5, 5);
        int delta = mutation_dist(random_gen_);
        op2_val = static_cast<uint8_t>(std::clamp(static_cast<int>(op2_val) + delta, 0, 255));
        entry.operand2 = {op2_val};
        
        entry.result = (entry.operand1[0] == entry.operand2[0]);
        entry.taint_offsets = {offset};
        
        mock_comparisons_.push_back(entry);
    }
    
    // Generate memory access records
    size_t num_accesses = std::min<size_t>(50, input.size() * 3);
    for (size_t i = 0; i < num_accesses; ++i) {
        MemoryAccess access;
        access.pc = pc_dist(random_gen_);
        access.address = 0x600000 + i * 8;
        access.size = 1;
        access.is_write = (i % 3 == 0);
        access.timestamp = i;
        
        size_t offset = offset_dist(random_gen_);
        access.data = {input[offset]};
        
        // Add taint tag
        TaintTag tag;
        tag.input_offset = offset;
        tag.length = 1;
        tag.tag_id = static_cast<uint32_t>(offset);
        tag.is_active = true;
        access.taint_tags = {tag};
        
        mock_memory_accesses_.push_back(access);
    }
    
    // Generate control-flow transfer records
    size_t num_transfers = std::min<size_t>(30, input.size());
    for (size_t i = 0; i < num_transfers; ++i) {
        ControlFlowTransfer transfer;
        transfer.from_pc = pc_dist(random_gen_);
        transfer.to_pc = pc_dist(random_gen_);
        transfer.is_conditional = (i % 2 == 0);
        transfer.branch_taken = (input[i % input.size()] & 1) == 1;
        transfer.timestamp = i;
        
        // Attach taint info for conditional branches
        if (transfer.is_conditional) {
            TaintTag tag;
            tag.input_offset = i % input.size();
            tag.length = 1;
            tag.tag_id = static_cast<uint32_t>(i);
            tag.is_active = true;
            transfer.condition_taint = {tag};
        }
        
        mock_control_flow_transfers_.push_back(transfer);
    }
}

// =============================================================================
// PinBasedTracer Implementation - basic implementation
// =============================================================================

PinBasedTracer::PinBasedTracer() : taint_tracking_enabled_(false) {}

PinBasedTracer::~PinBasedTracer() {
    shutdown();
}

bool PinBasedTracer::initialize() {
    // Check whether the PIN tool is available
    if (pin_tool_path_.empty()) {
        pin_tool_path_ = "/opt/pin/pin";  // Default path
    }
    
    if (pintool_so_path_.empty()) {
        pintool_so_path_ = "./pintool/collafuzz_tracer.so";  // Default tool
    }
    
    // Check whether the file exists
    std::ifstream pin_check(pin_tool_path_);
    if (!pin_check.good()) {
        return false;  // PIN unavailable; fall back to mock mode
    }
    
    return true;
}

void PinBasedTracer::shutdown() {
    clearTraceData();
}

bool PinBasedTracer::setTarget(const std::string& target_path, 
                              const std::vector<std::string>& args) {
    target_path_ = target_path;
    target_args_ = args;
    return true;
}

bool PinBasedTracer::executeWithTracing(const std::vector<uint8_t>& input,
                                       std::chrono::milliseconds timeout) {
    clearTraceData();
    
    // Create temporary file
    std::string trace_file = "/tmp/collafuzz_trace_" + std::to_string(getpid()) + ".txt";
    
    // Launch PIN tool
    bool success = launchPinTool(input, trace_file, timeout);
    
    if (success) {
        success = parseTraceOutput(trace_file);
    }
    
    // Clean up temporary file
    std::remove(trace_file.c_str());
    
    return success;
}

const std::vector<ComparisonEntry>& PinBasedTracer::getComparisons() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    return comparisons_;
}

const std::vector<MemoryAccess>& PinBasedTracer::getMemoryAccesses() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    return memory_accesses_;
}

const std::vector<ControlFlowTransfer>& PinBasedTracer::getControlFlowTransfers() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    return control_flow_transfers_;
}

void PinBasedTracer::enableTaintTracking(bool enable) {
    taint_tracking_enabled_ = enable;
}

std::vector<TaintTag> PinBasedTracer::getTaintInfo(const std::vector<uint8_t>& input) {
    // Simplified: create taint tags for all input bytes
    std::vector<TaintTag> taint_tags;
    for (size_t i = 0; i < input.size(); ++i) {
        TaintTag tag;
        tag.input_offset = i;
        tag.length = 1;
        tag.tag_id = static_cast<uint32_t>(i);
        tag.is_active = true;
        taint_tags.push_back(tag);
    }
    return taint_tags;
}

std::vector<uint64_t> PinBasedTracer::getCoveredBasicBlocks() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    std::vector<uint64_t> blocks;
    for (const auto& block : covered_basic_blocks_) {
        blocks.push_back(block);
    }
    return blocks;
}

std::vector<std::pair<uint64_t, uint64_t>> PinBasedTracer::getCoveredEdges() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    std::vector<std::pair<uint64_t, uint64_t>> edges;
    for (const auto& edge : covered_edges_) {
        edges.push_back(edge);
    }
    return edges;
}

void PinBasedTracer::clearTraceData() {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    comparisons_.clear();
    memory_accesses_.clear();
    control_flow_transfers_.clear();
    covered_basic_blocks_.clear();
    covered_edges_.clear();
    memory_taint_map_.clear();
    register_taint_map_.clear();
}

void PinBasedTracer::setPinToolPath(const std::string& pin_path, const std::string& pintool_path) {
    pin_tool_path_ = pin_path;
    pintool_so_path_ = pintool_path;
}

bool PinBasedTracer::launchPinTool(const std::vector<uint8_t>& input, 
                                  const std::string& output_file,
                                  std::chrono::milliseconds timeout) {
    // Create input file
    std::string input_file = output_file + ".input";
    std::ofstream ofs(input_file, std::ios::binary);
    if (!ofs.is_open()) {
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(input.data()), input.size());
    ofs.close();
    
    // Build PIN command
    std::ostringstream cmd;
    cmd << pin_tool_path_ << " -t " << pintool_so_path_;
    cmd << " -o " << output_file;
    if (taint_tracking_enabled_) {
        cmd << " -taint";
    }
    cmd << " -- " << target_path_;
    for (const auto& arg : target_args_) {
        cmd << " " << arg;
    }
    cmd << " < " << input_file;
    cmd << " 2>/dev/null";  // Suppress stderr output
    
    // Execute command
    int result = std::system(cmd.str().c_str());
    
    // Clean up input file
    std::remove(input_file.c_str());
    
    return (result == 0);
}

bool PinBasedTracer::parseTraceOutput(const std::string& trace_file) {
    std::ifstream ifs(trace_file);
    if (!ifs.is_open()) {
        return false;
    }
    
    std::string line;
    std::regex cmp_pattern(R"(CMP:(\w+):(\w+):(\w+):([01]):(\d+))");
    std::regex mem_pattern(R"(MEM:(\w+):(\w+):(\d+):([RW]):(.+))");
    std::regex br_pattern(R"(BR:(\w+):(\w+):([01]):([01]))");
    
    std::lock_guard<std::mutex> lock(trace_mutex_);
    
    while (std::getline(ifs, line)) {
        std::smatch match;
        
        if (std::regex_match(line, match, cmp_pattern)) {
            // Parse comparison instruction
            ComparisonEntry entry;
            entry.pc = std::stoull(match[1].str(), nullptr, 16);
            
            std::string op1_str = match[2].str();
            std::string op2_str = match[3].str();
            entry.result = (match[4].str() == "1");
            entry.timestamp = std::stoull(match[5].str());
            
            // Parse operands (simplified; assume hex bytes)
            for (size_t i = 0; i < op1_str.length(); i += 2) {
                entry.operand1.push_back(static_cast<uint8_t>(
                    std::stoul(op1_str.substr(i, 2), nullptr, 16)));
            }
            for (size_t i = 0; i < op2_str.length(); i += 2) {
                entry.operand2.push_back(static_cast<uint8_t>(
                    std::stoul(op2_str.substr(i, 2), nullptr, 16)));
            }
            
            entry.type = ::tracer_utils::inferComparisonType(entry.operand1, entry.operand2);
            entry.hit_count = 1;
            entry.is_input_dependent = true;
            entry.function_id = entry.pc & 0xFFF000;
            entry.basic_block_id = static_cast<uint32_t>(entry.pc & 0xFFF);
            
            comparisons_.push_back(entry);
            covered_basic_blocks_.insert(entry.pc);
            
        } else if (std::regex_match(line, match, mem_pattern)) {
            // Parse memory access
            MemoryAccess access;
            access.pc = std::stoull(match[1].str(), nullptr, 16);
            access.address = std::stoull(match[2].str(), nullptr, 16);
            access.size = std::stoull(match[3].str());
            access.is_write = (match[4].str() == "W");
            access.timestamp = comparisons_.size();  // Simplified timestamp
            
            // Parse data
            std::string data_str = match[5].str();
            for (size_t i = 0; i < data_str.length(); i += 2) {
                access.data.push_back(static_cast<uint8_t>(
                    std::stoul(data_str.substr(i, 2), nullptr, 16)));
            }
            
            memory_accesses_.push_back(access);
            
        } else if (std::regex_match(line, match, br_pattern)) {
            // Parse branch instruction
            ControlFlowTransfer transfer;
            transfer.from_pc = std::stoull(match[1].str(), nullptr, 16);
            transfer.to_pc = std::stoull(match[2].str(), nullptr, 16);
            transfer.is_conditional = (match[3].str() == "1");
            transfer.branch_taken = (match[4].str() == "1");
            transfer.timestamp = comparisons_.size();
            
            control_flow_transfers_.push_back(transfer);
            covered_edges_.insert({transfer.from_pc, transfer.to_pc});
        }
    }
    
    return true;
}

void PinBasedTracer::propagateTaint(const MemoryAccess& access) {
    // Simplified taint propagation
    if (taint_tracking_enabled_ && !access.taint_tags.empty()) {
        memory_taint_map_[access.address] = access.taint_tags;
    }
}

void PinBasedTracer::updateRegisterTaint(uint32_t reg, const std::vector<TaintTag>& tags) {
    if (taint_tracking_enabled_) {
        register_taint_map_[reg] = tags;
    }
}

void PinBasedTracer::analyzeComparison(const ComparisonEntry& entry) {
    // Comparison analysis can be extended here.
    // Currently only stores basic information.
}

// =============================================================================
// QemuBasedTracer Implementation - simplified implementation
// =============================================================================

QemuBasedTracer::QemuBasedTracer() : trace_enabled_(false) {}

QemuBasedTracer::~QemuBasedTracer() {
    shutdown();
}

bool QemuBasedTracer::initialize() {
    if (qemu_path_.empty()) {
        qemu_path_ = "qemu-x86_64";  // Default path
    }
    return true;
}

void QemuBasedTracer::shutdown() {
    clearTraceData();
}

bool QemuBasedTracer::setTarget(const std::string& target_path, 
                               const std::vector<std::string>& args) {
    target_path_ = target_path;
    target_args_ = args;
    return true;
}

bool QemuBasedTracer::executeWithTracing(const std::vector<uint8_t>& input,
                                        std::chrono::milliseconds timeout) {
    clearTraceData();
    
    std::string trace_file = "/tmp/qemu_trace_" + std::to_string(getpid()) + ".txt";
    bool success = launchQemuTrace(input, trace_file, timeout);
    
    if (success) {
        success = parseQemuTraceOutput(trace_file);
    }
    
    std::remove(trace_file.c_str());
    return success;
}

const std::vector<ComparisonEntry>& QemuBasedTracer::getComparisons() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    return comparisons_;
}

const std::vector<MemoryAccess>& QemuBasedTracer::getMemoryAccesses() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    return memory_accesses_;
}

const std::vector<ControlFlowTransfer>& QemuBasedTracer::getControlFlowTransfers() const {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    return control_flow_transfers_;
}

void QemuBasedTracer::enableTaintTracking(bool enable) {
    trace_enabled_ = enable;
}

std::vector<TaintTag> QemuBasedTracer::getTaintInfo(const std::vector<uint8_t>& input) {
    std::vector<TaintTag> taint_tags;
    for (size_t i = 0; i < input.size(); ++i) {
        TaintTag tag;
        tag.input_offset = i;
        tag.length = 1;
        tag.tag_id = static_cast<uint32_t>(i);
        tag.is_active = true;
        taint_tags.push_back(tag);
    }
    return taint_tags;
}

std::vector<uint64_t> QemuBasedTracer::getCoveredBasicBlocks() const {
    // Simplified: return empty list
    return {};
}

std::vector<std::pair<uint64_t, uint64_t>> QemuBasedTracer::getCoveredEdges() const {
    // Simplified: return empty list
    return {};
}

void QemuBasedTracer::clearTraceData() {
    std::lock_guard<std::mutex> lock(trace_mutex_);
    comparisons_.clear();
    memory_accesses_.clear();
    control_flow_transfers_.clear();
}

void QemuBasedTracer::setQemuPath(const std::string& qemu_path) {
    qemu_path_ = qemu_path;
}

bool QemuBasedTracer::launchQemuTrace(const std::vector<uint8_t>& input,
                                     const std::string& output_file,
                                     std::chrono::milliseconds timeout) {
    // QEMU tracing is more complex; this is only a basic skeleton.
    // In practice, customize a QEMU plugin based on your needs.
    return false;  // Not implemented yet
}

bool QemuBasedTracer::parseQemuTraceOutput(const std::string& trace_file) {
    // Parse QEMU trace output
    return false;  // Not implemented yet
}

// =============================================================================
// TracerFactory Implementation
// =============================================================================

std::unique_ptr<ExecutionTracer> TracerFactory::createTracer(TracerType type) {
    switch (type) {
        case TracerType::PIN_BASED:
            return std::make_unique<PinBasedTracer>();
        case TracerType::QEMU_BASED:
            return std::make_unique<QemuBasedTracer>();
        case TracerType::MOCK:
        default:
            return std::make_unique<MockTracer>();
    }
}

std::unique_ptr<ExecutionTracer> TracerFactory::createBestAvailableTracer() {
    // Try creating a PIN tracer
    auto pin_tracer = std::make_unique<PinBasedTracer>();
    if (pin_tracer->initialize()) {
        return std::move(pin_tracer);
    }
    
    // Fall back to QEMU tracer
    auto qemu_tracer = std::make_unique<QemuBasedTracer>();
    if (qemu_tracer->initialize()) {
        return std::move(qemu_tracer);
    }
    
    // Final fallback: mock tracer
    return std::make_unique<MockTracer>();
}

// =============================================================================
} // namespace triofuzz

// Utility Functions Implementation
// =============================================================================

namespace tracer_utils {

using namespace triofuzz;

uint64_t extractInteger(const std::vector<uint8_t>& data, bool little_endian) {
    if (data.empty()) return 0;
    
    uint64_t result = 0;
    if (little_endian) {
        for (int i = static_cast<int>(data.size()) - 1; i >= 0; --i) {
            result = (result << 8) | data[i];
        }
    } else {
        for (size_t i = 0; i < data.size(); ++i) {
            result = (result << 8) | data[i];
        }
    }
    return result;
}

bool compareOperands(const std::vector<uint8_t>& op1, 
                    const std::vector<uint8_t>& op2,
                    ComparisonType type) {
    if (op1.size() != op2.size()) {
        return false;
    }
    
    switch (type) {
        case ComparisonType::INT8_EQ:
        case ComparisonType::INT16_EQ:
        case ComparisonType::INT32_EQ:
        case ComparisonType::INT64_EQ:
            return std::equal(op1.begin(), op1.end(), op2.begin());
            
        case ComparisonType::INT8_NE:
        case ComparisonType::INT16_NE:
        case ComparisonType::INT32_NE:
        case ComparisonType::INT64_NE:
            return !std::equal(op1.begin(), op1.end(), op2.begin());
            
        case ComparisonType::INT8_LT:
        case ComparisonType::INT16_LT:
        case ComparisonType::INT32_LT:
        case ComparisonType::INT64_LT:
            return extractInteger(op1, true) < extractInteger(op2, true);
            
        case ComparisonType::STRING_EQ:
            return std::equal(op1.begin(), op1.end(), op2.begin());
            
        case ComparisonType::MEMCMP:
            return std::memcmp(op1.data(), op2.data(), op1.size()) == 0;
            
        default:
            return false;
    }
}

double extractFloat(const std::vector<uint8_t>& data, bool single_precision) {
    if (data.size() < (single_precision ? 4 : 8)) {
        return 0.0;
    }
    
    if (single_precision) {
        float value;
        std::memcpy(&value, data.data(), sizeof(float));
        return static_cast<double>(value);
    } else {
        double value;
        std::memcpy(&value, data.data(), sizeof(double));
        return value;
    }
}

ComparisonType inferComparisonType(const std::vector<uint8_t>& op1,
                                  const std::vector<uint8_t>& op2) {
    if (op1.size() != op2.size()) {
        return ComparisonType::MEMCMP;
    }
    
    switch (op1.size()) {
        case 1:
            return ComparisonType::INT8_EQ;
        case 2:
            return ComparisonType::INT16_EQ;
        case 4:
            return ComparisonType::INT32_EQ;
        case 8:
            return ComparisonType::INT64_EQ;
        default:
            return ComparisonType::MEMCMP;
    }
}

std::vector<TaintTag> propagateTaintTags(const std::vector<TaintTag>& input_tags,
                                        const std::vector<uint8_t>& operation_result) {
    std::vector<TaintTag> output_tags;
    
    // Simplified propagation: keep input taint tags
    for (const auto& tag : input_tags) {
        if (tag.is_active && tag.input_offset < operation_result.size()) {
            output_tags.push_back(tag);
        }
    }
    
    return output_tags;
}

std::vector<std::string> extractConstraints(const std::vector<ComparisonEntry>& comparisons) {
    std::vector<std::string> constraints;
    
    for (const auto& cmp : comparisons) {
        if (!cmp.is_input_dependent) continue;
        
        std::ostringstream constraint;
        constraint << "input[" << (cmp.taint_offsets.empty() ? 0 : cmp.taint_offsets[0]) << "] ";
        
        switch (cmp.type) {
            case ComparisonType::INT8_EQ:
            case ComparisonType::INT16_EQ:
            case ComparisonType::INT32_EQ:
            case ComparisonType::INT64_EQ:
                constraint << "== " << extractInteger(cmp.operand2, true);
                break;
            case ComparisonType::INT8_LT:
            case ComparisonType::INT16_LT:
            case ComparisonType::INT32_LT:
            case ComparisonType::INT64_LT:
                constraint << "< " << extractInteger(cmp.operand2, true);
                break;
            case ComparisonType::INT8_GT:
            case ComparisonType::INT16_GT:
            case ComparisonType::INT32_GT:
            case ComparisonType::INT64_GT:
                constraint << "> " << extractInteger(cmp.operand2, true);
                break;
            default:
                continue;  // Skip unsupported types
        }
        
        constraints.push_back(constraint.str());
    }
    
    return constraints;
}

} // namespace tracer_utils 
