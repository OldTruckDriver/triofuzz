#pragma once

#include "../core/context.hpp"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>
#include <random>

namespace triofuzz {

// Hash function for std::pair<uint64_t, uint64_t>.
struct PairHash {
    std::size_t operator()(const std::pair<uint64_t, uint64_t>& p) const {
        return std::hash<uint64_t>{}(p.first) ^ (std::hash<uint64_t>{}(p.second) << 1);
    }
};

// Comparison instruction types
enum class ComparisonType {
    INT8_EQ, INT8_NE, INT8_LT, INT8_LE, INT8_GT, INT8_GE,
    INT16_EQ, INT16_NE, INT16_LT, INT16_LE, INT16_GT, INT16_GE,
    INT32_EQ, INT32_NE, INT32_LT, INT32_LE, INT32_GT, INT32_GE,
    INT64_EQ, INT64_NE, INT64_LT, INT64_LE, INT64_GT, INT64_GE,
    STRING_EQ, STRING_NE, STRING_CMP,
    MEMCMP, MEMCMP_N,
    FLOAT_EQ, FLOAT_NE, FLOAT_LT, FLOAT_LE, FLOAT_GT, FLOAT_GE,
    DOUBLE_EQ, DOUBLE_NE, DOUBLE_LT, DOUBLE_LE, DOUBLE_GT, DOUBLE_GE
};

// Comparison instruction record
struct ComparisonEntry {
    uint64_t pc;                        // Program counter
    ComparisonType type;                // Comparison type
    std::vector<uint8_t> operand1;      // First operand
    std::vector<uint8_t> operand2;      // Second operand
    bool result;                        // Comparison result
    uint64_t timestamp;                 // Timestamp
    uint32_t hit_count;                 // Hit count
    
    // Taint-analysis related
    std::vector<size_t> taint_offsets;  // Taint offsets
    bool is_input_dependent;            // Input-dependent?
    
    // Context info
    uint64_t function_id;               // Function ID
    uint32_t basic_block_id;            // Basic block ID
};

// Taint tag
struct TaintTag {
    size_t input_offset;                // Offset in the input
    size_t length;                      // Length
    uint32_t tag_id;                    // Tag ID
    bool is_active;                     // Active?
};

// Memory access record
struct MemoryAccess {
    uint64_t pc;                        // Program counter
    uint64_t address;                   // Memory address
    size_t size;                        // Access size
    bool is_write;                      // Is write?
    std::vector<uint8_t> data;          // Data payload
    std::vector<TaintTag> taint_tags;   // Taint tags
    uint64_t timestamp;                 // Timestamp
};

// Control-flow transfer record
struct ControlFlowTransfer {
    uint64_t from_pc;                   // Source program counter
    uint64_t to_pc;                     // Target program counter
    bool is_conditional;                // Conditional?
    bool branch_taken;                  // Branch taken?
    std::vector<TaintTag> condition_taint; // Taint info for the condition
    uint64_t timestamp;                 // Timestamp
};

// Execution tracing interface
class ExecutionTracer {
public:
    virtual ~ExecutionTracer() = default;
    
    // Initialize tracing
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    
    // Set target program
    virtual bool setTarget(const std::string& target_path, 
                          const std::vector<std::string>& args) = 0;
    
    // Execute program with tracing
    virtual bool executeWithTracing(const std::vector<uint8_t>& input,
                                   std::chrono::milliseconds timeout) = 0;
    
    // Get trace results
    virtual const std::vector<ComparisonEntry>& getComparisons() const = 0;
    virtual const std::vector<MemoryAccess>& getMemoryAccesses() const = 0;
    virtual const std::vector<ControlFlowTransfer>& getControlFlowTransfers() const = 0;
    
    // Taint analysis
    virtual void enableTaintTracking(bool enable) = 0;
    virtual std::vector<TaintTag> getTaintInfo(const std::vector<uint8_t>& input) = 0;
    
    // Coverage info
    virtual std::vector<uint64_t> getCoveredBasicBlocks() const = 0;
    virtual std::vector<std::pair<uint64_t, uint64_t>> getCoveredEdges() const = 0;
    
    // Clear trace data
    virtual void clearTraceData() = 0;
};

// PIN-based execution tracer
class PinBasedTracer : public ExecutionTracer {
private:
    std::string target_path_;
    std::vector<std::string> target_args_;
    
    // Trace data
    std::vector<ComparisonEntry> comparisons_;
    std::vector<MemoryAccess> memory_accesses_;
    std::vector<ControlFlowTransfer> control_flow_transfers_;
    
    // Coverage data
    std::unordered_set<uint64_t> covered_basic_blocks_;
    std::unordered_set<std::pair<uint64_t, uint64_t>, PairHash> covered_edges_;
    
    // Taint tracking
    bool taint_tracking_enabled_ = false;
    std::unordered_map<uint64_t, std::vector<TaintTag>> memory_taint_map_;
    std::unordered_map<uint32_t, std::vector<TaintTag>> register_taint_map_;
    
    // Thread safety
    mutable std::mutex trace_mutex_;
    
    // PIN tool paths
    std::string pin_tool_path_;
    std::string pintool_so_path_;
    
public:
    PinBasedTracer();
    ~PinBasedTracer() override;
    
    bool initialize() override;
    void shutdown() override;
    
    bool setTarget(const std::string& target_path, 
                  const std::vector<std::string>& args) override;
    
    bool executeWithTracing(const std::vector<uint8_t>& input,
                           std::chrono::milliseconds timeout) override;
    
    const std::vector<ComparisonEntry>& getComparisons() const override;
    const std::vector<MemoryAccess>& getMemoryAccesses() const override;
    const std::vector<ControlFlowTransfer>& getControlFlowTransfers() const override;
    
    void enableTaintTracking(bool enable) override;
    std::vector<TaintTag> getTaintInfo(const std::vector<uint8_t>& input) override;
    
    std::vector<uint64_t> getCoveredBasicBlocks() const override;
    std::vector<std::pair<uint64_t, uint64_t>> getCoveredEdges() const override;
    
    void clearTraceData() override;
    
    // PIN tool configuration
    void setPinToolPath(const std::string& pin_path, const std::string& pintool_path);
    
	private:
    // Parse PIN tool output
    bool parseTraceOutput(const std::string& trace_file);
    
    // Taint propagation analysis
    void propagateTaint(const MemoryAccess& access);
    void updateRegisterTaint(uint32_t reg, const std::vector<TaintTag>& tags);
    
    // Comparison instruction analysis
    void analyzeComparison(const ComparisonEntry& entry);
    
    // Launch PIN tool
    bool launchPinTool(const std::vector<uint8_t>& input, 
                      const std::string& output_file,
                      std::chrono::milliseconds timeout);
};

// QEMU-based execution tracer (lightweight alternative)
class QemuBasedTracer : public ExecutionTracer {
private:
    std::string target_path_;
    std::vector<std::string> target_args_;
    std::vector<ComparisonEntry> comparisons_;
    std::vector<MemoryAccess> memory_accesses_;
    std::vector<ControlFlowTransfer> control_flow_transfers_;
    
    // QEMU user-mode configuration
    std::string qemu_path_;
    bool trace_enabled_ = false;
    mutable std::mutex trace_mutex_;
    
public:
    QemuBasedTracer();
    ~QemuBasedTracer() override;
    
    bool initialize() override;
    void shutdown() override;
    
    bool setTarget(const std::string& target_path, 
                  const std::vector<std::string>& args) override;
    
    bool executeWithTracing(const std::vector<uint8_t>& input,
                           std::chrono::milliseconds timeout) override;
    
    const std::vector<ComparisonEntry>& getComparisons() const override;
    const std::vector<MemoryAccess>& getMemoryAccesses() const override;
    const std::vector<ControlFlowTransfer>& getControlFlowTransfers() const override;
    
    void enableTaintTracking(bool enable) override;
    std::vector<TaintTag> getTaintInfo(const std::vector<uint8_t>& input) override;
    
    std::vector<uint64_t> getCoveredBasicBlocks() const override;
    std::vector<std::pair<uint64_t, uint64_t>> getCoveredEdges() const override;
    
    void clearTraceData() override;
    
    // QEMU configuration
    void setQemuPath(const std::string& qemu_path);
    
private:
    bool launchQemuTrace(const std::vector<uint8_t>& input,
                        const std::string& output_file,
                        std::chrono::milliseconds timeout);
    bool parseQemuTraceOutput(const std::string& trace_file);
};

// Mock execution tracer (for testing and development)
class MockTracer : public ExecutionTracer {
private:
    std::vector<ComparisonEntry> mock_comparisons_;
    std::vector<MemoryAccess> mock_memory_accesses_;
    std::vector<ControlFlowTransfer> mock_control_flow_transfers_;
    mutable std::mt19937 random_gen_;
    
public:
    MockTracer();
    
    bool initialize() override { return true; }
    void shutdown() override {}
    
    bool setTarget(const std::string& target_path, 
                  const std::vector<std::string>& args) override { return true; }
    
    bool executeWithTracing(const std::vector<uint8_t>& input,
                           std::chrono::milliseconds timeout) override;
    
    const std::vector<ComparisonEntry>& getComparisons() const override;
    const std::vector<MemoryAccess>& getMemoryAccesses() const override;
    const std::vector<ControlFlowTransfer>& getControlFlowTransfers() const override;
    
    void enableTaintTracking(bool enable) override {}
    std::vector<TaintTag> getTaintInfo(const std::vector<uint8_t>& input) override;
    
    std::vector<uint64_t> getCoveredBasicBlocks() const override;
    std::vector<std::pair<uint64_t, uint64_t>> getCoveredEdges() const override;
    
    void clearTraceData() override;
    
private:
    void generateMockTraceData(const std::vector<uint8_t>& input);
};

// Tracer factory
class TracerFactory {
public:
    enum class TracerType {
        PIN_BASED,
        QEMU_BASED, 
        MOCK
    };
    
    static std::unique_ptr<ExecutionTracer> createTracer(TracerType type);
    static std::unique_ptr<ExecutionTracer> createBestAvailableTracer();
};

} // namespace triofuzz

// Utility functions
namespace tracer_utils {

using namespace triofuzz;

// Compare operands
bool compareOperands(const std::vector<uint8_t>& op1, 
                    const std::vector<uint8_t>& op2,
                    ComparisonType type);

// Extract integer value
uint64_t extractInteger(const std::vector<uint8_t>& data, bool little_endian = true);

// Extract floating-point value
double extractFloat(const std::vector<uint8_t>& data, bool single_precision = true);

// Data type inference
ComparisonType inferComparisonType(const std::vector<uint8_t>& op1,
                                  const std::vector<uint8_t>& op2);

// Taint propagation
std::vector<TaintTag> propagateTaintTags(const std::vector<TaintTag>& input_tags,
                                        const std::vector<uint8_t>& operation_result);

// Constraint extraction
std::vector<std::string> extractConstraints(const std::vector<ComparisonEntry>& comparisons);

} // namespace tracer_utils 
