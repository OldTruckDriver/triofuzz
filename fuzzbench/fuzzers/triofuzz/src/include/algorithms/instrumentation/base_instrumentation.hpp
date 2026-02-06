#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include <vector>
#include <map>
#include <string>

namespace triofuzz {

// Execution trace event
struct ExecutionTraceEvent {
    std::string event_type;        // Event type (comparison, memory_load, etc.)
    uint64_t source_address = 0;  // Source address
    uint64_t target_address = 0;  // Target address
    uint64_t operand1 = 0;        // Operand 1
    uint64_t operand2 = 0;        // Operand 2
    bool result = false;          // Comparison result
    size_t data_size = 0;         // Data size
    uint32_t thread_id = 0;       // Thread ID
};

// Instrumentation input
struct InstrumentationInputData {
    std::vector<uint8_t> test_data;                    // Test data
    std::vector<ExecutionTraceEvent> execution_trace;  // Execution trace
};

// Instrumentation output structure
struct InstrumentationOutputData {
    // Coverage info
    struct {
        std::vector<uint64_t> covered_edges;
        double coverage_gain = 0.0;
        std::vector<uint64_t> rare_edges;
    } coverage_info;
    
    // Constraint info
    struct {
        std::vector<std::shared_ptr<Constraint>> constraints;
        double constraint_score = 0.0;
        size_t solvable_count = 0;
    } constraint_info;
    
    // Data-flow info
    struct {
        std::vector<uint64_t> operations; // Simplified to address list
        size_t vulnerability_count = 0;
        double taint_coverage = 0.0;
    } dataflow_info;
    
    // Trace info
    struct {
        std::vector<uint64_t> control_flow_events; // Simplified to address list
        size_t anomaly_count = 0;
        double anomaly_score = 0.0;
    } trace_info;
};

// Instrumentation input/output types
using InstrumentationInputData_Alias = InstrumentationInputData;
using InstrumentationOutputData_Alias = InstrumentationOutputData;

// Backward-compatibility alias: base algorithm type using the basic data structures
using TaintInstrumentationAlgorithm = Algorithm<InstrumentationInputData, InstrumentationOutputData, SharedContext>;

} // namespace triofuzz 
