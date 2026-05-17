#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include <unordered_set>
#include <stack>

namespace triofuzz {

// Instrumentation strategy enum
enum class InstrumentationStrategy {
    BasicBlock,
    Function,
    Edge
};

// Instrumentation algorithm input/output types
struct InstrumentationInput {
    std::vector<uint8_t> binary_data;
    std::string binary_path;
    std::map<std::string, std::any> options;
};

struct InstrumentationOutput {
    std::vector<uint8_t> instrumented_binary;
    std::map<uint64_t, std::string> edge_map;      // Map from edge ID to description
    std::map<uint64_t, std::string> function_map;  // Map from function address to name
    size_t total_edges;
    size_t total_blocks;
};

// Base class for instrumentation algorithms
class InstrumentationAlgorithm : public Algorithm<InstrumentationInput, InstrumentationOutput, SharedContext> {
public:
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Instrumentation;
        info.version = "1.0";
        return info;
    }
    
    void saveState(StateWriter& writer) const override {
        // Instrumentation algorithms are typically stateless.
    }
    
    void loadState(StateReader& reader) override {
        // Instrumentation algorithms are typically stateless.
    }
};

// Concrete instrumentation algorithm classes (EdgeCoverage, ContextSensitive, DataFlow, TaintAnalysis,
// MemoryAccess, SymbolicExecution) have been archived to archive/

} // namespace triofuzz
