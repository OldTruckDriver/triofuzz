#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include "../../types/contraint_types.hpp"
#include <unordered_map>
#include <any>

namespace triofuzz {

// Feedback algorithm input/output types
using FeedbackInput = ExecutionResult;
using FeedbackOutput = std::map<std::string, std::any>;

// Base class for feedback processing algorithms
class FeedbackAlgorithm : public Algorithm<FeedbackInput, FeedbackOutput, SharedContext> {
public:
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Feedback;
        info.version = "1.0";
        return info;
    }
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
};

} // namespace triofuzz 
