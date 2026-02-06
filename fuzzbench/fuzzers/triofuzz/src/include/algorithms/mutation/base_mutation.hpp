#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include <random>
#include <algorithm>
#include <cstring>

namespace triofuzz {

// Mutation input/output types
using MutationInput = std::vector<uint8_t>;
using MutationOutput = std::vector<uint8_t>;

// Base class for mutation algorithms
class MutationAlgorithm : public Algorithm<MutationInput, MutationOutput, SharedContext> {
protected:
    mutable std::mt19937 random_gen_;
    
public:
    MutationAlgorithm() : random_gen_(std::random_device{}()) {}
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.type = AlgorithmType::Mutation;
        info.version = "1.0";
        return info;
    }
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
};

} // namespace triofuzz 
