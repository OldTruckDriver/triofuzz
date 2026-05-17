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

// Havoc mutation algorithm
class HavocMutation : public MutationAlgorithm {
private:
    // Mutation operation enum
    enum class MutationOp {
        FlipBit,
        FlipByte,
        Arithmetic,
        InterestingValue,
        DeleteBytes,
        InsertBytes,
        ShuffleBytes,
        CrossOver,
        Dictionary
    };
    
    // Gradient weights (if gradient info is available)
    std::vector<double> mutation_weights_;
    
public:
    HavocMutation() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "havoc";
        info.provided_info = {InfoType::Coverage};
        info.required_info = {InfoType::Gradient}; // Optionally uses gradient info
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        return measureExecution([&]() {
            MutationOutput result = input;
            
            // Get gradient info (if available).
            auto gradient_info = ctx.getGradientInfo();
            if (gradient_info.has_value()) {
                updateMutationWeights(gradient_info.value(), result.size());
            }
            
            // Determine mutation count.
            std::uniform_int_distribution<size_t> havoc_dist(1, 16);
            size_t mutation_count = havoc_dist(random_gen_);
            
            // Apply multiple mutations.
            for (size_t i = 0; i < mutation_count; ++i) {
                MutationOp op = selectMutationOp();
                applyMutation(result, op, ctx);
            }
            
            return result;
        });
    }
    
    // Set mutation weights (for gradient guidance).
    void setMutationWeights(const GradientInfo& gradient_info) {
        mutation_weights_.clear();
        mutation_weights_.resize(gradient_info.positions.size());
        
        for (size_t i = 0; i < gradient_info.positions.size(); ++i) {
            mutation_weights_[i] = std::abs(gradient_info.gradients[i]);
        }
        
        // Normalize weights.
        double sum = std::accumulate(mutation_weights_.begin(), mutation_weights_.end(), 0.0);
        if (sum > 0) {
            for (auto& w : mutation_weights_) {
                w /= sum;
            }
        }
    }
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
private:
    // Select mutation operation
    MutationOp selectMutationOp() {
        std::uniform_int_distribution<int> dist(0, 8);
        return static_cast<MutationOp>(dist(random_gen_));
    }
    
    // Apply mutation
    void applyMutation(MutationOutput& data, MutationOp op, SharedContext& ctx);
    
    // Bit flip
    void flipBit(MutationOutput& data);
    
    // Byte flip
    void flipByte(MutationOutput& data);
    
    // Arithmetic mutation
    void arithmeticMutation(MutationOutput& data);
    
    // Insert interesting value
    void insertInterestingValue(MutationOutput& data);
    
    // Delete bytes
    void deleteBytes(MutationOutput& data);
    
    // Insert bytes
    void insertBytes(MutationOutput& data);
    
    // Shuffle bytes
    void shuffleBytes(MutationOutput& data);
    
    // Crossover mutation
    void crossOver(MutationOutput& data, SharedContext& ctx);
    
    // Dictionary mutation
    void dictionaryMutation(MutationOutput& data, SharedContext& ctx);
    
    // Select position (weighted)
    size_t selectPosition(size_t max_pos);
    
    // Update mutation weights
    void updateMutationWeights(const GradientInfo& gradient_info, size_t data_size);
};

// Gradient-descent mutation algorithm
class GradientDescentMutation : public MutationAlgorithm {
private:
    double learning_rate_ = 0.01;
    double momentum_ = 0.9;
    std::map<size_t, double> velocity_; // Momentum velocity
    
public:
    GradientDescentMutation() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "gradient_descent";
        info.provided_info = {InfoType::Gradient, InfoType::Coverage};
        info.required_info = {InfoType::Constraint}; // Optionally uses constraint info
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void updateParameters(const Parameters& params) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
private:
    // Compute gradient
    GradientInfo computeGradient(const MutationInput& input, SharedContext& ctx) {
        GradientInfo gradient_info;
        
        // This should contain the real gradient computation logic.
        // Simplified example: randomly select some positions and assign gradients.
        std::uniform_int_distribution<size_t> pos_dist(0, input.size() - 1);
        std::uniform_real_distribution<double> grad_dist(-1.0, 1.0);
        
        size_t num_positions = std::min<size_t>(10, input.size() / 10);
        for (size_t i = 0; i < num_positions; ++i) {
            size_t pos = pos_dist(random_gen_);
            double grad = grad_dist(random_gen_);
            
            gradient_info.positions.push_back(pos);
            gradient_info.gradients.push_back(grad);
        }
        
        gradient_info.learning_rate = learning_rate_;
        gradient_info.momentum = momentum_;
        
        return gradient_info;
    }
    
    // Apply gradient update
    void applyGradientUpdate(MutationOutput& data, const GradientInfo& gradient_info) {
        for (size_t i = 0; i < gradient_info.positions.size(); ++i) {
            size_t pos = gradient_info.positions[i];
            if (pos >= data.size()) continue;
            
            double gradient = gradient_info.gradients[i];
            
            // Apply momentum
            double& v = velocity_[pos];
            v = momentum_ * v - learning_rate_ * gradient;
            
            // Update value
            int new_val = static_cast<int>(data[pos]) + static_cast<int>(v);
            data[pos] = static_cast<uint8_t>(std::max(0, std::min(255, new_val)));
        }
    }
    
    // Apply constraints
    void applyConstraints(MutationOutput& data, const ConstraintInfo& constraint_info) {
        // If concrete constraint solutions exist, apply them.
        for (const auto& [pos, values] : constraint_info.concrete_values) {
            if (pos < data.size() && !values.empty()) {
                data[pos] = values[0]; // Use the first solution
            }
        }
    }
};

// Bit-flip mutation algorithm
class BitFlipMutation : public MutationAlgorithm {
private:
    size_t flip_bits_ = 1; // Bits to flip per mutation
    
public:
    BitFlipMutation() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "bit_flip";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void updateParameters(const Parameters& params) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
};

// Arithmetic mutation algorithm
class ArithmeticMutation : public MutationAlgorithm {
private:
    int max_delta_ = 35;
    
public:
    ArithmeticMutation() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "arithmetic";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void updateParameters(const Parameters& params) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
private:
    void applyArithmetic(MutationOutput& data, size_t pos, int delta, size_t total_len) {
        if (pos >= data.size()) return;
        
        // Handle multi-byte arithmetic.
        if (total_len == 2 && pos + 1 < data.size()) {
            // 16-bit arithmetic
            uint16_t val = (data[pos] << 8) | data[pos + 1];
            val += delta;
            data[pos] = (val >> 8) & 0xFF;
            data[pos + 1] = val & 0xFF;
        } else if (total_len == 4 && pos + 3 < data.size()) {
            // 32-bit arithmetic
            uint32_t val = (data[pos] << 24) | (data[pos + 1] << 16) | 
                          (data[pos + 2] << 8) | data[pos + 3];
            val += delta;
            data[pos] = (val >> 24) & 0xFF;
            data[pos + 1] = (val >> 16) & 0xFF;
            data[pos + 2] = (val >> 8) & 0xFF;
            data[pos + 3] = val & 0xFF;
        } else {
            // 8-bit arithmetic
            int new_val = static_cast<int>(data[pos]) + delta;
            data[pos] = static_cast<uint8_t>(std::max(0, std::min(255, new_val)));
        }
    }
};

// Splice mutation algorithm
class SpliceMutation : public MutationAlgorithm {
public:
    SpliceMutation() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "splice";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
};

// Deterministic mutation algorithm - systematically explores the input space
class DeterministicMutation : public MutationAlgorithm {
private:
    size_t current_byte_pos_ = 0;
    size_t current_bit_pos_ = 0;
    size_t phase_ = 0; // 0: bit flip, 1: byte flip, 2: arithmetic, 3: interesting values
    bool completed_cycle_ = false;
    
    // Interesting value lists
    static const std::vector<uint8_t> interesting_8_bit_;
    static const std::vector<uint16_t> interesting_16_bit_;
    static const std::vector<uint32_t> interesting_32_bit_;
    
public:
    DeterministicMutation() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "deterministic";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void updateParameters(const Parameters& params) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
    // Reset state to start a new deterministic cycle.
    void reset() {
        current_byte_pos_ = 0;
        current_bit_pos_ = 0;
        phase_ = 0;
        completed_cycle_ = false;
    }
    
    // Check whether a full deterministic cycle is complete.
    bool hasCompletedCycle() const {
        return completed_cycle_;
    }
    
private:
    // Bit-flip phase
    MutationOutput bitFlipPhase(const MutationInput& input);
    
    // Byte-flip phase
    MutationOutput byteFlipPhase(const MutationInput& input);
    
    // Arithmetic phase
    MutationOutput arithmeticPhase(const MutationInput& input);
    
    // Interesting-value replacement phase
    MutationOutput interestingValuePhase(const MutationInput& input);
    
    // Advance to the next state
    void advanceState(size_t input_size);
};

// Smart dictionary mutation algorithm
class SmartDictionaryMutation : public MutationAlgorithm {
private:
    std::vector<std::vector<uint8_t>> static_dictionary_;
    std::vector<std::vector<uint8_t>> dynamic_dictionary_;
    size_t max_dynamic_entries_ = 1000;
    
public:
    SmartDictionaryMutation() {
        initializeStaticDictionary();
    }
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "smart_dictionary";
        info.provided_info = {InfoType::Coverage};
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
    // Extract dictionary entries from inputs with new coverage.
    void extractDictionaryFromInput(const std::vector<uint8_t>& input);
    
private:
    void initializeStaticDictionary();
    
    // Find potential dictionary tokens in the input.
    std::vector<std::vector<uint8_t>> findPotentialTokens(const std::vector<uint8_t>& input);
    
    // Apply dictionary mutation
    MutationOutput applyDictionaryMutation(const MutationInput& input, 
                                         const std::vector<uint8_t>& dict_entry);
};

} // namespace triofuzz
