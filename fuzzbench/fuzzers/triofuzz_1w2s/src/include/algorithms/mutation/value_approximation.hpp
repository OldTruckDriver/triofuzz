#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <random>

namespace triofuzz {

/**
 * Value approximation helper.
 * Implements LAF-Intel-style staged value approximation.
 * Helps break through multi-byte comparison checks.
 */
class ValueApproximation {
public:
    // Approximation strategies
    enum class Strategy {
        BINARY_SEARCH,      // Binary-search approximation
        LINEAR_PROGRESSION, // Linear progression
        EXPONENTIAL_JUMP,   // Exponential jumps
        RANDOM_WALK        // Random walk
    };
    
private:
    static std::mt19937 random_gen_;
    
public:
    /**
     * Break a multi-byte comparison into per-byte steps and gradually approach the target value.
     */
    static std::vector<uint8_t> approximateValue(
        const std::vector<uint8_t>& current,
        const std::vector<uint8_t>& target,
        size_t offset,
        double progress_rate = 0.5) {
        
        if (offset >= current.size()) {
            return current;
        }
        
        std::vector<uint8_t> result = current;
        
        // Approximate byte-by-byte towards the target value.
        for (size_t i = 0; i < target.size() && offset + i < result.size(); ++i) {
            uint8_t curr = result[offset + i];
            uint8_t tgt = target[i];
            
            if (curr != tgt) {
                // Move towards the target with some probability.
                std::uniform_real_distribution<> dis(0.0, 1.0);
                if (dis(random_gen_) < progress_rate) {
                    // Compute step size.
                    if (curr < tgt) {
                        uint8_t step = (tgt - curr) / 2;
                        if (step == 0) step = 1;
                        result[offset + i] = curr + step;
                    } else {
                        uint8_t step = (curr - tgt) / 2;
                        if (step == 0) step = 1;
                        result[offset + i] = curr - step;
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Approximate integer comparisons.
     */
    template<typename T>
    static std::vector<uint8_t> approximateInteger(
        const std::vector<uint8_t>& current,
        T target,
        size_t offset,
        Strategy strategy = Strategy::BINARY_SEARCH) {
        
        if (offset + sizeof(T) > current.size()) {
            return current;
        }
        
        std::vector<uint8_t> result = current;
        T current_val;
        std::memcpy(&current_val, &result[offset], sizeof(T));
        
        T new_val = current_val;
        
        switch (strategy) {
            case Strategy::BINARY_SEARCH: {
                // Binary-search approximation
                T diff = (target > current_val) ? 
                        (target - current_val) : (current_val - target);
                diff /= 2;
                if (diff == 0) diff = 1;
                
                new_val = (target > current_val) ? 
                         (current_val + diff) : (current_val - diff);
                break;
            }
            
            case Strategy::LINEAR_PROGRESSION: {
                // Linear progression
                T step = (target - current_val) / 10;
                if (step == 0) {
                    step = (target > current_val) ? 1 : -1;
                }
                new_val = current_val + step;
                break;
            }
            
            case Strategy::EXPONENTIAL_JUMP: {
                // Exponential jumps
                T diff = std::abs(static_cast<long long>(target) - 
                                 static_cast<long long>(current_val));
                T jump = 1;
                while (jump < diff / 4) {
                    jump *= 2;
                }
                new_val = (target > current_val) ? 
                         (current_val + jump) : (current_val - jump);
                break;
            }
            
            case Strategy::RANDOM_WALK: {
                // Random walk
                std::uniform_int_distribution<T> dis(
                    std::min(current_val, target),
                    std::max(current_val, target)
                );
                new_val = dis(random_gen_);
                break;
            }
        }
        
        std::memcpy(&result[offset], &new_val, sizeof(T));
        return result;
    }
    
    /**
     * Approximate floating-point comparisons.
     */
    static std::vector<uint8_t> approximateFloat(
        const std::vector<uint8_t>& current,
        float target,
        size_t offset,
        float step_ratio = 0.1f) {
        
        if (offset + sizeof(float) > current.size()) {
            return current;
        }
        
        std::vector<uint8_t> result = current;
        float current_val;
        std::memcpy(&current_val, &result[offset], sizeof(float));
        
        // Handle special values
        if (std::isnan(current_val) || std::isinf(current_val)) {
            current_val = 0.0f;
        }
        
        // Stepwise approximation
        float new_val = current_val + (target - current_val) * step_ratio;
        
        // Handle very small differences
        if (std::abs(new_val - current_val) < 1e-7f) {
            new_val = target;
        }
        
        std::memcpy(&result[offset], &new_val, sizeof(float));
        return result;
    }
    
    /**
     * Approximate string comparisons (strcmp, memcmp, etc.).
     */
    static std::vector<uint8_t> approximateString(
        const std::vector<uint8_t>& current,
        const std::string& target,
        size_t offset) {
        
        if (offset >= current.size()) {
            return current;
        }
        
        std::vector<uint8_t> result = current;
        size_t max_len = std::min(target.size(), current.size() - offset);
        
        // Approximate character-by-character
        for (size_t i = 0; i < max_len; ++i) {
            // Modify each character with 50% probability.
            std::uniform_real_distribution<> dis(0.0, 1.0);
            if (dis(random_gen_) < 0.5) {
                result[offset + i] = static_cast<uint8_t>(target[i]);
            }
        }
        
        // If the target string is longer, consider extending.
        if (target.size() > max_len && offset + target.size() <= result.size()) {
            for (size_t i = max_len; i < target.size(); ++i) {
                result[offset + i] = static_cast<uint8_t>(target[i]);
            }
        }
        
        return result;
    }
    
    /**
     * Multi-stage approximation: from coarse to fine.
     */
    static std::vector<uint8_t> multiStageApproximation(
        const std::vector<uint8_t>& current,
        const std::vector<uint8_t>& target,
        size_t offset,
        int stage) {
        
        // Adjust progress rate by stage.
        double progress_rates[] = {0.1, 0.25, 0.5, 0.75, 0.9, 1.0};
        int max_stage = sizeof(progress_rates) / sizeof(progress_rates[0]);
        
        if (stage >= max_stage) {
            stage = max_stage - 1;
        }
        
        return approximateValue(current, target, offset, progress_rates[stage]);
    }
    
    /**
     * Smart approximation: choose strategy based on difference magnitude.
     */
    static std::vector<uint8_t> smartApproximation(
        const std::vector<uint8_t>& current,
        const std::vector<uint8_t>& target,
        size_t offset) {
        
        if (offset >= current.size() || target.empty()) {
            return current;
        }
        
        // Compute Hamming distance.
        size_t hamming_distance = 0;
        size_t check_len = std::min(target.size(), current.size() - offset);
        
        for (size_t i = 0; i < check_len; ++i) {
            if (current[offset + i] != target[i]) {
                hamming_distance++;
            }
        }
        
        // Choose progress rate based on distance.
        double progress_rate;
        if (hamming_distance <= check_len * 0.1) {
            // Very close: small steps
            progress_rate = 0.9;
        } else if (hamming_distance <= check_len * 0.5) {
            // Medium distance: normal steps
            progress_rate = 0.5;
        } else {
            // Far apart: larger jumps
            progress_rate = 0.2;
        }
        
        return approximateValue(current, target, offset, progress_rate);
    }
    
    /**
     * Handle magic bytes (e.g., file headers).
     */
    static std::vector<uint8_t> approximateMagicBytes(
        const std::vector<uint8_t>& current,
        const std::vector<uint8_t>& magic,
        size_t offset = 0) {
        
        if (offset + magic.size() > current.size()) {
            return current;
        }
        
        std::vector<uint8_t> result = current;
        
        // Magic bytes usually require exact matches, so replace directly.
        std::copy(magic.begin(), magic.end(), result.begin() + offset);
        
        return result;
    }
    
    /**
     * Boundary-value approximation.
     */
    template<typename T>
    static std::vector<uint8_t> approximateBoundary(
        const std::vector<uint8_t>& current,
        size_t offset,
        bool use_max = false) {
        
        if (offset + sizeof(T) > current.size()) {
            return current;
        }
        
        std::vector<uint8_t> result = current;
        T boundary_val;
        
        if (use_max) {
            boundary_val = std::numeric_limits<T>::max();
        } else {
            boundary_val = std::numeric_limits<T>::min();
        }
        
        std::memcpy(&result[offset], &boundary_val, sizeof(T));
        return result;
    }
};

// Static member initialization
std::mt19937 ValueApproximation::random_gen_(std::random_device{}());

} // namespace triofuzz
