#include "../../include/core/algorithm.hpp"
#include "../../include/core/context.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

namespace triofuzz {

// Algorithm compatibility check
bool isCompatible(const AlgorithmInfo& a, const AlgorithmInfo& b) {
    // Check type compatibility
    if (a.type == b.type) {
        return false; // Algorithms of the same type are typically not combined
    }
    
    // Check information dependencies
    for (const auto& required : a.required_info) {
        bool found = false;
        for (const auto& provided : b.provided_info) {
            if (required == provided) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    
    return true;
}

} // namespace collabuzz 
