#include "../../include/core/algorithm.hpp"
#include "../../include/core/context.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

namespace triofuzz {

// 算法信息比较函数
bool isCompatible(const AlgorithmInfo& a, const AlgorithmInfo& b) {
    // 检查类型兼容性
    if (a.type == b.type) {
        return false; // 同类型算法通常不组合
    }
    
    // 检查信息依赖
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