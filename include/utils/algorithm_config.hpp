#pragma once

#include <vector>
#include <set>
#include <string>
#include <algorithm>

namespace triofuzz {

/**
 * @brief Centralized algorithm configuration - Single Source of Truth
 *
 * All algorithm enable/disable states are defined here.
 * To archive an algorithm, remove it from the corresponding ENABLED list and add it to ARCHIVED.
 *
 * Usage:
 *   - Reference AlgorithmConfig::ENABLED_MUTATIONS etc. wherever algorithm lists are needed
 *   - Check if an algorithm is available: AlgorithmConfig::isEnabled("havoc")
 *   - Check if an algorithm is archived: AlgorithmConfig::isArchived("afl_plus_plus")
 */
namespace AlgorithmConfig {

// ============================================================================
// 启用的算法列表 - 这是唯一需要修改的地方！
// ============================================================================

/**
 * @brief 启用的变异算法 - 对标 AFL++ 配置空间
 *
 * 外层学习（Thompson Sampling）选择的是"配置"（power schedule ×
 * {havoc,mopt} × splice），因此需要同时具备：
 * 1) AFL++ TS Parallel 的 37 个独立 mut_* 算子（用于 havoc stacking，支持 splice on/off）
 * 2) AFL++ MOpt 的 19 个 mopt_* stage（用于 mopt 选算子，支持 splice on/off）
 *
 * 0..18 对应关系：
 * 00. mopt_flip1           - 翻转 1 bit
 * 01. mopt_flip2           - 翻转相邻 2 bit
 * 02. mopt_flip4           - 翻转相邻 4 bit
 * 03. mopt_flip8           - 翻转 1 byte (XOR 0xFF)
 * 04. mopt_flip16          - 翻转 2 bytes (XOR 0xFFFF)
 * 05. mopt_flip32          - 翻转 4 bytes (XOR 0xFFFFFFFF)
 * 06. mopt_arith8          - 8-bit add/sub (一次包含减+加)
 * 07. mopt_arith16         - 16-bit add/sub (随机端序，包含减+加)
 * 08. mopt_arith32         - 32-bit add/sub (随机端序，包含减+加)
 * 09. mopt_interest8       - 8-bit interesting value
 * 10. mopt_interest16      - 16-bit interesting value (随机端序)
 * 11. mopt_interest32      - 32-bit interesting value (随机端序)
 * 12. mopt_rand8           - 随机字节 XOR (1..255)
 * 13. mopt_deletebyte      - 删除随机块
 * 14. mopt_clone75         - clone(75%) / const insert(25%)
 * 15. mopt_overwrite75     - copy overwrite(75%) / fixed overwrite(25%)
 * 16. mopt_overwrite_extra - 字典覆写
 * 17. mopt_insert_extra    - 字典插入
 * 18. mopt_splice          - splice（overwrite / insert）
 */
inline const std::vector<std::string> ENABLED_MUTATIONS = {
    // AFL++ individual mutations (TS Parallel operator set, 37 ops)
    "mut_flipbit",               // 00
    "mut_interesting8",          // 01
    "mut_interesting16",         // 02
    "mut_interesting16be",       // 03
    "mut_interesting32",         // 04
    "mut_interesting32be",       // 05
    "mut_arith8_sub",            // 06
    "mut_arith8_add",            // 07
    "mut_arith16_sub",           // 08
    "mut_arith16be_sub",         // 09
    "mut_arith16_add",           // 10
    "mut_arith16be_add",         // 11
    "mut_arith32_sub",           // 12
    "mut_arith32be_sub",         // 13
    "mut_arith32_add",           // 14
    "mut_arith32be_add",         // 15
    "mut_rand8",                 // 16
    "mut_clone_copy",            // 17
    "mut_clone_fixed",           // 18
    "mut_overwrite_copy",        // 19
    "mut_overwrite_fixed",       // 20
    "mut_byteadd",               // 21
    "mut_bytesub",               // 22
    "mut_flip8",                 // 23
    "mut_switch",                // 24
    "mut_del",                   // 25
    "mut_shuffle",               // 26
    "mut_delone",                // 27
    "mut_insertone",             // 28
    "mut_asciinum",              // 29
    "mut_insertasciinum",        // 30
    "mut_extra_overwrite",       // 31
    "mut_extra_insert",          // 32
    "mut_auto_extra_overwrite",  // 33
    "mut_auto_extra_insert",     // 34
    "mut_splice_overwrite",      // 35
    "mut_splice_insert",         // 36

    // triofuzz integration algorithms (9 ops)
    "byte_weighted_havoc",
    "varint",
    "token",
    "chunk_based",
    "run_length",
    "magic_byte",
    "length_extension",
    "endianness_swap",
    "trim",

    // 高级分析引导变异算法 (5 ops) - 从 triofuzz 整合
    // 这些算法执行时间较长 (1-50ms)，但能发现复杂约束和魔法字节
    // 通过 TS 的 "explore_analysis" arm 选择使用
    "cmplog",                // 比较指令日志 - 利用 trace-cmp 发现魔法字节 (~1-5ms)
    "redqueen",              // 输入-状态映射 - 非侵入式约束求解 (~15-50ms)
    "smart_dictionary",      // 智能字典 - 从输入中提取 token (~0.5-2ms)
    "runtime_dictionary",    // 运行时字典 - 动态收集字典 (~0.5-2ms)
    "format_overflow",       // 格式感知整数溢出 - PNG001/004/005/006/007 精确触发 (~0.1-1ms)

    // AFL++ MOpt stage set (operator_num=19)
    "mopt_flip1",            // 00
    "mopt_flip2",            // 01
    "mopt_flip4",            // 02
    "mopt_flip8",            // 03
    "mopt_flip16",           // 04
    "mopt_flip32",           // 05
    "mopt_arith8",           // 06
    "mopt_arith16",          // 07
    "mopt_arith32",          // 08
    "mopt_interest8",        // 09
    "mopt_interest16",       // 10
    "mopt_interest32",       // 11
    "mopt_rand8",            // 12
    "mopt_deletebyte",       // 13
    "mopt_clone75",          // 14
    "mopt_overwrite75",      // 15
    "mopt_overwrite_extra",  // 16
    "mopt_insert_extra",     // 17
    "mopt_splice",           // 18
};

/**
 * @brief 启用的反馈分析器
 *
 * 当前全部归档，不使用任何feedback analyzer以优化性能
 */
inline const std::vector<std::string> ENABLED_FEEDBACKS = {
    // 全部归档
    // "lightweight_coverage_analyzer",
    // "coverage_analyzer",
    // "enhanced_coverage_analyzer",
};

/**
 * @brief 启用的调度器
 *
 * 当前全部归档，使用默认的CorpusManager调度
 */
inline const std::vector<std::string> ENABLED_SCHEDULERS = {
    // 全部归档
    // "fast_scheduler",
    // "energy_scheduler",
};

// ============================================================================
// 已归档的算法 - 用于检查和警告
// ============================================================================

/**
 * @brief 已归档的算法集合
 *
 * Batch 1-5 归档的所有算法列表，用于：
 * 1. 运行时警告用户使用了已归档算法
 * 2. 防止意外重新启用
 * 3. 文档记录
 */
inline const std::set<std::string> ARCHIVED_ALGORITHMS = {
    // Batch 1: 慢速instrumentation算法
    // "redqueen",           // 极慢 (15-50ms/exec) — 已启用以参与主流程
    // "cmplog",             // 已启用
    "taint_guided",       // 慢速 (3-8ms)
    "rare_branch",        // 中慢速
    // "arithmetic",       // 已启用

    // Batch 2: 中等开销算法
    "classic_libfuzzer",  // 中等开销
    // "icc_profile",        // 特定格式，中等开销
    "jpeg_mutation",      // 特定格式，中等开销
    "entropy_guided",     // 功能被byte_weighted_havoc(0.35ms)和token(0.25ms)完全覆盖，计算开销过高（熵分布计算>1ms）
    "performance_analyzer", // 性能分析开销
    "smart_format",       // 性能慢 (13ms)
    "fast_scheduler",     // 调度器开销

    // Batch 3: 调度器和字典算法
    "lightweight_coverage_analyzer",
    "coverage_analyzer",
    "mopt_scheduler",     // 性能慢 (11-13ms)
    "energy_scheduler",
    "enhanced_coverage_analyzer",
    // "format_aware",       // 格式感知开销大 — 已启用以参与主流程
    // "smart_dictionary", // 已启用
    "runtime_dictionary",

    // Batch 4: AFL++和Honggfuzz
    "afl_plus_plus",      // 中等开销 (0.5-2ms/exec)
    "honggfuzz",          // 功能重复70%，核心优势（硬件反馈）未实现，已拆分为trim和block

    // Batch 5: Deterministic
    "deterministic",      // 系统性变异，低开销但重复性高

    // 其他已归档的高开销算法
    "neuzz",              // AI算法，极高开销
    "gradient_descent",   // 梯度下降，高开销
    "symbolic_execution", // 符号执行，极高开销
    "zest",               // 结构化fuzzing，高开销
    "libfuzzer_structured", // 结构化fuzzing，高开销
    "rare_edge_scheduler", // 调度器，性能慢 (11-13ms)
    "aflgo",              // 定向fuzzing，性能慢 (14ms)
    "crash_analyzer",     // 崩溃分析，性能慢 (11-12ms)
    "angora_gradient_descent", // 梯度下降，高开销
    "adaptive_mutation_orchestrator", // 编排器开销大
    "icc_aggressive",     // ICC特定，中等开销
    "fairfuzz",           // 公平性算法，中等开销
};

// ============================================================================
// 辅助函数 - 提供统一的查询接口
// ============================================================================

/**
 * @brief 检查算法是否已启用
 */
inline bool isEnabled(const std::string& algo_name) {
    // 检查是否在启用列表中
    if (std::find(ENABLED_MUTATIONS.begin(), ENABLED_MUTATIONS.end(), algo_name) != ENABLED_MUTATIONS.end()) {
        return true;
    }
    if (std::find(ENABLED_FEEDBACKS.begin(), ENABLED_FEEDBACKS.end(), algo_name) != ENABLED_FEEDBACKS.end()) {
        return true;
    }
    if (std::find(ENABLED_SCHEDULERS.begin(), ENABLED_SCHEDULERS.end(), algo_name) != ENABLED_SCHEDULERS.end()) {
        return true;
    }
    return false;
}

/**
 * @brief 检查算法是否已归档
 */
inline bool isArchived(const std::string& algo_name) {
    return ARCHIVED_ALGORITHMS.find(algo_name) != ARCHIVED_ALGORITHMS.end();
}

/**
 * @brief 获取所有启用的算法（mutation + feedback + scheduler）
 */
inline std::vector<std::string> getAllEnabled() {
    std::vector<std::string> all;
    all.insert(all.end(), ENABLED_MUTATIONS.begin(), ENABLED_MUTATIONS.end());
    all.insert(all.end(), ENABLED_FEEDBACKS.begin(), ENABLED_FEEDBACKS.end());
    all.insert(all.end(), ENABLED_SCHEDULERS.begin(), ENABLED_SCHEDULERS.end());
    return all;
}

/**
 * @brief 过滤掉已归档的算法
 * @param algorithms 待过滤的算法列表
 * @return 过滤后只包含启用算法的列表
 */
inline std::vector<std::string> filterEnabled(const std::vector<std::string>& algorithms) {
    std::vector<std::string> filtered;
    for (const auto& algo : algorithms) {
        if (isEnabled(algo) && !isArchived(algo)) {
            filtered.push_back(algo);
        }
    }
    return filtered;
}

/**
 * @brief 组合模式配置
 *
 * 为了优化性能，只使用sequential模式
 * parallel模式有线程同步开销，性能较差
 */
inline const std::vector<std::string> ENABLED_COMBINATION_MODES = {
    "sequential"
    // "parallel" - 已禁用，有同步开销
    // "adaptive" - 较少使用
};

/**
 * @brief 性能配置
 */
struct PerformanceConfig {
    // Havoc变异次数限制
    static constexpr size_t HAVOC_MIN_MUTATIONS = 1;
    static constexpr size_t HAVOC_MAX_MUTATIONS = 8;      // 从16降到8
    static constexpr size_t HAVOC_MAX_RARE_EDGE = 16;     // 从32降到16
    static constexpr size_t HAVOC_MAX_LARGE_INPUT = 4;    // 从8降到4

    // 组合中算法数量限制
    static constexpr size_t MAX_ALGORITHMS_PER_COMBO = 3;
    static constexpr size_t PREFERRED_ALGORITHMS_PER_COMBO = 2;
};

} // namespace AlgorithmConfig
} // namespace triofuzz
