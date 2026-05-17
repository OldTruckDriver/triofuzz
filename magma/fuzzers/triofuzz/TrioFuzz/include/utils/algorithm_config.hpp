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
// Enabled algorithm lists - this is the only place you need to edit!
// ============================================================================

/**
 * @brief Enabled mutation algorithms - aligned with the AFL++ configuration space
 *
 * The outer learner (Thompson Sampling) selects a "configuration"
 * (power schedule × {havoc,mopt} × splice), so we need both:
 * 1) The 37 independent AFL++ TS Parallel mut_* operators (for havoc stacking, splice on/off)
 * 2) The 19 AFL++ MOpt mopt_* stages (for MOpt operator selection, splice on/off)
 *
 * Mapping 0..18:
 * 00. mopt_flip1           - Flip 1 bit
 * 01. mopt_flip2           - Flip 2 adjacent bits
 * 02. mopt_flip4           - Flip 4 adjacent bits
 * 03. mopt_flip8           - Flip 1 byte (XOR 0xFF)
 * 04. mopt_flip16          - Flip 2 bytes (XOR 0xFFFF)
 * 05. mopt_flip32          - Flip 4 bytes (XOR 0xFFFFFFFF)
 * 06. mopt_arith8          - 8-bit add/sub (includes both subtract and add)
 * 07. mopt_arith16         - 16-bit add/sub (random endianness; includes subtract and add)
 * 08. mopt_arith32         - 32-bit add/sub (random endianness; includes subtract and add)
 * 09. mopt_interest8       - 8-bit interesting value
 * 10. mopt_interest16      - 16-bit interesting value (random endianness)
 * 11. mopt_interest32      - 32-bit interesting value (random endianness)
 * 12. mopt_rand8           - Random byte XOR (1..255)
 * 13. mopt_deletebyte      - Delete random block
 * 14. mopt_clone75         - clone(75%) / const insert(25%)
 * 15. mopt_overwrite75     - copy overwrite(75%) / fixed overwrite(25%)
 * 16. mopt_overwrite_extra - Dictionary overwrite
 * 17. mopt_insert_extra    - Dictionary insert
 * 18. mopt_splice          - splice (overwrite / insert)
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

    // Advanced analysis-guided mutation algorithms (5 ops) - integrated from triofuzz
    // These algorithms take longer (1-50ms), but can find complex constraints and magic bytes.
    // Selected via the TS "explore_analysis" arm.
    "cmplog",                // Comparison instruction logging - uses trace-cmp to discover magic bytes (~1-5ms)
    "redqueen",              // Input-to-state mapping - non-intrusive constraint solving (~15-50ms)
    "smart_dictionary",      // Smart dictionary - extract tokens from input (~0.5-2ms)
    "runtime_dictionary",    // Runtime dictionary - dynamically collect entries (~0.5-2ms)
    "format_overflow",       // Format-aware integer overflow - precisely targets PNG001/004/005/006/007 (~0.1-1ms)

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
 * @brief Enabled feedback analyzers
 *
 * Currently all archived; no feedback analyzers are enabled to optimize performance.
 */
inline const std::vector<std::string> ENABLED_FEEDBACKS = {
    // All archived
    // "lightweight_coverage_analyzer",
    // "coverage_analyzer",
    // "enhanced_coverage_analyzer",
};

/**
 * @brief Enabled schedulers
 *
 * Currently all archived; use the default CorpusManager scheduling.
 */
inline const std::vector<std::string> ENABLED_SCHEDULERS = {
    // All archived
    // "fast_scheduler",
    // "energy_scheduler",
};

// ============================================================================
// Archived algorithms - used for checks and warnings
// ============================================================================

/**
 * @brief Archived algorithm set
 *
 * List of all algorithms archived in Batch 1-5, used to:
 * 1. Warn users at runtime when an archived algorithm is used
 * 2. Prevent accidental re-enablement
 * 3. Provide documentation/reference
 */
inline const std::set<std::string> ARCHIVED_ALGORITHMS = {
    // Batch 1: slow instrumentation algorithms
    // "redqueen",           // Extremely slow (15-50ms/exec) — enabled to participate in the main pipeline
    // "cmplog",             // Enabled
    "taint_guided",       // Slow (3-8ms)
    "rare_branch",        // Moderately slow
    // "arithmetic",       // Enabled

    // Batch 2: medium-overhead algorithms
    "classic_libfuzzer",  // Medium overhead
    // "icc_profile",        // Format-specific, medium overhead
    "jpeg_mutation",      // Format-specific, medium overhead
    "entropy_guided",     // Fully covered by byte_weighted_havoc (0.35ms) and token (0.25ms); too expensive (entropy distribution computation >1ms)
    "performance_analyzer", // Performance analysis overhead
    "smart_format",       // Slow (13ms)
    "fast_scheduler",     // Scheduler overhead

    // Batch 3: schedulers and dictionary algorithms
    "lightweight_coverage_analyzer",
    "coverage_analyzer",
    "mopt_scheduler",     // Slow (11-13ms)
    "energy_scheduler",
    "enhanced_coverage_analyzer",
    // "format_aware",       // High overhead for format awareness — enabled to participate in the main pipeline
    // "smart_dictionary", // Enabled
    "runtime_dictionary",

    // Batch 4: AFL++ and Honggfuzz
    "afl_plus_plus",      // Medium overhead (0.5-2ms/exec)
    "honggfuzz",          // ~70% functionality overlap; core advantage (hardware feedback) not implemented; split into trim and block

    // Batch 5: Deterministic
    "deterministic",      // Systematic mutations; low overhead but high redundancy

    // Other archived high-overhead algorithms
    "neuzz",              // AI algorithm, very high overhead
    "gradient_descent",   // Gradient descent, high overhead
    "symbolic_execution", // Symbolic execution, very high overhead
    "zest",               // Structured fuzzing, high overhead
    "libfuzzer_structured", // Structured fuzzing, high overhead
    "rare_edge_scheduler", // Scheduler, slow (11-13ms)
    "aflgo",              // Targeted fuzzing, slow (14ms)
    "crash_analyzer",     // Crash analysis, slow (11-12ms)
    "angora_gradient_descent", // Gradient descent, high overhead
    "adaptive_mutation_orchestrator", // Orchestrator has high overhead
    "icc_aggressive",     // ICC-specific, medium overhead
    "fairfuzz",           // Fairness-based algorithm, medium overhead
};

// ============================================================================
// Helper functions - provide a unified query interface
// ============================================================================

/**
 * @brief Check whether an algorithm is enabled
 */
inline bool isEnabled(const std::string& algo_name) {
    // Check whether it is in any enabled list
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
 * @brief Check whether an algorithm is archived
 */
inline bool isArchived(const std::string& algo_name) {
    return ARCHIVED_ALGORITHMS.find(algo_name) != ARCHIVED_ALGORITHMS.end();
}

/**
 * @brief Get all enabled algorithms (mutation + feedback + scheduler)
 */
inline std::vector<std::string> getAllEnabled() {
    std::vector<std::string> all;
    all.insert(all.end(), ENABLED_MUTATIONS.begin(), ENABLED_MUTATIONS.end());
    all.insert(all.end(), ENABLED_FEEDBACKS.begin(), ENABLED_FEEDBACKS.end());
    all.insert(all.end(), ENABLED_SCHEDULERS.begin(), ENABLED_SCHEDULERS.end());
    return all;
}

/**
 * @brief Filter out archived algorithms
 * @param algorithms Algorithms to filter
 * @return Filtered list containing only enabled algorithms
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
 * @brief Combination mode configuration
 *
 * To optimize performance, only sequential mode is enabled.
 * Parallel mode has thread synchronization overhead and performs worse.
 */
inline const std::vector<std::string> ENABLED_COMBINATION_MODES = {
    "sequential"
    // "parallel" - disabled due to synchronization overhead
    // "adaptive" - rarely used
};

/**
 * @brief Performance configuration
 */
struct PerformanceConfig {
    // Havoc mutation count limits
    static constexpr size_t HAVOC_MIN_MUTATIONS = 1;
    static constexpr size_t HAVOC_MAX_MUTATIONS = 8;      // Reduced from 16 to 8
    static constexpr size_t HAVOC_MAX_RARE_EDGE = 16;     // Reduced from 32 to 16
    static constexpr size_t HAVOC_MAX_LARGE_INPUT = 4;    // Reduced from 8 to 4

    // Algorithm count limits per combination
    static constexpr size_t MAX_ALGORITHMS_PER_COMBO = 3;
    static constexpr size_t PREFERRED_ALGORITHMS_PER_COMBO = 2;
};

} // namespace AlgorithmConfig
} // namespace triofuzz
