#include "../../include/core/engine.hpp"
#include "../../include/utils/corpus_manager.hpp"
#include "../../include/algorithms/scheduling/rare_edge_scheduler.hpp"
// #include "../../include/algorithms/scheduling/fast_scheduler.hpp" // 已归档
// #include "../../include/algorithms/scheduling/mopt_scheduler.hpp" // 已归档
#include "../../include/algorithms/scheduling/scheduling_algorithms.hpp"
#include <iostream>

namespace triofuzz {

// 根据完整流水线组合选择种子 (支持调度器)
Seed FuzzingEngine::selectSeedWithScheduler(const AlgorithmCombination& combination) {
    // 如果组合指定了scheduler，使用对应的调度器
    if (!combination.scheduler_name.empty()) {
        // 获取所有可用种子
        std::vector<Seed> available_seeds;
        if (corpus_manager_) {
            // 简化方案：多次调用getNextSeed()来构建种子池
            // 限制为最多100个种子以避免性能问题
            for (size_t i = 0; i < 100; ++i) {
                auto seed_opt = corpus_manager_->getNextSeed();
                if (seed_opt.has_value()) {
                    available_seeds.push_back(seed_opt.value());
                } else {
                    break;  // 没有更多种子
                }
            }
        }

        // 如果没有可用种子，回退到默认选择
        if (available_seeds.empty()) {
            return selectSeed();
        }

        // 根据scheduler类型选择种子
        try {
            if (combination.scheduler_name == "rare_edge_scheduler") {
                // 使用RareEdgeScheduler - 优先选择触发稀有边的种子
                RareEdgeScheduler scheduler;
                auto selected = scheduler.execute(available_seeds, *global_context_);

                static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
                if (verbose) {
                    std::cout << "[Scheduler] RareEdgeScheduler selected seed with "
                              << selected.coverage.rare_edges.size() << " rare edges" << std::endl;
                }
                return selected;

            // 已归档
            // } else if (combination.scheduler_name == "fast_scheduler") {
            //     // 使用FastScheduler - 优先选择favored种子
            //     FastScheduler scheduler;
            //     auto selected = scheduler.execute(available_seeds, *global_context_);

            //     static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
            //     if (verbose) {
            //         std::cout << "[Scheduler] FastScheduler selected "
            //                   << (selected.favored ? "favored" : "unfavored") << " seed" << std::endl;
            //     }
            //     return selected;

            // } else if (combination.scheduler_name == "mopt_scheduler") { // 已归档
            //     // 使用MOPTScheduler - 多目标优化选择
            //     MOptScheduler scheduler;
            //     auto selected = scheduler.execute(available_seeds, *global_context_);

            //     static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
            //     if (verbose) {
            //         std::cout << "[Scheduler] MOPTScheduler selected seed" << std::endl;
            //     }
            //     return selected;

            // } else if (combination.scheduler_name == "energy_scheduler") { // 已归档
            //     // 使用EnergyScheduler - 基于能量分配选择
            //     EnergyScheduler scheduler;
            //     auto selected = scheduler.execute(available_seeds, *global_context_);

            //     static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
            //     if (verbose) {
            //         std::cout << "[Scheduler] EnergyScheduler selected seed with energy "
            //                   << selected.energy << std::endl;
            //     }
            //     return selected;
            } else {
                std::cerr << "[WARNING] Unknown scheduler: " << combination.scheduler_name
                          << ", falling back to default" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Scheduler '" << combination.scheduler_name
                      << "' failed: " << e.what() << ", falling back to default" << std::endl;
        }
    }

    // 如果没有指定scheduler或调度器失败，使用默认的CorpusManager选择
    return selectSeed();
}

// 根据feedback_analyzer处理执行结果
void FuzzingEngine::processFeedbackWithAnalyzer(
    const ExecutionResult& result,
    const Seed& seed,
    const AlgorithmCombination& combination
) {
    // 如果指定了feedback_analyzer，使用对应的分析器
    if (!combination.feedback_analyzer.empty()) {
        try {
            if (combination.feedback_analyzer == "coverage_analyzer") {
                // 使用CoverageAnalyzer - 专注覆盖率分析
                // 这是默认行为，与processResultFast类似
                if (result.coverage.hasNewCoverage() && !result.coverage.new_edges.empty()) {
                    // 直接使用processResultFast处理
                    processResultFast(result, seed, combination);
                    return;
                }

            } else if (combination.feedback_analyzer == "crash_analyzer") {
                // 使用CrashAnalyzer - 专注崩溃分析
                if (result.status == ExecutionResult::Status::Crash) {
                    // 更详细的崩溃分析
                    analyzeCrash(result, seed, combination);
                }
                // 仍然处理覆盖率 - 使用processResultFast
                processResultFast(result, seed, combination);

            } else if (combination.feedback_analyzer == "enhanced_coverage_analyzer") {
                // 使用EnhancedCoverageAnalyzer - 更深入的覆盖率分析
                enhancedCoverageAnalysis(result, seed, combination);

            } else if (combination.feedback_analyzer == "lightweight_coverage_analyzer") {
                // 使用LightweightCoverageAnalyzer - 轻量级快速分析
                if (result.coverage.hasNewCoverage()) {
                    // 快速路径：只添加明显有价值的种子
                    if (result.coverage.new_edges.size() >= 5 ||
                        result.status == ExecutionResult::Status::Crash) {
                        processResultFast(result, seed, combination);
                    }
                }
            } else {
                // 未知的analyzer，使用默认处理
                processResultFast(result, seed, combination);
            }
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Feedback analyzer '" << combination.feedback_analyzer
                      << "' failed: " << e.what() << ", using default processing" << std::endl;
            // 回退到默认处理
            processResultFast(result, seed, combination);
        }
    } else {
        // 没有指定analyzer，使用默认处理
        processResultFast(result, seed, combination);
    }
}

// 崩溃详细分析
void FuzzingEngine::analyzeCrash(
    const ExecutionResult& result,
    const Seed& seed,
    const AlgorithmCombination& combination
) {
    static bool verbose = std::getenv("triofuzz_VERBOSE_CRASH") != nullptr;

    if (verbose) {
        std::cout << "\n[CrashAnalyzer] Detailed crash analysis:" << std::endl;
        std::cout << "  Combination: " << combination.toString() << std::endl;
        std::cout << "  Input size: " << result.input_data.size() << " bytes" << std::endl;
        std::cout << "  Parent seed size: " << seed.data.size() << " bytes" << std::endl;

        if (result.exit_code.has_value()) {
            std::cout << "  Exit code: " << result.exit_code.value() << std::endl;
        }

        std::cout << "  Crash info lines: " << result.crash_info.size() << std::endl;
        for (const auto& info : result.crash_info) {
            std::cout << "    " << info << std::endl;
        }
    }

    // 崩溃样本会由processResultFast自动保存，这里只做额外分析
}

// 增强覆盖率分析
void FuzzingEngine::enhancedCoverageAnalysis(
    const ExecutionResult& result,
    const Seed& seed,
    const AlgorithmCombination& combination
) {
    if (result.coverage.hasNewCoverage()) {
        static bool verbose = std::getenv("triofuzz_VERBOSE_COVERAGE") != nullptr;

        if (verbose) {
            std::cout << "[EnhancedCoverageAnalyzer] New coverage found:" << std::endl;
            std::cout << "  New edges: " << result.coverage.new_edges.size() << std::endl;
            std::cout << "  Rare edges: " << result.coverage.rare_edges.size() << std::endl;
            std::cout << "  Coverage gain: " << result.coverage.coverage_gain << std::endl;
            std::cout << "  Combination: " << combination.toString() << std::endl;
        }

        // 使用processResultFast处理并添加到语料库
        processResultFast(result, seed, combination);

        // 如果发现稀有边，记录到统计中（Thompson Sampling会通过reward看到这个效果）
        if (!result.coverage.rare_edges.empty()) {
            static bool verbose_rare = std::getenv("triofuzz_VERBOSE_RARE") != nullptr;
            if (verbose_rare) {
                std::cout << "[EnhancedCoverageAnalyzer] Found " << result.coverage.rare_edges.size()
                          << " rare edges!" << std::endl;
            }
        }
    }
}

} // namespace triofuzz
