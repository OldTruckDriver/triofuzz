#include "../../include/core/engine.hpp"
#include "../../include/utils/corpus_manager.hpp"
#include "../../include/algorithms/scheduling/rare_edge_scheduler.hpp"
// #include "../../include/algorithms/scheduling/fast_scheduler.hpp" // Archived
// #include "../../include/algorithms/scheduling/mopt_scheduler.hpp" // Archived
#include "../../include/algorithms/scheduling/scheduling_algorithms.hpp"
#include <iostream>

namespace triofuzz {

// Select seed based on the full pipeline combination (scheduler-aware)
Seed FuzzingEngine::selectSeedWithScheduler(const AlgorithmCombination& combination) {
    // If the combination specifies a scheduler, use it.
    if (!combination.scheduler_name.empty()) {
        // Collect all available seeds
        std::vector<Seed> available_seeds;
        if (corpus_manager_) {
            // Simplified approach: call getNextSeed() repeatedly to build a seed pool.
            // Limit to at most 100 seeds to avoid performance issues.
            for (size_t i = 0; i < 100; ++i) {
                auto seed_opt = corpus_manager_->getNextSeed();
                if (seed_opt.has_value()) {
                    available_seeds.push_back(seed_opt.value());
                } else {
                    break;  // No more seeds
                }
            }
        }

        // If no seeds are available, fall back to default selection.
        if (available_seeds.empty()) {
            return selectSeed();
        }

        // Select seed based on scheduler type
        try {
            if (combination.scheduler_name == "rare_edge_scheduler") {
                // Use RareEdgeScheduler - prioritize seeds that hit rare edges
                RareEdgeScheduler scheduler;
                auto selected = scheduler.execute(available_seeds, *global_context_);

                static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
                if (verbose) {
                    std::cout << "[Scheduler] RareEdgeScheduler selected seed with "
                              << selected.coverage.rare_edges.size() << " rare edges" << std::endl;
                }
                return selected;

            // Archived
            // } else if (combination.scheduler_name == "fast_scheduler") {
            //     // Use FastScheduler - prioritize favored seeds
            //     FastScheduler scheduler;
            //     auto selected = scheduler.execute(available_seeds, *global_context_);

            //     static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
            //     if (verbose) {
            //         std::cout << "[Scheduler] FastScheduler selected "
            //                   << (selected.favored ? "favored" : "unfavored") << " seed" << std::endl;
            //     }
            //     return selected;

            // } else if (combination.scheduler_name == "mopt_scheduler") { // Archived
            //     // Use MOptScheduler - multi-objective optimization selection
            //     MOptScheduler scheduler;
            //     auto selected = scheduler.execute(available_seeds, *global_context_);

            //     static bool verbose = std::getenv("triofuzz_VERBOSE_SCHEDULER") != nullptr;
            //     if (verbose) {
            //         std::cout << "[Scheduler] MOPTScheduler selected seed" << std::endl;
            //     }
            //     return selected;

            // } else if (combination.scheduler_name == "energy_scheduler") { // Archived
            //     // Use EnergyScheduler - energy-based selection
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

    // If no scheduler is specified or the scheduler fails, use the default CorpusManager selection.
    return selectSeed();
}

// Process execution results according to feedback_analyzer
void FuzzingEngine::processFeedbackWithAnalyzer(
    const ExecutionResult& result,
    const Seed& seed,
    const AlgorithmCombination& combination
) {
    // If feedback_analyzer is specified, use the corresponding analyzer.
    if (!combination.feedback_analyzer.empty()) {
        try {
            if (combination.feedback_analyzer == "coverage_analyzer") {
                // Use CoverageAnalyzer - focus on coverage analysis
                // This is the default behavior, similar to processResultFast.
                if (result.coverage.hasNewCoverage() && !result.coverage.new_edges.empty()) {
                    // Process directly with processResultFast
                    processResultFast(result, seed, combination);
                    return;
                }

            } else if (combination.feedback_analyzer == "crash_analyzer") {
                // Use CrashAnalyzer - focus on crash analysis
                if (result.status == ExecutionResult::Status::Crash) {
                    // More detailed crash analysis
                    analyzeCrash(result, seed, combination);
                }
                // Still handle coverage via processResultFast
                processResultFast(result, seed, combination);

            } else if (combination.feedback_analyzer == "enhanced_coverage_analyzer") {
                // Use EnhancedCoverageAnalyzer - deeper coverage analysis
                enhancedCoverageAnalysis(result, seed, combination);

            } else if (combination.feedback_analyzer == "lightweight_coverage_analyzer") {
                // Use LightweightCoverageAnalyzer - lightweight fast analysis
                if (result.coverage.hasNewCoverage()) {
                    // Fast path: only add clearly valuable seeds
                    if (result.coverage.new_edges.size() >= 5 ||
                        result.status == ExecutionResult::Status::Crash) {
                        processResultFast(result, seed, combination);
                    }
                }
            } else {
                // Unknown analyzer; use default processing
                processResultFast(result, seed, combination);
            }
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Feedback analyzer '" << combination.feedback_analyzer
                      << "' failed: " << e.what() << ", using default processing" << std::endl;
            // Fall back to default processing
            processResultFast(result, seed, combination);
        }
    } else {
        // No analyzer specified; use default processing
        processResultFast(result, seed, combination);
    }
}

// Detailed crash analysis
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

    // Crash samples are saved by processResultFast; only do extra analysis here.
}

// Enhanced coverage analysis
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

        // Process with processResultFast and add to the corpus
        processResultFast(result, seed, combination);

        // If rare edges are found, record them in stats (Thompson Sampling will observe it via reward).
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
