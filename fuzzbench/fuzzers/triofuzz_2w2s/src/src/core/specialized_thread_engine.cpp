#include "../../include/core/specialized_thread_engine.hpp"
#include "../../include/utils/corpus_manager.hpp"
#include "../../include/utils/coverage_tracker.hpp"
#include "../../include/utils/execution_tracer.hpp"
#include "../../include/core/optimized_thompson_sampling.hpp"
#include "../../include/utils/algorithm_config.hpp"
#include "../../include/utils/tiered_algorithm_scheduler.hpp"
#include <iostream>
#include <iomanip>
#include <random>
#include <chrono>
#include <set>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>

namespace triofuzz {

namespace {
thread_local std::vector<SynergyContribution> tls_synergy_updates;

// Thread-local seed buffer pool to avoid frequent global lock contention
thread_local std::vector<std::unique_ptr<std::vector<uint8_t>>> tls_seed_buffer_pool;
constexpr size_t TLS_SEED_POOL_LIMIT = 4;  // 4 buffers retained per thread

// Thread-local seed cache, batch-fetch seeds to reduce corpus lock contention
thread_local std::vector<Seed> tls_seed_cache;
constexpr size_t TLS_SEED_CACHE_SIZE = 512;  // Large cache to reduce corpus lock access
thread_local size_t tls_seed_cache_index = 0;

// Additional cache for energy-based selection (getNextSeed), used by TS schedules.
thread_local std::vector<Seed> tls_seed_cache_next;
constexpr size_t TLS_SEED_CACHE_NEXT_SIZE = 64;
thread_local size_t tls_seed_cache_next_index = 0;

// Trio-TS: AFL++ individual mutation operator sets (with/without splice).
const std::vector<std::string> kTsHavocOpsNoSplice = {
    "mut_flipbit",
    "mut_interesting8",
    "mut_interesting16",
    "mut_interesting16be",
    "mut_interesting32",
    "mut_interesting32be",
    "mut_arith8_sub",
    "mut_arith8_add",
    "mut_arith16_sub",
    "mut_arith16be_sub",
    "mut_arith16_add",
    "mut_arith16be_add",
    "mut_arith32_sub",
    "mut_arith32be_sub",
    "mut_arith32_add",
    "mut_arith32be_add",
    "mut_rand8",
    "mut_clone_copy",
    "mut_clone_fixed",
    "mut_overwrite_copy",
    "mut_overwrite_fixed",
    "mut_byteadd",
    "mut_bytesub",
    "mut_flip8",
    "mut_switch",
    "mut_del",
    "mut_shuffle",
    "mut_delone",
    "mut_insertone",
    "mut_asciinum",
    "mut_insertasciinum",
    "mut_extra_overwrite",
    "mut_extra_insert",
    "mut_auto_extra_overwrite",
    "mut_auto_extra_insert",
    // Structure/format aware operators (coverage-focused, but keep vuln triggers too).
    "structure_aware",
    "format_aware",
    "format_overflow",
};

const std::vector<std::string> kTsHavocOpsWithSplice = []() {
    std::vector<std::string> ops = kTsHavocOpsNoSplice;
    ops.push_back("mut_splice_overwrite");
    ops.push_back("mut_splice_insert");
    return ops;
}();

// TrioFuzz Unified: MOpt operator sets (with/without splice).
const std::vector<std::string> kTriofuzzMoptOpsNoSplice = {
    "mopt_flip1",
    "mopt_flip2",
    "mopt_flip4",
    "mopt_flip8",
    "mopt_flip16",
    "mopt_flip32",
    "mopt_arith8",
    "mopt_arith16",
    "mopt_arith32",
    "mopt_interest8",
    "mopt_interest16",
    "mopt_interest32",
    "mopt_rand8",
    "mopt_deletebyte",
    "mopt_clone75",
    "mopt_overwrite75",
    "mopt_overwrite_extra",
    "mopt_insert_extra",
    // Allow occasional structure-preserving edits even in MOpt mode.
    "structure_aware",
};

const std::vector<std::string> kTriofuzzMoptOpsWithSplice = []() {
    std::vector<std::string> ops = kTriofuzzMoptOpsNoSplice;
    ops.push_back("mopt_splice");
    return ops;
}();

// TrioFuzz Analysis: advanced analysis-guided mutation operator set
// These operators have longer execution times (1-50ms) but can discover complex constraints and magic bytes
const std::vector<std::string> kTriofuzzAnalysisOps = {
    "cmplog",            // Comparison instruction logging - discovers magic bytes via trace-cmp (~1-5ms)
    "redqueen",          // Input-to-state mapping - non-intrusive constraint solving (~15-50ms)
    "smart_dictionary",  // Smart dictionary - extracts tokens from input (~0.5-2ms)
    "runtime_dictionary", // Runtime dictionary - dynamically collects dictionary entries (~0.5-2ms)
    "format_overflow",   // Format-aware integer overflow - precise trigger for structured format vulnerabilities (~0.1-1ms)
    "format_aware",      // Structured format mutation - covers SQL/XML/JSON/WOFF etc. (~0.5-5ms)
};

static inline double sampleBeta(double alpha, double beta, std::mt19937& rng) {
    std::gamma_distribution<double> gamma_alpha(alpha, 1.0);
    std::gamma_distribution<double> gamma_beta(beta, 1.0);
    const double a = gamma_alpha(rng);
    const double b = gamma_beta(rng);
    return a / (a + b + 1e-10);
}

// Analysis operators are intentionally expensive (cmplog/redqueen/etc). If they
// run too frequently on worker threads, overall exec/s can collapse as the
// fuzzer transitions from fast reject paths to deeper (slower) parsing paths.
//
// Default behavior: keep analysis tasks in explorer threads, and avoid them in
// worker threads unless explicitly enabled.
static inline bool worker_analysis_enabled() {
    static int cached = -1;
    if (cached == -1) {
        const char* v = std::getenv("TRIOFUZZ_ENABLE_WORKER_ANALYSIS");
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached != 0;
}

}  // namespace

// Helper: compute geometric credit shares for a sequential chain
static inline std::vector<double> computeGeometricShares(size_t length, double decay = 0.7) {
    std::vector<double> shares(length, 0.0);
    if (length == 0) return shares;
    // Newest step (last) gets highest credit. Earlier steps decay by factor.
    double sum = 0.0;
    for (size_t i = 0; i < length; ++i) {
        size_t from_end = (length - 1 - i);
        double w = std::pow(decay, static_cast<double>(from_end));
        shares[i] = w;
        sum += w;
    }
    if (sum > 0.0) {
        for (auto& s : shares) s /= sum;
    }
    return shares;
}

SpecializedThreadEngine::SpecializedThreadEngine(
    FuzzingConfig config,
    CorpusManager* corpus_manager,
    CoverageTracker* coverage_tracker,
    ExecutionTracer* execution_tracer,
    InProcessExecutor* executor,
    ExecutionCallback execution_callback,
    CoverageCallback coverage_callback
) : config_(config),
    corpus_manager_(corpus_manager),
    coverage_tracker_(coverage_tracker),
    execution_tracer_(execution_tracer),
    executor_(executor),
    execution_callback_(execution_callback),
    coverage_callback_(coverage_callback),
    seed_pool_limit_(0)
{
    // Initialize Thompson Sampling
    thompson_sampling_ = std::make_unique<OptimizedThompsonSampling>();
    thompson_sampling_->setExplorationProbability(0.50);  // 50% exploration for better algorithm diversity
    thompson_sampling_->setStatsSyncFrequency(10000);
    thompson_sampling_->enableFastPath(false);  // Disable fast path, force Thompson Sampling

    // Thread allocation strategy:
    // User-configured thread_count is the total thread count (including Scheduler)
    // Allocation: 1 Scheduler + (n-1) Worker/Explorer
    size_t total_threads = config_.thread_count;

    // Optional explicit split overrides (specialized mode only).
    // Priority:
    //  1) If both worker+explorer are set: use exactly those counts and
    //     normalize total_threads to (1 + workers + explorers).
    //  2) If only one is set: derive the other from total_threads (and
    //     clamp to ensure at least 1 worker thread exists).
    const bool has_worker_override = config_.worker_threads_override.has_value();
    const bool has_explorer_override = config_.explorer_threads_override.has_value();
    if (has_worker_override || has_explorer_override) {
        size_t desired_workers = has_worker_override ? *config_.worker_threads_override : 0;
        size_t desired_explorers = has_explorer_override ? *config_.explorer_threads_override : 0;

        if (total_threads < 2) {
            std::cout << "[WARNING] -threads=" << total_threads
                      << " is too small for specialized architecture. Using 2 (1 Scheduler + 1 Worker)."
                      << std::endl;
            total_threads = 2;
        }

        if (has_worker_override && has_explorer_override) {
            // Use explicit split; total thread count becomes a derived value.
            if (desired_workers == 0) {
                std::cout << "[WARNING] --worker-threads=0 is invalid. Using 1 worker thread." << std::endl;
                desired_workers = 1;
            }
            const size_t normalized_total = 1 + desired_workers + desired_explorers;
            if (total_threads != normalized_total) {
                std::cout << "[WARNING] -threads=" << total_threads
                          << " does not match (1 + --worker-threads + --explorer-threads)="
                          << normalized_total << ". Using " << normalized_total << " threads." << std::endl;
            }
            total_threads = normalized_total;
        } else if (has_worker_override) {
            // Worker count fixed; explorers fill the remainder.
            if (desired_workers == 0) {
                std::cout << "[WARNING] --worker-threads=0 is invalid. Using 1 worker thread." << std::endl;
                desired_workers = 1;
            }
            if (total_threads <= 1 + desired_workers) {
                desired_explorers = 0;
                const size_t expanded_total = 1 + desired_workers + desired_explorers;
                if (total_threads != expanded_total) {
                    std::cout << "[WARNING] -threads=" << total_threads
                              << " is smaller than (1 + --worker-threads)=" << expanded_total
                              << ". Using " << expanded_total << " threads." << std::endl;
                }
                total_threads = expanded_total;
            } else {
                desired_explorers = total_threads - 1 - desired_workers;
            }
        } else {  // has_explorer_override only
            // Explorer count fixed; workers fill the remainder (must be >=1).
            if (total_threads <= 1 + desired_explorers) {
                desired_workers = 1;
                const size_t expanded_total = 1 + desired_workers + desired_explorers;
                std::cout << "[WARNING] -threads=" << total_threads
                          << " is smaller than (1 + --explorer-threads + 1 worker)=" << expanded_total
                          << ". Using " << expanded_total << " threads." << std::endl;
                total_threads = expanded_total;
            } else {
                desired_workers = total_threads - 1 - desired_explorers;
                if (desired_workers == 0) {
                    desired_workers = 1;
                    total_threads = 1 + desired_workers + desired_explorers;
                    std::cout << "[WARNING] Specialized architecture requires at least 1 worker. "
                              << "Using workers=1, explorers=" << desired_explorers
                              << " (threads=" << total_threads << ")." << std::endl;
                }
            }
        }

        num_workers_ = desired_workers;
        num_explorers_ = desired_explorers;
        config_.thread_count = total_threads;
        std::cout << "[SpecializedThreadEngine] Using explicit thread split: "
                  << "workers=" << num_workers_ << ", explorers=" << num_explorers_
                  << " (threads=" << config_.thread_count << ")" << std::endl;
    } else if (total_threads <= 1) {
        // Minimum 2 threads needed (1 Scheduler + 1 Worker)
        num_workers_ = 1;
        num_explorers_ = 0;
        std::cout << "[WARNING] Need at least 2 threads for specialized architecture. Using 1 Worker + 1 Scheduler." << std::endl;
    } else if (total_threads == 2) {
        // 2 threads: 1 Scheduler + 1 Worker, no Explorer
        num_workers_ = 1;
        num_explorers_ = 0;
    } else if (total_threads == 3) {
        // 3 threads: 1 Scheduler + 1 Worker + 1 Explorer
        num_workers_ = 1;
        num_explorers_ = 1;
    } else if (total_threads == 4) {
        // 4 threads: 1 Scheduler + 2 Workers + 1 Explorer
        num_workers_ = 2;
        num_explorers_ = 1;
    } else if (total_threads <= 8) {
        // 5-8 threads: 1 Scheduler + (n-3) Workers + 2 Explorers
        num_workers_ = total_threads - 3;
        num_explorers_ = 2;
    } else {
        // 9+ threads: use more conservative Worker ratio to avoid Scheduler starvation
        // For large thread counts, Worker exploit mode significantly reduces Scheduler demand
        // Strategy: Worker count = total threads * 0.5, remainder allocated to Explorers
        // Keep 1 Scheduler (exploit mode reduces need for more)
        num_workers_ = std::max<size_t>(3, total_threads / 2);
        num_explorers_ = total_threads - num_workers_ - 1;  // 1 Scheduler
    }
    seed_pool_limit_ = std::max<size_t>(8, num_workers_ + num_explorers_ + 4);

    std::cout << "[SpecializedThreadEngine] Initialized with:" << std::endl;
    const char* scheduler_mode =
        config_.use_ts_scheduler ? "TS (Thompson Sampling configs)" :
        (config_.use_mopt_learning ? "MOpt (PSO)" : "Thompson Sampling");
    std::cout << "  - 1 Scheduler thread (" << scheduler_mode << ")" << std::endl;
    std::cout << "  - " << num_workers_ << " Worker threads (fast execution)" << std::endl;
    std::cout << "  - " << num_explorers_ << " Explorer threads (new combinations)" << std::endl;
    std::cout << "  - Micro-batch (workers/explorers): "
              << config_.micro_batch_workers << "/" << config_.micro_batch_explorers << std::endl;
    std::cout << "  - Worker queue target depth: " << config_.worker_queue_target_depth << std::endl;

    if (config_.use_mopt_learning) {
        std::cout << "[SpecializedThreadEngine] MOpt mode: operator selection is driven by PSO learning" << std::endl;
    } else {
        // Initialize complete pipeline combinations (Scheduler + Mutation + Feedback)
        // No predefined combinations; discovered through Thompson Sampling
        std::cout << "[SpecializedThreadEngine] No predefined combinations" << std::endl;
        std::cout << "[SpecializedThreadEngine] Complete pipeline combinations (Scheduler + Mutation + Feedback)" << std::endl;
        std::cout << "[SpecializedThreadEngine] will be discovered through Thompson Sampling" << std::endl;
    }

    // triofuzz-Mini: Disable tiered scheduler for simplified comparison
    // This ensures we use basic Thompson Sampling without tiered algorithm scheduling
    use_tiered_scheduler_ = false;
    tiered_scheduler_.reset();  // Explicitly disable
    std::cout << "[SpecializedThreadEngine-Mini] Tiered Algorithm Scheduler: DISABLED" << std::endl;
    if (config_.use_ts_scheduler) {
        std::cout << "[SpecializedThreadEngine-Mini] Using Trio-TS (TS over configs + AFL++ schedules)" << std::endl;
    } else if (config_.use_mopt_learning) {
        std::cout << "[SpecializedThreadEngine-Mini] Using MOpt (PSO) operator learning" << std::endl;
    } else {
        std::cout << "[SpecializedThreadEngine-Mini] Using simplified Thompson Sampling (no geometric credit, no synergy)" << std::endl;
    }

    // Use centralized config to get available algorithms
    if (!config_.enabled_algorithms.empty()) {
        // Filter to enabled mutation algorithms (excluding schedulers and feedback)
        for (const auto& algo : config_.enabled_algorithms) {
            if (AlgorithmConfig::isEnabled(algo) && !AlgorithmConfig::isArchived(algo)) {
                available_algorithms_.push_back(algo);
            }
        }
    }

    if (available_algorithms_.empty()) {
        // Use centralized config default list (filtered for archived items)
        available_algorithms_ = AlgorithmConfig::ENABLED_MUTATIONS;
    }
    // Uniformly filter archived algorithms to avoid slow algorithms dominating
    {
        std::vector<std::string> filtered;
        filtered.reserve(available_algorithms_.size());
        for (const auto& a : available_algorithms_) {
            if (!AlgorithmConfig::isArchived(a)) filtered.push_back(a);
        }
        available_algorithms_.swap(filtered);
    }
    std::cout << "[SpecializedThreadEngine] Available mutation algorithms for exploration: " << available_algorithms_.size() << std::endl;
    {
        std::lock_guard<std::mutex> lock(seed_pool_mutex_);
        seed_buffer_pool_.reserve(seed_pool_limit_);
    }

    // Initialize last new coverage time to now, avoiding false stagnation detection
    {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        last_new_cov_ns_.store(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
    }

    worker_queues_.clear();
    worker_queues_.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_queues_.push_back(std::make_unique<WorkerQueue>());
    }

    // Initialize per-thread result queues (workers + explorers) - double buffered
    size_t total_exec_threads = num_workers_ + num_explorers_;
    result_queues_.clear();
    result_queues_.reserve(total_exec_threads);
    for (size_t i = 0; i < total_exec_threads; ++i) {
        result_queues_.push_back(std::make_unique<DoubleBufferedResultQueue>());
    }

    // If MOpt learning mode is enabled, initialize PSO learner and operator mapping
    if (config_.use_mopt_learning) {
        mopt_operator_names_ = available_algorithms_;
        mopt_operator_index_.clear();
        mopt_operator_index_.reserve(mopt_operator_names_.size());
        for (size_t i = 0; i < mopt_operator_names_.size(); ++i) {
            mopt_operator_index_[mopt_operator_names_[i]] = i;
        }

        MOptOnlineLearner::PSOParams p;
        p.update_period = config_.mopt_update_period;
        mopt_learner_ = std::make_unique<MOptOnlineLearner>(mopt_operator_names_.size(), p);

        std::cout << "[SpecializedThreadEngine] MOpt (PSO) learning mode initialized with "
                  << mopt_operator_names_.size() << " operators" << std::endl;
    }
}

SpecializedThreadEngine::~SpecializedThreadEngine() {
    stop();
}

void SpecializedThreadEngine::start() {
    if (running_.load()) {
        std::cout << "[SpecializedThreadEngine] Already running" << std::endl;
        return;
    }

    // TrioFuzz Unified: Three-layer learning architecture
	    if (config_.use_triofuzz_unified) {
	        triofuzz::TrioFuzzUnifiedLearner::Config learner_cfg;
	        learner_cfg.enable_ts = config_.enable_ts;
	        learner_cfg.enable_ecofuzz = config_.enable_ecofuzz;
	        learner_cfg.ts_decay = config_.ts_decay;
	        learner_cfg.ts_update_period = config_.ts_update_period;
	        learner_cfg.havoc_stack_pow2 = config_.ts_havoc_stack_pow2;
        learner_cfg.enable_mopt_pso = config_.enable_mopt_pso;
        learner_cfg.mopt_update_period = config_.mopt_update_period;
        learner_cfg.enable_markov = config_.enable_muofuzz_markov;
        learner_cfg.havoc_ops_nosplice = kTsHavocOpsNoSplice.size();
        learner_cfg.havoc_ops_splice = kTsHavocOpsWithSplice.size();
        learner_cfg.mopt_ops_nosplice = kTriofuzzMoptOpsNoSplice.size();
        learner_cfg.mopt_ops_splice = kTriofuzzMoptOpsWithSplice.size();

        // Hybrid period configuration for non-stationary adaptation
        learner_cfg.ts_time_period_sec = config_.ts_time_period_sec;
        learner_cfg.mopt_time_period_sec = config_.mopt_time_period_sec;
        learner_cfg.markov_time_period_sec = config_.markov_time_period_sec;
        learner_cfg.ts_min_samples = config_.ts_min_samples;
        learner_cfg.mopt_min_samples = config_.mopt_min_samples;
        learner_cfg.markov_min_samples = config_.markov_min_samples;

        triofuzz_learner_ = std::make_unique<triofuzz::TrioFuzzUnifiedLearner>(learner_cfg);

        next_worker_to_fill_ = 0;
        running_.store(true);

        std::cout << "[SpecializedThreadEngine] Starting threads in TrioFuzz Unified mode..." << std::endl;
        std::cout << "[TrioFuzz] Workers: " << num_workers_ << " | Explorers: " << num_explorers_ << std::endl;

        scheduler_thread_ = std::make_unique<std::thread>([this]() { schedulerThreadTrioFuzz(); });
        for (size_t i = 0; i < num_workers_; ++i) {
            worker_threads_.push_back(std::make_unique<std::thread>([this, i]() { workerThreadTrioFuzz(i); }));
        }
        for (size_t i = 0; i < num_explorers_; ++i) {
            explorer_threads_.push_back(std::make_unique<std::thread>([this, i]() { explorerThreadTrioFuzz(i); }));
        }

        std::cout << "[SpecializedThreadEngine] All threads started (TrioFuzz Unified)" << std::endl;
        return;
    }

    // Trio-TS: outer-loop config TS + AFL++ schedule emulation + optional inner MOpt
    if (config_.use_ts_scheduler) {
        // (Re)initialize TS arms and learners for this run.
        ts_arms_.clear();
        ts_stats_.clear();
        ts_key_to_index_.clear();
        ts_key_to_index_.reserve(16);

        auto scheduleToString = [](TsPowerSchedule s) -> const char* {
            switch (s) {
                case TsPowerSchedule::Explore: return "explore";
                case TsPowerSchedule::Fast: return "fast";
                case TsPowerSchedule::Coe: return "coe";
            }
            return "explore";
        };
        auto mutatorToString = [](TsMutator m) -> const char* {
            switch (m) {
                case TsMutator::Havoc: return "havoc";
                case TsMutator::Mopt: return "mopt";
                case TsMutator::Analysis: return "analysis";
            }
            return "havoc";
        };
        auto makeKey = [&](TsPowerSchedule s, TsMutator m, bool splice) -> std::string {
            std::string key = std::string(scheduleToString(s)) + "_" + mutatorToString(m);
            if (splice) key += "_splice";
            return key;
        };
        auto addArm = [&](TsPowerSchedule s, TsMutator m, bool splice) {
            TsConfigArm arm;
            arm.schedule = s;
            arm.mutator = m;
            arm.splice = splice;
            arm.key = makeKey(s, m, splice);
            const size_t idx = ts_arms_.size();
            ts_key_to_index_[arm.key] = idx;
            ts_arms_.push_back(std::move(arm));
            ts_stats_.push_back(TsArmStats{});
        };

        for (auto sched : {TsPowerSchedule::Explore, TsPowerSchedule::Fast, TsPowerSchedule::Coe}) {
            for (auto mut : {TsMutator::Havoc, TsMutator::Mopt}) {
                addArm(sched, mut, false);
                addArm(sched, mut, true);
            }
        }

        // Analysis arms: advanced analysis algorithms (cmplog/redqueen/smart_dictionary/runtime_dictionary)
        // Only uses Explore schedule since analysis algorithms are inherently explorative
        // No splice variants needed; analysis algorithms have their own internal logic
        addArm(TsPowerSchedule::Explore, TsMutator::Analysis, false);

        // Inner MOpt operator spaces (with/without splice as part of config).
        ts_mopt_ops_nosplice_ = {
            "mopt_flip1", "mopt_flip2", "mopt_flip4", "mopt_flip8", "mopt_flip16", "mopt_flip32",
            "mopt_arith8", "mopt_arith16", "mopt_arith32",
            "mopt_interest8", "mopt_interest16", "mopt_interest32",
            "mopt_rand8",
            "mopt_deletebyte", "mopt_clone75", "mopt_overwrite75",
            "mopt_overwrite_extra", "mopt_insert_extra",
            "structure_aware",
        };
        ts_mopt_ops_splice_ = ts_mopt_ops_nosplice_;
        ts_mopt_ops_splice_.push_back("mopt_splice");

        ts_mopt_index_nosplice_.clear();
        ts_mopt_index_nosplice_.reserve(ts_mopt_ops_nosplice_.size());
        for (size_t i = 0; i < ts_mopt_ops_nosplice_.size(); ++i) {
            ts_mopt_index_nosplice_[ts_mopt_ops_nosplice_[i]] = i;
        }
        ts_mopt_index_splice_.clear();
        ts_mopt_index_splice_.reserve(ts_mopt_ops_splice_.size());
        for (size_t i = 0; i < ts_mopt_ops_splice_.size(); ++i) {
            ts_mopt_index_splice_[ts_mopt_ops_splice_[i]] = i;
        }

        MOptOnlineLearner::PSOParams p;
        p.update_period = std::max<size_t>(1, config_.mopt_update_period);
        ts_mopt_learner_nosplice_ = std::make_unique<MOptOnlineLearner>(ts_mopt_ops_nosplice_.size(), p);
        ts_mopt_learner_splice_ = std::make_unique<MOptOnlineLearner>(ts_mopt_ops_splice_.size(), p);

        next_worker_to_fill_ = 0;
        running_.store(true);

        std::cout << "[SpecializedThreadEngine] Starting threads in Trio-TS mode..." << std::endl;
        std::cout << "[Trio-TS] Configs: " << ts_arms_.size()
                  << " | TS update period: " << config_.ts_update_period
                  << " | TS decay: " << config_.ts_decay
                  << " | Havoc stack pow2: " << config_.ts_havoc_stack_pow2
                  << " | MOpt update period: " << config_.mopt_update_period
                  << std::endl;

        scheduler_thread_ = std::make_unique<std::thread>([this]() { schedulerThreadTS(); });
        for (size_t i = 0; i < num_workers_; ++i) {
            worker_threads_.push_back(std::make_unique<std::thread>([this, i]() { workerThreadTS(i); }));
        }
        for (size_t i = 0; i < num_explorers_; ++i) {
            explorer_threads_.push_back(std::make_unique<std::thread>([this, i]() { explorerThreadTS(i); }));
        }

        std::cout << "[SpecializedThreadEngine] All threads started (Trio-TS)" << std::endl;
        return;
    }

    // MOpt (PSO) learning mode: replaces Thompson Sampling for combination selection
    if (config_.use_mopt_learning) {
        if (!mopt_learner_ || mopt_operator_names_.empty()) {
            // Fallback: constructor did not initialize (should not occur in practice)
            mopt_operator_names_ = available_algorithms_;
            mopt_operator_index_.clear();
            mopt_operator_index_.reserve(mopt_operator_names_.size());
            for (size_t i = 0; i < mopt_operator_names_.size(); ++i) {
                mopt_operator_index_[mopt_operator_names_[i]] = i;
            }
            MOptOnlineLearner::PSOParams p;
            p.update_period = config_.mopt_update_period;
            mopt_learner_ = std::make_unique<MOptOnlineLearner>(mopt_operator_names_.size(), p);
        }

        next_worker_to_fill_ = 0;
        running_.store(true);

        std::cout << "[SpecializedThreadEngine] Starting threads in MOpt (PSO) mode..." << std::endl;

        scheduler_thread_ = std::make_unique<std::thread>([this]() { schedulerThreadMOpt(); });
        for (size_t i = 0; i < num_workers_; ++i) {
            worker_threads_.push_back(std::make_unique<std::thread>([this, i]() { workerThreadMOpt(i); }));
        }
        for (size_t i = 0; i < num_explorers_; ++i) {
            explorer_threads_.push_back(std::make_unique<std::thread>([this, i]() { explorerThreadMOpt(i); }));
        }

        std::cout << "[SpecializedThreadEngine] All threads started (MOpt)" << std::endl;
        return;
    }

    // Initialize Thompson Sampling candidate combinations
    // Generate a set of initial candidates for Thompson Sampling
    std::vector<AlgorithmCombination> initial_candidates;
    std::mt19937 init_rng(std::random_device{}());

    // Generate 50 random combinations as initial candidates
    for (size_t i = 0; i < 50; ++i) {
        AlgorithmCombination combo;

        // Use sequential mode only (parallel has synchronization overhead)
        std::vector<std::string> modes = {"sequential"};
        std::uniform_int_distribution<size_t> mode_dist(0, modes.size() - 1);
        combo.combination_mode = modes[mode_dist(init_rng)];

        // Random 1-3 algorithms
        std::uniform_int_distribution<size_t> num_algos_dist(1, 2);
        size_t num_algos = num_algos_dist(init_rng);

        std::vector<std::string> shuffled = available_algorithms_;
        std::shuffle(shuffled.begin(), shuffled.end(), init_rng);
        for (size_t j = 0; j < std::min(num_algos, shuffled.size()); ++j) {
            combo.algorithm_names.push_back(shuffled[j]);
        }

        // Use centralized config for scheduler and feedback (currently empty; all archived)
        combo.scheduler_name = AlgorithmConfig::ENABLED_SCHEDULERS.empty() ? "" : AlgorithmConfig::ENABLED_SCHEDULERS[0];
        combo.feedback_analyzer = AlgorithmConfig::ENABLED_FEEDBACKS.empty() ? "" : AlgorithmConfig::ENABLED_FEEDBACKS[0];

        initial_candidates.push_back(combo);
    }

    // Ensure we seed a few strong candidates that exercise byte_weighted_havoc early
    auto ensure_algo = [&](const std::string& name) {
        return std::find(available_algorithms_.begin(), available_algorithms_.end(), name) != available_algorithms_.end();
    };
    if (ensure_algo("byte_weighted_havoc")) {
        AlgorithmCombination c1; c1.combination_mode = "sequential"; c1.algorithm_names = {"byte_weighted_havoc"};
        AlgorithmCombination c2; c2.combination_mode = "sequential"; c2.algorithm_names = {"byte_weighted_havoc", "havoc"};
        AlgorithmCombination c3; c3.combination_mode = "sequential"; c3.algorithm_names = {"arithmetic", "byte_weighted_havoc"};
        initial_candidates.push_back(c1);
        initial_candidates.push_back(c2);
        initial_candidates.push_back(c3);
    }

    thompson_sampling_->setCandidateCombinations(initial_candidates);
    std::cout << "[SpecializedThreadEngine] Initialized Thompson Sampling with "
              << initial_candidates.size() << " candidate combinations" << std::endl;

    next_worker_to_fill_ = 0;

    running_.store(true);

    std::cout << "[SpecializedThreadEngine] Starting threads..." << std::endl;

    // Start scheduler thread
    scheduler_thread_ = std::make_unique<std::thread>([this]() {
        schedulerThread();
    });

    // Start worker threads
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_threads_.push_back(std::make_unique<std::thread>([this, i]() {
            workerThread(i);
        }));
    }

    // Start explorer threads
    for (size_t i = 0; i < num_explorers_; ++i) {
        explorer_threads_.push_back(std::make_unique<std::thread>([this, i]() {
            explorerThread(i);
        }));
    }

    std::cout << "[SpecializedThreadEngine] All threads started" << std::endl;
}

void SpecializedThreadEngine::stop() {
    if (!running_.load()) {
        return;
    }

    std::cout << "[SpecializedThreadEngine] Stopping threads..." << std::endl;
    running_.store(false);

    // Wake up all waiting threads
    for (auto& queue : worker_queues_) {
        if (queue) {
            queue->cv.notify_all();
        }
    }
    result_cv_.notify_all();
    scheduler_cv_.notify_all();

    // Wait for scheduler thread
    if (scheduler_thread_ && scheduler_thread_->joinable()) {
        scheduler_thread_->join();
    }
    scheduler_thread_.reset();

    // Wait for worker threads
    for (auto& thread : worker_threads_) {
        if (thread && thread->joinable()) {
            thread->join();
        }
    }

    // Wait for explorer threads
    for (auto& thread : explorer_threads_) {
        if (thread && thread->joinable()) {
            thread->join();
        }
    }
    explorer_threads_.clear();
    worker_threads_.clear();

    // Clear task and result queues; ensure seed buffers are recycled while pool still exists
    for (size_t i = 0; i < worker_queues_.size(); ++i) {
        auto& queue = worker_queues_[i];
        if (queue) {
            std::lock_guard<std::mutex> lock(queue->mutex);
            queue->tasks.clear();
        }
    }
    // Clear all per-thread result queues (double buffered)
    for (auto& rq : result_queues_) {
        if (rq) {
            std::lock_guard<std::mutex> lock(rq->mutex);
            rq->active_buffer.clear();
            rq->processing_buffer.clear();
        }
    }
    {
        std::lock_guard<std::mutex> lock(seed_pool_mutex_);
        seed_buffer_pool_.clear();
    }
    next_worker_to_fill_ = 0;

    std::cout << "[SpecializedThreadEngine] All threads stopped" << std::endl;
    std::cout << "[SpecializedThreadEngine] Statistics:" << std::endl;
    std::cout << "  Total executions: " << total_executions_.load() << std::endl;
    std::cout << "  Scheduler decisions: " << scheduler_decisions_.load() << std::endl;
    std::cout << "  Worker executions: " << worker_executions_.load() << std::endl;
    std::cout << "  Explorer executions: " << explorer_executions_.load() << std::endl;
}

// Scheduler thread - handles Thompson Sampling decisions and task generation
void SpecializedThreadEngine::schedulerThread() {
    std::cout << "[Scheduler] Thread started" << std::endl;

    auto last_stats_time = std::chrono::steady_clock::now();
    size_t last_total_executions = 0;

    while (running_.load()) {
        // 1. Process result queue - update Thompson Sampling stats and combination performance
        static std::atomic<size_t> total_new_cov{0};
        static std::atomic<size_t> total_results{0};

        // [PERF-CRITICAL] Batch-process results to reduce lock contention and function call overhead
        // Using double-buffered queue to atomically swap and get all results
        std::vector<TaskResult> batch_buffer;
        batch_buffer.reserve(2000);  // Pre-allocate to avoid realloc

        // Poll all per-thread result queues (double-buffered)
        for (auto& rq : result_queues_) {
            if (!rq) continue;

            auto results = rq->swapAndGet();  // Atomic swap, very fast
            batch_buffer.insert(batch_buffer.end(), results.begin(), results.end());
        }

        // Batch-process collected results (lock-free)
        // triofuzz-Mini: Simplified reward calculation
        // - Binary reward: 1.0 for new coverage, 0.0 otherwise (matches AFL++ TS)
        // - No time normalization
        // - No stagnation boost/decay
        // - No geometric credit assignment
        // - No synergy tracking
        if (!batch_buffer.empty()) {
            // Batch-update combination performance (fewer lock acquisitions)
            std::unique_lock<std::mutex> perf_lock(performance_mutex_);

            for (auto& result : batch_buffer) {
                // Track new coverage and crashes
                if (result.found_new_coverage) {
                    total_new_cov.fetch_add(1);
                    // Record time of most recent new coverage
                    auto n = std::chrono::steady_clock::now().time_since_epoch();
                    last_new_cov_ns_.store(std::chrono::duration_cast<std::chrono::nanoseconds>(n).count());
                }
                total_results.fetch_add(1);

                // triofuzz-Mini: Simple binary reward (like AFL++ TS)
                // 1.0 = found new coverage (success)
                // 0.0 = no new coverage (failure)
                double binary_reward = result.found_new_coverage ? 1.0 : 0.0;

                // Update combination performance tracking (lock already held)
                size_t combo_hash = result.combination.hash();
                auto& perf = combination_performance_[combo_hash];
                if (perf.executions == 0) {
                    perf.combination = result.combination;
                }
                perf.executions++;
                perf.total_reward += binary_reward;
                perf.avg_reward = perf.total_reward / perf.executions;
                if (result.found_new_coverage) perf.new_coverage_count++;
                if (result.crashed) perf.crash_count++;

                // Accumulate execution time (retained for statistics)
                perf.total_execution_time_ms += result.execution_time_ms;
                perf.avg_execution_time_ms = perf.total_execution_time_ms / perf.executions;

                // Update Thompson Sampling with binary reward
                thompson_sampling_->updatePerformance(result.combination, binary_reward);

                // triofuzz-Mini: Tiered scheduler and geometric credit DISABLED
                // (see constructor for explicit disable)
            }

            perf_lock.unlock();
            batch_buffer.clear();
        }
        // End processing results

        // Periodically print new coverage stats (once per 10000 results)
        size_t current_results = total_results.load();
        if (current_results > 0 && current_results % 10000 == 0 &&
            current_results != last_coverage_print_.load()) {
            last_coverage_print_.store(current_results);

            double new_cov_rate = (double)total_new_cov.load() / current_results * 100.0;
            size_t total_edges = coverage_callback_ ? coverage_callback_() : 0;

            std::cout << "[Scheduler-Coverage] Total results: " << current_results
                      << " | Execs with new cov: " << total_new_cov.load()
                      << " (" << std::fixed << std::setprecision(2) << new_cov_rate << "%)"
                      << " | Total edges: " << total_edges << std::endl;
        }

        // [PERF-CRITICAL] Periodically update top combination list (every 50000 decisions or 30s)
        // Minimize lock hold time - compute top-k while holding lock, don't copy entire map
        static std::atomic<size_t> last_top_update{0};
        static auto last_top_update_time = std::chrono::steady_clock::now();
        size_t current_decisions = scheduler_decisions_.load();
        auto now_top = std::chrono::steady_clock::now();
        auto elapsed_top = std::chrono::duration_cast<std::chrono::seconds>(now_top - last_top_update_time);

        if (current_decisions > 0 &&
            (current_decisions % 50000 == 0 || elapsed_top.count() >= 30) &&
            current_decisions != last_top_update.load()) {
            last_top_update.store(current_decisions);
            last_top_update_time = now_top;

            // STEP 1+2: Compute top-k directly while lock is held (avoid overhead of copying all combinations)
            constexpr size_t TOP_K = 3;
            std::vector<std::pair<size_t, CombinationPerformance>> top_k_snapshot;
            size_t total_combos = 0;
            size_t qualified_count = 0;

            {
                std::unique_lock<std::mutex> perf_lock(performance_mutex_);
                total_combos = combination_performance_.size();

                // Use min-heap to find top-k (single pass, O(N log K), K=3 is small)
                // Sorted by time-aware avg_reward
                auto comp = [](const std::pair<size_t, double>& a,
                              const std::pair<size_t, double>& b) {
                    return a.second > b.second;  // Min-heap
                };
                std::priority_queue<std::pair<size_t, double>,
                                  std::vector<std::pair<size_t, double>>,
                                  decltype(comp)> min_heap(comp);

                for (const auto& kv : combination_performance_) {
                    if (kv.second.executions >= 10) {  // Minimum threshold: 10 executions
                        qualified_count++;

                        // Use time-aware avg_reward (already computed in Thompson Sampling)
                        min_heap.push({kv.first, kv.second.avg_reward});
                        if (min_heap.size() > TOP_K) {
                            min_heap.pop();
                        }
                    }
                }

                // Extract top-k hashes, then copy only these K combos (not all combinations)
                std::vector<size_t> top_hashes;
                while (!min_heap.empty()) {
                    top_hashes.push_back(min_heap.top().first);
                    min_heap.pop();
                }

                // Only copy top-k combos (3 vs thousands)
                for (size_t hash : top_hashes) {
                    if (combination_performance_.count(hash)) {
                        top_k_snapshot.push_back({hash, combination_performance_[hash]});
                    }
                }
            }  // Lock released; total hold time: O(N) map traversal + copy 3 objects

            std::cout << "[Scheduler] Updating top combinations. Total unique combos: "
                      << total_combos
                      << " | Combos with >=10 execs: " << qualified_count << std::endl;

            // STEP 3: Prepare new top combination list (lock-free)
            std::vector<AlgorithmCombination> new_top_combinations;
            std::vector<double> avg_rewards;       // Time-aware avg reward
            std::vector<double> avg_exec_times;    // Average execution time
            std::vector<size_t> exec_counts;       // Execution count

            if (!top_k_snapshot.empty()) {
                // Sort by avg_reward (time-aware) descending
                std::sort(top_k_snapshot.begin(), top_k_snapshot.end(),
                         [](const auto& a, const auto& b) {
                             return a.second.avg_reward > b.second.avg_reward;
                         });

                for (const auto& kv : top_k_snapshot) {
                    new_top_combinations.push_back(kv.second.combination);
                    avg_rewards.push_back(kv.second.avg_reward);
                    avg_exec_times.push_back(kv.second.avg_execution_time_ms);
                    exec_counts.push_back(kv.second.executions);
                }
            }

            // STEP 4: Atomically replace top combinations (very short lock, <1ms)
            {
                std::unique_lock<std::mutex> top_lock(top_combinations_mutex_);
                top_combinations_ = std::move(new_top_combinations);
            }  // Lock released immediately

            // STEP 5: Print statistics (lock-free) - show time-aware reward and execution time
            if (!avg_rewards.empty()) {
                std::cout << "[Scheduler-Thompson] Updated top-" << avg_rewards.size() << " combinations:" << std::endl;
                for (size_t i = 0; i < avg_rewards.size(); ++i) {
                    std::cout << "  [" << (i+1) << "] reward/s=" << std::fixed << std::setprecision(1) << avg_rewards[i]
                              << " | avg_time=" << std::setprecision(2) << avg_exec_times[i] << "ms"
                              << " | execs=" << exec_counts[i] << std::endl;
                }
            } else {
                std::cout << "[Scheduler-Thompson] No combinations meet criteria (need >=10 executions)" << std::endl;
            }
        }

        // Print statistics periodically (every 5 seconds)
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time);
        if (elapsed.count() >= 5) {
            size_t current_total = total_executions_.load();
            size_t exec_in_period = current_total - last_total_executions;
            double exec_per_sec = exec_in_period / (elapsed.count() > 0 ? elapsed.count() : 1);

            // Get current top combinations
            std::string top_combos_str;
            {
                std::unique_lock<std::mutex> lock(top_combinations_mutex_);
                for (size_t i = 0; i < top_combinations_.size() && i < 3; ++i) {
                    if (i > 0) top_combos_str += ", ";
                    top_combos_str += top_combinations_[i].toString();
                }
            }

            // Get current covered edge count (for adaptive exploration rate and tier probability), lightweight
            size_t covered_edges = coverage_callback_ ? coverage_callback_() : 0;

            // Adaptive exploration rate: increase on stagnation, decrease on gains
            {
                static double explore_p = 0.50; // Same as constructor default
                static size_t last_cov = 0;
                if (covered_edges > last_cov) {
                    // Coverage gain detected: more exploitation
                    explore_p = std::max(0.15, explore_p - 0.05);
                } else {
                    // No gain: moderately increase exploration
                    explore_p = std::min(0.50, explore_p + 0.05);
                }
                last_cov = covered_edges;
                if (thompson_sampling_) {
                    thompson_sampling_->setExplorationProbability(explore_p);
                }
            }

            // On coverage stagnation, boost Tier2/Tier3 base probability to promote exploration
            if (use_tiered_scheduler_ && tiered_scheduler_) {
                static size_t last_cov_tier = 0;
                bool stagnating = (covered_edges == last_cov_tier);
                if (stagnating) {
                    // More aggressive exploration：Tier1=0.57, Tier2=0.35, Tier3=0.08
                    tiered_scheduler_->setTierBaseProbabilities(0.57, 0.35, 0.08);
                } else {
                    // Restore defaults：Tier1=0.73, Tier2=0.25, Tier3=0.02
                    tiered_scheduler_->setTierBaseProbabilities(0.73, 0.25, 0.02);
                }
                last_cov_tier = covered_edges;
            }

            // Decide whether to show coverage based on config (to avoid performance overhead)
            if (config_.show_coverage_in_stats) {
                // Get current instrumented point coverage count (already read above)
                
                static size_t prev_mcts = 0, prev_fanout = 0, prev_baton = 0, prev_two_stage = 0;
                size_t mcts_total = mcts_constructed_.load();
                size_t fanout_total = fanout_triggers_.load();
                size_t baton_total = baton_enqueued_.load();
                size_t two_stage_total = two_stage_triggers_.load();
                long long dmcts = static_cast<long long>(mcts_total) - static_cast<long long>(prev_mcts);
                long long dfan = static_cast<long long>(fanout_total) - static_cast<long long>(prev_fanout);
                long long dbat = static_cast<long long>(baton_total) - static_cast<long long>(prev_baton);
                long long dtwo = static_cast<long long>(two_stage_total) - static_cast<long long>(prev_two_stage);
                prev_mcts = mcts_total; prev_fanout = fanout_total; prev_baton = baton_total; prev_two_stage = two_stage_total;

                std::cout << "[Stats] Executions: " << current_total
                          << " | Speed: " << static_cast<size_t>(exec_per_sec) << " exec/s"
                          << " | Coverage: " << covered_edges << " edges"
                          << " | Workers: " << worker_executions_.load()
                          << " | Explorers: " << explorer_executions_.load()
                          << "\n        Top combinations: " << top_combos_str
                          << "\n        Modes: mcts=" << mcts_total << " (" << (dmcts>=0?"+":"") << dmcts << ")"
                          << ", fanout=" << fanout_total << " (" << (dfan>=0?"+":"") << dfan << ")"
                          << ", baton=" << baton_total << " (" << (dbat>=0?"+":"") << dbat << ")"
                          << ", two_stage=" << two_stage_total << " (" << (dtwo>=0?"+":"") << dtwo << ")"
                          << std::endl;
            } else {
                // Don't show coverage, reduce overhead
                static size_t prev_mcts = 0, prev_fanout = 0, prev_baton = 0, prev_two_stage = 0;
                size_t mcts_total = mcts_constructed_.load();
                size_t fanout_total = fanout_triggers_.load();
                size_t baton_total = baton_enqueued_.load();
                size_t two_stage_total = two_stage_triggers_.load();
                long long dmcts = static_cast<long long>(mcts_total) - static_cast<long long>(prev_mcts);
                long long dfan = static_cast<long long>(fanout_total) - static_cast<long long>(prev_fanout);
                long long dbat = static_cast<long long>(baton_total) - static_cast<long long>(prev_baton);
                long long dtwo = static_cast<long long>(two_stage_total) - static_cast<long long>(prev_two_stage);
                prev_mcts = mcts_total; prev_fanout = fanout_total; prev_baton = baton_total; prev_two_stage = two_stage_total;

                std::cout << "[Stats] Executions: " << current_total
                          << " | Speed: " << static_cast<size_t>(exec_per_sec) << " exec/s"
                          << " | Workers: " << worker_executions_.load()
                          << " | Explorers: " << explorer_executions_.load()
                          << "\n        Top combinations: " << top_combos_str
                          << "\n        Modes: mcts=" << mcts_total << " (" << (dmcts>=0?"+":"") << dmcts << ")"
                          << ", fanout=" << fanout_total << " (" << (dfan>=0?"+":"") << dfan << ")"
                          << ", baton=" << baton_total << " (" << (dbat>=0?"+":"") << dbat << ")"
                          << ", two_stage=" << two_stage_total << " (" << (dtwo>=0?"+":"") << dtwo << ")"
                          << std::endl;

                // Print tiered scheduler stats every 10000 executions
                if (use_tiered_scheduler_ && tiered_scheduler_ && current_total % 10000 == 0 &&
                    tiered_scheduler_->getTotalExecutions() > 0) {
                    std::cout << tiered_scheduler_->getStatisticsReport() << std::endl;
                }
            }

            last_stats_time = now;
            last_total_executions = current_total;
        }

        // 2. Generate new tasks - prepare tasks for worker threads
        size_t target_queue_depth = std::max<size_t>(1, config_.worker_queue_target_depth);
        bool produced_tasks = false;

        if (num_workers_ > 0) {
            for (size_t i = 0; i < num_workers_ && running_.load(); ++i) {
                size_t worker_index = next_worker_to_fill_;
                next_worker_to_fill_ = (next_worker_to_fill_ + 1) % num_workers_;

                if (getQueueSize(worker_index) >= target_queue_depth) {
                    continue;
                }

                AlgorithmCombination combo = selectTopCombination();
                auto seed = getSeedFromCorpus();
                if (!seed) {
                    continue;
                }

                FuzzTask task;
                task.combination = combo;
                task.seed = std::move(seed);
                task.task_id = task_id_counter_.fetch_add(1);

                enqueueTask(worker_index, std::move(task));
                scheduler_decisions_.fetch_add(1);
                produced_tasks = true;
            }
        }

        if (!running_.load()) {
            break;
        }

        if (!produced_tasks) {
            std::unique_lock<std::mutex> wait_lock(scheduler_mutex_);
            scheduler_cv_.wait_for(wait_lock, std::chrono::milliseconds(2));
        }
    }

    std::cout << "[Scheduler] Thread stopped" << std::endl;
}

// Worker thread - fast execution of top combinations (hybrid mode: exploit with opportunistic check)
void SpecializedThreadEngine::workerThread(size_t id) {
    std::cout << "[Worker-" << id << "] Thread started (Exploit Mode)" << std::endl;

    size_t local_executions = 0;  // Execution count for this thread
    size_t exploit_switches = 0;  // Early switch count
    size_t early_stops = 0;       // Early stop count

    // Get configuration parameters
    size_t EXPLOIT_COUNT = config_.worker_exploit_count;  // Non-const to support dynamic adjustment
    const size_t CHECK_INTERVAL = config_.worker_exploit_check_interval;
    const bool ENABLE_EARLY_STOP = config_.enable_exploit_early_stop;
    const size_t EARLY_STOP_WINDOW = config_.exploit_early_stop_window;
    const double EARLY_STOP_THRESHOLD = config_.exploit_early_stop_threshold;

    std::cout << "[Worker-" << id << "] Configuration: exploit_count=" << EXPLOIT_COUNT
              << ", check_interval=" << CHECK_INTERVAL
              << ", early_stop=" << (ENABLE_EARLY_STOP ? "enabled" : "disabled") << std::endl;

    // Worker never-wait mode
    // 1. Get initial task (only blocks once at startup)
    FuzzTask current_task;
    if (!waitAndPopTask(id, current_task)) {
        std::cout << "[Worker-" << id << "] Failed to get initial task, exiting" << std::endl;
        return;
    }

    std::cout << "[Worker-" << id << "] Got initial task, entering continuous execution mode" << std::endl;

    // Task switch statistics
    size_t task_switches = 0;
    size_t continuous_loops = 0;

    while (running_.load()) {
        // 2. Continuously execute current combo (never proactively wait for new tasks)
        // Adaptive exploit count: dynamically compute optimal exploit count for current combination
        EXPLOIT_COUNT = calculateAdaptiveExploitCount(current_task.combination);

        std::vector<TaskResult> batch_results;
        batch_results.reserve(EXPLOIT_COUNT);

        double last_window_avg_reward = 0.0;  // For early stop detection
        bool switched_to_new_task = false;

        // [Optional] Performance diagnostics: record exploit loop start time (disabled by default)
        #ifdef ENABLE_EXPLOIT_LOOP_STATS
        auto exploit_loop_start = std::chrono::steady_clock::now();
        #endif
        size_t seed_acquisition_failures = 0;

        continuous_loops++;

        for (size_t i = 0; i < EXPLOIT_COUNT && running_.load(); ++i) {
            // 2.1 Execute current combo
            // [Optional] Performance diagnostics: seed acquisition timing (disabled by default)
            #ifdef ENABLE_SEED_TIMING_STATS
            auto seed_acquire_start = std::chrono::steady_clock::now();
            #endif

            auto seed = getSeedFromCorpus();

            #ifdef ENABLE_SEED_TIMING_STATS
            auto seed_acquire_end = std::chrono::steady_clock::now();
            auto seed_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
                seed_acquire_end - seed_acquire_start).count();
            #endif

            if (!seed) {
                // Corpus is empty, wait briefly and retry
                if (seed_acquisition_failures % 100 == 0) {
                    std::cout << "[WARNING-Worker-" << id << "] Corpus empty! failures="
                              << seed_acquisition_failures << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                seed_acquisition_failures++;
                continue;  // Continue loop, do not exit
            }

            FuzzTask exploit_task;
            exploit_task.combination = current_task.combination;  // Use current combo
            exploit_task.seed = std::move(seed);
            exploit_task.task_id = task_id_counter_.fetch_add(1);

            #ifdef ENABLE_EXEC_TIMING_STATS
            auto exec_start = std::chrono::steady_clock::now();
            #endif

            TaskResult result;
            executeTask(exploit_task, result, id);

            #ifdef ENABLE_EXEC_TIMING_STATS
            auto exec_end = std::chrono::steady_clock::now();
            auto exec_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
                exec_end - exec_start).count();
            #endif

            batch_results.push_back(result);
            local_executions++;

            // [Optional] Performance diagnostics: print stats every 1000 executions (disabled by default)
            #if defined(ENABLE_SEED_TIMING_STATS) || defined(ENABLE_EXEC_TIMING_STATS)
            static thread_local size_t perf_counter = 0;
            static thread_local uint64_t total_seed_time = 0;
            static thread_local uint64_t total_exec_time = 0;
            perf_counter++;
            #ifdef ENABLE_SEED_TIMING_STATS
            total_seed_time += seed_time_us;
            #endif
            #ifdef ENABLE_EXEC_TIMING_STATS
            total_exec_time += exec_time_us;
            #endif

            if (perf_counter % 1000 == 0) {
                double avg_seed_ms = total_seed_time / (double)perf_counter / 1000.0;
                double avg_exec_ms = total_exec_time / (double)perf_counter / 1000.0;
                std::cout << "[DEBUG-Worker-" << id << "] Timing:"
                          << " seed=" << std::fixed << std::setprecision(3) << avg_seed_ms << "ms"
                          << ", exec=" << std::setprecision(1) << avg_exec_ms << "ms"
                          << ", total=" << (avg_seed_ms + avg_exec_ms) << "ms/iter"
                          << std::endl;
            }
            #endif

            // 2.2 Opportunistic check: try to get a better task every CHECK_INTERVAL executions (non-blocking)
            if (CHECK_INTERVAL > 0 && i > 0 && i % CHECK_INTERVAL == 0) {
                FuzzTask new_task;
                if (tryStealNewerTask(id, new_task)) {
                    // Found a better combo! Switch immediately
                    task_switches++;

                    // Submit current batch results
                    if (!batch_results.empty()) {
                        submitResultsBatch(batch_results);
                        worker_executions_.fetch_add(batch_results.size());
                        total_executions_.fetch_add(batch_results.size());
                        local_executions += batch_results.size();
                    }

                    // Switch to new combo, reset state
                    current_task = std::move(new_task);
                    batch_results.clear();
                    batch_results.reserve(EXPLOIT_COUNT);
                    i = -1;  // Reset counter
                    switched_to_new_task = true;
                    last_window_avg_reward = 0.0;
                    continue;
                }
            }

            // 2.3 Early stop check: based on diminishing returns
            if (ENABLE_EARLY_STOP && i >= EARLY_STOP_WINDOW &&
                i % EARLY_STOP_WINDOW == 0) {

                double current_avg = calculateAvgReward(batch_results, EARLY_STOP_WINDOW);

                // If reward drops below threshold, terminate exploit early
                if (i > EARLY_STOP_WINDOW && last_window_avg_reward > 0.0) {
                    if (current_avg < last_window_avg_reward * EARLY_STOP_THRESHOLD) {
                        early_stops++;
                        break;  // Exit exploit loop early
                    }
                }

                last_window_avg_reward = current_avg;
            }
        }

        // 3. Submit final batch results
        if (!batch_results.empty()) {
            submitResultsBatch(batch_results);
            worker_executions_.fetch_add(batch_results.size());
            total_executions_.fetch_add(batch_results.size());
            local_executions += batch_results.size();
        }

        // [Optional] Performance diagnostics: print exploit loop stats (disabled by default)
        #ifdef ENABLE_EXPLOIT_LOOP_STATS
        auto exploit_loop_end = std::chrono::steady_clock::now();
        auto exploit_loop_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            exploit_loop_end - exploit_loop_start).count();

        static thread_local size_t total_exploit_loops = 0;
        static thread_local uint64_t total_exploit_time_ms = 0;
        static thread_local size_t total_batch_size = 0;
        total_exploit_loops++;
        total_exploit_time_ms += exploit_loop_duration_ms;
        total_batch_size += batch_results.size();

        if (total_exploit_loops % 100 == 0) {
            double avg_exploit_time_ms = total_exploit_time_ms / (double)total_exploit_loops;
            double avg_batch_size = total_batch_size / (double)total_exploit_loops;
            std::cout << "[DEBUG-Worker-" << id << "] Continuous mode stats:"
                      << " loops=" << continuous_loops
                      << ", switches=" << task_switches
                      << ", avg_batch=" << std::setprecision(1) << avg_batch_size
                      << ", execs=" << local_executions << std::endl;
        }
        #endif
    }

    flushThreadLocalSynergyCache();

    std::cout << "[Worker-" << id << "] Thread stopped (Continuous Mode)" << std::endl;
    std::cout << "[Worker-" << id << "] Statistics:" << std::endl;
    std::cout << "  - Total executions: " << local_executions << std::endl;
    std::cout << "  - Continuous loops: " << continuous_loops << std::endl;
    std::cout << "  - Task switches: " << task_switches << std::endl;
}

// Explorer thread - tests new algorithm combinations
void SpecializedThreadEngine::explorerThread(size_t id) {
    std::cout << "[Explorer-" << id << "] Thread started" << std::endl;

    size_t local_executions = 0;  // Execution count for this thread

    while (running_.load()) {
        // 1. Select exploration combination (Thompson Sampling)
        AlgorithmCombination combo = selectExplorationCombination();

        size_t micro = std::max<size_t>(1, config_.micro_batch_explorers);
        if (micro <= 1) {
            // Single execution path
            auto seed = getSeedFromCorpus();
            if (!seed) {
                std::this_thread::sleep_for(std::chrono::microseconds(200));
                continue;
            }
            FuzzTask task;
            task.combination = combo;
            task.seed = std::move(seed);
            task.task_id = task_id_counter_.fetch_add(1);

            TaskResult result;
            executeTask(task, result, 1000 + id);
            submitResult(result);
            explorer_executions_.fetch_add(1);
            total_executions_.fetch_add(1);
            local_executions++;
        } else {
            // Micro-batch: execute the same combo multiple times consecutively
            std::vector<TaskResult> batch_results;
            batch_results.reserve(micro);

            for (size_t i = 0; i < micro && running_.load(); ++i) {
                auto seed = getSeedFromCorpus();
                if (!seed) {
                    break;
                }
                FuzzTask task;
                task.combination = combo;
                task.seed = std::move(seed);
                task.task_id = task_id_counter_.fetch_add(1);

                TaskResult result;
                executeTask(task, result, 1000 + id);
                batch_results.push_back(result);
            }

            if (!batch_results.empty()) {
                submitResultsBatch(batch_results);
                explorer_executions_.fetch_add(batch_results.size());
                total_executions_.fetch_add(batch_results.size());
                local_executions += batch_results.size();
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(200));
            }
        }

        // Explorer thread runs slightly slower, giving scheduler thread more time to process results
        std::this_thread::sleep_for(std::chrono::microseconds(500));
    }

    flushThreadLocalSynergyCache();

    std::cout << "[Explorer-" << id << "] Thread stopped, executions: "
              << local_executions << std::endl;
}

// Task queue management
void SpecializedThreadEngine::enqueueTask(size_t worker_index, FuzzTask&& task) {
    if (worker_index >= worker_queues_.size()) {
        return;
    }
    auto& queue = worker_queues_[worker_index];
    {
        std::lock_guard<std::mutex> lock(queue->mutex);
        queue->tasks.push_back(std::move(task));
    }
    queue->cv.notify_one();
}

bool SpecializedThreadEngine::waitAndPopTask(size_t worker_id, FuzzTask& task) {
    if (worker_id >= worker_queues_.size()) {
        return false;
    }

    auto& queue = worker_queues_[worker_id];

    while (running_.load()) {
        std::unique_lock<std::mutex> lock(queue->mutex);
        queue->cv.wait_for(lock, std::chrono::milliseconds(5), [&]() {
            return !queue->tasks.empty() || !running_.load();
        });

        if (!queue->tasks.empty()) {
            task = std::move(queue->tasks.front());
            queue->tasks.pop_front();
            bool should_notify = queue->tasks.empty();
            lock.unlock();
            if (should_notify) {
                scheduler_cv_.notify_one();
            }
            return true;
        }

        if (!running_.load()) {
            return false;
        }

        lock.unlock();

        if (stealTask(worker_id, task)) {
            return true;
        }
    }

    return false;
}

bool SpecializedThreadEngine::stealTask(size_t thief_id, FuzzTask& task) {
    if (worker_queues_.empty()) {
        return false;
    }

    for (size_t i = 1; i < worker_queues_.size(); ++i) {
        size_t victim = (thief_id + i) % worker_queues_.size();
        auto& queue = worker_queues_[victim];
        std::unique_lock<std::mutex> lock(queue->mutex, std::try_to_lock);
        if (!lock || queue->tasks.empty()) {
            continue;
        }

        task = std::move(queue->tasks.back());
        queue->tasks.pop_back();
        return true;
    }

    return false;
}

void SpecializedThreadEngine::submitResult(const TaskResult& result) {
    // Use thread-local queue index to reduce lock contention
    static thread_local size_t tls_queue_index = std::numeric_limits<size_t>::max();

    if (tls_queue_index >= result_queues_.size()) {
        // First access: assign a queue index (using hash of thread id)
        std::hash<std::thread::id> hasher;
        tls_queue_index = hasher(std::this_thread::get_id()) % result_queues_.size();
    }

    auto& rq = result_queues_[tls_queue_index];
    rq->submit(result);  // Use double-buffered queue submit
    result_cv_.notify_one();
}

void SpecializedThreadEngine::submitResultsBatch(const std::vector<TaskResult>& results) {
    if (results.empty()) return;

    // Use thread-local queue index to reduce lock contention
    static thread_local size_t tls_queue_index = std::numeric_limits<size_t>::max();

    if (tls_queue_index >= result_queues_.size()) {
        // First access: assign a queue index (using hash of thread id)
        std::hash<std::thread::id> hasher;
        tls_queue_index = hasher(std::this_thread::get_id()) % result_queues_.size();
    }

    auto& rq = result_queues_[tls_queue_index];
    rq->submitBatch(results);  // Use double-buffered queue batch submit
    result_cv_.notify_one();
}

size_t SpecializedThreadEngine::getQueueSize(size_t worker_index) {
    if (worker_index >= worker_queues_.size()) {
        return 0;
    }
    auto& queue = worker_queues_[worker_index];
    std::lock_guard<std::mutex> lock(queue->mutex);
    return queue->tasks.size();
}

// Select top combination (used by worker threads)
AlgorithmCombination SpecializedThreadEngine::selectTopCombination() {
    std::unique_lock<std::mutex> lock(top_combinations_mutex_);

    if (top_combinations_.empty()) {
        // Before top combinations are established, use Thompson Sampling to select
        lock.unlock();  // Release lock
        return thompson_sampling_->selectNext();
    }

    // Randomly select from top combinations
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, top_combinations_.size() - 1);
    return top_combinations_[dist(rng)];
}

// Select exploration combination (used by explorer threads)
AlgorithmCombination SpecializedThreadEngine::selectExplorationCombination() {
    // Use tiered scheduler to select algorithms (if enabled)
    if (use_tiered_scheduler_ && tiered_scheduler_ && tiered_scheduler_->hasAlgorithms()) {
        // Use tiered scheduler to select 1-2 algorithms for combination
        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> count_dist(1, 2); // 1-2 algorithms
        size_t num_algorithms = count_dist(rng);

        auto selected_algorithms = tiered_scheduler_->selectAlgorithms(num_algorithms, true);

        AlgorithmCombination combo;
        combo.algorithm_names = selected_algorithms;

        // N-gram motif sampling: configurable probability to construct from high-scoring motif seeds
        if (config_.enable_ngram_motifs) {
            std::uniform_real_distribution<double> p01(0.0, 1.0);
            if (p01(rng) < config_.motif_sample_prob && !algorithm_motifs_.empty()) {
                std::shared_lock<std::shared_mutex> lock(synergy_mutex_);
                // Randomly sample up to 16 motifs, pick highest scoring
                std::vector<std::pair<std::string, double>> candidates;
                size_t sample = 0;
                for (const auto& kv : algorithm_motifs_) {
                    if (kv.second.support >= config_.motif_min_support) {
                        candidates.emplace_back(kv.first, kv.second.score);
                        if (++sample >= 16) break;
                    }
                }
                if (!candidates.empty()) {
                    std::sort(candidates.begin(), candidates.end(), [](auto& a, auto& b){return a.second > b.second;});
                    // Take top-1 motif to construct combination
                    auto key = candidates.front().first;
                    std::vector<std::string> parts;
                    size_t pos=0, start=0;
                    while ((pos = key.find('+', start)) != std::string::npos) {
                        parts.emplace_back(key.substr(start, pos-start));
                        start = pos+1;
                    }
                    parts.emplace_back(key.substr(start));
                    if (!parts.empty()) {
                        combo.algorithm_names.clear();
                        // Limit to at most 2 to avoid overly long chains
                        for (size_t i=0; i<parts.size() && i<2; ++i) {
                            const auto& p = parts[i];
                            if (AlgorithmConfig::isEnabled(p) && !AlgorithmConfig::isArchived(p)) combo.algorithm_names.push_back(p);
                        }
                    }
                }
            }
        }
        // Explorer: prefer MCTS (more structured search), then fanout; otherwise two_stage/sequential
        std::uniform_real_distribution<double> p01(0.0, 1.0);
        std::string mode = "sequential";
        // Simple stagnation detection: no edge growth over a time window indicates stagnation
        auto now = std::chrono::steady_clock::now();
        static size_t last_edges = 0;
        static auto last_edge_change = now;
        bool stagnating = false;
        if (coverage_callback_) {
            size_t edges = coverage_callback_();
            if (edges > last_edges) {
                last_edges = edges;
                last_edge_change = now;
            }
            stagnating = std::chrono::duration_cast<std::chrono::seconds>(now - last_edge_change).count() >= static_cast<long long>(config_.stagnation_seconds);
        } else {
            // No coverage callback: use last new coverage time as stagnation fallback
            long long last_ns = last_new_cov_ns_.load();
            if (last_ns > 0) {
                auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                stagnating = (now_ns - last_ns) >= (static_cast<long long>(config_.stagnation_seconds) * 1000000000LL);
            }
        }

        if (config_.enable_burst && stagnating && p01(rng) < config_.burst_exec_pct) {
            mode = "sequential"; // burst is algorithm selection, not a mode
            // Use T3 candidates for coverage algorithms (if available)
            std::vector<std::string> t3 = {"smart_dictionary", "afl_plus_plus"};
            std::vector<std::string> t3_enabled;
            for (const auto& a : t3) if (AlgorithmConfig::isEnabled(a) && !AlgorithmConfig::isArchived(a)) t3_enabled.push_back(a);
            if (!t3_enabled.empty()) {
                std::uniform_int_distribution<size_t> d(0, t3_enabled.size()-1);
                combo.algorithm_names = { t3_enabled[d(rng)] };
            }
        } else {
            if (stagnating) {
                // Dynamically allocate probability between MCTS and fanout: longer stagnation increases MCTS probability
                double elapsed_sec = 0.0;
                if (coverage_callback_) {
                    elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(now - last_edge_change).count();
                } else {
                    long long last_ns = last_new_cov_ns_.load();
                    if (last_ns > 0) {
                        auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                        elapsed_sec = std::max(0.0, (now_ns - static_cast<double>(last_ns)) / 1e9);
                    }
                }
                double T = static_cast<double>(config_.stagnation_seconds);
                double factor = 0.0; // 0: just stagnated; 1: long stagnation (~5x window)
                if (T > 0.0) {
                    double capped = std::min(1.0, std::max(0.0, (elapsed_sec / (5.0 * T))));
                    factor = capped;
                }
                double p_mcts = config_.mcts_min_probability + (config_.mcts_max_probability - config_.mcts_min_probability) * factor;
                if (p_mcts < 0.0) p_mcts = 0.0; if (p_mcts > 1.0) p_mcts = 1.0;
                double p_fanout = (1.0 - p_mcts) * config_.fanout_probability;

                double rpick = p01(rng);
                if (config_.enable_mcts_step && (!config_.mcts_on_stagnation_only || stagnating) && rpick < p_mcts) {
                    mode = "mcts";
                } else if (config_.enable_fanout && rpick < (p_mcts + p_fanout)) {
                    mode = "fanout";
                } else if (config_.enable_two_stage) {
                    mode = "two_stage";
                } else {
                    mode = "sequential";
                }
            } else {
                // Not stagnating: prefer two_stage if enabled
                if (config_.enable_two_stage) {
                    mode = "two_stage";
                } else {
                    mode = "sequential";
                }
            }
        }
        combo.combination_mode = mode;
        combo.scheduler_name = "";
        combo.feedback_analyzer = "";

        // Fanout requires at least 2 algorithms; pad with an additional different algorithm if needed
        if (combo.combination_mode == "fanout" && combo.algorithm_names.size() < 2) {
            try {
                auto extra = tiered_scheduler_->selectAlgorithms(1, true);
                if (!extra.empty()) {
                    // Avoid duplicates
                    if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), extra[0]) == combo.algorithm_names.end()) {
                        combo.algorithm_names.push_back(extra[0]);
                    }
                }
            } catch (...) {
                // Ignore exception, keep existing
            }
        }

        // MCTS: construct two-step combination (lightweight UCB/synergy heuristic, limited to 2 steps)
        if (combo.combination_mode == "mcts") {
            // step1 is already in selected_algorithms
            if (combo.algorithm_names.empty()) {
                auto base = tiered_scheduler_->selectAlgorithms(1, true);
                if (!base.empty()) combo.algorithm_names.push_back(base[0]);
            }
            // step2 selection: combine pair-synergy with historical avg_reward of existing combinations (UCB approximation)
            // [DEADLOCK-FIX] Acquire locks separately to avoid deadlock from holding two locks simultaneously
            std::string best_next;
            double best_score = -1e9;

            // Copy needed synergy data (brief lock hold)
            std::unordered_map<std::string, double> synergy_scores;
            {
                std::shared_lock<std::shared_mutex> syn_lock(synergy_mutex_);
                for (const auto& cand : available_algorithms_) {
                    std::string key = combo.algorithm_names.empty() ? "" : (combo.algorithm_names[0] + "+" + cand);
                    auto it = algorithm_synergies_.find(key);
                    if (it != algorithm_synergies_.end() && it->second.co_occurrences >= 5) {
                        synergy_scores[cand] = it->second.synergy_score;
                    }
                }
            }
            // syn_lock released

            // Copy needed performance data (brief lock hold)
            std::unordered_map<size_t, double> perf_scores;
            {
                std::unique_lock<std::mutex> perf_lock(performance_mutex_);
                for (const auto& cand : available_algorithms_) {
                    AlgorithmCombination tmp;
                    tmp.combination_mode = "sequential";
                    tmp.algorithm_names = combo.algorithm_names.empty() ?
                        std::vector<std::string>{cand} :
                        std::vector<std::string>{combo.algorithm_names[0], cand};
                    size_t h = tmp.hash();
                    if (combination_performance_.count(h)) {
                        perf_scores[h] = combination_performance_[h].avg_reward;
                    }
                }
            }
            // perf_lock released

            // Compute best candidate without holding locks
            for (const auto& cand : available_algorithms_) {
                if (std::find(combo.algorithm_names.begin(), combo.algorithm_names.end(), cand) != combo.algorithm_names.end()) continue;
                double syn = 0.5;
                auto syn_it = synergy_scores.find(cand);
                if (syn_it != synergy_scores.end()) syn = syn_it->second;
                AlgorithmCombination tmp;
                tmp.combination_mode = "sequential";
                tmp.algorithm_names = combo.algorithm_names.empty() ?
                    std::vector<std::string>{cand} :
                    std::vector<std::string>{combo.algorithm_names[0], cand};
                size_t h = tmp.hash();
                double avg = 0.5;
                auto perf_it = perf_scores.find(h);
                if (perf_it != perf_scores.end()) avg = perf_it->second;
                double score = 0.6*syn + 0.4*avg;
                if (score > best_score) { best_score = score; best_next = cand; }
            }

            if (!best_next.empty()) combo.algorithm_names.push_back(best_next);
            // Force limit to 2 steps to avoid overly long chains
            if (combo.algorithm_names.size() > 2) {
                combo.algorithm_names.resize(2);
            }
            // Track MCTS construction count in tiered scheduler path (previously only counted in fallback path)
            mcts_constructed_.fetch_add(1);
        }
        return combo;
    }

    // triofuzz-Mini: Simplified exploration - pure random algorithm selection
    // No synergy learning, no MCTS, no fanout, no two-stage
    // This matches AFL++ TS's simple random exploration strategy
    static thread_local std::mt19937 rng(std::random_device{}());

    if (available_algorithms_.empty()) {
        // If no algorithms available, return havoc
        AlgorithmCombination default_combo;
        default_combo.algorithm_names = {"havoc"};
        default_combo.combination_mode = "sequential";
        return default_combo;
    }

    AlgorithmCombination combo;
    combo.combination_mode = "sequential";  // Always sequential for simplicity

    // Randomly select 1-2 algorithms (simple distribution like AFL++ TS)
    std::discrete_distribution<int> algo_count_dist({60, 40}); // 60% single, 40% two
    size_t num_algorithms = static_cast<size_t>(algo_count_dist(rng) + 1);
    num_algorithms = std::min(num_algorithms, available_algorithms_.size());

    // Pure random selection without synergy learning
    std::vector<std::string> shuffled_algos = available_algorithms_;
    std::shuffle(shuffled_algos.begin(), shuffled_algos.end(), rng);

    for (size_t i = 0; i < num_algorithms; ++i) {
        combo.algorithm_names.push_back(shuffled_algos[i]);
    }

    // No scheduler/feedback selection - keep it simple
    combo.scheduler_name = "";
    combo.feedback_analyzer = "";

    return combo;
}

// Get seed from corpus
std::shared_ptr<std::vector<uint8_t>> SpecializedThreadEngine::getSeedFromCorpus() {
    auto buffer = acquireSeedBuffer();
    if (!buffer) {
        return nullptr;
    }

    if (!corpus_manager_) {
        buffer->clear();
        return buffer;
    }

    // Use thread-local cache for batch seed acquisition, greatly reducing corpus lock contention
    if (tls_seed_cache_index >= tls_seed_cache.size()) {
        // Cache exhausted, batch-fetch new seeds
        tls_seed_cache.clear();
        tls_seed_cache.reserve(TLS_SEED_CACHE_SIZE);

        // Fetch multiple seeds at once
        for (size_t i = 0; i < TLS_SEED_CACHE_SIZE; ++i) {
            auto seed = corpus_manager_->getRandomSeed();
            if (seed) {
                tls_seed_cache.push_back(std::move(*seed));
            } else {
                break;  // Corpus is empty
            }
        }

        tls_seed_cache_index = 0;
    }

    if (tls_seed_cache_index < tls_seed_cache.size()) {
        // Get seed from cache (lock-free)
        const auto& seed = tls_seed_cache[tls_seed_cache_index++];
        buffer->assign(seed.data.begin(), seed.data.end());
    } else {
        buffer->clear();
    }

    return buffer;
}

std::shared_ptr<std::vector<uint8_t>> SpecializedThreadEngine::acquireSeedBuffer() {
    std::unique_ptr<std::vector<uint8_t>> buffer;

    // First try to acquire from thread-local pool (lock-free)
    if (!tls_seed_buffer_pool.empty()) {
        buffer = std::move(tls_seed_buffer_pool.back());
        tls_seed_buffer_pool.pop_back();
    } else {
        // Thread-local pool is empty, try to acquire from global pool
        std::lock_guard<std::mutex> lock(seed_pool_mutex_);
        if (!seed_buffer_pool_.empty()) {
            buffer = std::move(seed_buffer_pool_.back());
            seed_buffer_pool_.pop_back();
        }
    }

    if (!buffer) {
        buffer = std::make_unique<std::vector<uint8_t>>();
    }

    buffer->clear();
    return std::shared_ptr<std::vector<uint8_t>>(
        buffer.release(),
        [this](std::vector<uint8_t>* ptr) { recycleSeedBuffer(ptr); }
    );
}

void SpecializedThreadEngine::recycleSeedBuffer(std::vector<uint8_t>* buffer) {
    if (!buffer) {
        return;
    }

    std::unique_ptr<std::vector<uint8_t>> holder(buffer);
    holder->clear();

    // First try to recycle to thread-local pool (lock-free)
    if (tls_seed_buffer_pool.size() < TLS_SEED_POOL_LIMIT) {
        tls_seed_buffer_pool.push_back(std::move(holder));
        return;
    }

    // Thread-local pool is full, recycle to global pool
    std::lock_guard<std::mutex> lock(seed_pool_mutex_);
    if (seed_buffer_pool_.size() < seed_pool_limit_) {
        seed_buffer_pool_.push_back(std::move(holder));
    }
    // Exceeds limit: holder is automatically freed
}

// Execute task
void SpecializedThreadEngine::executeTask(const FuzzTask& task, TaskResult& result, size_t thread_id) {
    // ===== [PERF] Performance diagnostics: start timing =====
#if ENABLE_DETAILED_PERF
    auto task_start = std::chrono::high_resolution_clock::now();
#endif

    result.task_id = task.task_id;
    result.combination = task.combination;
    result.found_new_coverage = false;
    result.crashed = false;
    result.reward = 0.0;
    result.execution_time_ms = 0.0;  // Initialize execution time
    result.seed_hash = task.seed_hash;
    result.ecofuzz_cycle_id = task.ecofuzz_cycle_id;

    // ===== [PERF] Timing point: callback start =====
#if ENABLE_DETAILED_PERF
    auto callback_start = std::chrono::high_resolution_clock::now();
    auto callback_end = callback_start;  // Initialize to avoid undefined
#endif

    // Use execution callback provided by FuzzingEngine to execute the task
    // The callback handles: mutation + execution + coverage detection

    // [Optional] Performance diagnostics: measure callback time (includes mutation + execution) (disabled by default)
    #ifdef ENABLE_CALLBACK_TIMING_STATS
    auto callback_timing_start = std::chrono::steady_clock::now();
    #endif

    // If two_stage is enabled and the combination is declared as two_stage, execute two-stage cascade
    if (execution_callback_ && config_.enable_two_stage &&
        task.combination.combination_mode == "two_stage") {

        auto pick_polish_algorithms = [&](size_t count) {
            // Candidates: fine-tuning/polishing algorithms
            static const std::vector<std::string> kPolish = {
                "magic_byte", "arithmetic", "value_approximation"
            };
            std::vector<std::string> pool;
            for (const auto& a : kPolish) {
                if (AlgorithmConfig::isEnabled(a) && !AlgorithmConfig::isArchived(a)) {
                    pool.push_back(a);
                }
            }
            if (pool.empty()) {
                return std::vector<std::string>{"magic_byte"};
            }
            static thread_local std::mt19937 rng(std::random_device{}());
            std::shuffle(pool.begin(), pool.end(), rng);
            if (count > pool.size()) count = pool.size();
            return std::vector<std::string>(pool.begin(), pool.begin() + count);
        };

        // Local execution function reusing existing logic: execute + reward calculation. Synergy recording controlled by parameter.
        auto execute_one = [&](const std::vector<uint8_t>& seed_data,
                               const AlgorithmCombination& combo,
                               TaskResult& out,
                               bool record_synergy) {
            out.task_id = task.task_id;
            out.combination = combo;
            out.found_new_coverage = false;
            out.crashed = false;
            out.reward = 0.0;
            out.execution_time_ms = 0.0;
            out.seed_hash = task.seed_hash;
            out.ecofuzz_cycle_id = task.ecofuzz_cycle_id;

            #ifdef ENABLE_CALLBACK_TIMING_STATS
            auto callback_timing_start = std::chrono::steady_clock::now();
            #endif

            ExecutionResult exec_result = execution_callback_(seed_data, combo);

            #ifdef ENABLE_CALLBACK_TIMING_STATS
            auto callback_timing_end = std::chrono::steady_clock::now();
            auto callback_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
                callback_timing_end - callback_timing_start).count();

            static thread_local size_t callback_counter = 0;
            static thread_local uint64_t total_callback_time = 0;
            callback_counter++;
            total_callback_time += callback_time_us;
            if (callback_counter % 1000 == 0) {
                double avg_callback_ms = total_callback_time / (double)callback_counter / 1000.0;
                std::cout << "[DEBUG-Callback-Thread-" << thread_id << "] Avg callback time: "
                          << std::fixed << std::setprecision(2) << avg_callback_ms << "ms"
                          << " | Combo: " << combo.toString()
                          << std::endl;
            }
            #endif

            out.found_new_coverage = !exec_result.coverage.new_edges.empty();
            out.crashed = (exec_result.status == ExecutionResult::Status::Crash);
            out.execution_time_ms = exec_result.performance.execution_time_ms;

            double reward = 0.0;
            if (out.found_new_coverage) {
                size_t num_new_edges = exec_result.coverage.new_edges.size();
                reward = 0.5 + (0.5 * std::min(1.0, static_cast<double>(num_new_edges) / 10.0));

                static thread_local std::unordered_map<size_t, size_t> tls_edge_counts;
                static std::unordered_map<size_t, std::atomic<size_t>> global_edge_counts;
                static std::mutex global_edge_mutex;

                double rarity_bonus = 0.0;
                for (size_t edge : exec_result.coverage.new_edges) {
                    tls_edge_counts[edge]++;
                    static thread_local size_t sync_counter = 0;
                    if (++sync_counter % 256 == 0) {
                        std::lock_guard<std::mutex> lock(global_edge_mutex);
                        for (auto& [e, count] : tls_edge_counts) {
                            if (global_edge_counts.find(e) == global_edge_counts.end()) {
                                global_edge_counts[e].store(0);
                            }
                            global_edge_counts[e].fetch_add(count);
                        }
                        tls_edge_counts.clear();
                    }
                    if (tls_edge_counts[edge] <= 5) {
                        rarity_bonus += 0.1;
                    }
                }
                reward += std::min(0.3, rarity_bonus);

                double execution_time_ms = exec_result.performance.execution_time_ms;
                if (execution_time_ms > 0.1) {
                    double speed_factor = 1.0 / (1.0 + std::log10(1.0 + execution_time_ms));
                    reward *= speed_factor;
                    if (execution_time_ms < 5.0) {
                        reward += 0.05;
                    }
                }
                if (!exec_result.coverage.new_branches.empty()) {
                    size_t nb = exec_result.coverage.new_branches.size();
                    reward += 0.2 + 0.05 * std::min<size_t>(5, nb);
                }
                if (exec_result.coverage.branch_coverage_gain > 0.0) {
                    reward += std::min(0.3, exec_result.coverage.branch_coverage_gain * 10.0);
                }
            } else if (out.crashed) {
                reward = 0.6;
                double execution_time_ms = exec_result.performance.execution_time_ms;
                if (execution_time_ms > 0.1) {
                    double speed_factor = 1.0 / (1.0 + std::log10(1.0 + execution_time_ms));
                    reward *= speed_factor;
                }
            } else {
                // Baseline reward for no new coverage, kept very low to avoid reward/s being clamped to 1.0 by time floor
                reward = 0.00005;
            }
            out.reward = reward;

            static thread_local size_t debug_counter_local = 0;
            static const char* verbose_reward_local = std::getenv("triofuzz_VERBOSE_REWARD");
            if (verbose_reward_local && (++debug_counter_local % 1000 == 0)) {
                std::cout << "[REWARD-DEBUG] Combo: " << combo.toString().substr(0, 60)
                          << " | Exec: " << exec_result.performance.execution_time_ms << "ms"
                          << " | Reward: " << out.reward
                          << " | NewCov: " << (exec_result.coverage.new_edges.size() > 0 ? "YES" : "NO")
                          << std::endl;
            }

            if (record_synergy) {
                recordSynergyContribution(out.combination, std::min(1.0, out.reward));
            }

            return exec_result; // Return so second stage can use its input_data
        };

        // Stage 1: use current combination (treat mode as sequential execution)
        AlgorithmCombination stage1_combo = task.combination;
        stage1_combo.combination_mode = "sequential";

        TaskResult stage1_result;
        auto exec1 = execute_one(*task.seed, stage1_combo, stage1_result, /*record_synergy=*/false);

        bool trigger = false;
        if (config_.two_stage_trigger_on_new_coverage && stage1_result.found_new_coverage) {
            trigger = true;
        } else if (stage1_result.reward >= config_.two_stage_trigger_reward) {
            trigger = true;
        }

        if (trigger) {
            two_stage_triggers_.fetch_add(1);
            // Select second-stage polishing algorithms
            size_t want = std::max<size_t>(config_.two_stage_polish_min, 1);
            want = std::min<size_t>(want, config_.two_stage_polish_max);
            auto polish = pick_polish_algorithms(want);

            AlgorithmCombination stage2_combo;
            stage2_combo.combination_mode = "sequential";
            stage2_combo.algorithm_names = polish;
            stage2_combo.scheduler_name = "";
            stage2_combo.feedback_analyzer = "";

            // Stage 2 preferably continues from stage 1's mutated input (if available)
            const std::vector<uint8_t>* stage2_seed = &(*task.seed);
            if (!exec1.input_data.empty()) {
                stage2_seed = &exec1.input_data;
            }

            TaskResult stage2_result;
            (void)execute_one(*stage2_seed, stage2_combo, stage2_result, /*record_synergy=*/true);
            result = stage2_result; // Return stage 2 result
            return;
        } else {
            // Second stage not triggered, return first stage result and record synergy
            recordSynergyContribution(stage1_result.combination, std::min(1.0, stage1_result.reward));
            result = stage1_result;
            // Baton pass: hand sample to polishing algorithms on Worker side for additional attempts (rate-limited)
            if (config_.enable_baton_pass && stage1_result.reward >= config_.baton_threshold_reward) {
                // Only when workers exist and queue is not full
                if (!worker_queues_.empty()) {
                    // Select worker with shallowest queue
                    size_t best_w = 0; size_t best_q = SIZE_MAX;
                    for (size_t w = 0; w < worker_queues_.size(); ++w) {
                        size_t q = getQueueSize(w);
                        if (q < best_q) { best_q = q; best_w = w; }
                    }
                    if (best_q < config_.worker_queue_target_depth) {
                        // Reuse the polishing algorithm set selected above
                        size_t want = std::max<size_t>(config_.two_stage_polish_min, 1);
                        want = std::min<size_t>(want, config_.two_stage_polish_max);
                        auto polish = pick_polish_algorithms(want);
                        AlgorithmCombination baton_combo; baton_combo.combination_mode = "sequential"; baton_combo.algorithm_names = polish;
                        auto seed_buf = acquireSeedBuffer();
                        // Select seed: prefer stage 1's mutated input
                        const std::vector<uint8_t>* baton_seed = &(*task.seed);
                        if (!exec1.input_data.empty()) baton_seed = &exec1.input_data;
                        seed_buf->assign(baton_seed->begin(), baton_seed->end());
                        FuzzTask baton_task; baton_task.combination = baton_combo; baton_task.seed = std::move(seed_buf); baton_task.task_id = task_id_counter_.fetch_add(1);
                        enqueueTask(best_w, std::move(baton_task));
                        baton_enqueued_.fetch_add(1);
                    }
                }
            }
            return;
        }
    }

    // If fanout is enabled and the combination is declared as fanout, execute K=2 best-of selection
    if (execution_callback_ && config_.enable_fanout &&
        task.combination.combination_mode == "fanout") {
        // Select two branch algorithms: prefer first two from combination, pad if insufficient
        std::string a1, a2;
        if (!task.combination.algorithm_names.empty()) a1 = task.combination.algorithm_names[0];
        if (task.combination.algorithm_names.size() >= 2) a2 = task.combination.algorithm_names[1];
        static thread_local std::mt19937 rng(std::random_device{}());
        auto pick_random_algo = [&]() -> std::string {
            if (available_algorithms_.empty()) return std::string("havoc");
            std::uniform_int_distribution<size_t> dist(0, available_algorithms_.size() - 1);
            return available_algorithms_[dist(rng)];
        };
        if (a1.empty()) a1 = pick_random_algo();
        if (a2.empty() || a2 == a1) {
            // Pick a different one
            for (int attempt = 0; attempt < 5 && (a2.empty() || a2 == a1); ++attempt) {
                a2 = pick_random_algo();
            }
            if (a2 == a1) {
                // If still the same, degrade to sequential single algorithm
                a2.clear();
            }
        }

        auto exec_single = [&](const std::string& algo, TaskResult& out) {
            AlgorithmCombination c;
            c.combination_mode = "sequential";
            c.scheduler_name = "";
            c.feedback_analyzer = "";
            if (!algo.empty()) c.algorithm_names = {algo};

            out.task_id = task.task_id;
            out.combination = c;
            out.found_new_coverage = false;
            out.crashed = false;
            out.reward = 0.0;
            out.execution_time_ms = 0.0;
            out.seed_hash = task.seed_hash;
            out.ecofuzz_cycle_id = task.ecofuzz_cycle_id;

            ExecutionResult er = execution_callback_(*task.seed, c);
            out.found_new_coverage = !er.coverage.new_edges.empty();
            out.crashed = (er.status == ExecutionResult::Status::Crash);
            out.execution_time_ms = er.performance.execution_time_ms;

            double reward = 0.0;
            if (out.found_new_coverage) {
                size_t num_new_edges = er.coverage.new_edges.size();
                reward = 0.5 + (0.5 * std::min(1.0, static_cast<double>(num_new_edges) / 10.0));
                // Rare edge bonus + time normalization
                double rarity_bonus = 0.0;
                static thread_local std::unordered_map<size_t, size_t> tls_edge_counts;
                static std::unordered_map<size_t, std::atomic<size_t>> global_edge_counts;
                static std::mutex global_edge_mutex;
                for (size_t edge : er.coverage.new_edges) {
                    tls_edge_counts[edge]++;
                    static thread_local size_t sync_counter = 0;
                    if (++sync_counter % 256 == 0) {
                        std::lock_guard<std::mutex> lock(global_edge_mutex);
                        for (auto& [e, count] : tls_edge_counts) {
                            if (global_edge_counts.find(e) == global_edge_counts.end()) {
                                global_edge_counts[e].store(0);
                            }
                            global_edge_counts[e].fetch_add(count);
                        }
                        tls_edge_counts.clear();
                    }
                    if (tls_edge_counts[edge] <= 5) rarity_bonus += 0.1;
                }
                reward += std::min(0.3, rarity_bonus);
                double t = er.performance.execution_time_ms;
                if (t > 0.1) {
                    double speed = 1.0 / (1.0 + std::log10(1.0 + t));
                    reward *= speed;
                    if (t < 5.0) reward += 0.05;
                }
                if (!er.coverage.new_branches.empty()) {
                    size_t nb = er.coverage.new_branches.size();
                    reward += 0.2 + 0.05 * std::min<size_t>(5, nb);
                }
                if (er.coverage.branch_coverage_gain > 0.0) {
                    reward += std::min(0.3, er.coverage.branch_coverage_gain * 10.0);
                }
            } else if (out.crashed) {
                reward = 0.6;
                double t = er.performance.execution_time_ms;
                if (t > 0.1) reward *= (1.0 / (1.0 + std::log10(1.0 + t)));
            } else {
                reward = 0.0005;
            }
            out.reward = reward;
        };

        TaskResult r1, r2;
        exec_single(a1, r1);
        if (!a2.empty()) exec_single(a2, r2);

        const TaskResult* best = &r1;
        if (!a2.empty()) {
            best = (r2.reward > r1.reward ? &r2 : &r1);
        }
        recordSynergyContribution(best->combination, std::min(1.0, best->reward));
        fanout_triggers_.fetch_add(1);
        result = *best;
        return;
    }

    // If MCTS combination, execute as sequential chain (at most two steps)
    if (execution_callback_ &&
        task.combination.combination_mode == "mcts") {
        AlgorithmCombination seq_combo = task.combination;
        seq_combo.combination_mode = "sequential";
        if (seq_combo.algorithm_names.size() > 2) {
            seq_combo.algorithm_names.resize(2);
        }

        // Use default single-stage execution path computation
        ExecutionResult exec_result = execution_callback_(*task.seed, seq_combo);

        result.task_id = task.task_id;
        result.combination = seq_combo;
        result.found_new_coverage = !exec_result.coverage.new_edges.empty();
        result.crashed = (exec_result.status == ExecutionResult::Status::Crash);
        result.execution_time_ms = exec_result.performance.execution_time_ms;

        double reward = 0.0;
        if (result.found_new_coverage) {
            size_t num_new_edges = exec_result.coverage.new_edges.size();
            reward = 0.5 + (0.5 * std::min(1.0, static_cast<double>(num_new_edges) / 10.0));

            static thread_local std::unordered_map<size_t, size_t> tls_edge_counts;
            static std::unordered_map<size_t, std::atomic<size_t>> global_edge_counts;
            static std::mutex global_edge_mutex;

            double rarity_bonus = 0.0;
            for (size_t edge : exec_result.coverage.new_edges) {
                tls_edge_counts[edge]++;
                static thread_local size_t sync_counter = 0;
                if (++sync_counter % 256 == 0) {
                    std::lock_guard<std::mutex> lock(global_edge_mutex);
                    for (auto& [e, count] : tls_edge_counts) {
                        if (global_edge_counts.find(e) == global_edge_counts.end()) {
                            global_edge_counts[e].store(0);
                        }
                        global_edge_counts[e].fetch_add(count);
                    }
                    tls_edge_counts.clear();
                }
                if (tls_edge_counts[edge] <= 5) {
                    rarity_bonus += 0.1;
                }
            }
            reward += std::min(0.3, rarity_bonus);

            double execution_time_ms = exec_result.performance.execution_time_ms;
            if (execution_time_ms > 0.1) {
                double speed_factor = 1.0 / (1.0 + std::log10(1.0 + execution_time_ms));
                reward *= speed_factor;
                if (execution_time_ms < 5.0) {
                    reward += 0.05;
                }
            }
            if (!exec_result.coverage.new_branches.empty()) {
                size_t nb = exec_result.coverage.new_branches.size();
                reward += 0.2 + 0.05 * std::min<size_t>(5, nb);
            }
            if (exec_result.coverage.branch_coverage_gain > 0.0) {
                reward += std::min(0.3, exec_result.coverage.branch_coverage_gain * 10.0);
            }
        } else if (result.crashed) {
            reward = 0.6;
            double execution_time_ms = exec_result.performance.execution_time_ms;
            if (execution_time_ms > 0.1) {
                double speed_factor = 1.0 / (1.0 + std::log10(1.0 + execution_time_ms));
                reward *= speed_factor;
            }
        } else {
            reward = 0.0005;
        }
        result.reward = reward;
        recordSynergyContribution(result.combination, std::min(1.0, result.reward));
        return;
    }

    // Default: keep original single-stage execution logic
    if (execution_callback_) {
        ExecutionResult exec_result = execution_callback_(*task.seed, task.combination);

        #ifdef ENABLE_CALLBACK_TIMING_STATS
        auto callback_timing_end = std::chrono::steady_clock::now();
        auto callback_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
            callback_timing_end - callback_timing_start).count();

        // Track callback time
        static thread_local size_t callback_counter = 0;
        static thread_local uint64_t total_callback_time = 0;
        callback_counter++;
        total_callback_time += callback_time_us;

        if (callback_counter % 1000 == 0) {
            double avg_callback_ms = total_callback_time / (double)callback_counter / 1000.0;
            std::cout << "[DEBUG-Callback-Thread-" << thread_id << "] Avg callback time: "
                      << std::fixed << std::setprecision(2) << avg_callback_ms << "ms"
                      << " | Combo: " << task.combination.toString()
                      << std::endl;
        }
        #endif

        // ===== [PERF] Timing point: callback end =====
#if ENABLE_DETAILED_PERF
        callback_end = std::chrono::high_resolution_clock::now();
#endif

        // Analyze execution result
        result.found_new_coverage = !exec_result.coverage.new_edges.empty();
        result.crashed = (exec_result.status == ExecutionResult::Status::Crash);

        // Record execution time (for UCB + time normalization)
        result.execution_time_ms = exec_result.performance.execution_time_ms;

        // Adaptive reward computation
        double reward = 0.0;

        if (result.found_new_coverage) {
            // Base reward: scales with new_edges count, encouraging discovery of multiple edges at once
            size_t num_new_edges = exec_result.coverage.new_edges.size();
            reward = 0.5 + (0.5 * std::min(1.0, static_cast<double>(num_new_edges) / 10.0));

            // Rare edge bonus: use thread-local cache to avoid global lock
            static thread_local std::unordered_map<size_t, size_t> tls_edge_counts;
            static std::unordered_map<size_t, std::atomic<size_t>> global_edge_counts;
            static std::mutex global_edge_mutex;

            double rarity_bonus = 0.0;
            for (size_t edge : exec_result.coverage.new_edges) {
                // Update thread-local count first
                tls_edge_counts[edge]++;

                // Sync to global every 256 executions (reduce lock contention)
                static thread_local size_t sync_counter = 0;
                if (++sync_counter % 256 == 0) {
                    std::lock_guard<std::mutex> lock(global_edge_mutex);
                    for (auto& [e, count] : tls_edge_counts) {
                        if (global_edge_counts.find(e) == global_edge_counts.end()) {
                            global_edge_counts[e].store(0);
                        }
                        global_edge_counts[e].fetch_add(count);
                    }
                    tls_edge_counts.clear();
                }

                // Determine rarity based on thread-local count (approximate but lock-free)
                if (tls_edge_counts[edge] <= 5) {
                    rarity_bonus += 0.1;  // Extra reward for rare edges
                }
            }
            reward += std::min(0.3, rarity_bonus);

            // ===== THROUGHPUT-AWARE REWARD: coverage gain / execution time =====
            // Problem: slow algorithms find coverage but tank throughput (50-500ms)
            // Solution: normalize reward by execution time, rewarding "coverage per unit time"
            double execution_time_ms = exec_result.performance.execution_time_ms;
            if (execution_time_ms > 0.1) {  // Avoid division by zero
                // Baseline: 1ms execution = 1.0x multiplier
                // 10ms = 0.1x, 100ms = 0.01x
                // Use log scale to avoid excessive penalty: speed_factor = 1 / log10(1 + time_ms)
                // 1ms -> 1.0, 10ms -> 0.5, 100ms -> 0.25, 1000ms -> 0.125
                double speed_factor = 1.0 / (1.0 + std::log10(1.0 + execution_time_ms));
                reward *= speed_factor;

                // Extra bonus: small reward for very fast executions (<5ms)
                if (execution_time_ms < 5.0) {
                    reward += 0.05;
                }
            }
            // Extra branch coverage reward: new branch count and branch coverage gain
            if (!exec_result.coverage.new_branches.empty()) {
                size_t nb = exec_result.coverage.new_branches.size();
                reward += 0.2 + 0.05 * std::min<size_t>(5, nb);
            }
            if (exec_result.coverage.branch_coverage_gain > 0.0) {
                reward += std::min(0.3, exec_result.coverage.branch_coverage_gain * 10.0);
            }

        } else if (result.crashed) {
            reward = 0.6;  // Crashes have value but less than coverage
            // Crashes also factor in execution time
            double execution_time_ms = exec_result.performance.execution_time_ms;
            if (execution_time_ms > 0.1) {
                double speed_factor = 1.0 / (1.0 + std::log10(1.0 + execution_time_ms));
                reward *= speed_factor;
            }
        } else {
            // No-contribution execution: give minimal baseline reward for sparse signal, but do not amplify by time
            reward = 0.0005;
        }

        // Do not clamp reward, allow wider range
        // Theoretical max: (1.0 + 0.3 + 0.05) * 1.0 (very fast) = 1.35
        // Slow algorithms are heavily penalized: (1.0 + 0.3) * 0.1 (100ms) = 0.13
        result.reward = reward;

        // DEBUG: print reward and execution time info (sample every 1000 executions)
        static thread_local size_t debug_counter = 0;
        static const char* verbose_reward = std::getenv("triofuzz_VERBOSE_REWARD");
        if (verbose_reward && (++debug_counter % 1000 == 0)) {
            std::cout << "[REWARD-DEBUG] Combo: " << result.combination.toString().substr(0, 60)
                      << " | Exec: " << exec_result.performance.execution_time_ms << "ms"
                      << " | Reward: " << result.reward
                      << " | NewCov: " << (exec_result.coverage.new_edges.size() > 0 ? "YES" : "NO")
                      << std::endl;
        }

        // Synergy learning uses raw reward (clamped to [0,1] to avoid excessive influence on synergy scores)
        recordSynergyContribution(result.combination, std::min(1.0, result.reward));
    }

    // ===== [PERF] Performance statistics =====
#if ENABLE_DETAILED_PERF
    auto task_end = std::chrono::high_resolution_clock::now();

    thread_local struct {
        size_t count = 0;
        uint64_t total_callback_us = 0;
        uint64_t total_overhead_us = 0;
        std::chrono::steady_clock::time_point last_print = std::chrono::steady_clock::now();
    } perf_stats;

    auto callback_duration = std::chrono::duration_cast<std::chrono::microseconds>(callback_end - callback_start).count();
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(task_end - task_start).count();
    auto overhead_duration = total_duration - callback_duration;

    perf_stats.total_callback_us += callback_duration;
    perf_stats.total_overhead_us += overhead_duration;
    perf_stats.count++;

    // Print statistics every 10 seconds
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - perf_stats.last_print).count() >= 10) {
        double avg_callback_ms = perf_stats.total_callback_us / (double)perf_stats.count / 1000.0;
        double avg_overhead_ms = perf_stats.total_overhead_us / (double)perf_stats.count / 1000.0;
        double avg_total_ms = (perf_stats.total_callback_us + perf_stats.total_overhead_us) / (double)perf_stats.count / 1000.0;

        // std::cout << "[Perf-Thread" << thread_id << "] Executions: " << perf_stats.count
        //           << " | Callback: " << std::fixed << std::setprecision(2) << avg_callback_ms << "ms"
        //           << " | Overhead: " << avg_overhead_ms << "ms"
        //           << " | Total: " << avg_total_ms << "ms"
        //           << " | OH%: " << (avg_overhead_ms / avg_total_ms * 100) << "%" << std::endl;

        perf_stats.last_print = now;
    }
#endif
}

void SpecializedThreadEngine::recordSynergyContribution(const AlgorithmCombination& combination, double reward) {
    // Only update adjacent pairs in sequential chain with weighting, avoiding spreading credit evenly across all pairs
    const auto& algos = combination.algorithm_names;
    if (algos.size() < 2 || reward <= 0.0) {
        return;
    }

    // Compute per-step share using geometric decay
    auto shares = computeGeometricShares(algos.size(), 0.7);

    auto& cache = tls_synergy_updates;
    for (size_t i = 0; i + 1 < algos.size(); ++i) {
        double pair_share = 0.5 * ((i < shares.size() ? shares[i] : 0.0) + (i + 1 < shares.size() ? shares[i + 1] : 0.0));
        double contrib = reward * pair_share;
        if (contrib <= 0.0) continue;
        cache.push_back({algos[i] + "+" + algos[i + 1], contrib});
    }

    // Batch-flush cache to reduce lock contention
    if (cache.size() >= 256) {
        flushSynergyUpdates(cache);
        cache.clear();
    }

    // Record triple-step motif (low frequency direct write, lock-protected)
    if (config_.enable_ngram_motifs && algos.size() >= 3 && reward > 0.0) {
        std::string motif_key = algos[0] + "+" + algos[1] + "+" + algos[2];
        std::unique_lock<std::shared_mutex> lock(synergy_mutex_);
        auto& m = algorithm_motifs_[motif_key];
        m.support++;
        // EMA update
        double alpha = 0.1;
        m.score = m.score * (1.0 - alpha) + reward * alpha;
        // Capacity constraint (simple eviction)
        if (algorithm_motifs_.size() > config_.motif_capacity) {
            // Remove an arbitrary early element (for simplicity)
            algorithm_motifs_.erase(algorithm_motifs_.begin());
        }
    }
}

void SpecializedThreadEngine::flushSynergyUpdates(std::vector<SynergyContribution>& updates) {
    if (updates.empty()) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(synergy_mutex_);
    const double SYNERGY_LEARNING_RATE = 0.1;

    for (const auto& update : updates) {
        auto& synergy = algorithm_synergies_[update.key];
        synergy.co_occurrences++;
        synergy.synergy_score = synergy.synergy_score * (1.0 - SYNERGY_LEARNING_RATE) +
                               update.reward * SYNERGY_LEARNING_RATE;
    }
}

void SpecializedThreadEngine::flushThreadLocalSynergyCache() {
    auto& cache = tls_synergy_updates;
    if (cache.empty()) {
        return;
    }
    flushSynergyUpdates(cache);
    cache.clear();
}

// ============================================================================
// Hybrid mode helper function implementations
// ============================================================================

// Non-blocking attempt to acquire a newer task
bool SpecializedThreadEngine::tryStealNewerTask(size_t worker_id, FuzzTask& task) {
    if (worker_id >= worker_queues_.size()) {
        return false;
    }

    auto& queue = worker_queues_[worker_id];

    // Non-blocking lock attempt
    std::unique_lock<std::mutex> lock(queue->mutex, std::try_to_lock);
    if (!lock || queue->tasks.empty()) {
        return false;
    }

    // Get task from queue
    task = std::move(queue->tasks.front());
    queue->tasks.pop_front();

    return true;
}

// Check whether the last N executions had new coverage
bool SpecializedThreadEngine::hasRecentCoverage(
    const std::vector<TaskResult>& results, size_t window) {

    if (results.size() < window) {
        window = results.size();
    }

    if (window == 0) {
        return false;
    }

    // Check last window results
    for (size_t i = results.size() - window; i < results.size(); ++i) {
        if (results[i].found_new_coverage) {
            return true;
        }
    }

    return false;
}

// Calculate average reward over the last N executions
double SpecializedThreadEngine::calculateAvgReward(
    const std::vector<TaskResult>& results, size_t window) {

    if (results.empty()) {
        return 0.0;
    }

    if (results.size() < window) {
        window = results.size();
    }

    double total_reward = 0.0;
    for (size_t i = results.size() - window; i < results.size(); ++i) {
        total_reward += results[i].reward;
    }

    return total_reward / window;
}

// Adaptive exploit count - dynamically adjust batch size based on execution time
size_t SpecializedThreadEngine::calculateAdaptiveExploitCount(const AlgorithmCombination& combo) {
    if (!config_.enable_adaptive_exploit_count) {
        return config_.worker_exploit_count;  // Return fixed value when disabled
    }

    // Look up historical performance data for this combination
    size_t combo_hash = combo.hash();
    std::unique_lock<std::mutex> lock(performance_mutex_);
    auto it = combination_performance_.find(combo_hash);

    if (it == combination_performance_.end() || it->second.executions < 10) {
        // New combination or insufficient data, use default
        return config_.worker_exploit_count;
    }

    double avg_time_ms = it->second.avg_execution_time_ms;
    lock.unlock();  // Release lock early

    // Target: each exploit cycle should be approximately target_exploit_duration_sec seconds
    // exploit_count = target_duration_sec * 1000 / avg_time_ms
    double target_ms = config_.target_exploit_duration_sec * 1000.0;
    size_t calculated_count = static_cast<size_t>(target_ms / std::max(0.1, avg_time_ms));

    // Clamp to reasonable range
    calculated_count = std::max(config_.min_exploit_count, calculated_count);
    calculated_count = std::min(config_.max_exploit_count, calculated_count);

    return calculated_count;
}

// ============================================================================
// Trio-TS (AFL++ schedules + Thompson Sampling over configs) mode implementation
// ============================================================================

AlgorithmCombination SpecializedThreadEngine::buildTsCombination(
    const TsConfigArm& arm,
    bool explorer,
    std::mt19937& rng
) {
    AlgorithmCombination combo;
    combo.combination_mode = "sequential";
    combo.scheduler_name = arm.key;  // stable key for config-level learning
    combo.feedback_analyzer = "";

    if (arm.mutator == TsMutator::Havoc) {
        const auto& ops = arm.splice ? kTsHavocOpsWithSplice : kTsHavocOpsNoSplice;
        if (ops.empty()) {
            combo.algorithm_names = {"mut_flipbit"};
            return combo;
        }

        // AFL++ havoc stacking: 1 << (1 + rand_below(pow2))
        uint32_t pow2 = std::max<uint32_t>(1, config_.ts_havoc_stack_pow2);
        std::uniform_int_distribution<uint32_t> pow_dist(0, pow2 - 1);
        uint32_t use_stacking = 1u << (1u + pow_dist(rng));
        if (use_stacking > 1024) use_stacking = 1024;  // safety cap

        combo.algorithm_names.reserve(use_stacking);
        std::uniform_int_distribution<size_t> op_dist(0, ops.size() - 1);
        for (uint32_t i = 0; i < use_stacking; ++i) {
            combo.algorithm_names.push_back(ops[op_dist(rng)]);
        }
        return combo;
    }

    // Analysis mutator: advanced analysis-guided mutation algorithms
    // These algorithms have longer execution times but can discover complex constraints and magic bytes
    // Smaller stack size (1-2) since each algorithm is already heavyweight
    if (arm.mutator == TsMutator::Analysis) {
        const auto& ops = kTriofuzzAnalysisOps;
        if (ops.empty()) {
            combo.algorithm_names = {"smart_dictionary"};
            return combo;
        }

        // Analysis algorithms use smaller stack size (1-2)
        // since they already have long execution times and do not need excessive stacking
        std::uniform_int_distribution<size_t> stack_dist(1, 2);
        size_t stack_size = stack_dist(rng);

        combo.algorithm_names.reserve(stack_size);
        std::uniform_int_distribution<size_t> op_dist(0, ops.size() - 1);
        for (size_t i = 0; i < stack_size; ++i) {
            combo.algorithm_names.push_back(ops[op_dist(rng)]);
        }
        return combo;
    }

    // MOpt mutator: workers use PSO learner (core-like), explorers do random (pilot-like)
    const auto& ops = arm.splice ? ts_mopt_ops_splice_ : ts_mopt_ops_nosplice_;
    if (ops.empty()) {
        combo.algorithm_names = {"mopt_flip1"};
        return combo;
    }

    size_t min_len = std::max<size_t>(1, config_.mopt_min_sequence_length);
    size_t max_len = std::max<size_t>(1, config_.mopt_max_sequence_length);
    if (min_len > max_len) std::swap(min_len, max_len);

    if (!explorer) {
        MOptOnlineLearner* learner = arm.splice ? ts_mopt_learner_splice_.get() : ts_mopt_learner_nosplice_.get();
        if (learner) {
            auto seq_idx = learner->generateSequence(min_len, max_len);
            combo.algorithm_names.reserve(seq_idx.size());
            for (size_t idx : seq_idx) {
                if (idx < ops.size()) combo.algorithm_names.push_back(ops[idx]);
            }
        }
    }

    if (combo.algorithm_names.empty()) {
        std::uniform_int_distribution<size_t> len_dist(min_len, max_len);
        std::uniform_int_distribution<size_t> op_dist(0, ops.size() - 1);
        const size_t len = len_dist(rng);
        combo.algorithm_names.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            combo.algorithm_names.push_back(ops[op_dist(rng)]);
        }
    }

    return combo;
}

std::shared_ptr<std::vector<uint8_t>> SpecializedThreadEngine::getSeedFromCorpusForSchedule(
    const TsConfigArm& arm,
    std::mt19937& rng
) {
    // explore: uniformly random corpus entry (fast path with large cache)
    if (arm.schedule == TsPowerSchedule::Explore) {
        return getSeedFromCorpus();
    }

    // coe: mostly energy-based, with a small chance to fall back to random
    if (arm.schedule == TsPowerSchedule::Coe) {
        std::uniform_real_distribution<double> p(0.0, 1.0);
        if (p(rng) < 0.10) {
            return getSeedFromCorpus();
        }
    }

    auto buffer = acquireSeedBuffer();
    if (!buffer) {
        return nullptr;
    }
    if (!corpus_manager_) {
        buffer->clear();
        return buffer;
    }

    if (tls_seed_cache_next_index >= tls_seed_cache_next.size()) {
        tls_seed_cache_next.clear();
        tls_seed_cache_next.reserve(TLS_SEED_CACHE_NEXT_SIZE);

        for (size_t i = 0; i < TLS_SEED_CACHE_NEXT_SIZE; ++i) {
            auto seed = corpus_manager_->getNextSeed();
            if (seed) {
                tls_seed_cache_next.push_back(std::move(*seed));
            } else {
                break;
            }
        }
        tls_seed_cache_next_index = 0;
    }

    if (tls_seed_cache_next_index < tls_seed_cache_next.size()) {
        const auto& seed = tls_seed_cache_next[tls_seed_cache_next_index++];
        buffer->assign(seed.data.begin(), seed.data.end());
    } else {
        buffer->clear();
    }

    return buffer;
}

SeedSelectionResult SpecializedThreadEngine::getSeedFromCorpusForTrioSchedule(
    const std::string& schedule,
    std::mt19937& rng
) {
    if (schedule == "explore") {
        SeedSelectionResult out;
        out.seed = getSeedFromCorpus();
        return out;
    }

    if (schedule == "coe") {
        TsConfigArm arm;
        arm.schedule = TsPowerSchedule::Coe;
        SeedSelectionResult out;
        out.seed = getSeedFromCorpusForSchedule(arm, rng);
        return out;
    }

    if (schedule == "fast") {
        TsConfigArm arm;
        arm.schedule = TsPowerSchedule::Fast;
        SeedSelectionResult out;
        out.seed = getSeedFromCorpusForSchedule(arm, rng);
        return out;
    }

    if (schedule == "ecofuzz") {
        SeedSelectionResult out;
        auto buffer = acquireSeedBuffer();
        if (!buffer) {
            return out;
        }
        if (!corpus_manager_) {
            buffer->clear();
            out.seed = buffer;
            return out;
        }

        // Thread-local EcoFuzz "current parent" cache to emulate per-input energy scheduling.
        struct EcoFuzzThreadState {
            uint64_t seed_hash = 0;
            uint64_t cycle_id = 0;
            uint32_t remaining = 0;
            std::vector<uint8_t> seed_data;
        };
        static thread_local EcoFuzzThreadState tls_ecofuzz;

        // Fast path: keep using the same seed while it still has remaining energy.
        if (tls_ecofuzz.remaining > 0 && !tls_ecofuzz.seed_data.empty()) {
            buffer->assign(tls_ecofuzz.seed_data.begin(), tls_ecofuzz.seed_data.end());
            out.seed = buffer;
            out.seed_hash = tls_ecofuzz.seed_hash;
            out.ecofuzz_cycle_id = tls_ecofuzz.cycle_id;
            tls_ecofuzz.remaining--;
            return out;
        }

        // Slow path: pick a new seed and start a new EcoFuzz cycle.
        auto get_sqrt = [](uint32_t val) -> uint32_t {
            uint32_t s = static_cast<uint32_t>(std::sqrt(static_cast<double>(val)));
            return (s == 0) ? 1u : s;
        };

        auto refresh_seed_pool_locked = [&]() {
            const auto now = std::chrono::steady_clock::now();
            const size_t corpus_size = corpus_manager_->getCurrentCorpusSize();

            // Refresh seed pool if the corpus size changed (but rate-limit refresh to reduce overhead).
            const bool need_refresh = ecofuzz_seed_pool_.empty() || (corpus_size != ecofuzz_last_corpus_size_);
            const bool allow_refresh =
                (ecofuzz_last_refresh_time_.time_since_epoch().count() == 0) ||
                (std::chrono::duration_cast<std::chrono::milliseconds>(now - ecofuzz_last_refresh_time_).count() >= 1000);

            if (need_refresh && allow_refresh) {
                ecofuzz_seed_pool_ = corpus_manager_->getAllSeedHashes();
                std::sort(ecofuzz_seed_pool_.begin(), ecofuzz_seed_pool_.end());
                ecofuzz_seed_pool_.erase(std::unique(ecofuzz_seed_pool_.begin(), ecofuzz_seed_pool_.end()),
                                         ecofuzz_seed_pool_.end());

                ecofuzz_last_corpus_size_ = corpus_size;
                ecofuzz_last_refresh_time_ = now;

                for (uint64_t h : ecofuzz_seed_pool_) {
                    auto [it, inserted] = ecofuzz_seed_stats_.emplace(h, EcoFuzzSeedStats{});
                    if (inserted) {
                        it->second.serial = ++ecofuzz_serial_cnt_;
                        it->second.n_fuzz_entry =
                            static_cast<uint32_t>(h % static_cast<uint64_t>(EcoFuzzGlobalStats::kNFuzzSize));
                    }
                }
            }

            if (ecofuzz_global_.init_flag == 0 && !ecofuzz_seed_pool_.empty()) {
                ecofuzz_global_.queued_paths_initial = ecofuzz_seed_pool_.size();
                ecofuzz_global_.init_flag = 1;
            }
        };

        auto pick_ecofuzz_seed_locked = [&](uint32_t& state_of_fuzz) -> uint64_t {
            state_of_fuzz = 0;
            if (ecofuzz_seed_pool_.empty()) {
                return 0;
            }

            // State 1: fuzz every seed at least once.
            for (uint64_t h : ecofuzz_seed_pool_) {
                auto it = ecofuzz_seed_stats_.find(h);
                if (it == ecofuzz_seed_stats_.end()) continue;
                if (!it->second.was_fuzzed) {
                    state_of_fuzz = 1;
                    it->second.was_fuzzed = true;
                    return h;
                }
            }

            // State 2: EcoFuzz selection among already-fuzzed seeds.
            state_of_fuzz = 2;

            uint64_t p_hash = 0;
            for (uint64_t h : ecofuzz_seed_pool_) {
                auto it = ecofuzz_seed_stats_.find(h);
                if (it == ecofuzz_seed_stats_.end()) continue;
                if (it->second.state != 2) {
                    p_hash = h;
                    break;
                }
            }

            if (p_hash == 0) {
                // All entries reached state=2; reset all to 0.
                for (uint64_t h : ecofuzz_seed_pool_) {
                    auto it = ecofuzz_seed_stats_.find(h);
                    if (it != ecofuzz_seed_stats_.end()) {
                        it->second.state = 0;
                    }
                }
                p_hash = ecofuzz_seed_pool_.front();
            }

            for (uint64_t h : ecofuzz_seed_pool_) {
                auto it = ecofuzz_seed_stats_.find(h);
                if (it == ecofuzz_seed_stats_.end()) continue;
                auto& q = it->second;
                if (q.state != 0) continue;

                const auto& p = ecofuzz_seed_stats_[p_hash];
                const uint32_t p_sqrt = get_sqrt(p.serial);
                const uint32_t q_sqrt = get_sqrt(q.serial);

                const __uint128_t lhs = static_cast<__uint128_t>(q.exec_by_mutation) *
                                        static_cast<__uint128_t>(p.mutation_num) *
                                        static_cast<__uint128_t>(p_sqrt);
                const __uint128_t rhs = static_cast<__uint128_t>(p.exec_by_mutation) *
                                        static_cast<__uint128_t>(q.mutation_num) *
                                        static_cast<__uint128_t>(q_sqrt);

                if (lhs < rhs) {
                    p_hash = h;
                }
            }

            // Mark selected seed as "state=2" for this round.
            ecofuzz_seed_stats_[p_hash].state = 2;
            return p_hash;
        };

        auto calculate_ecofuzz_energy_locked = [&](const EcoFuzzSeedStats& st, uint32_t state_of_fuzz) -> uint32_t {
            const uint64_t corpus_size = ecofuzz_seed_pool_.empty() ? 0 : ecofuzz_seed_pool_.size();
            uint64_t average_cost = 1024;

            if (corpus_size > 0 && corpus_size == ecofuzz_global_.queued_paths_initial) {
                average_cost = (ecofuzz_global_.total_fuzz == 0) ? 0 : (ecofuzz_global_.total_fuzz / corpus_size);
            } else {
                if (ecofuzz_global_.path_increase == 0) {
                    average_cost = 1024;
                } else {
                    average_cost = ecofuzz_global_.total_fuzz / ecofuzz_global_.path_increase;
                }
            }

            if (average_cost == 0 || ecofuzz_global_.path_increase == 0) {
                average_cost = 1024;
            }

            uint64_t energy = 0;
            const uint32_t nf = (st.n_fuzz_entry < ecofuzz_global_.n_fuzz.size())
                                    ? ecofuzz_global_.n_fuzz[st.n_fuzz_entry]
                                    : 0;

            auto base_energy = [&]() -> uint64_t {
                if (nf > average_cost) return average_cost / 4;
                if (nf > average_cost / 2) return average_cost / 2;
                return average_cost;
            };

            if (state_of_fuzz == 2) {
                if (st.last_found == 0) {
                    energy = std::min<uint64_t>(static_cast<uint64_t>(2) * st.last_energy,
                                                static_cast<uint64_t>(16) * average_cost);
                } else {
                    energy = std::min<uint64_t>(static_cast<uint64_t>(st.last_energy),
                                                static_cast<uint64_t>(16) * average_cost);
                }
                if (energy == 0) {
                    energy = base_energy();
                }
            } else {
                energy = base_energy();
            }

            energy = static_cast<uint64_t>(static_cast<double>(energy) * static_cast<double>(ecofuzz_global_.rate) * 5.0);
            if (energy > 1000) energy = 1000;
            if (energy == 0) energy = 1;
            return static_cast<uint32_t>(energy);
        };

        uint64_t selected_hash = 0;
        uint32_t state_of_fuzz = 0;
        uint32_t assigned_energy = 0;
        uint64_t cycle_id = 0;

        {
            std::lock_guard<std::mutex> lock(ecofuzz_mutex_);
            refresh_seed_pool_locked();

            selected_hash = pick_ecofuzz_seed_locked(state_of_fuzz);
            if (selected_hash != 0) {
                const auto it = ecofuzz_seed_stats_.find(selected_hash);
                if (it != ecofuzz_seed_stats_.end()) {
                    assigned_energy = calculate_ecofuzz_energy_locked(it->second, state_of_fuzz);
                    cycle_id = ecofuzz_next_cycle_id_.fetch_add(1);

                    EcoFuzzCycle cyc;
                    cyc.seed_hash = selected_hash;
                    cyc.assigned_energy = assigned_energy;
                    cyc.start_mutation_num = it->second.mutation_num;
                    cyc.state_of_fuzz = state_of_fuzz;
                    ecofuzz_cycles_[cycle_id] = std::move(cyc);
                }
            }
        }

        // If we failed to pick a seed, fall back to the default corpus selection.
        if (selected_hash == 0 || assigned_energy == 0 || cycle_id == 0) {
            buffer->clear();
            out.seed = buffer;
            return out;
        }

        // Fetch the selected seed data from CorpusManager.
        auto seed_opt = corpus_manager_->getSeedByHash(selected_hash);
        if (!seed_opt.has_value() || seed_opt->data.empty()) {
            {
                std::lock_guard<std::mutex> lock(ecofuzz_mutex_);
                ecofuzz_cycles_.erase(cycle_id);
            }
            buffer->clear();
            out.seed = buffer;
            return out;
        }

        tls_ecofuzz.seed_hash = selected_hash;
        tls_ecofuzz.cycle_id = cycle_id;
        tls_ecofuzz.remaining = assigned_energy;
        tls_ecofuzz.seed_data = std::move(seed_opt->data);

        buffer->assign(tls_ecofuzz.seed_data.begin(), tls_ecofuzz.seed_data.end());
        out.seed = buffer;
        out.seed_hash = tls_ecofuzz.seed_hash;
        out.ecofuzz_cycle_id = tls_ecofuzz.cycle_id;
        tls_ecofuzz.remaining--;
        return out;
    }

    SeedSelectionResult out;
    out.seed = getSeedFromCorpus();
    return out;
}

void SpecializedThreadEngine::schedulerThreadTS() {
    std::cout << "[Scheduler-TS] Thread started - TS over configs active" << std::endl;

    std::random_device rd;
    std::mt19937 rng(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));

    auto last_stats_time = std::chrono::steady_clock::now();
    auto last_mopt_stats_time = last_stats_time;
    size_t last_total_executions = 0;

    while (running_.load()) {
        // 1) Process results: update config-level TS + inner MOpt learners.
        for (auto& rq : result_queues_) {
            if (!rq) continue;
            auto results = rq->swapAndGet();
            for (const auto& result : results) {
                if (result.found_new_coverage) {
                    auto now = std::chrono::steady_clock::now().time_since_epoch();
                    last_new_cov_ns_.store(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
                }

                const auto key_it = ts_key_to_index_.find(result.combination.scheduler_name);
                if (key_it == ts_key_to_index_.end()) continue;

                const size_t arm_idx = key_it->second;
                const auto& arm = ts_arms_[arm_idx];
                auto& stats = ts_stats_[arm_idx];

                const bool success = result.found_new_coverage;
                stats.executions += 1;
                stats.total_finds += success ? 1 : 0;
                stats.window_execs += 1;
                stats.window_finds += success ? 1 : 0;

                const size_t period = std::max<size_t>(1, config_.ts_update_period);
                if (stats.window_execs >= period) {
                    const double decay = std::min(1.0, std::max(0.0, config_.ts_decay));
                    const size_t window_fail = stats.window_execs - stats.window_finds;

                    stats.alpha = 1.0 + (stats.alpha - 1.0) * decay + static_cast<double>(stats.window_finds);
                    stats.beta = 1.0 + (stats.beta - 1.0) * decay + static_cast<double>(window_fail);

                    stats.updates += 1;
                    stats.last_window_finds = stats.window_finds;
                    stats.last_window_cycles = stats.window_execs;
                    stats.window_execs = 0;
                    stats.window_finds = 0;
                }

                if (arm.mutator == TsMutator::Mopt) {
                    MOptOnlineLearner* learner = arm.splice ? ts_mopt_learner_splice_.get() : ts_mopt_learner_nosplice_.get();
                    const auto& index_map = arm.splice ? ts_mopt_index_splice_ : ts_mopt_index_nosplice_;
                    if (!learner) continue;

                    std::vector<size_t> seq;
                    seq.reserve(result.combination.algorithm_names.size());
                    for (const auto& name : result.combination.algorithm_names) {
                        auto it = index_map.find(name);
                        if (it != index_map.end()) seq.push_back(it->second);
                    }
                    if (!seq.empty()) {
                        learner->update(seq, result.found_new_coverage, result.execution_time_ms);
                    }
                }
            }
        }

        // 2) Fill worker queues with tasks (each task = one exec).
        size_t target_queue_depth = std::max<size_t>(1, config_.worker_queue_target_depth);
        bool produced_tasks = false;

        if (num_workers_ > 0 && !ts_arms_.empty()) {
            std::uniform_real_distribution<double> explore_p(0.0, 1.0);
            const double eps = std::min(1.0, std::max(0.0, config_.exploration_ratio));
            std::uniform_int_distribution<size_t> uniform_arm(0, ts_arms_.size() - 1);

            auto select_arm_ts = [&]() -> size_t {
                double best_sample = -1.0;
                size_t best_idx = 0;
                for (size_t i = 0; i < ts_stats_.size(); ++i) {
                    const auto& s = ts_stats_[i];
                    const double sample = sampleBeta(std::max(1e-6, s.alpha), std::max(1e-6, s.beta), rng);
                    if (sample > best_sample) {
                        best_sample = sample;
                        best_idx = i;
                    }
                }
                return best_idx;
            };

            for (size_t i = 0; i < num_workers_ && running_.load(); ++i) {
                size_t worker_index = next_worker_to_fill_;
                next_worker_to_fill_ = (next_worker_to_fill_ + 1) % num_workers_;

                if (getQueueSize(worker_index) >= target_queue_depth) {
                    continue;
                }

                const bool do_explore = explore_p(rng) < eps;
                const size_t arm_idx = do_explore ? uniform_arm(rng) : select_arm_ts();
                const auto& arm = ts_arms_[arm_idx];

                auto seed = getSeedFromCorpusForSchedule(arm, rng);
                if (!seed) {
                    continue;
                }

                AlgorithmCombination combo = buildTsCombination(arm, /*explorer=*/false, rng);

                FuzzTask task;
                task.combination = std::move(combo);
                task.seed = std::move(seed);
                task.task_id = task_id_counter_.fetch_add(1);

                enqueueTask(worker_index, std::move(task));
                scheduler_decisions_.fetch_add(1);
                produced_tasks = true;
            }
        }

        // 3) Periodic stats.
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time);
        if (elapsed.count() >= 5) {
            size_t current_total = total_executions_.load();
            size_t exec_in_period = current_total - last_total_executions;
            double exec_per_sec = static_cast<double>(exec_in_period) / (elapsed.count() > 0 ? elapsed.count() : 1);

            size_t covered_edges = coverage_callback_ ? coverage_callback_() : 0;
            std::cout << "[TS-Stats] Execs: " << current_total
                      << " | Speed: " << std::fixed << std::setprecision(0) << exec_per_sec << "/s"
                      << " | Coverage: " << covered_edges << " edges"
                      << " | Worker: " << worker_executions_.load()
                      << " | Explorer: " << explorer_executions_.load()
                      << std::endl;

            if (!ts_arms_.empty()) {
                std::vector<std::pair<size_t, double>> probs;
                probs.reserve(ts_arms_.size());
                double sum_means = 0.0;
                for (size_t i = 0; i < ts_arms_.size(); ++i) {
                    const auto& s = ts_stats_[i];
                    const double mean = s.alpha / (s.alpha + s.beta + 1e-10);
                    probs.emplace_back(i, mean);
                    sum_means += mean;
                }
                if (sum_means <= 0.0) sum_means = 1.0;
                for (auto& p : probs) p.second /= sum_means;

                std::sort(probs.begin(), probs.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });

                std::cout << "[TSConfig Statistics]\n"
                          << "  Configs: " << ts_arms_.size() << "\n"
                          << "  Executions: " << current_total << "\n"
                          << "  Update period: " << config_.ts_update_period << "\n"
                          << "  Decay: " << config_.ts_decay << "\n"
                          << "  Top probabilities:" << std::endl;

                const size_t topk = std::min<size_t>(8, probs.size());
                for (size_t i = 0; i < topk; ++i) {
                    const size_t idx = probs[i].first;
                    const auto& s = ts_stats_[idx];
                    std::cout << "    [" << ts_arms_[idx].key << "] p=" << std::setprecision(6) << probs[i].second
                              << " execs=" << s.executions
                              << " updates=" << s.updates
                              << std::endl;
                }
            }

            last_stats_time = now;
            last_total_executions = current_total;
        }

        // Inner MOpt stats at a slower cadence.
        auto mopt_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_mopt_stats_time);
        if (mopt_elapsed.count() >= 30) {
            if (ts_mopt_learner_nosplice_) {
                std::cout << "[TS-MOpt(no-splice)]\n" << ts_mopt_learner_nosplice_->getStatisticsReport(8) << std::endl;
            }
            if (ts_mopt_learner_splice_) {
                std::cout << "[TS-MOpt(splice)]\n" << ts_mopt_learner_splice_->getStatisticsReport(8) << std::endl;
            }
            last_mopt_stats_time = now;
        }

        if (!running_.load()) {
            break;
        }

        if (!produced_tasks) {
            std::unique_lock<std::mutex> wait_lock(scheduler_mutex_);
            scheduler_cv_.wait_for(wait_lock, std::chrono::milliseconds(2));
        }
    }

    std::cout << "[Scheduler-TS] Thread stopped" << std::endl;
}

void SpecializedThreadEngine::workerThreadTS(size_t id) {
    std::cout << "[Worker-TS-" << id << "] Thread started" << std::endl;

    size_t result_queue_id = id;
    size_t local_executions = 0;

    while (running_.load()) {
        FuzzTask task;
        if (!waitAndPopTask(id, task)) {
            continue;
        }

        TaskResult result;
        executeTask(task, result, id);
        result_queues_[result_queue_id]->submit(result);

        total_executions_.fetch_add(1);
        worker_executions_.fetch_add(1);
        local_executions++;
    }

    std::cout << "[Worker-TS-" << id << "] Thread stopped (executions: " << local_executions << ")" << std::endl;
}

void SpecializedThreadEngine::explorerThreadTS(size_t id) {
    std::cout << "[Explorer-TS-" << id << "] Thread started" << std::endl;

    size_t result_queue_id = num_workers_ + id;
    size_t local_executions = 0;

    std::random_device rd;
    std::mt19937 rng(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));

    while (running_.load()) {
        if (ts_arms_.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        size_t micro = std::max<size_t>(1, config_.micro_batch_explorers);
        std::uniform_int_distribution<size_t> arm_dist(0, ts_arms_.size() - 1);
        const auto& arm = ts_arms_[arm_dist(rng)];

        std::vector<TaskResult> batch_results;
        batch_results.reserve(micro);

        for (size_t i = 0; i < micro && running_.load(); ++i) {
            auto seed = getSeedFromCorpusForSchedule(arm, rng);
            if (!seed) break;

            AlgorithmCombination combo = buildTsCombination(arm, /*explorer=*/true, rng);

            FuzzTask task;
            task.combination = std::move(combo);
            task.seed = std::move(seed);
            task.task_id = task_id_counter_.fetch_add(1);

            TaskResult result;
            executeTask(task, result, num_workers_ + id);
            batch_results.push_back(std::move(result));
        }

        if (!batch_results.empty()) {
            result_queues_[result_queue_id]->submitBatch(batch_results);
            total_executions_.fetch_add(batch_results.size());
            explorer_executions_.fetch_add(batch_results.size());
            local_executions += batch_results.size();
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }

        std::this_thread::sleep_for(std::chrono::microseconds(500));
    }

    std::cout << "[Explorer-TS-" << id << "] Thread stopped (executions: " << local_executions << ")" << std::endl;
}

// ============================================================================
// MOpt (PSO) learning mode implementation
// ============================================================================

void SpecializedThreadEngine::schedulerThreadMOpt() {
    std::cout << "[Scheduler-MOpt] Thread started - PSO learning active" << std::endl;

    auto last_stats_time = std::chrono::steady_clock::now();
    size_t last_total_executions = 0;

    while (running_.load()) {
        // 1) Process result queues, update MOpt learner
        for (auto& rq : result_queues_) {
            if (!rq) continue;
            auto results = rq->swapAndGet();
            for (const auto& result : results) {
                if (result.found_new_coverage) {
                    auto now = std::chrono::steady_clock::now().time_since_epoch();
                    last_new_cov_ns_.store(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
                }

                if (!mopt_learner_) continue;

                std::vector<size_t> seq;
                seq.reserve(result.combination.algorithm_names.size());
                for (const auto& name : result.combination.algorithm_names) {
                    auto it = mopt_operator_index_.find(name);
                    if (it != mopt_operator_index_.end()) {
                        seq.push_back(it->second);
                    }
                }
                if (!seq.empty()) {
                    mopt_learner_->update(seq, result.found_new_coverage, result.execution_time_ms);
                }
            }
        }

        // 2) Fill worker task queues
        size_t target_queue_depth = std::max<size_t>(1, config_.worker_queue_target_depth);
        bool produced_tasks = false;

        if (num_workers_ > 0 && mopt_learner_ && !mopt_operator_names_.empty()) {
            for (size_t i = 0; i < num_workers_ && running_.load(); ++i) {
                size_t worker_index = next_worker_to_fill_;
                next_worker_to_fill_ = (next_worker_to_fill_ + 1) % num_workers_;

                if (getQueueSize(worker_index) >= target_queue_depth) {
                    continue;
                }

                auto seed = getSeedFromCorpus();
                if (!seed) {
                    continue;
                }

                // Generate operator sequence (default 1, for operator-level comparison)
                auto seq_idx = mopt_learner_->generateSequence(
                    config_.mopt_min_sequence_length,
                    config_.mopt_max_sequence_length);

                AlgorithmCombination combo;
                combo.combination_mode = "sequential";
                combo.algorithm_names.reserve(seq_idx.size());
                for (size_t idx : seq_idx) {
                    if (idx < mopt_operator_names_.size()) {
                        combo.algorithm_names.push_back(mopt_operator_names_[idx]);
                    }
                }
                if (combo.algorithm_names.empty()) {
                    combo.algorithm_names.push_back(mopt_operator_names_[0]);
                }

                FuzzTask task;
                task.combination = std::move(combo);
                task.seed = std::move(seed);
                task.task_id = task_id_counter_.fetch_add(1);

                enqueueTask(worker_index, std::move(task));
                scheduler_decisions_.fetch_add(1);
                produced_tasks = true;
            }
        }

        // 3) Periodically print brief statistics
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time);
        if (elapsed.count() >= 5) {
            size_t current_total = total_executions_.load();
            size_t exec_in_period = current_total - last_total_executions;
            double exec_per_sec = static_cast<double>(exec_in_period) / (elapsed.count() > 0 ? elapsed.count() : 1);

            size_t covered_edges = coverage_callback_ ? coverage_callback_() : 0;
            std::cout << "[MOpt-Stats] Execs: " << current_total
                      << " | Speed: " << std::fixed << std::setprecision(0) << exec_per_sec << "/s"
                      << " | Coverage: " << covered_edges << " edges"
                      << std::endl;

            // Print probability distribution summary every 10000 executions
            if (mopt_learner_ && current_total > 0 && (current_total % 10000) < exec_in_period) {
                std::cout << mopt_learner_->getStatisticsReport(8) << std::endl;
            }

            last_stats_time = now;
            last_total_executions = current_total;
        }

        if (!running_.load()) {
            break;
        }

        if (!produced_tasks) {
            std::unique_lock<std::mutex> wait_lock(scheduler_mutex_);
            scheduler_cv_.wait_for(wait_lock, std::chrono::milliseconds(2));
        }
    }

    std::cout << "[Scheduler-MOpt] Thread stopped" << std::endl;
}

void SpecializedThreadEngine::workerThreadMOpt(size_t id) {
    std::cout << "[Worker-MOpt-" << id << "] Thread started" << std::endl;

    size_t result_queue_id = id;
    size_t local_executions = 0;

    while (running_.load()) {
        FuzzTask task;
        if (!waitAndPopTask(id, task)) {
            continue;
        }

        TaskResult result;
        executeTask(task, result, id);
        result_queues_[result_queue_id]->submit(result);

        total_executions_.fetch_add(1);
        worker_executions_.fetch_add(1);
        local_executions++;
    }

    std::cout << "[Worker-MOpt-" << id << "] Thread stopped (executions: " << local_executions << ")" << std::endl;
}

void SpecializedThreadEngine::explorerThreadMOpt(size_t id) {
    std::cout << "[Explorer-MOpt-" << id << "] Thread started" << std::endl;

    size_t result_queue_id = num_workers_ + id;
    size_t local_executions = 0;

    std::random_device rd;
    std::mt19937 rng(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));

    while (running_.load()) {
        auto seed = getSeedFromCorpus();
        if (!seed) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (mopt_operator_names_.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        size_t min_len = std::max<size_t>(1, config_.mopt_min_sequence_length);
        size_t max_len = std::max<size_t>(1, config_.mopt_max_sequence_length);
        if (min_len > max_len) std::swap(min_len, max_len);

        std::uniform_int_distribution<size_t> len_dist(min_len, max_len);
        std::uniform_int_distribution<size_t> op_dist(0, mopt_operator_names_.size() - 1);

        size_t len = len_dist(rng);

        AlgorithmCombination combo;
        combo.combination_mode = "sequential";
        combo.algorithm_names.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            combo.algorithm_names.push_back(mopt_operator_names_[op_dist(rng)]);
        }

        FuzzTask task;
        task.combination = std::move(combo);
        task.seed = std::move(seed);
        task.task_id = task_id_counter_.fetch_add(1);

        TaskResult result;
        executeTask(task, result, num_workers_ + id);
        result_queues_[result_queue_id]->submit(result);

        total_executions_.fetch_add(1);
        explorer_executions_.fetch_add(1);
        local_executions++;
    }

    std::cout << "[Explorer-MOpt-" << id << "] Thread stopped (executions: " << local_executions << ")" << std::endl;
}

double SpecializedThreadEngine::getCoveragePercentage() const {
    if (!coverage_tracker_) {
        return 0.0;
    }
    // TODO: Implement coverage calculation
    return 0.0;
}

size_t SpecializedThreadEngine::getUniqueCrashes() const {
    // TODO: Implement crash statistics
    return 0;
}

// ========== TrioFuzz Unified: Three-layer learning architecture ==========

void SpecializedThreadEngine::schedulerThreadTrioFuzz() {
    std::cout << "[Scheduler-TrioFuzz] Thread started - Three-layer learning active" << std::endl;

    std::random_device rd;
    std::mt19937 rng(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));

    auto last_stats_time = std::chrono::steady_clock::now();
    size_t last_total_executions = 0;

    // Cache for storing tasks to track their results
    std::unordered_map<size_t, triofuzz::TrioFuzzUnifiedLearner::Task> pending_tasks;

    while (running_.load()) {
        // 1) Process results: update all three learning layers
        for (auto& rq : result_queues_) {
            if (!rq) continue;
            auto results = rq->swapAndGet();
            for (const auto& result : results) {
                if (result.found_new_coverage) {
                    auto now = std::chrono::steady_clock::now().time_since_epoch();
                    last_new_cov_ns_.store(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
                }

                // EcoFuzz bookkeeping (cycle tracking + dynamic energy adaptation).
                if (result.ecofuzz_cycle_id != 0 && result.seed_hash != 0) {
                    std::lock_guard<std::mutex> lock(ecofuzz_mutex_);

                    auto st_it = ecofuzz_seed_stats_.find(result.seed_hash);
                    if (st_it != ecofuzz_seed_stats_.end()) {
                        auto& st = st_it->second;

                        st.mutation_num++;
                        if (!result.found_new_coverage) {
                            st.exec_by_mutation++;
                        }

                        ecofuzz_global_.total_fuzz++;
                        if (st.n_fuzz_entry < ecofuzz_global_.n_fuzz.size() &&
                            ecofuzz_global_.n_fuzz[st.n_fuzz_entry] != 0xFFFFFFFFu) {
                            ecofuzz_global_.n_fuzz[st.n_fuzz_entry]++;
                        }

                        auto cyc_it = ecofuzz_cycles_.find(result.ecofuzz_cycle_id);
                        if (cyc_it != ecofuzz_cycles_.end()) {
                            auto& cyc = cyc_it->second;
                            cyc.results_seen++;
                            if (result.found_new_coverage) {
                                cyc.found_count++;
                                cyc.record_num = cyc.results_seen;
                                ecofuzz_global_.path_increase++;
                            }

                            if (cyc.results_seen >= cyc.assigned_energy) {
                                st.last_found = cyc.found_count;
                                st.last_energy = static_cast<uint32_t>(st.mutation_num - cyc.start_mutation_num);
                                st.fuzz_level++;

                                float regret = 0.0f;
                                if (cyc.results_seen > 0) {
                                    regret = static_cast<float>(cyc.record_num) /
                                             static_cast<float>(cyc.results_seen);
                                }
                                if (regret == 0.0f) {
                                    regret = 1.1f;
                                }

                                ecofuzz_global_.rate =
                                    ((ecofuzz_global_.rate * static_cast<float>(ecofuzz_global_.calculate_coe)) + regret) /
                                    static_cast<float>(ecofuzz_global_.calculate_coe + 1);
                                ecofuzz_global_.calculate_coe++;

                                const uint64_t corpus_limit =
                                    (ecofuzz_seed_pool_.empty() ? 0 : (ecofuzz_seed_pool_.size() / 100));
                                if (ecofuzz_global_.calculate_coe > corpus_limit) {
                                    ecofuzz_global_.calculate_coe = corpus_limit;
                                }

                                if (ecofuzz_global_.rate > 1.5f) {
                                    ecofuzz_global_.rate = 1.5f;
                                } else if (ecofuzz_global_.rate < 0.1f) {
                                    ecofuzz_global_.rate = 0.1f;
                                }

                                ecofuzz_cycles_.erase(cyc_it);
                            }
                        }
                    }
                }

                // Find and update the corresponding task
                if (triofuzz_learner_) {
                    auto it = pending_tasks.find(result.task_id);
                    if (it != pending_tasks.end()) {
                        triofuzz_learner_->processResult(it->second, result.found_new_coverage);
                        pending_tasks.erase(it);
                    }
                }
            }
        }

        // 2) Fill worker queues with tasks
        size_t target_queue_depth = std::max<size_t>(1, config_.worker_queue_target_depth);
        bool produced_tasks = false;

        if (num_workers_ > 0 && triofuzz_learner_) {
	            for (size_t i = 0; i < num_workers_ && running_.load(); ++i) {
                size_t worker_index = next_worker_to_fill_;
                next_worker_to_fill_ = (next_worker_to_fill_ + 1) % num_workers_;

                if (getQueueSize(worker_index) >= target_queue_depth) continue;

	                // Generate tasks to fill the queue
	                size_t tasks_needed = target_queue_depth - getQueueSize(worker_index);
		                for (size_t t = 0; t < tasks_needed && running_.load(); ++t) {
		                    auto task_info = triofuzz_learner_->generateWorkerTask(
		                        /*allow_analysis=*/worker_analysis_enabled());

		                    FuzzTask task;
		                    task.task_id = task_id_counter_.fetch_add(1);
	                    {
	                        auto sel = getSeedFromCorpusForTrioSchedule(task_info.power_schedule, rng);
                        task.seed = std::move(sel.seed);
                        task.seed_hash = sel.seed_hash;
                        task.ecofuzz_cycle_id = sel.ecofuzz_cycle_id;
                    }
                    if (!task.seed) {
                        continue;
                    }
                    // Set scheduler name based on mode
                    if (task_info.use_analysis) {
                        task.combination.scheduler_name = task_info.power_schedule + "_analysis";
                    } else {
                        task.combination.scheduler_name = task_info.power_schedule +
                            (task_info.use_mopt ? "_mopt" : "_havoc") +
                            (task_info.splice_enabled ? "_splice" : "");
                    }
                    task.combination.combination_mode = "sequential";

                    // Convert operator indices to algorithm names
                    if (task_info.use_analysis) {
                        // Analysis mode: use analysis algorithms (cmplog/redqueen/dictionary)
                        // operator_sequence stores analysis operator indices (0-3)
                        const auto& analysis_ops = kTriofuzzAnalysisOps;
                        for (size_t op_idx : task_info.operator_sequence) {
                            if (op_idx < analysis_ops.size()) {
                                task.combination.algorithm_names.push_back(analysis_ops[op_idx]);
                            } else {
                                task.combination.algorithm_names.push_back(analysis_ops[op_idx % analysis_ops.size()]);
                            }
                        }
                    } else if (task_info.use_mopt) {
                        // MOpt mode: mopt_* operators (19 operators, indices 0-18)
                        const auto& mopt_ops = task_info.splice_enabled ? kTriofuzzMoptOpsWithSplice : kTriofuzzMoptOpsNoSplice;
                        for (size_t op_idx : task_info.operator_sequence) {
                            if (op_idx < mopt_ops.size()) {
                                task.combination.algorithm_names.push_back(mopt_ops[op_idx]);
                            } else {
                                task.combination.algorithm_names.push_back(mopt_ops[op_idx % mopt_ops.size()]);
                            }
                        }
                    } else {
                        // Havoc mode: mut_* operators (37 operators with splice, indices 0-36)
                        const auto& ops = task_info.splice_enabled ? kTsHavocOpsWithSplice : kTsHavocOpsNoSplice;
                        for (size_t op_idx : task_info.operator_sequence) {
                            if (op_idx < ops.size()) {
                                task.combination.algorithm_names.push_back(ops[op_idx]);
                            } else {
                                task.combination.algorithm_names.push_back(ops[op_idx % ops.size()]);
                            }
                        }
                    }

                    // Store task for result tracking
                    pending_tasks[task.task_id] = task_info;

                    enqueueTask(worker_index, std::move(task));
                    produced_tasks = true;
                }
            }
        }

        // Cleanup old pending tasks (timeout after 60 seconds)
        if (pending_tasks.size() > 10000) {
            size_t current_task_id = task_id_counter_.load();
            for (auto it = pending_tasks.begin(); it != pending_tasks.end();) {
                if (current_task_id - it->first > 100000) {
                    it = pending_tasks.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // 3) Periodic stats
        auto now = std::chrono::steady_clock::now();
        auto stats_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count();
        if (stats_elapsed >= 30) {
            size_t current_executions = total_executions_.load();
            size_t exec_diff = current_executions - last_total_executions;
            double exec_per_sec = static_cast<double>(exec_diff) / static_cast<double>(stats_elapsed);

            std::cout << "[TrioFuzz] Total: " << current_executions
                      << " | Rate: " << std::fixed << std::setprecision(1) << exec_per_sec << " exec/s"
                      << std::endl;

            if (triofuzz_learner_) {
                triofuzz_learner_->printStats();
            }

            last_stats_time = now;
            last_total_executions = current_executions;
        }

        if (!produced_tasks) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }

    std::cout << "[Scheduler-TrioFuzz] Thread stopped" << std::endl;
}

void SpecializedThreadEngine::workerThreadTrioFuzz(size_t id) {
    std::cout << "[Worker-TrioFuzz-" << id << "] Thread started" << std::endl;

    size_t local_executions = 0;
    std::vector<TaskResult> local_results;
    local_results.reserve(config_.micro_batch_workers);

    while (running_.load()) {
        FuzzTask task;
        if (!waitAndPopTask(id, task)) {
            if (!running_.load()) break;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
            continue;
        }

        // Execute the task
        TaskResult result;
        executeTask(task, result, id);

        local_results.push_back(result);

        if (local_results.size() >= config_.micro_batch_workers) {
            submitResultsBatch(local_results);
            local_results.clear();
        }

        total_executions_.fetch_add(1);
        worker_executions_.fetch_add(1);
        local_executions++;
    }

    // Flush remaining results
    if (!local_results.empty()) {
        submitResultsBatch(local_results);
    }

    std::cout << "[Worker-TrioFuzz-" << id << "] Thread stopped (executions: " << local_executions << ")" << std::endl;
}

void SpecializedThreadEngine::explorerThreadTrioFuzz(size_t id) {
    std::cout << "[Explorer-TrioFuzz-" << id << "] Thread started" << std::endl;

    std::random_device rd;
    std::mt19937 rng(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));

    size_t result_queue_id = num_workers_ + id;
    size_t local_executions = 0;

    while (running_.load()) {
        if (!triofuzz_learner_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        const size_t micro = std::max<size_t>(1, config_.micro_batch_explorers);
        std::vector<TaskResult> batch_results;
        batch_results.reserve(micro);

        for (size_t i = 0; i < micro && running_.load(); ++i) {
            // Generate exploration task
            auto task_info = triofuzz_learner_->generateExplorerTask();

            FuzzTask task;
            task.task_id = task_id_counter_.fetch_add(1);
            {
                auto sel = getSeedFromCorpusForTrioSchedule(task_info.power_schedule, rng);
                task.seed = std::move(sel.seed);
                task.seed_hash = sel.seed_hash;
                task.ecofuzz_cycle_id = sel.ecofuzz_cycle_id;
            }
            if (!task.seed) {
                break;
            }

            // Set scheduler name based on mode
            if (task_info.use_analysis) {
                task.combination.scheduler_name = task_info.power_schedule + "_analysis";
            } else {
                task.combination.scheduler_name = task_info.power_schedule +
                    (task_info.use_mopt ? "_mopt" : "_havoc") +
                    (task_info.splice_enabled ? "_splice" : "");
            }
            task.combination.combination_mode = "sequential";

            // Convert operator indices to algorithm names (same logic as scheduler)
            if (task_info.use_analysis) {
                // Analysis mode: use analysis algorithms
                const auto& analysis_ops = kTriofuzzAnalysisOps;
                for (size_t op_idx : task_info.operator_sequence) {
                    if (op_idx < analysis_ops.size()) {
                        task.combination.algorithm_names.push_back(analysis_ops[op_idx]);
                    } else {
                        task.combination.algorithm_names.push_back(analysis_ops[op_idx % analysis_ops.size()]);
                    }
                }
            } else if (task_info.use_mopt) {
                const auto& mopt_ops = task_info.splice_enabled ? kTriofuzzMoptOpsWithSplice : kTriofuzzMoptOpsNoSplice;
                for (size_t op_idx : task_info.operator_sequence) {
                    if (op_idx < mopt_ops.size()) {
                        task.combination.algorithm_names.push_back(mopt_ops[op_idx]);
                    } else {
                        task.combination.algorithm_names.push_back(mopt_ops[op_idx % mopt_ops.size()]);
                    }
                }
            } else {
                const auto& ops = task_info.splice_enabled ? kTsHavocOpsWithSplice : kTsHavocOpsNoSplice;
                for (size_t op_idx : task_info.operator_sequence) {
                    if (op_idx < ops.size()) {
                        task.combination.algorithm_names.push_back(ops[op_idx]);
                    } else {
                        task.combination.algorithm_names.push_back(ops[op_idx % ops.size()]);
                    }
                }
            }

            // Execute directly
            TaskResult result;
            executeTask(task, result, num_workers_ + id);

            // Update learner with result (for exploration)
            triofuzz_learner_->processResult(task_info, result.found_new_coverage);

            batch_results.push_back(std::move(result));
        }

        if (!batch_results.empty()) {
            if (result_queue_id < result_queues_.size() && result_queues_[result_queue_id]) {
                result_queues_[result_queue_id]->submitBatch(batch_results);
            } else if (!result_queues_.empty() && result_queues_[id % result_queues_.size()]) {
                result_queues_[id % result_queues_.size()]->submitBatch(batch_results);
            }
            total_executions_.fetch_add(batch_results.size());
            explorer_executions_.fetch_add(batch_results.size());
            local_executions += batch_results.size();
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    }

    std::cout << "[Explorer-TrioFuzz-" << id << "] Thread stopped (executions: " << local_executions << ")" << std::endl;
}

} // namespace triofuzz
