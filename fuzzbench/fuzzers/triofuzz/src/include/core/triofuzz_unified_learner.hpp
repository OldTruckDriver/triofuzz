#pragma once

/**
 * TrioFuzz Unified Learner
 *
 * Integrates three learning algorithms into a coordinated multi-layer system:
 *
 * Layer 1: Thompson Sampling (Outer - Configuration Selection)
 *   - Selects configuration arms (power schedule x mutation mode x splice)
 *   - Uses Beta distribution sampling
 *   - 16 arms: 4 schedules × 2 modes × 2 splice options
 *
 * Layer 2: MOpt PSO (Middle - Operator Probability)
 *   - Particle Swarm Optimization for operator weight learning
 *   - Active when configuration uses MOpt mode
 *   - 19 MOpt operators
 *
 * Layer 3: MuoFuzz Markov Chain (Inner - Operator Sequences)
 *   - Online transition probability learning P[prev][next]
 *   - Alias tables for O(1) sampling
 *   - Stack size selection with ε-Greedy
 *   - Operator count matches the active operator set
 *   - Stack size 2-16
 *
 * All learning is centralized in the Scheduler thread.
 * Workers and Explorers only execute pre-determined tasks.
 *
 * Hybrid Period Strategy (Non-stationary Adaptation):
 *   To handle slow targets where execution-based periods take too long,
 *   each learner uses a hybrid trigger: whichever comes first between
 *   execution count and time limit triggers the update. This ensures
 *   timely adaptation even for slow targets while preserving statistical
 *   reliability for fast targets.
 *
 *   | Layer   | Exec Period | Time Period | Min Samples |
 *   |---------|-------------|-------------|-------------|
 *   | TS      | 50,000      | 30 sec      | 100         |
 *   | MOpt    | 500,000     | 30 sec      | 500         |
 *   | Markov  | 500         | 5 sec       | 50          |
 */

#include <atomic>
#include <array>
#include <vector>
#include <random>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include <functional>
#include <thread>
#include <iostream>

namespace triofuzz {

// ============================================================================
// Constants
// ============================================================================

// MuoFuzz Markov constants
constexpr size_t TRIOFUZZ_MIN_STACK = 2;
constexpr size_t TRIOFUZZ_MAX_STACK = 16;
constexpr double TRIOFUZZ_EPSILON_INITIAL = 1.0;
constexpr double TRIOFUZZ_EPSILON_FINAL = 0.5;
constexpr uint64_t TRIOFUZZ_EPSILON_DECAY_MS = 2ULL * 60 * 60 * 1000;  // 2 hours

// MOpt PSO constants
constexpr size_t TRIOFUZZ_MOPT_NUM_OPERATORS = 19;

// TS (config-level) constants
// Note: The unified learner's arm set is intentionally aligned with
// the TS configuration space:
//   - schedules: fast, explore, coe, ecofuzz
//   - mutation modes: havoc, mopt
//   - splice: enabled for fast/explore/coe; disabled for ecofuzz
// This yields 14 arms (3 schedules * 2 modes * 2 splice + 1 schedule * 2 modes).
constexpr size_t TRIOFUZZ_NUM_MUTATION_MODES = 2;   // havoc, mopt
constexpr size_t TRIOFUZZ_NUM_SPLICE_OPTIONS = 2;   // on, off (where supported)

// Stagnation detection constants
constexpr uint32_t TRIOFUZZ_STAGNATION_WINDOW_SEC = 300;     // 5 minutes detection window
constexpr double TRIOFUZZ_STAGNATION_THRESHOLD = 0.001;      // 0.1% coverage gain threshold
constexpr double TRIOFUZZ_STAGNATION_EXPLORE_BOOST = 0.3;    // 30% exploration boost on stagnation

// Hybrid period constants (for non-stationary adaptation)
// Time periods ensure learning happens even for slow targets
constexpr uint32_t TRIOFUZZ_TS_TIME_PERIOD_SEC = 30;    // TS: 30 seconds
constexpr uint32_t TRIOFUZZ_MOPT_TIME_PERIOD_SEC = 30;     // MOpt PSO: 30 seconds
constexpr uint32_t TRIOFUZZ_MARKOV_TIME_PERIOD_SEC = 5;    // Markov: 5 seconds

// Minimum samples required for time-triggered updates (noise protection)
constexpr size_t TRIOFUZZ_TS_MIN_SAMPLES = 100;
constexpr size_t TRIOFUZZ_MOPT_MIN_SAMPLES = 500;
constexpr size_t TRIOFUZZ_MARKOV_MIN_SAMPLES = 50;

// ============================================================================
// TS Configuration Arm
// ============================================================================

struct TrioFuzzConfigArm {
    size_t index;
    std::string power_schedule;  // "fast", "coe", "explore", "ecofuzz"
    bool use_mopt;               // true=mopt, false=havoc
    bool splice_enabled;
    bool use_analysis;           // true=use analysis algorithms (cmplog/redqueen/dictionary)

    std::string toString() const {
        if (use_analysis) {
            return power_schedule + "_analysis";
        }
        return power_schedule + "_" + (use_mopt ? "mopt" : "havoc") +
               (splice_enabled ? "_splice" : "_nosplice");
    }
};

inline std::vector<TrioFuzzConfigArm> getTrioFuzzConfigArms(bool enable_ecofuzz = true) {
    std::vector<TrioFuzzConfigArm> arms;
    std::vector<std::string> schedules;
    schedules.reserve(enable_ecofuzz ? 4 : 3);
    schedules.push_back("fast");
    if (enable_ecofuzz) schedules.push_back("ecofuzz");
    schedules.push_back("explore");
    schedules.push_back("coe");

    size_t idx = 0;
    for (const auto& sched : schedules) {
        for (bool mopt : {false, true}) {
            if (sched == "ecofuzz") {
                // Match TS config: EcoFuzz does not support splice configs.
                arms.push_back({idx++, sched, mopt, /*splice_enabled=*/false, /*use_analysis=*/false});
                continue;
            }
            for (bool splice : {false, true}) {
                arms.push_back({idx++, sched, mopt, splice, /*use_analysis=*/false});
            }
        }
    }

    // Analysis arm: advanced analysis algorithms (cmplog/redqueen/smart_dictionary/runtime_dictionary)
    // Only one arm added, using explore schedule (analysis algorithms are inherently explorative)
    // These algorithms have longer execution times (1-50ms) but can discover complex constraints and magic bytes
    arms.push_back({idx++, "explore", /*use_mopt=*/false, /*splice_enabled=*/false, /*use_analysis=*/true});

    return arms;
}

// ============================================================================
// Layer 1: Thompson Sampling (with Hybrid Period Support)
// ============================================================================

class TrioFuzzTS {
public:
    struct ArmStats {
        std::atomic<double> alpha{1.0};
        std::atomic<double> beta{1.0};
        std::atomic<uint64_t> uses{0};
        std::atomic<uint64_t> finds{0};

        void updateWindow(uint64_t window_finds, uint64_t window_fail, double decay = 0.95) {
            const double a_prev = alpha.load(std::memory_order_relaxed);
            const double b_prev = beta.load(std::memory_order_relaxed);

            // Exponentially-decayed Beta-Binomial update.
            // NOTE: To keep Thompson sampling meaningful, we must preserve the ratio alpha/(alpha+beta)
            // (the posterior mean). We therefore rescale (alpha, beta) together instead of clamping
            // them independently, which would otherwise collapse all arms to ~0.5 mean.
            double a = 1.0 + (a_prev - 1.0) * decay + static_cast<double>(window_finds);
            double b = 1.0 + (b_prev - 1.0) * decay + static_cast<double>(window_fail);

            constexpr double kMin = 1e-6;
            constexpr double kMaxSum = 50.0;  // keep TS sampling cheap while preserving the mean

            a = std::max(kMin, a);
            b = std::max(kMin, b);

            const double total = a + b;
            if (total > kMaxSum) {
                const double scale = kMaxSum / total;
                a *= scale;
                b *= scale;
            }

            alpha.store(a, std::memory_order_relaxed);
            beta.store(b, std::memory_order_relaxed);
        }

        double sample(std::mt19937& rng) const {
            const double a_shape = std::max(1e-6, alpha.load(std::memory_order_relaxed));
            const double b_shape = std::max(1e-6, beta.load(std::memory_order_relaxed));
            std::gamma_distribution<double> ga(a_shape, 1.0);
            std::gamma_distribution<double> gb(b_shape, 1.0);
            const double a = ga(rng);
            const double b = gb(rng);
            return (a + b > 0) ? a / (a + b) : 0.5;
        }

        double mean() const {
            const double a = alpha.load(std::memory_order_relaxed);
            const double b = beta.load(std::memory_order_relaxed);
            return a / (a + b);
        }
    };

private:
    std::vector<TrioFuzzConfigArm> arms_;
    std::vector<std::unique_ptr<ArmStats>> stats_;
    double decay_ = 0.95;
    size_t update_period_ = 50000;
    std::atomic<uint64_t> total_execs_{0};
    std::vector<uint64_t> window_execs_;
    std::vector<uint64_t> window_finds_;
    std::mutex mtx_;

    // Hybrid period support: time-based trigger for slow targets
    std::chrono::seconds time_period_{TRIOFUZZ_TS_TIME_PERIOD_SEC};
    size_t min_samples_ = TRIOFUZZ_TS_MIN_SAMPLES;
    std::vector<std::chrono::steady_clock::time_point> last_update_time_;
    std::atomic<uint64_t> time_triggered_updates_{0};

    // Stagnation detection and recovery
    std::chrono::steady_clock::time_point stagnation_check_time_;
    uint64_t stagnation_check_finds_{0};
    std::atomic<double> exploration_boost_{0.0};  // Additional exploration probability
    std::atomic<uint64_t> stagnation_resets_{0};
    std::chrono::seconds stagnation_window_{TRIOFUZZ_STAGNATION_WINDOW_SEC};
    double stagnation_threshold_ = TRIOFUZZ_STAGNATION_THRESHOLD;

    static thread_local std::mt19937 rng_;
    static thread_local bool rng_init_;

public:
    explicit TrioFuzzTS(bool enable_ecofuzz = true) {
        arms_ = getTrioFuzzConfigArms(enable_ecofuzz);
        auto now = std::chrono::steady_clock::now();
        for (size_t i = 0; i < arms_.size(); ++i) {
            stats_.push_back(std::make_unique<ArmStats>());
            last_update_time_.push_back(now);
        }
        window_execs_.assign(arms_.size(), 0);
        window_finds_.assign(arms_.size(), 0);
        stagnation_check_time_ = now;
        stagnation_check_finds_ = 0;
    }

    void setDecay(double d) { decay_ = d; }
    void setUpdatePeriod(size_t p) { update_period_ = std::max<size_t>(1, p); }
    void setTimePeriod(uint32_t sec) { time_period_ = std::chrono::seconds(sec); }
    void setMinSamples(size_t n) { min_samples_ = n; }
    void setStagnationWindow(uint32_t sec) { stagnation_window_ = std::chrono::seconds(sec); }
    void setStagnationThreshold(double t) { stagnation_threshold_ = t; }
    size_t numArms() const { return arms_.size(); }
    const TrioFuzzConfigArm& getArm(size_t i) const { return arms_[i]; }
    uint64_t getTotalExecs() const { return total_execs_.load(std::memory_order_relaxed); }
    uint64_t getTimeTriggeredUpdates() const { return time_triggered_updates_.load(std::memory_order_relaxed); }
    uint64_t getStagnationResets() const { return stagnation_resets_.load(std::memory_order_relaxed); }
    double getExplorationBoost() const { return exploration_boost_.load(std::memory_order_relaxed); }
    double getArmMean(size_t i) const { return (i < stats_.size()) ? stats_[i]->mean() : 0.0; }
    uint64_t getArmUses(size_t i) const {
        return (i < stats_.size()) ? stats_[i]->uses.load(std::memory_order_relaxed) : 0;
    }
    uint64_t getArmFinds(size_t i) const {
        return (i < stats_.size()) ? stats_[i]->finds.load(std::memory_order_relaxed) : 0;
    }

	    const TrioFuzzConfigArm& getTopArm() const {
	        size_t best_arm = 0;
	        double best_mean = 0.0;
	        for (size_t i = 0; i < stats_.size(); ++i) {
	            double m = stats_[i]->mean();
	            if (m > best_mean) { best_mean = m; best_arm = i; }
	        }
	        return arms_[best_arm];
	    }

    size_t selectArm() { return selectArm(/*allow_analysis=*/true); }

    size_t selectArm(bool allow_analysis) {
        ensureRng();

        // Check for exploration boost (from stagnation recovery)
        double boost = exploration_boost_.load(std::memory_order_relaxed);
        if (boost > 0.0 && std::uniform_real_distribution<double>(0, 1)(rng_) < boost) {
            // Random exploration: select uniformly from underused arms
            std::vector<size_t> candidates;
            uint64_t avg_uses = 0;
            size_t count = 0;
            for (size_t i = 0; i < stats_.size(); ++i) {
                if (!allow_analysis && arms_[i].use_analysis) continue;
                avg_uses += stats_[i]->uses.load(std::memory_order_relaxed);
                count++;
            }
            avg_uses = count > 0 ? avg_uses / count : 0;

            // Prefer underused arms (below average usage)
            for (size_t i = 0; i < stats_.size(); ++i) {
                if (!allow_analysis && arms_[i].use_analysis) continue;
                if (stats_[i]->uses.load(std::memory_order_relaxed) <= avg_uses) {
                    candidates.push_back(i);
                }
            }
            if (candidates.empty()) {
                // Fallback to all candidates
                for (size_t i = 0; i < stats_.size(); ++i) {
                    if (!allow_analysis && arms_[i].use_analysis) continue;
                    candidates.push_back(i);
                }
            }
            if (!candidates.empty()) {
                return candidates[std::uniform_int_distribution<size_t>(0, candidates.size() - 1)(rng_)];
            }
        }

        // Normal Thompson Sampling with UCB1 exploration bonus
        double best = -1.0;
        size_t best_arm = 0;
        bool found_candidate = false;
        uint64_t total_pulls = total_execs_.load(std::memory_order_relaxed);

        for (size_t i = 0; i < stats_.size(); ++i) {
            if (!allow_analysis && arms_[i].use_analysis) continue;

            // Thompson Sampling score
            double ts_score = stats_[i]->sample(rng_);

            // UCB1 exploration bonus: sqrt(2 * ln(N) / n_i)
            // This prevents arms from being "starved"
            uint64_t arm_pulls = stats_[i]->uses.load(std::memory_order_relaxed);
            double ucb_bonus = 0.0;
            if (total_pulls > 0 && arm_pulls > 0) {
                ucb_bonus = std::sqrt(2.0 * std::log(static_cast<double>(total_pulls)) / arm_pulls);
            } else if (arm_pulls == 0) {
                ucb_bonus = 10.0;  // High bonus for unexplored arms
            }

            // Combined score: TS + scaled UCB bonus
            // Scale UCB bonus to be comparable with TS score (0-1 range)
            double combined = ts_score + 0.1 * ucb_bonus;

            if (!found_candidate || combined > best) {
                best = combined;
                best_arm = i;
                found_candidate = true;
            }
        }
        return found_candidate ? best_arm : 0;
    }

    void update(size_t arm, bool found) {
        if (arm >= stats_.size()) return;

        stats_[arm]->uses.fetch_add(1, std::memory_order_relaxed);
        if (found) stats_[arm]->finds.fetch_add(1, std::memory_order_relaxed);
        total_execs_.fetch_add(1, std::memory_order_relaxed);

        std::lock_guard<std::mutex> lk(mtx_);

        window_execs_[arm] += 1;
        if (found) window_finds_[arm] += 1;

        // Hybrid trigger: execution count OR time, whichever comes first
        const size_t period = std::max<size_t>(1, update_period_);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_update_time_[arm];

        bool exec_trigger = (window_execs_[arm] >= period);
        bool time_trigger = (elapsed >= time_period_) && (window_execs_[arm] >= min_samples_);

        if (exec_trigger || time_trigger) {
            const uint64_t wf = window_finds_[arm];
            const uint64_t we = window_execs_[arm];
            const uint64_t wfail = (we >= wf) ? (we - wf) : 0;

            // Adaptive decay: when samples are insufficient, use stronger decay
            // to reduce influence of historical data
            double effective_decay = decay_;
            if (time_trigger && !exec_trigger) {
                double sample_ratio = static_cast<double>(we) / period;
                // Stronger decay when fewer samples (less trust in history)
                effective_decay = decay_ * std::min(1.0, std::sqrt(sample_ratio));
                time_triggered_updates_.fetch_add(1, std::memory_order_relaxed);
            }

            stats_[arm]->updateWindow(wf, wfail, effective_decay);
            window_execs_[arm] = 0;
            window_finds_[arm] = 0;
            last_update_time_[arm] = now;
        }

        // Stagnation detection: check every stagnation_window_ seconds
        auto stagnation_elapsed = now - stagnation_check_time_;
        if (stagnation_elapsed >= stagnation_window_) {
            checkAndHandleStagnation(now);
        }
    }

    /**
     * Check for coverage stagnation and trigger recovery if needed.
     * Called periodically from update().
     */
    void checkAndHandleStagnation(std::chrono::steady_clock::time_point now) {
        // Calculate total finds since last check
        uint64_t current_finds = 0;
        for (const auto& stat : stats_) {
            current_finds += stat->finds.load(std::memory_order_relaxed);
        }

        uint64_t finds_delta = current_finds - stagnation_check_finds_;
        uint64_t execs_delta = total_execs_.load(std::memory_order_relaxed);

        // Calculate find rate (proxy for coverage gain)
        double find_rate = execs_delta > 0 ? static_cast<double>(finds_delta) / execs_delta : 0.0;

        // Check if we're in stagnation (very low find rate)
        bool is_stagnating = (find_rate < stagnation_threshold_) && (execs_delta > min_samples_ * 10);

        if (is_stagnating) {
            // Trigger stagnation recovery
            triggerStagnationRecovery();
        } else {
            // Gradually decay exploration boost when not stagnating
            double current_boost = exploration_boost_.load(std::memory_order_relaxed);
            if (current_boost > 0.0) {
                // Decay boost by 50% each window
                exploration_boost_.store(current_boost * 0.5, std::memory_order_relaxed);
                if (current_boost * 0.5 < 0.01) {
                    exploration_boost_.store(0.0, std::memory_order_relaxed);
                }
            }
        }

        // Update check point
        stagnation_check_time_ = now;
        stagnation_check_finds_ = current_finds;
    }

    /**
     * Trigger stagnation recovery: reset TS parameters and boost exploration.
     */
    void triggerStagnationRecovery() {
        stagnation_resets_.fetch_add(1, std::memory_order_relaxed);

        // Strategy 1: Boost exploration probability
        // This forces random selection of underused arms
        exploration_boost_.store(TRIOFUZZ_STAGNATION_EXPLORE_BOOST, std::memory_order_relaxed);

        // Strategy 2: Partial reset of TS parameters for dominant arms
        // Find the dominant arm (highest usage)
        size_t dominant_arm = 0;
        uint64_t max_uses = 0;
        uint64_t total_uses = 0;
        for (size_t i = 0; i < stats_.size(); ++i) {
            uint64_t uses = stats_[i]->uses.load(std::memory_order_relaxed);
            total_uses += uses;
            if (uses > max_uses) {
                max_uses = uses;
                dominant_arm = i;
            }
        }

        // If one arm dominates (>50% of total uses), partially reset it
        if (total_uses > 0 && max_uses > total_uses / 2) {
            // Soften the dominant arm's posterior to encourage exploration
            // Move alpha/beta closer to uniform prior (1, 1)
            double a = stats_[dominant_arm]->alpha.load(std::memory_order_relaxed);
            double b = stats_[dominant_arm]->beta.load(std::memory_order_relaxed);

            // Blend with uniform prior: 70% current + 30% uniform
            double new_a = 0.7 * a + 0.3 * 1.0;
            double new_b = 0.7 * b + 0.3 * 1.0;

            stats_[dominant_arm]->alpha.store(new_a, std::memory_order_relaxed);
            stats_[dominant_arm]->beta.store(new_b, std::memory_order_relaxed);

            std::cout << "[TS] Stagnation recovery: softened dominant arm "
                      << arms_[dominant_arm].toString()
                      << " (uses=" << max_uses << "/" << total_uses << ")"
                      << " exploration_boost=" << TRIOFUZZ_STAGNATION_EXPLORE_BOOST
                      << std::endl;
        } else {
            std::cout << "[TS] Stagnation recovery: boosted exploration to "
                      << TRIOFUZZ_STAGNATION_EXPLORE_BOOST << std::endl;
        }
    }

    std::string report() const {
        std::ostringstream oss;
        oss << "[TS] Execs: " << total_execs_.load()
            << " TimeTriggeredUpdates: " << time_triggered_updates_.load()
            << " StagnationResets: " << stagnation_resets_.load()
            << " ExploreBoost: " << std::fixed << std::setprecision(2)
            << exploration_boost_.load() << "\n";
        for (size_t i = 0; i < arms_.size(); ++i) {
            oss << "  [" << i << "] " << arms_[i].toString()
                << " mean=" << std::fixed << std::setprecision(3) << stats_[i]->mean()
                << " uses=" << stats_[i]->uses.load()
                << " finds=" << stats_[i]->finds.load() << "\n";
        }
        return oss.str();
    }

private:
    static void ensureRng() {
        if (!rng_init_) {
            std::random_device rd;
            rng_.seed(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
            rng_init_ = true;
        }
    }
};

inline thread_local std::mt19937 TrioFuzzTS::rng_;
inline thread_local bool TrioFuzzTS::rng_init_ = false;

// ============================================================================
// Layer 2: MOpt PSO Learner (with Hybrid Period Support)
// ============================================================================

class TrioFuzzMOptPSO {
public:
    struct Params {
        double w_init;
        double w_end;
        int g_max;
        double v_min;
        double v_max;
        size_t update_period;

        Params() : w_init(0.9), w_end(0.3), g_max(5000), v_min(0.05), v_max(1.0), update_period(500000) {}
    };

private:
    Params params_;
    size_t n_;
    std::vector<double> x_, v_, l_best_, g_best_, eff_best_, prob_;
    std::vector<uint64_t> finds_, cycles_, finds_prev_, cycles_prev_;
    int g_now_ = 0;
    uint64_t execs_ = 0, updates_ = 0;
    mutable std::shared_mutex mtx_;

    // Hybrid period support: time-based trigger for slow targets
    std::chrono::seconds time_period_{TRIOFUZZ_MOPT_TIME_PERIOD_SEC};
    size_t min_samples_ = TRIOFUZZ_MOPT_MIN_SAMPLES;
    std::chrono::steady_clock::time_point last_update_time_;
    uint64_t execs_since_update_ = 0;
    uint64_t time_triggered_updates_ = 0;

    static thread_local std::mt19937 rng_;
    static thread_local bool rng_init_;

public:
    explicit TrioFuzzMOptPSO(size_t n = TRIOFUZZ_MOPT_NUM_OPERATORS, Params p = Params())
        : params_(p), n_(n), x_(n, 0), v_(n, 0.1), l_best_(n, 0), g_best_(n, 0),
          eff_best_(n, 0), prob_(n, 0), finds_(n, 0), cycles_(n, 0),
          finds_prev_(n, 0), cycles_prev_(n, 0),
          last_update_time_(std::chrono::steady_clock::now()) {
        double u = 1.0 / n_;
        std::fill(x_.begin(), x_.end(), u);
        std::fill(prob_.begin(), prob_.end(), u);
        std::fill(l_best_.begin(), l_best_.end(), u);
        std::fill(g_best_.begin(), g_best_.end(), u);
    }

    void setUpdatePeriod(size_t p) { params_.update_period = p; }
    void setTimePeriod(uint32_t sec) { time_period_ = std::chrono::seconds(sec); }
    void setMinSamples(size_t n) { min_samples_ = n; }
    const std::vector<double>& probs() const { return prob_; }
    uint64_t getTimeTriggeredUpdates() const { return time_triggered_updates_; }

    std::vector<size_t> generateSequence(size_t len) {
        ensureRng();
        std::shared_lock<std::shared_mutex> lk(mtx_);
        std::vector<size_t> seq;
        seq.reserve(len);
        std::discrete_distribution<size_t> dist(prob_.begin(), prob_.end());
        for (size_t i = 0; i < len; ++i) seq.push_back(dist(rng_));
        return seq;
    }

    void update(const std::vector<size_t>& seq, bool found) {
        std::unique_lock<std::shared_mutex> lk(mtx_);
        execs_++;
        execs_since_update_++;
        for (size_t idx : seq) {
            if (idx >= n_) continue;
            cycles_[idx]++;
            if (found) finds_[idx]++;
        }

        // Hybrid trigger: execution count OR time, whichever comes first
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_update_time_;

        bool exec_trigger = (params_.update_period > 0) && (execs_since_update_ >= params_.update_period);
        bool time_trigger = (elapsed >= time_period_) && (execs_since_update_ >= min_samples_);

        if (exec_trigger || time_trigger) {
            // Calculate sample ratio for adaptive PSO parameters
            double sample_ratio = 1.0;
            if (time_trigger && !exec_trigger && params_.update_period > 0) {
                sample_ratio = static_cast<double>(execs_since_update_) / params_.update_period;
                time_triggered_updates_++;
            }
            updateProbsAdaptive(sample_ratio);
            execs_since_update_ = 0;
            last_update_time_ = now;
        }
    }

    std::string report() const {
        std::ostringstream oss;
        oss << "[MOpt PSO] Execs: " << execs_ << " Updates: " << updates_
            << " TimeTriggeredUpdates: " << time_triggered_updates_ << "\n";
        return oss.str();
    }

private:
    void updateProbsAdaptive(double sample_ratio = 1.0) {
        ensureRng();
        // Compute efficiency
        for (size_t i = 0; i < n_; ++i) {
            uint64_t df = finds_[i] - finds_prev_[i];
            uint64_t dc = cycles_[i] - cycles_prev_[i];
            if (dc > 0) {
                double eff = static_cast<double>(df) / dc;
                if (eff > eff_best_[i]) { eff_best_[i] = eff; l_best_[i] = x_[i]; }
            }
        }
        updates_++;
        g_now_++;
        if (params_.g_max > 0 && g_now_ > params_.g_max) g_now_ = 0;

        // Adaptive inertia weight based on sample ratio
        // When samples are insufficient, use higher inertia (more conservative)
        double w = params_.w_init;
        if (params_.g_max > 0) {
            w = (params_.w_init - params_.w_end) * (params_.g_max - g_now_) / params_.g_max + params_.w_end;
        }
        if (sample_ratio < 1.0) {
            // Increase inertia when samples are insufficient (more conservative)
            w = w + (1.0 - w) * (1.0 - sample_ratio) * 0.5;
        }

        uint64_t tf = 0;
        for (auto f : finds_) tf += f;
        if (tf > 0) {
            for (size_t i = 0; i < n_; ++i) {
                g_best_[i] = static_cast<double>(finds_[i]) / tf;
            }
        }

        // Adaptive learning factors based on sample ratio
        double c_factor = std::min(1.0, sample_ratio + 0.3);  // At least 0.3x learning rate

        std::uniform_real_distribution<double> uni(0, 1);
        double xsum = 0;
        for (size_t i = 0; i < n_; ++i) {
            double r1 = uni(rng_), r2 = uni(rng_);
            // Scale learning by c_factor when samples are insufficient
            v_[i] = w * v_[i] + c_factor * r1 * (l_best_[i] - x_[i]) + c_factor * r2 * (g_best_[i] - x_[i]);

            // Limit velocity when samples are insufficient to prevent oscillation
            double v_limit = params_.v_max * std::min(1.0, sample_ratio + 0.3);
            v_[i] = std::clamp(v_[i], -v_limit, v_limit);

            x_[i] = std::clamp(x_[i] + v_[i], params_.v_min, params_.v_max);
            xsum += x_[i];
        }
        if (xsum > 0) {
            for (size_t i = 0; i < n_; ++i) {
                prob_[i] = x_[i] / xsum;
                x_[i] = prob_[i];
            }
        }
        finds_prev_ = finds_;
        cycles_prev_ = cycles_;
    }

    // Legacy method for backward compatibility
    void updateProbs() {
        updateProbsAdaptive(1.0);
    }

    static void ensureRng() {
        if (!rng_init_) {
            std::random_device rd;
            rng_.seed(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
            rng_init_ = true;
        }
    }
};

inline thread_local std::mt19937 TrioFuzzMOptPSO::rng_;
inline thread_local bool TrioFuzzMOptPSO::rng_init_ = false;

// ============================================================================
// Layer 3: MuoFuzz Markov Chain Learner (with Hybrid Period Support)
// ============================================================================

class TrioFuzzMarkov {
private:
    struct TransStats {
        std::atomic<uint64_t> finds{0};
        std::atomic<uint64_t> uses{0};
    };

    size_t n_ = 0;
    std::vector<TransStats> trans_;
    std::vector<double> prob_;
    std::vector<double> alias_prob_;
    std::vector<uint32_t> alias_idx_;

    struct StackStats { std::atomic<uint64_t> finds{0}, uses{0}; };
    std::array<StackStats, TRIOFUZZ_MAX_STACK + 1> stack_stats_;
    std::atomic<size_t> best_stack_{TRIOFUZZ_MIN_STACK};

    std::chrono::steady_clock::time_point start_;
    size_t alias_interval_ = 500;
    std::atomic<uint64_t> since_update_{0};
    std::atomic<uint64_t> total_execs_{0}, total_finds_{0};
    mutable std::shared_mutex mtx_;

    // Hybrid period support: time-based trigger for slow targets
    std::chrono::seconds time_period_{TRIOFUZZ_MARKOV_TIME_PERIOD_SEC};
    size_t min_samples_ = TRIOFUZZ_MARKOV_MIN_SAMPLES;
    std::chrono::steady_clock::time_point last_update_time_;
    std::atomic<uint64_t> time_triggered_updates_{0};

    static thread_local std::mt19937 rng_;
    static thread_local bool rng_init_;

public:
    explicit TrioFuzzMarkov(size_t num_mutators)
        : n_(std::max<size_t>(1, num_mutators)),
          trans_(n_ * n_),
          prob_(n_ * n_),
          alias_prob_(n_ * n_),
          alias_idx_(n_ * n_),
          start_(std::chrono::steady_clock::now()),
          last_update_time_(std::chrono::steady_clock::now()) {
        initUniform();
    }

    size_t numMutators() const { return n_; }
    void setAliasInterval(size_t n) { alias_interval_ = n; }
    void setTimePeriod(uint32_t sec) { time_period_ = std::chrono::seconds(sec); }
    void setMinSamples(size_t n) { min_samples_ = n; }
    uint64_t getTimeTriggeredUpdates() const { return time_triggered_updates_.load(std::memory_order_relaxed); }

    double epsilon() const {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_).count();
        return (static_cast<uint64_t>(ms) >= TRIOFUZZ_EPSILON_DECAY_MS) ?
               TRIOFUZZ_EPSILON_FINAL : TRIOFUZZ_EPSILON_INITIAL;
    }

    size_t selectNext(int prev) {
        ensureRng();
        if (prev < 0 || prev >= static_cast<int>(n_)) {
            return std::uniform_int_distribution<size_t>(0, n_ - 1)(rng_);
        }
        return sampleAlias(static_cast<size_t>(prev));
    }

    size_t selectStack() {
        ensureRng();
        if (std::uniform_real_distribution<double>(0, 1)(rng_) < epsilon()) {
            return std::uniform_int_distribution<size_t>(TRIOFUZZ_MIN_STACK, TRIOFUZZ_MAX_STACK)(rng_);
        }
        return best_stack_.load(std::memory_order_relaxed);
    }

    std::vector<size_t> generateSequence() {
        size_t len = selectStack();
        std::vector<size_t> seq;
        seq.reserve(len);
        int prev = -1;
        for (size_t i = 0; i < len; ++i) {
            size_t next = selectNext(prev);
            seq.push_back(next);
            prev = static_cast<int>(next);
        }
        return seq;
    }

    void update(const std::vector<size_t>& seq, bool found) {
        total_execs_.fetch_add(1, std::memory_order_relaxed);
        if (found) total_finds_.fetch_add(1, std::memory_order_relaxed);

        int prev = -1;
        for (size_t curr : seq) {
            if (prev >= 0 && prev < static_cast<int>(n_) && curr < n_) {
                const size_t idx = static_cast<size_t>(prev) * n_ + curr;
                trans_[idx].uses.fetch_add(1, std::memory_order_relaxed);
                if (found) trans_[idx].finds.fetch_add(1, std::memory_order_relaxed);
            }
            prev = static_cast<int>(curr);
        }

        size_t st = std::clamp(seq.size(), TRIOFUZZ_MIN_STACK, TRIOFUZZ_MAX_STACK);
        stack_stats_[st].uses.fetch_add(1, std::memory_order_relaxed);
        if (found) {
            stack_stats_[st].finds.fetch_add(1, std::memory_order_relaxed);
            updateBestStack();
        }

        // Hybrid trigger: execution count OR time, whichever comes first
        uint64_t current_since = since_update_.fetch_add(1, std::memory_order_relaxed) + 1;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_update_time_;

        bool exec_trigger = (current_since >= alias_interval_);
        bool time_trigger = (elapsed >= time_period_) && (current_since >= min_samples_);

        if (exec_trigger || time_trigger) {
            since_update_.store(0, std::memory_order_relaxed);
            if (time_trigger && !exec_trigger) {
                time_triggered_updates_.fetch_add(1, std::memory_order_relaxed);
            }
            rebuildAlias();
            last_update_time_ = now;
        }
    }

    std::string report() const {
        std::ostringstream oss;
        oss << "[MuoFuzz Markov] Ops: " << n_
            << " Execs: " << total_execs_.load()
            << " Finds: " << total_finds_.load()
            << " BestStack: " << best_stack_.load()
            << " Eps: " << epsilon()
            << " TimeTriggeredUpdates: " << time_triggered_updates_.load() << "\n";
        return oss.str();
    }

private:
    void initUniform() {
        const double u = 1.0 / static_cast<double>(n_);
        for (size_t i = 0; i < n_; ++i) {
            for (size_t j = 0; j < n_; ++j) {
                const size_t idx = i * n_ + j;
                trans_[idx].finds.store(1, std::memory_order_relaxed);
                trans_[idx].uses.store(1, std::memory_order_relaxed);
                prob_[idx] = u;
                alias_prob_[idx] = 1.0;
                alias_idx_[idx] = static_cast<uint32_t>(j);
            }
        }
        for (size_t i = TRIOFUZZ_MIN_STACK; i <= TRIOFUZZ_MAX_STACK; ++i) {
            stack_stats_[i].finds.store(1);
            stack_stats_[i].uses.store(1);
        }
    }

    size_t sampleAlias(size_t prev) {
        std::shared_lock<std::shared_mutex> lk(mtx_);
        size_t i = std::uniform_int_distribution<size_t>(0, n_ - 1)(rng_);
        const size_t idx = prev * n_ + i;
        if (std::uniform_real_distribution<double>(0, 1)(rng_) < alias_prob_[idx]) {
            return i;
        }
        return static_cast<size_t>(alias_idx_[idx]);
    }

    void updateBestStack() {
        uint64_t maxf = 0;
        size_t best = TRIOFUZZ_MIN_STACK;
        for (size_t i = TRIOFUZZ_MIN_STACK; i <= TRIOFUZZ_MAX_STACK; ++i) {
            uint64_t f = stack_stats_[i].finds.load(std::memory_order_relaxed);
            if (f > maxf) { maxf = f; best = i; }
        }
        best_stack_.store(best, std::memory_order_relaxed);
    }

    void rebuildAlias() {
        std::unique_lock<std::shared_mutex> lk(mtx_);
        for (size_t prev = 0; prev < n_; ++prev) {
            uint64_t total = 0;
            for (size_t j = 0; j < n_; ++j) {
                total += trans_[prev * n_ + j].finds.load(std::memory_order_relaxed);
            }
            if (total > 0) {
                for (size_t j = 0; j < n_; ++j) {
                    prob_[prev * n_ + j] = static_cast<double>(
                        trans_[prev * n_ + j].finds.load(std::memory_order_relaxed)) / total;
                }
            }
            buildAlias(prev);
        }
    }

    void buildAlias(size_t prev) {
        std::vector<double> scaled(n_);
        std::vector<size_t> small, large;
        small.reserve(n_);
        large.reserve(n_);
        for (size_t i = 0; i < n_; ++i) {
            scaled[i] = prob_[prev * n_ + i] * static_cast<double>(n_);
            if (scaled[i] < 1.0) small.push_back(i);
            else large.push_back(i);
        }
        while (!small.empty() && !large.empty()) {
            size_t l = small.back(); small.pop_back();
            size_t g = large.back(); large.pop_back();
            alias_prob_[prev * n_ + l] = scaled[l];
            alias_idx_[prev * n_ + l] = static_cast<uint32_t>(g);
            scaled[g] = scaled[g] + scaled[l] - 1.0;
            if (scaled[g] < 1.0) small.push_back(g);
            else large.push_back(g);
        }
        for (size_t g : large) {
            alias_prob_[prev * n_ + g] = 1.0;
            alias_idx_[prev * n_ + g] = static_cast<uint32_t>(g);
        }
        for (size_t l : small) {
            alias_prob_[prev * n_ + l] = 1.0;
            alias_idx_[prev * n_ + l] = static_cast<uint32_t>(l);
        }
    }

    static void ensureRng() {
        if (!rng_init_) {
            std::random_device rd;
            rng_.seed(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
            rng_init_ = true;
        }
    }
};

inline thread_local std::mt19937 TrioFuzzMarkov::rng_;
inline thread_local bool TrioFuzzMarkov::rng_init_ = false;

// ============================================================================
// Unified Learner - Coordinates All Three Layers
// ============================================================================

class TrioFuzzUnifiedLearner {
public:
    struct Config {
        bool enable_ts;
        bool enable_ecofuzz;  // Enable EcoFuzz power schedule arm(s)
        double ts_decay;
        size_t ts_update_period;
        uint32_t havoc_stack_pow2;
        bool enable_mopt_pso;
        size_t mopt_update_period;
        bool enable_markov;
        size_t markov_update_period;  // Alias interval for Markov

        // Operator-space sizes must match the mapping used by the engine when
        // converting operator indices into concrete mutation algorithm names.
        size_t havoc_ops_nosplice;
        size_t havoc_ops_splice;
        size_t mopt_ops_nosplice;
        size_t mopt_ops_splice;

        // Hybrid period configuration for non-stationary adaptation
        // Time periods ensure learning happens even for slow targets
        uint32_t ts_time_period_sec;   // TS time period (default: 30s)
        uint32_t mopt_time_period_sec;    // MOpt PSO time period (default: 30s)
        uint32_t markov_time_period_sec;  // Markov time period (default: 5s)

        // Minimum samples required for time-triggered updates (noise protection)
        size_t ts_min_samples;
        size_t mopt_min_samples;
        size_t markov_min_samples;

        Config()
            : enable_ts(true),
              enable_ecofuzz(true),
              ts_decay(0.95),
              ts_update_period(50000),
              havoc_stack_pow2(4),
              enable_mopt_pso(true),
              mopt_update_period(500000),
              enable_markov(true),
              markov_update_period(500),
              havoc_ops_nosplice(35),
              havoc_ops_splice(37),
              mopt_ops_nosplice(18),
              mopt_ops_splice(19),
              // Hybrid period defaults
              ts_time_period_sec(TRIOFUZZ_TS_TIME_PERIOD_SEC),
              mopt_time_period_sec(TRIOFUZZ_MOPT_TIME_PERIOD_SEC),
              markov_time_period_sec(TRIOFUZZ_MARKOV_TIME_PERIOD_SEC),
              ts_min_samples(TRIOFUZZ_TS_MIN_SAMPLES),
              mopt_min_samples(TRIOFUZZ_MOPT_MIN_SAMPLES),
              markov_min_samples(TRIOFUZZ_MARKOV_MIN_SAMPLES) {}
    };

private:
    Config cfg_;
    std::unique_ptr<TrioFuzzTS> ts_layer_;
    std::unique_ptr<TrioFuzzMOptPSO> mopt_nosplice_;
    std::unique_ptr<TrioFuzzMOptPSO> mopt_splice_;
    std::unique_ptr<TrioFuzzMarkov> markov_nosplice_;
    std::unique_ptr<TrioFuzzMarkov> markov_splice_;

    std::atomic<uint64_t> total_tasks_{0};
    std::atomic<uint64_t> total_results_{0};
    std::atomic<uint64_t> total_finds_{0};

    static thread_local std::mt19937 rng_;
    static thread_local bool rng_init_;

public:
    explicit TrioFuzzUnifiedLearner(const Config& cfg = Config()) : cfg_(cfg) {
        if (cfg_.enable_ts) {
            ts_layer_ = std::make_unique<TrioFuzzTS>(cfg_.enable_ecofuzz);
            ts_layer_->setDecay(cfg_.ts_decay);
            ts_layer_->setUpdatePeriod(cfg_.ts_update_period);
            // Hybrid period configuration
            ts_layer_->setTimePeriod(cfg_.ts_time_period_sec);
            ts_layer_->setMinSamples(cfg_.ts_min_samples);
        }
        if (cfg_.enable_mopt_pso) {
            const size_t nosplice_ops = std::max<size_t>(1, cfg_.mopt_ops_nosplice);
            const size_t splice_ops = std::max<size_t>(1, cfg_.mopt_ops_splice);
            mopt_nosplice_ = std::make_unique<TrioFuzzMOptPSO>(nosplice_ops);
            mopt_splice_ = std::make_unique<TrioFuzzMOptPSO>(splice_ops);
            mopt_nosplice_->setUpdatePeriod(cfg_.mopt_update_period);
            mopt_splice_->setUpdatePeriod(cfg_.mopt_update_period);
            // Hybrid period configuration
            mopt_nosplice_->setTimePeriod(cfg_.mopt_time_period_sec);
            mopt_splice_->setTimePeriod(cfg_.mopt_time_period_sec);
            mopt_nosplice_->setMinSamples(cfg_.mopt_min_samples);
            mopt_splice_->setMinSamples(cfg_.mopt_min_samples);
        }
        if (cfg_.enable_markov) {
            const size_t nosplice_ops = std::max<size_t>(1, cfg_.havoc_ops_nosplice);
            const size_t splice_ops = std::max<size_t>(1, cfg_.havoc_ops_splice);
            markov_nosplice_ = std::make_unique<TrioFuzzMarkov>(nosplice_ops);
            markov_splice_ = std::make_unique<TrioFuzzMarkov>(splice_ops);
            // Hybrid period configuration
            markov_nosplice_->setAliasInterval(cfg_.markov_update_period);
            markov_splice_->setAliasInterval(cfg_.markov_update_period);
            markov_nosplice_->setTimePeriod(cfg_.markov_time_period_sec);
            markov_splice_->setTimePeriod(cfg_.markov_time_period_sec);
            markov_nosplice_->setMinSamples(cfg_.markov_min_samples);
            markov_splice_->setMinSamples(cfg_.markov_min_samples);
        }

        std::cout << "[TrioFuzz Unified Learner] Initialized with Hybrid Period Strategy\n";
        std::cout << "  Thompson Sampling: " << (cfg_.enable_ts ? "ON" : "OFF");
        if (cfg_.enable_ts) {
            std::cout << " (exec_period=" << cfg_.ts_update_period
                      << ", time_period=" << cfg_.ts_time_period_sec << "s"
                      << ", min_samples=" << cfg_.ts_min_samples << ")";
        }
        std::cout << "\n";
        std::cout << "  MOpt PSO: " << (cfg_.enable_mopt_pso ? "ON" : "OFF");
        if (cfg_.enable_mopt_pso) {
            std::cout << " (exec_period=" << cfg_.mopt_update_period
                      << ", time_period=" << cfg_.mopt_time_period_sec << "s"
                      << ", min_samples=" << cfg_.mopt_min_samples
                      << ", ops nosplice=" << cfg_.mopt_ops_nosplice
                      << ", splice=" << cfg_.mopt_ops_splice << ")";
        }
        std::cout << "\n";
        std::cout << "  MuoFuzz Markov: " << (cfg_.enable_markov ? "ON" : "OFF");
        if (cfg_.enable_markov) {
            std::cout << " (exec_period=" << cfg_.markov_update_period
                      << ", time_period=" << cfg_.markov_time_period_sec << "s"
                      << ", min_samples=" << cfg_.markov_min_samples
                      << ", ops nosplice=" << cfg_.havoc_ops_nosplice
                      << ", splice=" << cfg_.havoc_ops_splice << ")";
        }
        std::cout << "\n";
    }

    // Task generation structure
    struct Task {
        size_t config_arm;
        std::string power_schedule;
        bool use_mopt;
        bool splice_enabled;
        bool use_analysis;       // Use analysis algorithms (cmplog/redqueen/dictionary)
        std::vector<size_t> operator_sequence;
        size_t stack_size;
        bool is_exploration;
    };

	    /**
	     * Generate a task for Worker threads using all three learning layers
	     */
	    Task generateWorkerTask() { return generateWorkerTask(/*allow_analysis=*/true); }

	    Task generateWorkerTask(bool allow_analysis) {
	        ensureRng();
	        Task task;
	        task.is_exploration = false;
	        task.use_analysis = false;
	        total_tasks_.fetch_add(1, std::memory_order_relaxed);

	        // Layer 1: Select configuration using Thompson Sampling (or random if disabled)
	        if (ts_layer_) {
	            task.config_arm = ts_layer_->selectArm(allow_analysis);
	            const auto& arm = ts_layer_->getArm(task.config_arm);
	            task.power_schedule = arm.power_schedule;
	            task.use_mopt = arm.use_mopt;
	            task.splice_enabled = arm.splice_enabled;
	            task.use_analysis = arm.use_analysis;
		        } else {
		            // Thompson Sampling disabled: use truly random configuration selection
		            // This enables fair ablation study comparing learning vs random
		            auto all_arms = getTrioFuzzConfigArms(cfg_.enable_ecofuzz);
		            std::vector<size_t> candidates;
		            candidates.reserve(all_arms.size());
		            for (size_t i = 0; i < all_arms.size(); ++i) {
	                if (allow_analysis || !all_arms[i].use_analysis) {
	                    candidates.push_back(i);
	                }
	            }
	            std::uniform_int_distribution<size_t> arm_dist(0, candidates.size() - 1);
	            task.config_arm = candidates[arm_dist(rng_)];
	            const auto& arm = all_arms[task.config_arm];
	            task.power_schedule = arm.power_schedule;
	            task.use_mopt = arm.use_mopt;
	            task.splice_enabled = arm.splice_enabled;
	            task.use_analysis = arm.use_analysis;
	        }

        // Analysis mode: use analysis algorithms (cmplog/redqueen/dictionary/format_overflow/format_aware)
        // These algorithms have longer execution times but can discover complex constraints and magic bytes
        // operator_sequence stores analysis operator indices (0-5)
        if (task.use_analysis) {
            // Analysis algorithms use smaller stack size (1-2)
            std::uniform_int_distribution<size_t> stack_dist(1, 2);
            task.stack_size = stack_dist(rng_);

            // 6 analysis operators:
            // cmplog(0), redqueen(1), smart_dictionary(2), runtime_dictionary(3),
            // format_overflow(4), format_aware(5)
            constexpr size_t NUM_ANALYSIS_OPS = 6;
            std::uniform_int_distribution<size_t> op_dist(0, NUM_ANALYSIS_OPS - 1);
            task.operator_sequence.reserve(task.stack_size);
            for (size_t i = 0; i < task.stack_size; ++i) {
                task.operator_sequence.push_back(op_dist(rng_));
            }
            return task;
        }

        // Layer 2 or 3: Generate operator sequence (MOpt or Havoc)
        if (task.use_mopt) {
            task.stack_size = selectStackSize();
            if (auto* learner = getMOptLearner(task.splice_enabled)) {
                task.operator_sequence = learner->generateSequence(task.stack_size);
            } else {
                task.operator_sequence = randomSequence(task.stack_size, getMOptOpCount(task.splice_enabled));
            }
        } else {
            if (auto* learner = getMarkovLearner(task.splice_enabled)) {
                task.operator_sequence = learner->generateSequence();
                task.stack_size = task.operator_sequence.size();
            } else {
                task.stack_size = selectStackSize();
                task.operator_sequence = randomSequence(task.stack_size, getHavocOpCount(task.splice_enabled));
            }
        }

        return task;
    }

    /**
     * Generate a random exploration task for Explorer threads
     */
    Task generateExplorerTask() {
        ensureRng();
        Task task;
        task.is_exploration = true;
        task.use_analysis = false;
        total_tasks_.fetch_add(1, std::memory_order_relaxed);

        // Explorer threads run truly random configs, but we bias toward the
        // analysis arm to make sure expensive but high-leverage analysis ops
        // (cmplog/redqueen/dictionary/format_aware/format_overflow) get sampled
        // frequently enough to stay effective.
        //
	        // Default: 18% analysis configs (override via TRIOFUZZ_EXPLORER_ANALYSIS_PROB).
	        auto all_arms = getTrioFuzzConfigArms(cfg_.enable_ecofuzz);
	        std::vector<size_t> analysis_arms;
	        std::vector<size_t> other_arms;
	        analysis_arms.reserve(all_arms.size());
        other_arms.reserve(all_arms.size());
        for (size_t i = 0; i < all_arms.size(); ++i) {
            if (all_arms[i].use_analysis) analysis_arms.push_back(i);
            else other_arms.push_back(i);
        }

        auto get_analysis_prob = []() -> double {
            static double cached = -1.0;
            if (cached >= 0.0) return cached;
            double p = 0.18;
            if (const char* env = std::getenv("TRIOFUZZ_EXPLORER_ANALYSIS_PROB")) {
                char* end = nullptr;
                double v = std::strtod(env, &end);
                if (end != env) p = v;
            }
            if (p < 0.0) p = 0.0;
            if (p > 1.0) p = 1.0;
            cached = p;
            return cached;
        };

        double analysis_prob = get_analysis_prob();
        if (analysis_arms.empty()) analysis_prob = 0.0;
        if (other_arms.empty()) analysis_prob = 1.0;

        std::uniform_real_distribution<double> prob_dist(0.0, 1.0);
        bool pick_analysis = (prob_dist(rng_) < analysis_prob);
        const auto& pool = pick_analysis ? analysis_arms : other_arms;
        std::uniform_int_distribution<size_t> arm_dist(0, pool.size() - 1);
        task.config_arm = pool[arm_dist(rng_)];
        const auto& arm = all_arms[task.config_arm];
        task.power_schedule = arm.power_schedule;
        task.use_mopt = arm.use_mopt;
        task.splice_enabled = arm.splice_enabled;
        task.use_analysis = arm.use_analysis;

        // Analysis mode: random selection from analysis operators (6 ops)
        if (task.use_analysis) {
            std::uniform_int_distribution<size_t> stack_dist(1, 2);
            task.stack_size = stack_dist(rng_);
            constexpr size_t NUM_ANALYSIS_OPS = 6;
            std::uniform_int_distribution<size_t> op_dist(0, NUM_ANALYSIS_OPS - 1);
            task.operator_sequence.reserve(task.stack_size);
            for (size_t i = 0; i < task.stack_size; ++i) {
                task.operator_sequence.push_back(op_dist(rng_));
            }
            return task;
        }

        // Random operator sequence for MOpt or Havoc
        task.stack_size = selectStackSize();
        if (task.use_mopt) {
            task.operator_sequence = randomSequence(task.stack_size, getMOptOpCount(task.splice_enabled));
        } else {
            task.operator_sequence = randomSequence(task.stack_size, getHavocOpCount(task.splice_enabled));
        }

        return task;
    }

    /**
     * Process execution result and update all learning layers
     */
	    void processResult(const Task& task, bool found_new_coverage) {
	        total_results_.fetch_add(1, std::memory_order_relaxed);
	        if (found_new_coverage) {
	            total_finds_.fetch_add(1, std::memory_order_relaxed);
	        }

	        // Update Layer 1: Thompson Sampling
	        if (ts_layer_) {
	            ts_layer_->update(task.config_arm, found_new_coverage);
	        }

	        // Analysis operators use a distinct operator id space (0..5) and are
	        // intentionally expensive. Their operator sequences should not be fed
	        // into MOpt/Markov learning (which expects MOpt/Havoc operator ids).
	        if (task.use_analysis) {
	            return;
	        }

	        // Update Layer 2: MOpt PSO (if task used MOpt)
	        if (task.use_mopt && !task.operator_sequence.empty()) {
	            if (auto* learner = getMOptLearner(task.splice_enabled)) {
	                learner->update(task.operator_sequence, found_new_coverage);
	            }
	        }

        // Update Layer 3: MuoFuzz Markov
        if (!task.use_mopt && !task.operator_sequence.empty()) {
            if (auto* learner = getMarkovLearner(task.splice_enabled)) {
                learner->update(task.operator_sequence, found_new_coverage);
            }
        }
    }

    std::string report() const {
        std::ostringstream oss;
        oss << "========================================\n";
        oss << "TrioFuzz Unified Learner Report\n";
        oss << "========================================\n";
        oss << "Tasks: " << total_tasks_.load()
            << " Results: " << total_results_.load()
            << " Finds: " << total_finds_.load() << "\n\n";
        if (ts_layer_) oss << ts_layer_->report() << "\n";
        if (mopt_nosplice_) oss << "[MOpt PSO - NoSplice]\n" << mopt_nosplice_->report() << "\n";
        if (mopt_splice_) oss << "[MOpt PSO - Splice]\n" << mopt_splice_->report() << "\n";
        if (markov_nosplice_) oss << "[MuoFuzz Markov - NoSplice]\n" << markov_nosplice_->report() << "\n";
        if (markov_splice_) oss << "[MuoFuzz Markov - Splice]\n" << markov_splice_->report() << "\n";
        return oss.str();
    }

    TrioFuzzTS* getTSLayer() { return ts_layer_.get(); }
    TrioFuzzMOptPSO* getMOpt(bool splice_enabled) {
        return splice_enabled ? mopt_splice_.get() : mopt_nosplice_.get();
    }
    TrioFuzzMarkov* getMarkov(bool splice_enabled) {
        return splice_enabled ? markov_splice_.get() : markov_nosplice_.get();
    }

    void printStats() const {
        uint64_t tasks = total_tasks_.load(std::memory_order_relaxed);
        uint64_t results = total_results_.load(std::memory_order_relaxed);
        uint64_t finds = total_finds_.load(std::memory_order_relaxed);
        double find_rate = results > 0 ? (100.0 * finds / results) : 0.0;

        std::cout << "[TrioFuzz Stats] Tasks: " << tasks
                  << " | Results: " << results
                  << " | Finds: " << finds
                  << " (" << std::fixed << std::setprecision(2) << find_rate << "%)"
                  << std::endl;

        if (ts_layer_) {
            std::cout << "  [TS] Top arm: " << ts_layer_->getTopArm().toString() << std::endl;
            const auto old_flags = std::cout.flags();
            const auto old_precision = std::cout.precision();

            std::cout << "  [TS] Arms (mean/uses/finds):" << std::endl;
            for (size_t i = 0; i < ts_layer_->numArms(); ++i) {
                const auto& arm = ts_layer_->getArm(i);
                std::cout << "    [" << i << "] " << arm.toString()
                          << " mean=" << std::fixed << std::setprecision(6) << ts_layer_->getArmMean(i)
                          << " uses=" << ts_layer_->getArmUses(i)
                          << " finds=" << ts_layer_->getArmFinds(i)
                          << std::endl;
            }

            std::cout.flags(old_flags);
            std::cout.precision(old_precision);
        }
    }

private:
    size_t selectStackSize() {
        ensureRng();
        // AFL++ havoc style: 1 << (1 + rand_below(pow2))
        const uint32_t pow2 = std::max<uint32_t>(1, cfg_.havoc_stack_pow2);
        std::uniform_int_distribution<uint32_t> dist(0, pow2 - 1);
        const size_t stacking = 1UL << (1UL + dist(rng_));
        return std::min<size_t>(1024, stacking);
    }

    size_t getHavocOpCount(bool splice_enabled) const {
        const size_t n = splice_enabled ? cfg_.havoc_ops_splice : cfg_.havoc_ops_nosplice;
        return std::max<size_t>(1, n);
    }

    size_t getMOptOpCount(bool splice_enabled) const {
        const size_t n = splice_enabled ? cfg_.mopt_ops_splice : cfg_.mopt_ops_nosplice;
        return std::max<size_t>(1, n);
    }

    TrioFuzzMOptPSO* getMOptLearner(bool splice_enabled) {
        return splice_enabled ? mopt_splice_.get() : mopt_nosplice_.get();
    }

    TrioFuzzMarkov* getMarkovLearner(bool splice_enabled) {
        return splice_enabled ? markov_splice_.get() : markov_nosplice_.get();
    }

    std::vector<size_t> randomSequence(size_t len, size_t num_ops) {
        ensureRng();
        std::vector<size_t> seq;
        seq.reserve(len);
        num_ops = std::max<size_t>(1, num_ops);
        std::uniform_int_distribution<size_t> dist(0, num_ops - 1);
        for (size_t i = 0; i < len; ++i) seq.push_back(dist(rng_));
        return seq;
    }

    static void ensureRng() {
        if (!rng_init_) {
            std::random_device rd;
            rng_.seed(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
            rng_init_ = true;
        }
    }
};

inline thread_local std::mt19937 TrioFuzzUnifiedLearner::rng_;
inline thread_local bool TrioFuzzUnifiedLearner::rng_init_ = false;

} // namespace triofuzz
