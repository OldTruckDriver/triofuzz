#pragma once

/**
 * AFL++ MOpt (PSO) Online Learner
 *
 * Purpose:
 * - Learn a probability distribution over mutation operators using a PSO-style
 *   update (the core idea behind AFL++'s MOpt).
 * - Designed to plug into the specialized-thread framework where the scheduler
 *   selects one (or a short chain) of operators per execution, and updates the
 *   learner using execution feedback (new coverage or not).
 *
 * Notes:
 * - This learner is intentionally lightweight and header-only.
 * - It does not depend on running the target between individual mutation steps.
 *   Credit is assigned at the execution level.
 */

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace triofuzz {

class MOptOnlineLearner {
public:
    struct PSOParams {
        // AFL++ MOpt-style PSO parameters.
        double w_init;
        double w_end;
        int g_max;
        double v_min;
        double v_max;

        // Update period in executions.
        size_t update_period;

        PSOParams()
            : w_init(0.9),
              w_end(0.3),
              g_max(5000),
              v_min(0.05),
              v_max(1.0),
              update_period(500000) {}
    };

    MOptOnlineLearner(size_t num_operators, PSOParams params = PSOParams())
        : params_(params),
          num_operators_(num_operators),
          x_now_(num_operators_, 0.0),
          v_now_(num_operators_, 0.1),
          l_best_(num_operators_, 0.0),
          g_best_(num_operators_, 0.0),
          eff_best_(num_operators_, 0.0),
          finds_total_(num_operators_, 0),
          cycles_total_(num_operators_, 0),
          finds_prev_(num_operators_, 0),
          cycles_prev_(num_operators_, 0),
          probability_(num_operators_, 0.0) {
        initializeState();
    }

    size_t numOperators() const { return num_operators_; }

    const std::vector<double>& getProbabilities() const { return probability_; }

    /**
     * Generate a mutation operator index sequence.
     *
     * Typical MOpt usage selects one operator per mutation step. In many
     * experimental setups (e.g. operator-level comparisons), min_len=max_len=1.
     */
    std::vector<size_t> generateSequence(size_t min_len, size_t max_len) {
        ensureRngInitialized();

        if (num_operators_ == 0) {
            return {};
        }

        if (min_len == 0) min_len = 1;
        if (max_len == 0) max_len = 1;
        if (min_len > max_len) std::swap(min_len, max_len);

        std::uniform_int_distribution<size_t> len_dist(min_len, max_len);
        size_t len = len_dist(rng_);

        std::vector<size_t> seq;
        seq.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            seq.push_back(selectOperator());
        }
        return seq;
    }

    /**
     * Update the learner using execution-level feedback.
     *
     * @param sequence Operator indices used to generate the test case.
     * @param found_new_coverage Whether the execution discovered new coverage.
     * @param execution_time_ms Execution time (ms) for the resulting test case.
     */
    void update(const std::vector<size_t>& sequence,
                bool found_new_coverage,
                double execution_time_ms) {
        if (num_operators_ == 0 || sequence.empty()) {
            return;
        }

        executions_++;
        (void)execution_time_ms;

        // MOpt tracks (cycles, finds) per operator. In this integration a "cycle"
        // is one operator application in the generated sequence.
        for (size_t idx : sequence) {
            if (idx >= num_operators_) continue;
            cycles_total_[idx] += 1;
            if (found_new_coverage) {
                finds_total_[idx] += 1;
            }
        }

        if (params_.update_period > 0 && (executions_ % params_.update_period) == 0) {
            updateProbabilities();
        }
    }

    std::string getStatisticsReport(size_t top_k = 10) const {
        std::ostringstream oss;
        oss << "[MOptOnlineLearner Statistics]\n";
        oss << "  Operators: " << num_operators_ << "\n";
        oss << "  Executions: " << executions_ << "\n";
        oss << "  Update period: " << params_.update_period << "\n";
        oss << "  Updates: " << updates_ << "\n";
        oss << "  Total finds: " << totalFinds() << "\n";
        oss << "  Last window finds: " << last_window_total_finds_ << "\n";
        oss << "  Last window cycles: " << last_window_total_cycles_ << "\n";
        oss << "  g_now: " << g_now_ << "\n";

        // Report top-k probabilities (by probability).
        std::vector<size_t> idx(num_operators_);
        std::iota(idx.begin(), idx.end(), 0);
        std::sort(idx.begin(), idx.end(),
                  [&](size_t a, size_t b) { return probability_[a] > probability_[b]; });

        oss << "  Top probabilities:\n";
        for (size_t i = 0; i < std::min(top_k, idx.size()); ++i) {
            size_t k = idx[i];
            oss << "    [" << k << "] p=" << probability_[k] << "\n";
        }
        return oss.str();
    }

private:
    void initializeState() {
        if (num_operators_ == 0) return;
        double uniform = 1.0 / static_cast<double>(num_operators_);
        std::fill(x_now_.begin(), x_now_.end(), uniform);
        std::fill(probability_.begin(), probability_.end(), uniform);
        std::fill(l_best_.begin(), l_best_.end(), uniform);
        std::fill(g_best_.begin(), g_best_.end(), uniform);

        g_now_ = 0;
        updates_ = 0;
        last_window_total_finds_ = 0;
        last_window_total_cycles_ = 0;
    }

    size_t selectOperator() {
        ensureRngInitialized();
        if (num_operators_ == 0) return 0;
        std::discrete_distribution<size_t> dist(probability_.begin(), probability_.end());
        return dist(rng_);
    }

    void updateProbabilities() {
        ensureRngInitialized();
        if (num_operators_ == 0) return;

        // Compute deltas for this window.
        uint64_t window_finds = 0;
        uint64_t window_cycles = 0;
        for (size_t i = 0; i < num_operators_; ++i) {
            uint64_t df = finds_total_[i] - finds_prev_[i];
            uint64_t dc = cycles_total_[i] - cycles_prev_[i];
            window_finds += df;
            window_cycles += dc;

            if (dc > 0) {
                double temp_eff = static_cast<double>(df) / static_cast<double>(dc);
                if (temp_eff > eff_best_[i]) {
                    eff_best_[i] = temp_eff;
                    l_best_[i] = x_now_[i];
                }
            }
        }

        last_window_total_finds_ = window_finds;
        last_window_total_cycles_ = window_cycles;
        updates_++;

        // Update inertia weight (linearly decays from w_init to w_end).
        g_now_++;
        if (params_.g_max > 0 && g_now_ > params_.g_max) {
            g_now_ = 0;
        }
        double w_now = params_.w_init;
        if (params_.g_max > 0) {
            w_now = (params_.w_init - params_.w_end) *
                        static_cast<double>(params_.g_max - g_now_) /
                        static_cast<double>(params_.g_max) +
                    params_.w_end;
        }

        // Update global best in probability-space using cumulative finds distribution.
        uint64_t total_finds = totalFinds();
        if (total_finds > 0) {
            for (size_t i = 0; i < num_operators_; ++i) {
                g_best_[i] = static_cast<double>(finds_total_[i]) / static_cast<double>(total_finds);
            }
        } else {
            // No signal yet: keep g_best_ as-is (initially uniform).
        }

        // PSO-style update (mirrors AFL++ MOpt's pso_updating).
        double x_sum = 0.0;
        for (size_t i = 0; i < num_operators_; ++i) {
            double r1 = randomCoeff();
            double r2 = randomCoeff();

            v_now_[i] = w_now * v_now_[i] +
                        r1 * (l_best_[i] - x_now_[i]) +
                        r2 * (g_best_[i] - x_now_[i]);
            x_now_[i] += v_now_[i];

            if (x_now_[i] > params_.v_max) {
                x_now_[i] = params_.v_max;
            } else if (x_now_[i] < params_.v_min) {
                x_now_[i] = params_.v_min;
            }

            x_sum += x_now_[i];
        }

        if (x_sum <= 0.0) {
            initializeState();
        } else {
            for (size_t i = 0; i < num_operators_; ++i) {
                probability_[i] = x_now_[i] / x_sum;
                x_now_[i] = probability_[i];
            }
        }

        // Snapshot counters for windowed efficiency calculation.
        finds_prev_ = finds_total_;
        cycles_prev_ = cycles_total_;
    }

    uint64_t totalFinds() const {
        return std::accumulate(finds_total_.begin(), finds_total_.end(), uint64_t{0});
    }

    double randomCoeff() {
        ensureRngInitialized();
        // Similar to AFL++'s RAND_C (0..0.999), but continuous.
        std::uniform_real_distribution<double> uni(0.0, 1.0);
        return uni(rng_);
    }

    static void ensureRngInitialized() {
        if (rng_initialized_) return;
        std::random_device rd;
        rng_.seed(rd() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
        rng_initialized_ = true;
    }

    PSOParams params_;
    size_t num_operators_ = 0;
    uint64_t executions_ = 0;

    int g_now_ = 0;
    uint64_t updates_ = 0;
    uint64_t last_window_total_finds_ = 0;
    uint64_t last_window_total_cycles_ = 0;

    std::vector<double> x_now_;
    std::vector<double> v_now_;
    std::vector<double> l_best_;
    std::vector<double> g_best_;
    std::vector<double> eff_best_;
    std::vector<uint64_t> finds_total_;
    std::vector<uint64_t> cycles_total_;
    std::vector<uint64_t> finds_prev_;
    std::vector<uint64_t> cycles_prev_;
    std::vector<double> probability_;

    static thread_local std::mt19937 rng_;
    static thread_local bool rng_initialized_;
};

inline thread_local std::mt19937 MOptOnlineLearner::rng_;
inline thread_local bool MOptOnlineLearner::rng_initialized_ = false;

}  // namespace triofuzz
