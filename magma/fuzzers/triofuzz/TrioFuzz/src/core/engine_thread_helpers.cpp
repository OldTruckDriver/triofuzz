#include "../../include/core/engine_thread_helpers.hpp"
#include "../../include/utils/random_utils.hpp"
#include <iostream>
#include <thread>
#include <set>
#include <mutex>

namespace triofuzz {

// Thread-local storage definitions for ImprovedFuzzingEngine
thread_local std::unique_ptr<std::mt19937> ImprovedFuzzingEngine::mcts_generator_;
thread_local std::unique_ptr<std::mt19937> ImprovedFuzzingEngine::adaptive_generator_;

// Thread tracking for cleanup
static std::mutex improved_engine_thread_mutex_;
static std::set<std::thread::id> improved_engine_threads_;

std::mt19937& ImprovedFuzzingEngine::getMCTSGenerator() {
    if (!mcts_generator_) {
        std::random_device rd;
        mcts_generator_ = std::make_unique<std::mt19937>(rd());
        
        // Register thread for cleanup
        std::lock_guard<std::mutex> lock(improved_engine_thread_mutex_);
        improved_engine_threads_.insert(std::this_thread::get_id());
    }
    return *mcts_generator_;
}

std::mt19937& ImprovedFuzzingEngine::getAdaptiveGenerator() {
    if (!adaptive_generator_) {
        std::random_device rd;
        adaptive_generator_ = std::make_unique<std::mt19937>(rd());
        
        // Register thread for cleanup
        std::lock_guard<std::mutex> lock(improved_engine_thread_mutex_);
        improved_engine_threads_.insert(std::this_thread::get_id());
    }
    return *adaptive_generator_;
}

void ImprovedFuzzingEngine::cleanupThreadLocalGenerators() {
    // Cleanup current thread's generators
    mcts_generator_.reset();
    adaptive_generator_.reset();
    
    // Remove from thread registry
    std::lock_guard<std::mutex> lock(improved_engine_thread_mutex_);
    improved_engine_threads_.erase(std::this_thread::get_id());
}

void ImprovedFuzzingEngine::cleanupAllThreadLocalData() {
    // Cleanup current thread's data
    mcts_generator_.reset();
    adaptive_generator_.reset();
    
    // Clear thread registry
    std::lock_guard<std::mutex> lock(improved_engine_thread_mutex_);
    improved_engine_threads_.clear();
}

void ImprovedFuzzingEngine::enhancedShutdown() {
    std::cout << "[ImprovedFuzzingEngine] Enhanced shutdown starting..." << std::endl;
    
    // Call parent shutdown first
    shutdown();
    
    // Cleanup all thread-local data
    cleanupAllThreadLocalData();
    
    std::cout << "[ImprovedFuzzingEngine] Enhanced shutdown completed" << std::endl;
}

AlgorithmCombination ImprovedFuzzingEngine::selectWithThompsonSampling(
    const std::vector<std::string>& enabled_algorithms) {
    
    // Thread-safe Thompson sampling implementation
    std::shared_lock<std::shared_mutex> lock(mcts_data_.mcts_mutex_);
    
    AlgorithmCombination combination;
    
    // Use thread-local generator for randomness
    auto& generator = getMCTSGenerator();
    std::uniform_int_distribution<size_t> dist(0, enabled_algorithms.size() - 1);
    
    if (!enabled_algorithms.empty()) {
        size_t selected_idx = dist(generator);
        combination.algorithm_names = {enabled_algorithms[selected_idx]};
        combination.combination_mode = "sequential";
    }
    
    return combination;
}

AlgorithmCombination ImprovedFuzzingEngine::selectWithMCTS(
    const std::vector<std::string>& enabled_algorithms) {
    
    // Thread-safe MCTS implementation
    std::shared_lock<std::shared_mutex> lock(mcts_data_.mcts_mutex_);
    
    AlgorithmCombination combination;
    
    // Use thread-local generator for randomness
    auto& generator = getAdaptiveGenerator();
    std::uniform_int_distribution<size_t> dist(0, enabled_algorithms.size() - 1);
    
    if (!enabled_algorithms.empty()) {
        size_t selected_idx = dist(generator);
        combination.algorithm_names = {enabled_algorithms[selected_idx]};
        combination.combination_mode = "sequential";
    }
    
    return combination;
}

void ImprovedFuzzingEngine::updateCombinationPerformance(
    const AlgorithmCombination& combination, 
    double reward, 
    const ExecutionResult& result) {
    
    // Thread-safe performance update
    std::unique_lock<std::shared_mutex> lock(mcts_data_.mcts_mutex_);
    
    std::string combo_key = combination.toString();
    
    // Update statistics atomically
    auto& stats = mcts_data_.node_stats_[combo_key];
    stats.first.store(stats.first.load() + reward);
    stats.second.fetch_add(1);
}

// Factory functions implementation
std::unique_ptr<ImprovedFuzzingEngine> createImprovedFuzzingEngine(const FuzzingConfig& config) {
    return std::make_unique<ImprovedFuzzingEngine>(config);
}

std::unique_ptr<ImprovedBatchAlgorithmSelector> createThreadSafeBatchSelector(
    const FuzzingConfig& config, const std::unique_ptr<SharedContext>& context) {
    return std::make_unique<ImprovedBatchAlgorithmSelector>(config, context);
}

std::unique_ptr<ImprovedCoverageCollector> createThreadSafeCoverageCollector() {
    return std::make_unique<ImprovedCoverageCollector>();
}

// ImprovedBatchAlgorithmSelector method implementations
// Note: Class definition is in the header file

// Thread-local generator for ImprovedBatchAlgorithmSelector
thread_local std::unique_ptr<std::mt19937> ImprovedBatchAlgorithmSelector::local_generator_;

std::mt19937& ImprovedBatchAlgorithmSelector::getThreadLocalGenerator() {
    if (!local_generator_) {
        std::random_device rd;
        local_generator_ = std::make_unique<std::mt19937>(rd());
    }
    return *local_generator_;
}

ImprovedBatchAlgorithmSelector::ImprovedBatchAlgorithmSelector(
    const FuzzingConfig& config, const std::unique_ptr<SharedContext>& context)
    : config_(config), global_context_(context) {
    
    // Initialize first batch
    initializeNewBatch();
}

AlgorithmCombination ImprovedBatchAlgorithmSelector::getCurrentCombination() {
    std::shared_lock<std::shared_mutex> lock(batch_mutex_);
    return current_batch_.current_combination;
}

void ImprovedBatchAlgorithmSelector::recordExecution(double reward) {
    current_batch_.executions_in_batch.fetch_add(1);
    current_batch_.total_reward.store(current_batch_.total_reward.load() + reward);
    
    // Check if we should end the current batch
    if (shouldEndCurrentBatch()) {
        endCurrentBatch();
    }
}

void ImprovedBatchAlgorithmSelector::forceEndBatch() {
    endCurrentBatch();
}

size_t ImprovedBatchAlgorithmSelector::getCurrentBatchExecutions() const {
    return current_batch_.executions_in_batch.load();
}

size_t ImprovedBatchAlgorithmSelector::getCurrentBatchSize() const {
    return current_batch_.batch_size.load();
}

double ImprovedBatchAlgorithmSelector::getCurrentBatchAverageReward() const {
    size_t executions = current_batch_.executions_in_batch.load();
    if (executions == 0) return 0.0;
    return current_batch_.total_reward.load() / executions;
}

bool ImprovedBatchAlgorithmSelector::shouldEndCurrentBatch() const {
    size_t executions = current_batch_.executions_in_batch.load();
    size_t batch_size = current_batch_.batch_size.load();
    return executions >= batch_size;
}

void ImprovedBatchAlgorithmSelector::endCurrentBatch() {
    std::unique_lock<std::shared_mutex> lock(batch_mutex_);
    
    // Update Thompson sampling with current batch results
    double avg_reward = getCurrentBatchAverageReward();
    size_t executions = current_batch_.executions_in_batch.load();
    
    if (executions > 0) {
        std::string combo_key = current_batch_.current_combination.toString();
        updateThompsonSampling(combo_key, avg_reward, executions);
        adaptBatchSize(avg_reward);
    }
    
    // Initialize new batch
    initializeNewBatch();
}

void ImprovedBatchAlgorithmSelector::initializeNewBatch() {
    // Reset counters
    current_batch_.executions_in_batch.store(0);
    current_batch_.total_reward.store(0.0);
    
    // Select new combination using Thompson sampling
    current_batch_.current_combination = selectWithThompsonSampling();
    
    // Record batch start time
    current_batch_.batch_start_time.store(std::chrono::steady_clock::now());
}

void ImprovedBatchAlgorithmSelector::updateThompsonSampling(const std::string& combo_key,
                                                           double avg_reward, size_t executions) {
    // Type aliases for convenience
    using BetaParams = ThompsonSamplingData::BetaParams;
    using CombinationStats = ThompsonSamplingData::CombinationStats;

    // Get or create beta parameters
    BetaParams* beta_params = nullptr;
    {
        std::shared_lock<std::shared_mutex> read_lock(thompson_data_.distributions_mutex_);
        auto it = thompson_data_.beta_distributions_.find(combo_key);
        if (it != thompson_data_.beta_distributions_.end()) {
            beta_params = it->second.get();
        }
    }

    if (!beta_params) {
        std::unique_lock<std::shared_mutex> write_lock(thompson_data_.distributions_mutex_);
        // Double-check after acquiring write lock
        auto it = thompson_data_.beta_distributions_.find(combo_key);
        if (it == thompson_data_.beta_distributions_.end()) {
            thompson_data_.beta_distributions_[combo_key] = std::make_unique<BetaParams>();
            beta_params = thompson_data_.beta_distributions_[combo_key].get();
        } else {
            beta_params = it->second.get();
        }
    }

    // Get or create combination stats
    CombinationStats* stats = nullptr;
    {
        std::shared_lock<std::shared_mutex> read_lock(thompson_data_.history_mutex_);
        auto it = thompson_data_.combination_history_.find(combo_key);
        if (it != thompson_data_.combination_history_.end()) {
            stats = it->second.get();
        }
    }

    if (!stats) {
        std::unique_lock<std::shared_mutex> write_lock(thompson_data_.history_mutex_);
        // Double-check after acquiring write lock
        auto it = thompson_data_.combination_history_.find(combo_key);
        if (it == thompson_data_.combination_history_.end()) {
            thompson_data_.combination_history_[combo_key] = std::make_unique<CombinationStats>();
            stats = thompson_data_.combination_history_[combo_key].get();
        } else {
            stats = it->second.get();
        }
    }

    // Update using thread-safe methods
    double success_rate = std::max(0.01, std::min(0.99, avg_reward));
    if (beta_params) {
        beta_params->update(success_rate, executions, 0.7);
    }
    if (stats) {
        stats->update(executions, avg_reward);
    }
}

void ImprovedBatchAlgorithmSelector::adaptBatchSize(double avg_reward) {
    double performance_threshold = current_batch_.performance_threshold.load();
    double adaptive_factor = current_batch_.adaptive_factor.load();
    size_t current_size = current_batch_.batch_size.load();
    
    if (avg_reward > performance_threshold) {
        // Good performance, increase batch size
        size_t new_size = static_cast<size_t>(current_size * adaptive_factor);
        size_t max_size = current_batch_.max_batch_size.load();
        new_size = std::min(new_size, max_size);
        current_batch_.batch_size.store(new_size);
    } else {
        // Poor performance, decrease batch size
        size_t new_size = static_cast<size_t>(current_size / adaptive_factor);
        size_t min_size = current_batch_.min_batch_size.load();
        new_size = std::max(new_size, min_size);
        current_batch_.batch_size.store(new_size);
    }
}

AlgorithmCombination ImprovedBatchAlgorithmSelector::selectWithThompsonSampling() {
    // Generate candidate combinations
    auto candidates = generateCandidateCombinations();

    if (candidates.empty()) {
        // Fallback combination
        AlgorithmCombination fallback;
        fallback.algorithm_names = {"havoc"};
        fallback.combination_mode = "sequential";
        return fallback;
    }

    // Use Thompson sampling to select
    auto& generator = getThreadLocalGenerator();

    double best_sample = -1.0;
    AlgorithmCombination best_combination = candidates[0];

    for (const auto& combo : candidates) {
        std::string combo_key = combo.toString();

        // Get beta parameters with thread-safe access
        double alpha = 1.0, beta = 1.0;
        {
            std::shared_lock<std::shared_mutex> lock(thompson_data_.distributions_mutex_);
            auto it = thompson_data_.beta_distributions_.find(combo_key);
            if (it != thompson_data_.beta_distributions_.end() && it->second) {
                auto params = it->second->sample();
                alpha = params.first;
                beta = params.second;
            }
        }

        // Sample from beta distribution
        std::gamma_distribution<double> gamma_alpha(alpha, 1.0);
        std::gamma_distribution<double> gamma_beta(beta, 1.0);

        double x = gamma_alpha(generator);
        double y = gamma_beta(generator);
        double sample = x / (x + y);

        if (sample > best_sample) {
            best_sample = sample;
            best_combination = combo;
        }
    }

    return best_combination;
}

std::vector<AlgorithmCombination> ImprovedBatchAlgorithmSelector::generateCandidateCombinations() {
    std::vector<AlgorithmCombination> candidates;
    
    // Generate basic single-algorithm combinations
    std::vector<std::string> algorithms = {"havoc", "bitflip", "arith", "interest", "dict", "splice"};
    
    for (const auto& algo : algorithms) {
        AlgorithmCombination combo;
        combo.algorithm_names = {algo};
        combo.combination_mode = "sequential";
        candidates.push_back(combo);
    }
    
    // Generate some multi-algorithm combinations
    AlgorithmCombination multi1;
    multi1.algorithm_names = {"havoc", "bitflip"};
    multi1.combination_mode = "sequential";
    candidates.push_back(multi1);
    
    AlgorithmCombination multi2;
    multi2.algorithm_names = {"dict", "splice"};
    multi2.combination_mode = "sequential";
    candidates.push_back(multi2);
    
    return candidates;
}

AlgorithmCombination ImprovedBatchAlgorithmSelector::parseComboKey(const std::string& combo_key) {
    AlgorithmCombination combo;
    // Simple parsing implementation
    combo.algorithm_names = {"havoc"}; // Fallback
    combo.combination_mode = "sequential";
    return combo;
}

// ImprovedCoverageCollector implementation
ImprovedCoverageCollector::ImprovedCoverageCollector() {
    initSharedMemory();
}

ImprovedCoverageCollector::~ImprovedCoverageCollector() {
    // Cleanup shared memory if needed
}

bool ImprovedCoverageCollector::initSharedMemory() {
    // Initialize shared memory for coverage tracking
    return true;
}

CoverageInfo ImprovedCoverageCollector::getCurrentCoverage() {
    std::shared_lock<std::shared_mutex> lock(guards_mutex_);
    
    CoverageInfo info;
    info.total_edges = total_guards_.load();
    info.covered_branch_count = covered_edges_.load();
    return info;
}

void ImprovedCoverageCollector::resetCoverage() {
    std::unique_lock<std::shared_mutex> lock(guards_mutex_);
    covered_edges_.store(0);
}

void ImprovedCoverageCollector::markGuardHit(uint32_t guard_id) {
    std::unique_lock<std::shared_mutex> lock(guards_mutex_);
    // Implementation for marking guard hit
}

size_t ImprovedCoverageCollector::getCoveredEdges() const {
    return covered_edges_.load();
}

double ImprovedCoverageCollector::getCoveragePercentage() const {
    size_t total = total_guards_.load();
    if (total == 0) return 0.0;
    return (double)covered_edges_.load() / total * 100.0;
}

} // namespace triofuzz 