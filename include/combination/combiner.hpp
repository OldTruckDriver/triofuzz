#pragma once

#include "../core/algorithm.hpp"
#include "../core/context.hpp"
#include <memory>
#include <vector>
#include <functional>
#include <type_traits>
// #include <future>  // Temporarily commented out to avoid compilation issues
#include <thread>
#include <atomic>
#include <queue>
#include <numeric>
#include <chrono>
#include <random>

namespace triofuzz {

// Composition modes
enum class CompositionMode {
    Sequential,    // Sequential execution: A -> B -> C
    Parallel,      // Parallel execution: A || B || C
    Conditional,   // Conditional execution: if (A) then B else C
    Nested,        // Nested execution: A(B(C))
    Weighted,      // Weighted combination: w1*A + w2*B + w3*C
    Pipeline,      // Pipeline: A | B | C
    Adaptive       // Adaptive: dynamically select using runtime information
};

// Combination strategy interface
class CombinationStrategy {
public:
    virtual ~CombinationStrategy() = default;
    
    // Decide how to combine algorithms
    virtual CompositionMode selectMode(
        const std::vector<AlgorithmInfo>& algorithms,
        const SharedContext& context
    ) = 0;
    
    // Compute weights (for weighted composition)
    virtual std::vector<double> computeWeights(
        const std::vector<AlgorithmInfo>& algorithms,
        const PerformanceMetrics& metrics
    ) = 0;
};

// Base class for composite algorithms
template<typename Input, typename Output, typename Context = SharedContext>
class CompositeAlgorithm : public Algorithm<Input, Output, Context> {
protected:
    std::vector<std::shared_ptr<Algorithm<Input, Output, Context>>> algorithms_;
    CompositionMode mode_;
    std::vector<double> weights_;
    
public:
    CompositeAlgorithm(CompositionMode mode = CompositionMode::Sequential)
        : mode_(mode) {}
    
    // Add a sub-algorithm
    void addAlgorithm(std::shared_ptr<Algorithm<Input, Output, Context>> algo) {
        algorithms_.push_back(algo);
        weights_.push_back(1.0);
    }
    
    // Set weights
    void setWeights(const std::vector<double>& weights) {
        if (weights.size() == algorithms_.size()) {
            weights_ = weights;
        }
    }
    
    // Get sub-algorithms
    const std::vector<std::shared_ptr<Algorithm<Input, Output, Context>>>& getAlgorithms() const {
        return algorithms_;
    }
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "Composite[" + std::to_string(algorithms_.size()) + "]";
        info.version = "1.0";
        info.type = AlgorithmType::Mutation; // Default type; may be adjusted based on sub-algorithms
        
        // Merge info from all sub-algorithms
        for (const auto& algo : algorithms_) {
            auto sub_info = algo->getInfo();
            info.provided_info.insert(info.provided_info.end(),
                                    sub_info.provided_info.begin(),
                                    sub_info.provided_info.end());
            info.required_info.insert(info.required_info.end(),
                                    sub_info.required_info.begin(),
                                    sub_info.required_info.end());
        }
        
        return info;
    }
    
    void saveState(StateWriter& writer) const override {
        writer.writeInt("algorithm_count", algorithms_.size());
        writer.writeInt("composition_mode", static_cast<int>(mode_));
        
        for (size_t i = 0; i < algorithms_.size(); ++i) {
            algorithms_[i]->saveState(writer);
        }
    }
    
    void loadState(StateReader& reader) override {
        // Implement state-loading logic
    }
};

// Sequential composite algorithm
template<typename Input, typename Output, typename Context = SharedContext>
class SequentialComposite : public CompositeAlgorithm<Input, Output, Context> {
public:
    SequentialComposite() : CompositeAlgorithm<Input, Output, Context>(CompositionMode::Sequential) {}
    
    Output execute(const Input& input, Context& ctx) override {
        return this->measureExecution([&]() {
            Input current_input = input;
            Output result;
            
            for (const auto& algo : this->algorithms_) {
                // Use each algorithm's output as the next algorithm's input
                if constexpr (std::is_same_v<Input, Output>) {
                    result = algo->execute(current_input, ctx);
                    current_input = result;
                } else {
                    result = algo->execute(current_input, ctx);
                }
            }
            
            return result;
        });
    }
};

// Parallel composite algorithm - simplified version (avoids std::future issues)
template<typename Input, typename Output, typename Context = SharedContext>
class ParallelComposite : public CompositeAlgorithm<Input, Output, Context> {
public:
    ParallelComposite() : CompositeAlgorithm<Input, Output, Context>(CompositionMode::Parallel) {}
    
    Output execute(const Input& input, Context& ctx) override {
        return this->measureExecution([&]() {
            std::vector<Output> results;
            
            // Temporarily execute sequentially to avoid std::future compilation issues.
            // TODO: Re-enable parallel execution after the standard library issue is fixed.
            for (const auto& algo : this->algorithms_) {
                ThreadLocalContext local_ctx(&ctx);
                auto result = algo->execute(input, local_ctx);
                local_ctx.sync();
                results.push_back(result);
            }
            
            // Merge results (requires a concrete implementation).
            return mergeResults(results);
        });
    }
    
private:
    Output mergeResults(const std::vector<Output>& results) {
        // By default, return the first result. Subclasses may override this method.
        if (!results.empty()) {
            return results[0];
        }
        return Output{};
    }
};

// Weighted composite algorithm
template<typename Input, typename Output, typename Context = SharedContext>
class WeightedComposite : public CompositeAlgorithm<Input, Output, Context> {
public:
    WeightedComposite() : CompositeAlgorithm<Input, Output, Context>(CompositionMode::Weighted) {}
    
    Output execute(const Input& input, Context& ctx) override {
        return this->measureExecution([&]() {
            // Randomly choose an algorithm to execute according to the weights.
            double total_weight = std::accumulate(this->weights_.begin(), this->weights_.end(), 0.0);
            double random_value = (std::rand() / static_cast<double>(RAND_MAX)) * total_weight;
            
            double cumulative_weight = 0.0;
            for (size_t i = 0; i < this->algorithms_.size(); ++i) {
                cumulative_weight += this->weights_[i];
                if (random_value <= cumulative_weight) {
                    return this->algorithms_[i]->execute(input, ctx);
                }
            }
            
            // Fallback to the last algorithm.
            return this->algorithms_.back()->execute(input, ctx);
        });
    }
};

// Conditional composite algorithm
template<typename Input, typename Output, typename Context = SharedContext>
class ConditionalComposite : public CompositeAlgorithm<Input, Output, Context> {
private:
    std::function<bool(const Input&, const Context&)> condition_;
    
public:
    ConditionalComposite(std::function<bool(const Input&, const Context&)> cond)
        : CompositeAlgorithm<Input, Output, Context>(CompositionMode::Conditional),
          condition_(cond) {}
    
    Output execute(const Input& input, Context& ctx) override {
        return this->measureExecution([&]() {
            if (this->algorithms_.size() < 2) {
                throw std::runtime_error("Conditional composite requires at least 2 algorithms");
            }
            
            if (condition_(input, ctx)) {
                return this->algorithms_[0]->execute(input, ctx);
            } else {
                return this->algorithms_[1]->execute(input, ctx);
            }
        });
    }
};

// Pipeline composite algorithm
template<typename Input, typename Output, typename Context = SharedContext>
class PipelineComposite : public CompositeAlgorithm<Input, Output, Context> {
private:
    std::queue<Input> pipeline_queue_;
    std::mutex queue_mutex_;
    
public:
    PipelineComposite() : CompositeAlgorithm<Input, Output, Context>(CompositionMode::Pipeline) {}
    
    Output execute(const Input& input, Context& ctx) override {
        return this->measureExecution([&]() {
            // Pipeline execution: each stage can process different inputs in parallel.
            std::vector<std::thread> stage_threads;
            std::vector<std::queue<Input>> stage_queues(this->algorithms_.size() + 1);
            std::vector<std::mutex> stage_mutexes(this->algorithms_.size() + 1);
            std::atomic<bool> done{false};
            
            // Initial input
            stage_queues[0].push(input);
            
            // Create a thread for each stage
            for (size_t i = 0; i < this->algorithms_.size(); ++i) {
                stage_threads.emplace_back([&, i]() {
                    while (!done.load()) {
                        std::unique_lock<std::mutex> in_lock(stage_mutexes[i]);
                        if (!stage_queues[i].empty()) {
                            auto stage_input = stage_queues[i].front();
                            stage_queues[i].pop();
                            in_lock.unlock();
                            
                            ThreadLocalContext local_ctx(&ctx);
                            auto result = this->algorithms_[i]->execute(stage_input, local_ctx);
                            local_ctx.sync();
                            
                            std::unique_lock<std::mutex> out_lock(stage_mutexes[i + 1]);
                            if constexpr (std::is_same_v<Input, Output>) {
                                stage_queues[i + 1].push(result);
                            }
                        } else {
                            in_lock.unlock();
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                    }
                });
            }
            
            // Wait for the final result
            Output final_result;
            auto start_time = std::chrono::steady_clock::now();
            while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
                std::unique_lock<std::mutex> lock(stage_mutexes.back());
                if (!stage_queues.back().empty()) {
                    if constexpr (std::is_same_v<Input, Output>) {
                        final_result = stage_queues.back().front();
                        stage_queues.back().pop();
                    }
                    break;
                }
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            
            done.store(true);
            for (auto& thread : stage_threads) {
                thread.join();
            }
            
            return final_result;
        });
    }
};

// Algorithm combiner
class AlgorithmCombiner {
private:
    std::unique_ptr<CombinationStrategy> strategy_;
    
public:
    // Set the combination strategy
    void setStrategy(std::unique_ptr<CombinationStrategy> strategy) {
        strategy_ = std::move(strategy);
    }
    
    // Create a composite algorithm
    template<typename Input, typename Output, typename Context = SharedContext>
    std::unique_ptr<CompositeAlgorithm<Input, Output, Context>> combine(
        CompositionMode mode,
        const std::vector<std::shared_ptr<Algorithm<Input, Output, Context>>>& algorithms
    ) {
        std::unique_ptr<CompositeAlgorithm<Input, Output, Context>> composite;
        
        switch (mode) {
            case CompositionMode::Sequential:
                composite = std::make_unique<SequentialComposite<Input, Output, Context>>();
                break;
            case CompositionMode::Parallel:
                composite = std::make_unique<ParallelComposite<Input, Output, Context>>();
                break;
            case CompositionMode::Weighted:
                composite = std::make_unique<WeightedComposite<Input, Output, Context>>();
                break;
            default:
                composite = std::make_unique<SequentialComposite<Input, Output, Context>>();
        }
        
        for (const auto& algo : algorithms) {
            composite->addAlgorithm(algo);
        }
        
        return composite;
    }
    
    // Dynamic combination
    template<typename Input, typename Output, typename Context = SharedContext>
    std::unique_ptr<CompositeAlgorithm<Input, Output, Context>> dynamicCombine(
        const std::vector<std::shared_ptr<Algorithm<Input, Output, Context>>>& algorithms,
        const Context& context
    ) {
        if (!strategy_) {
            throw std::runtime_error("No combination strategy set");
        }
        
        // Collect algorithm info
        std::vector<AlgorithmInfo> algo_infos;
        for (const auto& algo : algorithms) {
            algo_infos.push_back(algo->getInfo());
        }
        
        // Let the strategy decide the composition mode
        CompositionMode mode = strategy_->selectMode(algo_infos, context);
        
        // Create the composite
        auto composite = combine<Input, Output, Context>(mode, algorithms);
        
        // If weighted mode, set weights
        if (mode == CompositionMode::Weighted) {
            std::vector<PerformanceMetrics> metrics;
            for (const auto& algo : algorithms) {
                metrics.push_back(algo->getMetrics());
            }
            auto weights = strategy_->computeWeights(algo_infos, metrics[0]); // Simplified example
            composite->setWeights(weights);
        }
        
        return composite;
    }
    
    // Create an adaptive combination
    template<typename Input, typename Output, typename Context = SharedContext>
    std::unique_ptr<CompositeAlgorithm<Input, Output, Context>> createAdaptiveCombination(
        const std::vector<std::shared_ptr<Algorithm<Input, Output, Context>>>& algorithms
    ) {
        // Adaptive composition adjusts dynamically based on runtime performance.
        class AdaptiveComposite : public CompositeAlgorithm<Input, Output, Context> {
        private:
            std::map<size_t, double> algorithm_scores_;
            
        public:
            AdaptiveComposite() : CompositeAlgorithm<Input, Output, Context>(CompositionMode::Adaptive) {}
            
            Output execute(const Input& input, Context& ctx) override {
                // Select the algorithm with the highest score.
                size_t best_idx = 0;
                double best_score = -1.0;
                
                for (size_t i = 0; i < this->algorithms_.size(); ++i) {
                    double score = algorithm_scores_[i];
                    
                    // Balance exploration vs. exploitation.
                    double exploration_bonus = 1.0 / (this->algorithms_[i]->getMetrics().execution_count + 1);
                    score += exploration_bonus * 0.1;
                    
                    if (score > best_score) {
                        best_score = score;
                        best_idx = i;
                    }
                }
                
                // Execute the selected algorithm.
                auto start = std::chrono::high_resolution_clock::now();
                auto result = this->algorithms_[best_idx]->execute(input, ctx);
                auto end = std::chrono::high_resolution_clock::now();
                
                // Update score.
                double exec_time = std::chrono::duration<double, std::milli>(end - start).count();
                double reward = 0.0;
                
                // Compute reward based on execution outcome.
                if (ctx.has("coverage_gain")) {
                    reward += ctx.template get<double>("coverage_gain").value_or(0.0);
                }
                reward += 1.0 / (exec_time + 1.0); // Execution speed reward
                
                // Update via exponential moving average.
                algorithm_scores_[best_idx] = algorithm_scores_[best_idx] * 0.95 + reward * 0.05;
                
                return result;
            }
        };
        
        auto adaptive = std::make_unique<AdaptiveComposite>();
        for (const auto& algo : algorithms) {
            adaptive->addAlgorithm(algo);
        }
        
        return adaptive;
    }
};

} // namespace triofuzz
