#include "../../include/combination/combiner.hpp"
#include "../../include/core/engine.hpp"
#include <algorithm>
#include <random>

namespace triofuzz {

// Random combination strategy implementation
class RandomCombinationStrategy : public CombinationStrategy {
private:
    std::mt19937 random_gen_;
    size_t min_algorithms_;
    size_t max_algorithms_;
    
public:
    RandomCombinationStrategy(size_t min_algos = 1, size_t max_algos = 3) 
        : random_gen_(std::random_device{}()), 
          min_algorithms_(min_algos), 
          max_algorithms_(max_algos) {}
    
    CompositionMode selectMode(
        const std::vector<AlgorithmInfo>& algorithms,
        const SharedContext& context) override {
        
        std::uniform_int_distribution<int> mode_dist(0, 3);
        int mode_choice = mode_dist(random_gen_);
        
        switch (mode_choice) {
            case 0: return CompositionMode::Sequential;
            case 1: return CompositionMode::Parallel;
            case 2: return CompositionMode::Weighted;
            default: return CompositionMode::Sequential;
        }
    }
    
    std::vector<double> computeWeights(
        const std::vector<AlgorithmInfo>& algorithms,
        const PerformanceMetrics& metrics) override {
        
        std::vector<double> weights(algorithms.size());
        std::uniform_real_distribution<double> weight_dist(0.1, 1.0);
        
        for (size_t i = 0; i < weights.size(); ++i) {
            weights[i] = weight_dist(random_gen_);
        }
        
        // Normalize weights
        double total_weight = std::accumulate(weights.begin(), weights.end(), 0.0);
        if (total_weight > 0.0) {
            for (auto& weight : weights) {
                weight /= total_weight;
            }
        }
        
        return weights;
    }
};

// Performance-based combination strategy
class PerformanceBasedStrategy : public CombinationStrategy {
private:
    std::map<std::string, double> algorithm_scores_;
    
public:
    CompositionMode selectMode(
        const std::vector<AlgorithmInfo>& algorithms,
        const SharedContext& context) override {
        
        // If we have performance data, use parallel for high-performing algorithms
        bool has_high_performers = false;
        for (const auto& algo : algorithms) {
            if (algorithm_scores_[algo.name] > 0.7) {
                has_high_performers = true;
                break;
            }
        }
        
        if (has_high_performers && algorithms.size() > 1) {
            return CompositionMode::Parallel;
        } else if (algorithms.size() > 2) {
            return CompositionMode::Weighted;
        } else {
            return CompositionMode::Sequential;
        }
    }
    
    std::vector<double> computeWeights(
        const std::vector<AlgorithmInfo>& algorithms,
        const PerformanceMetrics& metrics) override {
        
        std::vector<double> weights(algorithms.size());
        
        for (size_t i = 0; i < algorithms.size(); ++i) {
            const auto& algo = algorithms[i];
            double score = algorithm_scores_[algo.name];
            
            // Default score if no data
            if (score == 0.0) {
                score = 0.5;
            }
            
            // Consider algorithm type
            switch (algo.type) {
                case AlgorithmType::Mutation:
                    weights[i] = score * 1.2; // Favor mutations
                    break;
                case AlgorithmType::Analysis:
                    weights[i] = score * 1.1; // Slightly favor coverage
                    break;
                default:
                    weights[i] = score;
                    break;
            }
        }
        
        // Normalize weights
        double total_weight = std::accumulate(weights.begin(), weights.end(), 0.0);
        if (total_weight > 0.0) {
            for (auto& weight : weights) {
                weight /= total_weight;
            }
        }
        
        return weights;
    }
    
    void updateAlgorithmScore(const std::string& algorithm_name, double score) {
        // Exponential moving average
        double alpha = 0.3;
        algorithm_scores_[algorithm_name] = 
            alpha * score + (1.0 - alpha) * algorithm_scores_[algorithm_name];
    }
};

// Factory function to create combination strategies
std::unique_ptr<CombinationStrategy> createCombinationStrategy(const std::string& strategy_name) {
    if (strategy_name == "random") {
        return std::make_unique<RandomCombinationStrategy>();
    } else if (strategy_name == "performance") {
        return std::make_unique<PerformanceBasedStrategy>();
    } else {
        // Default to random strategy
        return std::make_unique<RandomCombinationStrategy>();
    }
}

} // namespace triofuzz 