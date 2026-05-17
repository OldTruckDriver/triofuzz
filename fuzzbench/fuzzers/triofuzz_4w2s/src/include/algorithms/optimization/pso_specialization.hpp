#pragma once

#include "optimization_algorithms.hpp"
#include <random>
#include <cmath>

namespace triofuzz {

// Specialized implementation of binary PSO for optimizing binary data
class BinaryPSO : public ParticleSwarmOptimization<std::vector<uint8_t>> {
private:
    // Binary-PSO-specific parameters
    double sigmoid_steepness_ = 4.0;
    double mutation_rate_ = 0.01;
    
    // Random number generator
    std::mt19937 random_gen_{std::random_device{}()};
    
    // Stores particle velocities
    std::vector<std::vector<double>> velocities_;
    
public:
    BinaryPSO() = default;
    
    AlgorithmInfo getInfo() const override {
        auto info = ParticleSwarmOptimization<std::vector<uint8_t>>::getInfo();
        info.name = "binary_pso";
        info.description = "Binary PSO for fuzzing data optimization";
        return info;
    }
    
    void updateParameters(const Parameters& params) override {
        ParticleSwarmOptimization<std::vector<uint8_t>>::updateParameters(params);
        
        auto steepness = params.get<double>("sigmoid_steepness");
        if (steepness.has_value()) sigmoid_steepness_ = steepness.value();
        
        auto mutation = params.get<double>("mutation_rate");
        if (mutation.has_value()) mutation_rate_ = mutation.value();
    }
    
    void saveState(StateWriter& writer) const override {
        ParticleSwarmOptimization<std::vector<uint8_t>>::saveState(writer);
        writer.writeDouble("sigmoid_steepness", sigmoid_steepness_);
        writer.writeDouble("mutation_rate", mutation_rate_);
    }
    
    void loadState(StateReader& reader) override {
        ParticleSwarmOptimization<std::vector<uint8_t>>::loadState(reader);
        auto steepness = reader.readDouble("sigmoid_steepness");
        if (steepness.has_value()) sigmoid_steepness_ = steepness.value();
        
        auto mutation = reader.readDouble("mutation_rate");
        if (mutation.has_value()) mutation_rate_ = mutation.value();
    }
    
protected:
    // Binary PSO specialized execution
    std::vector<uint8_t> execute(const OptimizationProblem<std::vector<uint8_t>>& problem, SharedContext& ctx) override {
        return measureExecution([&]() {
            // Initialize swarm
            initializeSwarm(problem);
            
            std::vector<uint8_t> global_best;
            double global_best_fitness = -std::numeric_limits<double>::max();
            
            // Main PSO loop
            for (size_t iter = 0; iter < max_iterations_; ++iter) {
                for (size_t i = 0; i < swarm_size_; ++i) {
                    // Evaluate fitness
                    double fitness = problem.evaluate(particles_[i]);
                    
                    // Update personal best
                    if (fitness > personal_best_fitness_[i]) {
                        personal_best_[i] = particles_[i];
                        personal_best_fitness_[i] = fitness;
                    }
                    
                    // Update global best
                    if (fitness > global_best_fitness) {
                        global_best = particles_[i];
                        global_best_fitness = fitness;
                    }
                }
                
                // Update particle positions and velocities
                updateSwarm(global_best);
            }
            
            return global_best;
        });
    }
    
private:
    std::vector<std::vector<uint8_t>> particles_;
    std::vector<std::vector<uint8_t>> personal_best_;
    std::vector<double> personal_best_fitness_;
    size_t swarm_size_ = 50;
    size_t max_iterations_ = 1000;
    double inertia_weight_ = 0.729;
    double cognitive_weight_ = 1.49445;
    double social_weight_ = 1.49445;
    
    void initializeSwarm(const OptimizationProblem<std::vector<uint8_t>>& problem) {
        particles_.clear();
        personal_best_.clear();
        personal_best_fitness_.clear();
        velocities_.clear();
        
        particles_.resize(swarm_size_);
        personal_best_.resize(swarm_size_);
        personal_best_fitness_.resize(swarm_size_, -std::numeric_limits<double>::max());
        velocities_.resize(swarm_size_);
        
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        
        // Assume the problem can provide solution size somehow.
        size_t solution_size = 100; // Default size
        
        for (size_t i = 0; i < swarm_size_; ++i) {
            particles_[i].resize(solution_size);
            velocities_[i].resize(solution_size, 0.0);
            
            for (size_t j = 0; j < solution_size; ++j) {
                particles_[i][j] = byte_dist(random_gen_);
            }
            
            personal_best_[i] = particles_[i];
        }
    }
    
    void updateSwarm(const std::vector<uint8_t>& global_best) {
        std::uniform_real_distribution<double> rand_dist(0.0, 1.0);
        
        for (size_t i = 0; i < swarm_size_; ++i) {
            for (size_t j = 0; j < particles_[i].size(); ++j) {
                // Update velocity
                double r1 = rand_dist(random_gen_);
                double r2 = rand_dist(random_gen_);
                
                velocities_[i][j] = inertia_weight_ * velocities_[i][j] +
                                   cognitive_weight_ * r1 * (personal_best_[i][j] - particles_[i][j]) +
                                   social_weight_ * r2 * (global_best[j] - particles_[i][j]);
                
                // Update position using sigmoid
                double sigmoid_val = 1.0 / (1.0 + std::exp(-sigmoid_steepness_ * velocities_[i][j]));
                
                if (rand_dist(random_gen_) < sigmoid_val) {
                    particles_[i][j] = 1;
                } else {
                    particles_[i][j] = 0;
                }
                
                // Apply mutation
                if (rand_dist(random_gen_) < mutation_rate_) {
                    particles_[i][j] = byte_dist(random_gen_);
                }
            }
        }
    }
    
    std::uniform_int_distribution<uint8_t> byte_dist{0, 255};
};

} // namespace triofuzz 
