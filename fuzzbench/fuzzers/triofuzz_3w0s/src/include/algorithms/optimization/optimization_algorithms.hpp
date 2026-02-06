#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
// optimization_types archived (types unused in active code)
#include <cmath>
#include <random>
#include <algorithm>
#include <functional>
#include <limits>
#include <memory>
#include <vector>

namespace triofuzz {

// 优化问题定义
template<typename Solution>
struct OptimizationProblem {
    using EvaluationFunc = std::function<double(const Solution&)>;
    using NeighborFunc = std::function<Solution(const Solution&)>;
    using CrossoverFunc = std::function<Solution(const Solution&, const Solution&)>;
    using MutationFunc = std::function<Solution(const Solution&)>;
    
    EvaluationFunc evaluate;
    NeighborFunc generate_neighbor;
    CrossoverFunc crossover;
    MutationFunc mutate;
    
    // 约束条件
    std::function<bool(const Solution&)> is_valid;
    
    // 问题边界
    Solution lower_bound;
    Solution upper_bound;
};

// 模拟退火算法
template<typename Solution>
class SimulatedAnnealing : public Algorithm<OptimizationProblem<Solution>, Solution, SharedContext> {
private:
    // 退火参数
    double initial_temperature_ = 100.0;
    double cooling_rate_ = 0.95;
    double min_temperature_ = 0.01;
    size_t iterations_per_temp_ = 100;
    
    // 随机数生成器
    std::mt19937 random_gen_{std::random_device{}()};
    
public:
    SimulatedAnnealing() = default;
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "simulated_annealing";
        info.type = AlgorithmType::Analysis;
        info.version = "1.0";
        info.provided_info = {InfoType::Energy};
        return info;
    }
    
    Solution execute(const OptimizationProblem<Solution>& problem, SharedContext& ctx) override {
        return this->measureExecution([&]() {
            // 初始解
            Solution current_solution = problem.lower_bound;
            double current_cost = problem.evaluate(current_solution);
            
            Solution best_solution = current_solution;
            double best_cost = current_cost;
            
            double temperature = initial_temperature_;
            
            // 退火主循环
            while (temperature > min_temperature_) {
                for (size_t iter = 0; iter < iterations_per_temp_; ++iter) {
                    // 生成邻居解
                    Solution neighbor = problem.generate_neighbor(current_solution);
                    
                    // 确保解有效
                    if (problem.is_valid && !problem.is_valid(neighbor)) {
                        continue;
                    }
                    
                    double neighbor_cost = problem.evaluate(neighbor);
                    double delta = neighbor_cost - current_cost;
                    
                    // 接受准则
                    if (delta < 0 || acceptanceProbability(delta, temperature) > randomDouble()) {
                        current_solution = neighbor;
                        current_cost = neighbor_cost;
                        
                        // 更新最佳解
                        if (current_cost < best_cost) {
                            best_solution = current_solution;
                            best_cost = current_cost;
                            
                            // 更新上下文
                            updateContext(ctx, best_cost, temperature);
                        }
                    }
                }
                
                // 降温
                temperature *= cooling_rate_;
            }
            
            return best_solution;
        });
    }
    
    void updateParameters(const Parameters& params) override {
        auto temp = params.get<double>("initial_temperature");
        if (temp.has_value()) initial_temperature_ = temp.value();
        
        auto rate = params.get<double>("cooling_rate");
        if (rate.has_value()) cooling_rate_ = rate.value();
        
        auto min_temp = params.get<double>("min_temperature");
        if (min_temp.has_value()) min_temperature_ = min_temp.value();
        
        auto iters = params.get<size_t>("iterations_per_temp");
        if (iters.has_value()) iterations_per_temp_ = iters.value();
    }
    
    void saveState(StateWriter& writer) const override {
        writer.writeDouble("initial_temperature", initial_temperature_);
        writer.writeDouble("cooling_rate", cooling_rate_);
        writer.writeDouble("min_temperature", min_temperature_);
        writer.writeInt("iterations_per_temp", iterations_per_temp_);
    }
    
    void loadState(StateReader& reader) override {
        auto temp = reader.readDouble("initial_temperature");
        if (temp.has_value()) initial_temperature_ = temp.value();
        
        auto rate = reader.readDouble("cooling_rate");
        if (rate.has_value()) cooling_rate_ = rate.value();
        
        auto min_temp = reader.readDouble("min_temperature");
        if (min_temp.has_value()) min_temperature_ = min_temp.value();
        
        auto iters = reader.readInt("iterations_per_temp");
        if (iters.has_value()) iterations_per_temp_ = iters.value();
    }
    
private:
    double acceptanceProbability(double delta, double temperature) {
        return std::exp(-delta / temperature);
    }
    
    double randomDouble() {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(random_gen_);
    }
    
    void updateContext(SharedContext& ctx, double best_cost, double temperature) {
        EnergyInfo energy_info;
        energy_info.current_energy = 1.0 / (1.0 + best_cost);
        energy_info.energy_factors["temperature"] = temperature / initial_temperature_;
        ctx.setEnergyInfo(energy_info);
    }
};

// 遗传算法
template<typename Solution>
class GeneticAlgorithm : public Algorithm<OptimizationProblem<Solution>, Solution, SharedContext> {
private:
    // GA参数
    size_t population_size_ = 100;
    size_t generations_ = 1000;
    double crossover_rate_ = 0.8;
    double mutation_rate_ = 0.1;
    double elite_ratio_ = 0.1;
    
    // 选择策略
    enum class SelectionMethod {
        Tournament,
        RouletteWheel,
        Rank
    };
    SelectionMethod selection_method_ = SelectionMethod::Tournament;
    size_t tournament_size_ = 3;
    
    std::mt19937 random_gen_{std::random_device{}()};
    
    struct Individual {
        Solution solution;
        double fitness;
        
        bool operator<(const Individual& other) const {
            return fitness < other.fitness; // 假设最小化问题
        }
    };
    
public:
    GeneticAlgorithm() = default;
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "genetic_algorithm";
        info.type = AlgorithmType::Analysis;
        info.version = "1.0";
        info.provided_info = {InfoType::Energy};
        return info;
    }
    
    Solution execute(const OptimizationProblem<Solution>& problem, SharedContext& ctx) override {
        return this->measureExecution([&]() {
            // 初始化种群
            std::vector<Individual> population = initializePopulation(problem);
            
            Solution best_solution = population[0].solution;
            double best_fitness = population[0].fitness;
            
            // 进化主循环
            for (size_t gen = 0; gen < generations_; ++gen) {
                // 评估种群
                evaluatePopulation(population, problem);
                
                // 排序（精英保留）
                std::sort(population.begin(), population.end());
                
                // 更新最佳解
                if (population[0].fitness < best_fitness) {
                    best_solution = population[0].solution;
                    best_fitness = population[0].fitness;
                    
                    updateContext(ctx, best_fitness, gen);
                }
                
                // 生成新种群
                std::vector<Individual> new_population;
                
                // 精英保留
                size_t elite_count = static_cast<size_t>(population_size_ * elite_ratio_);
                for (size_t i = 0; i < elite_count; ++i) {
                    new_population.push_back(population[i]);
                }
                
                // 繁殖
                while (new_population.size() < population_size_) {
                    Individual parent1 = select(population);
                    Individual parent2 = select(population);
                    
                    Individual offspring;
                    
                    // 交叉
                    if (randomDouble() < crossover_rate_) {
                        offspring.solution = problem.crossover(parent1.solution, parent2.solution);
                    } else {
                        offspring.solution = randomDouble() < 0.5 ? parent1.solution : parent2.solution;
                    }
                    
                    // 变异
                    if (randomDouble() < mutation_rate_) {
                        offspring.solution = problem.mutate(offspring.solution);
                    }
                    
                    // 确保解有效
                    if (!problem.is_valid || problem.is_valid(offspring.solution)) {
                        new_population.push_back(offspring);
                    }
                }
                
                population = std::move(new_population);
            }
            
            return best_solution;
        });
    }
    
    void updateParameters(const Parameters& params) override {
        auto pop_size = params.get<size_t>("population_size");
        if (pop_size.has_value()) population_size_ = pop_size.value();
        
        auto gens = params.get<size_t>("generations");
        if (gens.has_value()) generations_ = gens.value();
        
        auto cross_rate = params.get<double>("crossover_rate");
        if (cross_rate.has_value()) crossover_rate_ = cross_rate.value();
        
        auto mut_rate = params.get<double>("mutation_rate");
        if (mut_rate.has_value()) mutation_rate_ = mut_rate.value();
    }
    
    void saveState(StateWriter& writer) const override {
        writer.writeInt("population_size", population_size_);
        writer.writeInt("generations", generations_);
        writer.writeDouble("crossover_rate", crossover_rate_);
        writer.writeDouble("mutation_rate", mutation_rate_);
    }
    
    void loadState(StateReader& reader) override {
        auto pop_size = reader.readInt("population_size");
        if (pop_size.has_value()) population_size_ = pop_size.value();
        
        auto gens = reader.readInt("generations");
        if (gens.has_value()) generations_ = gens.value();
        
        auto cross_rate = reader.readDouble("crossover_rate");
        if (cross_rate.has_value()) crossover_rate_ = cross_rate.value();
        
        auto mut_rate = reader.readDouble("mutation_rate");
        if (mut_rate.has_value()) mutation_rate_ = mut_rate.value();
    }
    
private:
    std::vector<Individual> initializePopulation(const OptimizationProblem<Solution>& problem) {
        std::vector<Individual> population;
        population.reserve(population_size_);
        
        for (size_t i = 0; i < population_size_; ++i) {
            Individual ind;
            // 随机初始化（应该根据具体问题定制）
            ind.solution = problem.generate_neighbor(problem.lower_bound);
            population.push_back(ind);
        }
        
        return population;
    }
    
    void evaluatePopulation(std::vector<Individual>& population, 
                           const OptimizationProblem<Solution>& problem) {
        for (auto& ind : population) {
            ind.fitness = problem.evaluate(ind.solution);
        }
    }
    
    Individual select(const std::vector<Individual>& population) {
        switch (selection_method_) {
            case SelectionMethod::Tournament:
                return tournamentSelection(population);
            case SelectionMethod::RouletteWheel:
                return rouletteWheelSelection(population);
            case SelectionMethod::Rank:
                return rankSelection(population);
            default:
                return tournamentSelection(population);
        }
    }
    
    Individual tournamentSelection(const std::vector<Individual>& population) {
        std::uniform_int_distribution<size_t> dist(0, population.size() - 1);
        
        size_t best_idx = dist(random_gen_);
        double best_fitness = population[best_idx].fitness;
        
        for (size_t i = 1; i < tournament_size_; ++i) {
            size_t idx = dist(random_gen_);
            if (population[idx].fitness < best_fitness) {
                best_idx = idx;
                best_fitness = population[idx].fitness;
            }
        }
        
        return population[best_idx];
    }
    
    Individual rouletteWheelSelection(const std::vector<Individual>& population) {
        // 计算适应度总和（转换为正值）
        double min_fitness = std::numeric_limits<double>::max();
        for (const auto& ind : population) {
            min_fitness = std::min(min_fitness, ind.fitness);
        }
        
        double total_fitness = 0.0;
        for (const auto& ind : population) {
            total_fitness += (min_fitness - ind.fitness + 1.0);
        }
        
        // 轮盘赌选择
        std::uniform_real_distribution<double> dist(0.0, total_fitness);
        double random_point = dist(random_gen_);
        
        double cumulative = 0.0;
        for (const auto& ind : population) {
            cumulative += (min_fitness - ind.fitness + 1.0);
            if (random_point <= cumulative) {
                return ind;
            }
        }
        
        return population.back();
    }
    
    Individual rankSelection(const std::vector<Individual>& population) {
        // 基于排名的选择（线性排名）
        double rank_sum = (population.size() * (population.size() + 1)) / 2.0;
        std::uniform_real_distribution<double> dist(0.0, rank_sum);
        double random_point = dist(random_gen_);
        
        double cumulative = 0.0;
        for (size_t i = 0; i < population.size(); ++i) {
            cumulative += population.size() - i;
            if (random_point <= cumulative) {
                return population[i];
            }
        }
        
        return population.back();
    }
    
    double randomDouble() {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(random_gen_);
    }
    
    void updateContext(SharedContext& ctx, double best_fitness, size_t generation) {
        EnergyInfo energy_info;
        energy_info.current_energy = 1.0 / (1.0 + best_fitness);
        energy_info.energy_factors["generation"] = static_cast<double>(generation) / generations_;
        energy_info.energy_factors["convergence"] = 1.0 - (mutation_rate_ * generation / generations_);
        ctx.setEnergyInfo(energy_info);
    }
};

// 粒子群优化算法
template<typename Solution>
class ParticleSwarmOptimization : public Algorithm<OptimizationProblem<Solution>, Solution, SharedContext> {
private:
    // PSO参数
    size_t swarm_size_ = 50;
    size_t max_iterations_ = 1000;
    double inertia_weight_ = 0.729;
    double cognitive_weight_ = 1.49445;
    double social_weight_ = 1.49445;
    double velocity_clamp_ = 0.2;
    
    std::mt19937 random_gen_{std::random_device{}()};
    
    struct Particle {
        Solution position;
        Solution velocity;
        Solution personal_best;
        double fitness;
        double personal_best_fitness;
    };
    
public:
    ParticleSwarmOptimization() = default;
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "particle_swarm";
        info.type = AlgorithmType::Analysis;
        info.version = "1.0";
        info.provided_info = {InfoType::Energy};
        return info;
    }
    
    Solution execute(const OptimizationProblem<Solution>& problem, SharedContext& ctx) override {
        return this->measureExecution([&]() {
            // 初始化粒子群
            std::vector<Particle> swarm = initializeSwarm(problem);
            
            Solution global_best = swarm[0].position;
            double global_best_fitness = swarm[0].fitness;
            
            // PSO主循环
            for (size_t iter = 0; iter < max_iterations_; ++iter) {
                // 评估粒子
                for (auto& particle : swarm) {
                    particle.fitness = problem.evaluate(particle.position);
                    
                    // 更新个体最优
                    if (particle.fitness < particle.personal_best_fitness) {
                        particle.personal_best = particle.position;
                        particle.personal_best_fitness = particle.fitness;
                    }
                    
                    // 更新全局最优
                    if (particle.fitness < global_best_fitness) {
                        global_best = particle.position;
                        global_best_fitness = particle.fitness;
                        
                        updateContext(ctx, global_best_fitness, iter);
                    }
                }
                
                // 更新粒子速度和位置
                for (auto& particle : swarm) {
                    updateParticle(particle, global_best, problem);
                }
                
                // 动态调整惯性权重
                inertia_weight_ = 0.9 - (0.5 * iter / max_iterations_);
            }
            
            return global_best;
        });
    }
    
    void updateParameters(const Parameters& params) override {
        auto swarm = params.get<size_t>("swarm_size");
        if (swarm.has_value()) swarm_size_ = swarm.value();
        
        auto iters = params.get<size_t>("max_iterations");
        if (iters.has_value()) max_iterations_ = iters.value();
        
        auto inertia = params.get<double>("inertia_weight");
        if (inertia.has_value()) inertia_weight_ = inertia.value();
        
        auto cognitive = params.get<double>("cognitive_weight");
        if (cognitive.has_value()) cognitive_weight_ = cognitive.value();
        
        auto social = params.get<double>("social_weight");
        if (social.has_value()) social_weight_ = social.value();
    }
    
    void saveState(StateWriter& writer) const override {
        writer.writeInt("swarm_size", swarm_size_);
        writer.writeInt("max_iterations", max_iterations_);
        writer.writeDouble("inertia_weight", inertia_weight_);
        writer.writeDouble("cognitive_weight", cognitive_weight_);
        writer.writeDouble("social_weight", social_weight_);
    }
    
    void loadState(StateReader& reader) override {
        auto swarm = reader.readInt("swarm_size");
        if (swarm.has_value()) swarm_size_ = swarm.value();
        
        auto iters = reader.readInt("max_iterations");
        if (iters.has_value()) max_iterations_ = iters.value();
        
        auto inertia = reader.readDouble("inertia_weight");
        if (inertia.has_value()) inertia_weight_ = inertia.value();
        
        auto cognitive = reader.readDouble("cognitive_weight");
        if (cognitive.has_value()) cognitive_weight_ = cognitive.value();
        
        auto social = reader.readDouble("social_weight");
        if (social.has_value()) social_weight_ = social.value();
    }
    
private:
    std::vector<Particle> initializeSwarm(const OptimizationProblem<Solution>& problem) {
        std::vector<Particle> swarm;
        swarm.reserve(swarm_size_);
        
        for (size_t i = 0; i < swarm_size_; ++i) {
            Particle particle;
            
            // 随机初始化位置
            particle.position = problem.generate_neighbor(problem.lower_bound);
            particle.velocity = Solution{}; // 零速度开始
            particle.personal_best = particle.position;
            particle.fitness = problem.evaluate(particle.position);
            particle.personal_best_fitness = particle.fitness;
            
            swarm.push_back(particle);
        }
        
        return swarm;
    }
    
    void updateParticle(Particle& particle, const Solution& global_best,
                       const OptimizationProblem<Solution>& problem) {
        // PSO速度更新公式
        // v = w*v + c1*r1*(pbest - x) + c2*r2*(gbest - x)
        
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        double r1 = dist(random_gen_);
        double r2 = dist(random_gen_);
        
        // 这里需要Solution类型支持向量运算
        // 简化示例，实际实现需要根据Solution类型定制
        updateVelocity(particle.velocity, particle.position, 
                      particle.personal_best, global_best,
                      inertia_weight_, cognitive_weight_ * r1, social_weight_ * r2);
        
        // 速度限制
        clampVelocity(particle.velocity);
        
        // 更新位置
        updatePosition(particle.position, particle.velocity, problem);
    }
    
    void updateVelocity(Solution& velocity, const Solution& position,
                       const Solution& personal_best, const Solution& global_best,
                       double inertia, double cognitive, double social) {
        // 实际实现需要根据Solution类型定制
        // 这里是概念性的伪代码
    }
    
    void clampVelocity(Solution& velocity) {
        // 限制速度在合理范围内
    }
    
    void updatePosition(Solution& position, const Solution& velocity,
                       const OptimizationProblem<Solution>& problem) {
        // 更新位置并确保在边界内
    }
    
    void updateContext(SharedContext& ctx, double best_fitness, size_t iteration) {
        EnergyInfo energy_info;
        energy_info.current_energy = 1.0 / (1.0 + best_fitness);
        energy_info.energy_factors["iteration_progress"] = static_cast<double>(iteration) / max_iterations_;
        energy_info.energy_factors["inertia"] = inertia_weight_;
        ctx.setEnergyInfo(energy_info);
    }
};

// Template specializations for vector<double>
template<>
void ParticleSwarmOptimization<std::vector<double>>::updateVelocity(
    std::vector<double>& velocity, const std::vector<double>& position,
    const std::vector<double>& personal_best, const std::vector<double>& global_best,
    double inertia, double cognitive, double social);

template<>
void ParticleSwarmOptimization<std::vector<double>>::clampVelocity(
    std::vector<double>& velocity);

template<>
void ParticleSwarmOptimization<std::vector<double>>::updatePosition(
    std::vector<double>& position, const std::vector<double>& velocity,
    const OptimizationProblem<std::vector<double>>& problem);

// 针对Fuzzing的特化：种子能量优化
class SeedEnergyOptimizer {
private:
    std::unique_ptr<SimulatedAnnealing<std::vector<double>>> sa_optimizer_;
    
public:
    SeedEnergyOptimizer() {
        sa_optimizer_ = std::make_unique<SimulatedAnnealing<std::vector<double>>>();
    }
    
    // 优化种子能量分配
    std::vector<double> optimizeEnergy(const std::vector<Seed>& seeds, SharedContext& ctx);
};

} // namespace triofuzz