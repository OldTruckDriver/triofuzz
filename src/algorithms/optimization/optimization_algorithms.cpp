#include "../../../include/algorithms/optimization/optimization_algorithms.hpp"
#include "../../../include/core/context.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>

namespace triofuzz {

// SeedEnergyOptimizer实现
std::vector<double> SeedEnergyOptimizer::optimizeEnergy(const std::vector<Seed>& seeds, SharedContext& ctx) {
    // 定义种子能量优化问题
    OptimizationProblem<std::vector<double>> problem;
    
    // 评估函数：基于覆盖率、多样性和历史性能
    problem.evaluate = [&seeds](const std::vector<double>& energy_distribution) -> double {
        double score = 0.0;
        
        for (size_t i = 0; i < energy_distribution.size() && i < seeds.size(); ++i) {
            const auto& seed = seeds[i];
            double energy = energy_distribution[i];
            
            // 覆盖率权重
            double coverage_score = seed.coverage.coverage_gain * energy;
            
            // 多样性权重（与其他种子的差异）
            double diversity_score = 0.0;
            for (size_t j = 0; j < seeds.size(); ++j) {
                if (i != j) {
                    // 简化多样性计算
                    size_t common_edges = 0;
                    for (auto edge : seed.coverage.new_edges) {
                        if (std::find(seeds[j].coverage.new_edges.begin(),
                                     seeds[j].coverage.new_edges.end(), edge) !=
                            seeds[j].coverage.new_edges.end()) {
                            common_edges++;
                        }
                    }
                    double similarity = static_cast<double>(common_edges) / 
                                      std::max(seed.coverage.new_edges.size(), size_t(1));
                    diversity_score += (1.0 - similarity) * energy;
                }
            }
            diversity_score /= std::max(seeds.size() - 1, size_t(1));
            
            // 历史性能权重
            double performance_score = seed.energy * energy;
            
            score += coverage_score * 0.4 + diversity_score * 0.3 + performance_score * 0.3;
        }
        
        return score;
    };
    
    // 邻居生成函数
    problem.generate_neighbor = [](const std::vector<double>& current) -> std::vector<double> {
        std::vector<double> neighbor = current;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::normal_distribution<double> noise(0.0, 0.1);
        
        // 随机扰动一些元素
        std::uniform_int_distribution<size_t> idx_dist(0, neighbor.size() - 1);
        size_t num_changes = std::max(size_t(1), neighbor.size() / 10);
        
        for (size_t i = 0; i < num_changes; ++i) {
            size_t idx = idx_dist(gen);
            neighbor[idx] += noise(gen);
            neighbor[idx] = std::max(0.0, std::min(1.0, neighbor[idx])); // 限制在[0,1]
        }
        
        // 重新归一化
        double sum = std::accumulate(neighbor.begin(), neighbor.end(), 0.0);
        if (sum > 0) {
            for (auto& val : neighbor) {
                val /= sum;
            }
        }
        
        return neighbor;
    };
    
    // 有效性检查
    problem.is_valid = [](const std::vector<double>& solution) -> bool {
        // 检查是否为有效的概率分布
        double sum = std::accumulate(solution.begin(), solution.end(), 0.0);
        return std::abs(sum - 1.0) < 1e-6 && 
               std::all_of(solution.begin(), solution.end(), [](double x) { return x >= 0.0; });
    };
    
    // 设置边界
    problem.lower_bound.resize(seeds.size(), 0.0);
    problem.upper_bound.resize(seeds.size(), 1.0);
    
    // 使用模拟退火求解
    auto result = sa_optimizer_->execute(problem, ctx);
    
    return result;
}

// 模板特化：针对向量类型的具体实现

// ParticleSwarmOptimization<std::vector<double>>的特化方法
template<>
void ParticleSwarmOptimization<std::vector<double>>::updateVelocity(
    std::vector<double>& velocity, 
    const std::vector<double>& position,
    const std::vector<double>& personal_best,
    const std::vector<double>& global_best,
    double inertia, double cognitive, double social) {
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    for (size_t i = 0; i < velocity.size(); ++i) {
        double r1 = dist(random_gen_);
        double r2 = dist(random_gen_);
        
        velocity[i] = inertia * velocity[i] +
                     cognitive * r1 * (personal_best[i] - position[i]) +
                     social * r2 * (global_best[i] - position[i]);
    }
}

// GeneticAlgorithm<std::vector<double>>的特化方法
template<>
std::vector<typename GeneticAlgorithm<std::vector<double>>::Individual> 
GeneticAlgorithm<std::vector<double>>::initializePopulation(
    const OptimizationProblem<std::vector<double>>& problem) {
    
    std::vector<Individual> population;
    population.reserve(population_size_);
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    for (size_t i = 0; i < population_size_; ++i) {
        Individual individual;
        individual.solution.resize(problem.lower_bound.size());
        
        // 随机初始化
        for (size_t j = 0; j < individual.solution.size(); ++j) {
            individual.solution[j] = problem.lower_bound[j] + 
                                   dist(random_gen_) * 
                                   (problem.upper_bound[j] - problem.lower_bound[j]);
        }
        
        // 如果是概率分布，进行归一化
        double sum = std::accumulate(individual.solution.begin(), individual.solution.end(), 0.0);
        if (sum > 0) {
            for (auto& val : individual.solution) {
                val /= sum;
            }
        }
        
        individual.fitness = problem.evaluate(individual.solution);
        population.push_back(individual);
    }
    
    return population;
}

template<>
typename GeneticAlgorithm<std::vector<double>>::Individual 
GeneticAlgorithm<std::vector<double>>::tournamentSelection(
    const std::vector<Individual>& population) {
    
    std::uniform_int_distribution<size_t> dist(0, population.size() - 1);
    
    Individual best = population[dist(random_gen_)];
    for (size_t i = 1; i < tournament_size_; ++i) {
        Individual candidate = population[dist(random_gen_)];
        if (candidate.fitness > best.fitness) { // 假设最大化
            best = candidate;
        }
    }
    
    return best;
}

template<>
typename GeneticAlgorithm<std::vector<double>>::Individual 
GeneticAlgorithm<std::vector<double>>::rouletteWheelSelection(
    const std::vector<Individual>& population) {
    
    // 计算总适应度
    double total_fitness = 0.0;
    double min_fitness = std::numeric_limits<double>::max();
    
    for (const auto& individual : population) {
        min_fitness = std::min(min_fitness, individual.fitness);
    }
    
    // 处理负适应度
    for (const auto& individual : population) {
        total_fitness += individual.fitness - min_fitness + 1.0; // 偏移确保正值
    }
    
    // 轮盘赌选择
    std::uniform_real_distribution<double> dist(0.0, total_fitness);
    double selection_point = dist(random_gen_);
    
    double cumulative_fitness = 0.0;
    for (const auto& individual : population) {
        cumulative_fitness += individual.fitness - min_fitness + 1.0;
        if (cumulative_fitness >= selection_point) {
            return individual;
        }
    }
    
    return population.back(); // 备用
}

// ParticleSwarmOptimization<std::vector<double>>的特化方法
template<>
std::vector<typename ParticleSwarmOptimization<std::vector<double>>::Particle> 
ParticleSwarmOptimization<std::vector<double>>::initializeSwarm(
    const OptimizationProblem<std::vector<double>>& problem) {
    
    std::vector<Particle> swarm;
    swarm.reserve(swarm_size_);
    
    std::uniform_real_distribution<double> pos_dist(0.0, 1.0);
    std::normal_distribution<double> vel_dist(0.0, 0.1);
    
    for (size_t i = 0; i < swarm_size_; ++i) {
        Particle particle;
        
        particle.position.resize(problem.lower_bound.size());
        particle.velocity.resize(problem.lower_bound.size());
        
        // 初始化位置
        for (size_t j = 0; j < particle.position.size(); ++j) {
            particle.position[j] = problem.lower_bound[j] + 
                                 pos_dist(random_gen_) * 
                                 (problem.upper_bound[j] - problem.lower_bound[j]);
            particle.velocity[j] = vel_dist(random_gen_);
        }
        
        // 归一化位置（如果是概率分布）
        double sum = std::accumulate(particle.position.begin(), particle.position.end(), 0.0);
        if (sum > 0) {
            for (auto& val : particle.position) {
                val /= sum;
            }
        }
        
        particle.personal_best = particle.position;
        particle.fitness = problem.evaluate(particle.position);
        particle.personal_best_fitness = particle.fitness;
        
        swarm.push_back(particle);
    }
    
    return swarm;
}

template<>
void ParticleSwarmOptimization<std::vector<double>>::updateParticle(
    typename ParticleSwarmOptimization<std::vector<double>>::Particle& particle, 
    const std::vector<double>& global_best,
    const OptimizationProblem<std::vector<double>>& problem) {
    
    // 更新速度
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    for (size_t i = 0; i < particle.velocity.size(); ++i) {
        double r1 = dist(random_gen_);
        double r2 = dist(random_gen_);
        
        particle.velocity[i] = inertia_weight_ * particle.velocity[i] +
                              cognitive_weight_ * r1 * (particle.personal_best[i] - particle.position[i]) +
                              social_weight_ * r2 * (global_best[i] - particle.position[i]);
    }
    
    // 限制速度
    for (auto& v : particle.velocity) {
        v = std::max(-velocity_clamp_, std::min(velocity_clamp_, v));
    }
    
    // 更新位置
    updatePosition(particle.position, particle.velocity, problem);
    
    // 评估新位置
    particle.fitness = problem.evaluate(particle.position);
    
    // 更新个体最佳
    if (particle.fitness > particle.personal_best_fitness) {
        particle.personal_best = particle.position;
        particle.personal_best_fitness = particle.fitness;
    }
}

// 实用工具函数
namespace optimization_utils {

std::vector<double> normalizeVector(const std::vector<double>& vec) {
    std::vector<double> normalized = vec;
    double sum = std::accumulate(normalized.begin(), normalized.end(), 0.0);
    
    if (sum > 0) {
        for (auto& val : normalized) {
            val /= sum;
        }
    } else {
        // 如果和为0，设置为均匀分布
        std::fill(normalized.begin(), normalized.end(), 1.0 / normalized.size());
    }
    
    return normalized;
}

double computeVectorDistance(const std::vector<double>& a, const std::vector<double>& b) {
    double distance = 0.0;
    size_t size = std::min(a.size(), b.size());
    
    for (size_t i = 0; i < size; ++i) {
        double diff = a[i] - b[i];
        distance += diff * diff;
    }
    
    return std::sqrt(distance);
}

std::vector<double> crossoverVectors(const std::vector<double>& parent1,
                                   const std::vector<double>& parent2,
                                   double crossover_rate) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    std::vector<double> child = parent1;
    
    for (size_t i = 0; i < child.size(); ++i) {
        if (dist(gen) < crossover_rate) {
            child[i] = parent2[i];
        }
    }
    
    return child;
}

std::vector<double> mutateVector(const std::vector<double>& individual,
                               double mutation_rate,
                               double mutation_strength) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    std::normal_distribution<double> noise(0.0, mutation_strength);
    
    std::vector<double> mutated = individual;
    
    for (size_t i = 0; i < mutated.size(); ++i) {
        if (dist(gen) < mutation_rate) {
            mutated[i] += noise(gen);
            mutated[i] = std::max(0.0, std::min(1.0, mutated[i]));
        }
    }
    
    return mutated;
}

} // namespace optimization_utils

} // namespace triofuzz 