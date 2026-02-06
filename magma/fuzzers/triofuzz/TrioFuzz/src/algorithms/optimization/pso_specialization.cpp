#include "../../../include/algorithms/optimization/optimization_algorithms.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>

namespace triofuzz {

// PSO算法的特殊实现，用于二进制数据优化
class BinaryPSO : public ParticleSwarmOptimization<std::vector<uint8_t>> {
private:
    // 二进制PSO特有参数
    double sigmoid_steepness_ = 4.0;
    double mutation_rate_ = 0.01;
    
    // 随机数生成器
    std::mt19937 random_gen_{std::random_device{}()};
    
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
    // 重写速度更新函数，使用sigmoid函数映射到二进制空间
    void updateParticleVelocity(std::vector<uint8_t>& velocity,
                       const std::vector<uint8_t>& position,
                       const std::vector<uint8_t>& personal_best,
                       const std::vector<uint8_t>& global_best,
                       double inertia, double cognitive, double social) {
        
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        
        for (size_t i = 0; i < velocity.size(); ++i) {
            // 计算连续空间中的速度更新
            double v = static_cast<double>(velocity[i]) * inertia +
                      cognitive * dist(random_gen_) * (static_cast<double>(personal_best[i]) - static_cast<double>(position[i])) +
                      social * dist(random_gen_) * (static_cast<double>(global_best[i]) - static_cast<double>(position[i]));
            
            // 应用突变
            if (dist(random_gen_) < mutation_rate_) {
                v += (dist(random_gen_) * 2.0 - 1.0) * 50.0; // 添加随机扰动
            }
            
            // 限制速度范围
            v = std::max(-255.0, std::min(255.0, v));
            
            // 存储新速度
            velocity[i] = static_cast<uint8_t>(std::abs(static_cast<int>(v)) % 256);
        }
    }
};

// 注册特殊PSO实现的工厂函数
std::unique_ptr<Algorithm<OptimizationProblem<std::vector<uint8_t>>, std::vector<uint8_t>, SharedContext>> 
createBinaryPSO() {
    return std::make_unique<BinaryPSO>();
}

} // namespace triofuzz 