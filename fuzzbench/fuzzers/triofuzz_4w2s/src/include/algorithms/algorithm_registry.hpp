#pragma once

#include "../core/algorithm.hpp"
#include <memory>
#include <string>
#include <map>
#include <functional>
#include <vector>
#include <any>

namespace triofuzz {

// 前向声明所有算法类
class AFLPlusPlusMutation;
class NeuralFuzzingMutation;
class CoverageGuidedScheduler;
class StructureAwareMutation;
class MultiObjectiveOptimization;
class NSGAII;
class MOEAD;
class ReinforcementLearningMutation;
class AlgorithmOrchestrator;

// 算法工厂函数类型
using AlgorithmFactory = std::function<std::shared_ptr<AlgorithmBase>()>;

// 算法配置模板
struct AlgorithmConfig {
    std::string name;
    std::string category;
    AlgorithmType type;
    std::vector<InfoType> provided_info;
    std::vector<InfoType> required_info;
    std::map<std::string, std::any> default_parameters;
    std::string description;
    bool enabled = true;
    
    // 兼容性信息
    std::vector<std::string> compatible_with;
    std::vector<std::string> incompatible_with;
    std::vector<std::string> dependencies;
};

// 算法注册表（实例化模式，每个FuzzingEngine拥有独立实例）
class AlgorithmRegistry {
private:
    // ⚠️ 移除单例模式，改为实例化
    // static AlgorithmRegistry* instance_;  // 已移除

    std::map<std::string, AlgorithmFactory> factories_;
    std::map<std::string, AlgorithmConfig> configs_;
    std::map<AlgorithmType, std::vector<std::string>> algorithms_by_type_;
    std::map<std::string, std::vector<std::string>> algorithms_by_category_;

    // 兼容性矩阵
    std::map<std::pair<std::string, std::string>, bool> compatibility_matrix_;

    // 算法别名映射
    std::map<std::string, std::string> algorithm_aliases_;

public:
    // 构造函数改为public，支持实例化
    AlgorithmRegistry() = default;
    ~AlgorithmRegistry() = default;

    // 禁止拷贝和移动（但允许创建多个独立实例）
    AlgorithmRegistry(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry& operator=(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry(AlgorithmRegistry&&) = delete;
    AlgorithmRegistry& operator=(AlgorithmRegistry&&) = delete;

    // ⚠️ 保留 getInstance() 用于向后兼容，但标记为 deprecated
    // 新代码应该使用 FuzzingEngine 提供的实例
    [[deprecated("Use FuzzingEngine::getAlgorithmRegistry() instead")]]
    static AlgorithmRegistry& getInstance() {
        static AlgorithmRegistry legacy_instance;
        return legacy_instance;
    }
    
    // 算法注册
    template<typename AlgorithmClass>
    void registerAlgorithm(const std::string& name, const AlgorithmConfig& config) {
        factories_[name] = []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<AlgorithmClass>();
        };
        configs_[name] = config;
        algorithms_by_type_[config.type].push_back(name);
        algorithms_by_category_[config.category].push_back(name);
        
        // 更新兼容性矩阵
        updateCompatibilityMatrix(name, config);
    }
    
    // 算法创建
    std::shared_ptr<AlgorithmBase> createAlgorithm(const std::string& name) const;
    
    // 算法查询
    std::vector<std::string> getAlgorithmsByType(AlgorithmType type) const;
    std::vector<std::string> getAlgorithmsByCategory(const std::string& category) const;
    std::vector<std::string> getCompatibleAlgorithms(const std::string& algorithm_name) const;
    std::vector<std::string> getAllAlgorithms() const;
    
    // 配置管理
    AlgorithmConfig getConfig(const std::string& name) const;
    void updateConfig(const std::string& name, const AlgorithmConfig& config);
    
    // 兼容性检查
    bool areCompatible(const std::string& alg1, const std::string& alg2) const;
    std::vector<std::string> getIncompatibleAlgorithms(const std::string& algorithm_name) const;
    
    // 依赖解析
    std::vector<std::string> resolveDependencies(const std::vector<std::string>& algorithms) const;
    bool hasCyclicDependencies(const std::vector<std::string>& algorithms) const;
    
    // 算法推荐
    std::vector<std::string> recommendAlgorithms(const std::vector<InfoType>& required_info,
                                                const std::vector<InfoType>& available_info) const;
    
    // 初始化所有内置算法
    void initializeBuiltinAlgorithms();
    void registerExistingAlgorithms();
    void registerMissingAlgorithms();

    // 别名管理
    void addAlias(const std::string& alias, const std::string& canonical_name);
    void removeAlias(const std::string& alias);
    std::string resolveAlias(const std::string& name) const;
    std::vector<std::string> getAliases(const std::string& canonical_name) const;

private:
    void updateCompatibilityMatrix(const std::string& name, const AlgorithmConfig& config);
    std::vector<std::string> topologicalSort(const std::vector<std::string>& algorithms) const;
};

// 便利宏定义
#define REGISTER_ALGORITHM(AlgorithmClass, name, config) \
    AlgorithmRegistry::getInstance().registerAlgorithm<AlgorithmClass>(name, config)

// 算法工厂函数
namespace algorithm_factory {

// 变异算法
std::shared_ptr<AlgorithmBase> createAFLPlusPlusMutation();
std::shared_ptr<AlgorithmBase> createNeuralFuzzingMutation();
std::shared_ptr<AlgorithmBase> createStructureAwareMutation();
std::shared_ptr<AlgorithmBase> createReinforcementLearningMutation();

// 调度算法
std::shared_ptr<AlgorithmBase> createCoverageGuidedScheduler();

// 优化算法
std::shared_ptr<AlgorithmBase> createNSGAII();
std::shared_ptr<AlgorithmBase> createMOEAD();

// 组合算法
std::shared_ptr<AlgorithmBase> createAlgorithmOrchestrator();

// 现有算法（从已有代码中）
std::shared_ptr<AlgorithmBase> createHavocMutation();
std::shared_ptr<AlgorithmBase> createZestMutation();
std::shared_ptr<AlgorithmBase> createLibFuzzerMutation();
std::shared_ptr<AlgorithmBase> createRedqueenMutation();
std::shared_ptr<AlgorithmBase> createNeuzzMutation();
std::shared_ptr<AlgorithmBase> createFairfuzzMutation();
std::shared_ptr<AlgorithmBase> createCmplogMutation();
std::shared_ptr<AlgorithmBase> createAngoraGradientDescent();

} // namespace algorithm_factory

} // namespace triofuzz 