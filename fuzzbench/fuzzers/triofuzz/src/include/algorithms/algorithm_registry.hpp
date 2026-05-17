#pragma once

#include "../core/algorithm.hpp"
#include <memory>
#include <string>
#include <map>
#include <functional>
#include <vector>
#include <any>

namespace triofuzz {

// Forward declarations for algorithm classes
class AFLPlusPlusMutation;
class NeuralFuzzingMutation;
class CoverageGuidedScheduler;
class StructureAwareMutation;
class MultiObjectiveOptimization;
class NSGAII;
class MOEAD;
class ReinforcementLearningMutation;
class AlgorithmOrchestrator;

// Algorithm factory function type
using AlgorithmFactory = std::function<std::shared_ptr<AlgorithmBase>()>;

// Algorithm configuration template
struct AlgorithmConfig {
    std::string name;
    std::string category;
    AlgorithmType type;
    std::vector<InfoType> provided_info;
    std::vector<InfoType> required_info;
    std::map<std::string, std::any> default_parameters;
    std::string description;
    bool enabled = true;
    
    // Compatibility info
    std::vector<std::string> compatible_with;
    std::vector<std::string> incompatible_with;
    std::vector<std::string> dependencies;
};

// Algorithm registry (instantiated; each FuzzingEngine has its own instance)
class AlgorithmRegistry {
private:
    // ⚠️ Singleton removed; use instances instead.
    // static AlgorithmRegistry* instance_;  // removed

    std::map<std::string, AlgorithmFactory> factories_;
    std::map<std::string, AlgorithmConfig> configs_;
    std::map<AlgorithmType, std::vector<std::string>> algorithms_by_type_;
    std::map<std::string, std::vector<std::string>> algorithms_by_category_;

    // Compatibility matrix
    std::map<std::pair<std::string, std::string>, bool> compatibility_matrix_;

    // Algorithm alias mapping
    std::map<std::string, std::string> algorithm_aliases_;

public:
    // Constructor is public to allow instantiation.
    AlgorithmRegistry() = default;
    ~AlgorithmRegistry() = default;

    // Disable copy/move (but allow multiple independent instances).
    AlgorithmRegistry(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry& operator=(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry(AlgorithmRegistry&&) = delete;
    AlgorithmRegistry& operator=(AlgorithmRegistry&&) = delete;

    // ⚠️ Keep getInstance() for backward compatibility, but mark as deprecated.
    // New code should use the instance provided by FuzzingEngine.
    [[deprecated("Use FuzzingEngine::getAlgorithmRegistry() instead")]]
    static AlgorithmRegistry& getInstance() {
        static AlgorithmRegistry legacy_instance;
        return legacy_instance;
    }
    
    // Algorithm registration
    template<typename AlgorithmClass>
    void registerAlgorithm(const std::string& name, const AlgorithmConfig& config) {
        factories_[name] = []() -> std::shared_ptr<AlgorithmBase> {
            return std::make_shared<AlgorithmClass>();
        };
        configs_[name] = config;
        algorithms_by_type_[config.type].push_back(name);
        algorithms_by_category_[config.category].push_back(name);
        
        // Update compatibility matrix
        updateCompatibilityMatrix(name, config);
    }
    
    // Algorithm creation
    std::shared_ptr<AlgorithmBase> createAlgorithm(const std::string& name) const;
    
    // Algorithm queries
    std::vector<std::string> getAlgorithmsByType(AlgorithmType type) const;
    std::vector<std::string> getAlgorithmsByCategory(const std::string& category) const;
    std::vector<std::string> getCompatibleAlgorithms(const std::string& algorithm_name) const;
    std::vector<std::string> getAllAlgorithms() const;
    
    // Config management
    AlgorithmConfig getConfig(const std::string& name) const;
    void updateConfig(const std::string& name, const AlgorithmConfig& config);
    
    // Compatibility checks
    bool areCompatible(const std::string& alg1, const std::string& alg2) const;
    std::vector<std::string> getIncompatibleAlgorithms(const std::string& algorithm_name) const;
    
    // Dependency resolution
    std::vector<std::string> resolveDependencies(const std::vector<std::string>& algorithms) const;
    bool hasCyclicDependencies(const std::vector<std::string>& algorithms) const;
    
    // Algorithm recommendation
    std::vector<std::string> recommendAlgorithms(const std::vector<InfoType>& required_info,
                                                const std::vector<InfoType>& available_info) const;
    
    // Initialize all built-in algorithms
    void initializeBuiltinAlgorithms();
    void registerExistingAlgorithms();
    void registerMissingAlgorithms();

    // Alias management
    void addAlias(const std::string& alias, const std::string& canonical_name);
    void removeAlias(const std::string& alias);
    std::string resolveAlias(const std::string& name) const;
    std::vector<std::string> getAliases(const std::string& canonical_name) const;

private:
    void updateCompatibilityMatrix(const std::string& name, const AlgorithmConfig& config);
    std::vector<std::string> topologicalSort(const std::vector<std::string>& algorithms) const;
};

// Convenience macro
#define REGISTER_ALGORITHM(AlgorithmClass, name, config) \
    AlgorithmRegistry::getInstance().registerAlgorithm<AlgorithmClass>(name, config)

// Algorithm factory functions
namespace algorithm_factory {

// Mutation algorithms
std::shared_ptr<AlgorithmBase> createAFLPlusPlusMutation();
std::shared_ptr<AlgorithmBase> createNeuralFuzzingMutation();
std::shared_ptr<AlgorithmBase> createStructureAwareMutation();
std::shared_ptr<AlgorithmBase> createReinforcementLearningMutation();

// Scheduling algorithms
std::shared_ptr<AlgorithmBase> createCoverageGuidedScheduler();

// Optimization algorithms
std::shared_ptr<AlgorithmBase> createNSGAII();
std::shared_ptr<AlgorithmBase> createMOEAD();

// Combination algorithms
std::shared_ptr<AlgorithmBase> createAlgorithmOrchestrator();

// Existing algorithms (from existing codebase)
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
