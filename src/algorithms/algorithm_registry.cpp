#include "../../include/algorithms/algorithm_registry.hpp"
#include "../../include/algorithms/mutation/structure_aware_mutation.hpp"
#include "../../include/combination/multi_armed_bandit.hpp"

// Basic mutation algorithm headers
#include "../../include/algorithms/mutation/runtime_dictionary_mutation.hpp"
#include "../../include/algorithms/mutation/smart_dictionary_mutation.hpp"
#include "../../include/algorithms/mutation/format_overflow_mutation.hpp"

// AFL++ 37 individual mutation operators (for a fair comparison with AFL++ TS Parallel)
#include "../../include/algorithms/mutation/aflpp_individual_mutations.hpp"

// Declare AFL++ individual mutation registration function
namespace triofuzz {
    void registerAFLPPIndividualMutations();
}

// Existing algorithm headers
#include "../../include/algorithms/mutation/redqueen_mutation.hpp"
#include "../../include/algorithms/mutation/cmplog_mutation.hpp"

// Instrumentation algorithm headers (only actively used ones)
#include "../../include/algorithms/instrumentation/cmplog_instrumentation.hpp"

// Scheduler algorithm headers (only actively used ones)
#include "../../include/algorithms/scheduling/rare_edge_scheduler.hpp"

// Optimization algorithm headers
#include "../../include/algorithms/optimization/optimization_algorithms.hpp"

#include <algorithm>
#include <stdexcept>

namespace triofuzz {

// Static instance
AlgorithmRegistry* AlgorithmRegistry::instance_ = nullptr;

std::shared_ptr<AlgorithmBase> AlgorithmRegistry::createAlgorithm(const std::string& name) const {
    // First resolve any aliases
    std::string resolved_name = resolveAlias(name);

    auto it = factories_.find(resolved_name);
    if (it != factories_.end()) {
        return it->second();
    }
    throw std::runtime_error("Algorithm not found: " + resolved_name + " (requested: " + name + ")");
}

std::vector<std::string> AlgorithmRegistry::getAlgorithmsByType(AlgorithmType type) const {
    auto it = algorithms_by_type_.find(type);
    if (it != algorithms_by_type_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> AlgorithmRegistry::getAlgorithmsByCategory(const std::string& category) const {
    auto it = algorithms_by_category_.find(category);
    if (it != algorithms_by_category_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> AlgorithmRegistry::getCompatibleAlgorithms(const std::string& algorithm_name) const {
    std::vector<std::string> compatible;
    for (const auto& [name, _] : configs_) {
        if (name != algorithm_name && areCompatible(algorithm_name, name)) {
            compatible.push_back(name);
        }
    }
    return compatible;
}

std::vector<std::string> AlgorithmRegistry::getAllAlgorithms() const {
    std::vector<std::string> algorithms;
    for (const auto& [name, _] : configs_) {
        algorithms.push_back(name);
    }
    return algorithms;
}

AlgorithmConfig AlgorithmRegistry::getConfig(const std::string& name) const {
    auto it = configs_.find(name);
    if (it != configs_.end()) {
        return it->second;
    }
    throw std::runtime_error("Algorithm config not found: " + name);
}

void AlgorithmRegistry::updateConfig(const std::string& name, const AlgorithmConfig& config) {
    if (configs_.find(name) != configs_.end()) {
        configs_[name] = config;
        updateCompatibilityMatrix(name, config);
    }
}

bool AlgorithmRegistry::areCompatible(const std::string& alg1, const std::string& alg2) const {
    auto key1 = std::make_pair(alg1, alg2);
    auto key2 = std::make_pair(alg2, alg1);
    
    auto it1 = compatibility_matrix_.find(key1);
    if (it1 != compatibility_matrix_.end()) {
        return it1->second;
    }
    
    auto it2 = compatibility_matrix_.find(key2);
    if (it2 != compatibility_matrix_.end()) {
        return it2->second;
    }
    
    // Default compatibility check
    auto config1 = getConfig(alg1);
    auto config2 = getConfig(alg2);
    
    // Check incompatibility lists
    if (std::find(config1.incompatible_with.begin(), config1.incompatible_with.end(), alg2) != config1.incompatible_with.end()) {
        return false;
    }
    if (std::find(config2.incompatible_with.begin(), config2.incompatible_with.end(), alg1) != config2.incompatible_with.end()) {
        return false;
    }
    
    // Check information dependencies
    for (const auto& required : config1.required_info) {
        if (std::find(config2.provided_info.begin(), config2.provided_info.end(), required) == config2.provided_info.end()) {
            // If alg2 cannot provide what alg1 requires, continue (other conflicts may exist).
            continue;
        }
    }
    
    return true; // Compatible by default
}

std::vector<std::string> AlgorithmRegistry::getIncompatibleAlgorithms(const std::string& algorithm_name) const {
    auto config = getConfig(algorithm_name);
    return config.incompatible_with;
}

std::vector<std::string> AlgorithmRegistry::resolveDependencies(const std::vector<std::string>& algorithms) const {
    std::vector<std::string> resolved = algorithms;
    
    for (const auto& alg : algorithms) {
        auto config = getConfig(alg);
        for (const auto& dep : config.dependencies) {
            if (std::find(resolved.begin(), resolved.end(), dep) == resolved.end()) {
                resolved.push_back(dep);
            }
        }
    }
    
    return topologicalSort(resolved);
}

bool AlgorithmRegistry::hasCyclicDependencies(const std::vector<std::string>& algorithms) const {
    try {
        topologicalSort(algorithms);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

std::vector<std::string> AlgorithmRegistry::recommendAlgorithms(
    const std::vector<InfoType>& required_info,
    const std::vector<InfoType>& available_info) const {
    
    std::vector<std::string> recommendations;
    
    for (const auto& [name, config] : configs_) {
        if (!config.enabled) continue;
        
        // Check whether required info can be provided
        bool can_provide_required = false;
        for (const auto& provided : config.provided_info) {
            if (std::find(required_info.begin(), required_info.end(), provided) != required_info.end()) {
                can_provide_required = true;
                break;
            }
        }
        
        // Check whether enough input info is available
        bool has_enough_input = true;
        for (const auto& required : config.required_info) {
            if (std::find(available_info.begin(), available_info.end(), required) == available_info.end()) {
                has_enough_input = false;
                break;
            }
        }
        
        if (can_provide_required && has_enough_input) {
            recommendations.push_back(name);
        }
    }
    
    return recommendations;
}

void AlgorithmRegistry::initializeBuiltinAlgorithms() {
    {
        AlgorithmConfig config;
        config.name = "Redqueen";
        config.category = "advanced_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage, InfoType::Performance};
        config.required_info = {InfoType::Coverage};
        config.description = "Redqueen mutation with multi-objective optimization";
        registerAlgorithm<RedqueenMutation>("redqueen", config);
    }

    // Structure-aware mutation
    {
        AlgorithmConfig config;
        config.name = "Structure-Aware Mutation";
        config.category = "structure_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Structure, InfoType::Constraint};
        config.required_info = {};
        config.description = "Structure-aware mutation for formatted data";
        config.default_parameters["preserve_structure"] = true;
        config.default_parameters["fix_checksums"] = true;
        registerAlgorithm<StructureAwareMutation>("structure_aware", config);
    }

    // UCB multi-armed bandit algorithm
    {
        AlgorithmConfig config;
        config.name = "UCB Bandit";
        config.category = "combination";
        config.type = AlgorithmType::Combination;
        config.provided_info = {InfoType::Scheduling, InfoType::Performance};
        config.required_info = {};
        config.description = "Upper Confidence Bound algorithm for algorithm selection";
        config.default_parameters["exploration_constant"] = 2.0;
        registerAlgorithm<UCBBandit>("ucb_bandit", config);
    }
    
    // Epsilon-Greedy algorithm (new)
    {
        AlgorithmConfig config;
        config.name = "Epsilon-Greedy Bandit";
        config.category = "combination";
        config.type = AlgorithmType::Combination;
        config.provided_info = {InfoType::Scheduling, InfoType::Performance};
        config.required_info = {};
        config.description = "Epsilon-Greedy algorithm for exploration-exploitation balance";
        config.default_parameters["epsilon"] = 0.1;
        config.default_parameters["decay_rate"] = 0.995;
        registerAlgorithm<EpsilonGreedyBandit>("epsilon_greedy", config);
    }
    
    // Contextual UCB algorithm (new)
    {
        AlgorithmConfig config;
        config.name = "Contextual UCB";
        config.category = "combination";
        config.type = AlgorithmType::Combination;
        config.provided_info = {InfoType::Scheduling, InfoType::Performance, InfoType::Context};
        config.required_info = {InfoType::Coverage, InfoType::Performance};
        config.description = "Context-aware UCB for adaptive algorithm selection";
        config.default_parameters["alpha"] = 1.0;
        config.default_parameters["context_dim"] = 5;
        registerAlgorithm<ContextualUCB>("contextual_ucb", config);
    }
    
    // Register existing algorithms
    registerExistingAlgorithms();

    // Register all missing algorithms (fix hard-coded inconsistencies)
    registerMissingAlgorithms();

    // Register AFL++ 37 individual mutation operators (for a fair comparison with AFL++ TS Parallel)
    registerAFLPPIndividualMutations();
}

void AlgorithmRegistry::registerExistingAlgorithms() {
    // Register existing algorithm implementations

    {
        AlgorithmConfig config;
        config.name = "Smart Dictionary Mutation";
        config.category = "dictionary_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage, InfoType::Dictionary};
        config.required_info = {};
        config.description = "Dictionary-based intelligent mutation";
        config.default_parameters["max_dict_entries"] = 1000;
        registerAlgorithm<SmartDictionaryMutation>("smart_dictionary", config);
    }

    {
        AlgorithmConfig config;
        config.name = "Format Overflow Mutation";
        config.category = "format_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage};
        config.required_info = {};
        config.description = "Format-aware integer overflow mutation for PNG/TIFF/image formats";
        registerAlgorithm<FormatOverflowMutation>("format_overflow", config);
    }
}

void AlgorithmRegistry::updateCompatibilityMatrix(const std::string& name, const AlgorithmConfig& config) {
    // Update compatibility matrix
    for (const auto& compatible : config.compatible_with) {
        compatibility_matrix_[{name, compatible}] = true;
        compatibility_matrix_[{compatible, name}] = true;
    }
    
    for (const auto& incompatible : config.incompatible_with) {
        compatibility_matrix_[{name, incompatible}] = false;
        compatibility_matrix_[{incompatible, name}] = false;
    }
}

std::vector<std::string> AlgorithmRegistry::topologicalSort(const std::vector<std::string>& algorithms) const {
    std::map<std::string, std::vector<std::string>> adj;
    std::map<std::string, int> in_degree;
    
    // Initialize
    for (const auto& alg : algorithms) {
        adj[alg] = {};
        in_degree[alg] = 0;
    }
    
    // Build graph
    for (const auto& alg : algorithms) {
        auto config = getConfig(alg);
        for (const auto& dep : config.dependencies) {
            if (std::find(algorithms.begin(), algorithms.end(), dep) != algorithms.end()) {
                adj[dep].push_back(alg);
                in_degree[alg]++;
            }
        }
    }
    
    // Topological sort
    std::queue<std::string> queue;
    for (const auto& [alg, degree] : in_degree) {
        if (degree == 0) {
            queue.push(alg);
        }
    }
    
    std::vector<std::string> result;
    while (!queue.empty()) {
        std::string current = queue.front();
        queue.pop();
        result.push_back(current);
        
        for (const auto& neighbor : adj[current]) {
            in_degree[neighbor]--;
            if (in_degree[neighbor] == 0) {
                queue.push(neighbor);
            }
        }
    }
    
    if (result.size() != algorithms.size()) {
        throw std::runtime_error("Cyclic dependency detected");
    }
    
    return result;
}

// Register all missing algorithms (fix hard-coded inconsistencies)
void AlgorithmRegistry::registerMissingAlgorithms() {
    // 1. Register missing mutation algorithms (only those with real implementations)

    {
        AlgorithmConfig config;
        config.name = "runtime_dictionary";
        config.category = "dictionary_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage, InfoType::Dictionary};
        config.required_info = {};
        config.description = "Runtime dictionary mutation based on dynamic extraction";
        config.default_parameters["max_dict_size"] = 500;
        registerAlgorithm<RuntimeDictionaryMutation>("runtime_dictionary", config);
    }

    {
        AlgorithmConfig config;
        config.name = "cmplog";
        config.category = "comparison_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage, InfoType::Constraint};
        config.required_info = {};
        config.description = "CmpLog comparison logging mutation";
        config.default_parameters["cmp_logging_enabled"] = true;
        registerAlgorithm<CmplogMutation>("cmplog", config);
    }

    {
        AlgorithmConfig config;
        config.name = "rare_edge_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Coverage};
        config.required_info = {InfoType::Coverage};
        config.description = "Rare edge focused scheduler";
        config.default_parameters["rare_edge_threshold"] = 0.01;
        registerAlgorithm<RareEdgeScheduler>("rare_edge_scheduler", config);
    }

    // CmpLog Instrumentation (still actively used)
    {
        AlgorithmConfig config;
        config.name = "cmplog_instrumentation";
        config.category = "instrumentation";
        config.type = AlgorithmType::Analysis;
        config.provided_info = {InfoType::Comparison, InfoType::Coverage};
        config.required_info = {};
        config.description = "CmpLog comparison instrumentation";
        config.default_parameters["log_comparisons"] = true;
        registerAlgorithm<CmplogInstrumentation>("cmplog_instrumentation", config);
    }

    // Add commonly used algorithm aliases
    addAlias("cmplog_mutation", "cmplog");

    std::cout << "[INFO] Registered all missing algorithms and aliases successfully" << std::endl;
}

// Algorithm factory function implementations
namespace algorithm_factory {

std::shared_ptr<AlgorithmBase> createStructureAwareMutation() {
    return std::make_shared<StructureAwareMutation>();
}

} // namespace algorithm_factory

// Alias management implementation
void AlgorithmRegistry::addAlias(const std::string& alias, const std::string& canonical_name) {
    // Ensure canonical_name exists
    if (factories_.find(canonical_name) == factories_.end()) {
        throw std::runtime_error("Cannot add alias '" + alias + "' for non-existent algorithm '" + canonical_name + "'");
    }
    algorithm_aliases_[alias] = canonical_name;
}

void AlgorithmRegistry::removeAlias(const std::string& alias) {
    algorithm_aliases_.erase(alias);
}

std::string AlgorithmRegistry::resolveAlias(const std::string& name) const {
    auto it = algorithm_aliases_.find(name);
    if (it != algorithm_aliases_.end()) {
        return it->second;
    }
    return name; // If it's not an alias, return the original name
}

std::vector<std::string> AlgorithmRegistry::getAliases(const std::string& canonical_name) const {
    std::vector<std::string> aliases;
    for (const auto& [alias, canonical] : algorithm_aliases_) {
        if (canonical == canonical_name) {
            aliases.push_back(alias);
        }
    }
    return aliases;
}

} // namespace triofuzz
