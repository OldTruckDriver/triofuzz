#pragma once

#include "../core/algorithm.hpp"
#include <unordered_map>
#include <functional>
#include <memory>
#include <mutex>
#include <typeindex>
#include <stdexcept>
#include <shared_mutex>

namespace triofuzz {

// Algorithm metadata
struct AlgorithmMetadata {
    std::string name;
    std::string description;
    std::string version;
    AlgorithmType type;
    std::vector<std::string> tags;
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> parameters_description;
    std::map<std::string, std::string> metadata;
    
    // Performance characteristics
    struct PerformanceCharacteristics {
        double avg_execution_time_ms = 0.0;
        size_t memory_usage_bytes = 0;
        bool is_thread_safe = true;
        bool is_deterministic = true;
    } performance;
    
    // Compatibility info
    struct Compatibility {
        std::vector<std::string> compatible_algorithms;
        std::vector<std::string> incompatible_algorithms;
        std::vector<std::string> recommended_combinations;
    } compatibility;
};

// Algorithm registry
class AlgorithmRegistry {
private:
    // Factory type
    using AlgorithmFactoryBase = std::function<std::shared_ptr<void>()>;
    
    // Typed factory alias
    template<typename AlgorithmType>
    using TypedAlgorithmFactory = std::function<std::shared_ptr<AlgorithmType>()>;
    
    // Storage entry
    struct RegistryEntry {
        AlgorithmFactoryBase factory;
        AlgorithmMetadata metadata;
        std::type_index type_index;
        bool is_enabled = true;
        
        // Constructor ensures type_index is initialized.
        RegistryEntry() : type_index(typeid(void)) {}
        
        RegistryEntry(AlgorithmFactoryBase f, const AlgorithmMetadata& m, std::type_index ti, bool enabled = true)
            : factory(f), metadata(m), type_index(ti), is_enabled(enabled) {}
    };
    
    // Registry
    std::unordered_map<std::string, RegistryEntry> registry_;
    mutable std::shared_mutex registry_mutex_;
    
    // Map from type to algorithm names
    std::unordered_map<std::type_index, std::vector<std::string>> type_to_algorithms_;
    
    // Instance cache (for singleton-like algorithms)
    mutable std::unordered_map<std::string, std::weak_ptr<void>> instance_cache_;
    mutable std::mutex cache_mutex_;
    
    // Singleton instance
    static std::unique_ptr<AlgorithmRegistry> instance_;
    static std::mutex instance_mutex_;
    
public:
    // Constructor is public.
    AlgorithmRegistry() = default;
    
    // Get singleton instance
    static AlgorithmRegistry& getInstance() {
        std::lock_guard<std::mutex> lock(instance_mutex_);
        if (!instance_) {
            instance_ = std::unique_ptr<AlgorithmRegistry>(new AlgorithmRegistry());
        }
        return *instance_;
    }
    
    // Disable copy and move
    AlgorithmRegistry(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry& operator=(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry(AlgorithmRegistry&&) = delete;
    AlgorithmRegistry& operator=(AlgorithmRegistry&&) = delete;
    
    // Register algorithm
    template<typename AlgorithmType>
    void registerAlgorithm(const std::string& name, 
                          TypedAlgorithmFactory<AlgorithmType> factory,
                          const AlgorithmMetadata& metadata) {
        std::unique_lock<std::shared_mutex> lock(registry_mutex_);
        
        if (registry_.find(name) != registry_.end()) {
            throw std::runtime_error("Algorithm already registered: " + name);
        }
        
        RegistryEntry entry;
        entry.factory = [factory]() -> std::shared_ptr<void> {
            return std::static_pointer_cast<void>(factory());
        };
        entry.metadata = metadata;
        entry.type_index = std::type_index(typeid(AlgorithmType));
        
        registry_[name] = entry;
        type_to_algorithms_[entry.type_index].push_back(name);
    }
    
    // Register using AlgorithmFactory
    void registerAlgorithm(const std::string& name, AlgorithmFactory factory) {
        std::unique_lock<std::shared_mutex> lock(registry_mutex_);
        
        if (registry_.find(name) != registry_.end()) {
            throw std::runtime_error("Algorithm already registered: " + name);
        }
        
        RegistryEntry entry;
        entry.factory = [factory]() -> std::shared_ptr<void> {
            return std::static_pointer_cast<void>(factory());
        };
        entry.metadata.name = name;
        entry.type_index = std::type_index(typeid(AlgorithmBase));
        
        registry_[name] = entry;
        type_to_algorithms_[entry.type_index].push_back(name);
    }
    
    // Convenience registration (default factory)
    template<typename AlgorithmClass>
    void registerAlgorithm(const std::string& name, const AlgorithmMetadata& metadata) {
        auto factory = []() { return std::make_shared<AlgorithmClass>(); };
        registerAlgorithm<AlgorithmClass>(name, factory, metadata);
    }
    
    // Create algorithm instance
    template<typename AlgorithmType>
    std::shared_ptr<AlgorithmType> create(const std::string& name, bool use_cache = false) {
        if (use_cache) {
            // Check cache
            std::lock_guard<std::mutex> cache_lock(cache_mutex_);
            auto it = instance_cache_.find(name);
            if (it != instance_cache_.end()) {
                if (auto cached = it->second.lock()) {
                    return std::static_pointer_cast<AlgorithmType>(cached);
                }
            }
        }
        
        // Create new instance
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(name);
        if (it == registry_.end()) {
            throw std::runtime_error("Algorithm not found: " + name);
        }
        
        if (!it->second.is_enabled) {
            throw std::runtime_error("Algorithm is disabled: " + name);
        }
        
        auto instance = std::static_pointer_cast<AlgorithmType>(it->second.factory());
        
        if (use_cache) {
            std::lock_guard<std::mutex> cache_lock(cache_mutex_);
            instance_cache_[name] = instance;
        }
        
        return instance;
    }
    
    // Create algorithms in batch
    template<typename AlgorithmType>
    std::vector<std::shared_ptr<AlgorithmType>> createAll(AlgorithmType type) {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        std::vector<std::shared_ptr<AlgorithmType>> algorithms;
        auto type_idx = std::type_index(typeid(AlgorithmType));
        
        auto it = type_to_algorithms_.find(type_idx);
        if (it != type_to_algorithms_.end()) {
            for (const auto& name : it->second) {
                if (registry_[name].is_enabled) {
                    try {
                        algorithms.push_back(create<AlgorithmType>(name));
                    } catch (const std::exception& e) {
                        // Ignore errors and continue.
                    }
                }
            }
        }
        
        return algorithms;
    }
    
    // Get algorithm metadata
    std::optional<AlgorithmMetadata> getMetadata(const std::string& name) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(name);
        if (it != registry_.end()) {
            return it->second.metadata;
        }
        
        return std::nullopt;
    }
    
    // Get all registered algorithms
    std::vector<std::string> getAllAlgorithms() const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        std::vector<std::string> names;
        names.reserve(registry_.size());
        
        for (const auto& [name, _] : registry_) {
            names.push_back(name);
        }
        
        return names;
    }
    
    // Get all algorithms of a specific type
    std::vector<std::string> getAlgorithmsByType(AlgorithmType type) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        std::vector<std::string> names;
        
        for (const auto& [name, entry] : registry_) {
            if (entry.metadata.type == type) {
                names.push_back(name);
            }
        }
        
        return names;
    }
    
    // Get algorithms with a specific tag
    std::vector<std::string> getAlgorithmsByTag(const std::string& tag) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        std::vector<std::string> names;
        
        for (const auto& [name, entry] : registry_) {
            const auto& tags = entry.metadata.tags;
            if (std::find(tags.begin(), tags.end(), tag) != tags.end()) {
                names.push_back(name);
            }
        }
        
        return names;
    }
    
    // Query compatible algorithms
    std::vector<std::string> getCompatibleAlgorithms(const std::string& algorithm) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(algorithm);
        if (it != registry_.end()) {
            return it->second.metadata.compatibility.compatible_algorithms;
        }
        
        return {};
    }
    
    // Query recommended combinations
    std::vector<std::string> getRecommendedCombinations(const std::string& algorithm) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(algorithm);
        if (it != registry_.end()) {
            return it->second.metadata.compatibility.recommended_combinations;
        }
        
        return {};
    }
    
    // Enable/disable algorithm
    void enableAlgorithm(const std::string& name, bool enable = true) {
        std::unique_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(name);
        if (it != registry_.end()) {
            it->second.is_enabled = enable;
        }
    }
    
    void disableAlgorithm(const std::string& name) {
        enableAlgorithm(name, false);
    }
    
    // Check whether algorithm is registered
    bool isRegistered(const std::string& name) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        return registry_.find(name) != registry_.end();
    }
    
    // Check whether algorithm is enabled
    bool isEnabled(const std::string& name) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(name);
        if (it != registry_.end()) {
            return it->second.is_enabled;
        }
        
        return false;
    }
    
    // Clear instance cache
    void clearCache() {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        instance_cache_.clear();
    }
    
    // Get registry statistics
    struct RegistryStats {
        size_t total_algorithms = 0;
        size_t enabled_algorithms = 0;
        std::map<AlgorithmType, size_t> algorithms_by_type;
        std::map<std::string, size_t> algorithms_by_tag;
    };
    
    RegistryStats getStats() const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        RegistryStats stats;
        stats.total_algorithms = registry_.size();
        
        for (const auto& [name, entry] : registry_) {
            if (entry.is_enabled) {
                stats.enabled_algorithms++;
            }
            
            stats.algorithms_by_type[entry.metadata.type]++;
            
            for (const auto& tag : entry.metadata.tags) {
                stats.algorithms_by_tag[tag]++;
            }
        }
        
        return stats;
    }
    
    // Register algorithm combination
    void registerCombination(const std::string& name,
                           const std::vector<std::string>& algorithms,
                           const std::string& mode) {
        // Store predefined algorithm combinations.
        // Can be extended to support more complex combination configs.
    }
};

// Algorithm registrar (for static registration)
template<typename AlgorithmClass>
class AlgorithmRegistrar {
public:
    AlgorithmRegistrar(const std::string& name, const AlgorithmMetadata& metadata) {
        AlgorithmRegistry::getInstance().registerAlgorithm<AlgorithmClass>(name, metadata);
    }
};

// Macro to simplify registration
#define REGISTER_ALGORITHM(AlgorithmClass, name, ...) \
    static AlgorithmRegistrar<AlgorithmClass> _registrar_##AlgorithmClass(name, __VA_ARGS__)

// Algorithm factory helper
template<typename BaseType>
class AlgorithmFactoryHelper {
public:
    template<typename DerivedType>
    static std::shared_ptr<BaseType> create() {
        return std::make_shared<DerivedType>();
    }
    
    template<typename DerivedType, typename... Args>
    static std::shared_ptr<BaseType> createWithArgs(Args&&... args) {
        return std::make_shared<DerivedType>(std::forward<Args>(args)...);
    }
};

} // namespace triofuzz
