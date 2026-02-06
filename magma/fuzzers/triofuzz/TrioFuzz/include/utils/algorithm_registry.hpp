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

// 算法元数据
struct AlgorithmMetadata {
    std::string name;
    std::string description;
    std::string version;
    AlgorithmType type;
    std::vector<std::string> tags;
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> parameters_description;
    std::map<std::string, std::string> metadata;
    
    // 性能特征
    struct PerformanceCharacteristics {
        double avg_execution_time_ms = 0.0;
        size_t memory_usage_bytes = 0;
        bool is_thread_safe = true;
        bool is_deterministic = true;
    } performance;
    
    // 兼容性信息
    struct Compatibility {
        std::vector<std::string> compatible_algorithms;
        std::vector<std::string> incompatible_algorithms;
        std::vector<std::string> recommended_combinations;
    } compatibility;
};

// 算法注册表
class AlgorithmRegistry {
private:
    // 算法工厂类型
    using AlgorithmFactoryBase = std::function<std::shared_ptr<void>()>;
    
    // 算法工厂模板
    template<typename AlgorithmType>
    using TypedAlgorithmFactory = std::function<std::shared_ptr<AlgorithmType>()>;
    
    // 存储结构
    struct RegistryEntry {
        AlgorithmFactoryBase factory;
        AlgorithmMetadata metadata;
        std::type_index type_index;
        bool is_enabled = true;
        
        // 添加构造函数以正确初始化type_index
        RegistryEntry() : type_index(typeid(void)) {}
        
        RegistryEntry(AlgorithmFactoryBase f, const AlgorithmMetadata& m, std::type_index ti, bool enabled = true)
            : factory(f), metadata(m), type_index(ti), is_enabled(enabled) {}
    };
    
    // 注册表
    std::unordered_map<std::string, RegistryEntry> registry_;
    mutable std::shared_mutex registry_mutex_;
    
    // 类型到算法名称的映射
    std::unordered_map<std::type_index, std::vector<std::string>> type_to_algorithms_;
    
    // 算法实例缓存（用于单例算法）
    mutable std::unordered_map<std::string, std::weak_ptr<void>> instance_cache_;
    mutable std::mutex cache_mutex_;
    
    // 单例实例
    static std::unique_ptr<AlgorithmRegistry> instance_;
    static std::mutex instance_mutex_;
    
public:
    // 构造函数改为公有
    AlgorithmRegistry() = default;
    
    // 获取单例实例
    static AlgorithmRegistry& getInstance() {
        std::lock_guard<std::mutex> lock(instance_mutex_);
        if (!instance_) {
            instance_ = std::unique_ptr<AlgorithmRegistry>(new AlgorithmRegistry());
        }
        return *instance_;
    }
    
    // 禁用拷贝和移动
    AlgorithmRegistry(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry& operator=(const AlgorithmRegistry&) = delete;
    AlgorithmRegistry(AlgorithmRegistry&&) = delete;
    AlgorithmRegistry& operator=(AlgorithmRegistry&&) = delete;
    
    // 注册算法
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
    
    // 接受AlgorithmFactory类型的注册方法
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
    
    // 便捷注册方法（使用默认工厂）
    template<typename AlgorithmClass>
    void registerAlgorithm(const std::string& name, const AlgorithmMetadata& metadata) {
        auto factory = []() { return std::make_shared<AlgorithmClass>(); };
        registerAlgorithm<AlgorithmClass>(name, factory, metadata);
    }
    
    // 创建算法实例
    template<typename AlgorithmType>
    std::shared_ptr<AlgorithmType> create(const std::string& name, bool use_cache = false) {
        if (use_cache) {
            // 检查缓存
            std::lock_guard<std::mutex> cache_lock(cache_mutex_);
            auto it = instance_cache_.find(name);
            if (it != instance_cache_.end()) {
                if (auto cached = it->second.lock()) {
                    return std::static_pointer_cast<AlgorithmType>(cached);
                }
            }
        }
        
        // 创建新实例
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
    
    // 批量创建算法
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
                        // 记录错误但继续
                    }
                }
            }
        }
        
        return algorithms;
    }
    
    // 获取算法元数据
    std::optional<AlgorithmMetadata> getMetadata(const std::string& name) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(name);
        if (it != registry_.end()) {
            return it->second.metadata;
        }
        
        return std::nullopt;
    }
    
    // 获取所有注册的算法
    std::vector<std::string> getAllAlgorithms() const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        std::vector<std::string> names;
        names.reserve(registry_.size());
        
        for (const auto& [name, _] : registry_) {
            names.push_back(name);
        }
        
        return names;
    }
    
    // 获取特定类型的所有算法
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
    
    // 获取带有特定标签的算法
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
    
    // 查询兼容算法
    std::vector<std::string> getCompatibleAlgorithms(const std::string& algorithm) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(algorithm);
        if (it != registry_.end()) {
            return it->second.metadata.compatibility.compatible_algorithms;
        }
        
        return {};
    }
    
    // 查询推荐组合
    std::vector<std::string> getRecommendedCombinations(const std::string& algorithm) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(algorithm);
        if (it != registry_.end()) {
            return it->second.metadata.compatibility.recommended_combinations;
        }
        
        return {};
    }
    
    // 启用/禁用算法
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
    
    // 检查算法是否已注册
    bool isRegistered(const std::string& name) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        return registry_.find(name) != registry_.end();
    }
    
    // 检查算法是否启用
    bool isEnabled(const std::string& name) const {
        std::shared_lock<std::shared_mutex> lock(registry_mutex_);
        
        auto it = registry_.find(name);
        if (it != registry_.end()) {
            return it->second.is_enabled;
        }
        
        return false;
    }
    
    // 清除实例缓存
    void clearCache() {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        instance_cache_.clear();
    }
    
    // 获取算法统计信息
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
    
    // 注册算法组合
    void registerCombination(const std::string& name,
                           const std::vector<std::string>& algorithms,
                           const std::string& mode) {
        // 存储预定义的算法组合
        // 可以扩展以支持更复杂的组合配置
    }
};

// 算法自动注册器（用于静态注册）
template<typename AlgorithmClass>
class AlgorithmRegistrar {
public:
    AlgorithmRegistrar(const std::string& name, const AlgorithmMetadata& metadata) {
        AlgorithmRegistry::getInstance().registerAlgorithm<AlgorithmClass>(name, metadata);
    }
};

// 宏定义简化注册
#define REGISTER_ALGORITHM(AlgorithmClass, name, ...) \
    static AlgorithmRegistrar<AlgorithmClass> _registrar_##AlgorithmClass(name, __VA_ARGS__)

// 算法工厂辅助类
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