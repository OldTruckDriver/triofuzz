#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include <any>
#include <functional>

namespace triofuzz {

// Forward declaration
class SharedContext;

// State writer interface
class StateWriter {
public:
    virtual ~StateWriter() = default;
    
    virtual void writeInt(const std::string& key, int64_t value) = 0;
    virtual void writeDouble(const std::string& key, double value) = 0;
    virtual void writeString(const std::string& key, const std::string& value) = 0;
    virtual void writeBytes(const std::string& key, const std::vector<uint8_t>& data) = 0;
    virtual void writeBool(const std::string& key, bool value) = 0;
    
    template<typename T>
    void write(const std::string& key, const T& value);
};

// State reader interface
class StateReader {
public:
    virtual ~StateReader() = default;
    
    virtual std::optional<int64_t> readInt(const std::string& key) = 0;
    virtual std::optional<double> readDouble(const std::string& key) = 0;
    virtual std::optional<std::string> readString(const std::string& key) = 0;
    virtual std::optional<std::vector<uint8_t>> readBytes(const std::string& key) = 0;
    virtual std::optional<bool> readBool(const std::string& key) = 0;
    
    template<typename T>
    std::optional<T> read(const std::string& key);
};

// Algorithm type enum
enum class AlgorithmType {
    Instrumentation,
    Scheduling,
    Mutation,
    Feedback,
    Analysis,
    Combination
};

// Info type enum
enum class InfoType {
    Gradient,
    Constraint,
    Coverage,
    Taint,
    Performance,
    Energy,
    Trace,
    Instrumentation,
    Fairness,
    Structure,
    Prediction,
    Scheduling,
    MultiObjective,
    Dictionary,
    DataFlow,
    ControlFlow,
    Edge,
    Comparison,
    Distance,
    Crash,
    Context
};

// Algorithm metadata
struct AlgorithmInfo {
    std::string name;
    std::string version;
    std::string description;
    AlgorithmType type;
    std::vector<InfoType> provided_info;
    std::vector<InfoType> required_info;
    std::map<std::string, std::string> metadata;
};

// Performance metrics
struct PerformanceMetrics {
    size_t execution_count = 0;
    double total_time_ms = 0.0;
    double average_time_ms = 0.0;
    double min_time_ms = std::numeric_limits<double>::max();
    double max_time_ms = 0.0;
    size_t memory_usage_bytes = 0;
    double success_rate = 0.0;
    std::map<std::string, double> custom_metrics;
    
    void recordExecution(double time_ms, bool success = true) {
        execution_count++;
        total_time_ms += time_ms;
        average_time_ms = total_time_ms / execution_count;
        min_time_ms = std::min(min_time_ms, time_ms);
        max_time_ms = std::max(max_time_ms, time_ms);
        if (success) {
            success_rate = (success_rate * (execution_count - 1) + 1.0) / execution_count;
        } else {
            success_rate = (success_rate * (execution_count - 1)) / execution_count;
        }
    }
};

// Algorithm parameters
class Parameters {
private:
    std::map<std::string, std::any> params;
    
public:
    template<typename T>
    void set(const std::string& key, T&& value) {
        params[key] = std::forward<T>(value);
    }
    
    template<typename T>
    std::optional<T> get(const std::string& key) const {
        auto it = params.find(key);
        if (it != params.end()) {
            try {
                return std::any_cast<T>(it->second);
            } catch (const std::bad_any_cast&) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }
    
    bool has(const std::string& key) const {
        return params.find(key) != params.end();
    }
    
    void merge(const Parameters& other) {
        for (const auto& [key, value] : other.params) {
            params[key] = value;
        }
    }
};

// Base algorithm interface (non-templated)
class AlgorithmBase {
public:
    virtual ~AlgorithmBase() = default;
    
    // Metadata interface
    virtual AlgorithmInfo getInfo() const = 0;
    
    // Performance metrics interface
    virtual PerformanceMetrics getMetrics() const = 0;
    
    // Parameter management interface
    virtual void updateParameters(const Parameters& params) = 0;
    virtual Parameters getParameters() const = 0;
    
    // State management interface
    virtual void saveState(StateWriter& writer) const = 0;
    virtual void loadState(StateReader& reader) = 0;
    
    // Lifecycle management
    virtual void initialize() {}
    virtual void shutdown() {}
    virtual void reset() = 0;
};

// Algorithm base template
template<typename Input = std::any, typename Output = std::any, typename Context = SharedContext>
class Algorithm : public AlgorithmBase {
public:
    virtual ~Algorithm() = default;
    
    // Core execution interface
    virtual Output execute(const Input& input, Context& ctx) = 0;
    
    // Metadata interface
    virtual AlgorithmInfo getInfo() const override = 0;
    
    // Performance metrics interface
    virtual PerformanceMetrics getMetrics() const override { return metrics_; }
    
    // Parameter management interface
    virtual void updateParameters(const Parameters& params) override {
        parameters_.merge(params);
        onParametersUpdated();
    }
    
    virtual Parameters getParameters() const override { return parameters_; }
    
    // Combination compatibility check
    virtual bool canCombineWith(const Algorithm& other) const {
        // Default implementation: check whether info dependencies are satisfied.
        const auto& my_info = getInfo();
        const auto& other_info = other.getInfo();
        
        // Check for circular dependencies.
        for (const auto& req : my_info.required_info) {
            for (const auto& other_req : other_info.required_info) {
                if (std::find(my_info.provided_info.begin(), 
                            my_info.provided_info.end(), other_req) != my_info.provided_info.end() &&
                    std::find(other_info.provided_info.begin(), 
                            other_info.provided_info.end(), req) != other_info.provided_info.end()) {
                    return false; // Circular dependency
                }
            }
        }
        return true;
    }
    
    // State management interface
    virtual void saveState(StateWriter& writer) const override = 0;
    virtual void loadState(StateReader& reader) override = 0;
    
    // Lifecycle management
    virtual void initialize() override {}
    virtual void shutdown() override {}
    virtual void reset() override { metrics_ = PerformanceMetrics(); }
    
protected:
    // Parameter update callback
    virtual void onParametersUpdated() {}
    
    // Helper: record execution time
    template<typename Func>
    auto measureExecution(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        
        try {
            auto result = func();
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            metrics_.recordExecution(duration.count() / 1000.0, true);
            
            return result;
        } catch (...) {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            metrics_.recordExecution(duration.count() / 1000.0, false);
            throw;
        }
    }
    
protected:
    Parameters parameters_;
    mutable PerformanceMetrics metrics_;
};

// Type aliases
template<typename T>
using AlgorithmPtr = std::shared_ptr<T>;

template<typename T>
using AlgorithmWeakPtr = std::weak_ptr<T>;

// Algorithm factory function type
using AlgorithmFactory = std::function<std::shared_ptr<AlgorithmBase>()>;

} // namespace triofuzz
