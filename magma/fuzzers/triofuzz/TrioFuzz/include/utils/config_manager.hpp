#pragma once

#include "../core/algorithm.hpp"
#include "../core/engine.hpp"
#include <json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <filesystem>

using json = nlohmann::json;

namespace triofuzz {

// Algorithm configuration struct (renamed from AlgorithmConfig to avoid conflict with AlgorithmConfig namespace)
struct AlgoConfigStruct {
    std::string name;
    bool enabled = true;
    Parameters parameters;
    std::vector<std::string> tags;
    std::map<std::string, std::any> custom_settings;

    // Convert to JSON
    json toJson() const {
        json j;
        j["name"] = name;
        j["enabled"] = enabled;
        j["tags"] = tags;

        // Parameters need special handling (std::any cannot be serialized directly)
        json params_json;
        // Simplified here; real code needs more complex serialization logic.
        j["parameters"] = params_json;

        return j;
    }

    // Create from JSON
    static AlgoConfigStruct fromJson(const json& j) {
        AlgoConfigStruct config;
        config.name = j["name"];
        config.enabled = j.value("enabled", true);

        if (j.contains("tags")) {
            config.tags = j["tags"].get<std::vector<std::string>>();
        }

        // Parameter deserialization
        if (j.contains("parameters")) {
            // Simplified handling
        }

        return config;
    }
};

// Combination strategy configuration
struct CombinationStrategyConfig {
    std::string type = "thompson_sampling"; // "thompson_sampling", "mcts", "random"
    
    // Thompson Sampling parameters
    struct ThompsonSamplingParams {
        double exploration_rate = 0.1;
        double decay_factor = 0.995;
        size_t min_samples = 10;
        
        struct RewardWeights {
            double coverage = 0.4;
            double crash = 0.3;
            double speed = 0.2;
            double diversity = 0.1;
        } reward_weights;
    } thompson_sampling;
    
    // MCTS parameters
    struct MCTSParams {
        double exploration_constant = 1.414;
        size_t simulation_count = 1000;
        size_t max_depth = 10;
    } mcts;
    
    json toJson() const {
        json j;
        j["type"] = type;
        
        if (type == "thompson_sampling") {
            j["thompson_sampling"]["exploration_rate"] = thompson_sampling.exploration_rate;
            j["thompson_sampling"]["decay_factor"] = thompson_sampling.decay_factor;
            j["thompson_sampling"]["min_samples"] = thompson_sampling.min_samples;
            j["thompson_sampling"]["reward_weights"]["coverage"] = thompson_sampling.reward_weights.coverage;
            j["thompson_sampling"]["reward_weights"]["crash"] = thompson_sampling.reward_weights.crash;
            j["thompson_sampling"]["reward_weights"]["speed"] = thompson_sampling.reward_weights.speed;
            j["thompson_sampling"]["reward_weights"]["diversity"] = thompson_sampling.reward_weights.diversity;
        } else if (type == "mcts") {
            j["mcts"]["exploration_constant"] = mcts.exploration_constant;
            j["mcts"]["simulation_count"] = mcts.simulation_count;
            j["mcts"]["max_depth"] = mcts.max_depth;
        }
        
        return j;
    }
    
    static CombinationStrategyConfig fromJson(const json& j) {
        CombinationStrategyConfig config;
        config.type = j.value("type", "thompson_sampling");
        
        if (config.type == "thompson_sampling" && j.contains("thompson_sampling")) {
            const auto& ts = j["thompson_sampling"];
            config.thompson_sampling.exploration_rate = ts.value("exploration_rate", 0.1);
            config.thompson_sampling.decay_factor = ts.value("decay_factor", 0.995);
            config.thompson_sampling.min_samples = ts.value("min_samples", 10);
            
            if (ts.contains("reward_weights")) {
                const auto& rw = ts["reward_weights"];
                config.thompson_sampling.reward_weights.coverage = rw.value("coverage", 0.4);
                config.thompson_sampling.reward_weights.crash = rw.value("crash", 0.3);
                config.thompson_sampling.reward_weights.speed = rw.value("speed", 0.2);
                config.thompson_sampling.reward_weights.diversity = rw.value("diversity", 0.1);
            }
        } else if (config.type == "mcts" && j.contains("mcts")) {
            const auto& mcts = j["mcts"];
            config.mcts.exploration_constant = mcts.value("exploration_constant", 1.414);
            config.mcts.simulation_count = mcts.value("simulation_count", 1000);
            config.mcts.max_depth = mcts.value("max_depth", 10);
        }
        
        return config;
    }
};

// Global configuration
struct GlobalConfig {
    // Execution configuration
    struct ExecutionConfig {
        size_t thread_count = std::thread::hardware_concurrency();
        size_t memory_limit_mb = 1024;
        size_t timeout_ms = 1000;
        size_t max_input_size = 1024 * 1024;
        std::string executor_type = "fork"; // "fork", "persistent", "qemu"
    } execution;
    
    // Corpus configuration
    struct CorpusConfig {
        size_t max_corpus_size = 1000000;
        size_t max_seed_size = 1024 * 1024;
        bool enable_minimization = true;
        bool enable_deduplication = true;
        double energy_decay_rate = 0.95;
        std::string corpus_dir = "./corpus";
        std::string crash_dir = "./crashes";
    } corpus;
    
    // Monitoring configuration
    struct MonitoringConfig {
        bool enable_performance_monitoring = true;
        bool enable_crash_analysis = true;
        size_t stats_interval_sec = 60;
        size_t metrics_history_size = 1000;
        std::string stats_output_file = "./fuzzing_stats.json";
    } monitoring;
    
    // Algorithm combination configuration
    struct AlgorithmCombinationConfig {
        bool enable_dynamic_combination = true;  // Enable dynamic algorithm combination
        
        // Fixed combination config (used when dynamic combination is disabled)
        struct FixedCombinationConfig {
            std::vector<std::vector<std::string>> thread_algorithm_combinations;  // Fixed algorithm combinations per thread
            std::string fixed_combination_mode = "sequential";  // Fixed combination mode
        } fixed_combination;
    } algorithm_combination;
    
    // Output configuration
    struct OutputConfig {
        std::string output_dir = "./output";
        std::string log_file = "./fuzzing.log";
        std::string log_level = "info"; // "debug", "info", "warning", "error"
        bool save_all_crashes = true;
        bool save_unique_crashes_only = false;
    } output;
    
    json toJson() const {
        json j;
        
        // Execution configuration
        j["execution"]["thread_count"] = execution.thread_count;
        j["execution"]["memory_limit_mb"] = execution.memory_limit_mb;
        j["execution"]["timeout_ms"] = execution.timeout_ms;
        j["execution"]["max_input_size"] = execution.max_input_size;
        j["execution"]["executor_type"] = execution.executor_type;
        
        // Corpus configuration
        j["corpus"]["max_corpus_size"] = corpus.max_corpus_size;
        j["corpus"]["max_seed_size"] = corpus.max_seed_size;
        j["corpus"]["enable_minimization"] = corpus.enable_minimization;
        j["corpus"]["enable_deduplication"] = corpus.enable_deduplication;
        j["corpus"]["energy_decay_rate"] = corpus.energy_decay_rate;
        j["corpus"]["corpus_dir"] = corpus.corpus_dir;
        j["corpus"]["crash_dir"] = corpus.crash_dir;
        
        // Monitoring configuration
        j["monitoring"]["enable_performance_monitoring"] = monitoring.enable_performance_monitoring;
        j["monitoring"]["enable_crash_analysis"] = monitoring.enable_crash_analysis;
        j["monitoring"]["stats_interval_sec"] = monitoring.stats_interval_sec;
        j["monitoring"]["metrics_history_size"] = monitoring.metrics_history_size;
        j["monitoring"]["stats_output_file"] = monitoring.stats_output_file;
        
        // Algorithm combination configuration
        j["algorithm_combination"]["enable_dynamic_combination"] = algorithm_combination.enable_dynamic_combination;
        
        // Fixed combination configuration
        json fixed_combination_json = json::array();
        for (const auto& combination : algorithm_combination.fixed_combination.thread_algorithm_combinations) {
            fixed_combination_json.push_back(combination);
        }
        j["algorithm_combination"]["fixed_combination"]["thread_algorithm_combinations"] = fixed_combination_json;
        j["algorithm_combination"]["fixed_combination"]["fixed_combination_mode"] = algorithm_combination.fixed_combination.fixed_combination_mode;
        
        // Output configuration
        j["output"]["output_dir"] = output.output_dir;
        j["output"]["log_file"] = output.log_file;
        j["output"]["log_level"] = output.log_level;
        j["output"]["save_all_crashes"] = output.save_all_crashes;
        j["output"]["save_unique_crashes_only"] = output.save_unique_crashes_only;
        
        return j;
    }
    
    static GlobalConfig fromJson(const json& j) {
        GlobalConfig config;
        
        // Execution configuration
        if (j.contains("execution")) {
            const auto& exec = j["execution"];
            config.execution.thread_count = exec.value("thread_count", std::thread::hardware_concurrency());
            config.execution.memory_limit_mb = exec.value("memory_limit_mb", 1024);
            config.execution.timeout_ms = exec.value("timeout_ms", 1000);
            config.execution.max_input_size = exec.value("max_input_size", 1024 * 1024);
            config.execution.executor_type = exec.value("executor_type", "fork");
        }
        
        // Corpus configuration
        if (j.contains("corpus")) {
            const auto& corpus = j["corpus"];
            config.corpus.max_corpus_size = corpus.value("max_corpus_size", 10000);
            config.corpus.max_seed_size = corpus.value("max_seed_size", 1024 * 1024);
            config.corpus.enable_minimization = corpus.value("enable_minimization", true);
            config.corpus.enable_deduplication = corpus.value("enable_deduplication", true);
            config.corpus.energy_decay_rate = corpus.value("energy_decay_rate", 0.95);
            config.corpus.corpus_dir = corpus.value("corpus_dir", "./corpus");
            config.corpus.crash_dir = corpus.value("crash_dir", "./crashes");
        }
        
        // Monitoring configuration
        if (j.contains("monitoring")) {
            const auto& mon = j["monitoring"];
            config.monitoring.enable_performance_monitoring = mon.value("enable_performance_monitoring", true);
            config.monitoring.enable_crash_analysis = mon.value("enable_crash_analysis", true);
            config.monitoring.stats_interval_sec = mon.value("stats_interval_sec", 60);
            config.monitoring.metrics_history_size = mon.value("metrics_history_size", 1000);
            config.monitoring.stats_output_file = mon.value("stats_output_file", "./fuzzing_stats.json");
        }
        
        // Algorithm combination configuration
        if (j.contains("algorithm_combination")) {
            const auto& algo_combination = j["algorithm_combination"];
            config.algorithm_combination.enable_dynamic_combination = algo_combination.value("enable_dynamic_combination", true);
            
            // Fixed combination configuration
            if (algo_combination.contains("fixed_combination")) {
                const auto& fixed_combination = algo_combination["fixed_combination"];
                if (fixed_combination.contains("thread_algorithm_combinations")) {
                    const auto& thread_combinations = fixed_combination["thread_algorithm_combinations"];
                    for (const auto& combination : thread_combinations) {
                        config.algorithm_combination.fixed_combination.thread_algorithm_combinations.push_back(combination.get<std::vector<std::string>>());
                    }
                }
                config.algorithm_combination.fixed_combination.fixed_combination_mode = fixed_combination.value("fixed_combination_mode", "sequential");
            }
        }
        
        // Output configuration
        if (j.contains("output")) {
            const auto& out = j["output"];
            config.output.output_dir = out.value("output_dir", "./output");
            config.output.log_file = out.value("log_file", "./fuzzing.log");
            config.output.log_level = out.value("log_level", "info");
            config.output.save_all_crashes = out.value("save_all_crashes", true);
            config.output.save_unique_crashes_only = out.value("save_unique_crashes_only", false);
        }
        
        return config;
    }
};

// Configuration manager
class ConfigManager {
private:
    // Configuration storage
    GlobalConfig global_config_;
    std::vector<AlgoConfigStruct> algorithm_configs_;
    CombinationStrategyConfig combination_strategy_;
    
    // Predefined combinations
    std::map<std::string, std::vector<std::string>> predefined_combinations_;
    
    // Config file path
    std::string config_file_path_;
    
    // Config validator
    class ConfigValidator {
    public:
        static bool validateGlobalConfig(const GlobalConfig& config) {
            // Validate thread count
            if (config.execution.thread_count == 0) {
                return false;
            }
            
            // Validate memory limit
            if (config.execution.memory_limit_mb < 32) {
                return false;
            }
            
            // Validate timeout
            if (config.execution.timeout_ms < 10) {
                return false;
            }
            
            // Validate corpus size
            if (config.corpus.max_corpus_size < 10) {
                return false;
            }
            
            // Validate energy decay rate
            if (config.corpus.energy_decay_rate <= 0 || config.corpus.energy_decay_rate > 1) {
                return false;
            }
            
            return true;
        }
        
        static bool validateAlgorithmConfig(const AlgoConfigStruct& config) {
            // Validate algorithm name
            if (config.name.empty()) {
                return false;
            }
            
            return true;
        }
        
        static bool validateCombinationStrategy(const CombinationStrategyConfig& config) {
            // Validate strategy type
            if (config.type != "thompson_sampling" && 
                config.type != "mcts" && 
                config.type != "random") {
                return false;
            }
            
            // Validate strategy-specific parameters
            if (config.type == "thompson_sampling") {
                if (config.thompson_sampling.exploration_rate < 0 || 
                    config.thompson_sampling.exploration_rate > 1) {
                    return false;
                }
                
                if (config.thompson_sampling.decay_factor <= 0 || 
                    config.thompson_sampling.decay_factor > 1) {
                    return false;
                }
                
                // Validate that weights sum to 1
                const auto& weights = config.thompson_sampling.reward_weights;
                double sum = weights.coverage + weights.crash + weights.speed + weights.diversity;
                if (std::abs(sum - 1.0) > 0.001) {
                    return false;
                }
            } else if (config.type == "mcts") {
                if (config.mcts.exploration_constant <= 0) {
                    return false;
                }
                
                if (config.mcts.simulation_count == 0) {
                    return false;
                }
            }
            
            return true;
        }
    };
    
public:
    ConfigManager() = default;
    
    // Load configuration file
    void loadFromFile(const std::string& path) {
        config_file_path_ = path;
        
        std::ifstream file(path);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open config file: " + path);
        }
        
        json j;
        file >> j;
        
        // Load global configuration
        if (j.contains("global")) {
            global_config_ = GlobalConfig::fromJson(j["global"]);
            if (!ConfigValidator::validateGlobalConfig(global_config_)) {
                throw std::runtime_error("Invalid global configuration");
            }
        }
        
        // Load algorithm configurations
        if (j.contains("algorithms")) {
            algorithm_configs_.clear();
            for (const auto& algo_json : j["algorithms"]) {
                auto algo_config = AlgoConfigStruct::fromJson(algo_json);
                if (!ConfigValidator::validateAlgorithmConfig(algo_config)) {
                    throw std::runtime_error("Invalid algorithm configuration: " + algo_config.name);
                }
                algorithm_configs_.push_back(algo_config);
            }
        }
        
        // Load combination strategy
        if (j.contains("combination_strategy")) {
            combination_strategy_ = CombinationStrategyConfig::fromJson(j["combination_strategy"]);
            if (!ConfigValidator::validateCombinationStrategy(combination_strategy_)) {
                throw std::runtime_error("Invalid combination strategy configuration");
            }
        }
        
        // Load predefined combinations
        if (j.contains("predefined_combinations")) {
            predefined_combinations_.clear();
            for (const auto& [name, algos] : j["predefined_combinations"].items()) {
                predefined_combinations_[name] = algos.get<std::vector<std::string>>();
            }
        }
    }
    
    // Save configuration to file
    void saveToFile(const std::string& path = "") {
        std::string save_path = path.empty() ? config_file_path_ : path;
        
        json j;
        j["global"] = global_config_.toJson();
        
        // Save algorithm configurations
        json algos_json = json::array();
        for (const auto& algo_config : algorithm_configs_) {
            algos_json.push_back(algo_config.toJson());
        }
        j["algorithms"] = algos_json;
        
        // Save combination strategy
        j["combination_strategy"] = combination_strategy_.toJson();
        
        // Save predefined combinations
        j["predefined_combinations"] = predefined_combinations_;
        
        // Write file
        std::ofstream file(save_path);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot save config file: " + save_path);
        }
        
        file << j.dump(4); // Pretty-print output
    }
    
    // Create default configuration
    void createDefaultConfig() {
        global_config_ = GlobalConfig();
        
        // Add default algorithm configurations
        algorithm_configs_.clear();
        
        // Havoc mutation
        AlgoConfigStruct havoc_config;
        havoc_config.name = "havoc";
        havoc_config.enabled = true;
        havoc_config.tags = {"mutation", "general"};
        algorithm_configs_.push_back(havoc_config);
        
        // Bit flip
        AlgoConfigStruct bitflip_config;
        bitflip_config.name = "bit_flip";
        bitflip_config.enabled = true;
        bitflip_config.tags = {"mutation", "simple"};
        algorithm_configs_.push_back(bitflip_config);
        
        // Gradient descent
        AlgoConfigStruct gradient_config;
        gradient_config.name = "gradient_descent";
        gradient_config.enabled = true;
        gradient_config.tags = {"mutation", "advanced"};
        algorithm_configs_.push_back(gradient_config);
        
        // Energy scheduler
        AlgoConfigStruct energy_config;
        energy_config.name = "energy_scheduler";
        energy_config.enabled = true;
        energy_config.tags = {"scheduling"};
        algorithm_configs_.push_back(energy_config);
        
        // Default combination strategy
        combination_strategy_ = CombinationStrategyConfig();
        
        // Predefined combinations
        predefined_combinations_["basic"] = {"havoc", "bit_flip"};
        predefined_combinations_["advanced"] = {"gradient_descent", "havoc", "constraint_solving"};
        predefined_combinations_["fast"] = {"bit_flip", "arithmetic"};
    }
    
    // Get configuration
    const GlobalConfig& getGlobalConfig() const { return global_config_; }
    const std::vector<AlgoConfigStruct>& getAlgorithmConfigs() const { return algorithm_configs_; }
    const CombinationStrategyConfig& getCombinationStrategy() const { return combination_strategy_; }
    
    // Update configuration
    void updateGlobalConfig(const GlobalConfig& config) {
        if (!ConfigValidator::validateGlobalConfig(config)) {
            throw std::runtime_error("Invalid global configuration");
        }
        global_config_ = config;
    }
    
    void updateAlgorithmConfig(const std::string& algo_name, const AlgoConfigStruct& config) {
        auto it = std::find_if(algorithm_configs_.begin(), algorithm_configs_.end(),
                              [&algo_name](const auto& cfg) { return cfg.name == algo_name; });
        
        if (it != algorithm_configs_.end()) {
            if (!ConfigValidator::validateAlgorithmConfig(config)) {
                throw std::runtime_error("Invalid algorithm configuration");
            }
            *it = config;
        } else {
            throw std::runtime_error("Algorithm not found: " + algo_name);
        }
    }
    
    void updateCombinationStrategy(const CombinationStrategyConfig& config) {
        if (!ConfigValidator::validateCombinationStrategy(config)) {
            throw std::runtime_error("Invalid combination strategy configuration");
        }
        combination_strategy_ = config;
    }
    
    // Get enabled algorithms
    std::vector<std::string> getEnabledAlgorithms() const {
        std::vector<std::string> enabled;
        for (const auto& config : algorithm_configs_) {
            if (config.enabled) {
                enabled.push_back(config.name);
            }
        }
        return enabled;
    }
    
    // Get predefined combination
    std::optional<std::vector<std::string>> getPredefinedCombination(const std::string& name) const {
        auto it = predefined_combinations_.find(name);
        if (it != predefined_combinations_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    
    // Add predefined combination
    void addPredefinedCombination(const std::string& name, const std::vector<std::string>& algorithms) {
        predefined_combinations_[name] = algorithms;
    }
    
    // Convert to FuzzingConfig
    FuzzingConfig toFuzzingConfig() const {
        FuzzingConfig config;
        
        // Basic configuration
        config.target_binary = "/bin/cat";  // Default target
        config.input_dir = "./seeds";
        config.output_dir = global_config_.output.output_dir;
        
        // Execution configuration
        config.thread_count = global_config_.execution.thread_count;
        config.memory_limit_mb = global_config_.execution.memory_limit_mb;
        config.timeout = std::chrono::milliseconds(global_config_.execution.timeout_ms);
        
        // Algorithm configuration
        config.enabled_algorithms = getEnabledAlgorithms();
        config.combination_strategy = combination_strategy_.type;
        config.enable_dynamic_combination = global_config_.algorithm_combination.enable_dynamic_combination;
        config.fixed_combination.thread_algorithm_combinations = global_config_.algorithm_combination.fixed_combination.thread_algorithm_combinations;
        config.fixed_combination.fixed_combination_mode = global_config_.algorithm_combination.fixed_combination.fixed_combination_mode;
        
        // Performance configuration
        config.enable_performance_monitoring = global_config_.monitoring.enable_performance_monitoring;
        config.enable_crash_analysis = global_config_.monitoring.enable_crash_analysis;
        config.stats_interval = std::chrono::seconds(global_config_.monitoring.stats_interval_sec);
        
        return config;
    }
    
    // Hot-reload support
    class HotReloader {
    private:
        ConfigManager& manager_;
        std::thread reload_thread_;
        std::atomic<bool> running_{false};
        std::filesystem::file_time_type last_write_time_;
        
    public:
        explicit HotReloader(ConfigManager& manager) : manager_(manager) {}
        
        ~HotReloader() {
            stop();
        }
        
        void start(std::chrono::seconds check_interval = std::chrono::seconds(5)) {
            if (running_.load()) return;
            
            running_ = true;
            last_write_time_ = std::filesystem::last_write_time(manager_.config_file_path_);
            
            reload_thread_ = std::thread([this, check_interval]() {
                while (running_.load()) {
                    try {
                        auto current_write_time = std::filesystem::last_write_time(manager_.config_file_path_);
                        if (current_write_time != last_write_time_) {
                            manager_.loadFromFile(manager_.config_file_path_);
                            last_write_time_ = current_write_time;
                            std::cout << "Configuration reloaded from: " << manager_.config_file_path_ << std::endl;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Error reloading configuration: " << e.what() << std::endl;
                    }
                    
                    std::this_thread::sleep_for(check_interval);
                }
            });
        }
        
        void stop() {
            running_ = false;
            if (reload_thread_.joinable()) {
                reload_thread_.join();
            }
        }
    };
    
    // Create hot reloader
    std::unique_ptr<HotReloader> createHotReloader() {
        return std::make_unique<HotReloader>(*this);
    }
};

} // namespace triofuzz
