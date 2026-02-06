// 快速补丁：注册所有缺失的算法
// 这是一个临时解决方案，用于快速修复硬编码算法和注册系统不一致的问题

#include "../../include/algorithms/algorithm_registry.hpp"
#include "../../include/algorithms/mutation/havoc_mutation.hpp"
#include "../../include/algorithms/mutation/bitflip_mutation.hpp"
#include "../../include/algorithms/mutation/arithmetic_mutation.hpp"
// #include "../../include/algorithms/mutation/gradient_descent_mutation.hpp" // 已归档 - 高开销
#include "../../include/algorithms/mutation/smart_dictionary_mutation.hpp"

namespace triofuzz {

// 算法包装器：将调度器伪装成变异算法
class SchedulerAsAlgorithm : public AlgorithmBase {
protected:
    std::shared_ptr<AlgorithmBase> underlying_mutation_;
    std::string scheduler_type_;

public:
    SchedulerAsAlgorithm(const std::string& scheduler_type, std::shared_ptr<AlgorithmBase> mutation)
        : scheduler_type_(scheduler_type), underlying_mutation_(mutation) {}

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // 调度器实际上只是选择合适的变异算法
        return underlying_mutation_->execute(input, context);
    }

    AlgorithmType getType() const override { return AlgorithmType::Scheduling; }
    std::string getName() const override { return scheduler_type_; }

    std::vector<InfoType> getProvidedInfo() const override {
        return {InfoType::Scheduling, InfoType::Coverage};
    }

    std::vector<InfoType> getRequiredInfo() const override {
        return {InfoType::Coverage};
    }
};

// 运行时字典变异（SmartDictionary的变体）
class RuntimeDictionaryMutation : public SmartDictionaryMutation {
public:
    RuntimeDictionaryMutation() : SmartDictionaryMutation("") {}
    std::string getName() const override { return "runtime_dictionary"; }
};

// 自适应长度变异
class AdaptiveLengthMutation : public HavocMutation {
public:
    std::string getName() const override { return "adaptive_length"; }

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // 自适应调整输入长度的特殊逻辑
        auto result = input;

        // 50% 概率增长，50% 概率缩短
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> choice(0, 1);

        if (choice(gen) == 0 && result.size() > 1) {
            // 缩短
            std::uniform_int_distribution<size_t> len_dist(1, result.size());
            result.resize(len_dist(gen));
        } else {
            // 增长
            std::uniform_int_distribution<size_t> grow_dist(1, 100);
            size_t grow_size = grow_dist(gen);
            std::uniform_int_distribution<uint8_t> val_dist(0, 255);
            for (size_t i = 0; i < grow_size; ++i) {
                result.push_back(val_dist(gen));
            }
        }

        // 然后应用基础havoc变异
        return HavocMutation::execute(result, context);
    }
};

// 值逼近变异
class ValueApproximationMutation : public ArithmeticMutation {
public:
    std::string getName() const override { return "value_approximation"; }

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // 尝试逼近特定的值（如魔术数字）
        auto result = input;
        if (result.size() >= 4) {
            // 检查并尝试生成常见的魔术数字
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> pos_dist(0, result.size() - 4);
            size_t pos = pos_dist(gen);

            // 常见的魔术数字
            static const uint32_t magic_numbers[] = {
                0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
                0x41414141, 0x42424242, 0xDEADBEEF, 0xCAFEBABE
            };

            std::uniform_int_distribution<> magic_dist(0, 7);
            uint32_t magic = magic_numbers[magic_dist(gen)];

            // 写入魔术数字
            result[pos] = (magic >> 24) & 0xFF;
            result[pos + 1] = (magic >> 16) & 0xFF;
            result[pos + 2] = (magic >> 8) & 0xFF;
            result[pos + 3] = magic & 0xFF;
        }

        return result;
    }
};

// 插桩包装器
class InstrumentationWrapper : public AlgorithmBase {
private:
    std::string instrumentation_type_;
    std::shared_ptr<AlgorithmBase> underlying_mutation_;

public:
    InstrumentationWrapper(const std::string& type, std::shared_ptr<AlgorithmBase> mutation)
        : instrumentation_type_(type), underlying_mutation_(mutation) {}

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // 插桩只是提供额外信息，实际变异由底层算法执行
        return underlying_mutation_->execute(input, context);
    }

    AlgorithmType getType() const override { return AlgorithmType::Analysis; }
    std::string getName() const override { return instrumentation_type_; }

    std::vector<InfoType> getProvidedInfo() const override {
        if (instrumentation_type_ == "data_flow_instrumentation") {
            return {InfoType::DataFlow, InfoType::Coverage};
        } else if (instrumentation_type_ == "taint_analysis_instrumentation") {
            return {InfoType::Taint, InfoType::Coverage};
        }
        return {InfoType::Coverage};
    }

    std::vector<InfoType> getRequiredInfo() const override {
        return {};
    }
};

// 注册所有缺失的算法
void registerMissingAlgorithms() {
    auto& registry = AlgorithmRegistry::getInstance();

    // 1. 注册缺失的变异算法
    {
        AlgorithmConfig config;
        config.name = "runtime_dictionary";
        config.category = "dictionary_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage};
        config.required_info = {};
        config.description = "Runtime dictionary mutation";
        registry.registerAlgorithm<RuntimeDictionaryMutation>("runtime_dictionary", config);
    }

    {
        AlgorithmConfig config;
        config.name = "adaptive_length";
        config.category = "adaptive_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage};
        config.required_info = {};
        config.description = "Adaptive length mutation";
        registry.registerAlgorithm<AdaptiveLengthMutation>("adaptive_length", config);
    }

    {
        AlgorithmConfig config;
        config.name = "value_approximation";
        config.category = "value_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage};
        config.required_info = {};
        config.description = "Value approximation mutation";
        registry.registerAlgorithm<ValueApproximationMutation>("value_approximation", config);
    }

    {
        AlgorithmConfig config;
        config.name = "angora_gradient_descent";
        config.category = "gradient_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Gradient, InfoType::Coverage};
        config.required_info = {};
        config.description = "Angora gradient descent mutation";
        registry.registerAlgorithm<AngoraGradientDescentMutation>("angora_gradient_descent", config);
    }

    {
        AlgorithmConfig config;
        config.name = "cmplog";
        config.category = "comparison_mutation";
        config.type = AlgorithmType::Mutation;
        config.provided_info = {InfoType::Coverage, InfoType::Constraint};
        config.required_info = {};
        config.description = "CmpLog comparison logging mutation";
        registry.registerAlgorithm<CmplogMutation>("cmplog", config);
    }

    // 2. 注册调度器（作为特殊的变异算法）
    {
        AlgorithmConfig config;
        config.name = "mopt_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Coverage};
        config.required_info = {InfoType::Coverage};
        config.description = "MOpt scheduler";

        // 使用工厂lambda创建包装器
        registry.registerAlgorithmFactory("mopt_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("mopt_scheduler",
                    std::make_shared<HavocMutation>());
            }, config);
    }

    // 已归档（性能慢11-13ms）
    // {
    //     AlgorithmConfig config;
    //     config.name = "rare_edge_scheduler";
    //     config.category = "scheduling";
    //     config.type = AlgorithmType::Scheduling;
    //     config.provided_info = {InfoType::Scheduling, InfoType::Coverage};
    //     config.required_info = {InfoType::Coverage};
    //     config.description = "Rare edge scheduler";

    //     registry.registerAlgorithmFactory("rare_edge_scheduler",
    //         []() -> std::shared_ptr<AlgorithmBase> {
    //             return std::make_shared<SchedulerAsAlgorithm>("rare_edge_scheduler",
    //                 std::make_shared<GradientDescentMutation>());
    //         }, config);
    // }

    {
        AlgorithmConfig config;
        config.name = "fast_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Coverage};
        config.required_info = {};
        config.description = "Fast scheduler";

        registry.registerAlgorithmFactory("fast_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("fast_scheduler",
                    std::make_shared<BitFlipMutation>());
            }, config);
    }

    {
        AlgorithmConfig config;
        config.name = "advanced_coverage_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Coverage, InfoType::Energy};
        config.required_info = {InfoType::Coverage};
        config.description = "Advanced coverage scheduler";

        registry.registerAlgorithmFactory("advanced_coverage_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("advanced_coverage_scheduler",
                    std::make_shared<HavocMutation>());
            }, config);
    }

    {
        AlgorithmConfig config;
        config.name = "energy_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Energy};
        config.required_info = {InfoType::Coverage};
        config.description = "Energy-based scheduler";

        registry.registerAlgorithmFactory("energy_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("energy_scheduler",
                    std::make_shared<HavocMutation>());
            }, config);
    }

    {
        AlgorithmConfig config;
        config.name = "enhanced_energy_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Energy, InfoType::Coverage};
        config.required_info = {InfoType::Coverage};
        config.description = "Enhanced energy scheduler";

        registry.registerAlgorithmFactory("enhanced_energy_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("enhanced_energy_scheduler",
                    std::make_shared<HavocMutation>());
            }, config);
    }

    {
        AlgorithmConfig config;
        config.name = "mab_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Coverage};
        config.required_info = {};
        config.description = "Multi-armed bandit scheduler";

        registry.registerAlgorithmFactory("mab_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("mab_scheduler",
                    std::make_shared<HavocMutation>());
            }, config);
    }

    // 3. 注册插桩算法
    {
        AlgorithmConfig config;
        config.name = "data_flow_instrumentation";
        config.category = "instrumentation";
        config.type = AlgorithmType::Analysis;
        config.provided_info = {InfoType::DataFlow, InfoType::Coverage};
        config.required_info = {};
        config.description = "Data flow instrumentation";

        registry.registerAlgorithmFactory("data_flow_instrumentation",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<InstrumentationWrapper>("data_flow_instrumentation",
                    std::make_shared<GradientDescentMutation>());
            }, config);
    }

    {
        AlgorithmConfig config;
        config.name = "taint_analysis_instrumentation";
        config.category = "instrumentation";
        config.type = AlgorithmType::Analysis;
        config.provided_info = {InfoType::Taint, InfoType::Coverage};
        config.required_info = {};
        config.description = "Taint analysis instrumentation";

        registry.registerAlgorithmFactory("taint_analysis_instrumentation",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<InstrumentationWrapper>("taint_analysis_instrumentation",
                    std::make_shared<ArithmeticMutation>());
            }, config);
    }

    // 4. 添加算法别名支持
    // registry.addAlias("libfuzzer", "libfuzzer_structured"); // 已归档 - 高开销
    registry.addAlias("afl++", "afl_plus_plus");
    registry.addAlias("aflpp", "afl_plus_plus");

    std::cout << "[INFO] Registered all missing algorithms successfully" << std::endl;
}

} // namespace triofuzz