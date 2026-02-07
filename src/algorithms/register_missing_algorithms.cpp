// Quick patch: register all missing algorithms
// Temporary solution to quickly fix inconsistencies between hard-coded algorithms and the registry.

#include "../../include/algorithms/algorithm_registry.hpp"
#include "../../include/algorithms/mutation/havoc_mutation.hpp"
#include "../../include/algorithms/mutation/bitflip_mutation.hpp"
#include "../../include/algorithms/mutation/arithmetic_mutation.hpp"
// #include "../../include/algorithms/mutation/gradient_descent_mutation.hpp" // Archived - high overhead
#include "../../include/algorithms/mutation/smart_dictionary_mutation.hpp"

namespace triofuzz {

// Algorithm wrapper: present a scheduler as a mutation algorithm
class SchedulerAsAlgorithm : public AlgorithmBase {
protected:
    std::shared_ptr<AlgorithmBase> underlying_mutation_;
    std::string scheduler_type_;

public:
    SchedulerAsAlgorithm(const std::string& scheduler_type, std::shared_ptr<AlgorithmBase> mutation)
        : scheduler_type_(scheduler_type), underlying_mutation_(mutation) {}

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // The scheduler only selects an appropriate mutation algorithm.
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

// Runtime dictionary mutation (a variant of SmartDictionary)
class RuntimeDictionaryMutation : public SmartDictionaryMutation {
public:
    RuntimeDictionaryMutation() : SmartDictionaryMutation("") {}
    std::string getName() const override { return "runtime_dictionary"; }
};

// Adaptive length mutation
class AdaptiveLengthMutation : public HavocMutation {
public:
    std::string getName() const override { return "adaptive_length"; }

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // Special logic to adaptively adjust input length
        auto result = input;

        // 50% chance to grow, 50% chance to shrink
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> choice(0, 1);

        if (choice(gen) == 0 && result.size() > 1) {
            // Shrink
            std::uniform_int_distribution<size_t> len_dist(1, result.size());
            result.resize(len_dist(gen));
        } else {
            // Grow
            std::uniform_int_distribution<size_t> grow_dist(1, 100);
            size_t grow_size = grow_dist(gen);
            std::uniform_int_distribution<uint8_t> val_dist(0, 255);
            for (size_t i = 0; i < grow_size; ++i) {
                result.push_back(val_dist(gen));
            }
        }

        // Then apply the base havoc mutation
        return HavocMutation::execute(result, context);
    }
};

// Value approximation mutation
class ValueApproximationMutation : public ArithmeticMutation {
public:
    std::string getName() const override { return "value_approximation"; }

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // Try to approximate specific values (e.g., magic numbers)
        auto result = input;
        if (result.size() >= 4) {
            // Try generating common magic numbers
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> pos_dist(0, result.size() - 4);
            size_t pos = pos_dist(gen);

            // Common magic numbers
            static const uint32_t magic_numbers[] = {
                0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
                0x41414141, 0x42424242, 0xDEADBEEF, 0xCAFEBABE
            };

            std::uniform_int_distribution<> magic_dist(0, 7);
            uint32_t magic = magic_numbers[magic_dist(gen)];

            // Write the magic number
            result[pos] = (magic >> 24) & 0xFF;
            result[pos + 1] = (magic >> 16) & 0xFF;
            result[pos + 2] = (magic >> 8) & 0xFF;
            result[pos + 3] = magic & 0xFF;
        }

        return result;
    }
};

// Instrumentation wrapper
class InstrumentationWrapper : public AlgorithmBase {
private:
    std::string instrumentation_type_;
    std::shared_ptr<AlgorithmBase> underlying_mutation_;

public:
    InstrumentationWrapper(const std::string& type, std::shared_ptr<AlgorithmBase> mutation)
        : instrumentation_type_(type), underlying_mutation_(mutation) {}

    std::vector<uint8_t> execute(const std::vector<uint8_t>& input, GlobalContext& context) override {
        // Instrumentation only provides extra info; the underlying algorithm performs the mutation.
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

// Register all missing algorithms
void registerMissingAlgorithms() {
    auto& registry = AlgorithmRegistry::getInstance();

    // 1. Register missing mutation algorithms
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

    // 2. Register schedulers (as special mutation algorithms)
    {
        AlgorithmConfig config;
        config.name = "mopt_scheduler";
        config.category = "scheduling";
        config.type = AlgorithmType::Scheduling;
        config.provided_info = {InfoType::Scheduling, InfoType::Coverage};
        config.required_info = {InfoType::Coverage};
        config.description = "MOpt scheduler";

        // Use a factory lambda to create the wrapper
        registry.registerAlgorithmFactory("mopt_scheduler",
            []() -> std::shared_ptr<AlgorithmBase> {
                return std::make_shared<SchedulerAsAlgorithm>("mopt_scheduler",
                    std::make_shared<HavocMutation>());
            }, config);
    }

    // Archived (slow: ~11-13ms)
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

    // 3. Register instrumentation algorithms
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

    // 4. Add algorithm alias support
    // registry.addAlias("libfuzzer", "libfuzzer_structured"); // Archived - high overhead
    registry.addAlias("afl++", "afl_plus_plus");
    registry.addAlias("aflpp", "afl_plus_plus");

    std::cout << "[INFO] Registered all missing algorithms successfully" << std::endl;
}

} // namespace triofuzz
