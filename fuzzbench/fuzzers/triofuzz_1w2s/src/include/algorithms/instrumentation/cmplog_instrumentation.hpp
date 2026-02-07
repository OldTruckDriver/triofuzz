#pragma once

#include "../../core/algorithm.hpp"
#include "../../core/context.hpp"
#include "../../core/engine.hpp"
#include "base_instrumentation.hpp"
#include "instrumentation_algorithms.hpp"
#include "../../types/contraint_types.hpp"
#include <unordered_map>
#include <set>
#include <queue>
#include <memory>
#include <utility>
#include <vector>

namespace triofuzz {

// CmpLog comparison-instruction instrumentation
class CmpLogInstrumentation : public InstrumentationAlgorithm {
public:
    // Comparison operation types
    enum class ComparisonType {
        INTEGER_EQ,    // Integer equality comparison
        INTEGER_NE,    // Integer inequality comparison
        INTEGER_LT,    // Integer less-than comparison
        INTEGER_LE,    // Integer less-than-or-equal comparison
        INTEGER_GT,    // Integer greater-than comparison
        INTEGER_GE,    // Integer greater-than-or-equal comparison
        STRING_EQ,     // String equality comparison
        STRING_NE,     // String inequality comparison
        STRING_CMP,    // String comparison (strcmp)
        MEMCMP,        // Memory comparison
        FLOATING_EQ,   // Floating-point equality comparison
        FLOATING_LT,   // Floating-point less-than comparison
        CUSTOM         // Custom comparison
    };
    
    // Comparison instruction information
    struct ComparisonInfo {
        uint64_t instruction_address;
        ComparisonType type;
        size_t operand_size;
        std::string function_name;
        std::string source_location;
        
        // Operand information
        struct Operand {
            std::vector<uint8_t> value;
            bool is_constant = false;
            bool is_input_derived = false;
            size_t input_offset = 0;  // If derived from input, record the offset
        };
        
        Operand left_operand;
        Operand right_operand;
        bool comparison_result = false;
        
        // Statistics
        uint64_t hit_count = 0;
        uint64_t true_count = 0;
        uint64_t false_count = 0;
        std::chrono::system_clock::time_point first_hit;
        std::chrono::system_clock::time_point last_hit;
    };
    
    // CmpLog configuration
    struct CmpLogConfig {
        bool enable_integer_comparisons = true;
        bool enable_string_comparisons = true;
        bool enable_memory_comparisons = true;
        bool enable_floating_comparisons = true;
        bool enable_constraint_generation = true;
        bool enable_input_tracking = true;
        
        size_t max_operand_size = 1024;
        size_t max_comparisons_per_location = 1000;
        size_t constraint_cache_size = 10000;
        
        // Optimization parameters
        bool enable_comparison_deduplication = true;
        bool enable_hot_comparison_optimization = true;
        double hot_comparison_threshold = 0.1;
        
        // Filtering parameters
        std::set<std::string> ignored_functions;
        std::set<uint64_t> ignored_addresses;
        size_t min_operand_size = 1;
    };
    
    // Constraint generation result
    struct ConstraintSet {
        std::vector<std::shared_ptr<Constraint>> constraints;
        std::map<size_t, std::vector<uint8_t>> suggested_mutations;
        double constraint_score = 0.0;
        size_t solvable_constraints = 0;
    };

private:
    CmpLogConfig config_;
    
    // Comparison instruction mapping
    std::unordered_map<uint64_t, ComparisonInfo> comparison_map_;
    std::unordered_map<uint64_t, std::queue<ComparisonInfo>> comparison_history_;
    
    // Constraint management
    std::vector<std::shared_ptr<Constraint>> generated_constraints_;
    std::unordered_map<std::string, std::shared_ptr<Constraint>> constraint_cache_;
    
    // Input tracking
    std::vector<uint8_t> current_input_;
    std::unordered_map<size_t, std::set<uint64_t>> input_dependencies_;
    
    // Statistics
    struct Statistics {
        size_t total_comparisons = 0;
        size_t unique_comparisons = 0;
        size_t generated_constraints = 0;
        size_t solvable_constraints = 0;
        size_t successful_mutations = 0;
        double constraint_solving_rate = 0.0;
        // Distribution by comparison type
        std::map<uint64_t, size_t> comparison_type_distribution;
    } stats_;
    
    // Runtime optimizations
    std::set<uint64_t> hot_comparisons_;
    std::unordered_map<uint64_t, size_t> comparison_frequencies_;
    
public:
    CmpLogInstrumentation();
    explicit CmpLogInstrumentation(const CmpLogConfig& config);
    
    AlgorithmInfo getInfo() const override {
        auto info = InstrumentationAlgorithm::getInfo();
        info.name = "cmplog_instrumentation";
        info.description = "Comparison instruction instrumentation for constraint extraction";
        info.provided_info = {InfoType::Constraint, InfoType::Instrumentation};
        return info;
    }
    
    InstrumentationOutput execute(const InstrumentationInput& input, SharedContext& ctx) override;
    
    void updateParameters(const Parameters& params) override;
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
    // Instrumentation API
    void instrumentComparison(uint64_t instruction_addr, ComparisonType type, size_t operand_size);
    void instrumentStringFunction(uint64_t func_addr, const std::string& func_name);
    void instrumentMemoryComparison(uint64_t instruction_addr, size_t size);
    
    // Runtime callback API
    void recordComparison(uint64_t instruction_addr, const void* left, const void* right,
                         size_t size, bool result);
    void recordStringComparison(uint64_t instruction_addr, const char* left, const char* right,
                               bool result);
    void recordIntegerComparison(uint64_t instruction_addr, uint64_t left, uint64_t right,
                                 size_t operand_size, ComparisonType type, bool result);
    
    // Constraint generation
    ConstraintSet generateConstraints(const std::vector<uint8_t>& input);
    std::vector<std::shared_ptr<Constraint>> extractConstraintsFromComparison(
        const ComparisonInfo& comp_info) const;
    
    // Mutation suggestions
    std::vector<std::vector<uint8_t>> generateMutationSuggestions(
        const std::vector<uint8_t>& input, size_t max_suggestions = 10);
    std::vector<uint8_t> mutateBasedOnComparison(const std::vector<uint8_t>& input,
                                                const ComparisonInfo& comp_info) const;
    
    // Query API
    std::vector<ComparisonInfo> getComparisons() const;
    std::vector<ComparisonInfo> getComparisonsForFunction(const std::string& func_name) const;
    ComparisonInfo getComparisonInfo(uint64_t instruction_addr) const;
    
    // Statistics and analysis
    Statistics getStatistics() const { return stats_; }
    std::vector<uint64_t> getHotComparisons() const;
    std::vector<uint64_t> getFailingComparisons() const;
    double getConstraintSolvingRate() const;
    
    // Configuration management
    void setConfig(const CmpLogConfig& config) { config_ = config; }
    CmpLogConfig getConfig() const { return config_; }
    
    // Input association
    void setCurrentInput(const std::vector<uint8_t>& input) { current_input_ = input; }
    void trackInputDependency(size_t input_offset, uint64_t instruction_addr);
    
private:
    // Initialization
    void initializeInstrumentation();
    
    // Comparison analysis
    void analyzeComparison(ComparisonInfo& comp_info);
    ComparisonType detectComparisonType(uint64_t instruction_addr) const;
    bool isInputDerived(const std::vector<uint8_t>& value, size_t& offset) const;
    void publishComparisonData(SharedContext& ctx) const;
    static size_t determineIntegerOperandSize(uint64_t left, uint64_t right, size_t requested_size);
    
    // Constraint generation helpers
    std::shared_ptr<Constraint> createEqualityConstraint(const ComparisonInfo& comp_info) const;
    std::shared_ptr<Constraint> createInequalityConstraint(const ComparisonInfo& comp_info) const;
    std::shared_ptr<Constraint> createStringConstraint(const ComparisonInfo& comp_info) const;
    
    // Mutation strategies
    std::vector<uint8_t> mutateForEquality(const std::vector<uint8_t>& input,
                                          const ComparisonInfo& comp_info) const;
    std::vector<uint8_t> mutateForInequality(const std::vector<uint8_t>& input,
                                            const ComparisonInfo& comp_info) const;
    std::vector<uint8_t> mutateForStringMatch(const std::vector<uint8_t>& input,
                                             const ComparisonInfo& comp_info) const;
    
    // Optimization
    void optimizeInstrumentation();
    void identifyHotComparisons();
    bool shouldInstrument(uint64_t instruction_addr) const;
    
    // Statistics updates
    void updateStatistics();
    void recordConstraintGeneration(const std::shared_ptr<Constraint>& constraint);
    
    // Cache management
    void cacheConstraint(const std::string& key, std::shared_ptr<Constraint> constraint);
    std::shared_ptr<Constraint> getCachedConstraint(const std::string& key) const;
    void cleanupCache();
    
    // Utility functions
    std::string formatOperand(const ComparisonInfo::Operand& operand) const;
    std::string generateConstraintKey(const ComparisonInfo& comp_info) const;
    size_t calculateEditDistance(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) const;
};

// CmpLog constraint solver interface
class CmpLogConstraintSolver {
public:
    virtual ~CmpLogConstraintSolver() = default;
    
    // Solve a constraint
    virtual bool solveConstraint(const Constraint& constraint,
                                std::vector<uint8_t>& solution) = 0;
    
    // Batch solve
    virtual std::vector<std::vector<uint8_t>> solveConstraints(
        const std::vector<std::shared_ptr<Constraint>>& constraints,
        size_t max_solutions = 1) = 0;
    
    // Constraint simplification
    virtual std::shared_ptr<Constraint> simplifyConstraint(
        const std::shared_ptr<Constraint>& constraint) = 0;
    
    // Constraint satisfiability check
    virtual bool isConstraintSatisfiable(const std::shared_ptr<Constraint>& constraint) = 0;
};

// Simple CmpLog constraint solver implementation
class SimpleCmpLogSolver : public CmpLogConstraintSolver {
private:
    size_t max_solve_time_ms_ = 1000;
    size_t max_iterations_ = 10000;
    
public:
    bool solveConstraint(const Constraint& constraint,
                        std::vector<uint8_t>& solution) override;
    
    std::vector<std::vector<uint8_t>> solveConstraints(
        const std::vector<std::shared_ptr<Constraint>>& constraints,
        size_t max_solutions = 1) override;
    
    std::shared_ptr<Constraint> simplifyConstraint(
        const std::shared_ptr<Constraint>& constraint) override;
    
    bool isConstraintSatisfiable(const std::shared_ptr<Constraint>& constraint) override;
    
    // Configuration
    void setMaxSolveTime(size_t time_ms) { max_solve_time_ms_ = time_ms; }
    void setMaxIterations(size_t iterations) { max_iterations_ = iterations; }
    
private:
    // Solving strategies
    bool solveEqualityConstraint(const Constraint& constraint, std::vector<uint8_t>& solution);
    bool solveInequalityConstraint(const Constraint& constraint, std::vector<uint8_t>& solution);
    bool solveStringConstraint(const Constraint& constraint, std::vector<uint8_t>& solution);
    
    // Helper functions
    std::vector<uint8_t> generateRandomSolution(size_t size);
    bool verifySolution(const Constraint& constraint, const std::vector<uint8_t>& solution);
};

// CmpLog analyzer
class CmpLogAnalyzer {
private:
    std::shared_ptr<CmpLogInstrumentation> instrumentation_;
    
public:
    explicit CmpLogAnalyzer(std::shared_ptr<CmpLogInstrumentation> inst);
    
    // Analysis interface
    struct AnalysisResult {
        std::vector<std::string> bottleneck_functions;
        std::map<std::string, size_t> comparison_type_distribution;
        std::vector<uint64_t> most_constraining_comparisons;
        double average_constraint_complexity = 0.0;
        size_t unsolvable_constraints = 0;
    };
    
    AnalysisResult analyzeComparisons();
    
    // Performance analysis
    std::vector<uint64_t> identifyPerformanceBottlenecks();
    std::map<std::string, double> getFunctionConstraintComplexity();
    
    // Visualization data
    std::map<uint64_t, std::vector<size_t>> getComparisonTypeTimeline();
    std::vector<std::pair<uint64_t, size_t>> getComparisonHeatmap();
};

// Concrete constraint class implementations (for CmpLog)
class CmpLogEqualityConstraint : public Constraint {
private:
    uint64_t instruction_address_;
    size_t input_offset_;
    std::vector<uint8_t> target_value_;
    size_t size_;

public:
    CmpLogEqualityConstraint(uint64_t addr, size_t offset, const std::vector<uint8_t>& target, size_t size)
        : Constraint(ConstraintType::ValueConstraint), instruction_address_(addr), 
          input_offset_(offset), target_value_(target), size_(size) {}

    bool isSatisfiable() const override { return true; }
    
    std::optional<std::map<size_t, ConcreteValue>> solve() const override {
        std::map<size_t, ConcreteValue> solution;
        for (size_t i = 0; i < target_value_.size(); ++i) {
            solution[input_offset_ + i] = ConcreteValue(target_value_[i], SymbolicType::UInt8);
        }
        return solution;
    }
    
    std::shared_ptr<Constraint> simplify() const override {
        return std::make_shared<CmpLogEqualityConstraint>(*this);
    }
    
    std::string toSMTLib() const override {
        std::string result = "(assert (= ";
        for (size_t i = 0; i < target_value_.size(); ++i) {
            result += "(select input " + std::to_string(input_offset_ + i) + ") ";
            result += std::to_string(target_value_[i]);
            if (i < target_value_.size() - 1) result += " ";
        }
        result += "))";
        return result;
    }
    
    std::string toString() const override {
        return "CmpLogEquality(@" + std::to_string(instruction_address_) + 
               ", offset=" + std::to_string(input_offset_) + 
               ", size=" + std::to_string(size_) + ")";
    }
    
    // Getters
    uint64_t getInstructionAddress() const { return instruction_address_; }
    size_t getInputOffset() const { return input_offset_; }
    const std::vector<uint8_t>& getTargetValue() const { return target_value_; }
    size_t getSize() const { return size_; }
};

class CmpLogInequalityConstraint : public Constraint {
private:
    uint64_t instruction_address_;
    size_t input_offset_;
    std::vector<uint8_t> target_value_;
    size_t size_;
    bool is_less_than_;

public:
    CmpLogInequalityConstraint(uint64_t addr, size_t offset, const std::vector<uint8_t>& target, 
                              size_t size, bool less_than)
        : Constraint(ConstraintType::RangeConstraint), instruction_address_(addr), 
          input_offset_(offset), target_value_(target), size_(size), is_less_than_(less_than) {}

    bool isSatisfiable() const override { return true; }
    
    std::optional<std::map<size_t, ConcreteValue>> solve() const override {
        std::map<size_t, ConcreteValue> solution;
        // Simple solving: for inequality constraints, slightly adjust the target value.
        for (size_t i = 0; i < target_value_.size(); ++i) {
            uint8_t adjusted = target_value_[i];
            if (is_less_than_ && adjusted > 0) {
                adjusted--;
            } else if (!is_less_than_ && adjusted < 255) {
                adjusted++;
            }
            solution[input_offset_ + i] = ConcreteValue(adjusted, SymbolicType::UInt8);
        }
        return solution;
    }
    
    std::shared_ptr<Constraint> simplify() const override {
        return std::make_shared<CmpLogInequalityConstraint>(*this);
    }
    
    std::string toSMTLib() const override {
        std::string op = is_less_than_ ? "bvult" : "bvugt";
        return "(assert (" + op + " input_val target_val))";
    }
    
    std::string toString() const override {
        std::string op = is_less_than_ ? "<" : ">";
        return "CmpLogInequality(@" + std::to_string(instruction_address_) + 
               ", offset=" + std::to_string(input_offset_) + " " + op + " target)";
    }
};

class CmpLogStringConstraint : public Constraint {
private:
    uint64_t instruction_address_;
    size_t input_offset_;
    std::vector<uint8_t> target_value_;
    size_t size_;

public:
    CmpLogStringConstraint(uint64_t addr, size_t offset, const std::vector<uint8_t>& target, size_t size)
        : Constraint(ConstraintType::ValueConstraint), instruction_address_(addr), 
          input_offset_(offset), target_value_(target), size_(size) {}

    bool isSatisfiable() const override { return true; }
    
    std::optional<std::map<size_t, ConcreteValue>> solve() const override {
        std::map<size_t, ConcreteValue> solution;
        for (size_t i = 0; i < target_value_.size(); ++i) {
            solution[input_offset_ + i] = ConcreteValue(target_value_[i], SymbolicType::UInt8);
        }
        return solution;
    }
    
    std::shared_ptr<Constraint> simplify() const override {
        return std::make_shared<CmpLogStringConstraint>(*this);
    }
    
    std::string toSMTLib() const override {
        return "(assert (str.= input_str target_str))";
    }
    
    std::string toString() const override {
        return "CmpLogString(@" + std::to_string(instruction_address_) + 
               ", offset=" + std::to_string(input_offset_) + 
               ", size=" + std::to_string(size_) + ")";
    }
};

} // namespace triofuzz 
