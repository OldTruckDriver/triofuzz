#pragma once

#include <variant>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <stack>
#include <set>
#include <map>
#include <variant>
#include <memory>
#include <stdexcept>

namespace triofuzz {

// Forward declarations
class SymbolicExpr;
using SymbolicExprPtr = std::shared_ptr<SymbolicExpr>;

// Symbolic value types
enum class SymbolicType {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    Pointer,
    Array,
    Struct
};

// Operator types
enum class OpType {
    // Arithmetic operations
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    
    // Bitwise operations
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    
    // Comparison operations
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    
    // logic operation
    LAnd,
    LOr,
    LNot,
    
    // Memory operations
    Load,
    Store,
    
    // others
    Select,  // Conditional select (? :)
    Concat,  // String/array concatenation
    Extract, // Extract substring/subarray
    Cast     // Type cast
};

// Concrete value
class ConcreteValue {
public:
    using Value = std::variant<
        bool,
        int8_t, int16_t, int32_t, int64_t,
        uint8_t, uint16_t, uint32_t, uint64_t,
        float, double,
        std::vector<uint8_t>  // Array/string
    >;
    
private:
    Value value_;
    SymbolicType type_;
    
public:
    // Default constructor
    ConcreteValue() : value_(0), type_(SymbolicType::Int32) {}
    
    ConcreteValue(Value val, SymbolicType type) : value_(val), type_(type) {}
    
    const Value& getValue() const { return value_; }
    SymbolicType getType() const { return type_; }
    
    // Type conversion
    template<typename T>
    T as() const {
        return std::get<T>(value_);
    }
    
    // Convert to string
    std::string toString() const;
    
    // Arithmetic operations
    ConcreteValue operator+(const ConcreteValue& other) const;
    ConcreteValue operator-(const ConcreteValue& other) const;
    ConcreteValue operator*(const ConcreteValue& other) const;
    ConcreteValue operator/(const ConcreteValue& other) const;
    
    // Comparison operations
    bool operator==(const ConcreteValue& other) const;
    bool operator!=(const ConcreteValue& other) const;
    bool operator<(const ConcreteValue& other) const;
    bool operator<=(const ConcreteValue& other) const;
    bool operator>(const ConcreteValue& other) const;
    bool operator>=(const ConcreteValue& other) const;
};

// Symbolic variable
class SymbolicVariable {
private:
    std::string name_;
    SymbolicType type_;
    size_t id_;
    
    // Variable constraint range
    std::optional<ConcreteValue> min_value_;
    std::optional<ConcreteValue> max_value_;
    
    static size_t next_id_;
    
public:
    SymbolicVariable(const std::string& name, SymbolicType type)
        : name_(name), type_(type), id_(next_id_++) {}
    
    const std::string& getName() const { return name_; }
    SymbolicType getType() const { return type_; }
    size_t getId() const { return id_; }
    
    // Set value-range constraint
    void setRange(const ConcreteValue& min, const ConcreteValue& max) {
        min_value_ = min;
        max_value_ = max;
    }
    
    std::optional<ConcreteValue> getMinValue() const { return min_value_; }
    std::optional<ConcreteValue> getMaxValue() const { return max_value_; }
};

// Symbolic expression
class SymbolicExpr {
public:
    enum class ExprType {
        Constant,
        Variable,
        Operation
    };
    
private:
    ExprType expr_type_;
    
protected:
    SymbolicExpr(ExprType type) : expr_type_(type) {}
    
public:
    virtual ~SymbolicExpr() = default;
    
    ExprType getExprType() const { return expr_type_; }
    virtual SymbolicType getType() const = 0;
    virtual std::string toString() const = 0;
    
    // Evaluate expression
    virtual ConcreteValue evaluate(const std::map<size_t, ConcreteValue>& var_values) const = 0;
    
    // Get free variables
    virtual std::set<size_t> getFreeVariables() const = 0;
    
    // Simplify expression
    virtual SymbolicExprPtr simplify() const = 0;
    
    // Substitute expression
    virtual SymbolicExprPtr substitute(size_t var_id, SymbolicExprPtr expr) const = 0;
};

// Constant expression
class ConstantExpr : public SymbolicExpr {
private:
    ConcreteValue value_;
    
public:
    explicit ConstantExpr(const ConcreteValue& value)
        : SymbolicExpr(ExprType::Constant), value_(value) {}
    
    SymbolicType getType() const override { return value_.getType(); }
    std::string toString() const override { return value_.toString(); }
    
    ConcreteValue evaluate(const std::map<size_t, ConcreteValue>&) const override {
        return value_;
    }
    
    std::set<size_t> getFreeVariables() const override {
        return {};
    }
    
    SymbolicExprPtr simplify() const override {
        return std::make_shared<ConstantExpr>(*this);
    }
    
    SymbolicExprPtr substitute(size_t, SymbolicExprPtr) const override {
        return std::make_shared<ConstantExpr>(*this);
    }
    
    const ConcreteValue& getValue() const { return value_; }
};

// Variable expression
class VariableExpr : public SymbolicExpr {
private:
    std::shared_ptr<SymbolicVariable> variable_;
    
public:
    explicit VariableExpr(std::shared_ptr<SymbolicVariable> var)
        : SymbolicExpr(ExprType::Variable), variable_(var) {}
    
    SymbolicType getType() const override { return variable_->getType(); }
    std::string toString() const override { return variable_->getName(); }
    
    ConcreteValue evaluate(const std::map<size_t, ConcreteValue>& var_values) const override {
        auto it = var_values.find(variable_->getId());
        if (it != var_values.end()) {
            return it->second;
        }
        throw std::runtime_error("Variable not found in evaluation context: " + variable_->getName());
    }
    
    std::set<size_t> getFreeVariables() const override {
        return {variable_->getId()};
    }
    
    SymbolicExprPtr simplify() const override {
        return std::make_shared<VariableExpr>(*this);
    }
    
    SymbolicExprPtr substitute(size_t var_id, SymbolicExprPtr expr) const override {
        if (var_id == variable_->getId()) {
            return expr;
        }
        return std::make_shared<VariableExpr>(*this);
    }
    
    std::shared_ptr<SymbolicVariable> getVariable() const { return variable_; }
};

// Operation expression
class OperationExpr : public SymbolicExpr {
private:
    OpType op_type_;
    std::vector<SymbolicExprPtr> operands_;
    SymbolicType result_type_;
    
public:
    OperationExpr(OpType op, std::vector<SymbolicExprPtr> operands, SymbolicType result_type)
        : SymbolicExpr(ExprType::Operation), op_type_(op), operands_(operands), result_type_(result_type) {}
    
    SymbolicType getType() const override { return result_type_; }
    
    std::string toString() const override {
        std::string result;
        
        switch (op_type_) {
            case OpType::Add:
                result = "(" + operands_[0]->toString() + " + " + operands_[1]->toString() + ")";
                break;
            case OpType::Sub:
                result = "(" + operands_[0]->toString() + " - " + operands_[1]->toString() + ")";
                break;
            case OpType::Eq:
                result = "(" + operands_[0]->toString() + " == " + operands_[1]->toString() + ")";
                break;
            case OpType::Lt:
                result = "(" + operands_[0]->toString() + " < " + operands_[1]->toString() + ")";
                break;
            // ... other operators
            default:
                result = "Op(" + std::to_string(static_cast<int>(op_type_)) + ")";
        }
        
        return result;
    }
    
    ConcreteValue evaluate(const std::map<size_t, ConcreteValue>& var_values) const override;
    std::set<size_t> getFreeVariables() const override;
    SymbolicExprPtr simplify() const override;
    SymbolicExprPtr substitute(size_t var_id, SymbolicExprPtr expr) const override;
    
    OpType getOpType() const { return op_type_; }
    const std::vector<SymbolicExprPtr>& getOperands() const { return operands_; }
};

// Constraint types
enum class ConstraintType {
    PathConstraint,      // Path constraint
    MemoryConstraint,    // Memory constraint
    ValueConstraint,     // Value constraint
    RangeConstraint,     // Range constraint
    RelationConstraint   // Relation constraint
};

// Base constraint class
class Constraint {
private:
    ConstraintType type_;
    bool is_negated_ = false;
    
protected:
    Constraint(ConstraintType type) : type_(type) {}
    
public:
    virtual ~Constraint() = default;
    
    ConstraintType getType() const { return type_; }
    bool isNegated() const { return is_negated_; }
    void negate() { is_negated_ = !is_negated_; }
    
    // Constraint solving
    virtual bool isSatisfiable() const = 0;
    virtual std::optional<std::map<size_t, ConcreteValue>> solve() const = 0;
    
    // Constraint simplification
    virtual std::shared_ptr<Constraint> simplify() const = 0;
    
    // Convert to SMT-LIB
    virtual std::string toSMTLib() const = 0;
    
    // Convert to string
    virtual std::string toString() const = 0;
};

// Path constraint
class PathConstraint : public Constraint {
private:
    SymbolicExprPtr condition_;
    bool taken_branch_;
    uint64_t branch_id_;
    
public:
    PathConstraint(SymbolicExprPtr condition, bool taken, uint64_t branch_id)
        : Constraint(ConstraintType::PathConstraint),
          condition_(condition), taken_branch_(taken), branch_id_(branch_id) {}
    
    bool isSatisfiable() const override;
    std::optional<std::map<size_t, ConcreteValue>> solve() const override;
    std::shared_ptr<Constraint> simplify() const override;
    std::string toSMTLib() const override;
    std::string toString() const override {
        return "Path(" + std::to_string(branch_id_) + "): " + 
               condition_->toString() + " = " + (taken_branch_ ? "true" : "false");
    }
    
    SymbolicExprPtr getCondition() const { return condition_; }
    bool getTakenBranch() const { return taken_branch_; }
    uint64_t getBranchId() const { return branch_id_; }
};

// Value constraint
class ValueConstraint : public Constraint {
private:
    size_t variable_id_;
    ConcreteValue value_;
    
public:
    ValueConstraint(size_t var_id, const ConcreteValue& value)
        : Constraint(ConstraintType::ValueConstraint),
          variable_id_(var_id), value_(value) {}
    
    bool isSatisfiable() const override { return true; }
    
    std::optional<std::map<size_t, ConcreteValue>> solve() const override {
        return std::map<size_t, ConcreteValue>{{variable_id_, value_}};
    }
    
    std::shared_ptr<Constraint> simplify() const override {
        return std::make_shared<ValueConstraint>(*this);
    }
    
    std::string toSMTLib() const override;
    std::string toString() const override {
        return "Value(var" + std::to_string(variable_id_) + " = " + value_.toString() + ")";
    }
};

// Range constraint
class RangeConstraint : public Constraint {
private:
    size_t variable_id_;
    std::optional<ConcreteValue> min_value_;
    std::optional<ConcreteValue> max_value_;
    
public:
    RangeConstraint(size_t var_id, 
                   std::optional<ConcreteValue> min = std::nullopt,
                   std::optional<ConcreteValue> max = std::nullopt)
        : Constraint(ConstraintType::RangeConstraint),
          variable_id_(var_id), min_value_(min), max_value_(max) {}
    
    bool isSatisfiable() const override;
    std::optional<std::map<size_t, ConcreteValue>> solve() const override;
    std::shared_ptr<Constraint> simplify() const override;
    std::string toSMTLib() const override;
    std::string toString() const override;
};

// Relation constraint
class RelationConstraint : public Constraint {
private:
    SymbolicExprPtr left_;
    SymbolicExprPtr right_;
    OpType relation_;  // Eq, Ne, Lt, Le, Gt, Ge
    
public:
    RelationConstraint(SymbolicExprPtr left, OpType relation, SymbolicExprPtr right)
        : Constraint(ConstraintType::RelationConstraint),
          left_(left), right_(right), relation_(relation) {}
    
    bool isSatisfiable() const override;
    std::optional<std::map<size_t, ConcreteValue>> solve() const override;
    std::shared_ptr<Constraint> simplify() const override;
    std::string toSMTLib() const override;
    std::string toString() const override {
        std::string op_str;
        switch (relation_) {
            case OpType::Eq: op_str = "=="; break;
            case OpType::Ne: op_str = "!="; break;
            case OpType::Lt: op_str = "<"; break;
            case OpType::Le: op_str = "<="; break;
            case OpType::Gt: op_str = ">"; break;
            case OpType::Ge: op_str = ">="; break;
            default: op_str = "?";
        }
        return left_->toString() + " " + op_str + " " + right_->toString();
    }
};

// Constraint solver interface
class ConstraintSolver {
public:
    virtual ~ConstraintSolver() = default;
    
    // Add constraint
    virtual void addConstraint(std::shared_ptr<Constraint> constraint) = 0;
    
    // Check satisfiability
    virtual bool checkSat() = 0;
    
    // Get model (variable assignments)
    virtual std::optional<std::map<size_t, ConcreteValue>> getModel() = 0;
    
    // Get UNSAT core
    virtual std::vector<std::shared_ptr<Constraint>> getUnsatCore() = 0;
    
    // Reset solver
    virtual void reset() = 0;
    
    // Push/pop context
    virtual void push() = 0;
    virtual void pop() = 0;
};

// Simple constraint solver implementation (for testing)
class SimpleConstraintSolver : public ConstraintSolver {
private:
    std::vector<std::shared_ptr<Constraint>> constraints_;
    std::stack<size_t> context_stack_;
    
public:
    void addConstraint(std::shared_ptr<Constraint> constraint) override {
        constraints_.push_back(constraint);
    }
    
    bool checkSat() override;
    std::optional<std::map<size_t, ConcreteValue>> getModel() override;
    std::vector<std::shared_ptr<Constraint>> getUnsatCore() override;
    
    void reset() override {
        constraints_.clear();
        while (!context_stack_.empty()) {
            context_stack_.pop();
        }
    }
    
    void push() override {
        context_stack_.push(constraints_.size());
    }
    
    void pop() override {
        if (!context_stack_.empty()) {
            size_t prev_size = context_stack_.top();
            context_stack_.pop();
            constraints_.resize(prev_size);
        }
    }
};

// Helper functions for building expressions
namespace SymExpr {
    inline SymbolicExprPtr constant(const ConcreteValue& value) {
        return std::make_shared<ConstantExpr>(value);
    }
    
    inline SymbolicExprPtr variable(const std::string& name, SymbolicType type) {
        auto var = std::make_shared<SymbolicVariable>(name, type);
        return std::make_shared<VariableExpr>(var);
    }
    
    inline SymbolicExprPtr add(SymbolicExprPtr left, SymbolicExprPtr right) {
        return std::make_shared<OperationExpr>(OpType::Add, 
            std::vector<SymbolicExprPtr>{left, right}, left->getType());
    }
    
    inline SymbolicExprPtr sub(SymbolicExprPtr left, SymbolicExprPtr right) {
        return std::make_shared<OperationExpr>(OpType::Sub,
            std::vector<SymbolicExprPtr>{left, right}, left->getType());
    }
    
    inline SymbolicExprPtr eq(SymbolicExprPtr left, SymbolicExprPtr right) {
        return std::make_shared<OperationExpr>(OpType::Eq,
            std::vector<SymbolicExprPtr>{left, right}, SymbolicType::Bool);
    }
    
    inline SymbolicExprPtr lt(SymbolicExprPtr left, SymbolicExprPtr right) {
        return std::make_shared<OperationExpr>(OpType::Lt,
            std::vector<SymbolicExprPtr>{left, right}, SymbolicType::Bool);
    }
}

} // namespace triofuzz
