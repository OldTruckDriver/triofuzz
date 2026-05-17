#pragma once

#include "base_mutation.hpp"
#include "runtime_dictionary.hpp"
#include "value_approximation.hpp"
#include <memory>
#include <random>

namespace triofuzz {

/**
 * Runtime dictionary mutation algorithm.
 * Uses a dynamically learned dictionary for smarter mutations.
 */
class RuntimeDictionaryMutation : public MutationAlgorithm {
private:
    std::shared_ptr<RuntimeDictionary> dictionary_;
    bool use_approximation_ = true;
    size_t dict_insert_probability_ = 30;  // 30% probability to insert a dictionary entry
    size_t dict_replace_probability_ = 50; // 50% probability to replace with a dictionary entry
    
public:
    RuntimeDictionaryMutation() {
        // Create the dictionary with default configuration.
        RuntimeDictionary::Config config;
        config.max_dict_size = 2000;
        config.max_entry_len = 256;
        config.auto_extract = true;
        dictionary_ = std::make_shared<RuntimeDictionary>(config);
    }
    
    explicit RuntimeDictionaryMutation(std::shared_ptr<RuntimeDictionary> dict) 
        : dictionary_(dict) {}
    
    AlgorithmInfo getInfo() const override {
        auto info = MutationAlgorithm::getInfo();
        info.name = "runtime_dictionary";
        info.description = "Mutation using runtime-learned dictionary";
        info.version = "1.0";
        return info;
    }
    
    MutationOutput execute(const MutationInput& input, SharedContext& context) override {
        // Learn from comparisons (if available).
        learnFromComparisons(context);
        
        // Get dictionary entries.
        auto dict_entries = dictionary_->getTopEntries(50);
        
        if (dict_entries.empty()) {
            // If the dictionary is empty, return the original input.
            return input;
        }
        
        std::vector<uint8_t> result = input;
        
        // Choose a mutation strategy.
        std::uniform_int_distribution<> strategy_dist(0, 99);
        int strategy = strategy_dist(random_gen_);
        
        if (static_cast<size_t>(strategy) < dict_insert_probability_) {
            // Insert dictionary entry
            result = insertDictionaryEntry(result, dict_entries);
        } else if (static_cast<size_t>(strategy) < dict_insert_probability_ + dict_replace_probability_) {
            // Replace with dictionary entry
            result = replaceDictionaryEntry(result, dict_entries);
        } else {
            // Value-approximation mutation
            if (use_approximation_ && !dict_entries.empty()) {
                result = approximateTowardsDictionary(result, dict_entries);
            }
        }
        
        // Update context stats.
        updateContext(context, result.size() != input.size());
        
        return result;
    }
    
	private:
    /**
     * Learn from comparison information in the context.
     */
    void learnFromComparisons(SharedContext& context) {
        // Check for CmpLog information.
        auto comparisons_opt = context.get<std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>>("cmplog_comparisons");
        if (comparisons_opt.has_value()) {
            for (const auto& [op1, op2] : comparisons_opt.value()) {
                dictionary_->extractFromComparison(op1, op2);
            }
        }
        
        // Check for magic-byte information.
        auto magic_opt = context.get<std::vector<uint8_t>>("magic_bytes");
        if (magic_opt.has_value()) {
            const auto& magic = magic_opt.value();
            dictionary_->extractFromMemory(magic.data(), magic.size());
        }
        
        // Check for integer constants.
        auto constants_opt = context.get<std::vector<int64_t>>("integer_constants");
        if (constants_opt.has_value()) {
            for (auto val : constants_opt.value()) {
                dictionary_->extractInteger(val);
            }
        }
    }
    
    /**
     * Insert a dictionary entry.
     */
    std::vector<uint8_t> insertDictionaryEntry(
        const std::vector<uint8_t>& input,
        const std::vector<std::vector<uint8_t>>& entries) {
        
        if (entries.empty()) return input;
        
        // Randomly select an entry.
        std::uniform_int_distribution<> entry_dist(0, entries.size() - 1);
        const auto& entry = entries[entry_dist(random_gen_)];
        
        // Randomly select insertion position.
        std::uniform_int_distribution<> pos_dist(0, input.size());
        size_t insert_pos = pos_dist(random_gen_);
        
        std::vector<uint8_t> result;
        result.reserve(input.size() + entry.size());
        
        // Insert
        result.insert(result.end(), input.begin(), input.begin() + insert_pos);
        result.insert(result.end(), entry.begin(), entry.end());
        result.insert(result.end(), input.begin() + insert_pos, input.end());
        
        return result;
    }
    
    /**
     * Replace with a dictionary entry.
     */
    std::vector<uint8_t> replaceDictionaryEntry(
        const std::vector<uint8_t>& input,
        const std::vector<std::vector<uint8_t>>& entries) {
        
        if (entries.empty() || input.empty()) return input;
        
        // Randomly select an entry.
        std::uniform_int_distribution<> entry_dist(0, entries.size() - 1);
        const auto& entry = entries[entry_dist(random_gen_)];
        
        // Randomly select replacement position.
        std::uniform_int_distribution<> pos_dist(0, 
            input.size() > entry.size() ? input.size() - entry.size() : 0);
        size_t replace_pos = pos_dist(random_gen_);
        
        std::vector<uint8_t> result = input;
        
        // Replace
        size_t replace_len = std::min(entry.size(), result.size() - replace_pos);
        std::copy(entry.begin(), entry.begin() + replace_len, 
                 result.begin() + replace_pos);
        
        return result;
    }
    
    /**
     * Approximate towards a dictionary value.
     */
    std::vector<uint8_t> approximateTowardsDictionary(
        const std::vector<uint8_t>& input,
        const std::vector<std::vector<uint8_t>>& entries) {
        
        if (entries.empty() || input.empty()) return input;
        
        // Randomly select an entry as the target.
        std::uniform_int_distribution<> entry_dist(0, entries.size() - 1);
        const auto& target = entries[entry_dist(random_gen_)];
        
        // Randomly select approximation offset.
        std::uniform_int_distribution<> pos_dist(0, 
            input.size() > target.size() ? input.size() - target.size() : 0);
        size_t offset = pos_dist(random_gen_);
        
        // Use smart approximation
        return ValueApproximation::smartApproximation(input, target, offset);
    }
    
    /**
     * Update context statistics.
     */
    void updateContext(SharedContext& context, bool size_changed) {
        // Update mutation stats.
        auto stats_opt = context.get<std::map<std::string, size_t>>("mutation_stats");
        if (stats_opt.has_value()) {
            auto stats = stats_opt.value();
            stats["runtime_dictionary_mutations"]++;
            if (size_changed) {
                stats["size_changing_mutations"]++;
            }
            context.set("mutation_stats", stats);
        } else {
            // Create a new stats map.
            std::map<std::string, size_t> stats;
            stats["runtime_dictionary_mutations"] = 1;
            if (size_changed) {
                stats["size_changing_mutations"] = 1;
            }
            context.set("mutation_stats", stats);
        }
        
        // Record dictionary size.
        context.set("runtime_dict_size", dictionary_->size());
    }
    
public:
    // Get dictionary handle (for external updates).
    std::shared_ptr<RuntimeDictionary> getDictionary() { return dictionary_; }
    
    // Configuration
    void setUseApproximation(bool use) { use_approximation_ = use; }
    void setInsertProbability(size_t prob) { dict_insert_probability_ = prob; }
    void setReplaceProbability(size_t prob) { dict_replace_probability_ = prob; }
};

} // namespace triofuzz
