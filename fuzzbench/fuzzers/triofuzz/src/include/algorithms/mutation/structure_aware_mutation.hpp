#pragma once

#include "base_mutation.hpp"
#include "../../core/context.hpp"
#include <memory>
#include <vector>
#include <map>
#include <functional>

namespace triofuzz {

// Structured data types
enum class DataStructureType {
    UNKNOWN,
    JSON,
    XML,
    PROTOBUF,
    CUSTOM_BINARY,
    PACKET,
    FILE_FORMAT,
    ASN1,
    TLV,  // Type-Length-Value
    CSV,
    BINARY_TREE
};

// Field information
struct FieldInfo {
    size_t offset;
    size_t length;
    std::string type;  // "int8", "int16", "string", "array", etc.
    std::string name;
    std::vector<uint8_t> valid_values;  // Valid value range
    bool is_length_field = false;
    bool is_checksum = false;
    size_t referenced_field = SIZE_MAX;  // Data field referenced by the length field
};

// Structure template
struct StructureTemplate {
    DataStructureType type;
    std::vector<FieldInfo> fields;
    std::map<std::string, std::function<bool(const std::vector<uint8_t>&)>> validators;
    std::function<void(std::vector<uint8_t>&)> checksum_fixer;
    std::function<void(std::vector<uint8_t>&)> length_fixer;
};

// Structure analyzer
class StructureAnalyzer {
public:
    virtual ~StructureAnalyzer() = default;
    
    // Analyze data structure
    virtual StructureTemplate analyzeStructure(const std::vector<uint8_t>& data) = 0;
    
    // Validate structural integrity
    virtual bool validateStructure(const std::vector<uint8_t>& data, 
                                 const StructureTemplate& tmpl) = 0;
    
    // Fix structure (checksums, length fields, etc.)
    virtual void fixStructure(std::vector<uint8_t>& data, 
                            const StructureTemplate& tmpl) = 0;
};

// Generic structure analyzer implementation
class GenericStructureAnalyzer : public StructureAnalyzer {
private:
    std::map<DataStructureType, std::function<StructureTemplate(const std::vector<uint8_t>&)>> parsers_;
    
public:
    GenericStructureAnalyzer();
    
    StructureTemplate analyzeStructure(const std::vector<uint8_t>& data) override;
    bool validateStructure(const std::vector<uint8_t>& data, 
                         const StructureTemplate& tmpl) override;
    void fixStructure(std::vector<uint8_t>& data, 
                    const StructureTemplate& tmpl) override;

private:
    // Format-specific parsers
    StructureTemplate parseJSON(const std::vector<uint8_t>& data);
    StructureTemplate parseXML(const std::vector<uint8_t>& data);
    StructureTemplate parseProtobuf(const std::vector<uint8_t>& data);
    StructureTemplate parseTLV(const std::vector<uint8_t>& data);
    StructureTemplate parsePacket(const std::vector<uint8_t>& data);
    StructureTemplate parseCustomBinary(const std::vector<uint8_t>& data);
    
    // Generic analysis methods
    DataStructureType detectDataType(const std::vector<uint8_t>& data);
    std::vector<size_t> findLengthFields(const std::vector<uint8_t>& data);
    std::vector<size_t> findChecksumFields(const std::vector<uint8_t>& data);
    std::vector<size_t> findStringFields(const std::vector<uint8_t>& data);
};

// Structure-aware mutation algorithm
class StructureAwareMutation : public MutationAlgorithm {
private:
    std::unique_ptr<StructureAnalyzer> analyzer_;
    std::map<std::vector<uint8_t>, StructureTemplate> structure_cache_;
    
    // Mutation strategy weights
    std::map<std::string, double> mutation_weights_;
    
    // Structure-preservation settings
    bool preserve_structure_ = true;
    bool fix_checksums_ = true;
    bool fix_length_fields_ = true;
    bool respect_field_types_ = true;
    
    // Mutation history
    struct MutationRecord {
        size_t field_index;
        std::string mutation_type;
        bool was_successful;
        double performance_score;
    };
    std::vector<MutationRecord> mutation_history_;
    
public:
    StructureAwareMutation();
    
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;
    
    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "Structure-Aware Mutation";
        info.version = "1.0";
        info.description = "Intelligent mutation that understands and preserves data structure";
        info.type = AlgorithmType::Mutation;
        info.provided_info = {InfoType::Structure, InfoType::Constraint};
        info.required_info = {};
        return info;
    }
    
    void saveState(StateWriter& writer) const override;
    void loadState(StateReader& reader) override;
    
    // Configuration options
    void setPreserveStructure(bool preserve) { preserve_structure_ = preserve; }
    void setFixChecksums(bool fix) { fix_checksums_ = fix; }
    void setFixLengthFields(bool fix) { fix_length_fields_ = fix; }
    void setRespectFieldTypes(bool respect) { respect_field_types_ = respect; }
    
    // Structure-template management
    void addStructureTemplate(const std::vector<uint8_t>& example, 
                            const StructureTemplate& tmpl);
    void clearStructureCache() { structure_cache_.clear(); }

protected:
    void onParametersUpdated() override;

private:
    // Core mutation methods
    void structureAwareMutate(MutationOutput& data, const StructureTemplate& tmpl, SharedContext& ctx);

    // Field-level mutations
    void mutateField(MutationOutput& data, const FieldInfo& field, const StructureTemplate& tmpl);
    void mutateIntegerField(MutationOutput& data, const FieldInfo& field);
    void mutateStringField(MutationOutput& data, const FieldInfo& field);
    void mutateArrayField(MutationOutput& data, const FieldInfo& field);
    void mutateLengthField(MutationOutput& data, const FieldInfo& field, const StructureTemplate& tmpl);

    // Structure-level mutations
    void insertField(MutationOutput& data, const StructureTemplate& tmpl);
    void deleteField(MutationOutput& data, const StructureTemplate& tmpl);
    void reorderFields(MutationOutput& data, const StructureTemplate& tmpl);
    void duplicateField(MutationOutput& data, const StructureTemplate& tmpl);

    // Semantic-aware mutations
    void semanticMutation(MutationOutput& data, const StructureTemplate& tmpl, SharedContext& ctx);
    void constraintBasedMutation(MutationOutput& data, const FieldInfo& field);
    void typeSpecificMutation(MutationOutput& data, const FieldInfo& field);

    // Repair and validation
    void repairStructure(MutationOutput& data, const StructureTemplate& tmpl);
    bool isValidMutation(const MutationOutput& data, const StructureTemplate& tmpl);

    // Smart mutation selection
    std::string selectMutationStrategy(const FieldInfo& field, const SharedContext& ctx);
    void updateMutationWeights(const std::string& strategy, bool success, double score);

    // Helper methods
    StructureTemplate getOrAnalyzeStructure(const std::vector<uint8_t>& data);
    std::vector<uint8_t> extractFieldData(const std::vector<uint8_t>& data, const FieldInfo& field);
    void setFieldData(std::vector<uint8_t>& data, const FieldInfo& field,
                     const std::vector<uint8_t>& field_data);

    // Type-specific mutation functions
    void mutateIPAddress(std::vector<uint8_t>& field_data);
    void mutateTimestamp(std::vector<uint8_t>& field_data);
    void mutateURL(std::vector<uint8_t>& field_data);
    void mutateFilename(std::vector<uint8_t>& field_data);

    // Checksum calculation
    uint32_t calculateCRC32(const std::vector<uint8_t>& data, size_t start, size_t len);
    uint16_t calculateChecksum(const std::vector<uint8_t>& data, size_t start, size_t len);

    // === NEW: Format-specific mutation methods ===
    // PNG format
    void mutatePNG(MutationOutput& data);
    void mutatePNGDimensions(MutationOutput& data);
    void mutatePNGColorInfo(MutationOutput& data);
    void mutatePNGChunks(MutationOutput& data);
    void mutatePNGData(MutationOutput& data);
    void mutatePNGInsertEXIF(MutationOutput& data);  
    void mutatePNGDeletePLTE(MutationOutput& data);  

    // Common image formats 
    void mutateJPEG(MutationOutput& data);
    void mutateGIF(MutationOutput& data);
    void mutateBMP(MutationOutput& data);
    void mutateTGA(MutationOutput& data);
    void mutatePNM(MutationOutput& data);
    void mutatePSD(MutationOutput& data);
    void mutateHDR(MutationOutput& data);
    bool maybeSynthesizeStbImages(MutationOutput& data);

    // TIFF format
    void mutateTIFF(MutationOutput& data);

    // Ogg container
    void mutateOgg(MutationOutput& data);

    // ICC profiles 
    void mutateICC(MutationOutput& data);

    // ASN.1 DER 
    void mutateASN1(MutationOutput& data);

    // DTLS record streams 
    void mutateDTLS(MutationOutput& data);

    // regex harnesses 
    void mutateRE2(MutationOutput& data);

    // Font containers
    void mutateFont(MutationOutput& data);

    // Generic fallback
    void applyGenericMutation(MutationOutput& data);

    // Random number generator
    std::mt19937 random_gen_;
};

} // namespace triofuzz 
