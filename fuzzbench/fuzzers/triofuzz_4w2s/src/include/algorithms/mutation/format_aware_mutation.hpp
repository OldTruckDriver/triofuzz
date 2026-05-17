#pragma once

#include "base_mutation.hpp"
#include <vector>
#include <random>

namespace triofuzz {

class FormatAwareMutation : public MutationAlgorithm {
private:
    // File format detection
    enum class FileFormat {
        OGG, VORBIS, PNG, JPEG, BMP, GIF, XML, JSON, YAML, PDF, WOFF2, WOFF, SQL, UNKNOWN
    };

    FileFormat detectFormat(const std::vector<uint8_t>& input) const;

    // Format-specific mutations
    std::vector<uint8_t> mutateOGG(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateVORBIS(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutatePNG(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateJPEG(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateXML(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateJSON(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateFont(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateSQL(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> mutateGeneric(const std::vector<uint8_t>& input) const;

    // Helper functions
    uint32_t readUint32BE(const uint8_t* data) const;
    void writeUint32BE(uint8_t* data, uint32_t value) const;

public:
    FormatAwareMutation() = default;

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info = MutationAlgorithm::getInfo();
        info.name = "format_aware";
        info.description = "Format-aware mutations for structured files";
        return info;
    }

    MutationOutput execute(
        const MutationInput& input,
        SharedContext& context
    ) override;
};

} // namespace triofuzz
