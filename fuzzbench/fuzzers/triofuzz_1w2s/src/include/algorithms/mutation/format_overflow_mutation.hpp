#pragma once

#include "base_mutation.hpp"
#include <vector>
#include <random>

namespace triofuzz {


class FormatOverflowMutation : public MutationAlgorithm {
public:
    FormatOverflowMutation();

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info = MutationAlgorithm::getInfo();
        info.name = "format_overflow";
        info.description = "Format-aware integer overflow mutation for image formats";
        return info;
    }

    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override;

private:
	mutable std::mt19937 rng_;

    // File format detection
    enum class FileFormat {
        PNG, TIFF, JPEG, BMP, GIF, UNKNOWN
    };

    FileFormat detectFormat(const std::vector<uint8_t>& input) const;

    // Format-specific overflow mutations
    MutationOutput mutatePNGOverflow(const MutationInput& input) const;
    MutationOutput mutateTIFFOverflow(const MutationInput& input) const;
    MutationOutput mutateGenericOverflow(const MutationInput& input) const;

    // PNG helpers
    void writeU32BE(uint8_t* data, uint32_t value) const;
    uint32_t readU32BE(const uint8_t* data) const;
    static uint32_t calculateCRC32(const uint8_t* data, size_t len);
    void fixPNGChunkCRC(std::vector<uint8_t>& data, size_t chunk_offset) const;
};

} // namespace triofuzz
