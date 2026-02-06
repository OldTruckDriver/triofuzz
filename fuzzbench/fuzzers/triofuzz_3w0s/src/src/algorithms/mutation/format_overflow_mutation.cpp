#include "../../../include/algorithms/mutation/format_overflow_mutation.hpp"
#include <algorithm>
#include <cstring>

namespace triofuzz {

FormatOverflowMutation::FormatOverflowMutation()
    : rng_(std::random_device{}()) {
}

FormatOverflowMutation::FileFormat FormatOverflowMutation::detectFormat(
    const std::vector<uint8_t>& input) const {
    if (input.size() < 8) return FileFormat::UNKNOWN;

    if (input[0] == 0x89 && input[1] == 0x50 && input[2] == 0x4E && input[3] == 0x47 &&
        input[4] == 0x0D && input[5] == 0x0A && input[6] == 0x1A && input[7] == 0x0A) {
        return FileFormat::PNG;
    }

    if ((input[0] == 0x49 && input[1] == 0x49 && input[2] == 0x2A && input[3] == 0x00) ||
        (input[0] == 0x4D && input[1] == 0x4D && input[2] == 0x00 && input[3] == 0x2A)) {
        return FileFormat::TIFF;
    }

    if (input[0] == 0xFF && input[1] == 0xD8 && input[2] == 0xFF) {
        return FileFormat::JPEG;
    }

    if (input[0] == 0x42 && input[1] == 0x4D) {
        return FileFormat::BMP;
    }

    if (input[0] == 0x47 && input[1] == 0x49 && input[2] == 0x46) {
        return FileFormat::GIF;
    }

    return FileFormat::UNKNOWN;
}

void FormatOverflowMutation::writeU32BE(uint8_t* data, uint32_t value) const {
    data[0] = (value >> 24) & 0xFF;
    data[1] = (value >> 16) & 0xFF;
    data[2] = (value >> 8) & 0xFF;
    data[3] = value & 0xFF;
}

uint32_t FormatOverflowMutation::readU32BE(const uint8_t* data) const {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

uint32_t FormatOverflowMutation::calculateCRC32(const uint8_t* data, size_t len) {
    static uint32_t crc_table[256];
    static bool table_computed = false;

    if (!table_computed) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++) {
                if (c & 1)
                    c = 0xEDB88320UL ^ (c >> 1);
                else
                    c = c >> 1;
            }
            crc_table[n] = c;
        }
        table_computed = true;
    }

    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFUL;
}

void FormatOverflowMutation::fixPNGChunkCRC(std::vector<uint8_t>& data, size_t chunk_offset) const {
    if (chunk_offset + 8 > data.size()) return;

    uint32_t length = readU32BE(&data[chunk_offset]);
    if (chunk_offset + 8 + length + 4 > data.size()) return;

    uint32_t crc = calculateCRC32(&data[chunk_offset + 4], 4 + length);

    size_t crc_offset = chunk_offset + 8 + length;
    writeU32BE(&data[crc_offset], crc);
}

MutationOutput FormatOverflowMutation::execute(const MutationInput& input, SharedContext& ctx) {
    if (input.empty()) return input;

    FileFormat format = detectFormat(input);

    switch (format) {
        case FileFormat::PNG:
            return mutatePNGOverflow(input);
        case FileFormat::TIFF:
            return mutateTIFFOverflow(input);
        default:
            return mutateGenericOverflow(input);
    }
}

MutationOutput FormatOverflowMutation::mutatePNGOverflow(const MutationInput& input) const {
    MutationOutput result = input;

    if (result.size() < 33) return result;

    std::uniform_int_distribution<int> strategy_dist(0, 100);
    int strategy = strategy_dist(rng_);

    uint32_t new_width, new_height;
    bool modify_dimensions = true;

    if (strategy < 20) {
        uint64_t target = 0xFFFFFFFFULL;
        new_width = static_cast<uint32_t>(target / 4);
        std::uniform_int_distribution<int> adj(-10, 10);
        new_width = static_cast<uint32_t>(static_cast<int64_t>(new_width) + adj(rng_));
        new_height = 1;

    } else if (strategy < 40) {
        uint64_t target = 0x100000000ULL;
        new_width = static_cast<uint32_t>(target / 4);
        std::uniform_int_distribution<int> adj(-5, 5);
        new_width = static_cast<uint32_t>(static_cast<int64_t>(new_width) + adj(rng_));
        new_height = 1;

    } else if (strategy < 55) {
        uint64_t target = 0x100000000ULL;
        new_width = static_cast<uint32_t>(target / 4);
        std::uniform_int_distribution<int> adj(-10, 10);
        new_width = static_cast<uint32_t>(static_cast<int64_t>(new_width) + adj(rng_));
        new_height = 1;

    } else if (strategy < 70) {
        static const uint32_t overflow_values[] = {
            0x40000000, 0x40000001, 0x3FFFFFFF, 0x3FFFFFFE,
            0x55555555, 0x55555556,
            0x80000000, 0x7FFFFFFF, 0xFFFFFFFF,
            0x20000000, 0x10000000, 0x08000000,
        };
        std::uniform_int_distribution<size_t> idx(0, sizeof(overflow_values)/sizeof(overflow_values[0]) - 1);
        new_width = overflow_values[idx(rng_)];
        new_height = 1;

    } else if (strategy < 82) {
        if (result.size() >= 26) {
            std::uniform_int_distribution<int> color_type_dist(0, 4);
            int ct = color_type_dist(rng_);
            uint8_t color_types[] = {0, 2, 3, 4, 6};
            result[25] = color_types[ct];

            if (result[25] == 3) {
                uint8_t palette_depths[] = {1, 2, 4, 8};
                std::uniform_int_distribution<size_t> depth_idx(0, 3);
                result[24] = palette_depths[depth_idx(rng_)];
            }

            fixPNGChunkCRC(result, 8);
        }
        modify_dimensions = false;

    } else if (strategy < 92) {
        if (result.size() >= 33) {
            std::vector<uint8_t> exif_chunk;
            uint32_t exif_len = 8;

            exif_chunk.push_back((exif_len >> 24) & 0xFF);
            exif_chunk.push_back((exif_len >> 16) & 0xFF);
            exif_chunk.push_back((exif_len >> 8) & 0xFF);
            exif_chunk.push_back(exif_len & 0xFF);

            exif_chunk.push_back('e'); exif_chunk.push_back('X');
            exif_chunk.push_back('I'); exif_chunk.push_back('f');

            exif_chunk.push_back('E'); exif_chunk.push_back('x');
            exif_chunk.push_back('i'); exif_chunk.push_back('f');
            exif_chunk.push_back(0); exif_chunk.push_back(0);
            exif_chunk.push_back('I'); exif_chunk.push_back('I');

            exif_chunk.push_back(0); exif_chunk.push_back(0);
            exif_chunk.push_back(0); exif_chunk.push_back(0);

            result.insert(result.begin() + 33, exif_chunk.begin(), exif_chunk.end());

            uint32_t crc = calculateCRC32(&result[33 + 4], 4 + exif_len);
            writeU32BE(&result[33 + 8 + exif_len], crc);
        }
        modify_dimensions = false;

    } else {
        if (result.size() > 29) {
            std::uniform_int_distribution<size_t> pos_dist(16, 28);
            size_t pos = pos_dist(rng_);
            result[pos] ^= (1 << (rng_() % 8));
            fixPNGChunkCRC(result, 8);
        }
        modify_dimensions = false;
    }

    if (modify_dimensions && result.size() >= 33) {
        writeU32BE(result.data() + 16, new_width);
        writeU32BE(result.data() + 20, new_height);
        fixPNGChunkCRC(result, 8);
    }

    return result;
}

MutationOutput FormatOverflowMutation::mutateTIFFOverflow(const MutationInput& input) const {
    MutationOutput result = input;

    if (result.size() < 16) return result;

    bool is_little_endian = (result[0] == 0x49 && result[1] == 0x49);

    std::uniform_int_distribution<int> strategy_dist(0, 3);
    int strategy = strategy_dist(rng_);

    static const uint32_t overflow_values[] = {
        0x40000000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0x3FFFFFFF, 0x55555555, 0x20000000, 0x10000000
    };
    std::uniform_int_distribution<size_t> idx(0, sizeof(overflow_values)/sizeof(overflow_values[0]) - 1);
    uint32_t overflow_val = overflow_values[idx(rng_)];

    if (result.size() >= 20 && strategy < 2) {
        if (is_little_endian) {
            result[16] = overflow_val & 0xFF;
            result[17] = (overflow_val >> 8) & 0xFF;
            result[18] = (overflow_val >> 16) & 0xFF;
            result[19] = (overflow_val >> 24) & 0xFF;
        } else {
            result[16] = (overflow_val >> 24) & 0xFF;
            result[17] = (overflow_val >> 16) & 0xFF;
            result[18] = (overflow_val >> 8) & 0xFF;
            result[19] = overflow_val & 0xFF;
        }
    }

    return result;
}

MutationOutput FormatOverflowMutation::mutateGenericOverflow(const MutationInput& input) const {
    MutationOutput result = input;

    if (result.size() < 8) return result;

    static const uint32_t overflow_values[] = {
        0x40000000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0x3FFFFFFF, 0x100000000ULL - 1, 0x7FFFFFFE, 0x3FFFFFFE
    };

    std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 4);
    std::uniform_int_distribution<size_t> val_idx(0, sizeof(overflow_values)/sizeof(overflow_values[0]) - 1);

    size_t pos = pos_dist(rng_);
    uint32_t val = overflow_values[val_idx(rng_)];

    result[pos] = (val >> 24) & 0xFF;
    result[pos + 1] = (val >> 16) & 0xFF;
    result[pos + 2] = (val >> 8) & 0xFF;
    result[pos + 3] = val & 0xFF;

    return result;
}

} // namespace triofuzz
