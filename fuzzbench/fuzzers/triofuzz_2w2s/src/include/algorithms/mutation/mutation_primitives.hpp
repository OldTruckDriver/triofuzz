#pragma once

#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <cstring>

namespace triofuzz {
namespace primitives {

/**
 * Mutation Primitives - high-performance, zero-dependency primitive mutation operations
 *
 * Design principles:
 * 1. All operations are inline with zero function-call overhead.
 * 2. Stateless, dependency-free, fully decoupled.
 * 3. Operate directly on data with no extra allocations.
 * 4. Optimized with templates and constexpr.
 */

// ============================================================================
// Bit-level Operations
// ============================================================================

/**
 * Flip a single bit.
 * @param data Data buffer (by reference).
 * @param byte_pos Byte position.
 * @param bit_pos Bit position (0-7).
 */
inline void flipBit(std::vector<uint8_t>& data, size_t byte_pos, int bit_pos) {
    if (byte_pos < data.size() && bit_pos >= 0 && bit_pos < 8) {
        data[byte_pos] ^= (1 << bit_pos);
    }
}

/**
 * Flip a contiguous range of bits.
 * @param data Data buffer (by reference).
 * @param byte_pos Byte position.
 * @param bit_pos Start bit position.
 * @param bit_count Number of bits to flip (1-8).
 */
inline void flipBits(std::vector<uint8_t>& data, size_t byte_pos, int bit_pos, int bit_count) {
    if (byte_pos < data.size() && bit_pos >= 0 && bit_count > 0) {
        int max_bits = 8 - bit_pos;
        bit_count = std::min(bit_count, max_bits);
        uint8_t mask = ((1 << bit_count) - 1) << bit_pos;
        data[byte_pos] ^= mask;
    }
}

/**
 * Flip a whole byte.
 */
inline void flipByte(std::vector<uint8_t>& data, size_t byte_pos) {
    if (byte_pos < data.size()) {
        data[byte_pos] ^= 0xFF;
    }
}

/**
 * Flip a random bit.
 */
template<typename RNG>
inline void flipRandomBit(std::vector<uint8_t>& data, RNG& rng) {
    if (data.empty()) return;
    std::uniform_int_distribution<size_t> byte_dist(0, data.size() - 1);
    std::uniform_int_distribution<int> bit_dist(0, 7);
    flipBit(data, byte_dist(rng), bit_dist(rng));
}

// ============================================================================
// Byte-level Operations
// ============================================================================

/**
 * 8-bit arithmetic operation.
 */
inline void arithmetic8(std::vector<uint8_t>& data, size_t pos, int delta) {
    if (pos < data.size()) {
        data[pos] = static_cast<uint8_t>(static_cast<int>(data[pos]) + delta);
    }
}

/**
 * 16-bit arithmetic operation (little endian).
 */
inline void arithmetic16LE(std::vector<uint8_t>& data, size_t pos, int delta) {
    if (pos + 1 < data.size()) {
        uint16_t val = data[pos] | (data[pos + 1] << 8);
        val = static_cast<uint16_t>(static_cast<int>(val) + delta);
        data[pos] = static_cast<uint8_t>(val & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    }
}

/**
 * 16-bit arithmetic operation (big endian).
 */
inline void arithmetic16BE(std::vector<uint8_t>& data, size_t pos, int delta) {
    if (pos + 1 < data.size()) {
        uint16_t val = (data[pos] << 8) | data[pos + 1];
        val = static_cast<uint16_t>(static_cast<int>(val) + delta);
        data[pos] = static_cast<uint8_t>((val >> 8) & 0xFF);
        data[pos + 1] = static_cast<uint8_t>(val & 0xFF);
    }
}

/**
 * 32-bit arithmetic operation (little endian).
 */
inline void arithmetic32LE(std::vector<uint8_t>& data, size_t pos, int delta) {
    if (pos + 3 < data.size()) {
        uint32_t val = static_cast<uint32_t>(data[pos]) |
                      (static_cast<uint32_t>(data[pos + 1]) << 8) |
                      (static_cast<uint32_t>(data[pos + 2]) << 16) |
                      (static_cast<uint32_t>(data[pos + 3]) << 24);
        val = static_cast<uint32_t>(static_cast<int64_t>(val) + delta);
        data[pos] = static_cast<uint8_t>(val & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        data[pos + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        data[pos + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    }
}

/**
 * 32-bit arithmetic operation (big endian).
 */
inline void arithmetic32BE(std::vector<uint8_t>& data, size_t pos, int delta) {
    if (pos + 3 < data.size()) {
        uint32_t val = (static_cast<uint32_t>(data[pos]) << 24) |
                      (static_cast<uint32_t>(data[pos + 1]) << 16) |
                      (static_cast<uint32_t>(data[pos + 2]) << 8) |
                      static_cast<uint32_t>(data[pos + 3]);
        val = static_cast<uint32_t>(static_cast<int64_t>(val) + delta);
        data[pos] = static_cast<uint8_t>((val >> 24) & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
        data[pos + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
        data[pos + 3] = static_cast<uint8_t>(val & 0xFF);
    }
}

// ============================================================================
// Interesting Values
// ============================================================================

/**
 * Set an 8-bit interesting value.
 */
inline void setInteresting8(std::vector<uint8_t>& data, size_t pos, uint8_t value) {
    if (pos < data.size()) {
        data[pos] = value;
    }
}

/**
 * Set a 16-bit interesting value (little endian).
 */
inline void setInteresting16LE(std::vector<uint8_t>& data, size_t pos, uint16_t value) {
    if (pos + 1 < data.size()) {
        data[pos] = static_cast<uint8_t>(value & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    }
}

/**
 * Set a 16-bit interesting value (big endian).
 */
inline void setInteresting16BE(std::vector<uint8_t>& data, size_t pos, uint16_t value) {
    if (pos + 1 < data.size()) {
        data[pos] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[pos + 1] = static_cast<uint8_t>(value & 0xFF);
    }
}

/**
 * Set a 32-bit interesting value (little endian).
 */
inline void setInteresting32LE(std::vector<uint8_t>& data, size_t pos, uint32_t value) {
    if (pos + 3 < data.size()) {
        data[pos] = static_cast<uint8_t>(value & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[pos + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[pos + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    }
}

/**
 * Set a 32-bit interesting value (big endian).
 */
inline void setInteresting32BE(std::vector<uint8_t>& data, size_t pos, uint32_t value) {
    if (pos + 3 < data.size()) {
        data[pos] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[pos + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[pos + 3] = static_cast<uint8_t>(value & 0xFF);
    }
}

// ============================================================================
// Block Operations
// ============================================================================

/**
 * Delete a byte block.
 * @param data Data buffer (by reference).
 * @param pos Start position.
 * @param len Delete length.
 */
inline void deleteBytes(std::vector<uint8_t>& data, size_t pos, size_t len) {
    if (pos < data.size() && len > 0) {
        size_t actual_len = std::min(len, data.size() - pos);
        data.erase(data.begin() + pos, data.begin() + pos + actual_len);
    }
}

/**
 * Insert random bytes.
 * @param data Data buffer (by reference).
 * @param pos Insertion position.
 * @param len Insertion length.
 * @param rng Random number generator.
 */
template<typename RNG>
inline void insertRandomBytes(std::vector<uint8_t>& data, size_t pos, size_t len, RNG& rng) {
    if (pos <= data.size() && len > 0) {
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        std::vector<uint8_t> new_bytes(len);
        for (auto& byte : new_bytes) {
            byte = byte_dist(rng);
        }
        data.insert(data.begin() + pos, new_bytes.begin(), new_bytes.end());
    }
}

/**
 * Insert a specific byte sequence.
 */
inline void insertBytes(std::vector<uint8_t>& data, size_t pos, const std::vector<uint8_t>& bytes) {
    if (pos <= data.size() && !bytes.empty()) {
        data.insert(data.begin() + pos, bytes.begin(), bytes.end());
    }
}

/**
 * Insert a single byte.
 */
inline void insertByte(std::vector<uint8_t>& data, size_t pos, uint8_t byte) {
    if (pos <= data.size()) {
        data.insert(data.begin() + pos, byte);
    }
}

/**
 * Duplicate and insert a byte block.
 */
inline void duplicateBytes(std::vector<uint8_t>& data, size_t src_pos, size_t len, size_t dst_pos) {
    if (src_pos < data.size() && len > 0) {
        size_t actual_len = std::min(len, data.size() - src_pos);
        std::vector<uint8_t> copied(data.begin() + src_pos, data.begin() + src_pos + actual_len);
        if (dst_pos <= data.size()) {
            data.insert(data.begin() + dst_pos, copied.begin(), copied.end());
        }
    }
}

/**
 * Overwrite a byte block.
 */
inline void overwriteBytes(std::vector<uint8_t>& data, size_t pos, const std::vector<uint8_t>& bytes) {
    if (pos < data.size() && !bytes.empty()) {
        size_t len = std::min(bytes.size(), data.size() - pos);
        std::copy(bytes.begin(), bytes.begin() + len, data.begin() + pos);
    }
}

/**
 * Shuffle a byte block.
 */
template<typename RNG>
inline void shuffleBytes(std::vector<uint8_t>& data, size_t pos, size_t len, RNG& rng) {
    if (pos < data.size() && len > 0) {
        size_t actual_len = std::min(len, data.size() - pos);
        if (actual_len > 1) {
            std::shuffle(data.begin() + pos, data.begin() + pos + actual_len, rng);
        }
    }
}

// ============================================================================
// Crossover/Splice Operations
// ============================================================================

/**
 * Single-point crossover: split at a position and replace.
 */
inline void singlePointCrossover(std::vector<uint8_t>& data, size_t split_pos,
                                  const std::vector<uint8_t>& source, size_t source_start) {
    if (split_pos < data.size() && source_start < source.size()) {
        size_t copy_len = source.size() - source_start;
        data.resize(split_pos);
        data.insert(data.end(), source.begin() + source_start, source.end());
    }
}

/**
 * Block-replace crossover: replace part of data with a slice of source.
 */
inline void blockReplaceCrossover(std::vector<uint8_t>& data, size_t data_pos, size_t data_len,
                                   const std::vector<uint8_t>& source, size_t source_pos, size_t source_len) {
    if (data_pos < data.size() && source_pos < source.size()) {
        // Remove the original block
        size_t actual_data_len = std::min(data_len, data.size() - data_pos);
        data.erase(data.begin() + data_pos, data.begin() + data_pos + actual_data_len);

        // Insert the new block
        size_t actual_source_len = std::min(source_len, source.size() - source_pos);
        data.insert(data.begin() + data_pos,
                   source.begin() + source_pos,
                   source.begin() + source_pos + actual_source_len);
    }
}

/**
 * Block-insert crossover: insert a block from source into data.
 */
inline void blockInsertCrossover(std::vector<uint8_t>& data, size_t insert_pos,
                                  const std::vector<uint8_t>& source, size_t source_pos, size_t source_len) {
    if (insert_pos <= data.size() && source_pos < source.size()) {
        size_t actual_len = std::min(source_len, source.size() - source_pos);
        data.insert(data.begin() + insert_pos,
                   source.begin() + source_pos,
                   source.begin() + source_pos + actual_len);
    }
}

// ============================================================================
// Dictionary Operations
// ============================================================================

/**
 * Replace at a random position with a dictionary entry.
 */
template<typename RNG>
inline void replaceDictionary(std::vector<uint8_t>& data, const std::vector<uint8_t>& dict_entry, RNG& rng) {
    if (!data.empty() && !dict_entry.empty()) {
        std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);
        size_t pos = pos_dist(rng);
        size_t len = std::min(dict_entry.size(), data.size() - pos);
        std::copy(dict_entry.begin(), dict_entry.begin() + len, data.begin() + pos);
    }
}

/**
 * Insert a dictionary entry at a random position.
 */
template<typename RNG>
inline void insertDictionary(std::vector<uint8_t>& data, const std::vector<uint8_t>& dict_entry, RNG& rng) {
    if (!dict_entry.empty()) {
        std::uniform_int_distribution<size_t> pos_dist(0, data.size());
        size_t pos = pos_dist(rng);
        data.insert(data.begin() + pos, dict_entry.begin(), dict_entry.end());
    }
}

// ============================================================================
// Special Operations
// ============================================================================

/**
 * XOR operation.
 */
inline void xorByte(std::vector<uint8_t>& data, size_t pos, uint8_t value) {
    if (pos < data.size()) {
        data[pos] ^= value;
    }
}

/**
 * XOR block operation.
 */
inline void xorBytes(std::vector<uint8_t>& data, size_t pos, size_t len, uint8_t value) {
    if (pos < data.size()) {
        size_t actual_len = std::min(len, data.size() - pos);
        for (size_t i = 0; i < actual_len; ++i) {
            data[pos + i] ^= value;
        }
    }
}

/**
 * Left shift operation.
 */
inline void shiftLeft(std::vector<uint8_t>& data, size_t pos, int bits) {
    if (pos < data.size() && bits > 0 && bits < 8) {
        data[pos] = static_cast<uint8_t>((data[pos] << bits) & 0xFF);
    }
}

/**
 * Right shift operation.
 */
inline void shiftRight(std::vector<uint8_t>& data, size_t pos, int bits) {
    if (pos < data.size() && bits > 0 && bits < 8) {
        data[pos] = data[pos] >> bits;
    }
}

/**
 * Two's-complement negation.
 */
inline void negate(std::vector<uint8_t>& data, size_t pos) {
    if (pos < data.size()) {
        data[pos] = static_cast<uint8_t>((~data[pos] + 1) & 0xFF);
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Randomly select a position (with weight support).
 */
template<typename RNG>
inline size_t selectRandomPosition(size_t max_pos, RNG& rng) {
    if (max_pos == 0) return 0;
    std::uniform_int_distribution<size_t> dist(0, max_pos - 1);
    return dist(rng);
}

/**
 * Randomly select a position (weighted).
 */
template<typename RNG>
inline size_t selectWeightedPosition(size_t max_pos, const std::vector<double>& weights, RNG& rng) {
    if (max_pos == 0 || weights.empty()) return 0;
    if (weights.size() < max_pos) return selectRandomPosition(max_pos, rng);

    std::discrete_distribution<size_t> dist(weights.begin(), weights.begin() + max_pos);
    return dist(rng);
}

/**
 * Compute a safe delete length.
 */
inline size_t calculateSafeDeleteLength(size_t data_size, size_t pos, size_t max_len, size_t min_remaining = 1) {
    if (pos >= data_size || data_size <= min_remaining) return 0;
    size_t available = data_size - pos;
    size_t max_delete = (data_size > min_remaining) ? (data_size - min_remaining) : 0;
    return std::min({max_len, available, max_delete});
}

/**
 * Compute a safe insert length.
 */
inline size_t calculateSafeInsertLength(size_t data_size, size_t max_len, size_t max_total_size = 1048576) {
    if (data_size >= max_total_size) return 0;
    return std::min(max_len, max_total_size - data_size);
}

} // namespace primitives
} // namespace triofuzz
