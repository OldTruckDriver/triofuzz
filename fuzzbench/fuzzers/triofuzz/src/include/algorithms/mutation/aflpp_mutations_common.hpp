#pragma once

/**
 * @file aflpp_mutations_common.hpp
 * @brief AFL++ compatible mutation constants and utilities
 *
 * This file provides common constants, interesting values, and utility functions
 * that match AFL++ exactly for fair comparison experiments.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <random>
#include <algorithm>

namespace triofuzz {
namespace aflpp {

// AFL++ ARITH_MAX = 35
constexpr int32_t ARITH_MAX = 35;

// AFL++ interesting values - exactly as defined in AFL++
constexpr int8_t interesting_8[] = {
    -128,    // INTERESTING_8
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127
};
constexpr size_t interesting_8_count = sizeof(interesting_8) / sizeof(interesting_8[0]);

constexpr int16_t interesting_16[] = {
    -128,    // INTERESTING_8
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    -32768,  // INTERESTING_16
    -129,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767
};
constexpr size_t interesting_16_count = sizeof(interesting_16) / sizeof(interesting_16[0]);

constexpr int32_t interesting_32[] = {
    -128,    // INTERESTING_8
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    -32768,  // INTERESTING_16
    -129,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    -2147483648LL,  // INTERESTING_32
    -100663046,
    -32769,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
    // === NEW: Integer overflow boundary values ===
    // These values are designed to trigger integer overflow bugs
    // when multiplied by common factors (channels=3,4,8, bit_depth=1,2,4,8,16)
    0x40000000,    // 2^30 = 1073741824 (width*4 overflows 2^32)
    0x20000000,    // 2^29 = 536870912  (width*8 overflows 2^32)
    0x10000000,    // 2^28 = 268435456
    0x08000000,    // 2^27 = 134217728
    0x04000000,    // 2^26 = 67108864
    0x55555555,    // ~1.43B (width*3 = 2^32)
    0x33333333,    // ~858M  (width*5 overflows)
    0x24924924,    // ~613M  (width*7 overflows)
    0x15555555,    // ~357M  (for larger multipliers)
    0x7FFFFF00,    // Near max with alignment
    0x7FFE0000,    // Large value with zeroed lower bits
    0x00010000,    // 64K boundary
    0x00008000,    // 32K boundary
    0x0000FFFF,    // 64K - 1
    0x00017FFF,    // Common allocation boundary
};
constexpr size_t interesting_32_count = sizeof(interesting_32) / sizeof(interesting_32[0]);

// Byte swap utilities
inline uint16_t swap16(uint16_t x) {
    return (x >> 8) | (x << 8);
}

inline uint32_t swap32(uint32_t x) {
    return ((x >> 24) & 0x000000FF) |
           ((x >> 8)  & 0x0000FF00) |
           ((x << 8)  & 0x00FF0000) |
           ((x << 24) & 0xFF000000);
}

// Read/write helpers for different sizes
inline uint16_t read16(const uint8_t* ptr) {
    uint16_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

inline uint32_t read32(const uint8_t* ptr) {
    uint32_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

inline void write16(uint8_t* ptr, uint16_t val) {
    memcpy(ptr, &val, sizeof(val));
}

inline void write32(uint8_t* ptr, uint32_t val) {
    memcpy(ptr, &val, sizeof(val));
}

// Random number generator wrapper for consistent behavior
class AFLRandom {
public:
    AFLRandom() : rng_(std::random_device{}()) {}
    explicit AFLRandom(uint64_t seed) : rng_(seed) {}

    // Get random value below limit (AFL++ rand_below equivalent)
    uint32_t below(uint32_t limit) {
        if (limit <= 1) return 0;
        std::uniform_int_distribution<uint32_t> dist(0, limit - 1);
        return dist(rng_);
    }

    // Get random byte
    uint8_t rand8() {
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        return static_cast<uint8_t>(dist(rng_));
    }

    // Get random 32-bit value
    uint32_t rand32() {
        std::uniform_int_distribution<uint32_t> dist;
        return dist(rng_);
    }

    // Get underlying generator for other uses
    std::mt19937& gen() { return rng_; }

private:
    std::mt19937 rng_;
};

// Check if a value could be the result of a bitflip
inline bool could_be_bitflip(uint32_t xor_val) {
    if (xor_val == 0) return true;

    // Check for single bit flips
    if ((xor_val & (xor_val - 1)) == 0) return true;

    // Check for adjacent 2, 4, 8, 16, 32 bit flips
    for (int i = 0; i < 32; i++) {
        uint32_t mask = 0;
        for (int j = 0; j < 32 && i + j < 32; j++) {
            mask |= (1U << (i + j));
            if (xor_val == mask) return true;
        }
    }
    return false;
}

// Check if a value change could be the result of arithmetic
inline bool could_be_arith(uint32_t old_val, uint32_t new_val, uint8_t blen) {
    int32_t diff = static_cast<int32_t>(new_val - old_val);
    if (diff >= -ARITH_MAX && diff <= ARITH_MAX && diff != 0) {
        return true;
    }

    // Check byte-swapped versions for multi-byte values
    if (blen == 2) {
        uint16_t old16 = swap16(static_cast<uint16_t>(old_val));
        uint16_t new16 = swap16(static_cast<uint16_t>(new_val));
        diff = static_cast<int32_t>(new16 - old16);
        if (diff >= -ARITH_MAX && diff <= ARITH_MAX && diff != 0) {
            return true;
        }
    } else if (blen == 4) {
        uint32_t old32 = swap32(old_val);
        uint32_t new32 = swap32(new_val);
        diff = static_cast<int32_t>(new32 - old32);
        if (diff >= -ARITH_MAX && diff <= ARITH_MAX && diff != 0) {
            return true;
        }
    }

    return false;
}

// Maximum input length (same as AFL++ default)
constexpr size_t MAX_FILE = 1024 * 1024;  // 1MB

// AFL++ havoc block constants (config.h)
constexpr uint32_t HAVOC_BLK_XL = 32768U;

// Helper to choose a block length for mutations
inline uint32_t choose_block_len(AFLRandom& rng, uint32_t limit) {
    uint32_t rlim = std::min(limit, static_cast<uint32_t>(32));

    switch (rng.below(3)) {
        case 0:
            return rng.below(rlim) + 1;
        case 1:
            return rng.below(rlim) + 1;
        default:
            if (rng.below(10)) {
                return rng.below(rlim) + 1;
            } else {
                uint32_t max_block = std::min(limit, static_cast<uint32_t>(128));
                return rng.below(max_block) + 1;
            }
    }
}

} // namespace aflpp
} // namespace triofuzz
