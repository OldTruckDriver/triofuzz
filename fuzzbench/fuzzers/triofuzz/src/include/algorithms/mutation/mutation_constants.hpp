#pragma once

#include <cstdint>
#include <array>

namespace triofuzz {
namespace constants {

/**
 * Mutation Constants - shared magic values, boundary values, and other constants
 *
 * This file centralizes constants used by all mutation algorithms to avoid duplication.
 */

// ============================================================================
// 8-bit Interesting Values
// ============================================================================

constexpr std::array<uint8_t, 17> INTERESTING_8 = {
    // Basic boundary values
    0x00, 0x01, 0x7F, 0x80, 0xFF,
    // Extended boundary values
    0x7E, 0x81, 0xFE,
    // Common special values
    0x10, 0x20, 0x40, 0x7D, 0x82, 0x83, 0xFD, 0xFC,
    // ASCII-related
    0x0A  // newline
};

// ============================================================================
// 16-bit Interesting Values
// ============================================================================

constexpr std::array<uint16_t, 20> INTERESTING_16 = {
    // Basic 16-bit values
    0x0000, 0x0001, 0x007F, 0x0080, 0x00FF, 0x0100,
    0x7FFF, 0x8000, 0xFFFF,
    // Near boundaries
    0x7FFE, 0x8001, 0xFFFE,
    // Common size values
    0x0400, 0x0800, 0x1000, 0x2000, 0x4000,
    // Special values
    0x0200, 0x03FF, 0x07FF
};

// ============================================================================
// 32-bit Interesting Values
// ============================================================================

constexpr std::array<uint32_t, 41> INTERESTING_32 = {
    // Basic 32-bit boundary values
    0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
    0x7FFFFFFE, 0x80000001, 0xFFFFFFFE,

    // File format magic numbers - Image formats
    0x89504E47,  // PNG: "\x89PNG"
    0xFFD8FFE0,  // JPEG (JFIF): 0xFF 0xD8 0xFF 0xE0
    0xFFD8FFE1,  // JPEG (EXIF): 0xFF 0xD8 0xFF 0xE1
    0x47494638,  // GIF: "GIF8"
    0x424D0000,  // BMP: "BM"
    0x49492A00,  // TIFF (little endian): "II*\0"
    0x4D4D002A,  // TIFF (big endian): "MM\0*"

    // Document format magic numbers
    0x25504446,  // PDF: "%PDF"
    0x504B0304,  // ZIP: "PK\x03\x04"
    0x504B0506,  // ZIP (empty): "PK\x05\x06"
    0x504B0708,  // ZIP (spanned): "PK\x07\x08"

    // ICC Profile-related
    0x61637370,  // 'acsp' - ICC profile signature
    0x52474220,  // 'RGB ' - RGB color space
    0x43594D4B,  // 'CYMK' - CMYK (NOTE: standard is "CMYK", but this is a common misspelling)
    0x434D594B,  // 'CMYK' - CMYK (correct spelling)
    0x47524159,  // 'GRAY' - Grayscale
    0x58595A20,  // 'XYZ ' - XYZ color space
    0x4C616220,  // 'Lab ' - Lab color space
    0x64657363,  // 'desc' - description tag
    0x63707274,  // 'cprt' - copyright tag
    0x77747074,  // 'wtpt' - white point tag
    0x63757276,  // 'curv' - curve tag
    0x74657874,  // 'text' - text tag
    0x6D6C7563,  // 'mluc' - multilingual unicode
    0x72545243,  // 'rTRC' - red TRC
    0x67545243,  // 'gTRC' - green TRC
    0x62545243,  // 'bTRC' - blue TRC

    // Vendor identifiers
    0x41444245,  // 'ADBE' - Adobe
    0x4150504C,  // 'APPL' - Apple
    0x73524742,  // 'sRGB' - sRGB
    
    // Common size values
    0x00010000,  // 64K
    0x00100000,  // 1MB
    0x01000000,  // 16MB
};

// ============================================================================
// 64-bit Interesting Values
// ============================================================================

constexpr std::array<uint64_t, 10> INTERESTING_64 = {
    0x0000000000000000ULL,
    0x0000000000000001ULL,
    0x7FFFFFFFFFFFFFFFULL,
    0x8000000000000000ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0x7FFFFFFFFFFFFFFEULL,
    0x8000000000000001ULL,
    0xFFFFFFFFFFFFFFFEULL,
    0x0000000100000000ULL,  // 4GB
    0x0000001000000000ULL,  // 64GB
};

// ============================================================================
// Arithmetic Deltas - common deltas for arithmetic mutations
// ============================================================================

constexpr std::array<int, 16> ARITHMETIC_DELTAS = {
    1, -1, 2, -2, 4, -4, 8, -8,
    16, -16, 32, -32, 64, -64, 127, -128
};

constexpr std::array<int, 10> ARITHMETIC_DELTAS_LARGE = {
    1, -1, 256, -256, 1024, -1024, 4096, -4096, 32768, -32768
};

// ============================================================================
// XOR Patterns - common XOR patterns
// ============================================================================

constexpr std::array<uint8_t, 8> XOR_PATTERNS = {
    0x01, 0x80, 0xFF, 0x7F, 0xAA, 0x55, 0xCC, 0x33
};

// ============================================================================
// String/Text Related Constants
// ============================================================================

// Common terminators and separators
constexpr std::array<uint8_t, 10> TERMINATORS_AND_SEPARATORS = {
    0x00,  // NULL
    0x0A,  // LF
    0x0D,  // CR
    0x09,  // TAB
    0x20,  // SPACE
    ';',
    ',',
    ':',
    '.',
    '/'
};

// Common brackets and quotes
constexpr std::array<uint8_t, 12> BRACKETS_AND_QUOTES = {
    '(', ')', '[', ']', '{', '}',
    '<', '>', '"', '\'', '`', '|'
};

// ============================================================================
// JPEG Specific Constants
// ============================================================================

namespace jpeg {
    constexpr uint8_t MARKER_PREFIX = 0xFF;
    constexpr uint8_t MARKER_SOI = 0xD8;    // Start of Image
    constexpr uint8_t MARKER_EOI = 0xD9;    // End of Image
    constexpr uint8_t MARKER_SOS = 0xDA;    // Start of Scan
    constexpr uint8_t MARKER_DQT = 0xDB;    // Quantization Table
    constexpr uint8_t MARKER_DHT = 0xC4;    // Huffman Table
    constexpr uint8_t MARKER_SOF0 = 0xC0;   // Start of Frame (Baseline)
    constexpr uint8_t MARKER_SOF2 = 0xC2;   // Start of Frame (Progressive)
    constexpr uint8_t MARKER_APP0 = 0xE0;   // JFIF
    constexpr uint8_t MARKER_APP1 = 0xE1;   // EXIF
    constexpr uint8_t MARKER_COM = 0xFE;    // Comment

    // Common JPEG markers for fuzzing
    constexpr std::array<uint8_t, 16> ALL_MARKERS = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xDA
    };
} // namespace jpeg

// ============================================================================
// ICC Profile Specific Constants
// ============================================================================

namespace icc {
    constexpr size_t ICC_HEADER_SIZE = 128;
    constexpr size_t ICC_MIN_SIZE = 132;
    constexpr uint32_t ICC_MAGIC = 0x61637370; // "acsp"

    // Color spaces
    constexpr uint32_t ICC_RGB  = 0x52474220; // "RGB "
    constexpr uint32_t ICC_GRAY = 0x47524159; // "GRAY"
    constexpr uint32_t ICC_CMYK = 0x434D594B; // "CMYK"
    constexpr uint32_t ICC_XYZ  = 0x58595A20; // "XYZ "
    constexpr uint32_t ICC_Lab  = 0x4C616220; // "Lab "

    // Tag signatures
    constexpr uint32_t TAG_DESC = 0x64657363; // "desc"
    constexpr uint32_t TAG_CPRT = 0x63707274; // "cprt"
    constexpr uint32_t TAG_WTPT = 0x77747074; // "wtpt"
    constexpr uint32_t TAG_RXYZ = 0x7258595A; // "rXYZ"
    constexpr uint32_t TAG_GXYZ = 0x6758595A; // "gXYZ"
    constexpr uint32_t TAG_BXYZ = 0x6258595A; // "bXYZ"
    constexpr uint32_t TAG_RTRC = 0x72545243; // "rTRC"
    constexpr uint32_t TAG_GTRC = 0x67545243; // "gTRC"
    constexpr uint32_t TAG_BTRC = 0x62545243; // "bTRC"

    constexpr std::array<uint32_t, 9> COMMON_TAGS = {
        TAG_DESC, TAG_CPRT, TAG_WTPT,
        TAG_RXYZ, TAG_GXYZ, TAG_BXYZ,
        TAG_RTRC, TAG_GTRC, TAG_BTRC
    };

    constexpr std::array<uint32_t, 5> COLOR_SPACES = {
        ICC_RGB, ICC_GRAY, ICC_CMYK, ICC_XYZ, ICC_Lab
    };
} // namespace icc

// ============================================================================
// Helper Functions for Random Selection
// ============================================================================

/**
 * Randomly select a value from an array.
 */
template<typename T, size_t N, typename RNG>
inline T selectRandom(const std::array<T, N>& arr, RNG& rng) {
    std::uniform_int_distribution<size_t> dist(0, N - 1);
    return arr[dist(rng)];
}

/**
 * Select an interesting value of the appropriate size.
 */
template<typename RNG>
inline uint8_t selectInteresting8(RNG& rng) {
    return selectRandom(INTERESTING_8, rng);
}

template<typename RNG>
inline uint16_t selectInteresting16(RNG& rng) {
    return selectRandom(INTERESTING_16, rng);
}

template<typename RNG>
inline uint32_t selectInteresting32(RNG& rng) {
    return selectRandom(INTERESTING_32, rng);
}

template<typename RNG>
inline uint64_t selectInteresting64(RNG& rng) {
    return selectRandom(INTERESTING_64, rng);
}

template<typename RNG>
inline int selectArithmeticDelta(RNG& rng) {
    return selectRandom(ARITHMETIC_DELTAS, rng);
}

template<typename RNG>
inline int selectArithmeticDeltaLarge(RNG& rng) {
    return selectRandom(ARITHMETIC_DELTAS_LARGE, rng);
}

template<typename RNG>
inline uint8_t selectXorPattern(RNG& rng) {
    return selectRandom(XOR_PATTERNS, rng);
}

} // namespace constants
} // namespace triofuzz
