/**
 * @file structure_aware_mutation.cpp
 * @brief Structure-aware mutation with automatic checksum repair
 *
 * This mutator understands file format structures (PNG, TIFF, ZIP, etc.)
 * and performs intelligent mutations while maintaining format validity.
 * Key feature: automatic CRC/checksum repair after mutation.
 */

#include "../../../include/algorithms/mutation/structure_aware_mutation.hpp"
#include <cstring>
#include <algorithm>
#include <random>
#include <iostream>
#include <string>
#include <optional>

namespace triofuzz {


namespace {

// CRC32 lookup table
static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

void initCRC32Table() {
    if (crc32_table_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xedb88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = true;
}

uint32_t calculateCRC32(const uint8_t* data, size_t len) {
    initCRC32Table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// Big-endian read/write for PNG
uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

void writeBE32(uint8_t* p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

uint16_t readBE16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

void writeBE16(uint8_t* p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

uint16_t readLE16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}

uint32_t readLE32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

} // anonymous namespace

//=============================================================================
// Format Detection
//=============================================================================

namespace {

bool isPNG(const std::vector<uint8_t>& data) {
    static const uint8_t PNG_SIG[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    return data.size() > 8 && std::memcmp(data.data(), PNG_SIG, 8) == 0;
}

bool isTIFF(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;
    // Little-endian: II, Big-endian: MM
    return (data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) ||
           (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A);
}

bool isZIP(const std::vector<uint8_t>& data) {
    return data.size() > 4 && data[0] == 0x50 && data[1] == 0x4B &&
           data[2] == 0x03 && data[3] == 0x04;
}

bool isGZIP(const std::vector<uint8_t>& data) {
    return data.size() > 2 && data[0] == 0x1F && data[1] == 0x8B;
}

bool isELF(const std::vector<uint8_t>& data) {
    return data.size() > 4 && data[0] == 0x7F && data[1] == 'E' &&
           data[2] == 'L' && data[3] == 'F';
}

bool isJPEG(const std::vector<uint8_t>& data) {
    // JPEG starts with SOI (FFD8) followed by a marker (FFxx).
    return data.size() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF;
}

bool isGIF(const std::vector<uint8_t>& data) {
    if (data.size() < 6) return false;
    return std::memcmp(data.data(), "GIF87a", 6) == 0 || std::memcmp(data.data(), "GIF89a", 6) == 0;
}

bool isBMP(const std::vector<uint8_t>& data) {
    return data.size() >= 2 && data[0] == 'B' && data[1] == 'M';
}

bool isPNM(const std::vector<uint8_t>& data) {
    // Netpbm: P1..P6
    return data.size() >= 2 && data[0] == 'P' && data[1] >= '1' && data[1] <= '6';
}

bool looksLikeTGA(const std::vector<uint8_t>& data) {
    // TGA has no magic; use conservative header plausibility checks.
    if (data.size() < 18) return false;
    uint8_t id_len = data[0];
    uint8_t cmap_type = data[1];
    uint8_t img_type = data[2];
    if (cmap_type > 1) return false;
    // Supported types: 1/2/3 (uncompressed) and 9/10/11 (RLE).
    if (!(img_type == 1 || img_type == 2 || img_type == 3 ||
          img_type == 9 || img_type == 10 || img_type == 11)) {
        return false;
    }
    uint16_t width = readLE16(&data[12]);
    uint16_t height = readLE16(&data[14]);
    uint8_t bpp = data[16];
    if (width == 0 || height == 0) return false;
    if (!(bpp == 8 || bpp == 15 || bpp == 16 || bpp == 24 || bpp == 32)) return false;
    // Basic bounds check for header + ID field.
    if (static_cast<size_t>(18) + id_len > data.size()) return false;
    return true;
}

bool isPSD(const std::vector<uint8_t>& data) {
    // Photoshop PSD/PSB: "8BPS" + version 1/2.
    return data.size() >= 26 && data[0] == '8' && data[1] == 'B' &&
           data[2] == 'P' && data[3] == 'S' && data[4] == 0 &&
           (data[5] == 1 || data[5] == 2);
}

bool isHDR(const std::vector<uint8_t>& data) {
    // Radiance HDR: "#?RADIANCE\n" or "#?RGBE\n"
    static const char kRad[] = "#?RADIANCE";
    static const char kRGBE[] = "#?RGBE";
    if (data.size() < 6) return false;
    if (data.size() >= sizeof(kRad) - 1 && std::memcmp(data.data(), kRad, sizeof(kRad) - 1) == 0) return true;
    if (data.size() >= sizeof(kRGBE) - 1 && std::memcmp(data.data(), kRGBE, sizeof(kRGBE) - 1) == 0) return true;
    return false;
}

bool isOgg(const std::vector<uint8_t>& data) {
    // Ogg page starts with "OggS" and version 0.
    return data.size() >= 27 && data[0] == 'O' && data[1] == 'g' &&
           data[2] == 'g' && data[3] == 'S' && data[4] == 0;
}

bool isICCProfile(const std::vector<uint8_t>& data) {
    // ICC profile header is 128 bytes and contains "acsp" at offset 36.
    return data.size() >= 128 && data[36] == 'a' && data[37] == 'c' &&
           data[38] == 's' && data[39] == 'p';
}

bool isDTLSRecordStream(const std::vector<uint8_t>& data) {
    // DTLS record header: type(1) + version(2) + epoch(2) + seq(6) + len(2) = 13 bytes.
    // Version is 0xFEFF (DTLS 1.0) or 0xFEFD (DTLS 1.2).
    return data.size() >= 13 && data[1] == 0xFE &&
           (data[2] == 0xFF || data[2] == 0xFD);
}

bool isWOFF2(const std::vector<uint8_t>& data) {
    return data.size() >= 4 && data[0] == 'w' && data[1] == 'O' &&
           data[2] == 'F' && data[3] == '2';
}

bool isWOFF(const std::vector<uint8_t>& data) {
    return data.size() >= 4 && data[0] == 'w' && data[1] == 'O' &&
           data[2] == 'F' && data[3] == 'F';
}

bool isSFNT(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;
    // 0x00010000, 'OTTO', 'true', 'typ1'
    const uint32_t tag = readBE32(data.data());
    return tag == 0x00010000u || tag == 0x4F54544Fu /* OTTO */ ||
           tag == 0x74727565u /* true */ || tag == 0x74797031u /* typ1 */;
}

static bool readDerLength(const std::vector<uint8_t>& data,
                          size_t offset,
                          size_t& out_len,
                          size_t& out_lenlen) {
    if (offset >= data.size()) return false;
    uint8_t b0 = data[offset];
    if ((b0 & 0x80) == 0) {
        out_len = b0;
        out_lenlen = 1;
        return true;
    }
    if (b0 == 0x80) {
        // Indefinite length is not DER.
        return false;
    }
    size_t n = b0 & 0x7F;
    if (n == 0 || n > 4) return false;
    if (offset + 1 + n > data.size()) return false;
    size_t len = 0;
    for (size_t i = 0; i < n; ++i) {
        len = (len << 8) | data[offset + 1 + i];
    }
    out_len = len;
    out_lenlen = 1 + n;
    return true;
}

bool looksLikeDER(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return false;
    // Cheap sanity: parse top-level length and ensure it fits in the buffer.
    size_t len = 0;
    size_t lenlen = 0;
    if (!readDerLength(data, 1, len, lenlen)) return false;
    size_t total = 1 + lenlen + len;
    return total <= data.size();
}

bool looksLikeRE2HarnessInput(const std::vector<uint8_t>& data) {
  
    if (data.empty()) return false;
    if (data.size() > 256) return false;

    if (isPNG(data) || isTIFF(data) || isJPEG(data) || isGIF(data) || isBMP(data) ||
        isPNM(data) || looksLikeTGA(data) || isPSD(data) || isHDR(data) ||
        isOgg(data) || isICCProfile(data) || isDTLSRecordStream(data) ||
        isWOFF2(data) || isWOFF(data) || isSFNT(data) || looksLikeDER(data)) {
        return false;
    }

    if (data.size() <= 128) return true;

    // For larger blobs, require a bit of text-likeness in the pattern area.
    if (data.size() < 3) return true;
    size_t printable = 0;
    size_t meta = 0;
    for (size_t i = 2; i < data.size(); ++i) {
        uint8_t c = data[i];
        if (c >= 0x20 && c <= 0x7E) printable++;
        if (c == '.' || c == '*' || c == '+' || c == '?' || c == '|' || c == '(' || c == ')' ||
            c == '[' || c == ']' || c == '{' || c == '}' || c == '^' || c == '$' || c == '\\') {
            meta++;
        }
    }
    size_t n = data.size() - 2;
    return n > 0 && (printable * 2 >= n) && (meta > 0);
}

static bool stb_synthesis_enabled() {
    // Always enabled: do not gate image synthesis by BENCHMARK.
    return true;
}

} // anonymous namespace

//=============================================================================
// PNG-specific operations
//=============================================================================

namespace png {

// PNG chunk structure:
// [length:4 BE][type:4][data:length][crc:4 BE]
// CRC covers type + data

struct ChunkInfo {
    size_t offset;      // Offset in file
    size_t length;      // Data length
    char type[5];       // Chunk type (null-terminated)
    size_t total_size;  // 12 + length
};

std::vector<ChunkInfo> parseChunks(const std::vector<uint8_t>& data) {
    std::vector<ChunkInfo> chunks;
    if (!isPNG(data)) return chunks;

    size_t pos = 8;  // Skip PNG signature
    while (pos + 12 <= data.size()) {
        ChunkInfo chunk;
        chunk.offset = pos;
        chunk.length = readBE32(&data[pos]);

        // Sanity check
        if (chunk.length > 0x7FFFFFFF || pos + 12 + chunk.length > data.size()) {
            break;
        }

        std::memcpy(chunk.type, &data[pos + 4], 4);
        chunk.type[4] = '\0';
        chunk.total_size = 12 + chunk.length;

        chunks.push_back(chunk);
        pos += chunk.total_size;
    }

    return chunks;
}

void fixAllCRCs(std::vector<uint8_t>& data) {
    if (!isPNG(data)) return;

    size_t pos = 8;
    while (pos + 12 <= data.size()) {
        uint32_t chunk_len = readBE32(&data[pos]);

        if (chunk_len > 0x7FFFFFFF || pos + 12 + chunk_len > data.size()) {
            break;
        }

        // Calculate CRC over type + data
        uint32_t crc = calculateCRC32(&data[pos + 4], 4 + chunk_len);
        writeBE32(&data[pos + 8 + chunk_len], crc);

        pos += 12 + chunk_len;
    }
}

// IHDR chunk offsets (after PNG signature + chunk header)
// IHDR is always the first chunk
constexpr size_t IHDR_WIDTH_OFFSET = 16;   // 8 (sig) + 4 (len) + 4 (type)
constexpr size_t IHDR_HEIGHT_OFFSET = 20;
constexpr size_t IHDR_BITDEPTH_OFFSET = 24;
constexpr size_t IHDR_COLORTYPE_OFFSET = 25;


static const uint32_t OVERFLOW_VALUES[] = {
   
    0x40000000,  
    0x55555555,  
    0x20000000,  
    0x2AAAAAAA,  
    0x33333333,  
    0x24924924,  

   
    0x10000000,  
    0x08000000,  
    0x04000000,  

   
    0x1FFFFFFF,  
    0x3FFFFFFF,  
    0x0FFFFFFF,  

    
    0x7FFFFFFF,  

 
    0x00010000,  
    0x0000FFFF,  
    0x00008000, 
    1,           
};

//=============================================================================
// eXIf chunk support for metadata parsing edge cases
//=============================================================================

// eXIf chunk type bytes: "eXIf" = 0x65 0x58 0x49 0x66
constexpr uint8_t EXIF_TYPE[4] = {'e', 'X', 'I', 'f'};

// Generate minimal valid EXIF data
// EXIF structure: "Exif\0\0" + TIFF header + minimal IFD
std::vector<uint8_t> generateMinimalEXIF() {
    std::vector<uint8_t> exif;

    // Exif header: "Exif\0\0"
    exif.push_back('E');
    exif.push_back('x');
    exif.push_back('i');
    exif.push_back('f');
    exif.push_back(0x00);
    exif.push_back(0x00);

    // TIFF header (little-endian: "II")
    exif.push_back('I');
    exif.push_back('I');
    exif.push_back(0x2A);  // TIFF magic number
    exif.push_back(0x00);

    // IFD0 offset (8 bytes from TIFF header start)
    exif.push_back(0x08);
    exif.push_back(0x00);
    exif.push_back(0x00);
    exif.push_back(0x00);

    // IFD0: 0 entries (minimal valid IFD)
    exif.push_back(0x00);
    exif.push_back(0x00);

    // Next IFD offset: 0 (no more IFDs)
    exif.push_back(0x00);
    exif.push_back(0x00);
    exif.push_back(0x00);
    exif.push_back(0x00);

    return exif;
}

// Insert a chunk into PNG data at specified position
void insertChunk(std::vector<uint8_t>& data, size_t pos,
                 const uint8_t type[4], const std::vector<uint8_t>& chunk_data) {
    if (pos > data.size()) pos = data.size();

    // Build chunk: [length:4][type:4][data:length][crc:4]
    std::vector<uint8_t> chunk;
    uint32_t len = static_cast<uint32_t>(chunk_data.size());

    // Length (big-endian)
    chunk.push_back((len >> 24) & 0xFF);
    chunk.push_back((len >> 16) & 0xFF);
    chunk.push_back((len >> 8) & 0xFF);
    chunk.push_back(len & 0xFF);

    // Type
    chunk.push_back(type[0]);
    chunk.push_back(type[1]);
    chunk.push_back(type[2]);
    chunk.push_back(type[3]);

    // Data
    chunk.insert(chunk.end(), chunk_data.begin(), chunk_data.end());

    // Calculate CRC over type + data
    std::vector<uint8_t> crc_data(chunk.begin() + 4, chunk.end());
    uint32_t crc = calculateCRC32(crc_data.data(), crc_data.size());

    // CRC (big-endian)
    chunk.push_back((crc >> 24) & 0xFF);
    chunk.push_back((crc >> 16) & 0xFF);
    chunk.push_back((crc >> 8) & 0xFF);
    chunk.push_back(crc & 0xFF);

    // Insert into data
    data.insert(data.begin() + pos, chunk.begin(), chunk.end());
}

// Find position before IDAT chunk (best place to insert ancillary chunks)
size_t findInsertPositionBeforeIDAT(const std::vector<uint8_t>& data) {
    auto chunks = parseChunks(data);

    for (const auto& chunk : chunks) {
        // Insert before IDAT or IEND
        if (std::strcmp(chunk.type, "IDAT") == 0 ||
            std::strcmp(chunk.type, "IEND") == 0) {
            return chunk.offset;
        }
    }

    // Default: after IHDR (position 8 + IHDR size)
    if (data.size() > 8 + 25) {
        return 8 + 25;  // After PNG signature + IHDR chunk
    }
    return data.size();
}

// Check if PNG already has eXIf chunk
bool hasEXIFChunk(const std::vector<uint8_t>& data) {
    auto chunks = parseChunks(data);
    for (const auto& chunk : chunks) {
        if (std::strcmp(chunk.type, "eXIf") == 0) {
            return true;
        }
    }
    return false;
}

// Ancillary chunk types used for coverage-focused mutations.
constexpr uint8_t GAMA_TYPE[4] = {'g', 'A', 'M', 'A'};
constexpr uint8_t SRGB_TYPE[4] = {'s', 'R', 'G', 'B'};
constexpr uint8_t CHRM_TYPE[4] = {'c', 'H', 'R', 'M'};
constexpr uint8_t PHYS_TYPE[4] = {'p', 'H', 'Y', 's'};
constexpr uint8_t SBIT_TYPE[4] = {'s', 'B', 'I', 'T'};
constexpr uint8_t BKGD_TYPE[4] = {'b', 'K', 'G', 'D'};
constexpr uint8_t TRNS_TYPE[4] = {'t', 'R', 'N', 'S'};
constexpr uint8_t ICCP_TYPE[4] = {'i', 'C', 'C', 'P'};

static uint32_t adler32(const uint8_t* buf, size_t len) {
    // RFC 1950 Adler-32.
    constexpr uint32_t MOD_ADLER = 65521;
    uint32_t a = 1;
    uint32_t b = 0;
    for (size_t i = 0; i < len; ++i) {
        a = (a + buf[i]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    return (b << 16) | a;
}

static std::vector<uint8_t> zlibUncompressed(const std::vector<uint8_t>& payload) {

    std::vector<uint8_t> out;
    if (payload.size() > 65535) return out;

    out.push_back(0x78);
    out.push_back(0x01);

    // DEFLATE uncompressed block header.
    out.push_back(0x01);
    uint16_t len = static_cast<uint16_t>(payload.size());
    uint16_t nlen = static_cast<uint16_t>(~len);
    out.push_back(static_cast<uint8_t>(len & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(nlen & 0xFF));
    out.push_back(static_cast<uint8_t>((nlen >> 8) & 0xFF));

    out.insert(out.end(), payload.begin(), payload.end());

    uint32_t a = adler32(payload.data(), payload.size());
    // Adler32 is stored big-endian.
    out.push_back(static_cast<uint8_t>((a >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((a >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((a >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(a & 0xFF));
    return out;
}

static std::vector<uint8_t> minimalICCProfile() {
    std::vector<uint8_t> p(128, 0);
    writeBE32(&p[0], static_cast<uint32_t>(p.size()));
    p[36] = 'a';
    p[37] = 'c';
    p[38] = 's';
    p[39] = 'p';
    // Device class at 12..15: 'mntr'
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    // Color space at 16..19: 'RGB '
    p[16] = 'R'; p[17] = 'G'; p[18] = 'B'; p[19] = ' ';
    // PCS at 20..23: 'XYZ '
    p[20] = 'X'; p[21] = 'Y'; p[22] = 'Z'; p[23] = ' ';
    return p;
}

} // namespace png

//=============================================================================
// Ogg helpers
//=============================================================================

namespace ogg {

struct Page {
    size_t offset = 0;
    size_t header_size = 0;
    size_t body_size = 0;
    size_t total_size = 0;
    uint8_t page_segments = 0;
};

static uint32_t crc_table[256];
static bool crc_table_initialized = false;

static void initCRCTable() {
    if (crc_table_initialized) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t r = i << 24;
        for (int j = 0; j < 8; ++j) {
            if (r & 0x80000000u) r = (r << 1) ^ 0x04C11DB7u;
            else r <<= 1;
        }
        crc_table[i] = r;
    }
    crc_table_initialized = true;
}

static uint32_t computePageCRC(const std::vector<uint8_t>& data, const Page& p) {
    initCRCTable();
    uint32_t crc = 0;
    for (size_t i = 0; i < p.total_size; ++i) {
        uint8_t b = data[p.offset + i];
        // checksum field is bytes 22..25 (inclusive) in the page header
        if (i >= 22 && i < 26) b = 0;
        crc = (crc << 8) ^ crc_table[((crc >> 24) & 0xFF) ^ b];
    }
    return crc;
}

static void writeLE32(std::vector<uint8_t>& data, size_t off, uint32_t v) {
    if (off + 4 > data.size()) return;
    data[off + 0] = static_cast<uint8_t>(v & 0xFF);
    data[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    data[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    data[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static std::vector<Page> parsePages(const std::vector<uint8_t>& data) {
    std::vector<Page> pages;
    if (data.size() < 27) return pages;

    size_t pos = 0;
    while (pos + 27 <= data.size()) {
        // Find next "OggS".
        size_t start = pos;
        for (; start + 4 <= data.size(); ++start) {
            if (data[start] == 'O' && data[start + 1] == 'g' &&
                data[start + 2] == 'g' && data[start + 3] == 'S') {
                break;
            }
        }
        if (start + 27 > data.size()) break;

        uint8_t segs = data[start + 26];
        size_t header = 27 + static_cast<size_t>(segs);
        if (start + header > data.size()) break;

        size_t body = 0;
        for (size_t i = 0; i < segs; ++i) {
            body += data[start + 27 + i];
        }
        if (start + header + body > data.size()) break;

        Page p;
        p.offset = start;
        p.header_size = header;
        p.body_size = body;
        p.total_size = header + body;
        p.page_segments = segs;
        pages.push_back(p);

        pos = start + header + body;
    }
    return pages;
}

static void fixAllCRCs(std::vector<uint8_t>& data) {
    auto pages = parsePages(data);
    for (const auto& p : pages) {
        if (p.offset + 26 >= data.size()) continue;
        uint32_t crc = computePageCRC(data, p);
        writeLE32(data, p.offset + 22, crc);
    }
}

}  // namespace ogg

//=============================================================================
// ICC profile helpers
//=============================================================================

namespace icc {

struct TagEntry {
    uint32_t signature = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
};

static uint32_t readU32BE(const std::vector<uint8_t>& data, size_t off) {
    if (off + 4 > data.size()) return 0;
    return readBE32(&data[off]);
}

static void writeU32BE(std::vector<uint8_t>& data, size_t off, uint32_t v) {
    if (off + 4 > data.size()) return;
    writeBE32(&data[off], v);
}

static std::vector<TagEntry> parseTagTable(const std::vector<uint8_t>& data) {
    std::vector<TagEntry> tags;
    if (data.size() < 132) return tags;
    uint32_t count = readU32BE(data, 128);
    size_t max_count = (data.size() - 132) / 12;
    if (count > max_count) count = static_cast<uint32_t>(max_count);
    tags.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        size_t base = 132 + static_cast<size_t>(i) * 12;
        TagEntry e;
        e.signature = readU32BE(data, base + 0);
        e.offset = readU32BE(data, base + 4);
        e.size = readU32BE(data, base + 8);
        // Basic bounds check.
        if (e.offset < 128 || static_cast<size_t>(e.offset) > data.size()) continue;
        if (e.size == 0) continue;
        if (static_cast<size_t>(e.offset) + static_cast<size_t>(e.size) > data.size()) continue;
        tags.push_back(e);
    }
    return tags;
}

}  // namespace icc

//=============================================================================
// sfnt checksum helper 
//=============================================================================

static uint32_t sfntChecksum(const uint8_t* data, size_t len) {
    // Sum of big-endian uint32 words, padding with zeros to 4-byte boundary.
    uint64_t sum = 0;
    size_t n = (len + 3) & ~static_cast<size_t>(3);
    for (size_t i = 0; i < n; i += 4) {
        uint32_t w = 0;
        for (size_t j = 0; j < 4; ++j) {
            w <<= 8;
            if (i + j < len) w |= data[i + j];
        }
        sum += w;
    }
    return static_cast<uint32_t>(sum & 0xFFFFFFFFu);
}

//=============================================================================
// StructureAwareMutation Implementation
//=============================================================================

StructureAwareMutation::StructureAwareMutation()
    : analyzer_(std::make_unique<GenericStructureAnalyzer>())
    , random_gen_(std::random_device{}()) {

    // Default mutation weights
    mutation_weights_["field_mutate"] = 0.4;
    mutation_weights_["overflow_inject"] = 0.3;  // High weight for overflow
    mutation_weights_["structure_mutate"] = 0.2;
    mutation_weights_["random_havoc"] = 0.1;
}

MutationOutput StructureAwareMutation::execute(const MutationInput& input, SharedContext& ctx) {
    if (input.empty()) return input;

    MutationOutput output = input;

    // stb_stbi_read_fuzzer: occasionally synthesize new image families (PSD/HDR)
    // to expand reachable decoder coverage without changing the harness.
    if (stb_synthesis_enabled()) {
        if (maybeSynthesizeStbImages(output)) {
            return output;
        }
    }

    // Detect format and apply appropriate mutation
    if (isPNG(output)) {
        mutatePNG(output);
    } else if (isTIFF(output)) {
        mutateTIFF(output);
    } else if (isJPEG(output)) {
        mutateJPEG(output);
    } else if (isGIF(output)) {
        mutateGIF(output);
    } else if (isBMP(output)) {
        mutateBMP(output);
    } else if (looksLikeTGA(output)) {
        mutateTGA(output);
    } else if (isPNM(output)) {
        mutatePNM(output);
    } else if (isPSD(output)) {
        mutatePSD(output);
    } else if (isHDR(output)) {
        mutateHDR(output);
    } else if (isOgg(output)) {
        mutateOgg(output);
    } else if (isICCProfile(output)) {
        mutateICC(output);
    } else if (isDTLSRecordStream(output)) {
        mutateDTLS(output);
    } else if (looksLikeRE2HarnessInput(output)) {
        mutateRE2(output);
    } else if (isWOFF2(output) || isWOFF(output) || isSFNT(output)) {
        mutateFont(output);
    } else if (looksLikeDER(output)) {
        mutateASN1(output);
    } else {
        // Unknown format - apply generic havoc
        applyGenericMutation(output);
    }

    return output;
}

void StructureAwareMutation::mutatePNG(MutationOutput& data) {
    std::uniform_real_distribution<double> prob(0.0, 1.0);
    double r = prob(random_gen_);

    auto mutate_safe_dims = [&]() {
        if (data.size() < 29) return;
        // Keep dimensions within a harness-friendly range to avoid early exits
        // due to huge image sizes, but still explore many decode paths.
        std::uniform_int_distribution<uint32_t> dim(1, 4096);
        std::uniform_int_distribution<int> choice(0, 2);
        int c = choice(random_gen_);
        uint32_t w = dim(random_gen_);
        uint32_t h = dim(random_gen_);
        if (c == 0 || c == 2) writeBE32(&data[png::IHDR_WIDTH_OFFSET], w);
        if (c == 1 || c == 2) writeBE32(&data[png::IHDR_HEIGHT_OFFSET], h);
    };

    if (r < 0.02) {
        // 2%: Insert eXIf chunk to trigger metadata parsing edge cases
        mutatePNGInsertEXIF(data);
    } else if (r < 0.04) {
        // 2%: Delete palette chunk to test null-palette handling
        mutatePNGDeletePLTE(data);
    } else if (r < 0.09) {
        // 5%: Mutate IHDR dimensions with overflow values to trigger integer overflow
        mutatePNGDimensions(data);
    } else if (r < 0.14) {
        // 5%: Mutate IHDR dimensions in a coverage-friendly range
        mutate_safe_dims();
    } else if (r < 0.24) {
        // 10%: Mutate IHDR color type / bit depth (biased towards valid combinations)
        mutatePNGColorInfo(data);
    } else if (r < 0.90) {
        // 66%: Mutate chunk structure / metadata (validity-preserving)
        mutatePNGChunks(data);
    } else {
        // 10%: Random byte mutation in data chunks (can break zlib, keep low)
        mutatePNGData(data);
    }

    // Always fix CRCs after mutation
    if (fix_checksums_) {
        png::fixAllCRCs(data);
    }
}

void StructureAwareMutation::mutatePNGDimensions(MutationOutput& data) {
    if (data.size() < 29) return;  // Need at least IHDR

    std::uniform_int_distribution<size_t> val_dist(0,
        sizeof(png::OVERFLOW_VALUES) / sizeof(png::OVERFLOW_VALUES[0]) - 1);
    std::uniform_int_distribution<int> choice(0, 2);

    int c = choice(random_gen_);
    uint32_t value = png::OVERFLOW_VALUES[val_dist(random_gen_)];

    if (c == 0 || c == 2) {
        // Mutate width
        writeBE32(&data[png::IHDR_WIDTH_OFFSET], value);
    }
    if (c == 1 || c == 2) {
        // Mutate height
        uint32_t height_value = png::OVERFLOW_VALUES[val_dist(random_gen_)];
        writeBE32(&data[png::IHDR_HEIGHT_OFFSET], height_value);
    }
}

void StructureAwareMutation::mutatePNGColorInfo(MutationOutput& data) {
    if (data.size() < 29) return;

    // Mostly keep values valid so the decoder explores deeper paths; keep a
    // small tail of invalid cases to exercise error handling.
    bool allow_invalid = (random_gen_() % 10) == 0;  // 10%

    uint8_t cur_ct = data[png::IHDR_COLORTYPE_OFFSET];
    uint8_t cur_bd = data[png::IHDR_BITDEPTH_OFFSET];
    (void)cur_bd;

    auto pick_valid_bit_depth = [&](uint8_t ct) -> uint8_t {
        static const uint8_t kGray[] = {1, 2, 4, 8, 16};
        static const uint8_t kRGB[] = {8, 16};
        static const uint8_t kPal[] = {1, 2, 4, 8};
        static const uint8_t kGA[] = {8, 16};
        static const uint8_t kRGBA[] = {8, 16};
        const uint8_t* arr = kGray;
        size_t n = sizeof(kGray);
        switch (ct) {
            case 0: arr = kGray; n = sizeof(kGray); break;
            case 2: arr = kRGB; n = sizeof(kRGB); break;
            case 3: arr = kPal; n = sizeof(kPal); break;
            case 4: arr = kGA; n = sizeof(kGA); break;
            case 6: arr = kRGBA; n = sizeof(kRGBA); break;
            default: arr = kGray; n = sizeof(kGray); break;
        }
        return arr[random_gen_() % n];
    };

    std::uniform_int_distribution<int> op(0, 2);
    int operation = op(random_gen_);

    if (allow_invalid) {
        static const uint8_t kInvalidCT[] = {1, 5, 7};
        static const uint8_t kInvalidBD[] = {0, 3, 32};
        if (operation == 0) {
            data[png::IHDR_BITDEPTH_OFFSET] = kInvalidBD[random_gen_() % (sizeof(kInvalidBD) / sizeof(kInvalidBD[0]))];
        } else if (operation == 1) {
            data[png::IHDR_COLORTYPE_OFFSET] = kInvalidCT[random_gen_() % (sizeof(kInvalidCT) / sizeof(kInvalidCT[0]))];
        } else {
            // Invalid interlace method
            data[28] = static_cast<uint8_t>(2 + (random_gen_() % 3));
        }
        return;
    }

    static const uint8_t kValidCT[] = {0, 2, 3, 4, 6};
    switch (operation) {
        case 0: {
            // Bit depth change compatible with current color type.
            data[png::IHDR_BITDEPTH_OFFSET] = pick_valid_bit_depth(cur_ct);
            break;
        }
        case 1: {
            // Color type change + adjust bit depth to a valid one.
            uint8_t ct = kValidCT[random_gen_() % (sizeof(kValidCT) / sizeof(kValidCT[0]))];
            data[png::IHDR_COLORTYPE_OFFSET] = ct;
            data[png::IHDR_BITDEPTH_OFFSET] = pick_valid_bit_depth(ct);
            break;
        }
        case 2: {
            // Toggle interlacing (0/1).
            data[28] ^= 1u;
            break;
        }
    }
}

void StructureAwareMutation::mutatePNGChunks(MutationOutput& data) {
    auto chunks = png::parseChunks(data);
    if (chunks.size() < 2) return;  // Need at least IHDR + IEND

    std::uniform_int_distribution<int> op(0, 6);
    int operation = op(random_gen_);

    auto is_critical = [](const char* type) {
        return std::strcmp(type, "IHDR") == 0 || std::strcmp(type, "IDAT") == 0 ||
               std::strcmp(type, "IEND") == 0;
    };

    auto has_chunk = [&](const char* type) -> bool {
        for (const auto& c : chunks) {
            if (std::strcmp(c.type, type) == 0) return true;
        }
        return false;
    };

    auto find_chunk = [&](const char* type) -> std::optional<png::ChunkInfo> {
        for (const auto& c : chunks) {
            if (std::strcmp(c.type, type) == 0) return c;
        }
        return std::nullopt;
    };

    auto ihdr_color_type = [&]() -> uint8_t {
        if (data.size() <= png::IHDR_COLORTYPE_OFFSET) return 6;
        return data[png::IHDR_COLORTYPE_OFFSET];
    };

    auto ihdr_bit_depth = [&]() -> uint8_t {
        if (data.size() <= png::IHDR_BITDEPTH_OFFSET) return 8;
        return data[png::IHDR_BITDEPTH_OFFSET];
    };

    auto insert_or_mutate_fixed_chunk = [&](const char* name,
                                           const uint8_t type[4],
                                           const std::vector<uint8_t>& payload) {
        for (const auto& c : chunks) {
            if (std::strcmp(c.type, name) != 0) continue;
            if (c.length == 0) break;
            size_t off = c.offset + 8;
            size_t end = off + c.length;
            if (end > data.size() || off >= end) break;
            // Overwrite as much as possible without changing length.
            size_t n = std::min(payload.size(), static_cast<size_t>(c.length));
            if (n == 0) break;
            std::memcpy(&data[off], payload.data(), n);
            return;
        }
        size_t pos = png::findInsertPositionBeforeIDAT(data);
        png::insertChunk(data, pos, type, payload);
    };

    switch (operation) {
        case 0: {
            // Mutate bytes inside a non-critical, non-empty chunk payload.
            std::vector<png::ChunkInfo> candidates;
            candidates.reserve(chunks.size());
            for (const auto& c : chunks) {
                if (is_critical(c.type)) continue;
                if (c.length == 0) continue;
                candidates.push_back(c);
            }
            if (candidates.empty()) break;
            std::uniform_int_distribution<size_t> idx(0, candidates.size() - 1);
            const auto& c = candidates[idx(random_gen_)];
            size_t off = c.offset + 8;
            size_t end = off + c.length;
            if (end > data.size() || off >= end) break;
            std::uniform_int_distribution<size_t> pos_dist(off, end - 1);
            size_t iters = 1 + (random_gen_() % 8);
            for (size_t i = 0; i < iters; ++i) {
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
            break;
        }
        case 1: {
            // Insert or mutate common ancillary chunks to reach more parsing paths.
            uint8_t ct = ihdr_color_type();
            uint8_t bd = ihdr_bit_depth();

            std::uniform_int_distribution<int> kind(0, 7);
            int k = kind(random_gen_);
            switch (k) {
                case 0: { // gAMA
                    std::vector<uint8_t> p(4, 0);
                    uint32_t gamma = 1 + (random_gen_() % 300000);
                    writeBE32(p.data(), gamma);
                    insert_or_mutate_fixed_chunk("gAMA", png::GAMA_TYPE, p);
                    break;
                }
                case 1: { // sRGB
                    std::vector<uint8_t> p(1, static_cast<uint8_t>(random_gen_() % 4));
                    insert_or_mutate_fixed_chunk("sRGB", png::SRGB_TYPE, p);
                    break;
                }
                case 2: { // cHRM
                    std::vector<uint8_t> p(32, 0);
                    // Base sRGB primaries, with small jitter.
                    uint32_t vals[8] = {
                        31270, 32900,  // white
                        64000, 33000,  // red
                        30000, 60000,  // green
                        15000,  6000,  // blue
                    };
                    for (int i = 0; i < 8; ++i) {
                        int32_t jitter = static_cast<int32_t>(random_gen_() % 2001) - 1000;
                        int64_t v = static_cast<int64_t>(vals[i]) + jitter;
                        if (v < 0) v = 0;
                        if (v > 100000) v = 100000;
                        writeBE32(&p[i * 4], static_cast<uint32_t>(v));
                    }
                    insert_or_mutate_fixed_chunk("cHRM", png::CHRM_TYPE, p);
                    break;
                }
                case 3: { // pHYs
                    std::vector<uint8_t> p(9, 0);
                    uint32_t xppm = 1 + (random_gen_() % 20000);
                    uint32_t yppm = 1 + (random_gen_() % 20000);
                    writeBE32(&p[0], xppm);
                    writeBE32(&p[4], yppm);
                    p[8] = (random_gen_() & 1) ? 1 : 0;
                    insert_or_mutate_fixed_chunk("pHYs", png::PHYS_TYPE, p);
                    break;
                }
                case 4: { // sBIT
                    auto clamp_bits = [&](uint8_t bits) -> uint8_t {
                        if (bits == 0) return 1;
                        if (bits > 16) bits = 16;
                        return bits;
                    };
                    uint8_t bits = clamp_bits(bd);
                    auto pick = [&]() -> uint8_t { return static_cast<uint8_t>(1 + (random_gen_() % bits)); };
                    std::vector<uint8_t> p;
                    switch (ct) {
                        case 0: p = {pick()}; break;
                        case 2: p = {pick(), pick(), pick()}; break;
                        case 3: p = {pick(), pick(), pick()}; break;
                        case 4: p = {pick(), pick()}; break;
                        case 6: p = {pick(), pick(), pick(), pick()}; break;
                        default: p = {pick()}; break;
                    }
                    insert_or_mutate_fixed_chunk("sBIT", png::SBIT_TYPE, p);
                    break;
                }
                case 5: { // bKGD
                    std::vector<uint8_t> p;
                    if (ct == 3) {
                        p = {static_cast<uint8_t>(random_gen_() % 256)};
                    } else if (ct == 0 || ct == 4) {
                        p.resize(2);
                        uint16_t v = static_cast<uint16_t>(random_gen_() & 0xFFFF);
                        writeBE16(p.data(), v);
                    } else {
                        p.resize(6);
                        uint16_t r = static_cast<uint16_t>(random_gen_() & 0xFFFF);
                        uint16_t g = static_cast<uint16_t>(random_gen_() & 0xFFFF);
                        uint16_t b = static_cast<uint16_t>(random_gen_() & 0xFFFF);
                        writeBE16(&p[0], r);
                        writeBE16(&p[2], g);
                        writeBE16(&p[4], b);
                    }
                    insert_or_mutate_fixed_chunk("bKGD", png::BKGD_TYPE, p);
                    break;
                }
                case 6: { // tRNS
                    std::vector<uint8_t> p;
                    if (ct == 3) {
                        size_t entries = 0;
                        if (auto plte = find_chunk("PLTE"); plte) {
                            entries = static_cast<size_t>(plte->length) / 3;
                        }
                        size_t n = std::max<size_t>(1, std::min<size_t>(entries ? entries : 16, 16));
                        p.resize(n);
                        for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(random_gen_() & 0xFF);
                    } else if (ct == 0) {
                        p.resize(2);
                        writeBE16(p.data(), static_cast<uint16_t>(random_gen_() & 0xFFFF));
                    } else if (ct == 2) {
                        p.resize(6);
                        writeBE16(&p[0], static_cast<uint16_t>(random_gen_() & 0xFFFF));
                        writeBE16(&p[2], static_cast<uint16_t>(random_gen_() & 0xFFFF));
                        writeBE16(&p[4], static_cast<uint16_t>(random_gen_() & 0xFFFF));
                    } else {
                        // For formats where tRNS is invalid, mutate bytes anyway (exercise error paths).
                        p.resize(2);
                        writeBE16(p.data(), static_cast<uint16_t>(random_gen_() & 0xFFFF));
                    }
                    insert_or_mutate_fixed_chunk("tRNS", png::TRNS_TYPE, p);
                    break;
                }
                case 7: { // iCCP (small, valid zlib stream)
                    if (!has_chunk("iCCP")) {
                        auto icc = png::minimalICCProfile();
                        auto z = png::zlibUncompressed(icc);
                        if (z.empty()) break;
                        const char kName[] = "TrioFuzz";
                        std::vector<uint8_t> p;
                        p.insert(p.end(), kName, kName + (sizeof(kName) - 1));
                        p.push_back(0x00);  // null terminator
                        p.push_back(0x00);  // compression method 0
                        p.insert(p.end(), z.begin(), z.end());
                        size_t pos = png::findInsertPositionBeforeIDAT(data);
                        png::insertChunk(data, pos, png::ICCP_TYPE, p);
                    } else {
                        // If present, mutate a few bytes after the name (keep NUL in place).
                        if (auto c = find_chunk("iCCP"); c && c->length > 0) {
                            size_t off = c->offset + 8;
                            size_t end = off + c->length;
                            if (end <= data.size() && off < end) {
                                std::uniform_int_distribution<size_t> pos_dist(off, end - 1);
                                size_t iters = 1 + (random_gen_() % 6);
                                for (size_t i = 0; i < iters; ++i) {
                                    size_t pos = pos_dist(random_gen_);
                                    if (data[pos] == 0x00 && (pos - off) < 16) continue;
                                    data[pos] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
                                }
                            }
                        }
                    }
                    break;
                }
            }
            break;
        }
        case 2: {
            // Mutate PLTE palette entries (keep structure).
            if (auto plte = find_chunk("PLTE"); plte && plte->length >= 3) {
                size_t off = plte->offset + 8;
                size_t end = off + plte->length;
                if (end > data.size() || off >= end) break;
                std::uniform_int_distribution<size_t> pos_dist(off, end - 1);
                size_t iters = 1 + (random_gen_() % 12);
                for (size_t i = 0; i < iters; ++i) {
                    size_t pos = pos_dist(random_gen_);
                    data[pos] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
                }
            }
            break;
        }
        case 3: {
            // Delete a non-critical ancillary chunk (avoid IHDR/IDAT/IEND/PLTE).
            std::vector<png::ChunkInfo> candidates;
            candidates.reserve(chunks.size());
            for (const auto& c : chunks) {
                if (is_critical(c.type)) continue;
                if (std::strcmp(c.type, "PLTE") == 0) continue;
                candidates.push_back(c);
            }
            if (candidates.empty()) break;
            std::uniform_int_distribution<size_t> idx(0, candidates.size() - 1);
            const auto& c = candidates[idx(random_gen_)];
            if (c.offset + c.total_size > data.size()) break;
            data.erase(data.begin() + c.offset, data.begin() + c.offset + c.total_size);
            break;
        }
        case 4: {
            // Duplicate a small ancillary chunk.
            std::vector<png::ChunkInfo> candidates;
            candidates.reserve(chunks.size());
            for (const auto& c : chunks) {
                if (is_critical(c.type)) continue;
                if (c.total_size > 256) continue;
                candidates.push_back(c);
            }
            if (candidates.empty()) break;
            std::uniform_int_distribution<size_t> idx(0, candidates.size() - 1);
            const auto& c = candidates[idx(random_gen_)];
            if (c.offset + c.total_size > data.size()) break;
            if (data.size() + c.total_size > 1024 * 1024) break;
            std::vector<uint8_t> chunk_bytes(data.begin() + c.offset,
                                             data.begin() + c.offset + c.total_size);
            data.insert(data.begin() + c.offset + c.total_size, chunk_bytes.begin(), chunk_bytes.end());
            break;
        }
        case 5: {
            // Insert an unknown ancillary chunk (lowercase first letter), small payload.
            uint8_t type[4] = {'x', 'X', 'X', 'x'};
            type[0] = static_cast<uint8_t>('a' + (random_gen_() % 26));
            type[1] = static_cast<uint8_t>('A' + (random_gen_() % 26));
            type[2] = static_cast<uint8_t>('A' + (random_gen_() % 26));
            type[3] = static_cast<uint8_t>('a' + (random_gen_() % 26));
            std::vector<uint8_t> payload(1 + (random_gen_() % 32));
            for (auto& b : payload) b = static_cast<uint8_t>(random_gen_() & 0xFF);
            size_t pos = png::findInsertPositionBeforeIDAT(data);
            png::insertChunk(data, pos, type, payload);
            break;
        }
        case 6: {
            // Rare: tweak an ancillary chunk length to exercise parser recovery.
            std::vector<png::ChunkInfo> candidates;
            candidates.reserve(chunks.size());
            for (const auto& c : chunks) {
                if (is_critical(c.type)) continue;
                if (std::strcmp(c.type, "PLTE") == 0) continue;
                candidates.push_back(c);
            }
            if (candidates.empty()) break;
            std::uniform_int_distribution<size_t> idx(0, candidates.size() - 1);
            const auto& c = candidates[idx(random_gen_)];
            if (c.offset + 4 > data.size()) break;
            uint32_t new_len = static_cast<uint32_t>(random_gen_() & 0xFFu);
            writeBE32(&data[c.offset], new_len);
            break;
        }
    }
}

void StructureAwareMutation::mutatePNGInsertEXIF(MutationOutput& data) {
    if (!isPNG(data) || data.size() < 33) return;  // Need valid PNG with IHDR

    // Generate minimal valid EXIF data
    auto exif_data = png::generateMinimalEXIF();

    // Find position before IDAT chunk
    size_t insert_pos = png::findInsertPositionBeforeIDAT(data);

    // Insert eXIf chunk
    png::insertChunk(data, insert_pos, png::EXIF_TYPE, exif_data);
}

void StructureAwareMutation::mutatePNGDeletePLTE(MutationOutput& data) {
    // Delete palette chunk to test null-palette handling
    // This only affects indexed color images (color type 3)
    if (!isPNG(data) || data.size() < 33) return;

    auto chunks = png::parseChunks(data);

    // Find and delete PLTE chunk
    for (size_t i = 0; i < chunks.size(); i++) {
        if (std::strcmp(chunks[i].type, "PLTE") == 0) {
            data.erase(data.begin() + chunks[i].offset,
                      data.begin() + chunks[i].offset + chunks[i].total_size);
            return;
        }
    }
}

void StructureAwareMutation::mutatePNGData(MutationOutput& data) {
    auto chunks = png::parseChunks(data);

    // Find IDAT chunks and mutate their data
    for (const auto& chunk : chunks) {
        if (std::strcmp(chunk.type, "IDAT") == 0 && chunk.length > 0) {
            size_t data_start = chunk.offset + 8;
            size_t data_end = data_start + chunk.length;

            if (data_end <= data.size()) {
                // Random byte flip in IDAT data
                std::uniform_int_distribution<size_t> pos_dist(data_start, data_end - 1);
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= (1 << (random_gen_() % 8));
            }
            break;  // Only mutate first IDAT
        }
    }
}

void StructureAwareMutation::mutateTIFF(MutationOutput& data) {
    // TIFF has no mandatory CRC, just apply random mutations
    applyGenericMutation(data);
}

namespace {

static void appendBE16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

static void appendBE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

static uint8_t entropyByte(const std::vector<uint8_t>& entropy, size_t idx) {
    if (entropy.empty()) return 0;
    return entropy[idx % entropy.size()];
}

static std::vector<uint8_t> synthPSD(const std::vector<uint8_t>& entropy, std::mt19937& rng) {
    // Minimal PSD with either raw or PackBits RLE image data (8-bit RGB/RGBA).
    std::uniform_int_distribution<int> dim(1, 256);
    uint32_t width = static_cast<uint32_t>(dim(rng));
    uint32_t height = static_cast<uint32_t>(dim(rng));
    // Keep total pixels reasonable.
    if (width * height > 65536) {
        height = std::max<uint32_t>(1, 65536 / std::max<uint32_t>(1, width));
    }
    uint16_t channels = (rng() & 1) ? 3 : 4;
    uint16_t depth = 8;
    uint16_t color_mode = 3;  // RGB
    uint16_t compression = (rng() & 1) ? 0 : 1;  // raw or RLE

    std::vector<uint8_t> out;
    out.reserve(64 + static_cast<size_t>(width) * height * channels);

    // Header (26 bytes)
    out.push_back('8'); out.push_back('B'); out.push_back('P'); out.push_back('S');
    appendBE16(out, 1);  // version
    out.insert(out.end(), 6, 0);  // reserved
    appendBE16(out, channels);
    appendBE32(out, height);
    appendBE32(out, width);
    appendBE16(out, depth);
    appendBE16(out, color_mode);

    // Color mode data, image resources, layer/mask info: all empty.
    appendBE32(out, 0);
    appendBE32(out, 0);
    appendBE32(out, 0);

    // Image data section.
    appendBE16(out, compression);

    const size_t row_bytes = static_cast<size_t>(width);
    const size_t plane_bytes = row_bytes * static_cast<size_t>(height);

    if (compression == 0) {
        // Raw planar data.
        for (uint16_t c = 0; c < channels; ++c) {
            for (size_t i = 0; i < plane_bytes; ++i) {
                out.push_back(entropyByte(entropy, i + static_cast<size_t>(c) * 131));
            }
        }
        return out;
    }

    // PackBits RLE: write row lengths table (channels*height u16), then row data.
    const size_t table_off = out.size();
    out.resize(out.size() + static_cast<size_t>(channels) * height * 2, 0);

    size_t table_idx = 0;
    for (uint16_t c = 0; c < channels; ++c) {
        for (uint32_t y = 0; y < height; ++y) {
            // Encode this row as literal packets.
            std::vector<uint8_t> row;
            row.reserve(row_bytes + row_bytes / 128 + 8);
            size_t produced = 0;
            while (produced < row_bytes) {
                size_t chunk = std::min<size_t>(128, row_bytes - produced);
                row.push_back(static_cast<uint8_t>(chunk - 1));  // literal count-1
                for (size_t i = 0; i < chunk; ++i) {
                    size_t idx = (static_cast<size_t>(y) * row_bytes + produced + i);
                    row.push_back(entropyByte(entropy, idx + static_cast<size_t>(c) * 257));
                }
                produced += chunk;
            }

            uint16_t row_len = static_cast<uint16_t>(std::min<size_t>(row.size(), 0xFFFF));
            // Write to table (big-endian).
            size_t off = table_off + table_idx * 2;
            out[off + 0] = static_cast<uint8_t>((row_len >> 8) & 0xFF);
            out[off + 1] = static_cast<uint8_t>(row_len & 0xFF);
            table_idx++;

            out.insert(out.end(), row.begin(), row.end());
        }
    }
    return out;
}

static std::vector<uint8_t> synthHDR(const std::vector<uint8_t>& entropy, std::mt19937& rng) {
    // Minimal Radiance HDR with RLE RGBE scanlines.
    std::uniform_int_distribution<int> wdist(8, 192);
    std::uniform_int_distribution<int> hdist(1, 128);
    uint32_t width = static_cast<uint32_t>(wdist(rng));
    uint32_t height = static_cast<uint32_t>(hdist(rng));

    std::string header;
    header += "#?RADIANCE\n";
    header += "FORMAT=32-bit_rle_rgbe\n";
    header += "\n";
    header += "-Y " + std::to_string(height) + " +X " + std::to_string(width) + "\n";

    std::vector<uint8_t> out(header.begin(), header.end());

    auto emit_literal = [&](std::vector<uint8_t>& dst, const uint8_t* bytes, size_t n) {
        while (n > 0) {
            size_t chunk = std::min<size_t>(128, n);
            dst.push_back(static_cast<uint8_t>(chunk));
            dst.insert(dst.end(), bytes, bytes + chunk);
            bytes += chunk;
            n -= chunk;
        }
    };

    // Scanlines
    for (uint32_t y = 0; y < height; ++y) {
        out.push_back(0x02);
        out.push_back(0x02);
        out.push_back(static_cast<uint8_t>((width >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(width & 0xFF));

        // Prepare channel data.
        std::vector<uint8_t> chan(width);
        for (int c = 0; c < 4; ++c) {
            for (uint32_t x = 0; x < width; ++x) {
                size_t idx = (static_cast<size_t>(y) * width + x) + static_cast<size_t>(c) * 911;
                uint8_t v = entropyByte(entropy, idx);
                // Keep exponent in a reasonable range.
                if (c == 3) v = static_cast<uint8_t>(128 + (v % 64));
                chan[x] = v;
            }
            emit_literal(out, chan.data(), chan.size());
        }
    }
    return out;
}

}  // namespace

bool StructureAwareMutation::maybeSynthesizeStbImages(MutationOutput& data) {
    if (!stb_synthesis_enabled()) return false;
    if (data.empty()) return false;

    std::uniform_real_distribution<double> prob(0.0, 1.0);
    // Keep this rare: avoid harming single-format benchmarks and keep throughput.
    if (prob(random_gen_) > 0.02) return false;

    MutationOutput entropy = data;
    if ((random_gen_() & 1u) == 0) {
        data = synthPSD(entropy, random_gen_);
    } else {
        data = synthHDR(entropy, random_gen_);
    }
    return !data.empty();
}

void StructureAwareMutation::mutateJPEG(MutationOutput& data) {
    if (!isJPEG(data) || data.size() < 4) {
        applyGenericMutation(data);
        return;
    }

    // Locate SOS (Start of Scan) and mutate entropy-coded data.
    size_t pos = 2;
    size_t scan_off = 0;
    bool found_sos = false;

    while (pos + 4 <= data.size()) {
        // Find marker 0xFF.
        if (data[pos] != 0xFF) {
            ++pos;
            continue;
        }
        // Skip fill bytes.
        while (pos < data.size() && data[pos] == 0xFF) ++pos;
        if (pos >= data.size()) break;
        uint8_t marker = data[pos++];

        if (marker == 0xD9) break;  // EOI
        if (marker == 0xDA) {       // SOS
            if (pos + 1 >= data.size()) break;
            uint16_t len = readBE16(&data[pos]);
            if (len < 2 || pos + len > data.size()) break;
            pos += len;
            scan_off = pos;
            found_sos = true;
            break;
        }

        // Markers without a length.
        if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
            continue;
        }

        if (pos + 1 >= data.size()) break;
        uint16_t len = readBE16(&data[pos]);
        if (len < 2 || pos + len > data.size()) break;
        pos += len;
    }

    size_t end = data.size();
    if (end >= 2 && data[end - 2] == 0xFF && data[end - 1] == 0xD9) end -= 2;

    if (!found_sos || scan_off >= end) {
        // Fallback: mutate bytes after SOI while keeping signature.
        std::uniform_int_distribution<size_t> pos_dist(2, data.size() - 1);
        size_t iters = 1 + (random_gen_() % 8);
        for (size_t i = 0; i < iters; ++i) {
            size_t p = pos_dist(random_gen_);
            data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
        }
        return;
    }

    std::uniform_int_distribution<size_t> pos_dist(scan_off, end - 1);
    size_t iters = 1 + (random_gen_() % 16);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        uint8_t v = data[p];
        v ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
        // Avoid introducing 0xFF bytes which can create spurious markers.
        if (v == 0xFF) v ^= 0x01;
        data[p] = v;
    }
}

void StructureAwareMutation::mutateGIF(MutationOutput& data) {
    if (!isGIF(data) || data.size() < 16) {
        applyGenericMutation(data);
        return;
    }

    // Preserve header + LSD + global color table (if present) and mutate after it.
    size_t off = 13;
    uint8_t packed = data[10];
    bool has_gct = (packed & 0x80) != 0;
    if (has_gct) {
        uint8_t sz = packed & 0x07;
        size_t gct_bytes = 3u * (1u << (sz + 1u));
        if (off + gct_bytes <= data.size()) off += gct_bytes;
    }
    if (off >= data.size()) return;

    std::uniform_int_distribution<size_t> pos_dist(off, data.size() - 1);
    size_t iters = 1 + (random_gen_() % 12);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
    }
}

void StructureAwareMutation::mutateBMP(MutationOutput& data) {
    if (!isBMP(data) || data.size() < 18) {
        applyGenericMutation(data);
        return;
    }
    if (data.size() < 14) return;
    uint32_t pixel_off = (data.size() >= 14) ? readLE32(&data[10]) : 0;
    if (pixel_off >= data.size()) {
        applyGenericMutation(data);
        return;
    }
    if (pixel_off < 14) pixel_off = 14;

    std::uniform_int_distribution<size_t> pos_dist(pixel_off, data.size() - 1);
    size_t iters = 1 + (random_gen_() % 16);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
    }
}

void StructureAwareMutation::mutateTGA(MutationOutput& data) {
    if (!looksLikeTGA(data)) {
        applyGenericMutation(data);
        return;
    }
    uint8_t id_len = data[0];
    uint16_t cmap_len = readLE16(&data[5]);
    uint8_t cmap_entry_bits = data[7];
    size_t cmap_bytes = static_cast<size_t>(cmap_len) * ((cmap_entry_bits + 7u) / 8u);
    size_t pixel_off = 18u + id_len + cmap_bytes;
    if (pixel_off >= data.size()) {
        applyGenericMutation(data);
        return;
    }
    std::uniform_int_distribution<size_t> pos_dist(pixel_off, data.size() - 1);
    size_t iters = 1 + (random_gen_() % 12);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
    }
}

void StructureAwareMutation::mutatePNM(MutationOutput& data) {
    if (!isPNM(data) || data.size() < 8) {
        applyGenericMutation(data);
        return;
    }
    // Find end of ASCII header: magic + width + height + maxval (+ optional comments).
    size_t pos = 2;
    int tokens = 0;
    while (pos < data.size() && tokens < 3) {
        // Skip whitespace.
        while (pos < data.size() && (data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t')) {
            ++pos;
        }
        if (pos >= data.size()) break;
        // Skip comments.
        if (data[pos] == '#') {
            while (pos < data.size() && data[pos] != '\n') ++pos;
            continue;
        }
        // Consume a token.
        while (pos < data.size() && !(data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t')) {
            ++pos;
        }
        tokens++;
    }
    // Skip single whitespace after maxval.
    while (pos < data.size() && (data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t')) {
        ++pos;
    }
    if (pos >= data.size()) return;

    std::uniform_int_distribution<size_t> pos_dist(pos, data.size() - 1);
    size_t iters = 1 + (random_gen_() % 16);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
    }
}

void StructureAwareMutation::mutatePSD(MutationOutput& data) {
    if (!isPSD(data) || data.size() < 34) {
        applyGenericMutation(data);
        return;
    }
    // Keep signature and version stable.
    data[0] = '8'; data[1] = 'B'; data[2] = 'P'; data[3] = 'S';
    data[4] = 0;  // big-endian version
    if (data[5] != 1 && data[5] != 2) data[5] = 1;

    size_t pos = 26;
    auto read_u32_be = [&](size_t off, uint32_t& out) -> bool {
        if (off + 4 > data.size()) return false;
        out = readBE32(&data[off]);
        return true;
    };

    // Skip 3 variable-length sections.
    for (int i = 0; i < 3; ++i) {
        uint32_t len = 0;
        if (!read_u32_be(pos, len)) return;
        pos += 4;
        if (pos + len > data.size()) return;
        pos += len;
    }
    if (pos + 2 > data.size()) return;
    uint16_t comp = readBE16(&data[pos]);
    pos += 2;
    if (pos >= data.size()) return;

    // For RLE, skip row-length table if present.
    if (comp == 1) {
        if (pos + 2 > data.size()) return;
        // channels * height rows; we cap the skip to stay in-bounds.
        uint16_t channels = readBE16(&data[12]);
        uint32_t height = readBE32(&data[14]);
        size_t table = static_cast<size_t>(channels) * static_cast<size_t>(height) * 2;
        if (pos + table > data.size()) return;
        pos += table;
    }

    if (pos >= data.size()) return;
    std::uniform_int_distribution<size_t> pos_dist(pos, data.size() - 1);
    size_t iters = 1 + (random_gen_() % 24);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
    }
}

void StructureAwareMutation::mutateHDR(MutationOutput& data) {
    if (!isHDR(data) || data.size() < 16) {
        applyGenericMutation(data);
        return;
    }
    // Find the blank line separating header from pixel data.
    size_t pos = 0;
    size_t found = std::string::npos;
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        if (data[i] == '\n' && data[i + 1] == '\n') {
            found = i + 2;
            break;
        }
    }
    if (found == std::string::npos) {
        applyGenericMutation(data);
        return;
    }
    pos = found;
    if (pos >= data.size()) return;

    std::uniform_int_distribution<size_t> pos_dist(pos, data.size() - 1);
    size_t iters = 1 + (random_gen_() % 24);
    for (size_t i = 0; i < iters; ++i) {
        size_t p = pos_dist(random_gen_);
        data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
    }
}

void StructureAwareMutation::mutateOgg(MutationOutput& data) {
    if (data.size() < 27) {
        applyGenericMutation(data);
        return;
    }

    auto pages = ogg::parsePages(data);
    if (pages.empty()) {
        applyGenericMutation(data);
        return;
    }

    std::uniform_int_distribution<size_t> page_dist(0, pages.size() - 1);
    ogg::Page p = pages[page_dist(random_gen_)];

    std::uniform_int_distribution<int> op(0, 4);
    int operation = op(random_gen_);

    switch (operation) {
        case 0: {
            // Payload mutation (cheap, structure-preserving).
            if (p.body_size == 0) break;
            size_t payload_off = p.offset + p.header_size;
            size_t payload_end = payload_off + p.body_size;
            if (payload_end > data.size()) break;
            std::uniform_int_distribution<size_t> pos_dist(payload_off, payload_end - 1);
            size_t iters = 1 + (random_gen_() % 8);
            for (size_t i = 0; i < iters; ++i) {
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
            break;
        }
        case 1: {
            // Shrink a lacing value and delete bytes to keep the page consistent.
            if (p.page_segments == 0 || p.body_size == 0) break;
            size_t lace_base = p.offset + 27;
            if (lace_base + p.page_segments > data.size()) break;
            std::uniform_int_distribution<size_t> seg_dist(0, p.page_segments - 1);
            size_t seg = seg_dist(random_gen_);
            uint8_t oldv = data[lace_base + seg];
            if (oldv == 0) break;

            uint8_t dec = static_cast<uint8_t>(1 + (random_gen_() % std::min<uint32_t>(32u, oldv)));
            uint8_t newv = static_cast<uint8_t>(oldv - dec);
            data[lace_base + seg] = newv;

            size_t payload_end = p.offset + p.header_size + p.body_size;
            if (payload_end > data.size()) break;
            size_t del = static_cast<size_t>(dec);
            if (del > p.body_size) del = p.body_size;
            if (del == 0) break;
            data.erase(data.begin() + (payload_end - del), data.begin() + payload_end);
            break;
        }
        case 2: {
            // Duplicate the selected page (page-aligned splice inside the input).
            if (p.total_size == 0) break;
            if (p.offset + p.total_size > data.size()) break;
            if (data.size() + p.total_size > 65536) break;
            std::vector<uint8_t> page_bytes(data.begin() + p.offset,
                                            data.begin() + p.offset + p.total_size);
            data.insert(data.begin() + p.offset + p.total_size,
                        page_bytes.begin(), page_bytes.end());
            break;
        }
        case 3: {
            // Delete the selected page.
            if (pages.size() <= 1) break;
            if (p.offset + p.total_size > data.size()) break;
            data.erase(data.begin() + p.offset, data.begin() + p.offset + p.total_size);
            break;
        }
        case 4: {
            // Tweak header fields conservatively.
            if (p.offset + 27 > data.size()) break;
            // header_type at offset + 5
            data[p.offset + 5] ^= static_cast<uint8_t>(1u << (random_gen_() % 3));
            // page sequence number (offset + 18..21) - small delta
            uint32_t seq = readBE32(&data[p.offset + 18]);
            seq ^= (random_gen_() & 0xFFu);
            writeBE32(&data[p.offset + 18], seq);
            break;
        }
    }

    // Always fix page CRCs after mutation to preserve deep parsing.
    if (fix_checksums_) {
        ogg::fixAllCRCs(data);
    }
}

void StructureAwareMutation::mutateICC(MutationOutput& data) {
    if (!isICCProfile(data) || data.size() < 132) {
        applyGenericMutation(data);
        return;
    }

    // Ensure signature stays intact.
    data[36] = 'a';
    data[37] = 'c';
    data[38] = 's';
    data[39] = 'p';

    auto tags = icc::parseTagTable(data);
    if (tags.empty()) {
        applyGenericMutation(data);
        return;
    }

    std::uniform_int_distribution<size_t> tag_dist(0, tags.size() - 1);
    const icc::TagEntry& tag = tags[tag_dist(random_gen_)];
    size_t off = static_cast<size_t>(tag.offset);
    size_t len = static_cast<size_t>(tag.size);
    if (off + len > data.size() || len == 0) {
        applyGenericMutation(data);
        return;
    }

    std::uniform_int_distribution<int> op(0, 3);
    int operation = op(random_gen_);

    static const uint32_t kTypeSigs[] = {
        0x63757276u, // curv
        0x70617261u, // para
        0x58595A20u, // XYZ␠
        0x64657363u, // desc
        0x74657874u, // text
        0x6D667431u, // mft1
        0x6D667432u, // mft2
        0x6D414220u, // mAB␠
        0x6D424120u, // mBA␠
    };

    static const uint32_t kTagSigs[] = {
        0x64657363u, // desc
        0x77747074u, // wtpt
        0x63505254u, // cPRT
        0x7258595Au, // rXYZ
        0x6758595Au, // gXYZ
        0x6258595Au, // bXYZ
        0x41324230u, // A2B0
        0x42324130u, // B2A0
        0x63686164u, // chad
        0x76636774u, // vcgt
    };

    switch (operation) {
        case 0: {
            // Mutate tag payload bytes (in-place).
            std::uniform_int_distribution<size_t> pos_dist(off, off + len - 1);
            size_t iters = 1 + (random_gen_() % 16);
            for (size_t i = 0; i < iters; ++i) {
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
            break;
        }
        case 1: {
            // Change tag type signature (first 4 bytes inside tag data).
            if (len >= 4) {
                uint32_t t = kTypeSigs[random_gen_() % (sizeof(kTypeSigs) / sizeof(kTypeSigs[0]))];
                writeBE32(&data[off], t);
            }
            break;
        }
        case 2: {
            // Mutate ICC header fields (device class / colorspace / PCS).
            static const uint32_t kDevClasses[] = {
                0x6D6E7472u, // mntr
                0x73636E72u, // scnr
                0x70727472u, // prtr
                0x6C696E6Bu, // link
                0x73706163u, // spac
                0x61627374u, // abst
            };
            static const uint32_t kColorSpaces[] = {
                0x52474220u, // RGB␠
                0x434D594Bu, // CMYK
                0x47524159u, // GRAY
                0x4C414220u, // LAB␠
                0x58595A20u, // XYZ␠
            };
            uint32_t dev = kDevClasses[random_gen_() % (sizeof(kDevClasses) / sizeof(kDevClasses[0]))];
            uint32_t cs = kColorSpaces[random_gen_() % (sizeof(kColorSpaces) / sizeof(kColorSpaces[0]))];
            uint32_t pcs = (random_gen_() & 1) ? 0x58595A20u : 0x4C414220u; // XYZ␠ or LAB␠
            if (data.size() >= 24) {
                writeBE32(&data[12], dev);
                writeBE32(&data[16], cs);
                writeBE32(&data[20], pcs);
            }
            break;
        }
        case 3: {
            // Mutate tag signature in the tag table entry for the selected tag.
            // Find its table entry by matching offset+size.
            uint32_t count = icc::readU32BE(data, 128);
            size_t max_count = (data.size() - 132) / 12;
            if (count > max_count) count = static_cast<uint32_t>(max_count);
            for (uint32_t i = 0; i < count; ++i) {
                size_t base = 132 + static_cast<size_t>(i) * 12;
                uint32_t eoff = icc::readU32BE(data, base + 4);
                uint32_t esz = icc::readU32BE(data, base + 8);
                if (eoff == tag.offset && esz == tag.size) {
                    uint32_t newsig = kTagSigs[random_gen_() % (sizeof(kTagSigs) / sizeof(kTagSigs[0]))];
                    icc::writeU32BE(data, base + 0, newsig);
                    break;
                }
            }
            break;
        }
    }

    // Keep profile size consistent.
    icc::writeU32BE(data, 0, static_cast<uint32_t>(data.size()));
}

void StructureAwareMutation::mutateASN1(MutationOutput& data) {
    if (data.size() < 2) {
        applyGenericMutation(data);
        return;
    }

    struct Node {
        size_t off = 0;
        size_t tag_len = 0;
        size_t len_len = 0;
        size_t len = 0;
        uint8_t tag0 = 0;
        bool constructed = false;
        int parent = -1;
    };

    auto parse_tag_len = [&](size_t off, size_t& out_tag_len, uint8_t& out_tag0) -> bool {
        if (off >= data.size()) return false;
        out_tag0 = data[off];
        out_tag_len = 1;
        if ((out_tag0 & 0x1F) == 0x1F) {
            // High-tag-number form: consume continuation bytes.
            size_t p = off + 1;
            for (int i = 0; i < 4 && p < data.size(); ++i, ++p) {
                out_tag_len++;
                if ((data[p] & 0x80) == 0) break;
            }
        }
        return off + out_tag_len <= data.size();
    };

    std::vector<Node> nodes;
    nodes.reserve(128);

    struct Range {
        size_t start;
        size_t end;
        int parent;
    };
    std::vector<Range> stack;
    stack.push_back({0, data.size(), -1});

    while (!stack.empty()) {
        Range r = stack.back();
        stack.pop_back();
        size_t pos = r.start;
        while (pos < r.end) {
            size_t tag_len = 0;
            uint8_t tag0 = 0;
            if (!parse_tag_len(pos, tag_len, tag0)) break;
            size_t len = 0;
            size_t len_len = 0;
            if (!readDerLength(data, pos + tag_len, len, len_len)) break;
            size_t header = tag_len + len_len;
            if (pos + header + len > r.end) break;

            Node n;
            n.off = pos;
            n.tag_len = tag_len;
            n.len_len = len_len;
            n.len = len;
            n.tag0 = tag0;
            n.constructed = (tag0 & 0x20) != 0;
            n.parent = r.parent;
            int idx = static_cast<int>(nodes.size());
            nodes.push_back(n);

            if (n.constructed && n.len > 0) {
                stack.push_back({pos + header, pos + header + len, idx});
            }

            pos += header + len;
        }
    }

    // Choose a primitive node with non-empty payload.
    std::vector<size_t> prim;
    prim.reserve(nodes.size());
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (!nodes[i].constructed && nodes[i].len > 0) prim.push_back(i);
    }
    if (prim.empty()) {
        applyGenericMutation(data);
        return;
    }

    std::uniform_int_distribution<size_t> pick(0, prim.size() - 1);
    const Node& n = nodes[prim[pick(random_gen_)]];
    size_t payload_off = n.off + n.tag_len + n.len_len;
    size_t payload_end = payload_off + n.len;
    if (payload_end > data.size() || payload_off >= payload_end) {
        applyGenericMutation(data);
        return;
    }

    std::uniform_int_distribution<int> op(0, 2);
    int operation = op(random_gen_);
    std::uniform_int_distribution<size_t> pos_dist(payload_off, payload_end - 1);

    switch (operation) {
        case 0: {
            // Bit flips.
            size_t iters = 1 + (random_gen_() % 8);
            for (size_t i = 0; i < iters; ++i) {
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
            break;
        }
        case 1: {
            // Interesting byte values.
            size_t iters = 1 + (random_gen_() % 6);
            for (size_t i = 0; i < iters; ++i) {
                size_t pos = pos_dist(random_gen_);
                static const uint8_t kVals[] = {0x00, 0x01, 0x7F, 0x80, 0xFF};
                data[pos] = kVals[random_gen_() % (sizeof(kVals) / sizeof(kVals[0]))];
            }
            break;
        }
        default: {
            // Type-aware small tweaks for INTEGER/OID/BitString.
            uint8_t tagnum = static_cast<uint8_t>(n.tag0 & 0x1F);
            if (tagnum == 0x02) {  // INTEGER
                size_t pos = payload_off;
                data[pos] ^= 0x80; // flip sign bit
            } else if (tagnum == 0x03) {  // BIT STRING
                if (payload_off < payload_end) {
                    data[payload_off] = static_cast<uint8_t>(random_gen_() % 8); // unused bits count
                }
            } else if (tagnum == 0x06) {  // OID
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= static_cast<uint8_t>(random_gen_() & 0x7F);
            } else {
                size_t pos = pos_dist(random_gen_);
                data[pos] ^= static_cast<uint8_t>(random_gen_() & 0xFF);
            }
            break;
        }
    }
}

void StructureAwareMutation::mutateDTLS(MutationOutput& data) {
    if (data.size() < 13) {
        applyGenericMutation(data);
        return;
    }

    struct Rec {
        size_t off;
        size_t header = 13;
        uint16_t len;
    };
    std::vector<Rec> recs;
    size_t pos = 0;
    while (pos + 13 <= data.size()) {
        uint16_t len = readBE16(&data[pos + 11]);
        size_t payload_off = pos + 13;
        if (payload_off > data.size()) break;
        if (payload_off + len > data.size()) {
            // Clamp and fix length.
            len = static_cast<uint16_t>(data.size() - payload_off);
            writeBE16(&data[pos + 11], len);
        }
        recs.push_back({pos, 13, len});
        pos = payload_off + len;
        if (len == 0) break;
    }

    if (recs.empty()) {
        applyGenericMutation(data);
        return;
    }

    std::uniform_int_distribution<size_t> rec_dist(0, recs.size() - 1);
    Rec r = recs[rec_dist(random_gen_)];
    size_t payload_off = r.off + r.header;
    if (payload_off + r.len > data.size()) {
        applyGenericMutation(data);
        return;
    }

    const bool is_handshake_rec = (data[r.off] == 22) && (r.len >= 12);
    int operation = 0;
    if (is_handshake_rec) {
        // Bias toward handshake-aware mutations: they are much more likely to
        // reach deep DTLS/X.509 parsing compared to random byte flips.
        std::uniform_int_distribution<int> op(0, 5);
        operation = op(random_gen_);
    } else {
        std::uniform_int_distribution<int> op(0, 2);
        operation = op(random_gen_);
    }
    switch (operation) {
        case 0: {
            // Mutate record payload.
            if (r.len == 0) break;
            std::uniform_int_distribution<size_t> pos_dist(payload_off, payload_off + r.len - 1);
            size_t iters = 1 + (random_gen_() % 8);
            for (size_t i = 0; i < iters; ++i) {
                size_t p = pos_dist(random_gen_);
                data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
            break;
        }
        case 1: {
            // Flip content type among common DTLS values.
            static const uint8_t kTypes[] = {20, 21, 22, 23}; // change_cipher_spec, alert, handshake, app_data
            data[r.off] = kTypes[random_gen_() % (sizeof(kTypes) / sizeof(kTypes[0]))];
            break;
        }
        case 2: {
            // Ensure DTLS version looks valid.
            data[r.off + 1] = 0xFE;
            data[r.off + 2] = (random_gen_() & 1) ? 0xFD : 0xFF;
            break;
        }
        case 3:
        case 4:
        case 5: {
            // Handshake-aware DTLS mutation: parse handshake messages and mutate
            // both headers and inner certificate data while keeping lengths sane.
            if (!is_handshake_rec) break;

            struct HS {
                size_t off = 0;            // handshake header offset in data
                uint8_t type = 0;          // msg_type
                size_t msg_len = 0;        // 24-bit
                uint16_t msg_seq = 0;      // message_seq
                size_t frag_off = 0;       // 24-bit
                size_t frag_len = 0;       // 24-bit (clamped)
                size_t frag_data_off = 0;  // start of fragment bytes
            };

            auto read_u24 = [&](size_t off) -> size_t {
                if (off + 3 > data.size()) return 0;
                return (static_cast<size_t>(data[off]) << 16) |
                       (static_cast<size_t>(data[off + 1]) << 8) |
                       static_cast<size_t>(data[off + 2]);
            };
            auto write_u24 = [&](size_t off, size_t v) {
                if (off + 3 > data.size()) return;
                v &= 0xFFFFFFu;
                data[off] = static_cast<uint8_t>((v >> 16) & 0xFF);
                data[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
                data[off + 2] = static_cast<uint8_t>(v & 0xFF);
            };

            std::vector<HS> msgs;
            msgs.reserve(8);
            const size_t end = payload_off + r.len;
            size_t p = payload_off;
            while (p + 12 <= end) {
                HS m;
                m.off = p;
                m.type = data[p + 0];
                m.msg_len = read_u24(p + 1);
                m.msg_seq = readBE16(&data[p + 4]);
                m.frag_off = read_u24(p + 6);
                m.frag_len = read_u24(p + 9);
                m.frag_data_off = p + 12;
                if (m.frag_data_off > end) break;

                size_t avail = end - m.frag_data_off;
                if (m.frag_len > avail) m.frag_len = avail;
                // Avoid impossible offsets/lengths.
                if (m.frag_off > m.msg_len) m.frag_off = 0;
                if (m.msg_len > 0 && m.frag_off + m.frag_len > m.msg_len) {
                    m.frag_len = (m.frag_off < m.msg_len) ? (m.msg_len - m.frag_off) : 0;
                }

                msgs.push_back(m);
                p = m.frag_data_off + m.frag_len;
                if (m.frag_len == 0) break;
            }

            if (msgs.empty()) break;
            std::uniform_int_distribution<size_t> msg_dist(0, msgs.size() - 1);
            HS m = msgs[msg_dist(random_gen_)];

            // Keep header fields consistent with the clamped parse.
            write_u24(m.off + 6, m.frag_off);
            write_u24(m.off + 9, m.frag_len);

            const size_t frag_start = m.frag_data_off;
            const size_t frag_end = m.frag_data_off + m.frag_len;
            if (frag_end > data.size() || frag_start >= frag_end) break;

            if (operation == 3) {
                // Mutate handshake type among common server-to-client messages.
                static const uint8_t kHsTypes[] = {
                    2,   // server_hello
                    3,   // hello_verify_request (DTLS)
                    11,  // certificate
                    12,  // server_key_exchange
                    13,  // certificate_request
                    14,  // server_hello_done
                    20,  // finished
                };
                data[m.off + 0] = kHsTypes[random_gen_() % (sizeof(kHsTypes) / sizeof(kHsTypes[0]))];
                // Small perturbation of message_seq.
                if ((random_gen_() & 1u) == 0) {
                    uint16_t seq = readBE16(&data[m.off + 4]);
                    seq ^= static_cast<uint16_t>(1u << (random_gen_() % 8));
                    writeBE16(&data[m.off + 4], seq);
                }
                break;
            }

            if (operation == 5) {
                // Fragmentation-focused tweak: explore reassembly code paths.
                size_t msg_len = m.msg_len;
                if (msg_len == 0) msg_len = m.frag_len;

                size_t new_off = (random_gen_() % 3 == 0) ? 0 : (random_gen_() % std::min<size_t>(msg_len + 1, 1024));
                if (new_off > msg_len) new_off = 0;

                size_t max_flen = msg_len > new_off ? (msg_len - new_off) : 0;
                size_t avail = frag_end - frag_start;
                size_t new_len = std::min(max_flen, avail);
                if (new_len > 0) {
                    // Sometimes shrink fragment_length to create partial fragments.
                    if ((random_gen_() % 3) != 0) new_len = 1 + (random_gen_() % new_len);
                }
                write_u24(m.off + 6, new_off);
                write_u24(m.off + 9, new_len);
                break;
            }

            // operation == 4: certificate-aware mutation when possible.
            if (m.type == 11 && m.frag_off == 0 && (frag_end - frag_start) >= 6) {
                size_t list_len = read_u24(frag_start);
                size_t list_start = frag_start + 3;
                size_t max_list_end = frag_end;
                if (list_start + list_len < max_list_end) max_list_end = list_start + list_len;

                struct CertEntry {
                    size_t off;
                    size_t len;
                };
                std::vector<CertEntry> certs;
                for (size_t q = list_start; q + 3 <= max_list_end;) {
                    size_t clen = read_u24(q);
                    q += 3;
                    if (q + clen > max_list_end) break;
                    if (clen >= 2) certs.push_back({q, clen});
                    q += clen;
                    if (certs.size() >= 8) break;
                }

                if (!certs.empty()) {
                    std::uniform_int_distribution<size_t> cd(0, certs.size() - 1);
                    CertEntry ce = certs[cd(random_gen_)];
                    if (ce.off + ce.len <= data.size()) {
                        std::vector<uint8_t> cert(data.begin() + static_cast<std::ptrdiff_t>(ce.off),
                                                  data.begin() + static_cast<std::ptrdiff_t>(ce.off + ce.len));
                        std::vector<uint8_t> orig = cert;
                        mutateASN1(cert);
                        if (cert.size() != orig.size()) {
                            size_t mutated_size = cert.size();
                            cert.resize(orig.size());
                            if (mutated_size < orig.size()) {
                                std::copy(orig.begin() + static_cast<std::ptrdiff_t>(mutated_size),
                                          orig.end(),
                                          cert.begin() + static_cast<std::ptrdiff_t>(mutated_size));
                            }
                        }
                        std::copy(cert.begin(), cert.end(), data.begin() + static_cast<std::ptrdiff_t>(ce.off));
                        break;
                    }
                }
            }

            // Fallback: mutate inside the fragment payload.
            std::uniform_int_distribution<size_t> pos_dist(frag_start, frag_end - 1);
            size_t iters = 1 + (random_gen_() % 8);
            for (size_t i = 0; i < iters; ++i) {
                size_t pp = pos_dist(random_gen_);
                data[pp] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
            break;
        }
    }
}

void StructureAwareMutation::mutateRE2(MutationOutput& data) {
    // re2_fuzzer constraints: if (size < 3 || size > 64) return 0.
    // Keep the payload small and regex-like to reach deeper parser/NFA code.
    if (data.size() < 3) {
        size_t old = data.size();
        data.resize(3);
        for (size_t i = old; i < 3; ++i) {
            data[i] = static_cast<uint8_t>('a' + (random_gen_() % 26));
        }
    }
    if (data.size() > 64) data.resize(64);

    // Flags live in data[1] (the harness effectively ignores data[0]).
    // Reduce the chance of "literal" mode, which bypasses most regex parsing.
    uint8_t flags = data[1];
    if ((random_gen_() % 4) != 0) flags = static_cast<uint8_t>(flags & ~0x08u);
    static const uint8_t kBits[] = {0x01, 0x02, 0x04, 0x10, 0x20, 0x40, 0x80, 0x08};
    flags ^= kBits[random_gen_() % (sizeof(kBits) / sizeof(kBits[0]))];
    if ((random_gen_() % 8) != 0) flags = static_cast<uint8_t>(flags & ~0x08u);
    data[1] = flags;

    auto gen_pattern = [&](size_t max_len) -> std::string {
        static const char* kAtoms[] = {
            "a",
            "b",
            "c",
            ".",
            "[a-z]",
            "[0-9]",
            "\\d",
            "\\w",
            "\\s",
            "\\D",
            "\\W",
            "\\S",
        };
        static const char* kQuants[] = {"", "?", "*", "+", "{0,1}", "{1,2}", "{0,3}"};

        std::string out;
        if ((random_gen_() & 3u) == 0 && out.size() + 1 <= max_len) out.push_back('^');

        int parts = 1 + static_cast<int>(random_gen_() % 8);
        for (int i = 0; i < parts; ++i) {
            if (!out.empty() && (random_gen_() % 6) == 0 && out.size() + 1 <= max_len) out.push_back('|');

            const char* atom = kAtoms[random_gen_() % (sizeof(kAtoms) / sizeof(kAtoms[0]))];
            std::string a(atom);
            if ((random_gen_() % 8) == 0 && out.size() + a.size() + 2 <= max_len) {
                a = "(" + a + ")";
            }

            const char* q = kQuants[random_gen_() % (sizeof(kQuants) / sizeof(kQuants[0]))];
            std::string qs(q);

            if (out.size() + a.size() > max_len) break;
            out += a;
            if (out.size() + qs.size() <= max_len) out += qs;
            if (out.size() >= max_len) break;
        }

        if ((random_gen_() & 3u) == 0 && out.size() + 1 <= max_len) out.push_back('$');
        if (out.empty()) out = "a";
        return out;
    };

    constexpr size_t kPayloadOff = 2;
    constexpr size_t kMaxPayload = 62;
    size_t payload_len = data.size() > kPayloadOff ? (data.size() - kPayloadOff) : 0;
    if (payload_len == 0) {
        data.resize(3);
        data[2] = 'a';
        payload_len = 1;
    }

    std::uniform_int_distribution<int> op(0, 4);
    int operation = op(random_gen_);
    switch (operation) {
        case 0: {
            // Full regeneration (high chance of valid regex).
            std::string pat = gen_pattern(kMaxPayload);
            size_t n = std::min(pat.size(), kMaxPayload);
            data.resize(kPayloadOff + n);
            std::memcpy(&data[kPayloadOff], pat.data(), n);
            break;
        }
        case 1: {
            // Token insertion/replacement.
            static const char* kTokens[] = {"(", ")", "[a-z]", "[0-9]", "|", ".", ".*", ".+", "\\d+", "\\w+", "^", "$"};
            std::string tok = kTokens[random_gen_() % (sizeof(kTokens) / sizeof(kTokens[0]))];
            if (payload_len == 0) break;
            std::uniform_int_distribution<size_t> pos_dist(0, payload_len - 1);
            size_t pos = pos_dist(random_gen_);
            size_t tok_len = tok.size();

            if (payload_len + tok_len <= kMaxPayload && (random_gen_() & 1u)) {
                data.insert(data.begin() + static_cast<std::ptrdiff_t>(kPayloadOff + pos), tok.begin(), tok.end());
                if (data.size() > 64) data.resize(64);
            } else {
                // Replace in-place.
                for (size_t i = 0; i < tok_len && pos + i < payload_len; ++i) {
                    data[kPayloadOff + pos + i] = static_cast<uint8_t>(tok[i]);
                }
            }
            break;
        }
        case 2: {
            // Gentle byte tweaks within printable/meta space.
            if (payload_len == 0) break;
            static const uint8_t kChars[] = {
                'a', 'b', 'c', 'x', 'y', 'z', '0', '1', '9',
                '.', '*', '+', '?', '|', '(', ')', '[', ']', '{', '}', '^', '$', '\\',
            };
            std::uniform_int_distribution<size_t> pos_dist(0, payload_len - 1);
            size_t iters = 1 + (random_gen_() % 6);
            for (size_t i = 0; i < iters; ++i) {
                size_t p = pos_dist(random_gen_);
                data[kPayloadOff + p] = kChars[random_gen_() % (sizeof(kChars) / sizeof(kChars[0]))];
            }
            break;
        }
        case 3: {
            // Deletion (keep above minimum size).
            if (payload_len <= 1) break;
            std::uniform_int_distribution<size_t> pos_dist(0, payload_len - 1);
            size_t pos = pos_dist(random_gen_);
            data.erase(data.begin() + static_cast<std::ptrdiff_t>(kPayloadOff + pos));
            if (data.size() < 3) data.resize(3, 'a');
            break;
        }
        default: {
            // Fallback: small generic mutations but clamped to size limits.
            size_t iters = 1 + (random_gen_() % 4);
            for (size_t i = 0; i < iters; ++i) {
                applyGenericMutation(data);
                if (data.size() < 3) data.resize(3, 'a');
                if (data.size() > 64) data.resize(64);
            }
            break;
        }
    }

    // Final clamp.
    if (data.size() < 3) data.resize(3, 'a');
    if (data.size() > 64) data.resize(64);
}

void StructureAwareMutation::mutateFont(MutationOutput& data) {
    if (data.size() < 16) {
        applyGenericMutation(data);
        return;
    }

    if (isSFNT(data)) {
        // Parse sfnt offset table + table records.
        if (data.size() < 12) return;
        uint16_t numTables = readBE16(&data[4]);
        size_t maxTables = (data.size() - 12) / 16;
        if (numTables > maxTables) numTables = static_cast<uint16_t>(maxTables);
        if (numTables == 0) return;

        std::uniform_int_distribution<uint16_t> td(0, numTables - 1);
        uint16_t t = td(random_gen_);
        size_t rec = 12 + static_cast<size_t>(t) * 16;
        if (rec + 16 > data.size()) return;

        uint32_t offset = readBE32(&data[rec + 8]);
        uint32_t length = readBE32(&data[rec + 12]);
        if (offset >= data.size()) return;
        if (length == 0) return;
        if (static_cast<size_t>(offset) + static_cast<size_t>(length) > data.size()) return;

        // Mutate within the table data and update its stored checksum.
        std::uniform_int_distribution<size_t> pos_dist(static_cast<size_t>(offset),
                                                       static_cast<size_t>(offset) + static_cast<size_t>(length) - 1);
        size_t iters = 1 + (random_gen_() % 8);
        for (size_t i = 0; i < iters; ++i) {
            size_t p = pos_dist(random_gen_);
            data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
        }

        uint32_t csum = sfntChecksum(&data[offset], length);
        writeBE32(&data[rec + 4], csum);
        return;
    }

    if (isWOFF2(data)) {
        // WOFF2 header is 48 bytes; keep it mostly intact and clamp obvious fields.
        if (data.size() >= 12) {
            // length field at offset 8
            writeBE32(&data[8], static_cast<uint32_t>(data.size()));
        }
        auto clamp_off = [&](size_t off) {
            if (off + 4 > data.size()) return;
            uint32_t v = readBE32(&data[off]);
            if (v >= data.size()) writeBE32(&data[off], 0);
        };
        clamp_off(28); // metaOffset
        clamp_off(40); // privOffset

        if (data.size() > 48) {
            std::uniform_int_distribution<size_t> pos_dist(48, data.size() - 1);
            size_t iters = 1 + (random_gen_() % 4);
            for (size_t i = 0; i < iters; ++i) {
                size_t p = pos_dist(random_gen_);
                data[p] ^= static_cast<uint8_t>(1u << (random_gen_() % 8));
            }
        }
        return;
    }

    // WOFF1 or unknown font container: fallback to gentle generic mutation.
    applyGenericMutation(data);
}

void StructureAwareMutation::applyGenericMutation(MutationOutput& data) {
    if (data.empty()) return;

    std::uniform_int_distribution<int> op(0, 4);
    std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);

    switch (op(random_gen_)) {
        case 0: {
            // Bit flip
            size_t pos = pos_dist(random_gen_);
            data[pos] ^= (1 << (random_gen_() % 8));
            break;
        }
        case 1: {
            // Byte replacement with interesting value
            if (data.size() >= 4) {
                size_t pos = random_gen_() % (data.size() - 3);
                uint32_t val = png::OVERFLOW_VALUES[random_gen_() %
                    (sizeof(png::OVERFLOW_VALUES) / sizeof(png::OVERFLOW_VALUES[0]))];
                writeBE32(&data[pos], val);
            }
            break;
        }
        case 2: {
            // Random byte
            size_t pos = pos_dist(random_gen_);
            data[pos] = random_gen_() & 0xFF;
            break;
        }
        case 3: {
            // Delete byte
            if (data.size() > 1) {
                size_t pos = pos_dist(random_gen_);
                data.erase(data.begin() + pos);
            }
            break;
        }
        case 4: {
            // Insert byte
            size_t pos = pos_dist(random_gen_);
            data.insert(data.begin() + pos, random_gen_() & 0xFF);
            break;
        }
    }
}

void StructureAwareMutation::saveState(StateWriter& writer) const {
    // Save mutation weights
}

void StructureAwareMutation::loadState(StateReader& reader) {
    // Load mutation weights
}

void StructureAwareMutation::onParametersUpdated() {
    // Update from parameters
}

//=============================================================================
// GenericStructureAnalyzer Implementation
//=============================================================================

GenericStructureAnalyzer::GenericStructureAnalyzer() {
    // Register format parsers
}

StructureTemplate GenericStructureAnalyzer::analyzeStructure(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = detectDataType(data);

    switch (tmpl.type) {
        case DataStructureType::FILE_FORMAT:
            if (isPNG(data)) {
                // Parse PNG structure
                auto chunks = png::parseChunks(data);
                for (const auto& chunk : chunks) {
                    FieldInfo field;
                    field.offset = chunk.offset;
                    field.length = chunk.total_size;
                    field.name = chunk.type;
                    field.type = "chunk";
                    tmpl.fields.push_back(field);
                }
                tmpl.checksum_fixer = [](std::vector<uint8_t>& d) {
                    png::fixAllCRCs(d);
                };
            }
            break;
        default:
            break;
    }

    return tmpl;
}

bool GenericStructureAnalyzer::validateStructure(const std::vector<uint8_t>& data,
                                                  const StructureTemplate& tmpl) {
    // Basic validation
    return !data.empty();
}

void GenericStructureAnalyzer::fixStructure(std::vector<uint8_t>& data,
                                            const StructureTemplate& tmpl) {
    if (tmpl.checksum_fixer) {
        tmpl.checksum_fixer(data);
    }
    if (tmpl.length_fixer) {
        tmpl.length_fixer(data);
    }
}

DataStructureType GenericStructureAnalyzer::detectDataType(const std::vector<uint8_t>& data) {
    if (isPNG(data) || isTIFF(data)) {
        return DataStructureType::FILE_FORMAT;
    }
    if (isZIP(data) || isGZIP(data)) {
        return DataStructureType::FILE_FORMAT;
    }
    if (isELF(data)) {
        return DataStructureType::FILE_FORMAT;
    }

    // Check for text formats
    if (data.size() > 0 && (data[0] == '{' || data[0] == '[')) {
        return DataStructureType::JSON;
    }
    if (data.size() > 0 && data[0] == '<') {
        return DataStructureType::XML;
    }

    return DataStructureType::UNKNOWN;
}

StructureTemplate GenericStructureAnalyzer::parseJSON(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = DataStructureType::JSON;
    return tmpl;
}

StructureTemplate GenericStructureAnalyzer::parseXML(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = DataStructureType::XML;
    return tmpl;
}

StructureTemplate GenericStructureAnalyzer::parseProtobuf(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = DataStructureType::PROTOBUF;
    return tmpl;
}

StructureTemplate GenericStructureAnalyzer::parseTLV(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = DataStructureType::TLV;
    return tmpl;
}

StructureTemplate GenericStructureAnalyzer::parsePacket(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = DataStructureType::PACKET;
    return tmpl;
}

StructureTemplate GenericStructureAnalyzer::parseCustomBinary(const std::vector<uint8_t>& data) {
    StructureTemplate tmpl;
    tmpl.type = DataStructureType::CUSTOM_BINARY;
    return tmpl;
}

std::vector<size_t> GenericStructureAnalyzer::findLengthFields(const std::vector<uint8_t>& data) {
    return {};
}

std::vector<size_t> GenericStructureAnalyzer::findChecksumFields(const std::vector<uint8_t>& data) {
    return {};
}

std::vector<size_t> GenericStructureAnalyzer::findStringFields(const std::vector<uint8_t>& data) {
    return {};
}

} // namespace triofuzz
