#include "../../../include/algorithms/mutation/format_aware_mutation.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <random>

namespace triofuzz {

FormatAwareMutation::FileFormat FormatAwareMutation::detectFormat(const std::vector<uint8_t>& input) const {
    if (input.size() < 4) return FileFormat::UNKNOWN;

    if (input[0] == 'O' && input[1] == 'g' && input[2] == 'g' && input[3] == 'S') {
        return FileFormat::OGG;
    }

    if (input.size() >= 7 &&
        (input[0] == 0x01 || input[0] == 0x03 || input[0] == 0x05) &&
        input[1] == 'v' && input[2] == 'o' && input[3] == 'r' &&
        input[4] == 'b' && input[5] == 'i' && input[6] == 's') {
        return FileFormat::VORBIS;
    }

    if (input.size() >= 48 &&
        input[0] == 0x77 && input[1] == 0x4F &&
        input[2] == 0x46 && input[3] == 0x32) {
        return FileFormat::WOFF2;
    }

    if (input.size() >= 44 &&
        input[0] == 0x77 && input[1] == 0x4F &&
        input[2] == 0x46 && input[3] == 0x46) {
        return FileFormat::WOFF;
    }

    if (input.size() >= 8 &&
        input[0] == 0x89 && input[1] == 0x50 && input[2] == 0x4E && input[3] == 0x47) {
        return FileFormat::PNG;
    }

    if (input[0] == 0xFF && input[1] == 0xD8 && input[2] == 0xFF) {
        return FileFormat::JPEG;
    }

    if (input[0] == 0x42 && input[1] == 0x4D) {
        return FileFormat::BMP;
    }

    if (input.size() >= 6 &&
        input[0] == 0x47 && input[1] == 0x49 && input[2] == 0x46) {
        return FileFormat::GIF;
    }

    if (input.size() >= 4 &&
        input[0] == 0x25 && input[1] == 0x50 && input[2] == 0x44 && input[3] == 0x46) {
        return FileFormat::PDF;
    }

    bool is_text = true;
    for (size_t i = 0; i < std::min(size_t(512), input.size()); i++) {
        if (input[i] < 0x20 && input[i] != '\n' && input[i] != '\r' && input[i] != '\t') {
            is_text = false;
            break;
        }
    }

    if (is_text && input.size() > 0) {
        constexpr size_t kMaxTextScan = 4096;
        std::string start(input.begin(), input.begin() + std::min(kMaxTextScan, input.size()));

        if (start.find("<?xml") != std::string::npos ||
            start.find("<!DOCTYPE") != std::string::npos ||
            start.find("<html") != std::string::npos) {
            return FileFormat::XML;
        }

        size_t first_non_space = start.find_first_not_of(" \t\r\n");
        if (first_non_space != std::string::npos) {
            char first_char = start[first_non_space];
            if (first_char == '{' || first_char == '[') {
                return FileFormat::JSON;
            }
        }

        {
            std::string lower = start;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            static constexpr const char* kSqlKeywords[] = {
                "select", "create", "insert", "update", "delete", "pragma",
                "with", "alter", "drop", "vacuum", "attach", "detach",
                "window", "over", "rtree", "fts5",
                "execsql", "do_execsql_test", "do_catchsql_test", "do_test", "run_test_suite"
            };

            for (const char* kw : kSqlKeywords) {
                if (lower.find(kw) != std::string::npos) {
                    return FileFormat::SQL;
                }
            }
        }

        if (start.find("---") == 0 ||
            (start.find(":") != std::string::npos && start.find("\n") != std::string::npos)) {
            return FileFormat::YAML;
        }
    }

    return FileFormat::UNKNOWN;
}

MutationOutput FormatAwareMutation::execute(
    const MutationInput& input,
    SharedContext& context) {

    if (input.empty()) {
        return input;
    }

    FileFormat format = detectFormat(input);

    switch (format) {
        case FileFormat::OGG:
            return mutateOGG(input);
        case FileFormat::VORBIS:
            return mutateVORBIS(input);
        case FileFormat::PNG:
            return mutatePNG(input);
        case FileFormat::JPEG:
            return mutateJPEG(input);
        case FileFormat::WOFF2:
        case FileFormat::WOFF:
            return mutateFont(input);
        case FileFormat::XML:
            return mutateXML(input);
        case FileFormat::JSON:
            return mutateJSON(input);
        case FileFormat::SQL:
            return mutateSQL(input);
        default:
            return mutateGeneric(input);
    }
}

namespace {

struct OggPageView {
    size_t offset = 0;
    size_t header_size = 0;
    size_t body_size = 0;
    size_t total_size = 0;
    uint8_t page_segments = 0;
};

static inline uint32_t readLE32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

static inline void writeLE32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static inline uint64_t readLE64(const uint8_t* p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) v |= (uint64_t(p[i]) << (i * 8));
    return v;
}

static inline void writeLE64(uint8_t* p, uint64_t v) {
    for (size_t i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
}

static uint32_t ogg_crc32(const uint8_t* data, size_t len) {
    static const std::array<uint32_t, 256> table = []() {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t r = i << 24;
            for (int j = 0; j < 8; ++j) {
                if (r & 0x80000000U) r = (r << 1) ^ 0x04C11DB7U;
                else r <<= 1;
            }
            t[i] = r;
        }
        return t;
    }();

    uint32_t crc = 0;
    for (size_t i = 0; i < len; ++i) {
        crc = (crc << 8) ^ table[((crc >> 24) & 0xFFU) ^ data[i]];
    }
    return crc;
}

static bool parseOggPage(const std::vector<uint8_t>& data, size_t off, OggPageView* out) {
    if (!out) return false;
    if (off + 27 > data.size()) return false;
    if (data[off + 0] != 'O' || data[off + 1] != 'g' || data[off + 2] != 'g' || data[off + 3] != 'S') {
        return false;
    }
    uint8_t segs = data[off + 26];
    size_t header_size = 27 + static_cast<size_t>(segs);
    if (off + header_size > data.size()) return false;
    size_t body_size = 0;
    for (size_t i = 0; i < segs; ++i) {
        body_size += data[off + 27 + i];
    }
    if (off + header_size + body_size > data.size()) return false;

    out->offset = off;
    out->page_segments = segs;
    out->header_size = header_size;
    out->body_size = body_size;
    out->total_size = header_size + body_size;
    return true;
}

static void fixOggPageCRC(std::vector<uint8_t>& data, const OggPageView& page) {
    if (page.offset + page.total_size > data.size()) return;
    if (page.offset + 26 <= data.size()) {
        data[page.offset + 22] = 0;
        data[page.offset + 23] = 0;
        data[page.offset + 24] = 0;
        data[page.offset + 25] = 0;
    }
    uint32_t crc = ogg_crc32(&data[page.offset], page.total_size);
    if (page.offset + 26 <= data.size()) {
        writeLE32(&data[page.offset + 22], crc);
    }
}

static void fixAllOggCRCs(std::vector<uint8_t>& data, size_t max_pages = 64) {
    size_t off = 0;
    size_t pages = 0;
    while (pages < max_pages) {
        OggPageView page{};
        if (!parseOggPage(data, off, &page)) break;
        fixOggPageCRC(data, page);
        off = page.offset + page.total_size;
        if (off >= data.size()) break;
        pages++;
    }
}

static constexpr size_t kNotFound = static_cast<size_t>(-1);

static size_t findVorbisIdHeader(const std::vector<uint8_t>& data, size_t max_scan = 65536) {
    const size_t n = std::min(max_scan, data.size());
    if (n < 7) return kNotFound;
    for (size_t i = 0; i + 7 <= n; ++i) {
        if (data[i] != 0x01) continue;
        if (data[i + 1] == 'v' && data[i + 2] == 'o' && data[i + 3] == 'r' &&
            data[i + 4] == 'b' && data[i + 5] == 'i' && data[i + 6] == 's') {
            return i;
        }
    }
    return kNotFound;
}

} // namespace

std::vector<uint8_t> FormatAwareMutation::mutateVORBIS(const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> result = input;
    if (result.size() < 16) return mutateGeneric(result);

    size_t off = findVorbisIdHeader(result);
    if (off == kNotFound || off + 30 > result.size()) {
        const size_t n = std::min<size_t>(65536, result.size());
        for (size_t i = 0; i + 6 <= n; ++i) {
            if (result[i] == 'v' && result[i + 1] == 'o' && result[i + 2] == 'r' &&
                result[i + 3] == 'b' && result[i + 4] == 'i' && result[i + 5] == 's') {
                size_t pos = (i > 0) ? (i - 1) : i;
                result[pos] ^= (1 << (random_gen_() % 8));
                return result;
            }
        }
        return mutateGeneric(result);
    }

    std::uniform_int_distribution<int> strategy_dist(0, 3);
    int strategy = strategy_dist(random_gen_);

    switch (strategy) {
        case 0: {
            std::uniform_int_distribution<int> ch_dist(1, 8);
            result[off + 11] = static_cast<uint8_t>(ch_dist(random_gen_));

            static constexpr uint32_t kRates[] = {8000, 11025, 16000, 22050, 32000, 44100, 48000};
            std::uniform_int_distribution<size_t> rdist(0, sizeof(kRates) / sizeof(kRates[0]) - 1);
            writeLE32(&result[off + 12], kRates[rdist(random_gen_)]);

            std::uniform_int_distribution<int> vdist(0, 9);
            writeLE32(&result[off + 7], (vdist(random_gen_) == 0) ? 1U : 0U);
            break;
        }
        case 1: {
            auto pick_exp = [&]() -> uint8_t {
                return static_cast<uint8_t>(6 + (random_gen_() % 8));
            };
            uint8_t bs0 = pick_exp();
            uint8_t bs1 = pick_exp();
            if (bs0 > bs1) std::swap(bs0, bs1);
            result[off + 28] = static_cast<uint8_t>((bs1 << 4) | (bs0 & 0x0F));
            if ((random_gen_() % 10) == 0) result[off + 29] ^= 1;
            break;
        }
        case 2: {
            std::uniform_int_distribution<uint32_t> br(0, 500000);
            writeLE32(&result[off + 16], br(random_gen_));
            writeLE32(&result[off + 20], br(random_gen_));
            writeLE32(&result[off + 24], br(random_gen_));
            break;
        }
        default: {
            std::uniform_int_distribution<size_t> pos_dist(off + 7, off + 29);
            for (int i = 0; i < 2; ++i) {
                size_t p = pos_dist(random_gen_);
                result[p] ^= (1 << (random_gen_() % 8));
            }
            break;
        }
    }

    return result;
}

std::vector<uint8_t> FormatAwareMutation::mutateOGG(const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> result = input;
    if (result.size() < 27) return mutateGeneric(result);

    std::vector<OggPageView> pages;
    pages.reserve(8);
    size_t off = 0;
    for (size_t i = 0; i < 8; ++i) {
        OggPageView page{};
        if (!parseOggPage(result, off, &page)) break;
        pages.push_back(page);
        off = page.offset + page.total_size;
        if (off >= result.size()) break;
    }
    if (pages.empty()) return mutateGeneric(result);

    std::uniform_int_distribution<int> strategy_dist(0, 2);
    int strategy = strategy_dist(random_gen_);

    std::uniform_int_distribution<size_t> page_dist(0, pages.size() - 1);
    OggPageView page = pages[page_dist(random_gen_)];

    switch (strategy) {
        case 0: {
            std::uniform_int_distribution<int> field_dist(0, 3);
            int field = field_dist(random_gen_);
            switch (field) {
                case 0:
                    result[page.offset + 5] ^= static_cast<uint8_t>(1u << (random_gen_() % 3));
                    break;
                case 1: {
                    int64_t gp = static_cast<int64_t>(readLE64(&result[page.offset + 6]));
                    int64_t delta = static_cast<int64_t>((random_gen_() % 2001) - 1000);
                    writeLE64(&result[page.offset + 6], static_cast<uint64_t>(gp + delta));
                    break;
                }
                case 2: {
                    int64_t seq = static_cast<int64_t>(readLE32(&result[page.offset + 18]));
                    int64_t delta = static_cast<int64_t>((random_gen_() % 11) - 5);
                    writeLE32(&result[page.offset + 18], static_cast<uint32_t>(seq + delta));
                    break;
                }
                default: {
                    uint32_t serial = readLE32(&result[page.offset + 14]);
                    if ((random_gen_() % 4) == 0) serial ^= (1u << (random_gen_() % 16));
                    writeLE32(&result[page.offset + 14], serial);
                    break;
                }
            }
            break;
        }
        case 1: {
            if (page.body_size > 0) {
                const size_t body_off = page.offset + page.header_size;
                std::uniform_int_distribution<size_t> pos_dist(0, page.body_size - 1);
                size_t num = 1 + (random_gen_() % 6);
                for (size_t i = 0; i < num; ++i) {
                    size_t p = body_off + pos_dist(random_gen_);
                    result[p] ^= (1 << (random_gen_() % 8));
                }
            }
            break;
        }
        default: {
            result = mutateVORBIS(result);
            break;
        }
    }

    fixAllOggCRCs(result);
    return result;
}

static uint32_t png_crc32(const uint8_t* data, size_t len) {
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

static void fixPNGChunkCRC(std::vector<uint8_t>& data, size_t chunk_offset) {
    if (chunk_offset + 8 > data.size()) return;

    uint32_t length = (data[chunk_offset] << 24) | (data[chunk_offset + 1] << 16) |
                      (data[chunk_offset + 2] << 8) | data[chunk_offset + 3];

    if (chunk_offset + 8 + length + 4 > data.size()) return;

    uint32_t crc = png_crc32(&data[chunk_offset + 4], 4 + length);

    size_t crc_offset = chunk_offset + 8 + length;
    data[crc_offset] = (crc >> 24) & 0xFF;
    data[crc_offset + 1] = (crc >> 16) & 0xFF;
    data[crc_offset + 2] = (crc >> 8) & 0xFF;
    data[crc_offset + 3] = crc & 0xFF;
}

std::vector<uint8_t> FormatAwareMutation::mutatePNG(const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> result = input;

    if (result.size() < 33) return result;

    std::uniform_int_distribution<int> strategy_dist(0, 100);
    int strategy = strategy_dist(random_gen_);

    uint32_t new_width, new_height;
    bool modify_dimensions = true;

    if (strategy < 20) {
        uint64_t target = 0xFFFFFFFFULL;
        new_width = static_cast<uint32_t>(target / 4);
        std::uniform_int_distribution<int> adj(-10, 10);
        new_width = static_cast<uint32_t>(static_cast<int64_t>(new_width) + adj(random_gen_));
        new_height = 1;

    } else if (strategy < 40) {
        uint64_t target = 0x100000000ULL;
        new_width = static_cast<uint32_t>(target / 4);
        std::uniform_int_distribution<int> adj(-5, 5);
        new_width = static_cast<uint32_t>(static_cast<int64_t>(new_width) + adj(random_gen_));
        new_height = 1;

    } else if (strategy < 60) {
        uint64_t target = 0x100000000ULL;
        new_width = static_cast<uint32_t>(target / 4);
        std::uniform_int_distribution<int> adj(-10, 10);
        new_width = static_cast<uint32_t>(static_cast<int64_t>(new_width) + adj(random_gen_));
        new_height = 1;

    } else if (strategy < 75) {
        static const uint32_t overflow_values[] = {
            0x40000000, 0x40000001, 0x3FFFFFFF, 0x3FFFFFFE,
            0x55555555, 0x55555556,
            0x80000000, 0x7FFFFFFF, 0xFFFFFFFF,
            0x20000000, 0x10000000, 0x08000000,
        };
        std::uniform_int_distribution<size_t> idx(0, sizeof(overflow_values)/sizeof(overflow_values[0]) - 1);
        new_width = overflow_values[idx(random_gen_)];
        new_height = 1;

    } else if (strategy < 85) {
        if (result.size() >= 26) {
            std::uniform_int_distribution<int> color_type_dist(0, 4);
            int ct = color_type_dist(random_gen_);
            uint8_t color_types[] = {0, 2, 3, 4, 6};
            result[25] = color_types[ct];

            if (result[25] == 3) {
                uint8_t palette_depths[] = {1, 2, 4, 8};
                std::uniform_int_distribution<size_t> depth_idx(0, 3);
                result[24] = palette_depths[depth_idx(random_gen_)];
            }
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
            fixPNGChunkCRC(result, 33);
        }
        modify_dimensions = false;

    } else {
        if (result.size() > 33) {
            std::uniform_int_distribution<size_t> pos_dist(33, result.size() - 1);
            size_t pos = pos_dist(random_gen_);
            result[pos] ^= (1 << (random_gen_() % 8));
        }
        modify_dimensions = false;
    }

    if (modify_dimensions && result.size() >= 33) {
        writeUint32BE(result.data() + 16, new_width);
        writeUint32BE(result.data() + 20, new_height);
        fixPNGChunkCRC(result, 8);
    }

    return result;
}

std::vector<uint8_t> FormatAwareMutation::mutateJPEG(const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> result = input;

    if (result.size() < 10) return result;

    std::uniform_int_distribution<int> strategy_dist(0, 3);
    int strategy = strategy_dist(random_gen_);

    switch (strategy) {
        case 0:
            {
                std::vector<uint8_t> exif_header = {
                    0xFF, 0xE1,
                    0xFF, 0xFF
                };
                result.insert(result.begin() + 2, exif_header.begin(), exif_header.end());
                std::vector<uint8_t> dummy(1000, 0xAA);
                result.insert(result.begin() + 6, dummy.begin(), dummy.end());
            }
            break;

        case 1:
            for (size_t i = 0; i < result.size() - 1; i++) {
                if (result[i] == 0xFF && result[i+1] == 0xDB) {
                    result[i+1] = 0xFF;
                    break;
                }
            }
            break;

        case 2:
            if (result.size() >= 2 && result[result.size()-2] == 0xFF && result[result.size()-1] == 0xD9) {
                result.resize(result.size() - 2);
            }
            break;

        default:
            if (result.size() > 10) {
                std::uniform_int_distribution<size_t> pos_dist(10, result.size() - 1);
                size_t pos = pos_dist(random_gen_);
                result[pos] ^= (1 << (random_gen_() % 8));
            }
    }

    return result;
}

std::vector<uint8_t> FormatAwareMutation::mutateXML(const std::vector<uint8_t>& input) const {
    std::string xml(input.begin(), input.end());

    std::uniform_int_distribution<int> strategy_dist(0, 5);
    int strategy = strategy_dist(random_gen_);

    switch (strategy) {
        case 0:
            {
                std::string deep_nest = "";
                for (int i = 0; i < 1000; i++) {
                    deep_nest += "<div>";
                }
                deep_nest += "content";
                for (int i = 0; i < 1000; i++) {
                    deep_nest += "</div>";
                }
                size_t pos = xml.find(">");
                if (pos != std::string::npos) {
                    xml.insert(pos + 1, deep_nest);
                }
            }
            break;

        case 1:
            {
                std::string entity = "&xxe; &lt;&lt;&lt; &#x0; &#xFFFF;";
                size_t pos = xml.find(">");
                if (pos != std::string::npos) {
                    xml.insert(pos + 1, entity);
                }
            }
            break;

        case 2:
            {
                size_t pos = xml.rfind("</");
                if (pos != std::string::npos) {
                    size_t end = xml.find(">", pos);
                    if (end != std::string::npos) {
                        xml.erase(pos, end - pos + 1);
                    }
                }
            }
            break;

        case 3:
            {
                std::string cdata = "<![CDATA[" + std::string(10000, 'A') + "]]>";
                size_t pos = xml.find(">");
                if (pos != std::string::npos) {
                    xml.insert(pos + 1, cdata);
                }
            }
            break;

        case 4:
            xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" + xml;
            break;

        default:
            {
                size_t pos = xml.find(">");
                if (pos != std::string::npos) {
                    xml.erase(pos, 1);
                }
            }
    }

    return std::vector<uint8_t>(xml.begin(), xml.end());
}

std::vector<uint8_t> FormatAwareMutation::mutateJSON(const std::vector<uint8_t>& input) const {
    std::string json(input.begin(), input.end());

    std::uniform_int_distribution<int> strategy_dist(0, 5);
    int strategy = strategy_dist(random_gen_);

    switch (strategy) {
        case 0:
            {
                std::string nested = "{";
                for (int i = 0; i < 1000; i++) {
                    nested += "\"a\":{";
                }
                nested += "\"val\":1";
                for (int i = 0; i < 1000; i++) {
                    nested += "}";
                }
                nested += "}";
                json = nested;
            }
            break;

        case 1:
            {
                std::string arr = "[";
                for (int i = 0; i < 10000; i++) {
                    if (i > 0) arr += ",";
                    arr += std::to_string(i);
                }
                arr += "]";
                json = arr;
            }
            break;

        case 2:
            {
                size_t pos = json.find("\"");
                if (pos != std::string::npos) {
                    json.insert(pos + 1, "\\u0000\\uffff\\uD800");
                }
            }
            break;

        case 3:
            {
                size_t pos = json.find("\"");
                if (pos != std::string::npos) {
                    size_t end = json.find("\"", pos + 1);
                    if (end != std::string::npos) {
                        std::string key = json.substr(pos, end - pos + 1);
                        size_t colon = json.find(":", end);
                        if (colon != std::string::npos) {
                            json.insert(colon + 1, "1," + key + ":");
                        }
                    }
                }
            }
            break;

        case 4:
            {
                size_t pos = json.find(":");
                if (pos != std::string::npos) {
                    json.insert(pos + 1, "NaN");
                }
            }
            break;

        default:
            {
                for (char bracket : {'{', '}', '[', ']'}) {
                    size_t pos = json.find(bracket);
                    if (pos != std::string::npos) {
                        json.erase(pos, 1);
                        break;
                    }
                }
            }
    }

    return std::vector<uint8_t>(json.begin(), json.end());
}

std::vector<uint8_t> FormatAwareMutation::mutateSQL(const std::vector<uint8_t>& input) const {
    std::string original(input.begin(), input.end());

    auto to_lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    };

    auto contains_any = [](const std::string& hay_lower,
                           std::initializer_list<const char*> needles) {
        for (const char* n : needles) {
            if (hay_lower.find(n) != std::string::npos) return true;
        }
        return false;
    };

    auto make_ident = [&](const char* prefix) {
        std::uniform_int_distribution<int> d(0, 999999);
        return std::string(prefix) + std::to_string(d(random_gen_));
    };

    struct SqlBlock {
        std::string sql;
        bool has_compound = false;
        bool has_join = false;
        bool has_create_table = false;
    };

    auto extract_sql_blocks = [&](const std::string& text) {
        std::vector<SqlBlock> blocks;
        std::vector<size_t> stack;
        stack.reserve(32);

        for (size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            if (c == '{') {
                stack.push_back(i);
                continue;
            }
            if (c != '}' || stack.empty()) continue;

            size_t start = stack.back();
            stack.pop_back();
            if (i <= start + 1) continue;

            size_t len = i - start - 1;
            if (len < 24 || len > 8192) continue;

            std::string block = text.substr(start + 1, len);
            std::string lower = to_lower(block);

            if (!contains_any(lower, {"select", "create", "insert", "update", "delete", "pragma", "with"})) {
                continue;
            }

            bool has_stmt_sep = (block.find(';') != std::string::npos) || (block.find('\n') != std::string::npos);
            if (!has_stmt_sep) continue;

            SqlBlock sb;
            sb.sql = std::move(block);
            sb.has_compound = contains_any(lower, {" union ", " union\n", " except ", " except\n", " intersect ", " intersect\n"});
            sb.has_join = contains_any(lower, {" join ", " join\n"});
            sb.has_create_table = contains_any(lower, {"create table", "create temp table", "create temporary table"});
            blocks.push_back(std::move(sb));

            if (blocks.size() >= 32) break;  // keep it cheap
        }

        std::sort(blocks.begin(), blocks.end(),
                  [](const SqlBlock& a, const SqlBlock& b) { return a.sql.size() > b.sql.size(); });
        return blocks;
    };

    auto pick_block_index = [&](const std::vector<SqlBlock>& blocks,
                                bool want_compound,
                                bool want_join,
                                bool want_create_table) -> int {
        if (blocks.empty()) return -1;
        std::vector<int> candidates;
        candidates.reserve(blocks.size());
        for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
            const auto& b = blocks[static_cast<size_t>(i)];
            if (want_compound && !b.has_compound) continue;
            if (want_join && !b.has_join) continue;
            if (want_create_table && !b.has_create_table) continue;
            candidates.push_back(i);
        }
        if (candidates.empty()) return -1;
        std::uniform_int_distribution<int> dist(0, static_cast<int>(candidates.size()) - 1);
        return candidates[static_cast<size_t>(dist(random_gen_))];
    };

    auto normalize_sql = [](std::string& sql) {
        while (!sql.empty() && (sql.back() == '\n' || sql.back() == '\r' || sql.back() == ' ' || sql.back() == '\t')) {
            sql.pop_back();
        }
        if (!sql.empty() && sql.back() != ';') sql.append(";");
        sql.append("\n");
    };

    auto sql003_mutate_distinct_left_join_subquery = [&](std::string& sql) -> bool {
        std::string lower = to_lower(sql);
        size_t sel = lower.find("select");
        if (sel != std::string::npos) {
            size_t after_select = sel + 6;
            if (lower.find("distinct", after_select) == std::string::npos ||
                lower.find("distinct", after_select) > after_select + 8) {
                sql.insert(after_select, " DISTINCT");
                lower = to_lower(sql);
            }
        }

        size_t join_pos = lower.find(" left join ");
        bool make_left = false;
        if (join_pos == std::string::npos) {
            join_pos = lower.find(" join ");
            make_left = (join_pos != std::string::npos);
        }
        if (join_pos == std::string::npos) return false;

        if (make_left) {
            sql.replace(join_pos, 6, " LEFT");
            lower = to_lower(sql);
            join_pos = lower.find(" left join ");
            if (join_pos == std::string::npos) return false;
        }

        size_t tok_start = join_pos + std::string(" left join ").size();
        while (tok_start < sql.size() && std::isspace(static_cast<unsigned char>(sql[tok_start]))) tok_start++;
        if (tok_start >= sql.size()) return false;
        if (sql[tok_start] == '(') return false;  // already a subquery

        size_t tok_end = tok_start;
        while (tok_end < sql.size()) {
            char ch = sql[tok_end];
            if (std::isspace(static_cast<unsigned char>(ch)) || ch == ',' || ch == ')' || ch == ';') break;
            tok_end++;
        }
        if (tok_end <= tok_start) return false;

        std::string table = sql.substr(tok_start, tok_end - tok_start);
        auto is_simple_ident = [](const std::string& t) {
            if (t.empty()) return false;
            if (!(std::isalpha(static_cast<unsigned char>(t[0])) || t[0] == '_')) return false;
            for (char c : t) {
                if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) return false;
            }
            return true;
        };
        if (!is_simple_ident(table)) return false;

        std::string repl = "(SELECT * FROM " + table + ") AS " + table;
        sql.replace(tok_start, tok_end - tok_start, repl);
        return true;
    };

    auto sql012_append_generated_notnull_check = [&](std::string& sql) {
        std::string lower = to_lower(sql);

        std::string table = "t12";
        bool saw_create = false;
        size_t ct = lower.find("create table");
        if (ct != std::string::npos) {
            saw_create = true;
            size_t p = ct + std::string("create table").size();
            while (p < sql.size() && std::isspace(static_cast<unsigned char>(sql[p]))) p++;
            if (lower.compare(p, 13, "if not exists") == 0) {
                p += 13;
                while (p < sql.size() && std::isspace(static_cast<unsigned char>(sql[p]))) p++;
            }
            size_t end = p;
            while (end < sql.size()) {
                char ch = sql[end];
                if (std::isspace(static_cast<unsigned char>(ch)) || ch == '(' || ch == ';') break;
                end++;
            }
            if (end > p) {
                std::string cand = sql.substr(p, end - p);
                bool ok = true;
                for (char c : cand) {
                    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) { ok = false; break; }
                }
                if (ok) table = cand;
            }
        }

        std::uniform_int_distribution<int> d(0, 1);
        int use_quick = d(random_gen_);

        std::uniform_int_distribution<int> col_d(0, 9999);
        std::string col = "g" + std::to_string(col_d(random_gen_));

        if (!saw_create) {
            sql.append("CREATE TABLE ");
            sql.append(table);
            sql.append("(c1 INT);\n");
        }

        sql.append("ALTER TABLE ");
        sql.append(table);
        sql.append(" ADD COLUMN ");
        sql.append(col);
        sql.append(" INT GENERATED ALWAYS AS (1) VIRTUAL NOT NULL;\n");
        sql.append(use_quick ? "PRAGMA quick_check;\n" : "PRAGMA integrity_check;\n");
    };

    auto sql013_append_skipsan_scenario = [&](std::string& sql) {
        std::uniform_int_distribution<int> cols_d(6, 9);
        int ncols = cols_d(random_gen_);
        std::uniform_int_distribution<int> rows_d(40, 120);
        int nrows = rows_d(random_gen_);
        std::uniform_int_distribution<int> mod_d(3, 11);
        int mod = mod_d(random_gen_);

        std::string tname = "t13";
        std::string iname = "i13";
        std::uniform_int_distribution<int> suf_d(0, 9999);
        int suf = suf_d(random_gen_);
        tname += std::to_string(suf);
        iname += std::to_string(suf);

        sql.append("CREATE TABLE ");
        sql.append(tname);
        sql.append("(");
        for (int i = 0; i < ncols; ++i) {
            if (i) sql.append(",");
            sql.append("c");
            sql.append(std::to_string(i + 1));
            sql.append(" INT");
        }
        sql.append(");\n");

        sql.append("CREATE INDEX ");
        sql.append(iname);
        sql.append(" ON ");
        sql.append(tname);
        sql.append("(");
        for (int i = 0; i < ncols; ++i) {
            if (i) sql.append(",");
            sql.append("c");
            sql.append(std::to_string(i + 1));
        }
        sql.append(");\n");

        sql.append("WITH RECURSIVE r(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM r WHERE x<");
        sql.append(std::to_string(nrows));
        sql.append(")\n");
        sql.append("INSERT INTO ");
        sql.append(tname);
        sql.append(" SELECT ");
        for (int i = 0; i < ncols - 1; ++i) {
            if (i) sql.append(",");
            sql.append("0");
        }
        sql.append(",(x%");
        sql.append(std::to_string(mod));
        sql.append(") FROM r;\n");

        sql.append("ANALYZE;\n");
        sql.append("SELECT count(*) FROM ");
        sql.append(tname);
        sql.append(" INDEXED BY ");
        sql.append(iname);
        sql.append(" WHERE c");
        sql.append(std::to_string(ncols));
        sql.append("=1;\n");
    };

    std::uniform_int_distribution<int> action_dist(0, 99);
    int action = action_dist(random_gen_);

    bool do_sql002 = (action >= 60 && action < 65);
    bool do_sql003 = (action >= 65 && action < 75);
    bool do_sql012 = (action >= 75 && action < 83);
    bool do_sql013 = (action >= 83 && action < 87);
    bool do_sql014 = (action >= 87 && action < 94);
    bool do_sql020 = (action >= 94);
    bool do_shaping = do_sql002 || do_sql003 || do_sql012 || do_sql013 || do_sql014 || do_sql020;

    auto blocks = extract_sql_blocks(original);
    std::string sql = original;
    if (!blocks.empty()) {
        bool want_compound = do_sql014;
        bool want_join = do_sql003;
        bool want_table = do_sql012 || do_sql013;
        int idx = pick_block_index(blocks, want_compound, want_join, want_table);
        if (idx < 0) idx = 0;
        sql = blocks[static_cast<size_t>(idx)].sql;
    } else if (do_shaping) {
        sql.clear();
    }

    if (do_sql002 || do_sql014 || do_sql020) {
        sql.clear();
    }

    std::string out;
    out.reserve(std::min<size_t>(65536, sql.size() + 2048));
    out.append("PRAGMA temp_store=MEMORY;\n");
    out.append(sql);
    normalize_sql(out);

    if (do_sql002) {
        std::string vt = make_ident("vt2_");
        std::string vw = make_ident("v2_");
        out.append("PRAGMA trusted_schema=OFF;\n");
        out.append("CREATE VIRTUAL TABLE ");
        out.append(vt);
        out.append(" USING rtree(id, minX, maxX, minY, maxY);\n");
        out.append("CREATE VIEW ");
        out.append(vw);
        out.append(" AS SELECT * FROM ");
        out.append(vt);
        out.append(";\n");
        out.append("SELECT * FROM ");
        out.append(vw);
        out.append(";\n");
    } else if (do_sql003) {
        if (!sql003_mutate_distinct_left_join_subquery(out)) {
            std::string ta = make_ident("t3a_");
            std::string tb = make_ident("t3b_");
            out.append("CREATE TABLE ");
            out.append(ta);
            out.append("(x INT);\n");
            out.append("CREATE TABLE ");
            out.append(tb);
            out.append("(x INT);\n");
            out.append("INSERT INTO ");
            out.append(ta);
            out.append("(x) VALUES(1),(2),(3);\n");
            out.append("INSERT INTO ");
            out.append(tb);
            out.append("(x) VALUES(2),(3),(4);\n");
            out.append("SELECT DISTINCT a.x FROM ");
            out.append(ta);
            out.append(" AS a LEFT JOIN (SELECT * FROM ");
            out.append(tb);
            out.append(") AS b ON a.x=b.x;\n");
        }
    } else if (do_sql012) {
        sql012_append_generated_notnull_check(out);
    } else if (do_sql013) {
        sql013_append_skipsan_scenario(out);
    } else if (do_sql014) {
        std::string v = make_ident("v14_");
        std::string c1 = make_ident("c14a_");
        std::string c2 = make_ident("c14b_");
        out.append("CREATE VIEW ");
        out.append(v);
        out.append("(");
        out.append(c1);
        out.append(",");
        out.append(c2);
        out.append(") AS SELECT 1;\n");
        out.append("SELECT 1 UNION SELECT 1 FROM ");
        out.append(v);
        out.append(";\n");
    } else if (do_sql020) {
        std::string w = make_ident("w20_");
        std::uniform_int_distribution<int> rows_d(2, 6);
        int nrows = rows_d(random_gen_);
        std::uniform_int_distribution<int> val_d(-8, 8);
        std::uniform_int_distribution<int> ord_d(1, 4);
        int ord = ord_d(random_gen_);
        out.append("WITH ");
        out.append(w);
        out.append("(x) AS (VALUES(");
        out.append(std::to_string(val_d(random_gen_)));
        out.append(")");
        for (int i = 1; i < nrows; ++i) {
            out.append(",(");
            out.append(std::to_string(val_d(random_gen_)));
            out.append(")");
        }
        out.append(")\n");
        out.append("SELECT row_number() OVER (ORDER BY ");
        out.append(std::to_string(ord));
        out.append(") FROM ");
        out.append(w);
        out.append(";\n");
    }

    if (out.size() > 65536) out.resize(65536);
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> FormatAwareMutation::mutateGeneric(const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> result = input;

    if (result.empty()) return result;

    std::uniform_int_distribution<int> strategy_dist(0, 4);
    int strategy = strategy_dist(random_gen_);

    switch (strategy) {
        case 0:
            {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
                size_t pos = pos_dist(random_gen_);
                result[pos] ^= (1 << (random_gen_() % 8));
            }
            break;

        case 1:
            {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
                std::uniform_int_distribution<uint8_t> byte_dist;
                size_t pos = pos_dist(random_gen_);
                result[pos] = byte_dist(random_gen_);
            }
            break;

        case 2:
            {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size());
                std::uniform_int_distribution<int> len_dist(1, 100);
                size_t pos = pos_dist(random_gen_);
                int len = len_dist(random_gen_);
                for (int i = 0; i < len; i++) {
                    result.insert(result.begin() + pos, random_gen_() & 0xFF);
                }
            }
            break;

        case 3:
            if (result.size() > 1) {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 1);
                std::uniform_int_distribution<int> len_dist(1, std::min(100, (int)result.size()));
                size_t pos = pos_dist(random_gen_);
                int len = len_dist(random_gen_);
                if (pos + len <= result.size()) {
                    result.erase(result.begin() + pos, result.begin() + pos + len);
                }
            }
            break;

        default:
            if (result.size() > 4) {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size() - 4);
                std::uniform_int_distribution<int> len_dist(2, std::min(100, (int)(result.size() - 2)));
                size_t pos = pos_dist(random_gen_);
                int len = len_dist(random_gen_);
                if (pos + len <= result.size()) {
                    std::shuffle(result.begin() + pos, result.begin() + pos + len, random_gen_);
                }
            }
    }

    return result;
}

std::vector<uint8_t> FormatAwareMutation::mutateFont(const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> result = input;

    if (result.size() < 48) {
        return mutateGeneric(result);
    }

    if (result.size() <= 48) {
        return result;
    }

    std::uniform_int_distribution<size_t> pos_dist(48, result.size() - 1);
    std::uniform_int_distribution<int> mutation_type(0, 2);

    size_t num_mutations = 1 + (random_gen_() % 3);
    for (size_t i = 0; i < num_mutations && result.size() > 48; ++i) {
        size_t pos = pos_dist(random_gen_);

        switch (mutation_type(random_gen_)) {
            case 0:
                result[pos] ^= (1 << (random_gen_() % 8));
                break;

            case 1:
                {
                    int delta = (random_gen_() % 5) - 2;
                    int new_val = static_cast<int>(result[pos]) + delta;
                    result[pos] = static_cast<uint8_t>(std::max(0, std::min(255, new_val)));
                }
                break;

            case 2:
                result[pos] = static_cast<uint8_t>(random_gen_() % 256);
                break;
        }
    }

    return result;
}

uint32_t FormatAwareMutation::readUint32BE(const uint8_t* data) const {
    return (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) |
           (uint32_t(data[2]) << 8) | uint32_t(data[3]);
}

void FormatAwareMutation::writeUint32BE(uint8_t* data, uint32_t value) const {
    data[0] = (value >> 24) & 0xFF;
    data[1] = (value >> 16) & 0xFF;
    data[2] = (value >> 8) & 0xFF;
    data[3] = value & 0xFF;
}

} // namespace triofuzz
