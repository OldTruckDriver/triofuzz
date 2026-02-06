#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <atomic>
#include <algorithm>
#include <cstring>

namespace triofuzz {
namespace cmplog {

// Lightweight, per-thread buffer for sanitizer trace-cmp events.
// Records at most MAX_RECORDS per execution to keep overhead bounded.

enum class CmpKind : uint8_t {
    Int = 0,
    ConstInt = 1,
    Mem = 2,
    Str = 3,
    StrN = 4,
    Switch = 5,
};

struct RecordedCmp {
    uint64_t pc;
    CmpKind kind;
    uint16_t size;        // requested size (for Int: 1/2/4/8; for Mem/StrN: n; for Str: observed length)
    uint16_t lhs_len;     // actual captured length (<= MAX_BYTES)
    uint16_t rhs_len;     // actual captured length (<= MAX_BYTES)
    uint8_t lhs[32];      // captured bytes (little-endian for integers)
    uint8_t rhs[32];
};

inline constexpr size_t MAX_RECORDS = 4096;           // per input
inline constexpr size_t PC_FILTER_SLOTS = 8192;       // simple dedup by PC slot
inline constexpr size_t MAX_BYTES = 32;               // max bytes per operand to capture

// Thread-local storage
inline thread_local std::vector<RecordedCmp> tls_records;
inline thread_local std::array<uint8_t, PC_FILTER_SLOTS> tls_pc_seen{}; // 0/1 flags
inline thread_local bool tls_enabled = true;
inline thread_local bool tls_full_enabled = false;

// Enable/disable collection for the current thread.
inline void setEnabled(bool enabled) { tls_enabled = enabled; }
inline bool isEnabled() { return tls_enabled; }

// Enable/disable full trace-cmp collection (non-const integer comparisons).
// Keep this off by default because it is extremely hot.
inline void setFullEnabled(bool enabled) { tls_full_enabled = enabled; }
inline bool isFullEnabled() { return tls_full_enabled; }

// Reset buffer and PC filter at the start of each input execution
inline void startNewInput() {
    tls_records.clear();
    // Clear the simple PC filter (fast memset)
    tls_pc_seen.fill(0);
}

// Utility to write integer value to byte array (little-endian)
template <typename T>
inline void storeLE(uint8_t out[MAX_BYTES], T value) {
    static_assert(sizeof(T) <= 8, "operand too large");
    for (size_t i = 0; i < sizeof(T); ++i) {
        out[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
    // Zero the rest to keep deterministic content
    for (size_t i = sizeof(T); i < MAX_BYTES; ++i) out[i] = 0;
}

// Record one integer comparison. Very hot path: keep it light.
template <typename T>
inline void recordInt(uint64_t pc, T lhs, T rhs, CmpKind kind = CmpKind::Int) {
    if (!tls_enabled) return;
    if (tls_records.size() >= MAX_RECORDS) return;

    // Simple PC-based filter to avoid repeated records for the same site within one input
    uint32_t slot = static_cast<uint32_t>((pc >> 4) & (PC_FILTER_SLOTS - 1));
    if (tls_pc_seen[slot]) return;
    tls_pc_seen[slot] = 1;

    RecordedCmp rec{};
    rec.pc = pc;
    rec.kind = kind;
    rec.size = static_cast<uint16_t>(sizeof(T));
    rec.lhs_len = static_cast<uint16_t>(sizeof(T));
    rec.rhs_len = static_cast<uint16_t>(sizeof(T));
    storeLE(rec.lhs, lhs);
    storeLE(rec.rhs, rhs);
    tls_records.push_back(rec);
}

// Record memory/string comparison
inline void recordMem(uint64_t pc, const void* s1, const void* s2, size_t n, CmpKind kind) {
    if (!tls_enabled) return;
    if (tls_records.size() >= MAX_RECORDS) return;
    uint32_t slot = static_cast<uint32_t>((pc >> 4) & (PC_FILTER_SLOTS - 1));
    if (tls_pc_seen[slot]) return;
    tls_pc_seen[slot] = 1;

    size_t cap = std::min(n, MAX_BYTES);
    RecordedCmp rec{};
    rec.pc = pc;
    rec.kind = kind;
    rec.size = static_cast<uint16_t>(n > 0xFFFF ? 0xFFFF : n);
    rec.lhs_len = static_cast<uint16_t>(cap);
    rec.rhs_len = static_cast<uint16_t>(cap);
    if (cap) {
        std::memcpy(rec.lhs, s1, cap);
        std::memcpy(rec.rhs, s2, cap);
    }
    // Zero tail
    if (cap < MAX_BYTES) {
        std::memset(rec.lhs + cap, 0, MAX_BYTES - cap);
        std::memset(rec.rhs + cap, 0, MAX_BYTES - cap);
    }
    tls_records.push_back(rec);
}

// Drain current thread records into an output vector and clear the buffer
inline std::vector<RecordedCmp> drain() {
    std::vector<RecordedCmp> out;
    if (!tls_records.empty()) {
        out.swap(tls_records);
    }
    // Don't clear pc_seen here; it is reset in startNewInput()
    return out;
}

} // namespace cmplog
} // namespace triofuzz
