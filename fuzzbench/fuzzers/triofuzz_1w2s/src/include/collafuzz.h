#pragma once

// ================================
// CollaFuzz - Simple Interface
// ================================

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ================================
// Core interface - libFuzzer-compatible naming
// ================================

// Users must implement this function (libFuzzer-compatible).
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

// Optional initialization function (libFuzzer-compatible).
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

// Optional configuration struct
struct triofuzzConfig {
    size_t max_len;
    size_t timeout_ms;
    size_t max_total_time;
    size_t max_executions;  // Max executions; 0 means unlimited (mutually exclusive with max_total_time)
    const char* output_dir;
    int verbose;
    int threads;
    const char* seeds_dir;
    const char* dict_file;
    size_t memory_limit_mb;  // Memory limit (MB), default 2048MB
};

// Users can set global configuration (optional).
__attribute__((weak)) extern struct triofuzzConfig triofuzz_config;

// Framework-provided main (implemented in the library; not instrumented).
int main(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

// ================================
// Build and usage
// ================================

/*

Simplest usage:

```cpp
// target.cpp - test code only; no headers needed
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Your test logic
    if (Size > 0 && Data[0] == 0x42) {
        abort();  // Trigger a crash
    }
    return 0;
}
```

Build and run:
```bash
# Using Clang (trace-pc-guard coverage instrumentation)
clang++ -g -O1 -fsanitize-coverage=trace-pc-guard target.cpp -c -o target.o
clang++ target.o -lcollafuzz -o fuzzer

# Using GCC (trace-pc coverage instrumentation as an alternative)
g++ -g -O1 -fsanitize-coverage=trace-pc target.cpp -c -o target.o
g++ target.o -lcollafuzz -o fuzzer

# Run
./fuzzer
```

Note: CollaFuzz supports both Clang and GCC:
- Clang: use -fsanitize-coverage=trace-pc-guard (recommended, more precise)
- GCC: use -fsanitize-coverage=trace-pc (alternative)

Version with configuration:
```cpp
// target.cpp
#include "collafuzz.h"  // Only include when you need configuration

// Optional: custom configuration
struct triofuzzConfig triofuzz_config = {
    .max_len = 1024 * 1024,
    .timeout_ms = 5000,
    .verbose = 1,
    .output_dir = "./output",
    .memory_limit_mb = 2048  // 2GB memory limit, useful for complex formats like woff2
};

// Optional: initialization function
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialization code
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Test logic
    return 0;
}
```

*/
