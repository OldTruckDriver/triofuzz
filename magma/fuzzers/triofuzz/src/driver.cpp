/*===- TrioFuzz Driver - Compatibility layer for Magma
//
// This file provides a compatibility layer for TrioFuzz to work with
// Magma's fuzzing infrastructure. TrioFuzz already provides its own
// main() function, so this driver is minimal.
//
// TrioFuzz uses the same interface as libFuzzer:
//   - LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
//   - LLVMFuzzerInitialize(int *argc, char ***argv) [optional]
//
// The actual main() function is provided by TrioFuzz library.
//===----------------------------------------------------------------------===*/

#include <cstdint>
#include <cstddef>

// TrioFuzz provides main() in the library, so this file is mainly
// for compatibility. If needed, we can add a wrapper here.

extern "C" {
    // These are weak symbols that will be provided by the target
    __attribute__((weak))
    extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

    __attribute__((weak))
    extern int LLVMFuzzerInitialize(int *argc, char ***argv);
}

// Note: TrioFuzz's main() function (in triofuzz_main.cpp) will call
// LLVMFuzzerTestOneInput, so we don't need to implement anything here.
// This file exists for compatibility with Magma's build system.
