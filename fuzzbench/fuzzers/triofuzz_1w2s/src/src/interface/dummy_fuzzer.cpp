// Dummy LLVMFuzzerTestOneInput implementation, only used to compile the collabf executable.
// In real usage, users should provide their own LLVMFuzzerTestOneInput implementation.

#include <cstdint>
#include <cstddef>

extern "C" {

// Dummy implementation to satisfy linker requirements.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // No-op
    return 0;
}

// Optional initialization function (dummy implementation).
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // No-op
    return 0;
}

}
