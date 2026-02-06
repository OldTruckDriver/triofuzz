// 虚拟的LLVMFuzzerTestOneInput实现，仅用于collabf可执行文件的编译
// 实际使用时，用户会提供自己的LLVMFuzzerTestOneInput实现

#include <cstdint>
#include <cstddef>

extern "C" {

// 虚拟实现，仅用于满足链接需求
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // 空实现
    return 0;
}

// 可选的初始化函数（虚拟实现）
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // 空实现
    return 0;
}

}