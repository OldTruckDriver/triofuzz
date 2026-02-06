#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env MAGMA: path to Magma support files
# - env OUT: path to directory where artifacts are stored
# - env CFLAGS and CXXFLAGS must be set to link against Magma instrumentation
##

export CC="clang"
export CXX="clang++"

# TrioFuzz requires specific coverage instrumentation flags
# trace-cmp: for comparison logging (CmpLog)
# trace-pc-guard: for coverage tracking (AFL++-compatible edge coverage)
export CFLAGS="$CFLAGS -fsanitize-coverage=trace-cmp,trace-pc-guard -g"
export CXXFLAGS="$CXXFLAGS -fsanitize-coverage=trace-cmp,trace-pc-guard -g"

# Link against TrioFuzz library and required dependencies
export LDFLAGS="$LDFLAGS -L$OUT"
# Link triofuzz library (contains main() function)
# Also link required dependencies: zlib, OpenSSL, pthread, rt, dl
export LIBS="$LIBS -ltriofuzz -lz -lcrypto -lpthread -lrt -ldl -lstdc++"

# Build target with TrioFuzz instrumentation
"$MAGMA/build.sh"
"$TARGET/build.sh"

# NOTE: TrioFuzz uses the same interface as libFuzzer (LLVMFuzzerTestOneInput)
#       so the target build.sh should work without modification
