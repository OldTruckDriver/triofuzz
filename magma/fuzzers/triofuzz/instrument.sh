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

# TrioFuzz coverage instrumentation
#   trace-pc-guard : AFL++-compatible edge coverage (XOR-hashed, 65536B bitmap)
#   trace-cmp      : comparison logging, feeds runtime CmpLog / RedQueen
#
# NOTE: the FuzzBench integration (fuzzbench/fuzzers/triofuzz/fuzzer.py) drops
# trace-cmp because it costs >=20% throughput on comparison-dense targets, and
# FuzzBench scores edge coverage. Magma scores *bugs* instead, and a large share
# of Magma bugs sit behind magic bytes / length fields / checksums that CmpLog
# is specifically good at getting past. So Magma keeps trace-cmp by default;
# the throughput trade-off that is right for FuzzBench is not right here.
#
# To reproduce the FuzzBench instrumentation exactly (useful as an ablation),
# set TRIOFUZZ_NO_TRACE_CMP=1. NOTE: this script runs during `docker build`
# (magma/docker/Dockerfile: RUN ${FUZZER}/instrument.sh), and captain's
# tools/captain/build.sh passes a fixed set of --build-arg values, so a host
# environment variable will NOT reach it. Use one of:
#   - add `ENV TRIOFUZZ_NO_TRACE_CMP 1` above that RUN line in the Dockerfile, or
#   - copy this fuzzer directory to fuzzers/triofuzz_nocmp/ and hardcode it there,
#     which also lets both configurations run side by side in one experiment.
if [ "$TRIOFUZZ_NO_TRACE_CMP" = "1" ]; then
    COV_FLAGS="-fsanitize-coverage=trace-pc-guard"
    echo "[TrioFuzz] Instrumentation: trace-pc-guard only (TRIOFUZZ_NO_TRACE_CMP=1)"
else
    COV_FLAGS="-fsanitize-coverage=trace-cmp,trace-pc-guard"
    echo "[TrioFuzz] Instrumentation: trace-cmp + trace-pc-guard (Magma default)"
fi

export CFLAGS="$CFLAGS $COV_FLAGS -g"
export CXXFLAGS="$CXXFLAGS $COV_FLAGS -g"

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
