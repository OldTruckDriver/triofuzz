#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

# build the libpng library
cd "$TARGET/repo"
autoreconf -f -i

# CCASFLAGS: Flags for assembler files (.S)
# We need to exclude -include canary.h from assembly compilation
# as it causes C code to be parsed as assembly instructions
export CCASFLAGS=""

# Disable ARM NEON assembly optimizations to avoid incompatible .section directives
# The filter_neon.S file uses macOS-specific syntax that doesn't work on Linux
./configure --with-libpng-prefix=MAGMA_ --disable-shared --disable-arm-neon
make -j$(nproc) clean
make -j$(nproc) libpng16.la

cp .libs/libpng16.a "$OUT/"

# build libpng_read_fuzzer.
$CXX $CXXFLAGS -std=c++11 -I. \
     contrib/oss-fuzz/libpng_read_fuzzer.cc \
     -o $OUT/libpng_read_fuzzer \
     $LDFLAGS .libs/libpng16.a $LIBS -lz