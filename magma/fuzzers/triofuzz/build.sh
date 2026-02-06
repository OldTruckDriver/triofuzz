#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env OUT: path to directory where artifacts are stored
##

if [ ! -d "$FUZZER/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "$FUZZER/repo"

# Build TrioFuzz library
echo "[TrioFuzz] Building TrioFuzz library..."

# Verify OpenSSL is installed and findable
echo "[TrioFuzz] Checking OpenSSL installation..."
if ! pkg-config --exists openssl; then
    echo "[TrioFuzz] ERROR: OpenSSL not found via pkg-config"
    echo "[TrioFuzz] Attempting to locate OpenSSL manually..."
    if [ -d "/usr/include/openssl" ]; then
        echo "[TrioFuzz] Found OpenSSL headers at /usr/include/openssl"
    else
        echo "[TrioFuzz] ERROR: OpenSSL headers not found. Please install libssl-dev"
        exit 1
    fi
    if [ -f "/usr/lib/x86_64-linux-gnu/libssl.so" ] || [ -f "/usr/lib/x86_64-linux-gnu/libssl.a" ]; then
        echo "[TrioFuzz] Found OpenSSL library"
    else
        echo "[TrioFuzz] ERROR: OpenSSL library not found"
        exit 1
    fi
else
    echo "[TrioFuzz] OpenSSL found via pkg-config: $(pkg-config --modversion openssl)"
fi

# Create build directory
rm -rf build
mkdir -p build
cd build

# Build with optimization
cmake -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-O3" \
      -DCMAKE_CXX_FLAGS="-O3" \
      ..

# Build the library
# Note: triofuzz target includes main() function (needed for Magma)
#       triofuzz_lib does not include main() (for custom main functions)
# For Magma, we need triofuzz (with main) so targets just implement LLVMFuzzerTestOneInput
make -j$(nproc)

# Copy library to output directory
# Use triofuzz (with main) for Magma compatibility
if [ -f "libtriofuzz.a" ]; then
    cp libtriofuzz.a "$OUT/"
    echo "[TrioFuzz] Library built successfully: $OUT/libtriofuzz.a"
elif [ -f "libtriofuzz_lib.a" ]; then
    # Fallback: if only triofuzz_lib is available, use it
    # But note: this requires the target to provide its own main()
    cp libtriofuzz_lib.a "$OUT/libtriofuzz.a"
    echo "[TrioFuzz] WARNING: Using triofuzz_lib (no main), target must provide main()"
    echo "[TrioFuzz] Library copied: $OUT/libtriofuzz.a"
else
    # Search for any triofuzz library
    FOUND_LIB=$(find . -name "libtriofuzz*.a" | head -1)
    if [ -n "$FOUND_LIB" ]; then
        cp "$FOUND_LIB" "$OUT/libtriofuzz.a"
        echo "[TrioFuzz] Library found and copied: $OUT/libtriofuzz.a"
    else
        echo "[TrioFuzz] ERROR: Library not found after build"
        echo "[TrioFuzz] Available files:"
        ls -la *.a 2>/dev/null || echo "No .a files found"
        exit 1
    fi
fi

# Compile driver if needed (TrioFuzz provides main, but we may need a wrapper)
cd "$FUZZER"
if [ -f "src/driver.cpp" ]; then
    $CMAKE_CXX_COMPILER $CXXFLAGS -std=c++11 -c "src/driver.cpp" -fPIC -o "$OUT/driver.o" || true
fi

echo "[TrioFuzz] Build completed successfully"
