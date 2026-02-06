#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

# Copy TrioFuzz source code from the downloaded fuzzbench directory
# The source is expected to be at $MAGMA/triofuzz/src (downloaded from fuzzbench)
if [ ! -d "$FUZZER/repo" ]; then
    # Check if triofuzz source exists in the magma root directory
    MAGMA_ROOT="$(dirname "$(dirname "$FUZZER")")"
    if [ -d "$MAGMA_ROOT/triofuzz/src" ]; then
        cp -r "$MAGMA_ROOT/triofuzz/src" "$FUZZER/repo"
        echo "[TrioFuzz] Copied source from $MAGMA_ROOT/triofuzz/src to $FUZZER/repo"
    elif [ -d "$FUZZER/TrioFuzz" ]; then
        cp -r "$FUZZER/TrioFuzz" "$FUZZER/repo"
        echo "[TrioFuzz] Copied source from $FUZZER/TrioFuzz to $FUZZER/repo"
    else
        echo "[TrioFuzz] ERROR: TrioFuzz source not found."
        echo "[TrioFuzz] Please ensure TrioFuzz source is available at:"
        echo "[TrioFuzz]   - $MAGMA_ROOT/triofuzz/src"
        echo "[TrioFuzz]   - $FUZZER/TrioFuzz"
        exit 1
    fi
fi
