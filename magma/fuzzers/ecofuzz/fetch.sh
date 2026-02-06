#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

export http_proxy=http://127.0.0.1:7892
export https_proxy=http://127.0.0.1:7892

git clone https://github.com/MoonLight-SteinsGate/EcoFuzz.git "$FUZZER/repo"
# git -C "$FUZZER/repo" checkout a9a5dc5c0c291c1cdb09b2b7b27d7cbf1db7ce7b
mv "$FUZZER/repo/EcoFuzz"/* "$FUZZER/repo"
#wget -O "$FUZZER/repo/afl_driver.cpp" \
#    "https://cs.chromium.org/codesearch/f/chromium/src/third_party/libFuzzer/src/afl/afl_driver.cpp"
cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/repo/afl_driver.cpp"
