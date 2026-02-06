#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

export http_proxy=http://127.0.0.1:7892
export https_proxy=http://127.0.0.1:7892


git clone --no-checkout https://github.com/google/AFL.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 61037103ae3722c8060ff7082994836a794f978e
#wget -O "$FUZZER/repo/afl_driver.cpp" \
#    "https://cs.chromium.org/codesearch/f/chromium/src/third_party/libFuzzer/src/afl/afl_driver.cpp"
cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/repo/afl_driver.cpp"

unset http_proxy
unset https_proxy