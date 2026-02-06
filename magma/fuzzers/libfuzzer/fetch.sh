#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

# export http_proxy=http://127.0.0.1:7892
# export https_proxy=http://127.0.0.1:7892

git clone --no-checkout https://github.com/llvm/llvm-project.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 29cc50e17a6800ca75cd23ed85ae1ddf3e3dcc14

unset http_proxy
unset https_proxy