#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

# export http_proxy=http://127.0.0.1:7892
# export https_proxy=http://127.0.0.1:7892

git clone --no-checkout https://github.com/openssl/openssl.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 3bd5319b5d0df9ecf05c8baba2c401ad8e3ba130

cp "$TARGET/src/abilist.txt" "$TARGET/repo/abilist.txt"

unset http_proxy
unset https_proxy