#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

# export http_proxy=http://127.0.0.1:7892
# export https_proxy=http://127.0.0.1:7892

curl "https://www.sqlite.org/src/tarball/sqlite.tar.gz?r=8c432642572c8c4b" \
  -o "$OUT/sqlite.tar.gz" && \
mkdir -p "$TARGET/repo" && \
tar -C "$TARGET/repo" --strip-components=1 -xzf "$OUT/sqlite.tar.gz"

unset http_proxy
unset https_proxy