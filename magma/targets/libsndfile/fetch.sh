#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

# export http_proxy=http://127.0.0.1:7892
# export https_proxy=http://127.0.0.1:7892

git clone --no-checkout https://github.com/libsndfile/libsndfile.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 86c9f9eb7022d186ad4d0689487e7d4f04ce2b29

unset http_proxy
unset https_proxy