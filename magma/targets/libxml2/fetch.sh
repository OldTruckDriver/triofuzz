#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

export http_proxy=http://127.0.0.1:7892
export https_proxy=http://127.0.0.1:7892

git clone --no-checkout https://gitlab.gnome.org/GNOME/libxml2.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout ec6e3efb06d7b15cf5a2328fabd3845acea4c815

unset http_proxy
unset https_proxy