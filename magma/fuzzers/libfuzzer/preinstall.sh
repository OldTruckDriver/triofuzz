#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update && \
    apt-get install -y make build-essential wget git

apt-get install -y apt-utils apt-transport-https ca-certificates gnupg

apt-get update && \
    apt-get install -y make build-essential wget git \
                       lsb-release software-properties-common gnupg

apt-add-repository -y ppa:ubuntu-toolchain-r/test

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
./llvm.sh 11