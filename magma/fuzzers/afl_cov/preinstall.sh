#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

# Install apt utilities first
apt-get update && \
    apt-get install -y apt-utils apt-transport-https ca-certificates gnupg wget software-properties-common

# Install basic build tools (including updated CMake)
apt-get update && \
    apt-get install -y make build-essential git cmake

# Install LLVM/Clang with better C++17 filesystem support
# Clang 12+ has better C++17 filesystem support than Clang 11
# Try Clang 13 first, fallback to Clang 12 if not available
# echo deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-13 main >> /etc/apt/sources.list
# echo deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-12 main >> /etc/apt/sources.list
# echo deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-11 main >> /etc/apt/sources.list
# wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

apt-get update && \
    apt-get install -y clang-11 llvm-11

# Determine which Clang version was installed
CLANG_VERSION=""
if command -v clang-13 &> /dev/null; then
    CLANG_VERSION=13
elif command -v clang-12 &> /dev/null; then
    CLANG_VERSION=12
elif command -v clang-11 &> /dev/null; then
    CLANG_VERSION=11
else
    echo "ERROR: No Clang version found"
    exit 1
fi

echo "[CollabFuzz] Installed Clang ${CLANG_VERSION} for better C++17 filesystem support"

# Install CollabFuzz dependencies
# libssl-dev is REQUIRED (OpenSSL is required by CMakeLists.txt)
# pkg-config helps CMake find OpenSSL
apt-get install -y \
    libssl-dev \
    zlib1g-dev \
    pkg-config

# Verify OpenSSL installation
if ! pkg-config --exists openssl; then
    echo "ERROR: OpenSSL (libssl-dev) installation failed or not found"
    exit 1
fi

# Set up LLVM alternatives for the installed version
update-alternatives \
  --install /usr/lib/llvm              llvm             /usr/lib/llvm-${CLANG_VERSION}  20 \
  --slave   /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-${CLANG_VERSION}  \
    --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-as           llvm-as           /usr/bin/llvm-as-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-c-test       llvm-c-test      /usr/bin/llvm-c-test-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-profdata     llvm-profdata    /usr/bin/llvm-profdata-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-${CLANG_VERSION} \
    --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-${CLANG_VERSION}

update-alternatives \
  --install /usr/bin/clang                 clang                  /usr/bin/clang-${CLANG_VERSION}     20 \
  --slave   /usr/bin/clang++               clang++                /usr/bin/clang++-${CLANG_VERSION} \
  --slave   /usr/bin/clang-cpp             clang-cpp              /usr/bin/clang-cpp-${CLANG_VERSION}
