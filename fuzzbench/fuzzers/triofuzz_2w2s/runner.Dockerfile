# fuzzers/triofuzz/runner.Dockerfile
# TrioFuzz - Unified Multi-Algorithm Fuzzer Runtime
# Copyright 2025

FROM gcr.io/fuzzbench/base-image

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential \
    cmake git nlohmann-json3-dev wget make autoconf automake \
    libtool zlib1g-dev unzip ca-certificates libssl-dev pkg-config \
    libcapstone-dev libprotobuf-dev libarchive-dev ninja-build \
    libbrotli-dev libbz2-dev liblzma-dev libzstd-dev \
    libfontconfig1 libfreetype6 libfribidi0

# Install llvm-17
RUN rm -f /usr/local/bin/clang /usr/local/bin/clang++ && \
    hash -r && \
    echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-17 main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-17 main" >> /etc/apt/sources.list && \
    (wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc) && \
    apt-get update && \
    apt-get install -y clang-17 llvm-17-dev lld-17 clangd-17 lldb-17 libc++1-17 libc++-17-dev libc++abi-17-dev && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-17 100 && \
    update-alternatives --install /usr/bin/lldb lldb /usr/bin/lldb-17 100 && \
    update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-17 100 && \
    update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-17 100
