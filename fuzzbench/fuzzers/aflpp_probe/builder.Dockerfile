# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        python3-dev \
        python3-setuptools \
        automake \
        cmake \
        git \
        flex \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        cargo \
        libgtk-3-dev \
        wget \
        gnupg \
        # for QEMU mode
        ninja-build \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Install LLVM 17 (required by the pinned AFL++ commit below).
RUN rm -f /usr/local/bin/clang /usr/local/bin/clang++ && \
    hash -r && \
    echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-17 main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-17 main" >> /etc/apt/sources.list && \
    (wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc) && \
    apt-get update && \
    apt-get install -y clang-17 llvm-17-dev lld-17 libc++1-17 libc++-17-dev libc++abi-17-dev && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-17 100 && \
    update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-17 100 && \
    update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-17 100

# PROBE fork of AFL++ (see ./AFLplusplus/docs/upstream.md for the pinned
# upstream commit). The fork lives in this build context so we COPY rather
# than `git clone`, keeping the build self-contained and reproducible.
COPY ./AFLplusplus /afl

# Build with PROBE_BUILD=1 so afl-fuzz is compiled with -DPROBE_ENABLED and
# probe-*.c is linked in. M2 hooks the LSH abstraction and a distinct-state
# telemetry harness (see AFLplusplus/docs/abstraction_tuning.md).
#
# AFL_NO_X86 skips flaky tests. NO_PYTHON=1 disables Python embedding so the
# resulting afl-fuzz does not depend on libpython3.10 at runtime — the runner
# image (gcr.io/fuzzbench/base-image) does not ship libpython, and we don't
# use AFL++ Python custom mutators in PROBE.
RUN cd /afl && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang-17 CXX=clang++-17 AFL_NO_X86=1 PROBE_BUILD=1 && \
    make NO_PYTHON=1 LLVM_CONFIG=llvm-config-17 && \
    cp utils/aflpp_driver/libAFLDriver.a /
