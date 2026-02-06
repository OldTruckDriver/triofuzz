# fuzzers/triofuzz/builder.Dockerfile
# TrioFuzz - Unified Multi-Algorithm Fuzzer
# Integrates XFuzz Thompson Sampling + MOpt PSO + MuoFuzz Markov Chain

ARG parent_image
FROM $parent_image

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential \
    cmake git nlohmann-json3-dev wget make autoconf automake \
    libtool zlib1g-dev unzip ca-certificates libssl-dev pkg-config \
    libcapstone-dev libprotobuf-dev libarchive-dev ninja-build \
    libbrotli-dev libbz2-dev liblzma-dev libzstd-dev \
    python3-dev python3-setuptools flex bison libglib2.0-dev libpixman-1-dev \
    gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
    libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Upgrade to a modern CMake (>=3.22) required by some benchmarks (e.g., assimp).
RUN apt-get update && \
    apt-get install -y --no-install-recommends gnupg && \
    wget -qO- https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor -o /usr/share/keyrings/kitware.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/kitware.gpg] https://apt.kitware.com/ubuntu/ focal main" > /etc/apt/sources.list.d/kitware.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    cmake --version && \
    rm -f /usr/local/bin/cmake /usr/local/bin/ccmake /usr/local/bin/cpack /usr/local/bin/ctest || true

# Install llvm-17
RUN rm /usr/local/bin/clang /usr/local/bin/clang++ && \
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

# Install AFL++ (needed for AFL_LLVM_DICT2FILE dictionary generation).
RUN git clone -b dev https://github.com/AFLplusplus/AFLplusplus /afl && \
    cd /afl && \
    git checkout 56d5aa3101945e81519a3fac8783d0d8fad82779 || \
    true

# Build AFL++ without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
RUN cd /afl && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang-17 CXX=clang++-17 AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make LLVM_CONFIG=llvm-config-17 && \
    cp utils/aflpp_driver/libAFLDriver.a /libAFLDriver.a

# Copy TrioFuzz source code
COPY src /triofuzz/

ENV PYTHONIOENCODING=utf8 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# Clean any existing build artifacts and CMake caches
RUN cd /triofuzz && \
    rm -rf build && \
    find . -name "build_instrumented" -type d -exec rm -rf {} + || true && \
    find . -name "CMakeCache.txt" -exec rm -f {} + || true && \
    find . -name "CMakeFiles" -type d -exec rm -rf {} + || true && \
    rm -rf /usr/local/include/absl /usr/local/lib/libabsl* /usr/local/lib/pkgconfig/absl*.pc || true

# Compile the TrioFuzz engine with libc++
RUN cd /triofuzz && mkdir build && cd build && \
    /usr/bin/cmake --version && \
    env CFLAGS="-O2 -g" \
        CXXFLAGS="-O2 -g -stdlib=libc++" \
        /usr/bin/cmake -DCMAKE_C_COMPILER=clang-17 -DCMAKE_CXX_COMPILER=clang++-17 \
          -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
          -DCMAKE_EXE_LINKER_FLAGS="-lbz2 -llzma -lzstd" \
          -DCMAKE_SHARED_LINKER_FLAGS="-lbz2 -llzma -lzstd" \
          ..

# Build core libraries
RUN cd /triofuzz/build && make triofuzz triofuzz_lib triofuzz_objects -j$(nproc)

# Install the TrioFuzz static engine
RUN install -D /triofuzz/build/libtriofuzz.a /usr/lib/libtriofuzz.a && \
    ranlib /usr/lib/libtriofuzz.a || true
