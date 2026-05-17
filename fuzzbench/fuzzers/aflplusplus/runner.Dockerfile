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

FROM gcr.io/fuzzbench/base-image

ARG DEBIAN_FRONTEND=noninteractive

# Targets are built with clang-17 + -stdlib=libc++, so they dynamically link
# against libc++.so.1 / libc++abi.so.1 / libunwind.so.1 from LLVM 17. Install
# them so the fuzz target can be loaded by afl-fuzz at runtime.
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget gnupg && \
    echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-17 main" >> /etc/apt/sources.list && \
    (wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc) && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libc++1-17 libc++abi1-17 libunwind-17

# This makes interactive docker runs painless:
ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/out"
#ENV AFL_MAP_SIZE=2621440
ENV PATH="$PATH:/out"
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV AFL_TESTCACHE_SIZE=2
# RUN apt-get update && apt-get upgrade && apt install -y unzip git gdb joe
