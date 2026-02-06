# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Use the pinned base-builder to keep LLVM toolchain consistent with the
# dispatcher (llvm-cov/llvm-profdata) and other benchmarks. Install Python
# tooling needed for generating the seed corpus from Capstone's Python bindings.
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make cmake python3 python3-pip && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1 && \
    python3 -m pip install --upgrade setuptools build wheel pip
RUN git clone --depth 1 --branch v5 https://github.com/capstone-engine/capstone.git capstonev5
RUN git clone --depth 1 --branch next https://github.com/capstone-engine/capstone.git capstonenext
WORKDIR $SRC
COPY build.sh $SRC/
