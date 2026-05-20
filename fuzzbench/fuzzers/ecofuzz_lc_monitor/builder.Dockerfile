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
    apt-get install -y python3 wget

# Download and compile EcoFuzz.
# Set AFL_NO_X86 to skip flaky tests.
RUN git clone https://github.com/MoonLight-SteinsGate/EcoFuzz /EcoFuzz && \
    cd /EcoFuzz && \
    git checkout 1fd94608291b708e9c97240780aea16349c688b8 && \
    mv /EcoFuzz/EcoFuzz /afl && \
    rm -rf /EcoFuzz

# Patch EcoFuzz to emit learning-cycle metrics into the output directory.
COPY patch_ecofuzz.py /afl/patch_ecofuzz.py
RUN cd /afl && \
    python3 patch_ecofuzz.py afl-fuzz.c afl-fuzz.c.patched && \
    mv afl-fuzz.c afl-fuzz.c.orig && \
    mv afl-fuzz.c.patched afl-fuzz.c && \
    AFL_NO_X86=1 make

# Use afl_driver.cpp from LLVM as our fuzzing library.
RUN wget https://raw.githubusercontent.com/llvm/llvm-project/5feb80e748924606531ba28c97fe65145c65372e/compiler-rt/lib/fuzzer/afl/afl_driver.cpp -O /afl/afl_driver.cpp && \
    clang -Wno-pointer-sign -c /afl/llvm_mode/afl-llvm-rt.o.c -I/afl && \
    clang++ -stdlib=libc++ -std=c++11 -O2 -c /afl/afl_driver.cpp && \
    ar r /libAFL.a *.o

