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
"""Integration code for TrioFuzz ablation: MuoFuzz Markov-only (among Trio modules).

This variant enables Layer 3 (MuoFuzz Markov) while disabling:
- EcoFuzz power schedule arms
- Layer 2: MOpt PSO
"""

import os

from fuzzers.libfuzzer import fuzzer as libfuzzer_fuzzer
from fuzzers.triofuzz import fuzzer as triofuzz_fuzzer


def build():
    """Build benchmark."""
    triofuzz_fuzzer.build()


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    benchmark = os.getenv('BENCHMARK', '')

    # For libwebp's fuzztest-based benchmark, use libFuzzer.
    if benchmark == 'libwebp_animencoder_fuzzer_animencoder.animencodertest':
        libfuzzer_fuzzer.fuzz(input_corpus, output_corpus, target_binary)
        return

    triofuzz_fuzzer.run_fuzzer(
        input_corpus,
        output_corpus,
        target_binary,
        extra_flags=[
            '--disable-ecofuzz',
            '--disable-mopt-pso',
            '--enable-muofuzz-markov',
        ],
    )

