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
"""Integration code for TrioFuzz - Unified Multi-Algorithm Fuzzer.

TrioFuzz integrates three learning algorithms into one unified framework:

1. Thompson Sampling (Outer Layer):
   - Selects among AFL++ configurations (power schedule x mutation mode x splice)
   - Uses Beta distribution-based Thompson Sampling
   - Provides global strategy selection

2. MOpt PSO (Middle Layer):
   - Particle Swarm Optimization for mutation operator probability learning
   - Updates operator weights based on coverage feedback
   - 19 MOpt-style operators

3. MuoFuzz Markov Chain (Inner Layer):
   - Online learning of operator transition probabilities
   - Transition matrix size matches the active operator set (e.g. havoc with/without splice)
   - Stack size selection with epsilon-greedy

Thread Architecture:
- Scheduler (1 thread): Centralized learning updates + task sampling
- Workers (~75% cores): Execute mutation tasks using learned strategies
- Explorers (~25% cores): Random exploration to prevent local optima

This enables:
- Fair comparison of unified vs individual learning algorithms
- Study of multi-level learning synergies
- Exploration/exploitation balance through thread specialization
"""

import os
import shutil
import subprocess

from fuzzers import utils
from fuzzers.libfuzzer import fuzzer as libfuzzer_fuzzer


def build():
    """Build benchmark."""
    build_directory = os.environ['OUT']

    # TrioFuzz uses trace-pc-guard instrumentation for AFL++-compatible
    # coverage tracking with XOR-based edge hashing (65536 byte bitmap).
    cflags_common = [
        '-g',
        '-O1',
        '-fsanitize-coverage=trace-pc-guard,trace-cmp',
        '-Wl,-lrt',
        '-Wno-error=documentation',
    ]
    benchmark = os.getenv('BENCHMARK', '')
    cflags_c = list(cflags_common)
    cflags_cxx = list(cflags_common)
    libs = ['-lpthread', '-lrt', '-ldl']

    if 'systemd' in benchmark:
        os.environ.setdefault('FUZZING_ENGINE', 'libfuzzer')
        ldflags = os.environ.get('LDFLAGS', '')
        if '-lcrypto' not in ldflags:
            os.environ['LDFLAGS'] = (ldflags + ' -lcrypto').strip()

    # Handle libwebp fuzztest benchmark
    if benchmark == 'libwebp_animencoder_fuzzer_animencoder.animencodertest':
        cflags_c.append('-fsanitize=fuzzer')
        cflags_cxx.append('-fsanitize=fuzzer')

    utils.append_flags('CFLAGS', cflags_c)
    utils.append_flags('CXXFLAGS', cflags_cxx)
    utils.append_flags('LIBS', libs)

    os.environ['CC'] = '/usr/bin/clang'
    os.environ['CXX'] = '/usr/bin/clang++'

    # Link against TrioFuzz unified engine
    os.environ['FUZZER_LIB'] = '/usr/lib/libtriofuzz.a'
    os.environ.setdefault('LIB_FUZZING_ENGINE', os.environ['FUZZER_LIB'])

    utils.build_benchmark()


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer. Wrapper that uses the defaults when calling run_fuzzer."""
    benchmark = os.getenv('BENCHMARK', '')

    # For libwebp's fuzztest-based benchmark, use libFuzzer
    if benchmark == 'libwebp_animencoder_fuzzer_animencoder.animencodertest':
        libfuzzer_fuzzer.fuzz(input_corpus, output_corpus, target_binary)
    else:
        run_fuzzer(input_corpus, output_corpus, target_binary)


def run_fuzzer(input_corpus, output_corpus, target_binary, extra_flags=None):
    """Run fuzzer."""
    if extra_flags is None:
        extra_flags = []

    utils.create_seed_file_for_empty_corpus(input_corpus)

    os.makedirs(output_corpus, exist_ok=True)

    # Mirror initial corpus into the output directory
    for root, _, files in os.walk(input_corpus):
        rel_dir = os.path.relpath(root, input_corpus)
        dest_dir = output_corpus if rel_dir == '.' else os.path.join(
            output_corpus, rel_dir)
        os.makedirs(dest_dir, exist_ok=True)
        for filename in files:
            src_path = os.path.join(root, filename)
            dst_path = os.path.join(dest_dir, filename)
            if not os.path.exists(dst_path):
                shutil.copy2(src_path, dst_path)

    # Record guard IDs into the AFL-style bitmap for coverage alignment
    if os.getenv('TRIOFUZZ_DISABLE_GUARD_COVERAGE') != '1':
        os.environ.setdefault('TRIOFUZZ_INCLUDE_GUARD_COVERAGE', '1')


    flags = [
        '-threads=5',
        '--worker-threads=2',
        '--explorer-threads=2',
    ]

    flags += extra_flags

    flags.append('--disable-corpus-optimization')

    if os.getenv('TRIOFUZZ_DISABLE_GUARD_COVERAGE') != '1':
        flags.append('--include-guard-coverage')

    # Dictionary support: merge available dictionaries
    dictionary_paths = []
    aflpp_dict_path = os.path.join(os.environ.get('OUT', ''), 'afl++.dict')
    if aflpp_dict_path and os.path.exists(aflpp_dict_path):
        dictionary_paths.append(aflpp_dict_path)

    benchmark_dict_path = utils.get_dictionary_path(target_binary)
    if benchmark_dict_path and os.path.exists(benchmark_dict_path):
        dictionary_paths.append(benchmark_dict_path)

    if dictionary_paths:
        combined_dict_path = os.path.join(os.environ.get('OUT', output_corpus),
                                          'triofuzz.dict')
        try:
            with open(combined_dict_path, 'w', encoding='utf-8') as out:
                out.write('# Auto-generated dictionary for TrioFuzz\n')
                for path in dictionary_paths:
                    out.write(f'\n# Source: {path}\n')
                    with open(path, 'r', encoding='utf-8', errors='ignore') as inp:
                        content = inp.read()
                        out.write(content)
                        if content and not content.endswith('\n'):
                            out.write('\n')
            flags.append('-dict=' + combined_dict_path)
        except Exception:
            flags.append('-dict=' + dictionary_paths[0])

    # Input/output configuration
    flags.append('-seeds=' + input_corpus)
    flags.append('-output=' + output_corpus)

    # ========== TrioFuzz Unified Learning Configuration ==========

    # Enable three-layer unified learning mode
    flags.append('--use-triofuzz-unified')

    # Thompson Sampling parameters (Layer 1)
    flags.append('--ts-update-period=50000')
    flags.append('--ts-decay=0.95')
    flags.append('--ts-havoc-stack-pow2=4')

    # MOpt PSO parameters (Layer 2)
    flags.append('--mopt-update-period=500000')

    # Hybrid period configuration for non-stationary adaptation
    flags.append('--ts-time-period=60')
    flags.append('--mopt-time-period=60')
    flags.append('--markov-time-period=10')

    # Minimum samples for time-triggered updates (noise protection)
    flags.append('--ts-min-samples=100')
    flags.append('--mopt-min-samples=500')
    flags.append('--markov-min-samples=50')

    # Allow callers to override defaults via ADDITIONAL_ARGS
    if 'ADDITIONAL_ARGS' in os.environ:
        flags += os.environ['ADDITIONAL_ARGS'].split(' ')

    command = [target_binary] + flags
    print('[run_fuzzer] Running TrioFuzz: ' + ' '.join(command))

    retcode = subprocess.call(command)
    if retcode != 0:
        print('[run_fuzzer] Fuzzer exited with non-zero code '
              f'{retcode}. Crash or abort likely occurred; '
              'see the output directory for crash artifacts.')
