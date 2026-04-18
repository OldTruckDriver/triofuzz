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
#
"""Integration code for AFL++ in vanilla parallel master-slave mode."""

import os
import shutil
import subprocess
import time

from fuzzers.afl import fuzzer as afl_fuzzer
from fuzzers import utils

# Default number of parallel instances (1 master + 3 slaves = 4 cores)
DEFAULT_NUM_CORES = 4


def get_cmplog_build_directory(target_directory):
    """Return path to CmpLog target directory."""
    return os.path.join(target_directory, 'cmplog')


def get_uninstrumented_build_directory(target_directory):
    """Return path to uninstrumented target directory."""
    return os.path.join(target_directory, 'uninstrumented')


def build(*args):  # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""
    build_modes = list(args)
    if 'BUILD_MODES' in os.environ:
        build_modes = os.environ['BUILD_MODES'].split(',')

    build_directory = os.environ['OUT']

    if not build_modes:
        build_modes = ['tracepc', 'cmplog', 'dict2file']

    build_flags = os.environ['CFLAGS']

    if build_flags.find(
            'array-bounds'
    ) != -1 and 'qemu' not in build_modes and 'classic' not in build_modes:
        if 'gcc' not in build_modes:
            build_modes[0] = 'native'

    if 'lto' in build_modes:
        os.environ['CC'] = '/afl/afl-clang-lto'
        os.environ['CXX'] = '/afl/afl-clang-lto++'
        edge_file = build_directory + '/aflpp_edges.txt'
        os.environ['AFL_LLVM_DOCUMENT_IDS'] = edge_file
        if os.path.isfile('/usr/local/bin/llvm-ranlib-13'):
            os.environ['RANLIB'] = 'llvm-ranlib-13'
            os.environ['AR'] = 'llvm-ar-13'
            os.environ['AS'] = 'llvm-as-13'
        elif os.path.isfile('/usr/local/bin/llvm-ranlib-12'):
            os.environ['RANLIB'] = 'llvm-ranlib-12'
            os.environ['AR'] = 'llvm-ar-12'
            os.environ['AS'] = 'llvm-as-12'
        else:
            os.environ['RANLIB'] = 'llvm-ranlib'
            os.environ['AR'] = 'llvm-ar'
            os.environ['AS'] = 'llvm-as'
    elif 'qemu' in build_modes:
        os.environ['CC'] = 'clang'
        os.environ['CXX'] = 'clang++'
    elif 'gcc' in build_modes:
        os.environ['CC'] = 'afl-gcc-fast'
        os.environ['CXX'] = 'afl-g++-fast'
        if build_flags.find('array-bounds') != -1:
            os.environ['CFLAGS'] = '-fsanitize=address -O1'
            os.environ['CXXFLAGS'] = '-fsanitize=address -O1'
        else:
            os.environ['CFLAGS'] = ''
            os.environ['CXXFLAGS'] = ''
            os.environ['CPPFLAGS'] = ''
    else:
        os.environ['CC'] = '/afl/afl-clang-fast'
        os.environ['CXX'] = '/afl/afl-clang-fast++'

    print('AFL++ Parallel build: ')
    print(build_modes)

    if 'qemu' in build_modes or 'symcc' in build_modes:
        os.environ['CFLAGS'] = ' '.join(utils.NO_SANITIZER_COMPAT_CFLAGS)
        cxxflags = [utils.LIBCPLUSPLUS_FLAG] + utils.NO_SANITIZER_COMPAT_CFLAGS
        os.environ['CXXFLAGS'] = ' '.join(cxxflags)

    if 'tracepc' in build_modes or 'pcguard' in build_modes:
        os.environ['AFL_LLVM_USE_TRACE_PC'] = '1'
    elif 'classic' in build_modes:
        os.environ['AFL_LLVM_INSTRUMENT'] = 'CLASSIC'
    elif 'native' in build_modes:
        os.environ['AFL_LLVM_INSTRUMENT'] = 'LLVMNATIVE'

    if 'dynamic' in build_modes:
        os.environ['AFL_LLVM_MAP_DYNAMIC'] = '1'
    if 'fixed' in build_modes:
        os.environ['AFL_LLVM_MAP_ADDR'] = '0x10000'
    if 'dict2file' in build_modes or 'native' in build_modes:
        os.environ['AFL_LLVM_DICT2FILE'] = build_directory + '/afl++.dict'
        os.environ['AFL_LLVM_DICT2FILE_NO_MAIN'] = '1'
    if 'ctx' in build_modes:
        os.environ['AFL_LLVM_CTX'] = '1'
    if 'ngram2' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '2'
    elif 'ngram3' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '3'
    elif 'ngram4' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '4'
    elif 'ngram5' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '5'
    elif 'ngram6' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '6'
    elif 'ngram7' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '7'
    elif 'ngram8' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '8'
    elif 'ngram16' in build_modes:
        os.environ['AFL_LLVM_NGRAM_SIZE'] = '16'
    if 'ctx1' in build_modes:
        os.environ['AFL_LLVM_CTX_K'] = '1'
    elif 'ctx2' in build_modes:
        os.environ['AFL_LLVM_CTX_K'] = '2'
    elif 'ctx3' in build_modes:
        os.environ['AFL_LLVM_CTX_K'] = '3'
    elif 'ctx4' in build_modes:
        os.environ['AFL_LLVM_CTX_K'] = '4'

    if 'laf' in build_modes:
        os.environ['AFL_LLVM_LAF_SPLIT_SWITCHES'] = '1'
        os.environ['AFL_LLVM_LAF_SPLIT_COMPARES'] = '1'
        os.environ['AFL_LLVM_LAF_SPLIT_FLOATS'] = '1'
        if 'autodict' not in build_modes:
            os.environ['AFL_LLVM_LAF_TRANSFORM_COMPARES'] = '1'

    if 'eclipser' in build_modes:
        os.environ['FUZZER_LIB'] = '/libStandaloneFuzzTarget.a'
    else:
        os.environ['FUZZER_LIB'] = '/libAFLDriver.a'

    os.environ['AFL_QUIET'] = '1'
    os.environ['AFL_MAP_SIZE'] = '2621440'

    src = os.getenv('SRC')
    work = os.getenv('WORK')

    with utils.restore_directory(src), utils.restore_directory(work):
        utils.build_benchmark()

    if 'cmplog' in build_modes and 'qemu' not in build_modes:
        new_env = os.environ.copy()
        new_env['AFL_LLVM_CMPLOG'] = '1'

        cmplog_build_directory = get_cmplog_build_directory(build_directory)
        os.mkdir(cmplog_build_directory)
        new_env['OUT'] = cmplog_build_directory
        fuzz_target = os.getenv('FUZZ_TARGET')
        if fuzz_target:
            new_env['FUZZ_TARGET'] = os.path.join(cmplog_build_directory,
                                                  os.path.basename(fuzz_target))

        print('Re-building benchmark for CmpLog fuzzing target')
        utils.build_benchmark(env=new_env)

    if 'symcc' in build_modes:
        symcc_build_directory = get_uninstrumented_build_directory(
            build_directory)
        os.mkdir(symcc_build_directory)

        new_env = os.environ.copy()
        new_env['CC'] = '/symcc/build/symcc'
        new_env['CXX'] = '/symcc/build/sym++'
        new_env['SYMCC_OUTPUT_DIR'] = '/tmp'
        new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stlib=libc++', '')
        new_env['FUZZER_LIB'] = '/libfuzzer-harness.o'
        new_env['OUT'] = symcc_build_directory
        new_env['SYMCC_LIBCXX_PATH'] = '/libcxx_native_build'
        new_env['SYMCC_NO_SYMBOLIC_INPUT'] = '1'
        new_env['SYMCC_SILENT'] = '1'

        new_env['OUT'] = symcc_build_directory
        fuzz_target = os.getenv('FUZZ_TARGET')
        if fuzz_target:
            new_env['FUZZ_TARGET'] = os.path.join(symcc_build_directory,
                                                  os.path.basename(fuzz_target))

        print('Re-building benchmark for symcc fuzzing target')
        utils.build_benchmark(env=new_env)

    shutil.copy('/afl/afl-fuzz', build_directory)
    if os.path.exists('/afl/afl-qemu-trace'):
        shutil.copy('/afl/afl-qemu-trace', build_directory)
    if os.path.exists('/aflpp_qemu_driver_hook.so'):
        shutil.copy('/aflpp_qemu_driver_hook.so', build_directory)
    if os.path.exists('/get_frida_entry.sh'):
        shutil.copy('/afl/afl-frida-trace.so', build_directory)
        shutil.copy('/get_frida_entry.sh', build_directory)


def _get_num_cores():
    """Get number of cores to use for parallel fuzzing."""
    # Check environment variable first
    if 'AFL_PARALLEL_CORES' in os.environ:
        return int(os.environ['AFL_PARALLEL_CORES'])
    return DEFAULT_NUM_CORES


def _build_base_command(input_corpus, output_corpus, target_binary,
                        cmplog_target_binary, additional_flags):
    """Build the base afl-fuzz command without -M/-S flags."""
    command = [
        './afl-fuzz',
        '-i', input_corpus,
        '-o', output_corpus,
        '-m', 'none',  # No memory limit
        '-t', '1000+',  # 1 sec timeout, skip hangs
    ]

    # Add dictionary if exists
    if os.path.exists('./afl++.dict'):
        command += ['-x', './afl++.dict']

    # Add cmplog if available
    if cmplog_target_binary and os.path.exists(cmplog_target_binary):
        command += ['-c', cmplog_target_binary]

    # Add any additional flags
    if additional_flags:
        command.extend(additional_flags)

    # Add target
    command += ['--', target_binary, '2147483647']

    return command


def fuzz(input_corpus,
         output_corpus,
         target_binary,
         flags=tuple(),
         skip=False,
         no_cmplog=False):
    """Run fuzzer in vanilla parallel master-slave mode (no Thompson Sampling)."""

    # Calculate CmpLog binary path
    target_binary_directory = os.path.dirname(target_binary)
    cmplog_target_binary_directory = (
        get_cmplog_build_directory(target_binary_directory))
    target_binary_name = os.path.basename(target_binary)
    cmplog_target_binary = os.path.join(cmplog_target_binary_directory,
                                        target_binary_name)

    if no_cmplog or not os.path.exists(cmplog_target_binary):
        cmplog_target_binary = None

    # Prepare environment
    afl_fuzzer.prepare_fuzz_environment(input_corpus)

    # Set AFL++ environment variables
    os.environ['AFL_IGNORE_UNKNOWN_ENVS'] = '1'
    os.environ['AFL_FAST_CAL'] = '1'
    os.environ['AFL_NO_WARN_INSTABILITY'] = '1'

    if not skip:
        os.environ['AFL_DISABLE_TRIM'] = '1'
        os.environ['AFL_CMPLOG_ONLY_NEW'] = '1'

    # Build additional flags
    additional_flags = list(flags)
    if 'ADDITIONAL_ARGS' in os.environ and not skip:
        additional_flags += os.environ['ADDITIONAL_ARGS'].split(' ')

    # Get number of cores
    num_cores = _get_num_cores()
    print(f'[AFL++ Parallel] Starting with {num_cores} cores '
          f'(1 master + {num_cores - 1} slaves)')

    # Build base command
    base_cmd = _build_base_command(input_corpus, output_corpus, target_binary,
                                   cmplog_target_binary, additional_flags)

    # Start master process
    master_cmd = base_cmd.copy()
    # Insert -M flag after -o output_corpus
    output_idx = master_cmd.index('-o') + 2
    master_cmd.insert(output_idx, '-M')
    master_cmd.insert(output_idx + 1, 'master')

    print(f'[AFL++ Parallel] Starting master: {" ".join(master_cmd)}')
    master_proc = subprocess.Popen(master_cmd)

    # Give master time to initialize
    time.sleep(2)

    # Start slave processes
    slave_procs = []
    for i in range(1, num_cores):
        slave_cmd = base_cmd.copy()
        # Insert -S flag after -o output_corpus
        output_idx = slave_cmd.index('-o') + 2
        slave_cmd.insert(output_idx, '-S')
        slave_cmd.insert(output_idx + 1, f'slave{i:02d}')

        # Remove -c cmplog for some slaves to increase diversity (optional)
        # Slaves 2+ don't use cmplog to reduce overhead
        if i >= 2 and '-c' in slave_cmd:
            c_idx = slave_cmd.index('-c')
            slave_cmd.pop(c_idx)  # Remove -c
            slave_cmd.pop(c_idx)  # Remove cmplog path

        print(f'[AFL++ Parallel] Starting slave{i:02d}: {" ".join(slave_cmd)}')
        slave_proc = subprocess.Popen(slave_cmd)
        slave_procs.append(slave_proc)

        # Small delay between slave starts
        time.sleep(1)

    print(f'[AFL++ Parallel] All {num_cores} instances started')

    # Wait for master (slaves will be terminated when master exits or vice versa)
    try:
        master_proc.wait()
    except KeyboardInterrupt:
        print('[AFL++ Parallel] Interrupted, terminating all instances...')
    finally:
        # Terminate all processes
        master_proc.terminate()
        for proc in slave_procs:
            proc.terminate()

        # Wait for graceful termination
        master_proc.wait()
        for proc in slave_procs:
            proc.wait()

    print('[AFL++ Parallel] All instances terminated')
