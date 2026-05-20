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
"""Integration code for EcoFuzz with learning-cycle monitoring."""

import json
import os

from fuzzers.afl import fuzzer as afl_fuzzer


def build():
    """Build benchmark."""
    afl_fuzzer.build()


def get_stats(output_corpus, fuzzer_log):  # pylint: disable=unused-argument
    """Gets fuzzer stats for EcoFuzz with learning-cycle monitoring."""
    stats = {}

    stats_file = os.path.join(output_corpus, 'fuzzer_stats')
    if os.path.exists(stats_file):
        with open(stats_file, encoding='utf-8') as file_handle:
            for line in file_handle.read().splitlines():
                if ': ' not in line:
                    continue
                key, value = line.split(': ', 1)
                key = key.strip()
                value = value.strip()
                try:
                    if '.' in value:
                        stats[key] = float(value)
                    else:
                        stats[key] = int(value)
                except ValueError:
                    stats[key] = value

    lc_stats_file = os.path.join(output_corpus, 'lc_stats')
    if os.path.exists(lc_stats_file):
        with open(lc_stats_file, encoding='utf-8') as file_handle:
            for line in file_handle.read().splitlines():
                if ': ' not in line:
                    continue
                key, value = line.split(': ', 1)
                key = 'lc_' + key.strip()
                value = value.strip()
                try:
                    if '.' in value:
                        stats[key] = float(value)
                    else:
                        stats[key] = int(value)
                except ValueError:
                    stats[key] = value

    if 'execs_per_sec' not in stats:
        stats['execs_per_sec'] = 0.0

    return json.dumps(stats)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    afl_fuzzer.prepare_fuzz_environment(input_corpus)

    # Defaults for monitoring; can be overridden by the environment.
    os.environ.setdefault('ECOFUZZ_LC_LOG', '1')
    os.environ.setdefault('ECOFUZZ_LC_LOG_MODE', 'significant')
    os.environ.setdefault('ECOFUZZ_LC_RATE_REL_DELTA', '0.10')
    os.environ.setdefault('ECOFUZZ_LC_RATE_ABS_DELTA', '0.05')
    os.environ.setdefault('ECOFUZZ_LC_ENERGY_REL_DELTA', '0.25')
    os.environ.setdefault('ECOFUZZ_LC_STATS_INTERVAL_MS', '1000')

    afl_fuzzer.run_afl_fuzz(
        input_corpus,
        output_corpus,
        target_binary,
        hide_output=True,
    )

