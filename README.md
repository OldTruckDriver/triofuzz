# TrioFuzz

A three-tier architecture for adaptive strategy selection in fuzzing. TrioFuzz integrates three online learning layers — Thompson Sampling, MOpt PSO, and MuoFuzz Markov Chain — into a unified, multi-threaded fuzzing engine, enabling coordinated adaptation across configuration selection, operator weighting, and mutation sequencing.

## Architecture

### Three-Tier Learning

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Thompson Sampling                         │
│  Selects configuration arm                          │
│  (power schedule (EcoFuzz) × mutation mode × splice)│
│  Beta distribution, hybrid period updates           │
├─────────────────────────────────────────────────────┤
│  Layer 2: MOpt PSO                                  │
│  Learns mutation operator probabilities             │
│  Particle Swarm Optimization over 19 operators      │
├─────────────────────────────────────────────────────┤
│  Layer 3: MuoFuzz Markov Chain                      │
│  Learns operator transition sequences               │
│  Transition matrix + epsilon-greedy stack size      │
└─────────────────────────────────────────────────────┘
```

- **Layer 1 (Thompson Sampling)**: Selects among AFL++ configurations — combinations of power schedules including EcoFuzz, mutation modes (havoc, mopt), and splice on/off. Uses Beta distribution sampling with exponential decay (0.95) and stagnation recovery.
- **Layer 2 (MOpt PSO)**: Particle Swarm Optimization that learns per-operator mutation probabilities. Tracks find rates across 19 mutation operators and updates weights via inertia + cognitive + social velocity terms.
- **Layer 3 (MuoFuzz Markov Chain)**: Learns operator-to-operator transition probabilities and selects mutation stack sizes (2–16) with epsilon-greedy exploration. Builds alias tables for O(1) sampling.

### Thread Architecture

```
┌──────────────────────────────────────────────┐
│              Scheduler Thread                │
│  - Runs three-layer learning                 │
│  - Generates tasks, distributes to workers   │
│  - Collects results, updates learners        │
│  - Detects stagnation, triggers recovery     │
├──────────────┬───────────────────────────────┤
│ Worker (×N)  │  Scouter (×M)                │
│ - Dequeue    │  - Random exploration         │
│   tasks      │  - Maintains diversity        │
│ - Execute    │  - Prevents local optima      │
│   mutations  │  - Biased toward analysis     │
│ - Report     │    algorithms (CmpLog, etc.)  │
│   results    │                               │
└──────────────┴───────────────────────────────┘
```

Default thread allocation: 1 scheduler + 2 workers + 1 scouter (4 threads total). Workers execute mutation tasks using learned strategies; scouters perform random exploration to maintain diversity.

## Project Structure

```
triofuzz/
├── CMakeLists.txt          # Build configuration (CMake 3.16+, C++17)
├── README.md
├── include/                # Header files
│   ├── core/               # Engine, context, thread engine, learners
│   ├── algorithms/         # Mutation, feedback, scheduling, instrumentation
│   ├── combination/        # Thompson Sampling, MAB, algorithm composition
│   ├── utils/              # Corpus, coverage, checkpoint, config managers
│   └── ...
├── src/                    # Implementation files
│   ├── core/               # Engine + thread engine (~12K lines)
│   ├── algorithms/         # Algorithm implementations
│   ├── combination/        # Strategy selection implementations
│   ├── interface/          # Main entry point (triofuzz_main.cpp)
│   └── utils/              # Utility implementations
├── external/               # Third-party (nlohmann/json header-only)
├── fuzzbench/              # FuzzBench integration (see fuzzbench/README.md)
├── magma/                  # Magma benchmark integration
└── ossfuzz_projects/       # OSS-Fuzz benchmark targets
```

### Source Code Organization

#### `include/core/` & `src/core/` — Engine Core

| File | Description |
|---|---|
| `engine.hpp` / `fuzzing_engine.cpp` | Main fuzzing engine: seed selection, algorithm combination, target execution, result processing |
| `specialized_thread_engine.hpp/.cpp` | Multi-threaded executor: scheduler/worker/scouter thread loops, task queues, result aggregation |
| `triofuzz_unified_learner.hpp` | Three-layer unified learner (TS + MOpt PSO + Markov), hybrid period strategy |
| `mopt_online_learner.hpp` | AFL++ MOpt PSO implementation: particle swarm operator weight learning |
| `context.hpp` / `context.cpp` | SharedContext (thread-safe data), HintBus (inter-algorithm signaling), CoverageInfo |
| `algorithm.hpp` | Algorithm base class: `execute()` interface, performance metrics, metadata |
| `lockfree_coverage_collector.hpp/.cpp` | Thread-local coverage accumulation with lock-free aggregation |
| `enhanced_crash_tracker.cpp` | Unique crash detection via stack hashing |

#### `include/algorithms/` & `src/algorithms/` — Algorithms

| Directory | Contents |
|---|---|
| `mutation/` | AFL++ havoc/splice, CmpLog, Redqueen, smart dictionary, format-aware, overflow, structure-aware mutations |
| `feedback/` | Feedback analysis interface |
| `scheduling/` | Seed scheduling: rare edge prioritization (AFL++ style) |
| `instrumentation/` | CmpLog instrumentation, coverage instrumentation base |
| `optimization/` | PSO specialization for operator learning |

#### `include/combination/` & `src/combination/` — Strategy Selection

| File | Description |
|---|---|
| `thompson_sampling.hpp/.cpp` | Beta distribution Thompson Sampling with batch execution, exploration/cooldown |
| `combiner.hpp/.cpp` | Algorithm composition (sequential, parallel, weighted, adaptive modes) |
| `multi_armed_bandit.hpp/.cpp` | Multi-armed bandit interface |
| `unified_thompson_sampling.hpp/.cpp` | Enhanced TS variant |

#### `src/interface/` — Entry Point

| File | Description |
|---|---|
| `triofuzz_main.cpp` | CLI argument parsing, engine initialization, main loop, signal handling |
| `dummy_fuzzer.cpp` | Test/development harness |

#### `include/utils/` & `src/utils/` — Utilities

| File | Description |
|---|---|
| `corpus_manager` | Thread-safe seed corpus management |
| `coverage_tracker` | Coverage statistics collection |
| `checkpoint_manager` | State serialization and crash recovery |
| `config_manager` | Configuration loading and validation |
| `performance_monitor` | Runtime performance tracking |
| `relaxed_stats` | Non-atomic statistics for low-overhead counters |

## Building

### Prerequisites

- CMake >= 3.16
- C++17 compiler (Clang-17 recommended, GCC also supported)
- OpenSSL (for crash tracking hashing)
- pthreads

### Build Steps

```bash
mkdir build && cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make -j$(nproc)
```

This produces three build targets:

| Target | Output | Description |
|---|---|---|
| `triofuzz` | `libtriofuzz.a` | Static library with main entry point — link with your fuzz target |
| `triofuzz_lib` | `libtriofuzz_lib.a` | Static library without main — for custom integration |
| `triofuzz_test` | `triofuzz_test` | Test executable with dummy fuzzer |

### Usage

Link `libtriofuzz.a` against your instrumented fuzz target:

```bash
clang++ -fsanitize-coverage=trace-pc-guard,trace-cmp -g -O1 \
    your_fuzz_target.cc -o your_fuzz_target \
    /path/to/libtriofuzz.a -lpthread -lrt -ldl -lm -lcrypto
```

Run:

```bash
./your_fuzz_target \
    -seeds=./seeds -output=./output \
    -threads=4 --worker-threads=2 --explorer-threads=1 \
    --use-triofuzz-unified \
    --ts-update-period=50000 --ts-decay=0.95 \
    --mopt-update-period=500000 \
    --ts-time-period=60 --mopt-time-period=60 --markov-time-period=10
```

Key flags:

| Flag | Description |
|---|---|
| `-threads=N` | Total thread count |
| `--worker-threads=N` | Number of worker threads |
| `--explorer-threads=N` | Number of scouter threads |
| `--use-triofuzz-unified` | Enable three-layer learning mode |
| `--ts-update-period=N` | Thompson Sampling update period (executions) |
| `--ts-decay=F` | TS exponential decay factor |
| `--mopt-update-period=N` | MOpt PSO update period (executions) |
| `--ts-time-period=S` | TS time-based update interval (seconds) |
| `--mopt-time-period=S` | MOpt time-based update interval (seconds) |
| `--markov-time-period=S` | Markov chain update interval (seconds) |
| `-dict=PATH` | Dictionary file for token-based mutations |
| `--disable-corpus-optimization` | Disable corpus minimization |
| `--include-guard-coverage` | Include guard IDs in coverage bitmap |

## Benchmarking

### FuzzBench

The `fuzzbench/` directory contains a full [Google FuzzBench](https://google.github.io/fuzzbench/) integration with 40 benchmarks covering image processing, compression, parsing, cryptography, networking, and more. See [fuzzbench/README.md](fuzzbench/README.md) for build and deployment instructions.

### Magma

The `magma/` directory integrates with the [Magma](https://hexhive.epfl.ch/magma/) ground-truth fuzzing benchmark. It includes:

- **9 target programs**: libpng, libsndfile, libtiff, libxml2, lua, openssl, php, poppler, sqlite3
- **29 fuzzers** for comparison: AFL, AFL++, MOpt, EcoFuzz, MuoFuzz, TrioFuzz, honggfuzz, fairfuzz, angora, symcc, and more
- **Tools**: `benchd` (benchmark daemon), `captain` (experiment orchestrator), `report_df` (result analysis)

### OSS-Fuzz Projects

The `ossfuzz_projects/` directory contains 10 real-world fuzz targets integrated from [Google OSS-Fuzz](https://github.com/google/oss-fuzz):

`c-ares_ares_parse_reply_fuzzer`, `capstone_fuzz_disasmv5`, `cmake_xml_parser_fuzzer`, `cppitertools_fuzz_cppitertools`, `libaom_av1_dec_fuzzer`, `libexif_exif_loader_fuzzer`, `libunwind_fuzz_libunwind`, `miniz_zip_fuzzer`, `rapidjson_fuzzer`, `yaml-cpp_load_fuzzer`

These have been integrated into the FuzzBench benchmarks for unified evaluation.
