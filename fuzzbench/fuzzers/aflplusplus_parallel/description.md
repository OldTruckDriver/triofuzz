# AFL++ Vanilla Parallel Mode

AFL++ running in vanilla master-slave parallel mode without Thompson Sampling.
Default configuration: 4 cores (1 master + 3 slaves).

## Overview

This fuzzer uses AFL++'s native parallel fuzzing capability with the standard
`-M` (master) and `-S` (slave) flags. Unlike `aflplusplus_ts_parallel`, this
variant does NOT use Thompson Sampling for mutation selection - it uses AFL++'s
default uniform random mutation selection.

## Architecture

```
+------------------+  +------------------+  +------------------+  +------------------+
|  Master (-M)     |  |  Slave01 (-S)    |  |  Slave02 (-S)    |  |  Slave03 (-S)    |
|  Uniform Random  |  |  Uniform Random  |  |  Uniform Random  |  |  Uniform Random  |
|  + CmpLog        |  |  + CmpLog        |  |  (no CmpLog)     |  |  (no CmpLog)     |
+--------+---------+  +--------+---------+  +--------+---------+  +--------+---------+
         |                     |                     |                     |
         +---------------------+---------------------+---------------------+
                                       |
                               +-------v-------+
                               |  Shared Corpus |
                               |  (sync_dir)    |
                               +---------------+
```

## Key Features

- **Uniform Random Mutation**: Standard AFL++ mutation selection (no adaptive learning)
- **Corpus Sharing**: AFL++ native sync mechanism shares interesting inputs
- **Diversity**: Slaves 2+ don't use CmpLog, reducing overhead
- **Configurable Cores**: Set `AFL_PARALLEL_CORES` environment variable

## Configuration

```bash
# Default: 4 cores (1 master + 3 slaves)
export AFL_PARALLEL_CORES=4

# Use 8 cores
export AFL_PARALLEL_CORES=8
```

## Comparison

| Fuzzer | Cores | Thompson Sampling | Parallelism |
|--------|-------|-------------------|-------------|
| aflplusplus | 1 | No | None |
| aflplusplus_parallel | 4 | No | Master-Slave |
| aflplusplus_ts | 1 | Yes | None |
| aflplusplus_ts_parallel | 4 | Yes | Master-Slave |

## Use Case

This variant is useful as a baseline for comparing the effectiveness of
Thompson Sampling in parallel fuzzing. By comparing `aflplusplus_parallel`
with `aflplusplus_ts_parallel`, you can measure the impact of adaptive
mutation selection while controlling for parallelism.

Repository: [https://github.com/AFLplusplus/AFLplusplus/](https://github.com/AFLplusplus/AFLplusplus/)
