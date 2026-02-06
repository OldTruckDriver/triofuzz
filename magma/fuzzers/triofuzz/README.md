# TrioFuzz Magma Integration

TrioFuzz is a unified multi-algorithm fuzzer that integrates three learning algorithms:

1. **Thompson Sampling (Outer Layer)**: Selects among AFL++ configurations
2. **MOpt PSO (Middle Layer)**: Particle Swarm Optimization for mutation operator probability learning
3. **MuoFuzz Markov Chain (Inner Layer)**: Online learning of operator transition probabilities

## Configuration Files

### 1. `fetch.sh`
- Copies TrioFuzz source code from `$MAGMA/triofuzz/src` to `$FUZZER/repo`
- Source should be pre-downloaded from FuzzBench

### 2. `preinstall.sh`
- Installs build dependencies (Clang 11+, CMake, OpenSSL, etc.)
- Sets up LLVM alternatives

### 3. `build.sh`
- Compiles TrioFuzz library (`libtriofuzz.a`)
- Outputs library to `$OUT/` directory

### 4. `run.sh`
- Runs TrioFuzz fuzzer with unified learning configuration
- Key parameters from fuzzer.py:
  - `-threads=4`: Fixed 4 threads (1 Scheduler + 2 Workers + 1 Explorer)
  - `--use-triofuzz-unified`: Enable three-layer unified learning
  - `--xfuzz-update-period=50000`: Thompson Sampling update window
  - `--xfuzz-ts-decay=0.95`: EMA decay factor
  - `--mopt-update-period=500000`: MOpt PSO update period
  - `--enable-crash-recovery`: Enable checkpoint-based crash recovery

### 5. `findings.sh`
- Lists crash findings in `$SHARED/findings`

### 6. `runonce.sh`
- Runs a single test case for verification

### 7. `driver.cpp`
- Compatibility layer for Magma's build system
- TrioFuzz library provides main(), targets implement `LLVMFuzzerTestOneInput()`

## Thread Architecture

- **Scheduler (1 thread)**: Centralized learning updates + task sampling
- **Workers (~75% cores)**: Execute mutation tasks using learned strategies
- **Scouters (~25% cores)**: Random exploration to prevent local optima

## Usage with Magma

```bash
# Build and run with Magma
./magma/tools/captain/captain.sh triofuzz <target>
```


## Command Line Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-threads` | 4 | Total thread count |
| `--worker-threads` | 2 | Worker thread count |
| `--explorer-threads` | 1 | Explorer thread count |
| `--use-triofuzz-unified` | enabled | Enable unified learning |
| `--xfuzz-update-period` | 50000 | TS update window (executions) |
| `--xfuzz-ts-decay` | 0.95 | EMA decay factor |
| `--xfuzz-havoc-stack-pow2` | 4 | Havoc stack size power |
| `--mopt-update-period` | 500000 | MOpt PSO update period |
| `--enable-crash-recovery` | enabled | Enable checkpoint recovery |
| `--checkpoint-interval` | 1 | Checkpoint save interval (seconds) |
