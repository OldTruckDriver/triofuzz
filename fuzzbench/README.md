# TrioFuzz FuzzBench Integration
## Prerequisites

- **OS**: Ubuntu 20.04+ (or any Linux with Docker support)
- **Docker**: 20.10+
- **Docker Compose**: v1.29+ (or v2)
- **Python**: 3.10+
- **Disk**: At least 50 GB free (Docker images are large)
- **CPU**: Multi-core recommended; experiments allocate CPU cores to runners

## Quick Start

```bash

# 1.Install make for your linux distribution.
sudo apt-get install build-essential

# 2. Install Python dependencies
sudo apt-get install python3.10-dev python3.10-venv
make install-dependencies

# 3. Activate this virtualenv before running further commands.
source .venv/bin/activate


# 4. Build Docker base images
docker build --no-cache -t gcr.io/fuzzbench/base-image docker/base-image/
docker build --no-cache -t gcr.io/fuzzbench/dispatcher-image docker/dispatcher-image/

# 5. Run a single fuzzer-benchmark pair (quick test with single CPU core, ~20 seconds)
export FUZZER_NAME=triofuzz
export BENCHMARK_NAME=libpng_libpng_read_fuzzer
make test-run-$FUZZER_NAME-$BENCHMARK_NAME
```

## Building the Environment

### Step 1: Install Python Dependencies

Create a virtual environment and install all required packages:

```bash
make install-dependencies
```

This creates a `.venv/` directory with Python 3.10 and installs packages from `requirements.txt` (numpy, pandas, sqlalchemy, redis, etc.).

Activate the virtual environment manually if needed:

```bash
source .venv/bin/activate
```

### Step 2: Build Docker Base Images

FuzzBench uses a layered Docker image architecture. The base images must be built first:

```bash
# Build the base image (Ubuntu 20.04 + Python 3.10 + Google Cloud CLI)
docker build --no-cache -t gcr.io/fuzzbench/base-image docker/base-image/

# Build the dispatcher image (orchestrates experiments)
docker build --no-cache -t gcr.io/fuzzbench/dispatcher-image docker/dispatcher-image/
```

### Step 3: Generate the Makefile Targets

The fuzzer/benchmark-specific Makefile targets are auto-generated:

```bash
source .venv/bin/activate
PYTHONPATH=. python3 docker/generate_makefile.py docker/generated.mk
```

This creates `docker/generated.mk` which defines build/run/test/debug targets for every fuzzer-benchmark combination.

## Docker Image Architecture

Images are built in a multi-stage pipeline:

```
base-image (Ubuntu 20.04 + Python 3.10)
├── dispatcher-image (orchestration + Docker client)
├── {benchmark}-project-builder (compiles benchmark source)
│   └── {fuzzer}-{benchmark}-builder-intermediate (adds fuzzer engine)
│       └── {fuzzer}-{benchmark}-builder (links fuzzer + benchmark)
│           └── {fuzzer}-{benchmark}-intermediate-runner (runtime deps)
│               └── {fuzzer}-{benchmark}-runner (final runner image)
└── coverage-{benchmark}-builder (for coverage measurement)
```

For TrioFuzz specifically, the builder image (`fuzzers/triofuzz/builder.Dockerfile`):
- Installs LLVM-17 with libc++
- Clones and builds AFL++ (for dictionary generation)
- Compiles the TrioFuzz C++ engine into `/usr/lib/libtriofuzz.a`
- Uses `trace-pc-guard` + `trace-cmp` instrumentation

## Running Experiments

### Single Fuzzer-Benchmark Pair

Build and run a single fuzzer on a single benchmark target:

```bash
export FUZZER_NAME=triofuzz
export BENCHMARK_NAME=libpng_libpng_read_fuzzer

# Full run
make run-$FUZZER_NAME-$BENCHMARK_NAME

# Quick 20-second test run
make test-run-$FUZZER_NAME-$BENCHMARK_NAME

# Debug mode (interactive shell in builder container)
make debug-builder-$FUZZER_NAME-$BENCHMARK_NAME
```

### Multi-Benchmark Experiment (Local, Docker Compose)

Run a full experiment with multiple benchmarks, trials, and automated measurement using Docker Compose:

```bash
make run-experiment
```

This starts three services defined in `compose/fuzzbench.yaml`:
- **run-experiment**: Orchestrates the experiment
- **worker** (x2 by default): Builds images and runs trials
- **queue-server**: Redis for job distribution

Stop a running experiment:

```bash
make stop-experiment
```

### Multi-Benchmark Experiment (Python API)

For more control, use the Python API directly:

```bash
source .venv/bin/activate

PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config config/experiment.yaml \
  --experiment-name my-experiment \
  --fuzzers triofuzz \
  --benchmarks libpng_libpng_read_fuzzer libjpeg-turbo_libjpeg_turbo_fuzzer lcms_cms_transform_fuzzer \
  --runners-cpus 64
```

#### Key CLI Arguments

| Argument | Description |
|---|---|
| `-c, --experiment-config` | Path to YAML config file (required) |
| `-e, --experiment-name` | Experiment name, lowercase alphanumeric + hyphens, max 30 chars (required) |
| `-f, --fuzzers` | Fuzzers to evaluate (default: all) |
| `-b, --benchmarks` | Benchmarks to use (default: all coverage benchmarks) |
| `-rc, --runners-cpus` | Total CPU cores available for runners |
| `-cb, --concurrent-builds` | Max concurrent Docker builds (default: 30) |
| `-ns, --no-seeds` | Run without seed corpora |
| `-nd, --no-dictionaries` | Run without dictionaries |
| `-o, --oss-fuzz-corpus` | Use OSS-Fuzz public corpora |
| `-cs, --custom-seed-corpus-dir` | Path to custom seed corpus directory |

## Experiment Configuration

The experiment config file (`config/experiment.yaml`) controls experiment parameters:

```yaml
# Benchmarks and fuzzers
benchmarks:
  - libpng_libpng_read_fuzzer
  - libjpeg-turbo_libjpeg_turbo_fuzzer
  - lcms_cms_transform_fuzzer
fuzzers:
  - triofuzz

# Experiment settings
max_total_time: 3600          # Duration per trial in seconds
trials: 3                     # Number of independent trials per fuzzer-benchmark pair
snapshot_period: 60           # Measurement interval in seconds

# Storage (local paths for local experiments, gs:// for GCP)
experiment_filestore: /tmp/experiment-data
report_filestore: /tmp/report-data
local_experiment: true

# Resource allocation
runners_cpus: 64              # Total CPU cores for runners
```

## Available Benchmarks

We have integrated 10 additional benchmarks from [OSS-Fuzz](https://github.com/google/oss-fuzz) into FuzzBench using the `oss_fuzz_benchmark_integration.py` script, expanding the evaluation suite to cover a wider range of real-world projects.

| Category | Benchmarks |
|---|---|
| Image | `libpng_libpng_read_fuzzer`, `libjpeg-turbo_libjpeg_turbo_fuzzer`, `stb_stbi_read_fuzzer`, `freetype2_ftfuzzer`, `libexif_exif_loader_fuzzer` |
| Codec | `libaom_av1_dec_fuzzer`, `openh264_decoder_fuzzer`, `vorbis_decode_fuzzer` |
| Compression | `zlib_zlib_uncompress_fuzzer`, `miniz_zip_fuzzer` |
| Parsing | `libxml2_xml`, `libxslt_xpath`, `rapidjson_fuzzer`, `yaml-cpp_load_fuzzer`, `jsoncpp_jsoncpp_fuzzer`, `cmake_xml_parser_fuzzer`, `cppitertools_fuzz_cppitertools` |
| Font/Text | `harfbuzz_hb-shape-fuzzer`, `woff2_convert_woff2ttf_fuzzer`, `lcms_cms_transform_fuzzer` |
| Crypto | `openssl_x509`, `mbedtls_fuzz_dtlsclient` |
| Database | `sqlite3_ossfuzz` |
| Network | `curl_curl_fuzzer_http`, `c-ares_ares_parse_reply_fuzzer`, `libpcap_fuzz_both` |
| Binary Analysis | `capstone_fuzz_disasmv5`, `bloaty_fuzz_target` |
| System | `systemd_fuzz-link-parser`, `libunwind_fuzz_libunwind`, `openthread_ot-ip6-send-fuzzer` |
| Hash/Regex | `highwayhash_highwayhash_fuzzer`, `re2_fuzzer` |
| Language Runtime | `mruby_mruby_fuzzer_8c8bbd`, `php_php-fuzz-parser_0dbedb` |
| Geospatial | `proj4_proj_crs_to_crs_fuzzer` |

See the `benchmarks/` directory for the full list (40 benchmarks total).

## TrioFuzz Variants

| Variant | Description |
|---|---|
| `triofuzz` | Default configuration (1 scheduler + 2 workers + 1 scouter) |
| `triofuzz_1w2s` | 1 worker, 2 scouter |
| `triofuzz_2w2s` | 2 workers, 2 scouter |
| `triofuzz_3w0s` | 3 workers, 0 scouter |
| `triofuzz_4w2s` | 4 workers, 2 scouter |

## Cleaning Up

```bash
# Remove experiment data
sudo rm -rf /tmp/experiment-data/ /tmp/report-data/

# Prune Docker images and containers
docker stop $(docker ps -q)
docker system prune -a
```
