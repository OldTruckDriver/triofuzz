# TrioFuzz Magma Integration

TrioFuzz is a unified multi-algorithm fuzzer that integrates three learning algorithms:

1. **Thompson Sampling (Outer Layer)**: Selects among AFL++ configurations
2. **MOpt PSO (Middle Layer)**: Particle Swarm Optimization for mutation operator probability learning
3. **MuoFuzz Markov Chain (Inner Layer)**: Online learning of operator transition probabilities

The vendored engine source lives in `TrioFuzz/` and is a mirror of the
repository's top-level `src/` and `include/`. `fetch.sh` copies it to
`$FUZZER/repo`, `build.sh` compiles `libtriofuzz.a` (which provides `main()`),
and targets only implement `LLVMFuzzerTestOneInput`.

---

## Crash arbitration (supervisor + single-threaded replay oracle)

TrioFuzz executes `LLVMFuzzerTestOneInput` in-process on several worker/explorer
threads with no lock. `main()` is a single-threaded **supervisor** that forks the
engine into a **worker** child. When the worker dies on a crash signal the
supervisor replays the captured input single-threaded in a fresh child and keeps
the crash only if it reproduces, then restarts the worker within the remaining
budget.

**Why it matters for Magma.** Magma's ground truth is the canary counters in
`$SHARED/canaries.raw`, not crashes, so the false-positive filtering is not the
main draw here. Campaign survivability is: under captain's `isan=1`
(`-DMAGMA_FATAL_CANARIES`) every *triggered* canary raises `SIGSEGV`, which
previously ended the campaign at the first bug found. The supervisor now absorbs
that and keeps fuzzing.

**Known, accepted artifact.** The replay child re-executes the candidate input,
so it increments the shared canary counters a second time. This slightly inflates
the `reached`/`triggered` **counts**. It does **not** change which bugs are
marked triggered, nor time-to-first-trigger — Magma's headline metrics.

Disable with `TRIOFUZZ_NO_ARBITER=1` (or `--no-arbiter`) to get the exact legacy
single-process behaviour.

| Env var | Default | Meaning |
|---|---|---|
| `TRIOFUZZ_NO_ARBITER` | unset | Set to any value to disable arbitration |
| `TRIOFUZZ_ARBITER_FAST_CRASH_SEC` | 10 | A worker dying sooner than this counts as a "fast crash" |
| `TRIOFUZZ_ARBITER_ESCALATE_AFTER` | 4000000000 (effectively off) | Consecutive fast crashes before target execution is serialized — see below |
| `TRIOFUZZ_ARBITER_MAX_RESTARTS` | 10000 | Fork-bomb guard (only enforced when a time budget is set) |

---

## Upstream arbiter behaviour this integration works around

**Adaptive serialization is disabled** (`TRIOFUZZ_ARBITER_ESCALATE_AFTER` set
absurdly high in `run.sh`). The supervisor latches `g_serialize_target` after 3
consecutive workers dying within 10s, on the theory that a target crashing that
fast is thread-unsafe. The predicate never checks whether the crash reproduced
single-threaded, so under Magma it misfires: with captain `isan=1` every
triggered canary raises `SIGSEGV`, so a target whose bugs are easy to reach dies
fast for entirely legitimate reasons; an OOM `SIGKILL` counts too. The flag is
never cleared anywhere in the source and is inherited by every later forked
worker, so one misfire serializes all target execution behind a single mutex for
the rest of the campaign. Serialization would not help in either case (neither
is a data race).

*Proper upstream fix, not applied here because it also changes FuzzBench
behaviour:* gate escalation on the false-positive counter (escalate only on
crashes that did **not** reproduce single-threaded, which is what the flag is
actually for), make it recoverable after N long-lived workers, and treat
`TRIOFUZZ_ARBITER_ESCALATE_AFTER=0` as "never".

**Killing the fuzzer means killing a process group.** The binary is a supervisor
that `fork()`s a worker. It forwards `SIGTERM` to that worker, but `SIGKILL`
cannot be caught and so cannot be forwarded — and the watchdog only ever fires
when the worker is already wedged and ignoring `SIGTERM`. `run.sh` therefore
launches the fuzzer in its own process group (`set -m`) and signals the whole
group, plus an `EXIT`/`TERM` trap so that `magma/run.sh`'s outer
`timeout $TIMEOUT` does not leave the tree running. Without this, one orphaned
multi-threaded worker would leak every `HANG_TIMEOUT`, each still writing this
campaign's corpus and still incrementing `$SHARED/canaries.raw`.

**The hang watchdog is load-bearing, not decorative.** The supervisor reaps its
worker with a blocking `waitpid(pid, &status, 0)` that has no deadline and no
liveness check — unlike `replay_reproduces`, which does poll with `WNOHANG`
against a deadline and `SIGKILL`s a stuck replay child. Compounding this,
`InProcessExecutor::execute` accepts a `timeout` parameter and never uses it, so
the in-process path has no per-execution timeout at all, and the
`--worker-threads`/`--explorer-threads` configuration this script uses takes
`SpecializedThreadEngine::stop()`, which joins unconditionally. A wedged worker
therefore freezes the campaign and defeats `-max_total_time`. `run.sh`'s
`HANG_TIMEOUT` watchdog is the only thing that recovers from that.

---

## Output layout

TrioFuzz derives **both** of these from `-output`:

```
$SHARED/triofuzz/corpus    on-disk corpus, reloaded on every engine start
$SHARED/triofuzz/crashes   crash artifacts (*.bin test cases, *.txt reports)
```

`run.sh` deliberately points `-output` at `$SHARED/triofuzz`, **not**
`$SHARED/findings`. Magma replays every path `findings.sh` prints through
`$MAGMA/runonce.sh` (see `tools/captain/extract.sh`); with the corpus living
under the findings directory, crash triage would replay the entire corpus.
`findings.sh` exposes only `$SHARED/triofuzz/crashes/*.bin`, plus
`$SHARED/output/crashes/*.bin` for the `TRIOFUZZ_NO_ARBITER=1` fallback —
in legacy mode signal crashes go through `EnhancedCrashTracker`, which hardcodes
a *relative* `"output/crashes"` and so writes them relative to the working
directory `magma/run.sh` sets (`$SHARED`).

**Keep `run.sh` and `findings.sh` in sync if you change this path.**

### Corpus persistence

`<output>/corpus` is the **only** mechanism carrying discovered seeds across an
engine restart, and with arbitration enabled the supervisor restarts its worker
after every crash verdict. Disk save must therefore stay enabled.

**Recovery is partial.** `CorpusManager::loadCorpus` caps a reload at
`std::min(seed_files.size(), 5000)` seeds
(`include/utils/corpus_manager.hpp`), regardless of how many `.bin` files are on
disk. A restarted worker therefore recovers at most 5000 seeds even though the
same change set raised `max_corpus_size` to 50000 and the on-disk cap to 200000 —
the write path and the reload path are an order of magnitude apart. Frequent
restarts consequently do lose corpus. Keep that in mind when reading results from
a target that crashes often.

`TRIOFUZZ_MAX_DISK_CORPUS_FILES` (default 20000 here) bounds the directory.
Upstream raised the internal cap to 200000, sized for FuzzBench's `/out` budget;
`$SHARED` is a host bind mount, so Magma keeps a tighter bound.

---

## Instrumentation

Magma keeps `trace-cmp` **on**:

```
-fsanitize-coverage=trace-cmp,trace-pc-guard
```

The FuzzBench integration (`fuzzbench/fuzzers/triofuzz/fuzzer.py`) drops
`trace-cmp` because it costs >=20% throughput on comparison-dense targets and
FuzzBench scores edge coverage. Magma scores **bugs**, and many Magma bugs sit
behind magic bytes, length fields and checksums that CmpLog is specifically good
at getting past — so the trade-off that is right for FuzzBench is not right here.

To run the FuzzBench instrumentation as an ablation, set
`TRIOFUZZ_NO_TRACE_CMP=1`. `instrument.sh` runs during `docker build` and
`tools/captain/build.sh` passes a fixed set of `--build-arg`s, so a host
environment variable will not reach it. Either add
`ENV TRIOFUZZ_NO_TRACE_CMP 1` above `RUN ${FUZZER}/instrument.sh` in
`magma/docker/Dockerfile`, or copy this directory to `fuzzers/triofuzz_nocmp/`
and hardcode it — the latter also lets both configurations run side by side.

---

## `runonce.sh`

Magma calls `$FUZZER/runonce.sh` (via `$MAGMA/runonce.sh`, under
`monitor --fetch watch`) from two places, and both need **exactly one**
execution of the target:

1. `magma/run.sh` — prunes fault-triggering seeds before a campaign starts
2. `tools/captain/extract.sh` — replays each finding to attribute a Magma bug ID

libFuzzer treats a positional file argument as "run this one input and exit".
TrioFuzz has no such convention — an unrecognised positional argument is ignored
and the binary launches a full campaign. This script therefore uses
`--replay-verify=FILE`, which runs `LLVMFuzzerInitialize` plus exactly one
`LLVMFuzzerTestOneInput`, single-threaded, with no engine and no crash handler,
then exits 0. A faulting input kills the process with the target's own signal.

`TIMELIMIT` (5s) and `MEMLIMIT_MB` (4096) are raised above Magma's stock
`0.1s`/`100MB`. Those limits bound the whole process, and for TrioFuzz that
includes engine static initialisation plus the target's `LLVMFuzzerInitialize` —
far heavier than libFuzzer's near-instant startup. Both are overridable.

---

## Notes on flags that were removed

`run.sh` used to pass `--enable-crash-recovery`, `--restore-from-checkpoint`,
`--checkpoint-interval` and `--checkpoint-dir`. **None of these four are parsed
by TrioFuzz** — they were silently ignored, so the checkpoint-recovery behaviour
the script described never existed. Restart recovery comes from reloading
`<output>/corpus`.

It also exported `COLLABFUZZ_DISABLE_DISK_SAVE=1`, which never had any effect:
the variable the code reads is `triofuzz_DISABLE_DISK_SAVE`
(`include/utils/corpus_manager.hpp`). It is now intentionally left unset, because
disk save is what makes restart recovery work.

`run.sh` also used to pass `-seeds=/corpus/$PROGRAM`. The Dockerfile makes two
independent copies of the target corpus (`COPY ${target_path} ${TARGET}/` and
`COPY ${target_path}/corpus /corpus`), and `magma/run.sh`'s pruning loop deletes
fault-triggering seeds from the `$TARGET` copy only. Seeding from `/corpus` meant
the engine replayed stock seeds Magma had already identified as tripping a
canary, during its initial calibration pass — reporting a time-to-bug of roughly
zero for bugs the fuzzer never found, and doing so only for TrioFuzz while every
baseline it is compared against consumes the pruned copy. It now uses
`$TARGET/corpus/$PROGRAM` like every other fuzzer in `magma/fuzzers/`.

The old hang watchdog polled `$SHARED/monitor` for new files. That directory is
written by `magma/run.sh`'s own polling loop every `$POLL` seconds regardless of
fuzzer state, so it could never detect a hang. The watchdog now tracks the
fuzzer's own log (`HANG_TIMEOUT`, default 600s).

---

## Usage

```bash
./magma/tools/captain/captain.sh triofuzz <target>
```

## Command-line parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-threads` | 4 | Total thread count |
| `--worker-threads` | 2 | Worker thread count |
| `--explorer-threads` | 1 | Explorer thread count |
| `-timeout` | 2000 | Per-execution timeout (ms), also bounds each replay |
| `--use-triofuzz-unified` | enabled | Enable three-layer unified learning |
| `--ts-update-period` | 50000 | Thompson Sampling update window (executions) |
| `--ts-decay` | 0.95 | EMA decay factor |
| `--ts-havoc-stack-pow2` | 4 | Havoc stack size power |
| `--mopt-update-period` | 500000 | MOpt PSO update period |
| `--replay-verify=FILE` | — | Run one input single-threaded and exit (used by `runonce.sh`) |
| `--no-arbiter` | — | Disable crash arbitration |

## Shell environment knobs

| Env var | Default | Meaning |
|---|---|---|
| `SEED_TIMEOUT_MS` | 2000 | Per-execution timeout passed as `-timeout` |
| `TRIOFUZZ_MAX_DISK_CORPUS_FILES` | 20000 | Bound on `<output>/corpus` file count |
| `HANG_TIMEOUT` | 600 | Seconds without progress before the watchdog restarts |
| `HANG_GRACE` | 3600 | Longer allowance before the *first* progress signal (initial corpus load + calibration) |
| `TRIOFUZZ_OUT` | `$SHARED/triofuzz` | Engine output tree; honored by both `run.sh` and `findings.sh` |
| `MAX_RESTARTS` | 100000 | Outer restart-loop cap |
| `TIMELIMIT` / `MEMLIMIT_MB` | 5s / 4096 | `runonce.sh` limits |
