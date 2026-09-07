#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env FUZZARGS: extra arguments to pass to the fuzzer
##

mkdir -p "$SHARED/findings"

export LLVM_PROFILE_FILE="$SHARED/default.profraw"

##
# Output layout
# ---------------------------------------------------------------------------
# TrioFuzz derives BOTH of these from -output:
#   <output>/corpus   on-disk corpus; reloaded on every engine start
#                     (src/core/fuzzing_engine.cpp: loadCorpus(output_dir+"/corpus"))
#   <output>/crashes  crash artifacts
#
# Magma's contract is that whatever findings.sh prints gets replayed one-by-one
# by tools/captain/extract.sh. Pointing -output at $SHARED/findings (as this
# script used to) therefore fed the entire corpus -- potentially tens of
# thousands of seeds -- into crash triage. Give the engine its own tree and let
# findings.sh expose only <output>/crashes. Keep this path in sync with
# findings.sh.
##
TRIOFUZZ_OUT="${TRIOFUZZ_OUT:-$SHARED/triofuzz}"
export TRIOFUZZ_OUT
mkdir -p "$TRIOFUZZ_OUT/corpus" "$TRIOFUZZ_OUT/crashes"

##
# Corpus persistence across restarts
# ---------------------------------------------------------------------------
# Do NOT disable disk save. <output>/corpus is the ONLY thing that carries
# discovered seeds across a restart of the engine, and with crash arbitration
# enabled the supervisor restarts its worker on every confirmed/rejected crash.
#
# This script previously exported COLLABFUZZ_DISABLE_DISK_SAVE=1, which never
# did anything -- the variable the code reads is triofuzz_DISABLE_DISK_SAVE
# (include/utils/corpus_manager.hpp). It is intentionally left unset.
#
# It also passed --enable-crash-recovery, --restore-from-checkpoint,
# --checkpoint-interval and --checkpoint-dir. None of those four flags are
# parsed by TrioFuzz; they were silently ignored, so the "restore from
# checkpoint" behaviour this script described never existed. They are removed
# rather than left in place suggesting a recovery mechanism that is not there.
#
# Upstream raised the on-disk cap to 200000 files, sized for FuzzBench's /out
# budget. Bound it here so $SHARED (a host bind mount) cannot grow without limit
# over a multi-day campaign.
##
export TRIOFUZZ_MAX_DISK_CORPUS_FILES="${TRIOFUZZ_MAX_DISK_CORPUS_FILES:-20000}"

##
# Crash arbitration (supervisor + single-threaded replay oracle)
# ---------------------------------------------------------------------------
# TrioFuzz executes LLVMFuzzerTestOneInput in-process on several threads with no
# lock. main() is now a single-threaded supervisor that forks the engine into a
# worker child; when the worker dies on a crash signal, the supervisor replays
# the captured input single-threaded in a fresh child and keeps the crash only
# if it reproduces, then restarts the worker within the remaining budget.
#
# For Magma the decisive benefit is campaign survivability rather than crash
# filtering: Magma's ground truth is the canary counters in $SHARED/canaries.raw,
# not crashes. In particular, under captain's `isan=1` (-DMAGMA_FATAL_CANARIES)
# every triggered canary raises SIGSEGV, which previously killed the campaign at
# the first bug found.
#
# Caveat, deliberate: the replay child re-executes the candidate input, so it
# increments the shared canary counters a second time. That slightly inflates the
# reached/triggered COUNTS. It does not change which bugs are marked triggered,
# nor the time-to-first-trigger, which are Magma's headline metrics.
#
# Set TRIOFUZZ_NO_ARBITER=1 to fall back to legacy single-process behaviour.
##
export TRIOFUZZ_ARBITER_FAST_CRASH_SEC="${TRIOFUZZ_ARBITER_FAST_CRASH_SEC:-10}"

# Adaptive serialization is left at the engine default (escalate after 3).
# It now counts only fast worker deaths whose captured input did NOT reproduce
# single-threaded -- the actual signature of a thread-unsafe target -- so a
# canary-triggered SIGSEGV under isan=1 (reproduces deterministically) or an
# OOM SIGKILL (not a crash signal) can no longer latch it. Set
# TRIOFUZZ_ARBITER_ESCALATE_AFTER=0 to disable outright.
#
# The supervisor also enforces a worker liveness deadline
# (TRIOFUZZ_ARBITER_WORKER_HANG_SEC, default 300s once the engine is fuzzing;
# TRIOFUZZ_ARBITER_STARTUP_GRACE_SEC, default 1800s for init + corpus reload +
# seed calibration before that). The HANG_TIMEOUT watchdog further down is the
# outer backstop for the supervisor itself.

# TrioFuzz command-line arguments
TRIOFUZZ_ARGS="-output=$TRIOFUZZ_OUT"
# Seed from $TARGET/corpus/$PROGRAM, NOT /corpus/$PROGRAM.
# magma/docker/Dockerfile makes two independent copies of the target corpus
# (COPY ${target_path} ${TARGET}/  and  COPY ${target_path}/corpus /corpus), and
# magma/run.sh's pruning loop deletes fault-triggering seeds from the $TARGET
# copy only. Seeding from /corpus therefore replays stock seeds that Magma
# already identified as tripping a canary: the engine executes them during its
# initial calibration pass, which increments the counters in
# $SHARED/canaries.raw within the first seconds and reports a time-to-bug of
# ~0 for a bug the fuzzer never found. Every other Magma fuzzer (afl,
# aflplusplus, honggfuzz, libfuzzer, ...) uses the pruned $TARGET copy, so this
# skewed TrioFuzz's headline metric relative to every baseline it is compared
# against.
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -seeds=$TARGET/corpus/$PROGRAM"

# Convert TIMEOUT to seconds (supports s/m/h/d suffixes)
convert_timeout_to_seconds() {
    local timeout_str="$1"
    if [ -z "$timeout_str" ]; then
        echo "0"
        return
    fi

    local num="${timeout_str%[smhdSMHD]}"
    local suffix="${timeout_str: -1}"

    if [[ "$suffix" =~ [0-9] ]]; then
        echo "$timeout_str"
        return
    fi

    case "$suffix" in
        s|S) echo "$num" ;;
        m|M) echo $((num * 60)) ;;
        h|H) echo $((num * 3600)) ;;
        d|D) echo $((num * 86400)) ;;
        *)   echo "$timeout_str" ;;
    esac
}

TIMEOUT_SECONDS=0
if [ -n "$TIMEOUT" ]; then
    TIMEOUT_SECONDS=$(convert_timeout_to_seconds "$TIMEOUT")
fi

# Thread configuration
# Fixed 4 threads to avoid lock contention at higher core counts
# 1 Scheduler (shares with Worker-0) + 2 Workers + 1 Explorer
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -threads=4"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --worker-threads=2"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --explorer-threads=1"

# Timeout for individual seed execution (milliseconds). This is also the base
# the supervisor uses to bound each single-threaded replay.
SEED_TIMEOUT_MS="${SEED_TIMEOUT_MS:-2000}"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -timeout=$SEED_TIMEOUT_MS"

TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --use-triofuzz-unified"

# Layer 1: Thompson Sampling (configuration selection)
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-update-period=50000"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-decay=0.95"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-havoc-stack-pow2=4"

# Layer 2: MOpt PSO (operator probability learning)
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --mopt-update-period=500000"

# Hybrid period configuration for non-stationary adaptation
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-time-period=60"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --mopt-time-period=60"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --markov-time-period=10"

# Minimum samples for time-triggered updates (noise protection)
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-min-samples=100"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --mopt-min-samples=500"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --markov-min-samples=50"

if [ -n "$FUZZARGS" ]; then
    TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS $FUZZARGS"
fi

LOG="$OUT/triofuzz_output.log"

echo "[$(date)] Output dir : $TRIOFUZZ_OUT" | tee -a "$LOG"
echo "[$(date)] Findings   : $TRIOFUZZ_OUT/crashes (exposed by findings.sh)" | tee -a "$LOG"
echo "[$(date)] Seeds      : $TARGET/corpus/$PROGRAM (pruned by magma/run.sh)" | tee -a "$LOG"
if [ -n "$TRIOFUZZ_NO_ARBITER" ]; then
    echo "[$(date)] Arbiter    : DISABLED (TRIOFUZZ_NO_ARBITER=$TRIOFUZZ_NO_ARBITER)" | tee -a "$LOG"
else
    echo "[$(date)] Arbiter    : enabled (supervisor + single-threaded replay oracle)" | tee -a "$LOG"
fi

##
# Outer supervision loop
# ---------------------------------------------------------------------------
# With arbitration enabled the in-process supervisor already restarts its worker
# after every crash, so this loop is only a backstop for the supervisor process
# itself dying or wedging. It also remains the sole restart mechanism when
# TRIOFUZZ_NO_ARBITER=1.
#
# The previous watchdog watched $SHARED/monitor for new files. That directory is
# written by magma/run.sh's own polling loop every $POLL seconds regardless of
# whether the fuzzer is alive, so it could never detect a hang. Watch the
# fuzzer's own log instead, which the engine appends to as it reports progress.
##
HANG_TIMEOUT="${HANG_TIMEOUT:-600}"
# Separate, much longer budget for the first progress signal after a (re)start.
# The engine loads and calibrates every initial seed before it reports anything,
# and Magma corpora are large (openssl/client has 2301 seeds; at the 2s
# -timeout that alone can exceed an hour worst-case). Enforcing HANG_TIMEOUT
# during that phase would kill a perfectly healthy campaign before it began.
HANG_GRACE="${HANG_GRACE:-3600}"
MAX_RESTARTS="${MAX_RESTARTS:-100000}"
START_TIME=$(date +%s)
RESTART_COUNT=0

# Liveness signal for the watchdog.
#
# Do not rely on the log alone: the fuzzer's stdout is a pipe here, not a tty, so
# libc block-buffers it and $LOG's mtime can stall for a long time while the
# engine is perfectly healthy -- which would make the watchdog kill a working
# campaign every HANG_TIMEOUT. Take the newest mtime across the log AND the
# directories the engine writes into; a directory's mtime advances whenever a
# seed or crash file is added, which is an unbuffered, kernel-level signal.
# Terminate the whole fuzzer process group: supervisor, its forked worker, and
# any replay child. Negative PID = process group (see `set -m` at the launch).
kill_fuzzer_group() {
    [ -n "$FUZZER_PID" ] || return 0
    kill -TERM "-$FUZZER_PID" 2>/dev/null || kill -TERM "$FUZZER_PID" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "-$FUZZER_PID" 2>/dev/null || return 0
        sleep 1
    done
    kill -KILL "-$FUZZER_PID" 2>/dev/null || kill -KILL "$FUZZER_PID" 2>/dev/null
}

# magma/run.sh wraps this script in `timeout $TIMEOUT`, which signals only this
# script. Without this trap the whole arbiter tree would survive the campaign.
trap 'kill_fuzzer_group; exit 143' TERM INT
trap 'kill_fuzzer_group' EXIT

progress_mtime() {
    local newest=0 t
    for f in "$LOG" "$TRIOFUZZ_OUT/corpus" "$TRIOFUZZ_OUT/crashes"; do
        t=$(stat -c %Y "$f" 2>/dev/null) || continue
        [ -n "$t" ] && [ "$t" -gt "$newest" ] && newest=$t
    done
    echo "$newest"
}

while [ $RESTART_COUNT -lt $MAX_RESTARTS ]; do
    RESTART_COUNT=$((RESTART_COUNT + 1))

    RUN_ARGS="$TRIOFUZZ_ARGS"

    # Give the fuzzer only the budget that is actually left, so a restart cannot
    # extend the campaign past $TIMEOUT.
    if [ "$TIMEOUT_SECONDS" -gt 0 ]; then
        ELAPSED=$(( $(date +%s) - START_TIME ))
        REMAINING=$(( TIMEOUT_SECONDS - ELAPSED ))
        if [ "$REMAINING" -le 1 ]; then
            echo "[$(date)] Budget exhausted (${ELAPSED}s / ${TIMEOUT_SECONDS}s), stopping." | tee -a "$LOG"
            break
        fi
        RUN_ARGS="$RUN_ARGS -max_total_time=$REMAINING"
    fi

    if [ $RESTART_COUNT -eq 1 ]; then
        echo "[$(date)] Starting TrioFuzz..." | tee -a "$LOG"
    else
        echo "[$(date)] Restarting TrioFuzz (run #$RESTART_COUNT)..." | tee -a "$LOG"
        sleep 2
    fi
    echo "[$(date)] Command: \"$OUT/$PROGRAM\" $RUN_ARGS $ARGS" >> "$LOG"

    # NOTE: use process substitution rather than `cmd | tee &`. For a background
    # pipeline bash sets $! to the LAST command in it (tee), so the watchdog
    # below would have been polling and killing tee instead of the fuzzer, and
    # $? after wait would have been tee's exit status. This form keeps $! (and
    # the waited-for status) on the fuzzer itself.
    # Launch in its OWN process group (set -m), so the whole arbiter tree can be
    # signalled as a unit.
    #
    # This matters because the fuzzer is a supervisor that fork()s a worker
    # child. SIGTERM to the supervisor is forwarded to the worker by
    # supervisor_term_handler, but SIGKILL cannot be caught and therefore cannot
    # be forwarded -- and the watchdog only ever fires when the worker is already
    # wedged and not responding to SIGTERM. Killing the supervisor alone would
    # leave an orphaned multi-threaded worker running, still writing this
    # campaign's corpus and still incrementing $SHARED/canaries.raw, with one
    # more leaking every HANG_TIMEOUT for the rest of the campaign.
    set -m
    "$OUT/$PROGRAM" $RUN_ARGS $ARGS > >(tee -a "$LOG") 2>&1 &
    FUZZER_PID=$!
    set +m

    LAST_PROGRESS=$(date +%s)
    LAST_MTIME=$(progress_mtime)
    SAW_PROGRESS=0
    HANG_DETECTED=0

    while kill -0 $FUZZER_PID 2>/dev/null; do
        sleep 30

        CUR_MTIME=$(progress_mtime)
        NOW=$(date +%s)
        if [ "$CUR_MTIME" -gt "$LAST_MTIME" ]; then
            LAST_MTIME=$CUR_MTIME
            LAST_PROGRESS=$NOW
            SAW_PROGRESS=1
        fi

        # Before the first progress signal the engine is still loading and
        # calibrating the initial corpus and reports nothing; allow HANG_GRACE
        # for that phase and the tighter HANG_TIMEOUT afterwards.
        if [ "$SAW_PROGRESS" -eq 1 ]; then
            THRESH=$HANG_TIMEOUT
        else
            THRESH=$HANG_GRACE
        fi

        STALLED=$((NOW - LAST_PROGRESS))
        if [ "$STALLED" -gt "$THRESH" ]; then
            echo "[$(date)] No progress (log/corpus/crashes) for ${STALLED}s (threshold ${THRESH}s); killing process group $FUZZER_PID." | tee -a "$LOG"
            kill_fuzzer_group
            HANG_DETECTED=1
            break
        fi

        # Respect the campaign budget even if the fuzzer overruns it.
        if [ "$TIMEOUT_SECONDS" -gt 0 ] && [ $((NOW - START_TIME)) -ge "$TIMEOUT_SECONDS" ]; then
            echo "[$(date)] Campaign budget reached; terminating fuzzer." | tee -a "$LOG"
            kill_fuzzer_group
            break
        fi
    done

    wait $FUZZER_PID 2>/dev/null
    EXIT_CODE=$?

    if [ $HANG_DETECTED -eq 1 ]; then
        echo "[$(date)] TrioFuzz killed after hang; restarting (corpus is reloaded from $TRIOFUZZ_OUT/corpus)." | tee -a "$LOG"
        continue
    fi

    echo "[$(date)] TrioFuzz exited (exit code $EXIT_CODE)" | tee -a "$LOG"
done

if [ $RESTART_COUNT -ge $MAX_RESTARTS ]; then
    echo "[$(date)] WARNING: reached maximum restart limit ($MAX_RESTARTS), stopping" | tee -a "$LOG"
fi

echo "[$(date)] Fuzzing session ended after $RESTART_COUNT run(s)" | tee -a "$LOG"
