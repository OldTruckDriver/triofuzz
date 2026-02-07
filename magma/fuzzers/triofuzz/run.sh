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

# TrioFuzz environment settings
export COLLABFUZZ_DISABLE_DISK_SAVE=1

# TrioFuzz command-line arguments
# Format: -key=value or --key=value (similar to libFuzzer/CollabFuzz)
TRIOFUZZ_ARGS="-output=$SHARED/findings"

TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -seeds=/corpus/$PROGRAM"

# Convert TIMEOUT to seconds (supports s/m/h/d suffixes)
# Examples: "24h" -> 86400, "1m" -> 60, "30s" -> 30, "2d" -> 172800
convert_timeout_to_seconds() {
    local timeout_str="$1"
    if [ -z "$timeout_str" ]; then
        echo "0"
        return
    fi

    # Extract number and suffix
    local num="${timeout_str%[smhd]}"
    local suffix="${timeout_str: -1}"

    # If no suffix, assume seconds
    if [[ "$suffix" =~ [0-9] ]]; then
        echo "$timeout_str"
        return
    fi

    # Convert based on suffix
    case "$suffix" in
        s|S)
            echo "$num"
            ;;
        m|M)
            echo $((num * 60))
            ;;
        h|H)
            echo $((num * 3600))
            ;;
        d|D)
            echo $((num * 86400))
            ;;
        *)
            # Unknown suffix, assume seconds
            echo "$timeout_str"
            ;;
    esac
}

# Set timeout in seconds
if [ -n "$TIMEOUT" ]; then
    TIMEOUT_SECONDS=$(convert_timeout_to_seconds "$TIMEOUT")
    TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -max_total_time=$TIMEOUT_SECONDS"
fi

# TrioFuzz thread configuration
# Fixed 4 threads to avoid lock contention at higher core counts
# 1 Scheduler (shares with Worker-0) + 2 Workers + 1 Explorer
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -threads=4"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --worker-threads=2"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --explorer-threads=1"

# Timeout for individual seed execution (in milliseconds)
# Default: 2000ms (2 seconds) - can be overridden via SEED_TIMEOUT_MS environment variable
SEED_TIMEOUT_MS="${SEED_TIMEOUT_MS:-2000}"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -timeout=$SEED_TIMEOUT_MS"

# Coverage tracking
# TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --enable-coverage-tracking"

# Calculate coverage recording interval from SNAPSHOT_PERIOD if available
if [ -n "$SNAPSHOT_PERIOD" ]; then
    # SNAPSHOT_PERIOD - 2 seconds buffer, minimum 1 second
    COVERAGE_INTERVAL=$((SNAPSHOT_PERIOD - 2))
    if [ "$COVERAGE_INTERVAL" -lt 1 ]; then
        COVERAGE_INTERVAL=1
    fi
else
    COVERAGE_INTERVAL=60
fi
# TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --coverage-recording-interval=$COVERAGE_INTERVAL"

# Crash recovery configuration
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --enable-crash-recovery"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --restore-from-checkpoint"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --checkpoint-interval=1"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --checkpoint-dir=$SHARED/checkpoints"

mkdir -p "$SHARED/checkpoints"


TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --use-triofuzz-unified"

# Layer 1: Thompson Sampling (configuration selection)
# Layer 2: MOpt PSO (operator probability learning)
# Layer 3: MuoFuzz Markov Chain (operator transitions)

# Thompson Sampling parameters (Layer 1)
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-update-period=50000"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-decay=0.95"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-havoc-stack-pow2=4"

# MOpt PSO parameters (Layer 2)
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --mopt-update-period=500000"

# Hybrid period configuration for non-stationary adaptation
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-time-period=60"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --mopt-time-period=60"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --markov-time-period=10"

# Minimum samples for time-triggered updates (noise protection)
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --ts-min-samples=100"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --mopt-min-samples=500"
TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS --markov-min-samples=50"

# Additional fuzzer arguments from environment
if [ -n "$FUZZARGS" ]; then
    TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS $FUZZARGS"
fi

# Optional per-target dictionary support (SmartDictionary / EXTRA_*).
# If `$FUZZER/dicts/$PROGRAM.dict` exists, copy it to `$SHARED` and enable it.
# DICT_SRC="$FUZZER/dicts/${PROGRAM}.dict"
# if [ -f "$DICT_SRC" ]; then
#     DICT_DST="$SHARED/${PROGRAM}.dict"
#     cp "$DICT_SRC" "$DICT_DST"
#     TRIOFUZZ_ARGS="$TRIOFUZZ_ARGS -dict=$DICT_DST"
# fi

# Run TrioFuzz
# Note: TrioFuzz uses LLVMFuzzerTestOneInput interface, so it's compatible
# with standard fuzz targets. The main() function is provided by TrioFuzz library.
LOG="$OUT/triofuzz_output.log"

echo "[$(date)] Running command:" >> "$LOG"
echo "\"$OUT/$PROGRAM\" $TRIOFUZZ_ARGS $ARGS" >> "$LOG"

echo "[$(date)] Using seeds directly from /corpus/$PROGRAM" | tee -a "$LOG"

# Run TrioFuzz with automatic restart on crash
# This loop ensures that if the fuzzer crashes (Signal 11, etc.), it will
# automatically restart and restore from the last checkpoint
RESTART_COUNT=0
MAX_RESTARTS=100000  # Prevent infinite loops
START_TIME=$(date +%s)

while [ $RESTART_COUNT -lt $MAX_RESTARTS ]; do
    RESTART_COUNT=$((RESTART_COUNT + 1))

    if [ $RESTART_COUNT -eq 1 ]; then
        echo "[$(date)] Starting TrioFuzz (initial run)..." | tee -a "$LOG"
        # First run: use --restore-from-checkpoint only if checkpoint exists
        if [ -f "$SHARED/checkpoints/fuzzing_checkpoint.bin" ]; then
            echo "[$(date)] Checkpoint found, restoring from checkpoint..." | tee -a "$LOG"
            RUN_ARGS="$TRIOFUZZ_ARGS $ARGS"
        else
            echo "[$(date)] No checkpoint found, starting fresh..." | tee -a "$LOG"
            # Remove --restore-from-checkpoint on first run if no checkpoint exists
            RUN_ARGS="${TRIOFUZZ_ARGS/--restore-from-checkpoint/} $ARGS"
        fi
    else
        echo "[$(date)] Restarting TrioFuzz after crash (restart #$RESTART_COUNT)..." | tee -a "$LOG"
        # Subsequent runs: always restore from checkpoint
        RUN_ARGS="$TRIOFUZZ_ARGS $ARGS"

        # Small delay before restart to avoid rapid crash loops
        sleep 2
    fi

    # Check if we've exceeded the timeout
    if [ -n "$TIMEOUT_SECONDS" ] && [ "$TIMEOUT_SECONDS" -gt 0 ]; then
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - START_TIME))
        if [ $ELAPSED -ge "$TIMEOUT_SECONDS" ]; then
            echo "[$(date)] Timeout reached ($TIMEOUT_SECONDS seconds), stopping fuzzing" | tee -a "$LOG"
            break
        fi
    fi

    # Run the fuzzer with timeout protection to detect hangs
    # HANG_TIMEOUT: maximum time without checkpoint update (default: 60 seconds)
    HANG_TIMEOUT="${HANG_TIMEOUT:-60}"

    # Start fuzzer in background
    "$OUT/$PROGRAM" $RUN_ARGS 2>&1 | tee -a "$LOG" &
    FUZZER_PID=$!

    echo "[$(date)] Fuzzer started (PID: $FUZZER_PID), monitoring for hangs (threshold: ${HANG_TIMEOUT}s)..." | tee -a "$LOG"

    # Monitor for hangs: check if monitor folder has new files being created
    MONITOR_DIR="$SHARED/monitor"
    LAST_MONITOR_FILE_TIME=0
    LAST_MONITOR_FILE_COUNT=0

    # Get the latest file in monitor directory (by modification time)
    get_latest_monitor_file_time() {
        if [ ! -d "$MONITOR_DIR" ]; then
            echo "0"
            return
        fi

        local latest_time=0
        for file in "$MONITOR_DIR"/*; do
            if [ -f "$file" ] && [ "$(basename "$file")" != "tmp" ]; then
                local file_time=$(stat -c %Y "$file" 2>/dev/null || echo 0)
                if [ $file_time -gt $latest_time ]; then
                    latest_time=$file_time
                fi
            fi
        done
        echo "$latest_time"
    }

    # Get the count of monitor files (excluding tmp)
    get_monitor_file_count() {
        if [ ! -d "$MONITOR_DIR" ]; then
            echo "0"
            return
        fi
        local count=0
        for file in "$MONITOR_DIR"/*; do
            if [ -f "$file" ] && [ "$(basename "$file")" != "tmp" ]; then
                count=$((count + 1))
            fi
        done
        echo "$count"
    }

    # Initialize: get the latest file time and count
    FUZZER_START_TIME=$(date +%s)
    if [ -d "$MONITOR_DIR" ]; then
        LAST_MONITOR_FILE_TIME=$(get_latest_monitor_file_time)
        LAST_MONITOR_FILE_COUNT=$(get_monitor_file_count)
    fi

    HANG_DETECTED=0
    while kill -0 $FUZZER_PID 2>/dev/null; do
        sleep 30  # Check every 30 seconds

        if [ -d "$MONITOR_DIR" ]; then
            CURRENT_MONITOR_FILE_TIME=$(get_latest_monitor_file_time)
            CURRENT_MONITOR_FILE_COUNT=$(get_monitor_file_count)

            # Check if new files were created or existing files were updated
            if [ $CURRENT_MONITOR_FILE_TIME -gt $LAST_MONITOR_FILE_TIME ] || [ $CURRENT_MONITOR_FILE_COUNT -gt $LAST_MONITOR_FILE_COUNT ]; then
                # Monitor files were updated, reset timer
                LAST_MONITOR_FILE_TIME=$CURRENT_MONITOR_FILE_TIME
                LAST_MONITOR_FILE_COUNT=$CURRENT_MONITOR_FILE_COUNT
            else
                # Check how long since last update
                CURRENT_TIME=$(date +%s)
                if [ $LAST_MONITOR_FILE_TIME -gt 0 ]; then
                    TIME_SINCE_UPDATE=$((CURRENT_TIME - LAST_MONITOR_FILE_TIME))
                else
                    TIME_SINCE_UPDATE=$((CURRENT_TIME - FUZZER_START_TIME))
                fi

                if [ $TIME_SINCE_UPDATE -gt $HANG_TIMEOUT ]; then
                    echo "[$(date)] WARNING: No monitor file update for ${TIME_SINCE_UPDATE}s (threshold: ${HANG_TIMEOUT}s), hang detected!" | tee -a "$LOG"
                    echo "[$(date)] Killing hung fuzzer process (PID: $FUZZER_PID)..." | tee -a "$LOG"
                    kill -TERM $FUZZER_PID 2>/dev/null
                    sleep 2
                    if kill -0 $FUZZER_PID 2>/dev/null; then
                        kill -KILL $FUZZER_PID 2>/dev/null
                    fi
                    HANG_DETECTED=1
                    break
                fi
            fi
        else
            # No monitor directory yet, check if process has been running too long
            CURRENT_TIME=$(date +%s)
            if [ $LAST_MONITOR_FILE_TIME -eq 0 ]; then
                LAST_MONITOR_FILE_TIME=$CURRENT_TIME
            else
                TIME_SINCE_START=$((CURRENT_TIME - LAST_MONITOR_FILE_TIME))
                if [ $TIME_SINCE_START -gt $HANG_TIMEOUT ]; then
                    echo "[$(date)] WARNING: No monitor folder created after ${TIME_SINCE_START}s, possible hang!" | tee -a "$LOG"
                    echo "[$(date)] Killing hung fuzzer process (PID: $FUZZER_PID)..." | tee -a "$LOG"
                    kill -TERM $FUZZER_PID 2>/dev/null
                    sleep 2
                    if kill -0 $FUZZER_PID 2>/dev/null; then
                        kill -KILL $FUZZER_PID 2>/dev/null
                    fi
                    HANG_DETECTED=1
                    break
                fi
            fi
        fi
    done

    # Wait for the process to finish and get exit code
    wait $FUZZER_PID 2>/dev/null
    EXIT_CODE=$?

    if [ $HANG_DETECTED -eq 1 ]; then
        echo "[$(date)] Fuzzer was killed due to hang detection (exit code $EXIT_CODE)" | tee -a "$LOG"
        echo "[$(date)] TrioFuzz will restart from checkpoint after hang..." | tee -a "$LOG"

        if [ ! -f "$SHARED/checkpoints/fuzzing_checkpoint.bin" ]; then
            echo "[$(date)] WARNING: No checkpoint found, starting fresh..." | tee -a "$LOG"
        fi

        continue
    fi

    echo "[$(date)] TrioFuzz exited (exit code $EXIT_CODE)" | tee -a "$LOG"

    # For all cases, restart from checkpoint
    # Docker container timeout will handle the final shutdown
    echo "[$(date)] TrioFuzz will restart from checkpoint..." | tee -a "$LOG"

    if [ ! -f "$SHARED/checkpoints/fuzzing_checkpoint.bin" ]; then
        echo "[$(date)] WARNING: No checkpoint found, starting fresh..." | tee -a "$LOG"
    fi
done

if [ $RESTART_COUNT -ge $MAX_RESTARTS ]; then
    echo "[$(date)] WARNING: Reached maximum restart limit ($MAX_RESTARTS), stopping" | tee -a "$LOG"
fi

echo "[$(date)] Fuzzing session ended after $RESTART_COUNT run(s)" | tee -a "$LOG"
