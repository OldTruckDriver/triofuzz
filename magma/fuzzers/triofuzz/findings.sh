#!/bin/bash

##
# Pre-requirements:
# - env SHARED: path to directory shared with host (to store results)
##

##
# Magma's contract: every path printed here is replayed by
# tools/captain/extract.sh via $MAGMA/runonce.sh and, if it faults, saved as a
# PoC. So this must print crash candidates ONLY.
#
# TrioFuzz derives both its on-disk corpus and its crash directory from -output.
# run.sh therefore points -output at $SHARED/triofuzz (NOT $SHARED/findings), so
# that the corpus -- which can reach tens of thousands of seeds and is reloaded
# on every engine restart -- never enters the findings set.
#
# Within the crashes directory, only *.bin files are test cases. The soft-crash
# callback also writes crash_<ts>_report.txt companions, which must not be
# replayed as inputs.
##

CRASH_DIR="${TRIOFUZZ_OUT:-$SHARED/triofuzz}/crashes"

# Second location, for the documented TRIOFUZZ_NO_ARBITER=1 fallback only.
# In legacy mode signal crashes are handled by EnhancedCrashTracker, which
# hardcodes a RELATIVE output_directory_ = "output/crashes"
# (src/core/enhanced_crash_tracker.cpp). magma/run.sh does `cd "$SHARED"` before
# launching, so those land in $SHARED/output/crashes as crash_input_*.bin and
# would otherwise be invisible to crash triage. In arbiter mode this directory
# stays empty (the capture handler replaces that tracker).
LEGACY_CRASH_DIR="$SHARED/output/crashes"

found=0
for d in "$CRASH_DIR" "$LEGACY_CRASH_DIR"; do
    if [ -d "$d" ]; then
        find "$d" -type f -name '*.bin'
        found=1
    fi
done

[ $found -eq 1 ] || exit 1
