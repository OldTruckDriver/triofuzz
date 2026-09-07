#!/bin/bash -e

##
# Pre-requirements:
# - $1: path to test case
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

##
# Why this differs from fuzzers/libfuzzer/runonce.sh
# -------------------------------------------------------------------------
# Magma calls this through $MAGMA/runonce.sh (under `monitor --fetch watch`)
# from two places, and both need EXACTLY ONE execution of the target:
#   1. magma/run.sh          -- prunes fault-triggering seeds before a campaign
#   2. tools/captain/extract.sh -- replays each finding to attribute a bug ID
#
# libFuzzer treats a positional file argument as "run this one input and exit".
# TrioFuzz has no such convention: an unrecognised positional argument is
# ignored and the binary launches a full multi-threaded campaign instead. Under
# the 0.1s `timeout -s KILL --preserve-status` that campaign is always killed,
# yielding 137, so `test $? -lt 128` always failed -- every seed looked like a
# fault (pruning the whole corpus) and every finding looked confirmed.
#
# `--replay-verify=FILE` runs LLVMFuzzerInitialize + exactly one
# LLVMFuzzerTestOneInput, single-threaded, with no engine and no crash handler,
# then exits 0. A faulting input kills the process with the target's own signal,
# which is what `test $? -lt 128` and Magma's canary monitor both expect.
##

# The limits below bound the WHOLE process, and for TrioFuzz that includes the
# static initialisation of the engine (algorithm registry, etc.) plus the
# target's LLVMFuzzerInitialize -- both far heavier than libFuzzer's near-instant
# startup. Magma's stock 0.1s / 100MB budget is consumed before the test case is
# even executed, which would misreport every input as a fault. Both are
# overridable if you want to tighten them for a specific target.
export TIMELIMIT="${TIMELIMIT:-5s}"
export MEMLIMIT_MB="${MEMLIMIT_MB:-4096}"

run_limited()
{
    ulimit -Sv $[MEMLIMIT_MB << 10];
    ${@:1}
    test $? -lt 128
}
export -f run_limited

# $ARGS is deliberately not forwarded: TrioFuzz targets always receive their
# input through LLVMFuzzerTestOneInput, and --replay-verify returns before any
# command-line parsing happens, so extra arguments would be silently ignored.
timeout -s KILL --preserve-status $TIMELIMIT bash -c \
    "run_limited '$OUT/$PROGRAM' --replay-verify='$1'"
