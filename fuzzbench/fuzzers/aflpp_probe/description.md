# aflpp_probe

PROBE: Pure Tree Search for Fuzzing — UCT-based tree search integrated into AFL++.

Status (as of 2026-04-28): **M1 stub build**. The PROBE fork compiles cleanly
with `PROBE_BUILD=1` and links the `probe-*.c` no-op stubs, but no PROBE logic
is active yet — runtime behavior is expected to match upstream AFL++ within
parity tolerances. Real algorithm activates in M3.

Fork pin: AFL++ at commit `56d5aa3` (matches FuzzBench's bundled
`fuzzers/aflplusplus/builder.Dockerfile`). See
[AFLplusplus/docs/upstream.md](AFLplusplus/docs/upstream.md).

Inherits the same configuration as the upstream `aflplusplus` fuzzer:
  - PCGUARD instrumentation
  - cmplog feature
  - dict2file feature
  - "fast" power schedule
  - persistent mode + shared memory test cases

Spec: [PROBE_SPEC.md](PROBE_SPEC.md)

[builder.Dockerfile](builder.Dockerfile)
[fuzzer.py](fuzzer.py)
[runner.Dockerfile](runner.Dockerfile)
