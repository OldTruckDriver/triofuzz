#!/usr/bin/env python3
"""
Analyze EcoFuzz learning-cycle logs produced by ecofuzz_lc_monitor.

Usage:
  python3 analyze_lc.py <output_corpus_dir>

Looks for:
  - <output>/lc_timeline.csv
  - <output>/fuzzer_stats
  - <output>/lc_stats
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
from typing import Iterable, List, Tuple


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    if p <= 0:
        return values[0]
    if p >= 100:
        return values[-1]
    k = (len(values) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(values) - 1)
    if f == c:
        return values[f]
    d0 = values[f] * (c - k)
    d1 = values[c] * (k - f)
    return d0 + d1


def _format_seconds(seconds: float) -> str:
    if seconds < 0:
        return f"{seconds:.3f}s"
    if seconds < 60:
        return f"{seconds:.3f}s"
    minutes = seconds / 60.0
    if minutes < 60:
        return f"{minutes:.2f}m"
    hours = minutes / 60.0
    if hours < 24:
        return f"{hours:.2f}h"
    days = hours / 24.0
    return f"{days:.2f}d"


def _summary_ms(deltas_ms: List[int]) -> str:
    if not deltas_ms:
        return "n=0"
    deltas_s = [d / 1000.0 for d in deltas_ms]
    return (
        f"n={len(deltas_ms)}, mean={statistics.fmean(deltas_s):.3f}s, "
        f"median={statistics.median(deltas_s):.3f}s, p90={_percentile(deltas_s, 90):.3f}s"
    )


def _summary_s(deltas_s: List[float]) -> str:
    if not deltas_s:
        return "n=0"
    return (
        f"n={len(deltas_s)}, mean={statistics.fmean(deltas_s):.3f}s, "
        f"median={statistics.median(deltas_s):.3f}s, p90={_percentile(deltas_s, 90):.3f}s"
    )


def _read_fuzzer_stats(path: str) -> dict:
    stats: dict = {}
    if not os.path.exists(path):
        return stats
    with open(path, encoding="utf-8") as f:
        for line in f:
            if ": " not in line:
                continue
            k, v = line.rstrip("\n").split(": ", 1)
            k = k.strip()
            v = v.strip()
            try:
                stats[k] = float(v) if "." in v else int(v)
            except ValueError:
                stats[k] = v
    return stats


def _read_timeline(path: str) -> List[Tuple[int, str]]:
    if not os.path.exists(path):
        return []
    rows: List[Tuple[int, str]] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = int(row["timestamp_ms"])
            except Exception:
                continue
            rows.append((ts, row.get("event", "")))
    rows.sort()
    return rows


def _deltas_for_event(rows: Iterable[Tuple[int, str]], event: str) -> List[int]:
    ts = [t for t, e in rows if e == event]
    return [ts[i] - ts[i - 1] for i in range(1, len(ts))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("output_corpus_dir", help="AFL/EcoFuzz output directory (the -o path).")
    args = ap.parse_args()

    out = args.output_corpus_dir
    timeline_path = os.path.join(out, "lc_timeline.csv")
    stats_path = os.path.join(out, "fuzzer_stats")

    rows = _read_timeline(timeline_path)
    if not rows:
        print(f"Missing or empty: {timeline_path}")
    else:
        print(f"Loaded: {timeline_path} ({len(rows)} events)")
        qc = _deltas_for_event(rows, "queue_cycle")
        rc = _deltas_for_event(rows, "rate_change")
        ec = _deltas_for_event(rows, "energy_change")
        print(f"Queue-cycle duration: {_summary_ms(qc)}")
        if qc:
            first_s = qc[0] / 1000.0
            print(f"  cycle_1 duration: {_format_seconds(first_s)}")
            all_cycles = [d / 1000.0 for d in qc]
        if len(qc) > 1:
            rest = [d / 1000.0 for d in qc[1:]]
            rest_s = statistics.fmean(rest)
            print(f"  cycles_2.. mean:  {_format_seconds(rest_s)} (n={len(rest)})")

            # Heuristic: exclude \"fast queue sweep\" cycles by minimum duration.
            for th in (1.0, 5.0):
                if qc:
                    filtered_all = [d for d in all_cycles if d > th]
                    print(f"  cycles_1.. >{th:.0f}s: {_summary_s(filtered_all)}")
                filtered = [d for d in rest if d > th]
                print(f"  cycles_2.. >{th:.0f}s: {_summary_s(filtered)}")
        print(f"Rate-change interval: {_summary_ms(rc)}")
        print(f"Energy-change interval: {_summary_ms(ec)}")

    stats = _read_fuzzer_stats(stats_path)
    if stats:
        cycles_done = stats.get("cycles_done", 0)
        run_time = stats.get("run_time", 0)
        try:
            cycles_done_i = int(cycles_done)
            run_time_i = int(run_time)
        except Exception:
            cycles_done_i = 0
            run_time_i = 0
        derived_run_time = False
        if run_time_i <= 0:
            try:
                start_time_i = int(stats.get("start_time", 0))
                last_update_i = int(stats.get("last_update", 0))
            except Exception:
                start_time_i = 0
                last_update_i = 0
            if start_time_i > 0 and last_update_i > start_time_i:
                run_time_i = last_update_i - start_time_i
                derived_run_time = True

        if cycles_done_i > 0 and run_time_i > 0:
            suffix = " (derived last_update-start_time)" if derived_run_time else ""
            print(
                f"Avg queue traversal (from fuzzer_stats{suffix}): {run_time_i / cycles_done_i:.2f}s "
                f"(run_time={run_time_i}s, cycles_done={cycles_done_i})"
            )
        else:
            print("fuzzer_stats present but missing/zero run_time or cycles_done.")
    else:
        print(f"Missing: {stats_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
