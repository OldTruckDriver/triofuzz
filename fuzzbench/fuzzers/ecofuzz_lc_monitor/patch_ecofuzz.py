#!/usr/bin/env python3
"""
Patch EcoFuzz's afl-fuzz.c to emit learning-cycle metrics for analysis.

This is intended for use from fuzzers/ecofuzz_lc_monitor/builder.Dockerfile.
It writes:
  - lc_timeline.csv: sparse (or full) timeline of rate/energy changes and
    queue-cycle boundaries.
  - lc_stats: periodically refreshed snapshot for FuzzBench get_stats().
"""

from __future__ import annotations

import sys


def _ensure_once(haystack: str, needle: str, insert_after: str, insertion: str) -> str:
    if needle in haystack:
        return haystack
    if insert_after not in haystack:
        raise RuntimeError(f"Could not find insertion point: {insert_after!r}")
    return haystack.replace(insert_after, insert_after + insertion, 1)


def patch_afl_fuzz(input_file: str, output_file: str) -> None:
    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 1) Ensure we have <math.h> for fabs().
    content = _ensure_once(
        content,
        "#include <math.h>",
        "#include <sched.h>\n",
        "#include <math.h>\n",
    )

    # 2) Add monitoring globals after EcoFuzz's learning variable.
    globals_marker = "static float rate = 1;                /* Rate of regret                   */\n"
    if globals_marker not in content:
        raise RuntimeError("Could not find EcoFuzz rate declaration for patching.")

    globals_insert = """

/* Learning-cycle monitoring (added by ecofuzz_lc_monitor) */
static u8    lc_enabled = 1;
static u8    lc_log_all = 0;
static double lc_rate_rel_delta = 0.10;     /* relative threshold */
static double lc_rate_abs_delta = 0.05;     /* absolute threshold */
static double lc_energy_rel_delta = 0.25;   /* relative threshold */
static u32   lc_stats_interval_ms = 1000;   /* snapshot interval */
static u64   lc_last_stats_ms = 0;
static float lc_last_logged_rate = -1.0f;
static u64   lc_last_logged_stage_max = 0;
static FILE* lc_timeline_file = NULL;

"""
    content = content.replace(globals_marker, globals_marker + globals_insert, 1)

    # 3) Insert helper functions before time file setup (out_dir already exists then).
    helper_marker = "/* Setup the time file fds.*/\n"
    if helper_marker not in content:
        raise RuntimeError("Could not find setup_time_fds marker for patching.")

    helper_insert = r"""
/* Learning-cycle monitoring helpers (added by ecofuzz_lc_monitor). */
static void lc_init(void) {

  if (!lc_enabled || lc_timeline_file) return;

  /* Config via environment. */
  {
    u8* env = (u8*)getenv("ECOFUZZ_LC_LOG");
    if (env && env[0] == '0') lc_enabled = 0;
  }
  if (!lc_enabled) return;

  {
    u8* env = (u8*)getenv("ECOFUZZ_LC_LOG_MODE");
    if (env && !strcmp((char*)env, "all")) lc_log_all = 1;
  }

  {
    u8* env = (u8*)getenv("ECOFUZZ_LC_RATE_REL_DELTA");
    if (env) lc_rate_rel_delta = atof((char*)env);
  }
  {
    u8* env = (u8*)getenv("ECOFUZZ_LC_RATE_ABS_DELTA");
    if (env) lc_rate_abs_delta = atof((char*)env);
  }
  {
    u8* env = (u8*)getenv("ECOFUZZ_LC_ENERGY_REL_DELTA");
    if (env) lc_energy_rel_delta = atof((char*)env);
  }
  {
    u8* env = (u8*)getenv("ECOFUZZ_LC_STATS_INTERVAL_MS");
    if (env) lc_stats_interval_ms = (u32)atoi((char*)env);
  }

  /* Timeline file. */
  {
    u8* path = alloc_printf("%s/lc_timeline.csv", out_dir);
    lc_timeline_file = fopen(path, "a");
    if (lc_timeline_file) {
      fseek(lc_timeline_file, 0, SEEK_END);
      if (ftell(lc_timeline_file) == 0) {
        fprintf(lc_timeline_file,
                "timestamp_ms,event,queue_cycle,current_entry,state,rate,regret,energy,stage_max,record_time_us,queued_paths\n");
        fflush(lc_timeline_file);
      }
    }
    ck_free(path);
  }

}

static void lc_write_stats(float regret, u64 energy, s32 stage_max,
                           u64 record_time_us) {

  if (!lc_enabled) return;
  if (!lc_stats_interval_ms) return;

  u64 now_ms = get_cur_time();
  if (now_ms - lc_last_stats_ms < lc_stats_interval_ms) return;
  lc_last_stats_ms = now_ms;

  u8* path = alloc_printf("%s/lc_stats", out_dir);
  FILE* f = fopen(path, "w");
  if (f) {
    fprintf(f, "rate            : %.6f\n", rate);
    fprintf(f, "regret          : %.6f\n", regret);
    fprintf(f, "queue_cycle     : %llu\n", queue_cycle);
    fprintf(f, "current_entry   : %u\n", current_entry);
    fprintf(f, "state_of_fuzz   : %u\n", state_of_fuzz);
    fprintf(f, "energy          : %llu\n", energy);
    fprintf(f, "stage_max       : %d\n", stage_max);
    fprintf(f, "record_time_us  : %llu\n", record_time_us);
    fprintf(f, "queued_paths    : %u\n", queued_paths);
    fclose(f);
  }
  ck_free(path);

}

static void lc_log_line(const char* event, float regret, u64 energy,
                        s32 stage_max, u64 record_time_us) {

  if (!lc_enabled) return;
  if (!lc_timeline_file) lc_init();
  if (!lc_timeline_file) return;

  fprintf(lc_timeline_file, "%llu,%s,%llu,%u,%u,%.6f,%.6f,%llu,%d,%llu,%u\n",
          get_cur_time(), event, queue_cycle, current_entry, state_of_fuzz, rate,
          regret, energy, stage_max, record_time_us, queued_paths);
  fflush(lc_timeline_file);

}

static void lc_log_queue_cycle(void) {
  lc_log_line("queue_cycle", 0.0f, 0, 0, 0);
}

static void lc_log_fuzz_one(float regret, u64 energy, s32 stage_max,
                            u64 record_time_us) {

  if (!lc_enabled) return;

  lc_write_stats(regret, energy, stage_max, record_time_us);

  if (lc_log_all) {
    lc_log_line("fuzz_one", regret, energy, stage_max, record_time_us);
    lc_last_logged_rate = rate;
    lc_last_logged_stage_max = (stage_max > 0) ? (u64)stage_max : 0;
    return;
  }

  if (lc_last_logged_rate < 0.0f) {
    lc_log_line("init", regret, energy, stage_max, record_time_us);
    lc_last_logged_rate = rate;
    lc_last_logged_stage_max = (stage_max > 0) ? (u64)stage_max : 0;
    return;
  }

  /* Rate changes. */
  {
    double abs_delta = fabs((double)rate - (double)lc_last_logged_rate);
    double rel_delta =
        (lc_last_logged_rate > 0.0f) ? (abs_delta / (double)lc_last_logged_rate)
                                     : 1.0;
    if (abs_delta >= lc_rate_abs_delta || rel_delta >= lc_rate_rel_delta) {
      lc_log_line("rate_change", regret, energy, stage_max, record_time_us);
      lc_last_logged_rate = rate;
    }
  }

  /* Energy changes (use stage_max as the effective energy allocation). */
  if (stage_max > 0) {
    u64 stage_max_u64 = (u64)stage_max;
    if (!lc_last_logged_stage_max) {
      lc_log_line("energy_change", regret, energy, stage_max, record_time_us);
      lc_last_logged_stage_max = stage_max_u64;
    } else {
      double abs_delta =
          fabs((double)stage_max_u64 - (double)lc_last_logged_stage_max);
      double rel_delta = abs_delta / (double)lc_last_logged_stage_max;
      if (rel_delta >= lc_energy_rel_delta) {
        lc_log_line("energy_change", regret, energy, stage_max, record_time_us);
        lc_last_logged_stage_max = stage_max_u64;
      }
    }
  }

}

"""
    content = content.replace(helper_marker, helper_insert + helper_marker, 1)

    # 4) Call lc_init() once output directory is ready (use time setup hook).
    time_fdopen_marker = 'if (!time_file) PFATAL("Fdopen time file failed.");'
    if time_fdopen_marker not in content:
        raise RuntimeError("Could not find setup_time_fds fdopen call.")
    content = content.replace(time_fdopen_marker, time_fdopen_marker + "\n\n  lc_init();", 1)

    # 5) Ensure energy is initialized in fuzz_one (so logging is safe on early exits).
    content = content.replace(
        "last_mutation_num = 0, energy, energy_in_det = 0,",
        "last_mutation_num = 0, energy = 0, energy_in_det = 0,",
        1,
    )

    # 6) Log queue-cycle boundaries.
    content = content.replace("      queue_cycle++;", "      queue_cycle++;\n\n      lc_log_queue_cycle();", 1)

    # 7) Log end-of-fuzz_one updates (rate/energy snapshot + significant-change events).
    content = content.replace(
        "  write_to_time_file(record_time);\n\n  return ret_val;",
        "  write_to_time_file(record_time);\n\n  lc_log_fuzz_one(regret, energy, stage_max, record_time);\n\n  return ret_val;",
        1,
    )

    # 8) Clean up logs when reusing an output directory.
    cleanup_block = (
        '  fn = alloc_printf("%s/information_of_time", out_dir);\n'
        '  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;\n'
        '  ck_free(fn);\n\n'
    )
    if cleanup_block not in content:
        raise RuntimeError("Could not find output-dir cleanup block for information_of_time.")
    cleanup_insert = (
        '  fn = alloc_printf("%s/lc_timeline.csv", out_dir);\n'
        '  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;\n'
        '  ck_free(fn);\n\n'
        '  fn = alloc_printf("%s/lc_stats", out_dir);\n'
        '  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;\n'
        '  ck_free(fn);\n\n'
    )
    content = content.replace(cleanup_block, cleanup_block + cleanup_insert, 1)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_afl-fuzz.c> <output_afl-fuzz.c>")
        return 2
    patch_afl_fuzz(sys.argv[1], sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
