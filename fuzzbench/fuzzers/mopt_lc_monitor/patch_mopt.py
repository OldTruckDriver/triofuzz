#!/usr/bin/env python3
"""
Script to patch MOpt-AFL for learning cycle monitoring.
This adds instrumentation to track learning cycle statistics.
"""

import sys
import re

def patch_afl_fuzz(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()

    # 1. Add learning cycle monitoring variables after "swarm_fitness[swarm_num];"
    lc_vars = '''
/* Learning cycle monitoring variables - added by mopt_lc_monitor */
u64 lc_cycle_count = 0;           /* Total number of complete learning cycles */
u64 lc_pilot_phases = 0;          /* Number of pilot phase completions */
u64 lc_core_phases = 0;           /* Number of core phase completions */
u64 lc_pso_updates = 0;           /* Number of PSO updates */
u64 lc_last_cycle_start = 0;      /* Start time of current cycle */
u64 lc_last_cycle_duration = 0;   /* Duration of last complete cycle (ms) */
u64 lc_total_cycle_time = 0;      /* Total time in learning cycles (ms) */
u64 lc_min_cycle_duration = (u64)-1; /* Minimum cycle duration */
u64 lc_max_cycle_duration = 0;    /* Maximum cycle duration */
u64 lc_last_pilot_execs = 0;      /* Execs in last pilot phase */
u64 lc_last_core_execs = 0;       /* Execs in last core phase */
FILE* lc_log_file = NULL;         /* Learning cycle log file */
'''

    marker = 'swarm_fitness[swarm_num];'
    if marker in content:
        content = content.replace(marker, marker + lc_vars, 1)
        print("Added learning cycle variables")
    else:
        print("Warning: Could not find 'swarm_fitness[swarm_num];'")

    # 2. Add the helper functions before "/* Write bitmap to file */"
    # Use literal backslash-n in the C code
    lc_functions = r'''
/* Write learning cycle stats to log file - added by mopt_lc_monitor */
static void write_lc_stats(void) {
    u8* lc_stats_file = alloc_printf("%s/lc_stats", out_dir);
    FILE* f = fopen(lc_stats_file, "w");
    if (f) {
        fprintf(f, "learning_cycles       : %llu\n", lc_cycle_count);
        fprintf(f, "pilot_phases          : %llu\n", lc_pilot_phases);
        fprintf(f, "core_phases           : %llu\n", lc_core_phases);
        fprintf(f, "pso_updates           : %llu\n", lc_pso_updates);
        fprintf(f, "last_cycle_duration_ms: %llu\n", lc_last_cycle_duration);
        fprintf(f, "total_cycle_time_ms   : %llu\n", lc_total_cycle_time);
        fprintf(f, "min_cycle_duration_ms : %llu\n",
                lc_min_cycle_duration == (u64)-1 ? 0 : lc_min_cycle_duration);
        fprintf(f, "max_cycle_duration_ms : %llu\n", lc_max_cycle_duration);
        fprintf(f, "avg_cycle_duration_ms : %llu\n",
                lc_cycle_count > 0 ? lc_total_cycle_time / lc_cycle_count : 0);
        fprintf(f, "current_swarm         : %d\n", swarm_now);
        fprintf(f, "current_key_module    : %d\n", key_module);
        fprintf(f, "last_pilot_execs      : %llu\n", lc_last_pilot_execs);
        fprintf(f, "last_core_execs       : %llu\n", lc_last_core_execs);
        fprintf(f, "total_pacemaker_time  : %llu\n", total_pacemaker_time);
        int i;
        for (i = 0; i < swarm_num; i++) {
            fprintf(f, "swarm_%d_fitness       : %.6f\n", i, swarm_fitness[i]);
        }
        fclose(f);
    }
    ck_free(lc_stats_file);
}

/* Append to learning cycle timeline log - added by mopt_lc_monitor */
static void log_lc_event(const char* event, u64 execs) {
    if (!lc_log_file) {
        u8* lc_log_path = alloc_printf("%s/lc_timeline.csv", out_dir);
        lc_log_file = fopen(lc_log_path, "w");
        if (lc_log_file) {
            fprintf(lc_log_file, "timestamp_ms,event,cycle,swarm,key_module,execs,duration_ms\n");
        }
        ck_free(lc_log_path);
    }
    if (lc_log_file) {
        fprintf(lc_log_file, "%llu,%s,%llu,%d,%d,%llu,%llu\n",
                get_cur_time(), event, lc_cycle_count, swarm_now, key_module, execs, lc_last_cycle_duration);
        fflush(lc_log_file);
    }
}

'''

    marker = '/* Write bitmap to file'
    if marker in content:
        content = content.replace(marker, lc_functions + marker, 1)
        print("Added write_lc_stats and log_lc_event functions")
    else:
        print("Warning: Could not find '/* Write bitmap to file'")

    # 3. Add pilot phase tracking
    pilot_tracking = '''
      lc_pilot_phases++;
      lc_last_pilot_execs = tmp_pilot_time;
      log_lc_event("pilot_complete", tmp_pilot_time);
'''
    marker = 'total_pacemaker_time += tmp_pilot_time;'
    if marker in content:
        content = content.replace(marker, marker + pilot_tracking, 1)
        print("Added pilot phase tracking")
    else:
        print("Warning: Could not find pilot phase completion pattern")

    # 4. Add core phase tracking
    core_tracking = '''
      lc_core_phases++;
      lc_last_core_execs = tmp_core_time;
      log_lc_event("core_complete", tmp_core_time);
'''
    marker = 'total_pacemaker_time += tmp_core_time;'
    if marker in content:
        content = content.replace(marker, marker + core_tracking, 1)
        print("Added core phase tracking")
    else:
        print("Warning: Could not find core phase completion pattern")

    # 5. Add PSO update tracking after g_now++
    pso_tracking = '''
      lc_pso_updates++;

      /* Calculate cycle duration - added by mopt_lc_monitor */
      {
          u64 cur_time = get_cur_time();
          if (lc_last_cycle_start > 0) {
              lc_last_cycle_duration = cur_time - lc_last_cycle_start;
              lc_total_cycle_time += lc_last_cycle_duration;
              if (lc_last_cycle_duration < lc_min_cycle_duration)
                  lc_min_cycle_duration = lc_last_cycle_duration;
              if (lc_last_cycle_duration > lc_max_cycle_duration)
                  lc_max_cycle_duration = lc_last_cycle_duration;
              lc_cycle_count++;
          }
          lc_last_cycle_start = cur_time;
          log_lc_event("pso_update", 0);
      }
'''
    # Try both patterns: g_now++; and g_now += 1;
    marker = 'g_now++;'
    marker2 = 'g_now += 1;'
    if marker in content:
        content = content.replace(marker, marker + pso_tracking, 1)
        print("Added PSO update tracking (g_now++)")
    elif marker2 in content:
        content = content.replace(marker2, marker2 + pso_tracking, 1)
        print("Added PSO update tracking (g_now += 1)")
    else:
        print("Warning: Could not find g_now++ or g_now += 1 pattern")

    # 6. Add write_lc_stats() call at the end of pso_updating
    # Find the pattern and add after it
    pattern = r'(swarm_now = 0;\s*\n\s*key_module = 0;)'
    match = re.search(pattern, content)
    if match:
        insert_pos = match.end()
        content = content[:insert_pos] + '\n      write_lc_stats();' + content[insert_pos:]
        print("Added write_lc_stats() call in pso_updating")
    else:
        print("Warning: Could not find end of pso_updating pattern")

    # 7. Add learning_cycles to fuzzer_stats output
    # Add to the fprintf format string
    old_format = '"afl_banner        : %s\\n"'
    new_format = '"learning_cycles   : %llu\\n"\n               "afl_banner        : %s\\n"'
    if old_format in content:
        content = content.replace(old_format, new_format, 1)
        print("Added learning_cycles to stats format")
    else:
        print("Warning: Could not find afl_banner pattern")

    # Add lc_cycle_count to the fprintf arguments (before use_banner)
    old_args = 'exec_tmout, use_banner,'
    new_args = 'exec_tmout, lc_cycle_count, use_banner,'
    if old_args in content:
        content = content.replace(old_args, new_args, 1)
        print("Added lc_cycle_count to stats arguments")
    else:
        print("Warning: Could not find exec_tmout, use_banner pattern")

    with open(output_file, 'w') as f:
        f.write(content)

    print(f"Patched file written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_afl-fuzz.c> <output_afl-fuzz.c>")
        sys.exit(1)

    patch_afl_fuzz(sys.argv[1], sys.argv[2])
