#!/usr/bin/env python3
"""
Analyze MOpt learning cycle data and generate visualizations.

Usage:
    python analyze_lc.py <output_corpus_dir> [--output-dir <dir>]

Example:
    python analyze_lc.py /path/to/fuzzer/output --output-dir ./plots
"""

import argparse
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path


def parse_lc_stats(stats_file):
    """Parse the lc_stats file into a dictionary."""
    stats = {}
    if not os.path.exists(stats_file):
        return stats

    with open(stats_file, 'r') as f:
        for line in f:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                try:
                    if '.' in value:
                        stats[key] = float(value)
                    else:
                        stats[key] = int(value)
                except ValueError:
                    stats[key] = value
    return stats


def parse_lc_timeline(timeline_file):
    """Parse the lc_timeline.csv file into a DataFrame."""
    if not os.path.exists(timeline_file):
        return None

    df = pd.read_csv(timeline_file)
    # Convert timestamp to seconds from start
    if len(df) > 0:
        df['time_sec'] = (df['timestamp_ms'] - df['timestamp_ms'].iloc[0]) / 1000.0
    return df


def plot_cycle_durations(df, output_dir):
    """Plot learning cycle durations over time."""
    if df is None or len(df) == 0:
        print("No timeline data available for cycle duration plot")
        return

    # Filter for PSO update events (end of each cycle)
    pso_events = df[df['event'] == 'pso_update'].copy()

    if len(pso_events) == 0:
        print("No PSO update events found")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    # Plot cycle durations
    ax.plot(pso_events['cycle'], pso_events['duration_ms'] / 1000.0,
            marker='o', linestyle='-', linewidth=1, markersize=4)
    ax.set_xlabel('Learning Cycle Number')
    ax.set_ylabel('Cycle Duration (seconds)')
    ax.set_title('MOpt Learning Cycle Duration Over Time')
    ax.grid(True, alpha=0.3)

    # Add average line
    avg_duration = pso_events['duration_ms'].mean() / 1000.0
    ax.axhline(y=avg_duration, color='r', linestyle='--',
               label=f'Average: {avg_duration:.2f}s')
    ax.legend()

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'cycle_durations.png'), dpi=150)
    plt.close()
    print(f"Saved: {output_dir}/cycle_durations.png")


def plot_phase_timeline(df, output_dir):
    """Plot the timeline of pilot, core, and PSO phases."""
    if df is None or len(df) == 0:
        print("No timeline data available for phase timeline plot")
        return

    fig, ax = plt.subplots(figsize=(14, 6))

    colors = {
        'pilot_complete': 'blue',
        'core_complete': 'green',
        'pso_update': 'red'
    }
    labels = {
        'pilot_complete': 'Pilot Phase',
        'core_complete': 'Core Phase',
        'pso_update': 'PSO Update'
    }

    for event_type in ['pilot_complete', 'core_complete', 'pso_update']:
        events = df[df['event'] == event_type]
        if len(events) > 0:
            ax.scatter(events['time_sec'] / 60.0, [event_type] * len(events),
                      c=colors[event_type], label=labels[event_type],
                      alpha=0.6, s=20)

    ax.set_xlabel('Time (minutes)')
    ax.set_ylabel('Event Type')
    ax.set_title('MOpt Learning Cycle Phase Timeline')
    ax.legend()
    ax.grid(True, alpha=0.3, axis='x')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'phase_timeline.png'), dpi=150)
    plt.close()
    print(f"Saved: {output_dir}/phase_timeline.png")


def plot_cycles_over_time(df, output_dir):
    """Plot cumulative learning cycles over time."""
    if df is None or len(df) == 0:
        print("No timeline data available for cycles over time plot")
        return

    pso_events = df[df['event'] == 'pso_update'].copy()

    if len(pso_events) == 0:
        print("No PSO update events found")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(pso_events['time_sec'] / 60.0, pso_events['cycle'],
            marker='.', linestyle='-', linewidth=1)
    ax.set_xlabel('Time (minutes)')
    ax.set_ylabel('Completed Learning Cycles')
    ax.set_title('MOpt Cumulative Learning Cycles Over Time')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'cycles_over_time.png'), dpi=150)
    plt.close()
    print(f"Saved: {output_dir}/cycles_over_time.png")


def plot_execution_counts(df, output_dir):
    """Plot execution counts per phase."""
    if df is None or len(df) == 0:
        print("No timeline data available for execution counts plot")
        return

    pilot_events = df[df['event'] == 'pilot_complete']
    core_events = df[df['event'] == 'core_complete']

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Pilot phase executions
    if len(pilot_events) > 0:
        axes[0].hist(pilot_events['execs'], bins=30, color='blue', alpha=0.7)
        axes[0].axvline(x=50000, color='r', linestyle='--',
                       label='period_pilot (50000)')
        axes[0].set_xlabel('Executions')
        axes[0].set_ylabel('Frequency')
        axes[0].set_title('Pilot Phase Execution Counts')
        axes[0].legend()

    # Core phase executions
    if len(core_events) > 0:
        axes[1].hist(core_events['execs'], bins=30, color='green', alpha=0.7)
        axes[1].axvline(x=500000, color='r', linestyle='--',
                       label='period_core (500000)')
        axes[1].set_xlabel('Executions')
        axes[1].set_ylabel('Frequency')
        axes[1].set_title('Core Phase Execution Counts')
        axes[1].legend()

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'execution_counts.png'), dpi=150)
    plt.close()
    print(f"Saved: {output_dir}/execution_counts.png")


def plot_swarm_distribution(df, output_dir):
    """Plot swarm usage distribution."""
    if df is None or len(df) == 0:
        print("No timeline data available for swarm distribution plot")
        return

    pilot_events = df[df['event'] == 'pilot_complete']

    if len(pilot_events) == 0:
        print("No pilot events found")
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    swarm_counts = pilot_events['swarm'].value_counts().sort_index()
    ax.bar(swarm_counts.index, swarm_counts.values, color='purple', alpha=0.7)
    ax.set_xlabel('Swarm Index')
    ax.set_ylabel('Number of Pilot Phases')
    ax.set_title('Swarm Usage Distribution')
    ax.set_xticks(range(5))
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'swarm_distribution.png'), dpi=150)
    plt.close()
    print(f"Saved: {output_dir}/swarm_distribution.png")


def print_summary(stats, df):
    """Print a summary of learning cycle statistics."""
    print("\n" + "=" * 60)
    print("MOpt Learning Cycle Summary")
    print("=" * 60)

    if stats:
        print(f"\nTotal Learning Cycles: {stats.get('learning_cycles', 'N/A')}")
        print(f"Pilot Phases: {stats.get('pilot_phases', 'N/A')}")
        print(f"Core Phases: {stats.get('core_phases', 'N/A')}")
        print(f"PSO Updates: {stats.get('pso_updates', 'N/A')}")

        avg_ms = stats.get('avg_cycle_duration_ms', 0)
        min_ms = stats.get('min_cycle_duration_ms', 0)
        max_ms = stats.get('max_cycle_duration_ms', 0)

        print(f"\nCycle Duration Statistics:")
        print(f"  Average: {avg_ms/1000:.2f} seconds ({avg_ms/60000:.2f} minutes)")
        print(f"  Minimum: {min_ms/1000:.2f} seconds")
        print(f"  Maximum: {max_ms/1000:.2f} seconds")

        print(f"\nLast Cycle:")
        print(f"  Pilot Execs: {stats.get('last_pilot_execs', 'N/A')}")
        print(f"  Core Execs: {stats.get('last_core_execs', 'N/A')}")
        print(f"  Duration: {stats.get('last_cycle_duration_ms', 0)/1000:.2f} seconds")

        print(f"\nSwarm Fitness Values:")
        for i in range(5):
            fitness = stats.get(f'swarm_{i}_fitness', 'N/A')
            print(f"  Swarm {i}: {fitness}")
    else:
        print("No lc_stats file found")

    if df is not None and len(df) > 0:
        total_time = (df['timestamp_ms'].iloc[-1] - df['timestamp_ms'].iloc[0]) / 1000.0
        pso_count = len(df[df['event'] == 'pso_update'])
        if pso_count > 0 and total_time > 0:
            cycles_per_hour = pso_count / (total_time / 3600.0)
            print(f"\nRuntime Statistics:")
            print(f"  Total Runtime: {total_time/60:.2f} minutes")
            print(f"  Cycles per Hour: {cycles_per_hour:.2f}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze MOpt learning cycle data')
    parser.add_argument('corpus_dir', help='Path to fuzzer output corpus directory')
    parser.add_argument('--output-dir', '-o', default='./lc_plots',
                       help='Directory to save plots (default: ./lc_plots)')
    args = parser.parse_args()

    corpus_dir = args.corpus_dir
    output_dir = args.output_dir

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Parse data files
    lc_stats_file = os.path.join(corpus_dir, 'lc_stats')
    lc_timeline_file = os.path.join(corpus_dir, 'lc_timeline.csv')

    stats = parse_lc_stats(lc_stats_file)
    df = parse_lc_timeline(lc_timeline_file)

    # Print summary
    print_summary(stats, df)

    # Generate plots
    print("\nGenerating plots...")
    plot_cycle_durations(df, output_dir)
    plot_phase_timeline(df, output_dir)
    plot_cycles_over_time(df, output_dir)
    plot_execution_counts(df, output_dir)
    plot_swarm_distribution(df, output_dir)

    print(f"\nAll plots saved to: {output_dir}")


if __name__ == '__main__':
    main()
