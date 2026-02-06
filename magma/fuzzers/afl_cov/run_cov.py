#!/usr/bin/env python3
import os
import argparse
import subprocess
from pathlib import Path

def run_cmd(cmd, env=None):
    print(f"[RUN] {' '.join(cmd)}")
    subprocess.check_call(cmd, env=env)

def main():
    parser = argparse.ArgumentParser(description="Run llvm-cov over corpus inputs")
    parser.add_argument("corpus", help="Path to corpus directory")
    parser.add_argument("target", help="Path to instrumented target executable")
    parser.add_argument("--output", default="coverage_html",
                        help="Output directory for HTML report")
    args = parser.parse_args()

    corpus = Path(args.corpus)
    target = Path(args.target)
    output_dir = Path(args.output)

    if not corpus.exists():
        raise FileNotFoundError(f"Corpus folder not found: {corpus}")
    if not target.exists():
        raise FileNotFoundError(f"Target executable not found: {target}")

    # 清理旧的 profraw，包括 default.profraw
    for old in Path(".").glob("*.profraw"):
        print(f"[CLEAN] remove old profraw: {old}")
        old.unlink()

    profraw_list = []

    # 对 corpus 里的每个 input 跑一次
    for inp in sorted(corpus.iterdir()):
        if inp.is_file():
            profraw = f"{inp.name}.profraw"

            env = os.environ.copy()
            env["LLVM_PROFILE_FILE"] = profraw

            print(f"\n=== Running {target} with input: {inp} ===")
            # 这里一定要传 env !!!
            run_cmd([str(target), str(inp)], env=env)

            profraw_list.append(profraw)

    if not profraw_list:
        print("No input files found in corpus, nothing to do.")
        return

    # 合并 profraw
    merged_file = "merged.profdata"
    merge_cmd = ["llvm-profdata", "merge", "-sparse"] + profraw_list + ["-o", merged_file]
    print("\n=== Merging profraw files ===")
    run_cmd(merge_cmd)

    # 生成 HTML 报告
    print("\n=== Generating HTML report ===")
    run_cmd([
        "llvm-cov", "show", str(target),
        "-instr-profile=" + merged_file,
        "-format=html",
        "-output-dir=" + str(output_dir),
        "-show-line-counts-or-regions"
    ])

    print(f"\n🎉 Coverage HTML report generated at: {output_dir}/index.html")


if __name__ == "__main__":
    main()