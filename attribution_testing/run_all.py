"""Convenience entry point — run E1..E5 and emit SUMMARY.md."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent

def run(script: str, limit: int):
    print(f"\n=== {script} ===")
    subprocess.check_call([sys.executable, str(HERE / script), "--limit", str(limit)])


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    run("e1_process_forest.py", args.limit)
    run("e2_syscall_attr.py", args.limit)
    run("e3_session_part.py", args.limit)
    run("e4_toolcall_attr.py", args.limit)
    run("e5_concurrency.py", args.limit)


if __name__ == "__main__":
    main()
