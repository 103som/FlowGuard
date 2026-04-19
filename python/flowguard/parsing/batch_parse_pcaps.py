#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Recursively parse pcap/pcapng files with C++ parser")
    p.add_argument("--parser-bin", required=True, help="Path to pcap_flow_parser binary")
    p.add_argument("--input-dir", required=True, help="Directory with pcap/pcapng files")
    p.add_argument("--output-dir", required=True, help="Where to store CSV files")
    p.add_argument("--skip-existing", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    parser_bin = Path(args.parser_bin).resolve()
    input_dir = Path(args.input_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(
        list(input_dir.rglob("*.pcap")) +
        list(input_dir.rglob("*.pcapng"))
    )

    if not files:
        print("[WARN] No pcap/pcapng files found")
        return

    print(f"[INFO] Found {len(files)} capture files")

    ok = 0
    fail = 0

    for src in files:
        rel = src.relative_to(input_dir)
        dst = output_dir / rel.with_suffix(".csv")
        dst.parent.mkdir(parents=True, exist_ok=True)

        if args.skip_existing and dst.exists():
            print(f"[SKIP] {dst}")
            continue

        cmd = [str(parser_bin), str(src), str(dst)]
        print(f"[RUN ] {' '.join(cmd)}")

        try:
            subprocess.run(cmd, check=True)
            ok += 1
        except subprocess.CalledProcessError:
            print(f"[FAIL] {src}")
            fail += 1

    print()
    print(f"[DONE] ok={ok}, fail={fail}")


if __name__ == "__main__":
    main()
