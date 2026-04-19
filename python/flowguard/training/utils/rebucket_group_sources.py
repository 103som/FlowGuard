#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args():
    p = argparse.ArgumentParser(description="Split one group CSV into pseudo-source buckets")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--bucket-size", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--prefix", default=None, help="Optional prefix for source_file")
    return p.parse_args()


def main():
    args = parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(inp)

    if "source_file" not in df.columns:
        base = args.prefix or inp.stem
        df["source_file"] = base
    else:
        df["source_file"] = df["source_file"].astype(str)

    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    old_source = df["source_file"].iloc[0] if len(df) > 0 else (args.prefix or inp.stem)
    bucket_ids = (df.index // args.bucket_size).astype(int)
    df["source_file"] = [f"{old_source}/bucket_{b:03d}" for b in bucket_ids]

    df.to_csv(out, index=False)

    print(f"[OK] wrote: {out}")
    print(f"rows: {len(df)}")
    print(f"unique source_file: {df['source_file'].nunique()}")


if __name__ == "__main__":
    main()
