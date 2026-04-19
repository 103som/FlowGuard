#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build Group 5: benign TLS from parsed benign CSVs")
    p.add_argument("--input-dir", required=True, help="Parsed CSV directory for benign_tls")
    p.add_argument("--out-csv", required=True, help="Output CSV path")
    p.add_argument("--target-size", type=int, default=2000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--per-source-max", type=int, default=300, help="Max rows per source CSV")
    return p.parse_args()


def ensure_ja4_present(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    if "ja4_present" in out.columns:
        out["ja4_present"] = pd.to_numeric(out["ja4_present"], errors="coerce").fillna(0).astype(int)
        return out

    if "tls_client_hello_c2s" in out.columns:
        out["tls_client_hello_c2s"] = pd.to_numeric(out["tls_client_hello_c2s"], errors="coerce").fillna(0)
        out["ja4_present"] = (out["tls_client_hello_c2s"] > 0).astype(int)
        return out

    if "ja4_legacy_version" in out.columns:
        s = out["ja4_legacy_version"].astype("string").fillna("").str.strip().str.lower()
        out["ja4_present"] = (~s.isin(["", "none", "nan", "<na>"])).astype(int)
        return out

    raise ValueError("Cannot derive ja4_present")


def main() -> None:
    args = parse_args()

    input_dir = Path(args.input_dir)
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(input_dir.rglob("*.csv"))
    if not csv_files:
        raise RuntimeError("No parsed CSV files found")

    parts = []

    for csv_path in csv_files:
        df = pd.read_csv(csv_path)
        df = ensure_ja4_present(df)

        df = df[df["ja4_present"] == 1].copy()
        if len(df) == 0:
            continue

        if len(df) > args.per_source_max:
            df = df.sample(n=args.per_source_max, random_state=args.seed)

        df["group_name"] = "benign_tls"
        df["binary_label"] = 0
        df["source_group"] = "g5_benign_tls"
        rel = csv_path.relative_to(input_dir).with_suffix("")
        df["source_file"] = str(rel).replace("\\", "/")
        parts.append(df)

        print(f"[KEEP] {csv_path.name}: {len(df)} rows")

    if not parts:
        raise RuntimeError("No rows left for G5")

    merged = pd.concat(parts, ignore_index=True)

    if len(merged) > args.target_size:
        merged = merged.sample(n=args.target_size, random_state=args.seed)

    merged = merged.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    merged.to_csv(out_csv, index=False)

    print()
    print(f"[OK] wrote: {out_csv}")
    print(f"[OK] rows: {len(merged)}")
    print(f"[OK] unique source files: {merged['source_file'].nunique()}")


if __name__ == "__main__":
    main()
