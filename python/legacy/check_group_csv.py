#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args():
    p = argparse.ArgumentParser(description="Check prepared group CSV")
    p.add_argument("--csv", required=True)
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

    out["ja4_present"] = 0
    return out


def main():
    args = parse_args()
    path = Path(args.csv)
    df = pd.read_csv(path)
    df = ensure_ja4_present(df)

    print(f"file: {path}")
    print(f"rows: {len(df)}")

    if "binary_label" in df.columns:
        print("\nbinary_label:")
        print(df["binary_label"].value_counts(dropna=False).to_string())

    print("\nja4_present:")
    print(df["ja4_present"].value_counts(dropna=False).to_string())

    if "source_file" in df.columns:
        print(f"\nunique source_file: {df['source_file'].nunique()}")

    for c in ["ja4_legacy_version", "ja4_alpn"]:
        if c in df.columns:
            print(f"\nTop values for {c}:")
            print(df[c].astype("string").value_counts(dropna=False).head(10).to_string())


if __name__ == "__main__":
    main()
