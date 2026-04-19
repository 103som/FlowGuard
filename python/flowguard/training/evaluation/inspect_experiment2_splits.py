#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args():
    p = argparse.ArgumentParser(description="Inspect experiment2 train/val/test composition")
    p.add_argument("--train", required=True)
    p.add_argument("--val", required=True)
    p.add_argument("--test", required=True)
    return p.parse_args()


def load_df(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "label" not in df.columns and "binary_label" in df.columns:
        df["label"] = pd.to_numeric(df["binary_label"], errors="raise").astype(int)
    return df


def print_basic(name: str, df: pd.DataFrame) -> None:
    print(f"\n=== {name} ===")
    print(f"rows: {len(df)}")
    if "label" in df.columns:
        print("\nlabel distribution:")
        print(df["label"].value_counts(dropna=False).to_string())
    if "group_name" in df.columns:
        print("\ngroup distribution:")
        print(df["group_name"].value_counts(dropna=False).to_string())
    if "source_file" in df.columns:
        print(f"\nunique source_file: {df['source_file'].nunique()}")
    if "family" in df.columns:
        print(f"unique family: {df['family'].astype(str).nunique()}")


def print_family_breakdown(name: str, df: pd.DataFrame) -> None:
    if "family" not in df.columns:
        print(f"\n[{name}] no family column")
        return

    print(f"\n--- {name}: family x label ---")
    tab = pd.crosstab(df["family"].astype(str), df["label"])
    print(tab.sort_values(by=list(tab.columns), ascending=False).to_string())

    print(f"\n--- {name}: top family counts ---")
    print(df["family"].astype(str).value_counts().to_string())

    if "source_file" in df.columns:
        fam_src = (
            df.groupby("family")["source_file"]
            .nunique()
            .sort_values(ascending=False)
        )
        print(f"\n--- {name}: unique sources per family ---")
        print(fam_src.to_string())


def print_g5_sources(name: str, df: pd.DataFrame) -> None:
    if "group_name" not in df.columns or "source_file" not in df.columns:
        return

    sub = df[df["group_name"] == "benign_tls"].copy()
    if len(sub) == 0:
        return

    print(f"\n--- {name}: benign_tls source counts ---")
    print(sub["source_file"].value_counts().to_string())


def compare_sets(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame) -> None:
    if "family" in train.columns:
        tr_f = set(train["family"].astype(str).unique())
        va_f = set(val["family"].astype(str).unique())
        te_f = set(test["family"].astype(str).unique())

        print("\n=== family overlap ===")
        print(f"train ∩ val : {sorted(tr_f & va_f)}")
        print(f"train ∩ test: {sorted(tr_f & te_f)}")
        print(f"val ∩ test  : {sorted(va_f & te_f)}")

    if "source_file" in train.columns:
        tr_s = set(train["source_file"].astype(str).unique())
        va_s = set(val["source_file"].astype(str).unique())
        te_s = set(test["source_file"].astype(str).unique())

        print("\n=== source overlap ===")
        print(f"train ∩ val : {len(tr_s & va_s)}")
        print(f"train ∩ test: {len(tr_s & te_s)}")
        print(f"val ∩ test  : {len(va_s & te_s)}")


def main():
    args = parse_args()

    train = load_df(args.train)
    val = load_df(args.val)
    test = load_df(args.test)

    print_basic("TRAIN", train)
    print_basic("VAL", val)
    print_basic("TEST", test)

    print_family_breakdown("TRAIN", train)
    print_family_breakdown("VAL", val)
    print_family_breakdown("TEST", test)

    print_g5_sources("TRAIN", train)
    print_g5_sources("VAL", val)
    print_g5_sources("TEST", test)

    compare_sets(train, val, test)


if __name__ == "__main__":
    main()
