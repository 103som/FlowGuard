#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import pandas as pd


RAW_LEAKAGE_COLS = {
    "label",
    "binary_label",
    "group_name",
    "source_group",
    "source_file",
    "source_dataset",
    "client_ip",
    "server_ip",
    "src_ip",
    "dst_ip",
    "client_port",
    "server_port",
    "src_port",
    "dst_port",
}

SUSPICIOUS_SUBSTRINGS = [
    "label",
    "class",
    "attack",
    "source",
    "group",
    "mal",
    "benign",
]


def parse_args():
    p = argparse.ArgumentParser(description="Audit Experiment 2 for leakage")
    p.add_argument("--raw-train", required=True)
    p.add_argument("--raw-val", required=True)
    p.add_argument("--raw-test", required=True)

    p.add_argument("--mi-train-flow", required=True)
    p.add_argument("--mi-val-flow", required=True)
    p.add_argument("--mi-test-flow", required=True)

    p.add_argument("--mi-train-ja4", required=True)
    p.add_argument("--mi-val-ja4", required=True)
    p.add_argument("--mi-test-ja4", required=True)
    return p.parse_args()


def row_hashes(df: pd.DataFrame, exclude: set[str]) -> set[str]:
    cols = [c for c in df.columns if c not in exclude]
    sub = df[cols].copy()
    sub = sub.reindex(sorted(sub.columns), axis=1)

    hashes = set()
    for row in sub.itertuples(index=False, name=None):
        s = "||".join("" if pd.isna(x) else str(x) for x in row)
        h = hashlib.sha1(s.encode("utf-8")).hexdigest()
        hashes.add(h)
    return hashes


def pairwise_overlap(name_a: str, set_a: set[str], name_b: str, set_b: set[str]) -> None:
    inter = set_a & set_b
    print(f"{name_a} vs {name_b}: {len(inter)} overlaps")


def print_source_overlap(train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame) -> None:
    if "source_file" not in train_df.columns:
        print("[WARN] No source_file column in raw splits")
        return

    train_sources = set(train_df["source_file"].astype(str).unique())
    val_sources = set(val_df["source_file"].astype(str).unique())
    test_sources = set(test_df["source_file"].astype(str).unique())

    print("\n=== Source file overlap ===")
    pairwise_overlap("train", train_sources, "val", val_sources)
    pairwise_overlap("train", train_sources, "test", test_sources)
    pairwise_overlap("val", val_sources, "test", test_sources)

    if "group_name" in train_df.columns:
        print("\n=== Source overlap by group ===")
        all_groups = sorted(set(train_df["group_name"].astype(str).unique()) |
                            set(val_df["group_name"].astype(str).unique()) |
                            set(test_df["group_name"].astype(str).unique()))
        for g in all_groups:
            tr = set(train_df.loc[train_df["group_name"] == g, "source_file"].astype(str).unique())
            va = set(val_df.loc[val_df["group_name"] == g, "source_file"].astype(str).unique())
            te = set(test_df.loc[test_df["group_name"] == g, "source_file"].astype(str).unique())
            print(f"\nGroup: {g}")
            pairwise_overlap("  train", tr, "val", va)
            pairwise_overlap("  train", tr, "test", te)
            pairwise_overlap("  val", va, "test", te)


def print_duplicate_overlap(train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame, title: str, exclude: set[str]) -> None:
    train_h = row_hashes(train_df, exclude=exclude)
    val_h = row_hashes(val_df, exclude=exclude)
    test_h = row_hashes(test_df, exclude=exclude)

    print(f"\n=== Exact row overlap: {title} ===")
    pairwise_overlap("train", train_h, "val", val_h)
    pairwise_overlap("train", train_h, "test", test_h)
    pairwise_overlap("val", val_h, "test", test_h)


def print_suspicious_columns(df: pd.DataFrame, title: str) -> None:
    cols = df.columns.tolist()
    suspicious = [c for c in cols if any(s in c.lower() for s in SUSPICIOUS_SUBSTRINGS)]
    print(f"\n=== Suspicious columns in {title} ===")
    if suspicious:
        for c in suspicious:
            print(" ", c)
    else:
        print("  none")


def print_ja4_tables(df: pd.DataFrame, title: str) -> None:
    print(f"\n=== JA4 breakdown in {title} ===")
    for col in ["ja4_legacy_version", "ja4_alpn"]:
        if col in df.columns:
            print(f"\n{col}:")
            tab = pd.crosstab(df[col].astype("string"), df["label"])
            print(tab.head(20).to_string())


def main():
    args = parse_args()

    raw_train = pd.read_csv(args.raw_train)
    raw_val = pd.read_csv(args.raw_val)
    raw_test = pd.read_csv(args.raw_test)

    mi_train_flow = pd.read_csv(args.mi_train_flow)
    mi_val_flow = pd.read_csv(args.mi_val_flow)
    mi_test_flow = pd.read_csv(args.mi_test_flow)

    mi_train_ja4 = pd.read_csv(args.mi_train_ja4)
    mi_val_ja4 = pd.read_csv(args.mi_val_ja4)
    mi_test_ja4 = pd.read_csv(args.mi_test_ja4)

    print_source_overlap(raw_train, raw_val, raw_test)

    print_duplicate_overlap(raw_train, raw_val, raw_test, "raw splits (excluding obvious leakage)", RAW_LEAKAGE_COLS)

    print_suspicious_columns(mi_train_flow, "model_inputs flow_only train")
    print_suspicious_columns(mi_train_ja4, "model_inputs flow_plus_ja4 train")

    print_duplicate_overlap(mi_train_flow, mi_val_flow, mi_test_flow, "model_inputs flow_only", {"label"})
    print_duplicate_overlap(mi_train_ja4, mi_val_ja4, mi_test_ja4, "model_inputs flow_plus_ja4", {"label"})

    print_ja4_tables(pd.concat([mi_train_ja4, mi_val_ja4, mi_test_ja4], ignore_index=True), "full flow_plus_ja4 inputs")


if __name__ == "__main__":
    main()
