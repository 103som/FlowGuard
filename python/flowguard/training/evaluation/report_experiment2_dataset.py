#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


FLOW_ONLY_ATTACK_GROUPS = {"flow_anomaly_noTLS", "flow_anomaly"}
JA4_ATTACK_GROUPS = {"tls_malware_ja4", "flow_ja4_anomaly_TLS"}

SAFE_JA4_COLS = [
    "tls_client_hello_c2s",
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build dataset report for Experiment 2")
    p.add_argument("--base-dir", required=True, help="e.g. ../../data/processed/experiment2_source_aware")
    p.add_argument("--out-json", default=None)
    return p.parse_args()


def pct(n: int, d: int) -> float:
    return 0.0 if d == 0 else 100.0 * n / d


def summarize_split(raw_df: pd.DataFrame, model_df: pd.DataFrame) -> dict:
    out: dict = {}
    out["rows"] = int(len(raw_df))

    # binary class balance
    label_counts = raw_df["label"].value_counts(dropna=False).to_dict()
    out["label_counts"] = {str(k): int(v) for k, v in label_counts.items()}
    out["label_percent"] = {str(k): round(pct(int(v), len(raw_df)), 3) for k, v in label_counts.items()}

    # group balance
    if "group_name" in raw_df.columns:
        grp_counts = raw_df["group_name"].value_counts(dropna=False).to_dict()
        out["group_counts"] = {str(k): int(v) for k, v in grp_counts.items()}
        out["group_percent"] = {str(k): round(pct(int(v), len(raw_df)), 3) for k, v in grp_counts.items()}

    # source/family
    if "source_file" in raw_df.columns:
        out["unique_sources"] = int(raw_df["source_file"].astype(str).nunique())
    if "family" in raw_df.columns:
        fam = raw_df["family"].dropna().astype(str)
        out["unique_families"] = int(fam.nunique()) if len(fam) else 0

    # attack subtypes
    attack_df = raw_df[raw_df["label"] == 1].copy()
    if "group_name" in attack_df.columns:
        flow_only_attacks = attack_df[attack_df["group_name"].isin(FLOW_ONLY_ATTACK_GROUPS)]
        ja4_attacks = attack_df[attack_df["group_name"].isin(JA4_ATTACK_GROUPS)]

        out["attack_rows_total"] = int(len(attack_df))
        out["flow_only_attack_rows"] = int(len(flow_only_attacks))
        out["ja4_attack_rows"] = int(len(ja4_attacks))
        out["flow_only_attack_percent_within_attacks"] = round(pct(len(flow_only_attacks), len(attack_df)), 3)
        out["ja4_attack_percent_within_attacks"] = round(pct(len(ja4_attacks), len(attack_df)), 3)

    # unique safe JA4 tuples among JA4 attack groups
    safe_present = [c for c in SAFE_JA4_COLS if c in model_df.columns]
    if safe_present and "group_name" in raw_df.columns:
        merged = pd.concat([raw_df[["label", "group_name"]].reset_index(drop=True),
                            model_df[safe_present].reset_index(drop=True)], axis=1)
        merged = merged[(merged["label"] == 1) & (merged["group_name"].isin(JA4_ATTACK_GROUPS))].copy()
        if len(merged):
            merged["safe_tuple"] = merged[safe_present].astype(str).agg("|".join, axis=1)
            out["ja4_attack_unique_safe_tuples"] = int(merged["safe_tuple"].nunique())

    return out


def main() -> None:
    args = parse_args()
    base = Path(args.base_dir)

    payload = {}
    for split in ["train", "val", "test"]:
        raw_path = base / f"experiment2_{split}.csv"
        model_path = base / "model_inputs" / split / "dataset_flow_plus_ja4.csv"

        raw_df = pd.read_csv(raw_path)
        model_df = pd.read_csv(model_path)

        payload[split] = summarize_split(raw_df, model_df)

    print(json.dumps(payload, ensure_ascii=False, indent=2))

    if args.out_json:
        out_path = Path(args.out_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
