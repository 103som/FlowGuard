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
    p = argparse.ArgumentParser(description="Report uniqueness of attack subsets")
    p.add_argument("--raw-csv", required=True, help="experiment2_train.csv / val / test")
    p.add_argument("--model-csv", required=True, help="dataset_flow_plus_ja4.csv for same split")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    raw_df = pd.read_csv(args.raw_csv)
    model_df = pd.read_csv(args.model_csv)

    merged = pd.concat([raw_df.reset_index(drop=True), model_df[SAFE_JA4_COLS].reset_index(drop=True)], axis=1)

    attacks = merged[merged["label"] == 1].copy()
    flow_only = attacks[attacks["group_name"].isin(FLOW_ONLY_ATTACK_GROUPS)].copy()
    ja4 = attacks[attacks["group_name"].isin(JA4_ATTACK_GROUPS)].copy()

    if len(ja4):
        ja4["safe_tuple"] = ja4[SAFE_JA4_COLS].astype(str).agg("|".join, axis=1)

    result = {
        "attack_rows_total": int(len(attacks)),
        "flow_only_attack_rows": int(len(flow_only)),
        "ja4_attack_rows": int(len(ja4)),
        "flow_only_unique_sources": int(flow_only["source_file"].astype(str).nunique()) if "source_file" in flow_only.columns else None,
        "ja4_unique_sources": int(ja4["source_file"].astype(str).nunique()) if "source_file" in ja4.columns else None,
        "flow_only_unique_families": int(flow_only["family"].dropna().astype(str).nunique()) if "family" in flow_only.columns else None,
        "ja4_unique_families": int(ja4["family"].dropna().astype(str).nunique()) if "family" in ja4.columns else None,
        "ja4_unique_safe_tuples": int(ja4["safe_tuple"].nunique()) if "safe_tuple" in ja4.columns else None,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
