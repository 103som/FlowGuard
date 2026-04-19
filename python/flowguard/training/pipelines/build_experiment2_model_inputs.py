#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pandas as pd


EXPLICIT_DROP = {
    "label",
    "binary_label",
    "label_raw",
    "group_name",
    "source_group",
    "source_file",
    "source_dataset",
    "source_file_name",
    "family",
    "source_day",
    "client_ip",
    "server_ip",
    "src_ip",
    "dst_ip",
    "client_port",
    "server_port",
    "src_port",
    "dst_port",
    "timestamp",
    "flow_row_id",
    "flow_start_ns",
    "flow_end_ns",
    "flow_start_rel_ns",
    "flow_end_rel_ns",
    "flow_sort_rel_ns",
    "start_diff_ns",
    "end_diff_ns",
    "duration_threshold_ns",
    "matched_time_anchor",
    "packet_c2s_diff",
    "packet_s2c_diff",
    "ja4",
    "ja4_cipher_suites",
    "ja4_extensions",
}

DROP_PATTERNS = [
    r"^label_.*",
    r".*_label$",
    r"^group_ord_diff$",
    r"^time_diff_ns$",
    r"^duration_diff_ns$",
    r"^packet_dir_diff.*",
    r"^match_.*",
    r"^candidate_.*",
    r"^orientation$",
    r"^time_anchor$",
]

JA4_SAFE_COLS = {
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
    "tls_client_hello_c2s",
}

REPORT_KEEP = ["label", "group_name", "source_group", "source_file", "family"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build model inputs for Experiment 2")
    p.add_argument("--input", required=True)
    p.add_argument("--outdir", required=True)
    p.add_argument("--schema-json", default=None)
    return p.parse_args()


def should_drop(col: str) -> bool:
    if col in EXPLICIT_DROP:
        return True
    for pat in DROP_PATTERNS:
        if re.match(pat, col):
            return True
    return False


def align_to_schema(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    out = df.copy()
    for col in feature_cols:
        if col not in out.columns:
            out[col] = pd.NA
    extra_cols = [c for c in out.columns if c not in feature_cols]
    if extra_cols:
        out = out.drop(columns=extra_cols)
    return out[feature_cols]


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path)

    if "label" not in df.columns:
        if "binary_label" in df.columns:
            df["label"] = pd.to_numeric(df["binary_label"], errors="raise").astype(int)
        else:
            raise ValueError("No label/binary_label column found")

    label = pd.to_numeric(df["label"], errors="raise").astype(int)
    report_cols = [c for c in REPORT_KEEP if c in df.columns]
    report_view = df[report_cols].copy()

    if args.schema_json:
        with open(args.schema_json, "r", encoding="utf-8") as f:
            schema = json.load(f)

        flow_only_feature_cols = schema["flow_only_features"]
        flow_plus_ja4_feature_cols = schema["flow_plus_ja4_features"]

        base_feature_cols = sorted(set(flow_plus_ja4_feature_cols) | set(flow_only_feature_cols))
        base_df = df.drop(columns=["label"], errors="ignore").copy()
        base_df = align_to_schema(base_df, base_feature_cols)

        X_flow_only = align_to_schema(base_df, flow_only_feature_cols)
        X_flow_plus_ja4 = align_to_schema(base_df, flow_plus_ja4_feature_cols)

        dropped_cols = sorted(
            [c for c in df.columns if c not in report_cols + ["label"] and c not in base_feature_cols]
        )
    else:
        dropped_cols = [c for c in df.columns if should_drop(c)]
        feature_cols = [c for c in df.columns if c not in dropped_cols and c != "label"]
        X_full = df[feature_cols].copy()
        flow_only_cols = [c for c in X_full.columns if c not in JA4_SAFE_COLS]
        X_flow_only = X_full[flow_only_cols].copy()
        X_flow_plus_ja4 = X_full.copy()

    flow_only = pd.concat([label.rename("label"), X_flow_only], axis=1)
    flow_plus_ja4 = pd.concat([label.rename("label"), X_flow_plus_ja4], axis=1)
    report_view = pd.concat([label.rename("label"), report_view.drop(columns=["label"], errors="ignore")], axis=1)

    flow_only.to_csv(outdir / "dataset_flow_only.csv", index=False)
    flow_plus_ja4.to_csv(outdir / "dataset_flow_plus_ja4.csv", index=False)
    report_view.to_csv(outdir / "report_view.csv", index=False)

    schema = {
        "input_file": str(input_path),
        "rows": int(len(df)),
        "flow_only_features": [c for c in flow_only.columns if c != "label"],
        "flow_plus_ja4_features": [c for c in flow_plus_ja4.columns if c != "label"],
        "dropped_columns": sorted(dropped_cols),
        "ja4_columns_included": sorted([c for c in X_flow_plus_ja4.columns if c in JA4_SAFE_COLS]),
    }

    with (outdir / "feature_schema.json").open("w", encoding="utf-8") as f:
        json.dump(schema, f, ensure_ascii=False, indent=2)

    print(f"[OK] wrote: {outdir / 'dataset_flow_only.csv'}")
    print(f"[OK] wrote: {outdir / 'dataset_flow_plus_ja4.csv'}")
    print(f"[OK] wrote: {outdir / 'report_view.csv'}")
    print(f"[OK] wrote: {outdir / 'feature_schema.json'}")
    print()
    print(f"Rows: {len(df)}")
    print(f"flow_only features     : {flow_only.shape[1] - 1}")
    print(f"flow_plus_ja4 features : {flow_plus_ja4.shape[1] - 1}")


if __name__ == "__main__":
    main()
