#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd


RAW_COLUMNS_REQUIRED = [
    "client_ip",
    "server_ip",
    "client_port",
    "server_port",
    "proto",
    "packets_total",
    "packets_c2s",
    "packets_s2c",
    "bytes_cap_total",
    "bytes_cap_c2s",
    "bytes_cap_s2c",
    "bytes_wire_total",
    "bytes_wire_c2s",
    "bytes_wire_s2c",
    "duration_ns",
    "tcp_syn_total",
    "tcp_syn_c2s",
    "tcp_synack_s2c",
    "tcp_ack_total",
    "tcp_fin_total",
    "tcp_rst_total",
    "tcp_psh_total",
    "tls_client_hello_c2s",
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
    "ja4_cipher_suites",
    "ja4_extensions",
    "avg_wirelen_total",
]

RAW_STRING_COLUMNS = [
    "client_ip",
    "server_ip",
    "ja4_legacy_version",
    "ja4_alpn",
    "ja4_cipher_suites",
    "ja4_extensions",
]

RAW_NUMERIC_COLUMNS = [
    "client_port",
    "server_port",
    "proto",
    "packets_total",
    "packets_c2s",
    "packets_s2c",
    "bytes_cap_total",
    "bytes_cap_c2s",
    "bytes_cap_s2c",
    "bytes_wire_total",
    "bytes_wire_c2s",
    "bytes_wire_s2c",
    "duration_ns",
    "tcp_syn_total",
    "tcp_syn_c2s",
    "tcp_synack_s2c",
    "tcp_ack_total",
    "tcp_fin_total",
    "tcp_rst_total",
    "tcp_psh_total",
    "tls_client_hello_c2s",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "avg_wirelen_total",
]

FLOW_ONLY_FEATURES = [
    "proto",
    "packets_total",
    "packets_c2s",
    "packets_s2c",
    "bytes_cap_total",
    "bytes_cap_c2s",
    "bytes_cap_s2c",
    "bytes_wire_total",
    "bytes_wire_c2s",
    "bytes_wire_s2c",
    "duration_ms",
    "tcp_syn_total",
    "tcp_syn_c2s",
    "tcp_synack_s2c",
    "tcp_ack_total",
    "tcp_fin_total",
    "tcp_rst_total",
    "tcp_psh_total",
    "avg_wirelen_total",
    "bytes_ratio_c2s_s2c",
    "packets_ratio_c2s_s2c",
    "pps_total",
    "bps_total",
    "is_tcp",
    "is_udp",
]

FLOW_PLUS_JA4_ADDITIONAL = [
    "tls_client_hello_c2s",
    "ja4_present",
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
]

REPORT_FIELDS = [
    "client_ip",
    "server_ip",
    "client_port",
    "server_port",
    "proto",
    "packets_total",
    "packets_c2s",
    "packets_s2c",
    "bytes_wire_total",
    "bytes_wire_c2s",
    "bytes_wire_s2c",
    "duration_ms",
    "tcp_syn_total",
    "tcp_ack_total",
    "tcp_fin_total",
    "tcp_rst_total",
    "tcp_psh_total",
    "tls_client_hello_c2s",
    "ja4_present",
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
    "ja4_cipher_suites",
    "ja4_extensions",
]

FLOW_PLUS_CATEGORICAL_COLUMNS = [
    "ja4_legacy_version",
    "ja4_alpn",
]

COMMON_BINARY_LABEL_MAP = {
    "0": 0,
    "1": 1,
    "benign": 0,
    "normal": 0,
    "legitimate": 0,
    "anomalous": 1,
    "anomaly": 1,
    "malicious": 1,
    "attack": 1,
    "true": 1,
    "false": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build flow-only, flow+JA4, and report datasets from raw parser CSV."
    )
    parser.add_argument("--input", required=True, help="Path to raw parser CSV")
    parser.add_argument("--outdir", required=True, help="Output directory")
    parser.add_argument(
        "--label-col",
        default=None,
        help="Optional label column in input CSV (for example: label, is_anomalous, target)",
    )
    return parser.parse_args()


def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [str(c).strip().replace("\ufeff", "") for c in out.columns]

    rename_map = {
        "pproto": "proto",
    }
    out = out.rename(columns=rename_map)
    return out


def read_raw_csv(path: Path) -> pd.DataFrame:
    dtype_map = {col: "string" for col in RAW_STRING_COLUMNS}

    df = pd.read_csv(
        path,
        encoding="utf-8-sig",
        dtype=dtype_map,
        keep_default_na=False,
    )
    df = normalize_column_names(df)
    return df


def ensure_columns(df: pd.DataFrame, label_col: Optional[str]) -> None:
    required = set(RAW_COLUMNS_REQUIRED)
    if label_col:
        required.add(label_col)

    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def cast_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    for col in RAW_NUMERIC_COLUMNS:
        out[col] = pd.to_numeric(out[col], errors="coerce")

    return out


def clean_string_value(x: object) -> str:
    if pd.isna(x):
        return ""
    s = str(x).strip()
    if s.lower() in {"nan", "none", "null"}:
        return ""
    return s


def normalize_ja4_legacy_version(series: pd.Series) -> pd.Series:
    def _norm(v: object) -> str:
        s = clean_string_value(v)
        if s in {"", "-"}:
            return "none"

        # Если пришло как "303" или "0303" — приводим к 4-символьной hex-like форме.
        # Не пытаемся интерпретировать десятичные значения, просто сохраняем токен.
        if s.isdigit():
            return s.zfill(4)

        # Если вдруг там hex-строка в другом регистре
        return s.lower()

    return series.apply(_norm).astype("string")


def normalize_ja4_alpn(series: pd.Series) -> pd.Series:
    def _norm(v: object) -> str:
        s = clean_string_value(v)
        if s in {"", "-"}:
            return "none"
        return s.lower()

    return series.apply(_norm).astype("string")


def normalize_text_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    out["client_ip"] = out["client_ip"].apply(clean_string_value).astype("string")
    out["server_ip"] = out["server_ip"].apply(clean_string_value).astype("string")
    out["ja4_cipher_suites"] = out["ja4_cipher_suites"].apply(clean_string_value).astype("string")
    out["ja4_extensions"] = out["ja4_extensions"].apply(clean_string_value).astype("string")

    out["ja4_legacy_version"] = normalize_ja4_legacy_version(out["ja4_legacy_version"])
    out["ja4_alpn"] = normalize_ja4_alpn(out["ja4_alpn"])

    return out


def attach_and_normalize_label(df: pd.DataFrame, label_col: Optional[str]) -> tuple[pd.DataFrame, bool]:
    out = df.copy()

    if not label_col:
        return out, False

    if label_col not in out.columns:
        raise ValueError(f"Label column '{label_col}' not found")

    raw_label = out[label_col]

    if pd.api.types.is_numeric_dtype(raw_label):
        out["label"] = pd.to_numeric(raw_label, errors="coerce")
    else:
        out["label"] = (
            raw_label.astype("string")
            .str.strip()
            .str.lower()
            .map(COMMON_BINARY_LABEL_MAP)
        )

    if out["label"].isna().any():
        bad_values = out.loc[out["label"].isna(), label_col].astype("string").dropna().unique().tolist()
        raise ValueError(
            "Failed to normalize some label values to binary 0/1. "
            f"Unknown values: {bad_values[:20]}"
        )

    out["label"] = out["label"].astype(int)

    if label_col != "label":
        out = out.drop(columns=[label_col])

    unique_labels = sorted(out["label"].unique().tolist())
    if unique_labels not in ([0], [1], [0, 1]):
        raise ValueError(f"Label must be binary after normalization. Got: {unique_labels}")

    return out, True


def normalize_ja4_fields(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    # JA4 считаем присутствующим, если есть ClientHello
    out["tls_client_hello_c2s"] = out["tls_client_hello_c2s"].fillna(0).astype(int)
    out["ja4_present"] = (out["tls_client_hello_c2s"] > 0).astype(int)

    out["ja4_cipher_suites_count"] = pd.to_numeric(out["ja4_cipher_suites_count"], errors="coerce").fillna(0).astype(int)
    out["ja4_extensions_count"] = pd.to_numeric(out["ja4_extensions_count"], errors="coerce").fillna(0).astype(int)
    out["ja4_has_sni"] = pd.to_numeric(out["ja4_has_sni"], errors="coerce").fillna(0).astype(int)

    mask_no_ja4 = out["ja4_present"] == 0
    out.loc[mask_no_ja4, "ja4_legacy_version"] = "none"
    out.loc[mask_no_ja4, "ja4_alpn"] = "none"
    out.loc[mask_no_ja4, "ja4_cipher_suites_count"] = 0
    out.loc[mask_no_ja4, "ja4_extensions_count"] = 0
    out.loc[mask_no_ja4, "ja4_has_sni"] = 0
    out.loc[mask_no_ja4, "ja4_cipher_suites"] = ""
    out.loc[mask_no_ja4, "ja4_extensions"] = ""

    out["ja4_legacy_version"] = out["ja4_legacy_version"].astype("string")
    out["ja4_alpn"] = out["ja4_alpn"].astype("string")
    out["ja4_cipher_suites"] = out["ja4_cipher_suites"].astype("string")
    out["ja4_extensions"] = out["ja4_extensions"].astype("string")

    return out


def fill_numeric_nans(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    numeric_cols = [col for col in RAW_NUMERIC_COLUMNS if col in out.columns]
    out[numeric_cols] = out[numeric_cols].fillna(0)

    integer_like_cols = [
        "client_port",
        "server_port",
        "proto",
        "packets_total",
        "packets_c2s",
        "packets_s2c",
        "bytes_cap_total",
        "bytes_cap_c2s",
        "bytes_cap_s2c",
        "bytes_wire_total",
        "bytes_wire_c2s",
        "bytes_wire_s2c",
        "tcp_syn_total",
        "tcp_syn_c2s",
        "tcp_synack_s2c",
        "tcp_ack_total",
        "tcp_fin_total",
        "tcp_rst_total",
        "tcp_psh_total",
        "tls_client_hello_c2s",
        "ja4_cipher_suites_count",
        "ja4_extensions_count",
        "ja4_has_sni",
    ]

    for col in integer_like_cols:
        if col in out.columns:
            out[col] = out[col].astype(np.int64)

    if "duration_ns" in out.columns:
        out["duration_ns"] = out["duration_ns"].astype(float)
    if "avg_wirelen_total" in out.columns:
        out["avg_wirelen_total"] = out["avg_wirelen_total"].astype(float)

    return out


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    eps = 1e-9

    out["duration_ms"] = out["duration_ns"] / 1_000_000.0
    out["duration_sec"] = out["duration_ns"] / 1_000_000_000.0

    out["bytes_ratio_c2s_s2c"] = out["bytes_wire_c2s"] / np.maximum(out["bytes_wire_s2c"], 1)
    out["packets_ratio_c2s_s2c"] = out["packets_c2s"] / np.maximum(out["packets_s2c"], 1)

    out["pps_total"] = out["packets_total"] / np.maximum(out["duration_sec"], eps)
    out["bps_total"] = out["bytes_wire_total"] / np.maximum(out["duration_sec"], eps)

    out["is_tcp"] = (out["proto"] == 6).astype(int)
    out["is_udp"] = (out["proto"] == 17).astype(int)

    derived_float_cols = [
        "duration_ms",
        "duration_sec",
        "bytes_ratio_c2s_s2c",
        "packets_ratio_c2s_s2c",
        "pps_total",
        "bps_total",
    ]

    out = out.replace([np.inf, -np.inf], np.nan)
    out[derived_float_cols] = out[derived_float_cols].fillna(0.0)

    return out


def validate_output(df: pd.DataFrame, has_label: bool) -> None:
    required_model_cols = FLOW_ONLY_FEATURES + FLOW_PLUS_JA4_ADDITIONAL
    missing = [col for col in required_model_cols if col not in df.columns]
    if missing:
        raise ValueError(f"Missing transformed columns: {missing}")

    model_cols = required_model_cols.copy()
    if has_label:
        model_cols.append("label")

    bad_nan = df[model_cols].isna().sum()
    bad_nan = bad_nan[bad_nan > 0]
    if not bad_nan.empty:
        raise ValueError(f"NaN values remain in output columns: {bad_nan.to_dict()}")


def build_output_frames(df: pd.DataFrame, has_label: bool) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    flow_only_cols = FLOW_ONLY_FEATURES.copy()
    flow_plus_cols = FLOW_ONLY_FEATURES + FLOW_PLUS_JA4_ADDITIONAL
    report_cols = REPORT_FIELDS.copy()

    if has_label:
        flow_only_cols.append("label")
        flow_plus_cols.append("label")
        report_cols.append("label")

    flow_only = df[flow_only_cols].copy()
    flow_plus = df[flow_plus_cols].copy()
    report_view = df[report_cols].copy()

    return flow_only, flow_plus, report_view


def save_schema(outdir: Path, has_label: bool) -> None:
    schema = {
        "flow_only_features": FLOW_ONLY_FEATURES,
        "flow_plus_ja4_features": FLOW_ONLY_FEATURES + FLOW_PLUS_JA4_ADDITIONAL,
        "flow_plus_categorical_columns": FLOW_PLUS_CATEGORICAL_COLUMNS,
        "report_fields": REPORT_FIELDS + (["label"] if has_label else []),
        "label_column": "label" if has_label else None,
        "notes": {
            "one_row_equals": "one bidirectional flow",
            "ip_and_ports_not_for_model": True,
            "ja4_lists_not_for_model": True,
            "ja4_placeholders": {
                "ja4_legacy_version": "none",
                "ja4_alpn": "none",
                "ja4_cipher_suites_count": 0,
                "ja4_extensions_count": 0,
                "ja4_has_sni": 0,
            },
        },
    }

    path = outdir / "feature_schema.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(schema, f, ensure_ascii=False, indent=2)


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = read_raw_csv(input_path)
    ensure_columns(df, args.label_col)

    df = cast_numeric_columns(df)
    df = normalize_text_columns(df)
    df, has_label = attach_and_normalize_label(df, args.label_col)
    df = fill_numeric_nans(df)
    df = normalize_ja4_fields(df)
    df = add_derived_features(df)

    validate_output(df, has_label)

    flow_only, flow_plus, report_view = build_output_frames(df, has_label)

    flow_only_path = outdir / "dataset_flow_only.csv"
    flow_plus_path = outdir / "dataset_flow_plus_ja4.csv"
    report_path = outdir / "report_view.csv"

    flow_only.to_csv(flow_only_path, index=False)
    flow_plus.to_csv(flow_plus_path, index=False)
    report_view.to_csv(report_path, index=False)
    save_schema(outdir, has_label)

    print(f"[OK] wrote: {flow_only_path}")
    print(f"[OK] wrote: {flow_plus_path}")
    print(f"[OK] wrote: {report_path}")
    print(f"[OK] wrote: {outdir / 'feature_schema.json'}")
    print()
    print("Shapes:")
    print(f"  flow_only     : {flow_only.shape}")
    print(f"  flow_plus_ja4 : {flow_plus.shape}")
    print(f"  report_view   : {report_view.shape}")
    print()
    if "ja4_present" in flow_plus.columns:
        print(f"JA4 present rows: {int(flow_plus['ja4_present'].sum())} / {len(flow_plus)}")
    if has_label:
        print("Label distribution:")
        print(flow_plus["label"].value_counts(dropna=False).sort_index().to_dict())


if __name__ == "__main__":
    main()
