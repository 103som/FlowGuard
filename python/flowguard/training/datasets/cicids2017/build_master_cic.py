#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import json
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd


FLOW_REQUIRED = [
    "client_ip",
    "server_ip",
    "client_port",
    "server_port",
    "proto",
    "packets_total",
    "packets_c2s",
    "packets_s2c",
    "duration_ns",
    "tls_client_hello_c2s",
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
]

FLOW_START_CANDIDATES = [
    "first_ts_ns",
    "flow_first_ts_ns",
    "start_ts_ns",
    "flow_start_ns",
    "first_seen_ns",
]

FLOW_END_CANDIDATES = [
    "last_ts_ns",
    "flow_last_ts_ns",
    "end_ts_ns",
    "flow_end_ns",
    "last_seen_ns",
]

LABEL_REQUIRED = [
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Label",
]

EXACT_KEY_COLS = [
    "match_src_ip",
    "match_src_port",
    "match_dst_ip",
    "match_dst_port",
    "proto",
    "match_packets_c2s",
    "match_packets_s2c",
]

RELAX_KEY_COLS = [
    "match_src_ip",
    "match_src_port",
    "match_dst_ip",
    "match_dst_port",
    "proto",
    "match_packets_total",
]

EMPTY_CANDIDATE_COLS = [
    "flow_row_id",
    "label_row_id",
    "match_orientation",
    "match_stage",
    "stage_rank",
    "orientation_rank",
    "duration_diff_ns",
    "duration_threshold_ns",
    "packet_c2s_diff",
    "packet_s2c_diff",
    "packet_dir_diff_total",
    "group_ord_diff",
    "start_diff_ns",
    "end_diff_ns",
    "time_diff_ns",
    "matched_time_anchor",
    "score_has_time",
    "score_time_diff_ns",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Memory-friendly CIC join. Keeps exact packet-direction matching as the main path, "
            "adds relaxed recovery for unmatched rows, and avoids storing giant all-candidate tables."
        )
    )
    parser.add_argument("--flows", required=True, help="Path to parser output CSV (flows.csv)")
    parser.add_argument("--labels", required=True, help="Path to CIC labels parquet")
    parser.add_argument("--outdir", required=True, help="Output directory")
    parser.add_argument(
        "--max-duration-diff-ns",
        type=int,
        default=10_000_000,
        help="Absolute duration diff threshold in ns (default: 10ms = 10_000_000 ns)",
    )
    parser.add_argument(
        "--max-duration-diff-ratio",
        type=float,
        default=0.20,
        help="Relative duration diff threshold (default: 0.20 = 20%%)",
    )
    parser.add_argument(
        "--relaxed-max-per-dir-packet-diff",
        type=int,
        default=1,
        help="Stage-2 relaxed pass: max absolute packet diff per direction (default: 1)",
    )
    parser.add_argument(
        "--relaxed-max-total-packet-diff",
        type=int,
        default=2,
        help="Stage-2 relaxed pass: max sum of directional packet diffs (default: 2)",
    )
    parser.add_argument(
        "--save-debug-csv",
        action="store_true",
        help="Save compact candidate CSVs. Disabled by default to avoid high memory / disk usage.",
    )
    return parser.parse_args()


def ensure_columns(df: pd.DataFrame, required: list[str], name: str) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{name}: missing required columns: {missing}")


def norm_ip(s: pd.Series) -> pd.Series:
    return s.astype("string").str.strip()


def norm_int(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce").fillna(0).astype("int64")


def find_first_present(columns: Iterable[str], candidates: Iterable[str]) -> str | None:
    cols = set(columns)
    for c in candidates:
        if c in cols:
            return c
    return None


def parse_label_timestamp(raw: pd.Series) -> pd.Series:
    s = raw.astype("string").str.strip()

    formats = [
        "%d/%m/%Y %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ]

    parsed = pd.Series(pd.NaT, index=s.index, dtype="datetime64[ns]")
    for fmt in formats:
        mask = parsed.isna()
        if not mask.any():
            break
        parsed.loc[mask] = pd.to_datetime(s.loc[mask], format=fmt, errors="coerce")

    mask = parsed.isna()
    if mask.any():
        parsed.loc[mask] = pd.to_datetime(s.loc[mask], errors="coerce", dayfirst=True)

    return parsed


def add_group_order(
    df: pd.DataFrame,
    group_cols: list[str],
    time_col: str,
    id_col: str,
    out_col: str,
) -> pd.DataFrame:
    work = df[group_cols + [time_col, id_col]].copy()
    work["_time_sort"] = work[time_col].fillna(np.inf)
    work = work.sort_values(group_cols + ["_time_sort", id_col]).copy()
    work[out_col] = work.groupby(group_cols).cumcount().astype("int64")
    return df.merge(work[[id_col, out_col]], on=id_col, how="left")


def load_flows(path: Path) -> tuple[pd.DataFrame, pd.DataFrame, str | None, str | None]:
    flows = pd.read_csv(path, low_memory=False)
    ensure_columns(flows, FLOW_REQUIRED, "flows.csv")

    flows = flows.copy()
    flows["flow_row_id"] = np.arange(len(flows), dtype=np.int64)

    flows["client_ip"] = norm_ip(flows["client_ip"])
    flows["server_ip"] = norm_ip(flows["server_ip"])

    int_cols = [
        "client_port",
        "server_port",
        "proto",
        "packets_total",
        "packets_c2s",
        "packets_s2c",
        "tls_client_hello_c2s",
        "ja4_cipher_suites_count",
        "ja4_extensions_count",
        "ja4_has_sni",
    ]
    for c in int_cols:
        flows[c] = norm_int(flows[c])

    flows["duration_ns"] = pd.to_numeric(flows["duration_ns"], errors="coerce").fillna(0).astype("int64")
    flows["ja4_legacy_version"] = flows["ja4_legacy_version"].astype("string").str.strip()
    flows["ja4_alpn"] = flows["ja4_alpn"].astype("string").str.strip()

    flow_start_col = find_first_present(flows.columns, FLOW_START_CANDIDATES)
    flow_end_col = find_first_present(flows.columns, FLOW_END_CANDIDATES)

    flows["flow_start_ns"] = pd.Series(np.nan, index=flows.index, dtype="float64")
    flows["flow_end_ns"] = pd.Series(np.nan, index=flows.index, dtype="float64")
    flows["flow_start_rel_ns"] = pd.Series(np.nan, index=flows.index, dtype="float64")
    flows["flow_end_rel_ns"] = pd.Series(np.nan, index=flows.index, dtype="float64")

    if flow_start_col is not None:
        flows[flow_start_col] = pd.to_numeric(flows[flow_start_col], errors="coerce")
        valid = flows[flow_start_col].notna()
        if valid.any():
            flows.loc[valid, "flow_start_ns"] = flows.loc[valid, flow_start_col].astype("float64")

    if flow_end_col is not None:
        flows[flow_end_col] = pd.to_numeric(flows[flow_end_col], errors="coerce")
        valid = flows[flow_end_col].notna()
        if valid.any():
            flows.loc[valid, "flow_end_ns"] = flows.loc[valid, flow_end_col].astype("float64")

    need_end = flows["flow_end_ns"].isna() & flows["flow_start_ns"].notna()
    if need_end.any():
        flows.loc[need_end, "flow_end_ns"] = (
            flows.loc[need_end, "flow_start_ns"] + flows.loc[need_end, "duration_ns"].astype("float64")
        )

    finite_flow_times = pd.concat([flows["flow_start_ns"], flows["flow_end_ns"]], ignore_index=True).dropna()
    if not finite_flow_times.empty:
        flow_base = float(finite_flow_times.min())
        valid_start = flows["flow_start_ns"].notna()
        valid_end = flows["flow_end_ns"].notna()
        flows.loc[valid_start, "flow_start_rel_ns"] = flows.loc[valid_start, "flow_start_ns"] - flow_base
        flows.loc[valid_end, "flow_end_rel_ns"] = flows.loc[valid_end, "flow_end_ns"] - flow_base

    flows["flow_sort_rel_ns"] = flows["flow_start_rel_ns"]
    missing_sort = flows["flow_sort_rel_ns"].isna()
    if missing_sort.any():
        flows.loc[missing_sort, "flow_sort_rel_ns"] = flows.loc[missing_sort, "flow_end_rel_ns"]
    missing_sort = flows["flow_sort_rel_ns"].isna()
    if missing_sort.any():
        flows.loc[missing_sort, "flow_sort_rel_ns"] = flows.loc[missing_sort, "flow_row_id"].astype("float64")

    # Compact match view only with the columns needed during joins.
    match_view = pd.DataFrame({
        "flow_row_id": flows["flow_row_id"],
        "match_src_ip": flows["client_ip"],
        "match_src_port": flows["client_port"],
        "match_dst_ip": flows["server_ip"],
        "match_dst_port": flows["server_port"],
        "proto": flows["proto"],
        "match_packets_c2s": flows["packets_c2s"],
        "match_packets_s2c": flows["packets_s2c"],
        "match_packets_total": flows["packets_total"],
        "duration_ns": flows["duration_ns"],
        "flow_start_rel_ns": flows["flow_start_rel_ns"],
        "flow_end_rel_ns": flows["flow_end_rel_ns"],
        "flow_sort_rel_ns": flows["flow_sort_rel_ns"],
    })

    match_view = add_group_order(match_view, EXACT_KEY_COLS, "flow_sort_rel_ns", "flow_row_id", "exact_group_ord")
    match_view = add_group_order(match_view, RELAX_KEY_COLS, "flow_sort_rel_ns", "flow_row_id", "relax_group_ord")

    return flows, match_view, flow_start_col, flow_end_col


def load_labels(path: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    labels = pd.read_parquet(path)
    ensure_columns(labels, LABEL_REQUIRED, "labels parquet")

    labels = labels.copy()
    labels["label_row_id"] = np.arange(len(labels), dtype=np.int64)

    labels["src_ip"] = norm_ip(labels["Source IP"])
    labels["dst_ip"] = norm_ip(labels["Destination IP"])
    labels["src_port"] = norm_int(labels["Source Port"])
    labels["dst_port"] = norm_int(labels["Destination Port"])
    labels["proto"] = norm_int(labels["Protocol"])

    labels["timestamp"] = parse_label_timestamp(labels["Timestamp"])

    valid_ts = labels["timestamp"].notna()
    labels["label_time_ns"] = pd.Series(np.nan, index=labels.index, dtype="float64")
    labels["label_time_rel_ns"] = pd.Series(np.nan, index=labels.index, dtype="float64")
    if valid_ts.any():
        labels.loc[valid_ts, "label_time_ns"] = labels.loc[valid_ts, "timestamp"].astype("int64").astype("float64")
        base = float(labels.loc[valid_ts, "label_time_ns"].min())
        labels.loc[valid_ts, "label_time_rel_ns"] = labels.loc[valid_ts, "label_time_ns"] - base

    labels["flow_duration_label"] = pd.to_numeric(labels["Flow Duration"], errors="coerce").fillna(0).astype("int64")
    labels["label_duration_ns"] = labels["flow_duration_label"] * 1000
    labels["packets_fwd_label"] = norm_int(labels["Total Fwd Packets"])
    labels["packets_bwd_label"] = norm_int(labels["Total Backward Packets"])
    labels["packets_total_label"] = labels["packets_fwd_label"] + labels["packets_bwd_label"]

    labels["label_raw"] = labels["Label"].astype("string").str.strip()
    labels["label"] = (labels["label_raw"].str.upper() != "BENIGN").astype("int64")

    labels["label_sort_rel_ns"] = labels["label_time_rel_ns"]
    missing_sort = labels["label_sort_rel_ns"].isna()
    if missing_sort.any():
        labels.loc[missing_sort, "label_sort_rel_ns"] = labels.loc[missing_sort, "label_row_id"].astype("float64")

    label_info = labels[[
        "label_row_id",
        "timestamp",
        "flow_duration_label",
        "label_duration_ns",
        "packets_fwd_label",
        "packets_bwd_label",
        "packets_total_label",
        "label_raw",
        "label",
    ]].copy()

    labels_direct = build_label_view(labels, "direct")
    labels_reverse = build_label_view(labels, "reverse")
    return label_info, labels_direct, labels_reverse


def build_label_view(labels: pd.DataFrame, orientation: str) -> pd.DataFrame:
    if orientation == "direct":
        match_src_ip = labels["src_ip"]
        match_src_port = labels["src_port"]
        match_dst_ip = labels["dst_ip"]
        match_dst_port = labels["dst_port"]
        match_packets_c2s = labels["packets_fwd_label"]
        match_packets_s2c = labels["packets_bwd_label"]
        orientation_rank = 0
    elif orientation == "reverse":
        match_src_ip = labels["dst_ip"]
        match_src_port = labels["dst_port"]
        match_dst_ip = labels["src_ip"]
        match_dst_port = labels["src_port"]
        match_packets_c2s = labels["packets_bwd_label"]
        match_packets_s2c = labels["packets_fwd_label"]
        orientation_rank = 1
    else:
        raise ValueError(f"Unknown orientation: {orientation}")

    out = pd.DataFrame({
        "label_row_id": labels["label_row_id"],
        "match_src_ip": match_src_ip,
        "match_src_port": match_src_port,
        "match_dst_ip": match_dst_ip,
        "match_dst_port": match_dst_port,
        "proto": labels["proto"],
        "match_packets_c2s": match_packets_c2s,
        "match_packets_s2c": match_packets_s2c,
        "match_packets_total": labels["packets_total_label"],
        "label_match_packets_c2s": match_packets_c2s,
        "label_match_packets_s2c": match_packets_s2c,
        "label_match_packets_total": labels["packets_total_label"],
        "label_time_rel_ns": labels["label_time_rel_ns"],
        "label_sort_rel_ns": labels["label_sort_rel_ns"],
        "label_duration_ns": labels["label_duration_ns"],
        "match_orientation": orientation,
        "orientation_rank": orientation_rank,
    })

    out = add_group_order(out, EXACT_KEY_COLS, "label_sort_rel_ns", "label_row_id", "label_exact_group_ord")
    out = add_group_order(out, RELAX_KEY_COLS, "label_sort_rel_ns", "label_row_id", "label_relax_group_ord")
    return out


def build_time_columns(merged: pd.DataFrame) -> pd.DataFrame:
    have_label_time = merged["label_time_rel_ns"].notna()
    have_start = merged["flow_start_rel_ns"].notna()
    have_end = merged["flow_end_rel_ns"].notna()

    merged["start_diff_ns"] = np.nan
    mask = have_label_time & have_start
    merged.loc[mask, "start_diff_ns"] = (
        merged.loc[mask, "flow_start_rel_ns"] - merged.loc[mask, "label_time_rel_ns"]
    ).abs()

    merged["end_diff_ns"] = np.nan
    mask = have_label_time & have_end
    merged.loc[mask, "end_diff_ns"] = (
        merged.loc[mask, "flow_end_rel_ns"] - merged.loc[mask, "label_time_rel_ns"]
    ).abs()

    start_vals = merged["start_diff_ns"].to_numpy(dtype="float64")
    end_vals = merged["end_diff_ns"].to_numpy(dtype="float64")
    stack = np.vstack([start_vals, end_vals])
    with np.errstate(all="ignore"):
        time_diff = np.nanmin(stack, axis=0)
    time_diff[np.isnan(stack).all(axis=0)] = np.nan
    merged["time_diff_ns"] = time_diff

    merged["matched_time_anchor"] = pd.Series(pd.NA, index=merged.index, dtype="string")
    has_any_time = merged["time_diff_ns"].notna()
    prefer_start = has_any_time & (
        merged["start_diff_ns"].notna() &
        (merged["end_diff_ns"].isna() | (merged["start_diff_ns"] <= merged["end_diff_ns"]))
    )
    prefer_end = has_any_time & ~prefer_start
    merged.loc[prefer_start, "matched_time_anchor"] = "start"
    merged.loc[prefer_end, "matched_time_anchor"] = "end"

    merged["score_has_time"] = has_any_time.astype("int64")
    merged["score_time_diff_ns"] = np.where(
        merged["time_diff_ns"].notna(),
        merged["time_diff_ns"],
        float(np.iinfo(np.int64).max),
    )
    return merged


def empty_candidates() -> pd.DataFrame:
    return pd.DataFrame(columns=EMPTY_CANDIDATE_COLS)


def build_stage_candidates(
    flow_view: pd.DataFrame,
    labels_view: pd.DataFrame,
    key_cols: list[str],
    flow_group_ord_col: str,
    label_group_ord_col: str,
    stage_name: str,
    stage_rank: int,
    max_duration_diff_ns: int,
    max_duration_diff_ratio: float,
    relaxed_max_per_dir_packet_diff: int = 0,
    relaxed_max_total_packet_diff: int = 0,
) -> tuple[pd.DataFrame, int, int]:
    label_cols = list(dict.fromkeys(
        key_cols + [
            "label_row_id",
            "label_time_rel_ns",
            "label_duration_ns",
            "label_match_packets_c2s",
            "label_match_packets_s2c",
            "label_match_packets_total",
            "match_orientation",
            "orientation_rank",
            label_group_ord_col,
        ]
    ))

    merged = flow_view.merge(
        labels_view[label_cols],
        on=key_cols,
        how="inner",
        suffixes=("", "_labelview"),
    )
    total_candidates = int(len(merged))
    if merged.empty:
        return empty_candidates(), total_candidates, 0

    merged["duration_diff_ns"] = (merged["duration_ns"] - merged["label_duration_ns"]).abs()
    merged["duration_scale_ns"] = np.maximum(merged["duration_ns"], merged["label_duration_ns"])
    merged["duration_threshold_ns"] = np.maximum(
        max_duration_diff_ns,
        (merged["duration_scale_ns"] * max_duration_diff_ratio).astype("int64"),
    )

    merged = build_time_columns(merged)
    merged["group_ord_diff"] = (
        merged[flow_group_ord_col] - merged[label_group_ord_col]
    ).abs().astype("int64")

    if stage_name == "exact":
        merged["packet_c2s_diff"] = 0
        merged["packet_s2c_diff"] = 0
        merged["packet_dir_diff_total"] = 0
        packet_ok = pd.Series(True, index=merged.index)
    else:
        merged["packet_c2s_diff"] = (
            merged["match_packets_c2s"] - merged["label_match_packets_c2s"]
        ).abs().astype("int64")
        merged["packet_s2c_diff"] = (
            merged["match_packets_s2c"] - merged["label_match_packets_s2c"]
        ).abs().astype("int64")
        merged["packet_dir_diff_total"] = (
            merged["packet_c2s_diff"] + merged["packet_s2c_diff"]
        ).astype("int64")
        packet_ok = (
            (merged["packet_c2s_diff"] <= relaxed_max_per_dir_packet_diff) &
            (merged["packet_s2c_diff"] <= relaxed_max_per_dir_packet_diff) &
            (merged["packet_dir_diff_total"] <= relaxed_max_total_packet_diff)
        )

    duration_ok = merged["duration_diff_ns"] <= merged["duration_threshold_ns"]
    candidates_ok = merged.loc[duration_ok & packet_ok, [
        "flow_row_id",
        "label_row_id",
        "match_orientation",
        "orientation_rank",
        "duration_diff_ns",
        "duration_threshold_ns",
        "packet_c2s_diff",
        "packet_s2c_diff",
        "packet_dir_diff_total",
        "group_ord_diff",
        "start_diff_ns",
        "end_diff_ns",
        "time_diff_ns",
        "matched_time_anchor",
        "score_has_time",
        "score_time_diff_ns",
    ]].copy()

    candidates_ok["match_stage"] = stage_name
    candidates_ok["stage_rank"] = stage_rank
    ok_candidates = int(len(candidates_ok))

    del merged
    gc.collect()
    return candidates_ok, total_candidates, ok_candidates


def select_greedy_best(candidates: pd.DataFrame) -> pd.DataFrame:
    if candidates.empty:
        return candidates.copy()

    ranked = candidates.sort_values(
        by=[
            "stage_rank",
            "duration_diff_ns",
            "group_ord_diff",
            "score_has_time",
            "score_time_diff_ns",
            "packet_dir_diff_total",
            "orientation_rank",
            "flow_row_id",
            "label_row_id",
        ],
        ascending=[True, True, True, False, True, True, True, True, True],
    ).reset_index(drop=True)

    used_flows: set[int] = set()
    used_labels: set[int] = set()
    keep_idx: list[int] = []

    for i, row in ranked.iterrows():
        fr = int(row["flow_row_id"])
        lr = int(row["label_row_id"])
        if fr in used_flows or lr in used_labels:
            continue
        used_flows.add(fr)
        used_labels.add(lr)
        keep_idx.append(i)

    return ranked.loc[keep_idx].copy()


def save_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False)


def stat_from_non_null(series: pd.Series, kind: str):
    valid = series.dropna()
    if valid.empty:
        return None
    if kind == "min":
        return int(valid.min())
    if kind == "median":
        return float(valid.median())
    if kind == "p95":
        return float(valid.quantile(0.95))
    if kind == "max":
        return int(valid.max())
    raise ValueError(kind)


def build_master(
    matched: pd.DataFrame,
    flows: pd.DataFrame,
    label_info: pd.DataFrame,
) -> pd.DataFrame:
    flow_cols = list(flows.columns)
    label_cols = [
        "label_row_id",
        "timestamp",
        "flow_duration_label",
        "label_duration_ns",
        "packets_fwd_label",
        "packets_bwd_label",
        "packets_total_label",
        "label_raw",
        "label",
    ]

    keep_cols = flow_cols + [
        "label",
        "label_raw",
        "timestamp",
        "flow_duration_label",
        "label_duration_ns",
        "packets_fwd_label",
        "packets_bwd_label",
        "packets_total_label",
        "match_orientation",
        "match_stage",
        "label_row_id",
        "duration_diff_ns",
        "duration_threshold_ns",
        "packet_c2s_diff",
        "packet_s2c_diff",
        "packet_dir_diff_total",
        "group_ord_diff",
        "start_diff_ns",
        "end_diff_ns",
        "time_diff_ns",
        "matched_time_anchor",
    ]

    if matched.empty:
        return pd.DataFrame(columns=keep_cols)

    master = matched.merge(flows, on="flow_row_id", how="left")
    master = master.merge(label_info[label_cols], on="label_row_id", how="left")
    return master[keep_cols].copy()


def write_placeholder_csv(path: Path) -> None:
    pd.DataFrame().to_csv(path, index=False)


def main() -> None:
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    flows, flow_match_view, flow_start_col, flow_end_col = load_flows(Path(args.flows))
    label_info, labels_direct, labels_reverse = load_labels(Path(args.labels))

    # ---- exact stage
    exact_direct_ok, exact_direct_total, exact_direct_ok_count = build_stage_candidates(
        flow_view=flow_match_view,
        labels_view=labels_direct,
        key_cols=EXACT_KEY_COLS,
        flow_group_ord_col="exact_group_ord",
        label_group_ord_col="label_exact_group_ord",
        stage_name="exact",
        stage_rank=0,
        max_duration_diff_ns=args.max_duration_diff_ns,
        max_duration_diff_ratio=args.max_duration_diff_ratio,
    )
    exact_reverse_ok, exact_reverse_total, exact_reverse_ok_count = build_stage_candidates(
        flow_view=flow_match_view,
        labels_view=labels_reverse,
        key_cols=EXACT_KEY_COLS,
        flow_group_ord_col="exact_group_ord",
        label_group_ord_col="label_exact_group_ord",
        stage_name="exact",
        stage_rank=0,
        max_duration_diff_ns=args.max_duration_diff_ns,
        max_duration_diff_ratio=args.max_duration_diff_ratio,
    )

    exact_all_ok = pd.concat([exact_direct_ok, exact_reverse_ok], ignore_index=True)
    matched_exact = select_greedy_best(exact_all_ok)
    matched_exact_flow_ids = set(matched_exact["flow_row_id"].astype(int).tolist()) if not matched_exact.empty else set()
    matched_exact_label_ids = set(matched_exact["label_row_id"].astype(int).tolist()) if not matched_exact.empty else set()

    ambiguous_direct_flow_rows = int(exact_direct_ok.groupby("flow_row_id").size().gt(1).sum()) if not exact_direct_ok.empty else 0
    ambiguous_reverse_flow_rows = int(exact_reverse_ok.groupby("flow_row_id").size().gt(1).sum()) if not exact_reverse_ok.empty else 0

    # ---- relaxed stage only on unmatched flows and unused labels
    unmatched_after_exact = flow_match_view[~flow_match_view["flow_row_id"].isin(matched_exact_flow_ids)].copy()
    labels_direct_after_exact = labels_direct[~labels_direct["label_row_id"].isin(matched_exact_label_ids)].copy()
    labels_reverse_after_exact = labels_reverse[~labels_reverse["label_row_id"].isin(matched_exact_label_ids)].copy()

    del exact_all_ok
    gc.collect()

    relax_direct_ok, relax_direct_total, relax_direct_ok_count = build_stage_candidates(
        flow_view=unmatched_after_exact,
        labels_view=labels_direct_after_exact,
        key_cols=RELAX_KEY_COLS,
        flow_group_ord_col="relax_group_ord",
        label_group_ord_col="label_relax_group_ord",
        stage_name="relaxed_dirpm1",
        stage_rank=1,
        max_duration_diff_ns=args.max_duration_diff_ns,
        max_duration_diff_ratio=args.max_duration_diff_ratio,
        relaxed_max_per_dir_packet_diff=args.relaxed_max_per_dir_packet_diff,
        relaxed_max_total_packet_diff=args.relaxed_max_total_packet_diff,
    )
    relax_reverse_ok, relax_reverse_total, relax_reverse_ok_count = build_stage_candidates(
        flow_view=unmatched_after_exact,
        labels_view=labels_reverse_after_exact,
        key_cols=RELAX_KEY_COLS,
        flow_group_ord_col="relax_group_ord",
        label_group_ord_col="label_relax_group_ord",
        stage_name="relaxed_dirpm1",
        stage_rank=1,
        max_duration_diff_ns=args.max_duration_diff_ns,
        max_duration_diff_ratio=args.max_duration_diff_ratio,
        relaxed_max_per_dir_packet_diff=args.relaxed_max_per_dir_packet_diff,
        relaxed_max_total_packet_diff=args.relaxed_max_total_packet_diff,
    )

    ambiguous_direct_flow_rows += int(relax_direct_ok.groupby("flow_row_id").size().gt(1).sum()) if not relax_direct_ok.empty else 0
    ambiguous_reverse_flow_rows += int(relax_reverse_ok.groupby("flow_row_id").size().gt(1).sum()) if not relax_reverse_ok.empty else 0

    relax_all_ok = pd.concat([relax_direct_ok, relax_reverse_ok], ignore_index=True)
    matched_relaxed = select_greedy_best(relax_all_ok)

    matched = pd.concat([matched_exact, matched_relaxed], ignore_index=True)
    if not matched.empty:
        matched["label_row_id"] = matched["label_row_id"].astype("int64")

    matched_flow_ids = set(matched["flow_row_id"].astype(int).tolist()) if not matched.empty else set()
    unmatched = flows[~flows["flow_row_id"].isin(matched_flow_ids)].copy()

    matched_direct = matched[matched["match_orientation"] == "direct"].copy() if not matched.empty else matched.copy()
    matched_reverse = matched[matched["match_orientation"] == "reverse"].copy() if not matched.empty else matched.copy()

    master_matched = build_master(matched, flows, label_info)

    master_path = outdir / "master_matched.csv"
    unmatched_path = outdir / "unmatched_flows.csv"
    cand_direct_path = outdir / "candidates_direct_all.csv"
    cand_reverse_path = outdir / "candidates_reverse_all.csv"
    amb_direct_path = outdir / "ambiguous_flow_candidates_direct.csv"
    amb_reverse_path = outdir / "ambiguous_flow_candidates_reverse.csv"
    report_path = outdir / "join_report.json"

    save_csv(master_matched, master_path)
    save_csv(unmatched, unmatched_path)

    if args.save_debug_csv:
        save_csv(pd.concat([exact_direct_ok, relax_direct_ok], ignore_index=True), cand_direct_path)
        save_csv(pd.concat([exact_reverse_ok, relax_reverse_ok], ignore_index=True), cand_reverse_path)
        # Keep ambiguity CSVs compact too.
        cand_direct_compact = pd.concat([exact_direct_ok, relax_direct_ok], ignore_index=True)
        cand_reverse_compact = pd.concat([exact_reverse_ok, relax_reverse_ok], ignore_index=True)
        amb_dir_ids = cand_direct_compact.groupby("flow_row_id").size()
        amb_dir_ids = amb_dir_ids[amb_dir_ids > 1].index
        amb_rev_ids = cand_reverse_compact.groupby("flow_row_id").size()
        amb_rev_ids = amb_rev_ids[amb_rev_ids > 1].index
        save_csv(cand_direct_compact[cand_direct_compact["flow_row_id"].isin(amb_dir_ids)], amb_direct_path)
        save_csv(cand_reverse_compact[cand_reverse_compact["flow_row_id"].isin(amb_rev_ids)], amb_reverse_path)
        del cand_direct_compact, cand_reverse_compact
    else:
        write_placeholder_csv(cand_direct_path)
        write_placeholder_csv(cand_reverse_path)
        write_placeholder_csv(amb_direct_path)
        write_placeholder_csv(amb_reverse_path)

    duplicate_label_matches = int(matched["label_row_id"].duplicated().sum()) if not matched.empty else 0

    report = {
        "flows_rows": int(len(flows)),
        "labels_rows": int(len(label_info)),
        "flow_start_column_used": flow_start_col,
        "flow_end_column_used": flow_end_col,
        "flow_time_matching_enabled": bool(flow_start_col or flow_end_col),
        "labels_timestamp_parsed_rows": int(label_info["timestamp"].notna().sum()),
        "labels_timestamp_parsed_rate": float(label_info["timestamp"].notna().mean()) if len(label_info) else 0.0,
        "exact_direct_candidates_total": exact_direct_total,
        "exact_direct_candidates_within_threshold": exact_direct_ok_count,
        "exact_reverse_candidates_total": exact_reverse_total,
        "exact_reverse_candidates_within_threshold": exact_reverse_ok_count,
        "relaxed_direct_candidates_total": relax_direct_total,
        "relaxed_direct_candidates_within_threshold": relax_direct_ok_count,
        "relaxed_reverse_candidates_total": relax_reverse_total,
        "relaxed_reverse_candidates_within_threshold": relax_reverse_ok_count,
        "direct_candidates_total": int(exact_direct_total + relax_direct_total),
        "reverse_candidates_total": int(exact_reverse_total + relax_reverse_total),
        "matched_rows_total": int(len(master_matched)),
        "unmatched_rows_total": int(len(unmatched)),
        "match_rate_total": float(len(master_matched) / len(flows)) if len(flows) else 0.0,
        "exact_matched_rows": int(len(matched_exact)),
        "relaxed_matched_rows": int(len(matched_relaxed)),
        "direct_matched_rows": int(len(matched_direct)),
        "reverse_matched_rows": int(len(matched_reverse)),
        "unique_labels_used": int(matched["label_row_id"].nunique()) if not matched.empty else 0,
        "duplicate_label_matches": duplicate_label_matches,
        "ambiguous_direct_flow_rows": ambiguous_direct_flow_rows,
        "ambiguous_reverse_flow_rows": ambiguous_reverse_flow_rows,
        "label_distribution_matched": master_matched["label"].value_counts(dropna=False).sort_index().to_dict() if not master_matched.empty else {},
        "orientation_distribution": master_matched["match_orientation"].value_counts(dropna=False).to_dict() if not master_matched.empty else {},
        "stage_distribution": master_matched["match_stage"].value_counts(dropna=False).to_dict() if not master_matched.empty else {},
        "time_anchor_distribution": master_matched["matched_time_anchor"].value_counts(dropna=False).to_dict() if not master_matched.empty else {},
        "duration_diff_ns_stats": {
            "min": stat_from_non_null(master_matched["duration_diff_ns"], "min") if not master_matched.empty else None,
            "median": stat_from_non_null(master_matched["duration_diff_ns"], "median") if not master_matched.empty else None,
            "p95": stat_from_non_null(master_matched["duration_diff_ns"], "p95") if not master_matched.empty else None,
            "max": stat_from_non_null(master_matched["duration_diff_ns"], "max") if not master_matched.empty else None,
        },
        "time_diff_ns_stats": {
            "min": stat_from_non_null(master_matched["time_diff_ns"], "min") if not master_matched.empty else None,
            "median": stat_from_non_null(master_matched["time_diff_ns"], "median") if not master_matched.empty else None,
            "p95": stat_from_non_null(master_matched["time_diff_ns"], "p95") if not master_matched.empty else None,
            "max": stat_from_non_null(master_matched["time_diff_ns"], "max") if not master_matched.empty else None,
        },
        "group_ord_diff_stats": {
            "min": stat_from_non_null(master_matched["group_ord_diff"], "min") if not master_matched.empty else None,
            "median": stat_from_non_null(master_matched["group_ord_diff"], "median") if not master_matched.empty else None,
            "p95": stat_from_non_null(master_matched["group_ord_diff"], "p95") if not master_matched.empty else None,
            "max": stat_from_non_null(master_matched["group_ord_diff"], "max") if not master_matched.empty else None,
        },
        "packet_dir_diff_total_stats": {
            "min": stat_from_non_null(master_matched["packet_dir_diff_total"], "min") if not master_matched.empty else None,
            "median": stat_from_non_null(master_matched["packet_dir_diff_total"], "median") if not master_matched.empty else None,
            "p95": stat_from_non_null(master_matched["packet_dir_diff_total"], "p95") if not master_matched.empty else None,
            "max": stat_from_non_null(master_matched["packet_dir_diff_total"], "max") if not master_matched.empty else None,
        },
        "debug_candidate_csv_saved": bool(args.save_debug_csv),
        "params": {
            "max_duration_diff_ns": int(args.max_duration_diff_ns),
            "max_duration_diff_ratio": float(args.max_duration_diff_ratio),
            "relaxed_max_per_dir_packet_diff": int(args.relaxed_max_per_dir_packet_diff),
            "relaxed_max_total_packet_diff": int(args.relaxed_max_total_packet_diff),
        },
    }

    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    print(f"[OK] wrote: {master_path}")
    print(f"[OK] wrote: {unmatched_path}")
    print(f"[OK] wrote: {cand_direct_path}")
    print(f"[OK] wrote: {cand_reverse_path}")
    print(f"[OK] wrote: {amb_direct_path}")
    print(f"[OK] wrote: {amb_reverse_path}")
    print(f"[OK] wrote: {report_path}")
    print()
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
