#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List

import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build balanced G3 (flow+JA4 anomaly TLS / DoH tunnels) from parsed CSVs"
    )
    p.add_argument("--input-dir", required=True, help="Parsed CSV dir, e.g. data/parsed/mta/flow_ja4")
    p.add_argument("--out-csv", required=True, help="Output CSV path")
    p.add_argument("--target-size", type=int, default=1500, help="Target total rows")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--per-source-max", type=int, default=120, help="Hard cap per parsed source file")
    p.add_argument("--per-ja4-max", type=int, default=40, help="Hard cap per JA4 key inside one tool")
    return p.parse_args()


def normalize_name(name: str) -> str:
    return name.lower().replace("\\", "/")


def derive_tool(source_file: str) -> str:
    s = normalize_name(source_file)
    if "dns2tcp" in s:
        return "dns2tcp"
    if "dnscat2" in s:
        return "dnscat2"
    if "iodine" in s:
        return "iodine"
    return "unknown"


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
        out["ja4_present"] = (~s.isin(["", "none", "nan", "<na>", "-"])).astype(int)
        return out

    raise ValueError("Cannot derive ja4_present")


def derive_ja4_key(df: pd.DataFrame) -> pd.Series:
    # Если есть полный ja4 token — используем его.
    if "ja4" in df.columns:
        s = df["ja4"].astype("string").fillna("").str.strip()
        s = s.mask(s.eq(""), pd.NA)
        s = s.mask(s.eq("-"), pd.NA)
    else:
        s = pd.Series([pd.NA] * len(df), index=df.index, dtype="string")

    # Fallback: компактный ключ из безопасных JA4 полей.
    legacy = df["ja4_legacy_version"].astype("string").fillna("-") if "ja4_legacy_version" in df.columns else "-"
    alpn = df["ja4_alpn"].astype("string").fillna("-") if "ja4_alpn" in df.columns else "-"
    c_cnt = (
        pd.to_numeric(df["ja4_cipher_suites_count"], errors="coerce").fillna(-1).astype(int).astype(str)
        if "ja4_cipher_suites_count" in df.columns
        else "-1"
    )
    e_cnt = (
        pd.to_numeric(df["ja4_extensions_count"], errors="coerce").fillna(-1).astype(int).astype(str)
        if "ja4_extensions_count" in df.columns
        else "-1"
    )
    has_sni = (
        pd.to_numeric(df["ja4_has_sni"], errors="coerce").fillna(-1).astype(int).astype(str)
        if "ja4_has_sni" in df.columns
        else "-1"
    )

    fallback = "legacy=" + legacy.astype(str) + "|alpn=" + alpn.astype(str) + "|c=" + c_cnt + "|e=" + e_cnt + "|sni=" + has_sni
    out = s.fillna(fallback)

    return out.astype(str)


def round_robin_allocate(capacities: Dict[str, int], target: int, seed: int) -> Dict[str, int]:
    keys = list(capacities.keys())
    rng = random.Random(seed)
    rng.shuffle(keys)

    alloc = {k: 0 for k in keys}
    remaining = min(target, sum(capacities.values()))

    while remaining > 0:
        progressed = False
        for k in keys:
            if alloc[k] < capacities[k]:
                alloc[k] += 1
                remaining -= 1
                progressed = True
                if remaining == 0:
                    break
        if not progressed:
            break

    return alloc


def cap_per_source(df_tool: pd.DataFrame, per_source_max: int, seed: int) -> pd.DataFrame:
    parts: List[pd.DataFrame] = []
    for source_file, sub in df_tool.groupby("source_file"):
        if len(sub) > per_source_max:
            sub = sub.sample(n=per_source_max, random_state=seed)
        parts.append(sub)
    return pd.concat(parts, ignore_index=True) if parts else df_tool.iloc[:0].copy()


def cap_per_ja4(df_tool: pd.DataFrame, per_ja4_max: int, seed: int) -> pd.DataFrame:
    parts: List[pd.DataFrame] = []
    for ja4_key, sub in df_tool.groupby("ja4_key"):
        if len(sub) > per_ja4_max:
            sub = sub.sample(n=per_ja4_max, random_state=seed)
        parts.append(sub)
    return pd.concat(parts, ignore_index=True) if parts else df_tool.iloc[:0].copy()


def sample_evenly_by_ja4_and_source(df_tool: pd.DataFrame, target_rows: int, seed: int) -> pd.DataFrame:
    """
    Внутри одного tool:
    1) распределяем бюджет между ja4_key
    2) внутри ja4_key равномерно по source_file
    """
    if len(df_tool) <= target_rows:
        return df_tool.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    ja4_caps = df_tool.groupby("ja4_key").size().to_dict()
    ja4_quota = round_robin_allocate(ja4_caps, target_rows, seed)

    parts: List[pd.DataFrame] = []
    for ja4_key, quota in ja4_quota.items():
        if quota <= 0:
            continue
        sub_ja4 = df_tool[df_tool["ja4_key"] == ja4_key].copy()

        src_caps = sub_ja4.groupby("source_file").size().to_dict()
        src_quota = round_robin_allocate(src_caps, quota, seed)

        for source_file, q in src_quota.items():
            if q <= 0:
                continue
            sub_src = sub_ja4[sub_ja4["source_file"] == source_file]
            parts.append(sub_src.sample(n=q, random_state=seed))

    out = pd.concat(parts, ignore_index=True) if parts else df_tool.iloc[:0].copy()
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> None:
    args = parse_args()

    input_dir = Path(args.input_dir)
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    summary_path = out_csv.with_suffix(".summary.json")

    csv_files = sorted(input_dir.rglob("*.csv"))
    if not csv_files:
        raise RuntimeError("No parsed CSV files found")

    all_parts: List[pd.DataFrame] = []

    for csv_path in csv_files:
        rel = csv_path.relative_to(input_dir).with_suffix("")
        source_file = str(rel).replace("\\", "/")
        tool = derive_tool(source_file)

        # Берём только нужные тулзы для группы 3
        if tool not in {"dns2tcp", "dnscat2", "iodine"}:
            continue

        df = pd.read_csv(csv_path)
        df = ensure_ja4_present(df)
        df = df[df["ja4_present"] == 1].copy()
        if len(df) == 0:
            continue

        df["source_file"] = source_file
        df["tool"] = tool
        df["ja4_key"] = derive_ja4_key(df)
        df["group_name"] = "flow_ja4_anomaly_TLS"
        df["binary_label"] = 1
        df["source_group"] = "g3_flow_ja4"

        all_parts.append(df)

    if not all_parts:
        raise RuntimeError("No JA4-positive rows left for G3")

    pool = pd.concat(all_parts, ignore_index=True)

    # 1) кап по source_file
    capped_source_parts: List[pd.DataFrame] = []
    for tool, df_tool in pool.groupby("tool"):
        capped_source_parts.append(cap_per_source(df_tool, args.per_source_max, args.seed))
    pool = pd.concat(capped_source_parts, ignore_index=True)

    # 2) кап по ja4_key
    capped_ja4_parts: List[pd.DataFrame] = []
    for tool, df_tool in pool.groupby("tool"):
        capped_ja4_parts.append(cap_per_ja4(df_tool, args.per_ja4_max, args.seed))
    pool = pd.concat(capped_ja4_parts, ignore_index=True)

    # 3) равномерный бюджет по tool
    tool_caps = pool.groupby("tool").size().to_dict()
    tool_quota = round_robin_allocate(tool_caps, args.target_size, args.seed)

    selected_parts: List[pd.DataFrame] = []
    selected_rows_by_tool: Dict[str, int] = {}
    unique_ja4_by_tool: Dict[str, int] = {}
    unique_sources_by_tool: Dict[str, int] = {}

    for tool, quota in sorted(tool_quota.items()):
        if quota <= 0:
            continue
        df_tool = pool[pool["tool"] == tool].copy()
        sampled = sample_evenly_by_ja4_and_source(df_tool, quota, args.seed)

        selected_parts.append(sampled)
        selected_rows_by_tool[tool] = int(len(sampled))
        unique_ja4_by_tool[tool] = int(sampled["ja4_key"].nunique())
        unique_sources_by_tool[tool] = int(sampled["source_file"].nunique())

    final_df = pd.concat(selected_parts, ignore_index=True).sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    final_df.to_csv(out_csv, index=False)

    summary = {
        "config": {
            "target_size": args.target_size,
            "actual_rows": int(len(final_df)),
            "seed": args.seed,
            "per_source_max": args.per_source_max,
            "per_ja4_max": args.per_ja4_max,
        },
        "selected_rows_by_tool": selected_rows_by_tool,
        "unique_ja4_by_tool": unique_ja4_by_tool,
        "unique_sources_by_tool": unique_sources_by_tool,
        "unique_source_files_total": int(final_df["source_file"].nunique()),
        "unique_ja4_total": int(final_df["ja4_key"].nunique()),
        "top_ja4_counts": final_df["ja4_key"].value_counts().head(20).to_dict(),
    }

    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[OK] wrote: {out_csv}")
    print(f"[OK] rows: {len(final_df)}")
    print(f"[OK] unique source files: {final_df['source_file'].nunique()}")
    print(f"[OK] unique ja4_key: {final_df['ja4_key'].nunique()}")
    print()
    print("Selected rows by tool:")
    for tool, rows in sorted(selected_rows_by_tool.items(), key=lambda x: (-x[1], x[0])):
        print(
            f"  {tool:8s} rows={rows:4d}  "
            f"sources={unique_sources_by_tool.get(tool, 0)}  "
            f"unique_ja4={unique_ja4_by_tool.get(tool, 0)}"
        )
    print()
    print(f"[OK] wrote summary: {summary_path}")


if __name__ == "__main__":
    main()
