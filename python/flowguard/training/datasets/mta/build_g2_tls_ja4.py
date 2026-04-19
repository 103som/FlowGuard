#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd


EXPLICIT_FAMILY_BY_STEM: Dict[str, str] = {
    "240326-sjtz6aga2x-behavioral1": "darkgate",
    "240717-ldf3savaqk-behavioral1": "darkgate",
    "241010-r6zcqawfmk-behavioral1": "lumma",
    "250322-tlxdqswwet-behavioral1": "asyncrat",
    "250328-whdtbsy1d1-njrat": "njrat",
    "250610-stealc": "stealc",
    "250806-latrodectus": "latrodectus",
    "250901-danabot": "danabot",
    "251001-sr3l9shn3z-behavioral1": "stealc",
    "260125-sectoprat": "sectoprat",
    "260318-lkp92acx6k-behavioral1": "agenttesla",
    "260321-vidarinfection": "vidar",
    "220621-xloader": "xloader",
}

FAMILY_CAPS: Dict[str, int] = {
    "qakbot": 140,
    "pikabot": 140,
    "icedid": 120,
    "ssload": 100,
    "asyncrat": 90,
    "asyncrat_xworm": 90,
    "darkgate": 90,
    "redline": 80,
    "lumma": 100,
    "remcos": 120,
    "agenttesla": 60,
    "originlogger": 40,
    "emotet_trickbot": 120,
    "netsupport_stealc": 120,
    "netsupport": 120,
    "stealc": 90,
    "latrodectus": 80,
    "danabot": 80,
    "sectoprat": 100,
    "vidar": 80,
    "xloader": 120,
    "koi": 120,
    "njrat": 40,
    "unknown": 50,
}

DEFAULT_EXCLUDE_FAMILIES = {
    "agenttesla",
    "njrat",
    "originlogger",
}

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(
    r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)
DATE_REGEX = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
TRIAGE_ID_REGEX = re.compile(r"\b(\d{6}-[a-z0-9]{6,})\b", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build family-balanced G2 JA4 anomaly dataset with per-source IoC hybrid filtering"
    )
    p.add_argument("--input-dir", required=True, help="Directory with parsed CSVs")
    p.add_argument("--out-csv", required=True, help="Output CSV path")
    p.add_argument("--target-size", type=int, default=800, help="Target final rows")
    p.add_argument("--seed", type=int, default=42)

    p.add_argument("--per-source-max-strict", type=int, default=80)
    p.add_argument("--per-source-max-fallback", type=int, default=140)
    p.add_argument("--per-source-max-no-ioc", type=int, default=140)

    p.add_argument("--default-family-cap", type=int, default=100)
    p.add_argument("--min-family-quota", type=int, default=20)

    p.add_argument("--min-ja4-rows-strict", type=int, default=10)
    p.add_argument("--min-ja4-rows-fallback", type=int, default=5)
    p.add_argument("--min-ja4-rows-no-ioc", type=int, default=5)

    p.add_argument("--ioc-dir", default=None, help="Directory with unpacked IoC text files")
    p.add_argument(
        "--ioc-fallback-mode",
        choices=["unfiltered", "drop"],
        default="unfiltered",
        help="What to do if strict IoC filtering leaves too few rows",
    )
    p.add_argument(
        "--exclude-families",
        default=",".join(sorted(DEFAULT_EXCLUDE_FAMILIES)),
        help="Comma-separated family names to exclude entirely",
    )
    p.add_argument("--dedup-enable", action="store_true", default=True)
    return p.parse_args()


def normalize_name(name: str) -> str:
    return (
        name.lower()
        .replace("\\", "/")
        .replace(".csv", "")
        .replace(".pcap", "")
        .replace(".pcapng", "")
        .replace(".txt", "")
    )


def derive_family(source_stem: str) -> str:
    s = normalize_name(source_stem)

    if s in EXPLICIT_FAMILY_BY_STEM:
        return EXPLICIT_FAMILY_BY_STEM[s]

    if "emotet" in s and "trickbot" in s:
        return "emotet_trickbot"
    if "asyncrat" in s and "xworm" in s:
        return "asyncrat_xworm"
    if "netsupport" in s and "stealc" in s:
        return "netsupport_stealc"

    if "qakbot" in s or "qbot" in s:
        return "qakbot"
    if "pikabot" in s:
        return "pikabot"
    if "icedid" in s:
        return "icedid"
    if "ssload" in s:
        return "ssload"
    if "asyncrat" in s:
        return "asyncrat"
    if "darkgate" in s:
        return "darkgate"
    if "redline" in s:
        return "redline"
    if "lumma" in s:
        return "lumma"
    if "remcos" in s:
        return "remcos"
    if "agenttesla" in s:
        return "agenttesla"
    if "originlogger" in s:
        return "originlogger"
    if "netsupport" in s:
        return "netsupport"
    if "stealc" in s:
        return "stealc"
    if "latrodectus" in s:
        return "latrodectus"
    if "danabot" in s:
        return "danabot"
    if "sectoprat" in s:
        return "sectoprat"
    if "vidar" in s:
        return "vidar"
    if "xloader" in s or "formbook" in s:
        return "xloader"
    if "koi" in s:
        return "koi"
    if "njrat" in s or "bladabindi" in s:
        return "njrat"

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
    if "ja4" in df.columns:
        s = df["ja4"].astype("string").fillna("").str.strip()
        s = s.mask(s.eq(""), pd.NA)
        s = s.mask(s.eq("-"), pd.NA)
    else:
        s = pd.Series([pd.NA] * len(df), index=df.index, dtype="string")

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

    fallback = (
        "legacy=" + legacy.astype(str)
        + "|alpn=" + alpn.astype(str)
        + "|c=" + c_cnt
        + "|e=" + e_cnt
        + "|sni=" + has_sni
    )
    return s.fillna(fallback).astype(str)


def packet_bucket(series: pd.Series) -> pd.Series:
    s = pd.to_numeric(series, errors="coerce").fillna(-1)
    bins = [-1, 5, 10, 20, 50, 100, 200, 500, 10**12]
    labels = ["<=5", "6-10", "11-20", "21-50", "51-100", "101-200", "201-500", ">500"]
    return pd.cut(s, bins=bins, labels=labels, include_lowest=True).astype(str)


def add_dedup_helpers(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    if "server_ip" in out.columns:
        out["_server_ip_norm"] = out["server_ip"].astype(str)
    elif "dst_ip" in out.columns:
        out["_server_ip_norm"] = out["dst_ip"].astype(str)
    else:
        out["_server_ip_norm"] = "unknown"

    if "packets_total" in out.columns:
        pkt = out["packets_total"]
    elif {"packets_fwd", "packets_bwd"}.issubset(out.columns):
        pkt = (
            pd.to_numeric(out["packets_fwd"], errors="coerce").fillna(0)
            + pd.to_numeric(out["packets_bwd"], errors="coerce").fillna(0)
        )
    elif {"packets_c2s", "packets_s2c"}.issubset(out.columns):
        pkt = (
            pd.to_numeric(out["packets_c2s"], errors="coerce").fillna(0)
            + pd.to_numeric(out["packets_s2c"], errors="coerce").fillna(0)
        )
    else:
        pkt = pd.Series([0] * len(out), index=out.index)

    out["_packet_count_bucket"] = packet_bucket(pkt)
    return out


def dedup_within_source(df: pd.DataFrame, seed: int) -> pd.DataFrame:
    out = add_dedup_helpers(df)
    out = out.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    out = out.drop_duplicates(
        subset=["source_file", "_server_ip_norm", "_ja4_key", "_packet_count_bucket"],
        keep="first",
    )
    return out.drop(columns=["_server_ip_norm", "_packet_count_bucket"], errors="ignore").reset_index(drop=True)


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


def allocate_family_budgets(capacities: Dict[str, int], target: int, min_quota: int, seed: int) -> Dict[str, int]:
    capacities = {k: int(v) for k, v in capacities.items() if int(v) > 0}
    if not capacities:
        return {}

    base = {k: min(v, min_quota) for k, v in capacities.items()}
    base_sum = sum(base.values())

    if base_sum > target:
        return round_robin_allocate(capacities, target, seed)

    budgets = dict(base)
    remaining_caps = {k: capacities[k] - budgets[k] for k in capacities}
    remaining_target = target - base_sum

    extra = round_robin_allocate(remaining_caps, remaining_target, seed)
    for k, v in extra.items():
        budgets[k] += v

    return budgets


def sample_evenly_within_family(df_family: pd.DataFrame, target_rows: int, source_caps: Dict[str, int], seed: int) -> pd.DataFrame:
    if len(df_family) <= target_rows:
        return df_family.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    capped_parts = []
    capacities: Dict[str, int] = {}

    for source_file, sub in df_family.groupby("source_file"):
        part = sub
        cap = int(source_caps.get(source_file, len(sub)))
        if len(part) > cap:
            part = part.sample(n=cap, random_state=seed)
        capped_parts.append(part)
        capacities[source_file] = len(part)

    capped_df = pd.concat(capped_parts, ignore_index=True)
    quotas = round_robin_allocate(capacities, target_rows, seed)

    sampled_parts = []
    for source_file, quota in quotas.items():
        if quota <= 0:
            continue
        sub = capped_df[capped_df["source_file"] == source_file]
        sampled_parts.append(sub.sample(n=quota, random_state=seed))

    out = pd.concat(sampled_parts, ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def extract_date_token(s: str) -> str | None:
    m = DATE_REGEX.search(s)
    return m.group(1) if m else None


def extract_sample_id(s: str) -> str | None:
    m = TRIAGE_ID_REGEX.search(s)
    return m.group(1).lower() if m else None


def normalize_host_series(s: pd.Series) -> pd.Series:
    out = s.astype(str).str.lower().str.strip()
    out = out.str.replace(r"^[a-z]+://", "", regex=True)
    out = out.str.replace(r"/.*$", "", regex=True)
    out = out.str.replace(r":\d+$", "", regex=True)
    return out


def collect_ioc_index(ioc_dir: str | None) -> Tuple[List[dict], int, int]:
    if not ioc_dir:
        return [], 0, 0

    root = Path(ioc_dir)
    if not root.exists():
        return [], 0, 0

    entries: List[dict] = []
    total_ips = 0
    total_domains = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".txt", ".csv", ".log", ".json"}:
            continue

        rel_norm = normalize_name(str(path.relative_to(root)))
        stem_norm = normalize_name(path.stem)
        date_token = extract_date_token(rel_norm)
        sample_id = extract_sample_id(rel_norm)

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        ips = set(IP_REGEX.findall(text))
        domains = set()
        for d in DOMAIN_REGEX.findall(text):
            d = d.lower().strip(".")
            if d.endswith((".pcap", ".csv", ".txt", ".zip", ".json", ".log")):
                continue
            if d in {"localhost"}:
                continue
            domains.add(d)

        total_ips += len(ips)
        total_domains += len(domains)

        entries.append({
            "path": path,
            "rel_norm": rel_norm,
            "stem_norm": stem_norm,
            "date_token": date_token,
            "sample_id": sample_id,
            "ips": ips,
            "domains": domains,
        })

    return entries, total_ips, total_domains


def match_ioc_entries_for_source(source_file: str, ioc_index: List[dict]) -> List[dict]:
    source_norm = normalize_name(source_file)
    date_token = extract_date_token(source_norm)
    sample_id = extract_sample_id(source_norm)

    scored: List[Tuple[int, dict]] = []

    for entry in ioc_index:
        score = 0

        if source_norm in entry["rel_norm"] or entry["stem_norm"] in source_norm:
            score = max(score, 100)

        if sample_id and entry["sample_id"] and sample_id == entry["sample_id"]:
            score = max(score, 95)

        if date_token and entry["date_token"] and date_token == entry["date_token"]:
            score = max(score, 80)

        if score > 0:
            scored.append((score, entry))

    if not scored:
        return []

    best_score = max(score for score, _ in scored)
    return [entry for score, entry in scored if score == best_score]


def filter_by_ioc(df: pd.DataFrame, ioc_ips: set[str], ioc_domains: set[str]) -> pd.DataFrame:
    if not ioc_ips and not ioc_domains:
        return df

    mask = pd.Series(False, index=df.index)

    ip_cols = [c for c in ["server_ip", "dst_ip", "remote_ip", "client_ip", "src_ip"] if c in df.columns]
    for c in ip_cols:
        mask = mask | df[c].astype(str).isin(ioc_ips)

    domain_cols = [c for c in ["tls_sni", "server_name", "hostname", "host", "http_host"] if c in df.columns]
    if ioc_domains and domain_cols:
        domains_tuple = tuple(sorted(ioc_domains))
        for c in domain_cols:
            vals = normalize_host_series(df[c])
            exact = vals.isin(ioc_domains)
            suffix = vals.apply(lambda x: any(x == d or x.endswith("." + d) for d in domains_tuple))
            mask = mask | exact | suffix

    if not ip_cols and not domain_cols:
        return df

    return df[mask].copy()


def main() -> None:
    args = parse_args()

    input_dir = Path(args.input_dir)
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    summary_path = out_csv.with_suffix(".summary.json")

    excluded_families = {x.strip().lower() for x in args.exclude_families.split(",") if x.strip()}

    ioc_index, total_ips, total_domains = collect_ioc_index(args.ioc_dir)
    print(f"[INFO] Loaded IoC files: {len(ioc_index)}  ips={total_ips} domains={total_domains}")

    csv_files = sorted(input_dir.rglob("*.csv"))
    if not csv_files:
        raise RuntimeError("No parsed CSV files found")

    all_parts: List[pd.DataFrame] = []
    source_stats: List[dict] = []
    source_sampling_caps: Dict[str, int] = {}

    for csv_path in csv_files:
        raw_df = pd.read_csv(csv_path)
        df = ensure_ja4_present(raw_df)

        rel = csv_path.relative_to(input_dir).with_suffix("")
        source_file = str(rel).replace("\\", "/")
        family = derive_family(source_file)

        if family in excluded_families:
            source_stats.append({
                "source_file": source_file,
                "family": family,
                "status": "excluded_family",
                "rows_before": int(len(df)),
                "rows_after": 0,
            })
            continue

        df = df[df["ja4_present"] == 1].copy()
        rows_after_ja4 = len(df)

        if len(df) == 0:
            source_stats.append({
                "source_file": source_file,
                "family": family,
                "status": "no_ja4_rows",
                "rows_before": int(len(raw_df)),
                "rows_after_ja4": 0,
                "rows_after": 0,
            })
            continue

        df["source_file"] = source_file
        df["family"] = family
        df["group_name"] = "tls_malware_ja4"
        df["binary_label"] = 1
        df["source_group"] = "g2_tls_ja4"
        df["_ja4_key"] = derive_ja4_key(df)

        base_df = df.copy()
        if args.dedup_enable:
            base_df = dedup_within_source(base_df, args.seed)
        rows_after_dedup_base = len(base_df)

        matched_ioc_entries = match_ioc_entries_for_source(source_file, ioc_index)
        ioc_ips: set[str] = set()
        ioc_domains: set[str] = set()
        for entry in matched_ioc_entries:
            ioc_ips.update(entry["ips"])
            ioc_domains.update(entry["domains"])

        strict_df = base_df.copy()
        if matched_ioc_entries:
            strict_df = filter_by_ioc(strict_df, ioc_ips, ioc_domains)
            ioc_mode = "strict_matched"
        else:
            ioc_mode = "no_ioc_match"

        rows_after_ioc = len(strict_df)

        if matched_ioc_entries and rows_after_ioc >= args.min_ja4_rows_strict:
            final_source_df = strict_df
            final_mode = "strict"
            keep_threshold = args.min_ja4_rows_strict
            source_sampling_caps[source_file] = args.per_source_max_strict
        elif matched_ioc_entries and rows_after_ioc < args.min_ja4_rows_strict:
            if args.ioc_fallback_mode == "unfiltered":
                final_source_df = base_df
                final_mode = "fallback_unfiltered"
                keep_threshold = args.min_ja4_rows_fallback
                source_sampling_caps[source_file] = args.per_source_max_fallback
            else:
                final_source_df = strict_df.iloc[:0].copy()
                final_mode = "drop_after_strict"
                keep_threshold = args.min_ja4_rows_fallback
                source_sampling_caps[source_file] = args.per_source_max_fallback
        else:
            final_source_df = base_df
            final_mode = "no_ioc_unfiltered"
            keep_threshold = args.min_ja4_rows_no_ioc
            source_sampling_caps[source_file] = args.per_source_max_no_ioc

        rows_after_final_choice = len(final_source_df)

        if rows_after_final_choice < keep_threshold:
            source_stats.append({
                "source_file": source_file,
                "family": family,
                "status": "too_few_rows_after_filtering",
                "ioc_mode": ioc_mode,
                "final_mode": final_mode,
                "ioc_files_matched": [str(x["path"].name) for x in matched_ioc_entries],
                "ioc_ips_used": len(ioc_ips),
                "ioc_domains_used": len(ioc_domains),
                "rows_after_ja4": rows_after_ja4,
                "rows_after_dedup_base": rows_after_dedup_base,
                "rows_after_ioc": rows_after_ioc,
                "rows_after_final_choice": rows_after_final_choice,
                "rows_after": 0,
            })
            continue

        source_stats.append({
            "source_file": source_file,
            "family": family,
            "status": "kept",
            "ioc_mode": ioc_mode,
            "final_mode": final_mode,
            "ioc_files_matched": [str(x["path"].name) for x in matched_ioc_entries],
            "ioc_ips_used": len(ioc_ips),
            "ioc_domains_used": len(ioc_domains),
            "rows_after_ja4": rows_after_ja4,
            "rows_after_dedup_base": rows_after_dedup_base,
            "rows_after_ioc": rows_after_ioc,
            "rows_after_final_choice": rows_after_final_choice,
            "rows_after": rows_after_final_choice,
            "unique_ja4": int(final_source_df["_ja4_key"].nunique()),
        })

        all_parts.append(final_source_df)

    if not all_parts:
        raise RuntimeError("No JA4 rows left after filtering")

    pool = pd.concat(all_parts, ignore_index=True)

    available_by_family = (
        pool.groupby("family", as_index=False)
        .size()
        .rename(columns={"size": "rows"})
        .sort_values(["rows", "family"], ascending=[False, True])
    )

    family_caps_effective: Dict[str, int] = {}
    for _, row in available_by_family.iterrows():
        family = str(row["family"])
        rows = int(row["rows"])
        family_cap = FAMILY_CAPS.get(family, args.default_family_cap)
        family_caps_effective[family] = min(rows, family_cap)

    total_possible = sum(family_caps_effective.values())
    target_size = min(args.target_size, total_possible)

    family_budgets = allocate_family_budgets(
        capacities=family_caps_effective,
        target=target_size,
        min_quota=args.min_family_quota,
        seed=args.seed,
    )

    selected_parts: List[pd.DataFrame] = []
    selected_rows_by_family: Dict[str, int] = {}
    selected_sources_by_family: Dict[str, int] = {}
    selected_unique_ja4_by_family: Dict[str, int] = {}

    for family, fam_budget in sorted(family_budgets.items()):
        if fam_budget <= 0:
            continue
        df_family = pool[pool["family"] == family].copy()
        sampled = sample_evenly_within_family(
            df_family=df_family,
            target_rows=fam_budget,
            source_caps=source_sampling_caps,
            seed=args.seed,
        )
        selected_parts.append(sampled)
        selected_rows_by_family[family] = len(sampled)
        selected_sources_by_family[family] = int(sampled["source_file"].nunique())
        selected_unique_ja4_by_family[family] = int(sampled["_ja4_key"].nunique())

    final_df = pd.concat(selected_parts, ignore_index=True).sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    unique_ja4_total = int(final_df["_ja4_key"].nunique())
    top_ja4_counts = final_df["_ja4_key"].value_counts().head(20).to_dict()

    final_df = final_df.drop(columns=["_ja4_key"], errors="ignore")
    final_df.to_csv(out_csv, index=False)

    summary = {
        "config": {
            "target_size": args.target_size,
            "actual_rows": int(len(final_df)),
            "seed": args.seed,
            "per_source_max_strict": args.per_source_max_strict,
            "per_source_max_fallback": args.per_source_max_fallback,
            "per_source_max_no_ioc": args.per_source_max_no_ioc,
            "default_family_cap": args.default_family_cap,
            "min_family_quota": args.min_family_quota,
            "min_ja4_rows_strict": args.min_ja4_rows_strict,
            "min_ja4_rows_fallback": args.min_ja4_rows_fallback,
            "min_ja4_rows_no_ioc": args.min_ja4_rows_no_ioc,
            "exclude_families": sorted(excluded_families),
            "ioc_dir": args.ioc_dir,
            "ioc_fallback_mode": args.ioc_fallback_mode,
            "dedup_enable": args.dedup_enable,
        },
        "ioc_loaded": {
            "ioc_files": len(ioc_index),
            "ips": total_ips,
            "domains": total_domains,
        },
        "available_by_family": available_by_family.to_dict(orient="records"),
        "family_caps_effective": family_caps_effective,
        "family_budgets": family_budgets,
        "selected_rows_by_family": selected_rows_by_family,
        "selected_sources_by_family": selected_sources_by_family,
        "selected_unique_ja4_by_family": selected_unique_ja4_by_family,
        "unique_source_files_total": int(final_df["source_file"].nunique()),
        "unique_ja4_total": unique_ja4_total,
        "top_ja4_counts": top_ja4_counts,
        "source_stats": source_stats,
    }

    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[OK] wrote: {out_csv}")
    print(f"[OK] rows: {len(final_df)}")
    print(f"[OK] unique source files: {final_df['source_file'].nunique()}")
    print(f"[OK] unique ja4_total: {unique_ja4_total}")
    print()

    print("Selected rows by family:")
    for family, rows in sorted(selected_rows_by_family.items(), key=lambda x: (-x[1], x[0])):
        srcs = selected_sources_by_family.get(family, 0)
        uja4 = selected_unique_ja4_by_family.get(family, 0)
        print(f"  {family:20s} rows={rows:4d}  sources={srcs:3d}  unique_ja4={uja4}")

    kept_sources = sum(1 for x in source_stats if x["status"] == "kept")
    strict_sources = sum(1 for x in source_stats if x.get("final_mode") == "strict")
    fallback_sources = sum(1 for x in source_stats if x.get("final_mode") == "fallback_unfiltered")
    unfiltered_sources = sum(1 for x in source_stats if x.get("final_mode") == "no_ioc_unfiltered")

    print()
    print(f"[INFO] kept sources: {kept_sources}/{len(source_stats)}")
    print(f"[INFO] strict sources: {strict_sources}")
    print(f"[INFO] fallback_unfiltered sources: {fallback_sources}")
    print(f"[INFO] no_ioc_unfiltered sources: {unfiltered_sources}")
    print(f"[OK] wrote summary: {summary_path}")


if __name__ == "__main__":
    main()

