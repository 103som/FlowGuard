#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build Experiment 2 dataset with full 5-group source-aware train/val/test split"
    )
    p.add_argument("--g1-csv", required=True)
    p.add_argument("--g2-csv", required=True)
    p.add_argument("--g3-csv", required=True)
    p.add_argument("--g4-csv", required=True)
    p.add_argument("--g5-csv", required=True)

    p.add_argument("--g1-size", type=int, default=800)
    p.add_argument("--g2-size", type=int, default=673)
    p.add_argument("--g3-size", type=int, default=700)
    p.add_argument("--g4-size", type=int, default=2000)
    p.add_argument("--g5-size", type=int, default=800)

    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--test-frac", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--outdir", required=True)

    # Group-specific split hints
    p.add_argument("--g1-min-holdout-sources", type=int, default=1)
    p.add_argument("--g2-min-holdout-sources", type=int, default=2)
    p.add_argument("--g2-min-holdout-families", type=int, default=2)
    p.add_argument("--g3-min-holdout-sources", type=int, default=5)
    p.add_argument("--g4-min-holdout-sources", type=int, default=1)
    p.add_argument("--g5-min-holdout-sources", type=int, default=2)

    return p.parse_args()


def load_df(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def ensure_label(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "label" in out.columns:
        out["label"] = pd.to_numeric(out["label"], errors="raise").astype(int)
    elif "binary_label" in out.columns:
        out["label"] = pd.to_numeric(out["binary_label"], errors="raise").astype(int)
    else:
        raise ValueError("No label/binary_label column found")
    return out


def ensure_group_name(df: pd.DataFrame, fallback: str) -> pd.DataFrame:
    out = df.copy()
    if "group_name" not in out.columns:
        out["group_name"] = fallback
    out["group_name"] = out["group_name"].fillna(fallback).astype(str)
    return out


def ensure_source_file(df: pd.DataFrame, fallback: str) -> pd.DataFrame:
    """
    Build a stable source key for source-aware split.
    Preference:
      1) source_file
      2) source_group
      3) source_day
      4) fallback constant
    """
    out = df.copy()

    source = None
    for col in ["source_file", "source_group", "source_day"]:
        if col in out.columns:
            cur = out[col].astype("string")
            if source is None:
                source = cur
            else:
                source = source.fillna(cur)

    if source is None:
        out["source_file"] = fallback
    else:
        out["source_file"] = source.fillna(fallback).astype(str)

    return out


def select_subset(df: pd.DataFrame, target_size: int, seed: int) -> pd.DataFrame:
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    if len(df) <= target_size:
        return df.copy()
    return df.sample(n=target_size, random_state=seed).reset_index(drop=True)


def calc_split_sizes(n: int, val_frac: float, test_frac: float) -> dict[str, int]:
    if n <= 0:
        return {"train": 0, "val": 0, "test": 0}

    n_val = int(round(n * val_frac))
    n_test = int(round(n * test_frac))
    n_train = n - n_val - n_test

    if n >= 3:
        if n_val == 0 and val_frac > 0:
            n_val = 1
        if n_test == 0 and test_frac > 0:
            n_test = 1
        n_train = n - n_val - n_test
        if n_train <= 0:
            # Keep train non-empty
            if n_val >= n_test and n_val > 1:
                n_val -= 1
            elif n_test > 1:
                n_test -= 1
            n_train = n - n_val - n_test

    if n_train < 0:
        n_train = 0

    return {"train": n_train, "val": n_val, "test": n_test}


def split_by_rows(df: pd.DataFrame, val_frac: float, test_frac: float, seed: int):
    """
    Fallback split when source-aware split is impossible.
    """
    work = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    sizes = calc_split_sizes(len(work), val_frac, test_frac)

    train_end = sizes["train"]
    val_end = train_end + sizes["val"]

    train_df = work.iloc[:train_end].copy()
    val_df = work.iloc[train_end:val_end].copy()
    test_df = work.iloc[val_end:].copy()

    return train_df, val_df, test_df


def _mode_or_unknown(series: pd.Series) -> str:
    s = series.dropna().astype(str)
    if len(s) == 0:
        return "unknown"
    mode = s.mode()
    if len(mode) == 0:
        return str(s.iloc[0])
    return str(mode.iloc[0])


def build_source_units(df: pd.DataFrame, family_col: Optional[str] = None) -> pd.DataFrame:
    work = df.copy()

    if family_col is not None and family_col in work.columns:
        grouped = (
            work.groupby("source_file", as_index=False)
            .agg(
                rows=("label", "size"),
                family=(family_col, _mode_or_unknown),
            )
            .sort_values(["rows", "source_file"], ascending=[False, True])
            .reset_index(drop=True)
        )
    else:
        grouped = (
            work.groupby("source_file", as_index=False)
            .agg(rows=("label", "size"))
            .sort_values(["rows", "source_file"], ascending=[False, True])
            .reset_index(drop=True)
        )

    return grouped


def assign_units_to_splits(
    units: pd.DataFrame,
    val_frac: float,
    test_frac: float,
    seed: int,
    min_holdout_sources: int = 1,
    family_col: Optional[str] = None,
    min_holdout_families: int = 0,
) -> dict[str, list[str]]:
    """
    Greedy source-aware assignment:
    - no source overlap between splits
    - tries to respect row targets
    - optionally encourages family diversity in val/test (for G2)
    """
    total_rows = int(units["rows"].sum())
    target = calc_split_sizes(total_rows, val_frac, test_frac)

    buckets = {"train": [], "val": [], "test": []}
    current_rows = {"train": 0, "val": 0, "test": 0}
    current_units = {"train": 0, "val": 0, "test": 0}
    split_families = {"train": set(), "val": set(), "test": set()}

    work = units.sample(frac=1.0, random_state=seed).copy()

    # 1) Seed val/test with smallest available sources so they are not empty and can gain diversity.
    seed_order = work.sort_values(["rows", "source_file"], ascending=[True, True]).reset_index(drop=True)

    used_sources: set[str] = set()
    for split in ["val", "test"]:
        need_units = max(1, min_holdout_sources)
        while current_units[split] < need_units:
            chosen_idx = None
            for idx, row in seed_order.iterrows():
                src = str(row["source_file"])
                rows = int(row["rows"])
                fam = str(row["family"]) if family_col is not None and "family" in row else None

                if src in used_sources:
                    continue

                # Do not explode holdout too early
                max_rows_allowed = max(target[split], 1) * 1.40
                if current_rows[split] + rows > max_rows_allowed:
                    continue

                chosen_idx = idx
                break

            if chosen_idx is None:
                break

            row = seed_order.iloc[chosen_idx]
            src = str(row["source_file"])
            rows = int(row["rows"])
            fam = str(row["family"]) if family_col is not None and "family" in row else None

            buckets[split].append(src)
            current_rows[split] += rows
            current_units[split] += 1
            used_sources.add(src)
            if fam is not None:
                split_families[split].add(fam)

    # 2) Greedy fill the rest by row deficit and diversity bonus.
    remaining = work[~work["source_file"].astype(str).isin(used_sources)].copy()
    remaining = remaining.sort_values(["rows", "source_file"], ascending=[False, True]).reset_index(drop=True)

    for _, row in remaining.iterrows():
        src = str(row["source_file"])
        rows = int(row["rows"])
        fam = str(row["family"]) if family_col is not None and "family" in row else None

        candidates: list[tuple[float, str]] = []
        for split in ["train", "val", "test"]:
            split_target = max(target[split], 1)
            deficit = target[split] - current_rows[split]
            overshoot = max(0, current_rows[split] + rows - target[split])

            score = deficit / split_target
            score -= overshoot / split_target

            # Encourage val/test to contain more than one source.
            if split in {"val", "test"} and current_units[split] < min_holdout_sources:
                score += 0.50

            # Encourage family diversity in val/test for G2.
            if (
                fam is not None
                and split in {"val", "test"}
                and current_units[split] >= 1
                and fam not in split_families[split]
                and len(split_families[split]) < max(1, min_holdout_families)
            ):
                score += 0.35

            # Soft penalty if holdout is already clearly over target.
            if split in {"val", "test"} and current_rows[split] >= target[split] * 1.25:
                score -= 1.50

            candidates.append((score, split))

        candidates.sort(reverse=True)
        chosen_split = candidates[0][1]

        buckets[chosen_split].append(src)
        current_rows[chosen_split] += rows
        current_units[chosen_split] += 1
        if fam is not None:
            split_families[chosen_split].add(fam)

    return buckets


def split_group_source_aware(
    df: pd.DataFrame,
    val_frac: float,
    test_frac: float,
    seed: int,
    min_holdout_sources: int = 1,
    family_col: Optional[str] = None,
    min_holdout_families: int = 0,
):
    """
    Split one group into train/val/test.
    - source-aware if possible
    - row-split fallback if sources are insufficient
    """
    n_sources = int(df["source_file"].astype(str).nunique())
    if n_sources < 3:
        return split_by_rows(df, val_frac, test_frac, seed)

    units = build_source_units(df, family_col=family_col)
    buckets = assign_units_to_splits(
        units=units,
        val_frac=val_frac,
        test_frac=test_frac,
        seed=seed,
        min_holdout_sources=min_holdout_sources,
        family_col=family_col,
        min_holdout_families=min_holdout_families,
    )

    train_df = df[df["source_file"].astype(str).isin(buckets["train"])].copy()
    val_df = df[df["source_file"].astype(str).isin(buckets["val"])].copy()
    test_df = df[df["source_file"].astype(str).isin(buckets["test"])].copy()

    # Safety fallback if one split accidentally became empty
    if len(train_df) == 0 or len(val_df) == 0 or len(test_df) == 0:
        return split_by_rows(df, val_frac, test_frac, seed)

    return train_df, val_df, test_df


def summarize(df: pd.DataFrame) -> dict:
    res = {
        "rows": int(len(df)),
        "label_distribution": {str(k): int(v) for k, v in df["label"].value_counts(dropna=False).to_dict().items()},
        "group_distribution": {
            str(k): int(v) for k, v in df["group_name"].value_counts(dropna=False).to_dict().items()
        },
    }
    if "source_file" in df.columns:
        res["unique_sources"] = int(df["source_file"].astype(str).nunique())
    if "family" in df.columns:
        fam = df["family"].dropna().astype(str)
        res["unique_families"] = int(fam.nunique()) if len(fam) else 0
    return res


def groupwise_summary(df: pd.DataFrame) -> dict:
    out: dict[str, dict] = {}
    for group_name, part in df.groupby("group_name", dropna=False):
        key = str(group_name)
        out[key] = {
            "rows": int(len(part)),
            "label_distribution": {
                str(k): int(v) for k, v in part["label"].value_counts(dropna=False).to_dict().items()
            },
            "unique_sources": int(part["source_file"].astype(str).nunique()) if "source_file" in part.columns else 0,
        }
        if "family" in part.columns:
            fam = part["family"].dropna().astype(str)
            out[key]["unique_families"] = int(fam.nunique()) if len(fam) else 0
    return out


def overlap_count(a: pd.DataFrame, b: pd.DataFrame) -> int:
    return len(set(a["source_file"].astype(str).unique()) & set(b["source_file"].astype(str).unique()))


def family_overlap_count(a: pd.DataFrame, b: pd.DataFrame) -> int:
    if "family" not in a.columns or "family" not in b.columns:
        return 0
    a_set = set(a["family"].dropna().astype(str).unique())
    b_set = set(b["family"].dropna().astype(str).unique())
    return len(a_set & b_set)


def main() -> None:
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Load + normalize groups
    g1 = ensure_source_file(
        ensure_group_name(ensure_label(load_df(args.g1_csv)), "flow_anomaly"),
        "g1_fallback",
    )
    g2 = ensure_source_file(
        ensure_group_name(ensure_label(load_df(args.g2_csv)), "tls_malware_ja4"),
        "g2_fallback",
    )
    g3 = ensure_source_file(
        ensure_group_name(ensure_label(load_df(args.g3_csv)), "flow_ja4_anomaly_TLS"),
        "g3_fallback",
    )
    g4 = ensure_source_file(
        ensure_group_name(ensure_label(load_df(args.g4_csv)), "benign_nontls"),
        "g4_fallback",
    )
    g5 = ensure_source_file(
        ensure_group_name(ensure_label(load_df(args.g5_csv)), "benign_tls"),
        "g5_fallback",
    )

    # Select final subset sizes
    g1 = select_subset(g1, args.g1_size, args.seed)
    g2 = select_subset(g2, args.g2_size, args.seed)
    g3 = select_subset(g3, args.g3_size, args.seed)
    g4 = select_subset(g4, args.g4_size, args.seed)
    g5 = select_subset(g5, args.g5_size, args.seed)

    # Split every group independently
    g1_train, g1_val, g1_test = split_group_source_aware(
        g1,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
        min_holdout_sources=args.g1_min_holdout_sources,
    )

    g2_train, g2_val, g2_test = split_group_source_aware(
        g2,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
        min_holdout_sources=args.g2_min_holdout_sources,
        family_col="family" if "family" in g2.columns else None,
        min_holdout_families=args.g2_min_holdout_families,
    )

    g3_train, g3_val, g3_test = split_group_source_aware(
        g3,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
        min_holdout_sources=args.g3_min_holdout_sources,
    )

    g4_train, g4_val, g4_test = split_group_source_aware(
        g4,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
        min_holdout_sources=args.g4_min_holdout_sources,
    )

    g5_train, g5_val, g5_test = split_group_source_aware(
        g5,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
        min_holdout_sources=args.g5_min_holdout_sources,
    )

    # Build final splits from ALL groups
    train_df = pd.concat([g1_train, g2_train, g3_train, g4_train, g5_train], ignore_index=True)
    val_df = pd.concat([g1_val, g2_val, g3_val, g4_val, g5_val], ignore_index=True)
    test_df = pd.concat([g1_test, g2_test, g3_test, g4_test, g5_test], ignore_index=True)

    train_df = train_df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    val_df = val_df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    test_df = test_df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    full_df = pd.concat([train_df, val_df, test_df], ignore_index=True)

    train_path = outdir / "experiment2_train.csv"
    val_path = outdir / "experiment2_val.csv"
    test_path = outdir / "experiment2_test.csv"
    full_path = outdir / "experiment2_full.csv"
    summary_path = outdir / "experiment2_summary.json"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    full_df.to_csv(full_path, index=False)

    summary = {
        "config": {
            "g1_size": args.g1_size,
            "g2_size": args.g2_size,
            "g3_size": args.g3_size,
            "g4_size": args.g4_size,
            "g5_size": args.g5_size,
            "val_frac": args.val_frac,
            "test_frac": args.test_frac,
            "seed": args.seed,
            "mode": "full_5_group_source_aware_split",
        },
        "train": summarize(train_df),
        "val": summarize(val_df),
        "test": summarize(test_df),
        "full": summarize(full_df),
        "train_by_group": groupwise_summary(train_df),
        "val_by_group": groupwise_summary(val_df),
        "test_by_group": groupwise_summary(test_df),
        "source_overlap": {
            "train_val": overlap_count(train_df, val_df),
            "train_test": overlap_count(train_df, test_df),
            "val_test": overlap_count(val_df, test_df),
        },
        "family_overlap": {
            "train_val": family_overlap_count(train_df, val_df),
            "train_test": family_overlap_count(train_df, test_df),
            "val_test": family_overlap_count(val_df, test_df),
        },
    }

    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[OK] wrote: {train_path}")
    print(f"[OK] wrote: {val_path}")
    print(f"[OK] wrote: {test_path}")
    print(f"[OK] wrote: {full_path}")
    print(f"[OK] wrote: {summary_path}")
    print()

    print("Source overlap:")
    print(json.dumps(summary["source_overlap"], ensure_ascii=False, indent=2))
    print()

    print("Family overlap:")
    print(json.dumps(summary["family_overlap"], ensure_ascii=False, indent=2))
    print()

    print("VAL by group:")
    print(json.dumps(summary["val_by_group"], ensure_ascii=False, indent=2))
    print()

    print("TEST by group:")
    print(json.dumps(summary["test_by_group"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
