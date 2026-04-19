#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract group1/group4 from CICIDS matched CSVs")
    p.add_argument("--wednesday", required=True, help="Path to Wednesday master_matched.csv")
    p.add_argument("--friday", required=True, help="Path to Friday master_matched.csv")
    p.add_argument("--outdir", required=True, help="Output directory")
    p.add_argument("--g1-size", type=int, default=1500, help="Target size for flow_anomaly")
    p.add_argument("--g4-size", type=int, default=2000, help="Target size for benign_nontls")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    day = path.parent.parent.name  # .../Wednesday/matched/master_matched.csv
    df["source_file"] = f"{day}/{path.stem}"
    df["source_day"] = day
    return df

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
        out["ja4_present"] = (~s.isin(["", "none", "nan", "<na>"])).astype(int)
        return out

    raise ValueError(
        "Could not derive ja4_present: none of ['ja4_present', 'tls_client_hello_c2s', 'ja4_legacy_version'] found"
    )


def sample_evenly(parts: list[pd.DataFrame], target_size: int, seed: int) -> pd.DataFrame:
    parts = [p for p in parts if len(p) > 0]
    if not parts:
        raise ValueError("No data parts provided")

    total_available = sum(len(x) for x in parts)
    if total_available <= target_size:
        return pd.concat(parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)

    base = target_size // len(parts)
    remainder = target_size % len(parts)

    sampled = []
    leftovers = []

    for i, part in enumerate(parts):
        n = min(base + (1 if i < remainder else 0), len(part))
        picked = part.sample(n=n, random_state=seed)
        sampled.append(picked)

        leftover = part.drop(index=picked.index)
        if len(leftover) > 0:
            leftovers.append(leftover)

    out = pd.concat(sampled, ignore_index=True)

    if len(out) < target_size and leftovers:
        pool = pd.concat(leftovers, ignore_index=True)
        need = min(target_size - len(out), len(pool))
        extra = pool.sample(n=need, random_state=seed)
        out = pd.concat([out, extra], ignore_index=True)

    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> None:
    args = parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    wed = ensure_ja4_present(load_csv(Path(args.wednesday)))
    fri = ensure_ja4_present(load_csv(Path(args.friday)))

    required = {"label", "ja4_present"}
    for name, df in [("Wednesday", wed), ("Friday", fri)]:
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"{name}: missing columns {sorted(missing)}")

    wed["label"] = pd.to_numeric(wed["label"], errors="raise").astype(int)
    fri["label"] = pd.to_numeric(fri["label"], errors="raise").astype(int)

    # Group 1: flow anomaly
    g1_wed = wed[(wed["label"] == 1) & (wed["ja4_present"] == 0)].copy()
    g1_fri = fri[(fri["label"] == 1) & (fri["ja4_present"] == 0)].copy()

    g1 = sample_evenly([g1_wed, g1_fri], args.g1_size, args.seed)
    g1["group_name"] = "flow_anomaly"
    g1["binary_label"] = 1

    # Group 4: benign non-TLS
    g4_wed = wed[(wed["label"] == 0) & (wed["ja4_present"] == 0)].copy()
    g4_fri = fri[(fri["label"] == 0) & (fri["ja4_present"] == 0)].copy()

    g4 = sample_evenly([g4_wed, g4_fri], args.g4_size, args.seed)
    g4["group_name"] = "benign_nontls"
    g4["binary_label"] = 0

    g1_path = outdir / "g1_flow_anomaly.csv"
    g4_path = outdir / "g4_benign_nontls.csv"

    g1.to_csv(g1_path, index=False)
    g4.to_csv(g4_path, index=False)

    print(f"[OK] wrote: {g1_path} ({len(g1)} rows)")
    print(f"[OK] wrote: {g4_path} ({len(g4)} rows)")
    print()
    print("Summary:")
    print(f"  G1 Wednesday candidates: {len(g1_wed)}")
    print(f"  G1 Friday candidates   : {len(g1_fri)}")
    print(f"  G4 Wednesday candidates: {len(g4_wed)}")
    print(f"  G4 Friday candidates   : {len(g4_fri)}")


if __name__ == "__main__":
    main()
