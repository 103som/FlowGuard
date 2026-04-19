#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect confusion matrices from baseline and JA4 ablations")
    p.add_argument("--ablations-dir", required=True, help="e.g. ../../data/processed/experiment2_source_aware/ablations_ja4/experiments")
    p.add_argument("--out-csv", default=None)
    return p.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    args = parse_args()
    base = Path(args.ablations_dir)

    rows = []
    for exp_dir in sorted([p for p in base.iterdir() if p.is_dir()]):
        exp_name = exp_dir.name
        for feature_set in ["flow_only", "flow_plus_ja4"]:
            metrics_path = exp_dir / feature_set / "metrics.json"
            if not metrics_path.exists():
                continue

            payload = load_json(metrics_path)
            for split_key in ["val_metrics", "test_metrics"]:
                m = payload.get(split_key, {})
                cm = m.get("confusion_matrix", {})
                rows.append({
                    "experiment": exp_name,
                    "feature_set": feature_set,
                    "split": split_key.replace("_metrics", ""),
                    "precision": m.get("precision"),
                    "recall": m.get("recall"),
                    "f1": m.get("f1"),
                    "balanced_accuracy": m.get("balanced_accuracy"),
                    "tn": cm.get("tn"),
                    "fp": cm.get("fp"),
                    "fn": cm.get("fn"),
                    "tp": cm.get("tp"),
                })

    df = pd.DataFrame(rows)
    print(df.to_string(index=False))

    if args.out_csv:
        out_path = Path(args.out_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(out_path, index=False)


if __name__ == "__main__":
    main()
