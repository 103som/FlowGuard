#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


DEFAULT_METRICS = [
    "val_precision",
    "val_recall",
    "val_f1",
    "val_balanced_accuracy",
]

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot JA4 ablation heatmap")
    p.add_argument("--input-csv", required=True, help="Path to ablation_summary.csv")
    p.add_argument("--out-png", required=True, help="Output PNG path")
    p.add_argument(
        "--feature-set",
        default="flow_plus_ja4",
        choices=["flow_only", "flow_plus_ja4"],
        help="Which feature_set rows to plot",
    )
    p.add_argument(
        "--metrics",
        nargs="*",
        default=DEFAULT_METRICS,
        help="Metric columns to include in heatmap",
    )
    p.add_argument(
        "--title",
        default="JA4 Ablation Heatmap",
        help="Plot title",
    )
    p.add_argument(
        "--annot",
        action="store_true",
        help="Show numeric annotations",
    )
    return p.parse_args()


def prettify_experiment(name: str) -> str:
    if name == "baseline":
        return "baseline"
    if name.startswith("drop_"):
        return name.replace("drop_", "drop ")
    return name


def main() -> None:
    args = parse_args()

    df = pd.read_csv(args.input_csv)
    df = df[df["feature_set"] == args.feature_set].copy()

    if df.empty:
        raise ValueError(f"No rows found for feature_set={args.feature_set}")

    missing_metrics = [m for m in args.metrics if m not in df.columns]
    if missing_metrics:
        raise ValueError(f"Missing metric columns: {missing_metrics}")

    # keep baseline first, then drop_* in original order
    baseline = df[df["experiment"] == "baseline"].copy()
    rest = df[df["experiment"] != "baseline"].copy()
    df = pd.concat([baseline, rest], ignore_index=True)

    row_labels = [prettify_experiment(x) for x in df["experiment"].tolist()]
    col_labels = args.metrics
    matrix = df[args.metrics].to_numpy(dtype=float)

    fig_w = max(8, 1.6 * len(col_labels))
    fig_h = max(4, 0.7 * len(row_labels))

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    im = ax.imshow(matrix, aspect="auto")

    ax.set_xticks(np.arange(len(col_labels)))
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_xticklabels(col_labels, rotation=25, ha="right")
    ax.set_yticklabels(row_labels)

    ax.set_title(args.title)
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label("metric value")

    if args.annot:
        for i in range(matrix.shape[0]):
            for j in range(matrix.shape[1]):
                val = matrix[i, j]
                ax.text(j, i, f"{val:.3f}", ha="center", va="center")

    plt.tight_layout()
    out_path = Path(args.out_png)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=180, bbox_inches="tight")
    plt.close(fig)

    print(f"[OK] wrote: {out_path}")


if __name__ == "__main__":
    main()
