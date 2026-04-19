#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare flow_only and flow_plus_ja4 datasets")
    p.add_argument("--split-dir", required=True, help="e.g. ../../data/processed/experiment2_source_aware/model_inputs/train")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    split_dir = Path(args.split_dir)

    flow = pd.read_csv(split_dir / "dataset_flow_only.csv")
    plus = pd.read_csv(split_dir / "dataset_flow_plus_ja4.csv")

    flow_cols = set(flow.columns)
    plus_cols = set(plus.columns)

    only_in_plus = sorted(list(plus_cols - flow_cols))
    only_in_flow = sorted(list(flow_cols - plus_cols))

    result = {
        "rows_flow_only": int(len(flow)),
        "rows_flow_plus_ja4": int(len(plus)),
        "same_row_count": len(flow) == len(plus),
        "same_label_vector": flow["label"].equals(plus["label"]),
        "only_in_flow_plus_ja4": only_in_plus,
        "only_in_flow_only": only_in_flow,
        "flow_only_duplicate_rows": int(flow.duplicated().sum()),
        "flow_plus_ja4_duplicate_rows": int(plus.duplicated().sum()),
    }

    # check if common part is exactly the same
    common_cols = [c for c in flow.columns if c in plus.columns]
    result["same_common_columns_same_order"] = common_cols == [c for c in plus.columns if c in flow.columns]

    # exact equality on common columns
    result["same_values_on_common_columns"] = flow[common_cols].equals(plus[common_cols])

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
