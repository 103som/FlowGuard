#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

import pandas as pd


DEFAULT_JA4_COLS = [
    "tls_client_hello_c2s",
    "ja4_legacy_version",
    "ja4_cipher_suites_count",
    "ja4_extensions_count",
    "ja4_has_sni",
    "ja4_alpn",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run JA4 ablation experiments for Experiment 2")
    p.add_argument(
        "--base-dir",
        required=True,
        help="Base dir with model_inputs/, e.g. ../../data/processed/experiment2_source_aware",
    )
    p.add_argument(
        "--trainer",
        default="train_xgb_experiment2.py",
        help="Path to train_xgb_experiment2.py",
    )
    p.add_argument(
        "--outdir",
        default=None,
        help="Output dir for ablations. Default: <base-dir>/ablations_ja4",
    )
    p.add_argument(
        "--threshold-mode",
        default="f1",
        choices=["f1", "f2", "balanced_accuracy", "f1_balanced"],
        help="Threshold mode to pass to trainer",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-jobs", type=int, default=4)

    # passthrough weights for your current trainer
    p.add_argument(
        "--class-weight-mode",
        default=None,
        choices=["none", "balanced", "manual"],
        help="Optional class weight mode for trainer",
    )
    p.add_argument("--attack-weight", type=float, default=None)
    p.add_argument("--benign-weight", type=float, default=None)

    p.add_argument(
        "--ja4-cols",
        nargs="*",
        default=DEFAULT_JA4_COLS,
        help="JA4 columns to ablate one by one",
    )
    return p.parse_args()


def read_columns(csv_path: Path) -> list[str]:
    return pd.read_csv(csv_path, nrows=1).columns.tolist()


def align_to_schema(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    out = df.copy()

    for col in cols:
        if col not in out.columns:
            out[col] = pd.NA

    extra_cols = [c for c in out.columns if c not in cols]
    if extra_cols:
        out = out.drop(columns=extra_cols)

    return out[cols]


def build_split_variant(
    src_split_dir: Path,
    dst_split_dir: Path,
    drop_col: str | None,
    train_flow_only_cols: list[str],
    train_flow_plus_cols: list[str],
) -> None:
    dst_split_dir.mkdir(parents=True, exist_ok=True)

    flow_only = pd.read_csv(src_split_dir / "dataset_flow_only.csv")
    flow_plus = pd.read_csv(src_split_dir / "dataset_flow_plus_ja4.csv")
    report = pd.read_csv(src_split_dir / "report_view.csv")

    if drop_col is not None and drop_col in flow_plus.columns:
        flow_plus = flow_plus.drop(columns=[drop_col])

    flow_only = align_to_schema(flow_only, train_flow_only_cols)
    flow_plus = align_to_schema(flow_plus, train_flow_plus_cols)

    flow_only.to_csv(dst_split_dir / "dataset_flow_only.csv", index=False)
    flow_plus.to_csv(dst_split_dir / "dataset_flow_plus_ja4.csv", index=False)
    report.to_csv(dst_split_dir / "report_view.csv", index=False)

    schema = {
        "flow_only_features": [c for c in flow_only.columns if c != "label"],
        "flow_plus_ja4_features": [c for c in flow_plus.columns if c != "label"],
        "dropped_ja4_column": drop_col,
    }
    with (dst_split_dir / "feature_schema.json").open("w", encoding="utf-8") as f:
        json.dump(schema, f, ensure_ascii=False, indent=2)


def run_trainer(
    trainer: str,
    train_dir: Path,
    val_dir: Path,
    test_dir: Path,
    outdir: Path,
    threshold_mode: str,
    seed: int,
    n_jobs: int,
    class_weight_mode: str | None,
    attack_weight: float | None,
    benign_weight: float | None,
) -> None:
    cmd = [
        "python",
        trainer,
        "--train-dir",
        str(train_dir),
        "--val-dir",
        str(val_dir),
        "--test-dir",
        str(test_dir),
        "--outdir",
        str(outdir),
        "--feature-set",
        "both",
        "--threshold-mode",
        threshold_mode,
        "--seed",
        str(seed),
        "--n-jobs",
        str(n_jobs),
    ]

    if class_weight_mode is not None:
        cmd.extend(["--class-weight-mode", class_weight_mode])

    if attack_weight is not None:
        cmd.extend(["--attack-weight", str(attack_weight)])

    if benign_weight is not None:
        cmd.extend(["--benign-weight", str(benign_weight)])

    subprocess.run(cmd, check=True)


def load_metrics(metrics_path: Path) -> dict:
    with metrics_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def flatten_metrics(exp_name: str, feature_set: str, payload: dict) -> dict:
    row = {
        "experiment": exp_name,
        "feature_set": feature_set,
        "selected_threshold_from_val": payload.get("selected_threshold_from_val"),
    }

    for split_key in ["val_metrics", "test_metrics"]:
        split_prefix = split_key.replace("_metrics", "")
        m = payload.get(split_key, {})
        row[f"{split_prefix}_precision"] = m.get("precision")
        row[f"{split_prefix}_recall"] = m.get("recall")
        row[f"{split_prefix}_f1"] = m.get("f1")
        row[f"{split_prefix}_balanced_accuracy"] = m.get("balanced_accuracy")
        row[f"{split_prefix}_average_precision"] = m.get("average_precision")
        row[f"{split_prefix}_roc_auc"] = m.get("roc_auc")

        cm = m.get("confusion_matrix", {})
        row[f"{split_prefix}_tn"] = cm.get("tn")
        row[f"{split_prefix}_fp"] = cm.get("fp")
        row[f"{split_prefix}_fn"] = cm.get("fn")
        row[f"{split_prefix}_tp"] = cm.get("tp")

    return row


def main() -> None:
    args = parse_args()

    base_dir = Path(args.base_dir)
    src_model_inputs = base_dir / "model_inputs"
    outdir = Path(args.outdir) if args.outdir else base_dir / "ablations_ja4"

    train_src = src_model_inputs / "train"
    val_src = src_model_inputs / "val"
    test_src = src_model_inputs / "test"

    required = [
        train_src / "dataset_flow_only.csv",
        train_src / "dataset_flow_plus_ja4.csv",
        val_src / "dataset_flow_only.csv",
        val_src / "dataset_flow_plus_ja4.csv",
        test_src / "dataset_flow_only.csv",
        test_src / "dataset_flow_plus_ja4.csv",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise FileNotFoundError("Missing required files:\n" + "\n".join(missing))

    outdir.mkdir(parents=True, exist_ok=True)

    # Train schema is source of truth
    train_flow_only_cols = read_columns(train_src / "dataset_flow_only.csv")
    train_flow_plus_cols = read_columns(train_src / "dataset_flow_plus_ja4.csv")

    experiments: list[tuple[str, str | None]] = [("baseline", None)]
    experiments.extend((f"drop_{col}", col) for col in args.ja4_cols)

    summary_rows = []

    for exp_name, dropped_col in experiments:
        print(f"\n===== {exp_name} =====")
        exp_inputs_dir = outdir / "inputs" / exp_name
        exp_train = exp_inputs_dir / "train"
        exp_val = exp_inputs_dir / "val"
        exp_test = exp_inputs_dir / "test"

        if exp_inputs_dir.exists():
            shutil.rmtree(exp_inputs_dir)

        build_split_variant(train_src, exp_train, dropped_col, train_flow_only_cols, train_flow_plus_cols)

        # for val/test we align to train schema after column drop
        exp_train_flow_plus_cols = read_columns(exp_train / "dataset_flow_plus_ja4.csv")
        exp_train_flow_only_cols = read_columns(exp_train / "dataset_flow_only.csv")

        build_split_variant(val_src, exp_val, dropped_col, exp_train_flow_only_cols, exp_train_flow_plus_cols)
        build_split_variant(test_src, exp_test, dropped_col, exp_train_flow_only_cols, exp_train_flow_plus_cols)

        exp_outdir = outdir / "experiments" / exp_name
        if exp_outdir.exists():
            shutil.rmtree(exp_outdir)

        run_trainer(
            trainer=args.trainer,
            train_dir=exp_train,
            val_dir=exp_val,
            test_dir=exp_test,
            outdir=exp_outdir,
            threshold_mode=args.threshold_mode,
            seed=args.seed,
            n_jobs=args.n_jobs,
            class_weight_mode=args.class_weight_mode,
            attack_weight=args.attack_weight,
            benign_weight=args.benign_weight,
        )

        for feature_set in ["flow_only", "flow_plus_ja4"]:
            metrics_path = exp_outdir / feature_set / "metrics.json"
            payload = load_metrics(metrics_path)
            row = flatten_metrics(exp_name, feature_set, payload)
            row["dropped_col"] = dropped_col
            summary_rows.append(row)

    summary_df = pd.DataFrame(summary_rows)
    summary_csv = outdir / "ablation_summary.csv"
    summary_json = outdir / "ablation_summary.json"

    summary_df.to_csv(summary_csv, index=False)
    with summary_json.open("w", encoding="utf-8") as f:
        json.dump(summary_rows, f, ensure_ascii=False, indent=2)

    print()
    print(f"[OK] wrote: {summary_csv}")
    print(f"[OK] wrote: {summary_json}")


if __name__ == "__main__":
    main()
