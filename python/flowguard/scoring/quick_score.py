#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Score parsed flow CSV with trained model")
    p.add_argument("--flows-csv", required=True, help="Input parsed flow CSV")
    p.add_argument("--model-dir", required=True, help="Directory with model.joblib and metrics.json")
    p.add_argument(
        "--feature-set",
        required=True,
        choices=["flow_only", "flow_plus_ja4"],
        help="Which feature schema to use",
    )
    p.add_argument("--outdir", required=True, help="Where to write scored outputs")
    p.add_argument(
        "--schema-json",
        default=None,
        help="Optional explicit path to feature_schema.json. "
             "If omitted, inferred as ../../model_inputs/train/feature_schema.json from model-dir.",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Optional manual threshold override. If omitted, taken from metrics.json, else 0.5 fallback.",
    )
    return p.parse_args()


def infer_schema_path(model_dir: Path) -> Path:
    # model_dir expected like:
    # .../data/processed/experiment2_source_aware/experiments/xgb/flow_plus_ja4
    base = model_dir.parents[2]
    return base / "model_inputs" / "train" / "feature_schema.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def resolve_threshold(metrics: dict[str, Any]) -> float:
    candidates = [
        metrics.get("selected_threshold_from_val"),
        metrics.get("threshold"),
        metrics.get("val_metrics", {}).get("threshold"),
        metrics.get("test_metrics", {}).get("threshold"),
    ]
    for value in candidates:
        if value is not None:
            return float(value)
    return 0.5


def align_features(df: pd.DataFrame, expected_features: list[str]) -> tuple[pd.DataFrame, list[str], list[str]]:
    current_cols = list(df.columns)

    missing = [c for c in expected_features if c not in current_cols]
    extra = [c for c in current_cols if c not in expected_features]

    X = df.copy()

    # ВАЖНО: использовать np.nan, а не pd.NA
    for col in missing:
        X[col] = np.nan

    # оставить только ожидаемые признаки в точном порядке
    X = X[expected_features].copy()

    # возможные pd.NA -> np.nan
    X = X.replace({pd.NA: np.nan})

    return X, missing, extra


def infer_column_types_from_pipeline(model: Any) -> tuple[list[str], list[str]]:
    numeric_cols: list[str] = []
    categorical_cols: list[str] = []

    if hasattr(model, "named_steps") and "preprocessor" in model.named_steps:
        pre = model.named_steps["preprocessor"]
        if hasattr(pre, "transformers_"):
            for name, transformer, cols in pre.transformers_:
                if cols is None or cols == "drop":
                    continue
                if not isinstance(cols, (list, tuple, np.ndarray, pd.Index)):
                    continue

                name_lower = str(name).lower()
                if name_lower.startswith("num"):
                    numeric_cols.extend(list(cols))
                elif name_lower.startswith("cat"):
                    categorical_cols.extend(list(cols))

    return numeric_cols, categorical_cols


def normalize_dtypes(X: pd.DataFrame, model: Any) -> pd.DataFrame:
    X = X.copy()

    numeric_cols, categorical_cols = infer_column_types_from_pipeline(model)

    # Если pipeline не отдал типы, пробуем мягко определить:
    # object-колонки оставляем как object, прочие пытаемся привести к numeric.
    if not numeric_cols and not categorical_cols:
        for col in X.columns:
            if pd.api.types.is_object_dtype(X[col]) or pd.api.types.is_string_dtype(X[col]):
                categorical_cols.append(col)
            else:
                numeric_cols.append(col)

    for col in numeric_cols:
        if col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce")

    for col in categorical_cols:
        if col in X.columns:
            # не string dtype, а object, чтобы sklearn спокойно ел np.nan
            X[col] = X[col].astype("object")
            X[col] = X[col].replace({pd.NA: np.nan})

    # финальная зачистка
    X = X.replace({pd.NA: np.nan})

    return X


def main() -> None:
    args = parse_args()

    flows_csv = Path(args.flows_csv)
    model_dir = Path(args.model_dir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    model_path = model_dir / "model.joblib"
    metrics_path = model_dir / "metrics.json"

    if not flows_csv.exists():
        raise FileNotFoundError(f"flows CSV not found: {flows_csv}")
    if not model_path.exists():
        raise FileNotFoundError(f"model.joblib not found: {model_path}")

    schema_path = Path(args.schema_json) if args.schema_json else infer_schema_path(model_dir)
    if not schema_path.exists():
        raise FileNotFoundError(f"feature_schema.json not found: {schema_path}")

    df = pd.read_csv(flows_csv)
    schema = load_json(schema_path)

    schema_key = "flow_only_features" if args.feature_set == "flow_only" else "flow_plus_ja4_features"
    if schema_key not in schema:
        raise KeyError(f"{schema_key} not found in {schema_path}")

    expected_features = [c for c in schema[schema_key] if c != "label"]

    model = joblib.load(model_path)

    X, missing, extra = align_features(df, expected_features)
    X = normalize_dtypes(X, model)

    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(X)[:, 1]
    elif hasattr(model, "decision_function"):
        raw = model.decision_function(X)
        scores = 1.0 / (1.0 + np.exp(-raw))
    else:
        raise TypeError("Loaded model does not support predict_proba or decision_function")

    if args.threshold is not None:
        threshold = float(args.threshold)
    else:
        metrics = load_json(metrics_path) if metrics_path.exists() else {}
        threshold = resolve_threshold(metrics)

    is_anomaly = (scores >= threshold).astype(int)

    scored = df.copy()
    scored["anomaly_score"] = scores
    scored["is_anomaly"] = is_anomaly

    top = scored.sort_values("anomaly_score", ascending=False).reset_index(drop=True)

    scored_path = outdir / "scored.csv"
    top_path = outdir / "top_scored.csv"
    summary_path = outdir / "summary.json"

    scored.to_csv(scored_path, index=False)
    top.to_csv(top_path, index=False)

    summary = {
        "rows_total": int(len(scored)),
        "anomalies_total": int(is_anomaly.sum()),
        "anomaly_share": float(is_anomaly.mean()) if len(scored) else 0.0,
        "threshold": float(threshold),
        "score_mean": float(np.mean(scores)) if len(scores) else 0.0,
        "score_max": float(np.max(scores)) if len(scores) else 0.0,
        "expected_features_count": int(len(expected_features)),
        "actual_columns_count": int(len(df.columns)),
        "missing_columns_added": missing,
        "extra_columns_ignored": extra,
        "schema_json": str(schema_path),
        "model_path": str(model_path),
        "flows_csv": str(flows_csv),
    }

    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[OK] wrote: {scored_path}")
    print(f"[OK] wrote: {top_path}")
    print(f"[OK] wrote: {summary_path}")


if __name__ == "__main__":
    main()
