#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier


FILE_MAP = {
    "flow_only": "dataset_flow_only.csv",
    "flow_plus_ja4": "dataset_flow_plus_ja4.csv",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train XGBoost on Experiment 2")
    p.add_argument("--train-dir", required=True)
    p.add_argument("--val-dir", required=True)
    p.add_argument("--test-dir", required=True)
    p.add_argument("--outdir", required=True)
    p.add_argument("--feature-set", choices=["flow_only", "flow_plus_ja4", "both"], default="both")
    p.add_argument("--threshold-mode", choices=["f1", "f2", "balanced_accuracy", "f1_balanced"], default="f1_balanced")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-jobs", type=int, default=4)
    return p.parse_args()


def set_global_seed(seed: int) -> None:
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)


def load_dataset(dataset_dir: Path, feature_set: str) -> tuple[pd.DataFrame, np.ndarray]:
    path = dataset_dir / FILE_MAP[feature_set]
    df = pd.read_csv(path)
    y = pd.to_numeric(df["label"], errors="raise").astype(np.int8).to_numpy()
    X = df.drop(columns=["label"]).copy()

    for c in X.columns:
        if pd.api.types.is_integer_dtype(X[c]):
            X[c] = X[c].astype(np.int32)
        elif pd.api.types.is_float_dtype(X[c]):
            X[c] = X[c].astype(np.float32)

    return X, y


def numeric_and_categorical_columns(X: pd.DataFrame) -> tuple[list[str], list[str]]:
    cat_cols = list(X.select_dtypes(include=["object", "string"]).columns)
    num_cols = [c for c in X.columns if c not in cat_cols]
    return num_cols, cat_cols


def safe_average_precision(y_true: np.ndarray, scores: np.ndarray) -> Optional[float]:
    y_true = np.asarray(y_true)
    if (y_true == 1).sum() == 0:
        return None
    return float(average_precision_score(y_true, scores))


def safe_roc_auc(y_true: np.ndarray, scores: np.ndarray) -> Optional[float]:
    y_true = np.asarray(y_true)
    pos = int((y_true == 1).sum())
    neg = int((y_true == 0).sum())
    if pos == 0 or neg == 0:
        return None
    return float(roc_auc_score(y_true, scores))


def choose_best_threshold(y_true: np.ndarray, scores: np.ndarray, mode: str) -> tuple[float, dict]:
    qs = np.linspace(0.01, 0.99, 199)
    thresholds = np.unique(np.quantile(scores, qs))

    best_thr = float(thresholds[0])
    best = None
    best_key = None

    for thr in thresholds:
        y_pred = (scores >= thr).astype(np.int8)

        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        f2 = fbeta_score(y_true, y_pred, beta=2, zero_division=0)
        bal_acc = balanced_accuracy_score(y_true, y_pred)

        current = {
            "threshold": float(thr),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "f2": float(f2),
            "balanced_accuracy": float(bal_acc),
        }

        if mode == "f1":
            key = (f1, bal_acc, precision, float(thr))
        elif mode == "f2":
            key = (f2, bal_acc, recall, float(thr))
        elif mode == "balanced_accuracy":
            key = (bal_acc, f1, precision, float(thr))
        elif mode == "f1_balanced":
            balance_penalty = abs(precision - recall)
            key = (
                round(f1, 6),
                round(bal_acc, 6),
                -round(balance_penalty, 6),
                round(min(precision, recall), 6),
                round(float(thr), 6),
            )
        else:
            raise ValueError(f"Unknown threshold mode: {mode}")

        if best_key is None or key > best_key:
            best_key = key
            best = current
            best_thr = float(thr)

    return best_thr, best


def evaluate_scores(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    y_pred = (scores >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    return {
        "threshold": float(threshold),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "average_precision": safe_average_precision(y_true, scores),
        "roc_auc": safe_roc_auc(y_true, scores),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def build_xgb_pipeline(X: pd.DataFrame, scale_pos_weight: float, seed: int, n_jobs: int) -> Pipeline:
    num_cols, cat_cols = numeric_and_categorical_columns(X)

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", SimpleImputer(strategy="constant", fill_value=0.0), num_cols),
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="constant", fill_value="none")),
                        ("ohe", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                cat_cols,
            ),
        ],
        remainder="drop",
        sparse_threshold=1.0,
    )

    clf = XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=400,
        max_depth=5,
        learning_rate=0.05,
        min_child_weight=5,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=2.0,
        tree_method="hist",
        random_state=seed,
        seed=seed,
        n_jobs=n_jobs,
        scale_pos_weight=scale_pos_weight,
    )

    return Pipeline(steps=[("preprocessor", preprocessor), ("classifier", clf)])


def run_one(feature_set: str, train_dir: Path, val_dir: Path, test_dir: Path, outdir: Path, seed: int, n_jobs: int, threshold_mode: str) -> None:
    X_train, y_train = load_dataset(train_dir, feature_set)
    X_val, y_val = load_dataset(val_dir, feature_set)
    X_test, y_test = load_dataset(test_dir, feature_set)

    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    pipe = build_xgb_pipeline(X_train, scale_pos_weight, seed=seed, n_jobs=n_jobs)
    pipe.fit(X_train, y_train)

    val_scores = pipe.predict_proba(X_val)[:, 1]
    test_scores = pipe.predict_proba(X_test)[:, 1]

    best_thr, best_val = choose_best_threshold(y_val, val_scores, mode=threshold_mode)
    val_metrics = evaluate_scores(y_val, val_scores, best_thr)
    test_metrics = evaluate_scores(y_test, test_scores, best_thr)

    model_dir = outdir / feature_set
    model_dir.mkdir(parents=True, exist_ok=True)

    with (model_dir / "metrics.json").open("w", encoding="utf-8") as f:
        json.dump(
            {
                "seed": seed,
                "feature_set": feature_set,
                "scale_pos_weight": float(scale_pos_weight),
                "selected_threshold_from_val": best_thr,
                "best_val_threshold_metrics": best_val,
                "val_metrics": val_metrics,
                "test_metrics": test_metrics,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    joblib.dump(pipe, model_dir / "model.joblib")

    print(f"\n=== {feature_set} ===")
    print("VAL:")
    print(json.dumps(val_metrics, ensure_ascii=False, indent=2))
    print("TEST:")
    print(json.dumps(test_metrics, ensure_ascii=False, indent=2))
    print(f"[OK] wrote: {model_dir / 'metrics.json'}")
    print(f"[OK] wrote: {model_dir / 'model.joblib'}")


def main() -> None:
    args = parse_args()
    set_global_seed(args.seed)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    feature_sets = ["flow_only", "flow_plus_ja4"] if args.feature_set == "both" else [args.feature_set]

    for feature_set in feature_sets:
        run_one(
            feature_set=feature_set,
            train_dir=Path(args.train_dir),
            val_dir=Path(args.val_dir),
            test_dir=Path(args.test_dir),
            outdir=outdir,
            seed=args.seed,
            n_jobs=args.n_jobs,
            threshold_mode=args.threshold_mode,
        )


if __name__ == "__main__":
    main()
