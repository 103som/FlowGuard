#!/usr/bin/env python3
"""
analyze_errors.py — разбор ошибок обученных моделей на VAL и TEST.

Для каждой feature_set (flow_only и flow_plus_ja4):
  - Confusion matrix на VAL и TEST
  - Расклад FP и FN по группам (flow_anomaly_noTLS / tls_malware_ja4 / ...)
  - Расклад FP и FN по source_file и family
  - Список конкретных FP / FN row-id чтобы можно было руками посмотреть

Дополнительно — сравнение двух моделей:
  - сколько строк обе модели ошиблись (пересечение FP/FN)
  - сколько ловит только flow_plus_ja4 (чистый вклад JA4)
  - сколько теряет flow_plus_ja4 по сравнению с flow_only

Использование:

python analyze_errors.py \
  --model-flow-only  ../../data/processed/experiment2_source_aware/experiments/xgb/flow_only/model.joblib \
  --model-flow-plus-ja4 ../../data/processed/experiment2_source_aware/experiments/xgb/flow_plus_ja4/model.joblib \
  --metrics-flow-only ../../data/processed/experiment2_source_aware/experiments/xgb/flow_only/metrics.json \
  --metrics-flow-plus-ja4 ../../data/processed/experiment2_source_aware/experiments/xgb/flow_plus_ja4/metrics.json \
  --val-dir  ../../data/processed/experiment2_source_aware/model_inputs/val \
  --test-dir ../../data/processed/experiment2_source_aware/model_inputs/test \
  --outdir   ../../data/processed/experiment2_source_aware/analysis

Результат в --outdir:
  errors_summary.json            — сводный отчёт с цифрами (для копирования в диплом)
  errors_flow_only.csv           — все ошибки flow_only
  errors_flow_plus_ja4.csv       — все ошибки flow_plus_ja4
  errors_by_group_val.csv        — табличка FP/FN по группам (VAL)
  errors_by_group_test.csv       — табличка FP/FN по группам (TEST)
  models_disagreement.csv        — какие строки только одна модель поймала, какие обе потеряли
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


FILE_MAP = {
    "flow_only": "dataset_flow_only.csv",
    "flow_plus_ja4": "dataset_flow_plus_ja4.csv",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--model-flow-only", required=True, help="Путь к model.joblib flow_only")
    p.add_argument("--model-flow-plus-ja4", required=True, help="Путь к model.joblib flow_plus_ja4")
    p.add_argument("--metrics-flow-only", required=True, help="metrics.json из которого берётся порог")
    p.add_argument("--metrics-flow-plus-ja4", required=True)
    p.add_argument("--val-dir", required=True, help="Папка с dataset_*.csv + report_view.csv (VAL)")
    p.add_argument("--test-dir", required=True, help="-//- TEST")
    p.add_argument("--outdir", required=True)
    return p.parse_args()


def load_threshold(metrics_path: Path) -> float:
    m = json.loads(metrics_path.read_text(encoding="utf-8"))
    # train_xgb_experiment2.py пишет selected_threshold_from_val
    if "selected_threshold_from_val" in m:
        return float(m["selected_threshold_from_val"])
    if "test_metrics" in m and "threshold" in m["test_metrics"]:
        return float(m["test_metrics"]["threshold"])
    raise ValueError(f"Cannot find threshold in {metrics_path}")


def load_dataset(dataset_dir: Path, feature_set: str) -> tuple[pd.DataFrame, np.ndarray]:
    df = pd.read_csv(dataset_dir / FILE_MAP[feature_set])
    y = pd.to_numeric(df["label"], errors="raise").astype(np.int8).to_numpy()
    X = df.drop(columns=["label"]).copy()
    for c in X.columns:
        if pd.api.types.is_integer_dtype(X[c]):
            X[c] = X[c].astype(np.int32)
        elif pd.api.types.is_float_dtype(X[c]):
            X[c] = X[c].astype(np.float32)
    return X, y


def load_report_view(dataset_dir: Path) -> pd.DataFrame:
    """report_view.csv содержит label + group_name + source_file + family,
    те самые "метаданные" которые убирались из обучающего датасета."""
    path = dataset_dir / "report_view.csv"
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def score_and_predict(model_path: Path, X: pd.DataFrame, threshold: float) -> tuple[np.ndarray, np.ndarray]:
    model = joblib.load(model_path)
    scores = model.predict_proba(X)[:, 1]
    preds = (scores >= threshold).astype(np.int8)
    return scores, preds


def make_error_frame(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray,
                     report: pd.DataFrame, split_name: str) -> pd.DataFrame:
    """DataFrame с колонками row_id, split, y_true, y_pred, score, error_type, group_name, source_file, family"""
    error_type = np.where(
        y_pred == y_true,
        "OK",
        np.where(y_pred == 1, "FP", "FN"),
    )

    out = pd.DataFrame({
        "row_id": np.arange(len(y_true)),
        "split": split_name,
        "y_true": y_true,
        "y_pred": y_pred,
        "score": np.round(scores, 5),
        "error_type": error_type,
    })

    if not report.empty:
        # report уже имеет столько же строк сколько dataset_*.csv (там label + мета)
        meta_cols = [c for c in ["group_name", "source_file", "family"] if c in report.columns]
        for c in meta_cols:
            out[c] = report[c].values

    return out


def confusion_by_group(err_df: pd.DataFrame) -> pd.DataFrame:
    """Для каждой группы считает tn/fp/fn/tp и кол-во ошибок."""
    if "group_name" not in err_df.columns:
        return pd.DataFrame()

    rows = []
    for group, sub in err_df.groupby("group_name", dropna=False):
        y_true = sub["y_true"].to_numpy()
        y_pred = sub["y_pred"].to_numpy()
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel().astype(int)
        elif cm.shape == (1, 1):
            # только один класс в группе (это нормально: G1 — всё атаки, G5 — всё benign)
            only_label = int(sub["y_true"].iloc[0])
            if only_label == 1:
                tn, fp = 0, 0
                tp = int((y_pred == 1).sum())
                fn = int((y_pred == 0).sum())
            else:
                tp, fn = 0, 0
                tn = int((y_pred == 0).sum())
                fp = int((y_pred == 1).sum())
        else:
            tn = fp = fn = tp = 0

        n = len(sub)
        fp_rate = fp / max(1, tn + fp)
        fn_rate = fn / max(1, fn + tp)

        rows.append({
            "group_name": str(group),
            "rows": n,
            "positives": int((y_true == 1).sum()),
            "negatives": int((y_true == 0).sum()),
            "TN": tn, "FP": fp, "FN": fn, "TP": tp,
            "fp_rate_on_negatives": round(fp_rate, 4),
            "fn_rate_on_positives": round(fn_rate, 4),
        })

    out = pd.DataFrame(rows).sort_values("group_name").reset_index(drop=True)
    return out


def top_breakdown(err_df: pd.DataFrame, by: str, error_type: str, top_n: int = 15) -> pd.DataFrame:
    """Самые частые источники ошибок (по source_file или family)"""
    if by not in err_df.columns:
        return pd.DataFrame()
    sub = err_df[err_df["error_type"] == error_type]
    if sub.empty:
        return pd.DataFrame()
    vc = sub[by].fillna("<nan>").astype(str).value_counts().head(top_n)
    return (
        vc.rename_axis(by)
          .reset_index(name=f"num_{error_type}")
    )


def compare_models(err_fo: pd.DataFrame, err_fp: pd.DataFrame) -> dict:
    """Сравнение flow_only vs flow_plus_ja4: по одним и тем же row_id и split."""
    join = err_fo[["row_id", "split", "y_true", "error_type"]].rename(
        columns={"error_type": "err_flow_only"}
    ).merge(
        err_fp[["row_id", "split", "error_type"]].rename(columns={"error_type": "err_flow_plus_ja4"}),
        on=["row_id", "split"],
        how="inner",
    )

    # Разные исходы
    both_ok = ((join["err_flow_only"] == "OK") & (join["err_flow_plus_ja4"] == "OK")).sum()
    both_wrong = ((join["err_flow_only"] != "OK") & (join["err_flow_plus_ja4"] != "OK")).sum()
    only_fo_wrong = ((join["err_flow_only"] != "OK") & (join["err_flow_plus_ja4"] == "OK")).sum()
    only_fp_wrong = ((join["err_flow_only"] == "OK") & (join["err_flow_plus_ja4"] != "OK")).sum()

    net_gain = int(only_fo_wrong - only_fp_wrong)

    summary = {
        "both_correct": int(both_ok),
        "both_wrong": int(both_wrong),
        "fixed_by_ja4": int(only_fo_wrong),  # flow_only ошибся, flow+ja4 поймал
        "broken_by_ja4": int(only_fp_wrong),  # flow_only был прав, flow+ja4 ошибся
        "net_ja4_gain": net_gain,
    }

    return summary, join


def safe_global_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel().astype(int)
    else:
        tn = fp = fn = tp = 0
    return {
        "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }


def main() -> None:
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    thr_fo = load_threshold(Path(args.metrics_flow_only))
    thr_fp = load_threshold(Path(args.metrics_flow_plus_ja4))

    print(f"[INFO] threshold flow_only      = {thr_fo:.6f}")
    print(f"[INFO] threshold flow_plus_ja4  = {thr_fp:.6f}")
    print()

    all_errors_fo: list[pd.DataFrame] = []
    all_errors_fp: list[pd.DataFrame] = []

    per_split_summary: dict = {}

    for split_name, dataset_dir in [("val", Path(args.val_dir)), ("test", Path(args.test_dir))]:
        print(f"===== {split_name.upper()} =====")
        X_fo, y_fo = load_dataset(dataset_dir, "flow_only")
        X_fp, y_fp = load_dataset(dataset_dir, "flow_plus_ja4")
        report = load_report_view(dataset_dir)

        # sanity check — y_fo и y_fp должны быть одинаковыми для одного split
        if not np.array_equal(y_fo, y_fp):
            print(f"[WARN] labels don't match between flow_only and flow_plus_ja4 on {split_name}!")

        if not report.empty and len(report) != len(y_fo):
            print(f"[WARN] report_view.csv has {len(report)} rows but dataset has {len(y_fo)}")
            report = pd.DataFrame()

        scores_fo, pred_fo = score_and_predict(Path(args.model_flow_only), X_fo, thr_fo)
        scores_fp, pred_fp = score_and_predict(Path(args.model_flow_plus_ja4), X_fp, thr_fp)

        err_fo = make_error_frame(y_fo, pred_fo, scores_fo, report, split_name)
        err_fp = make_error_frame(y_fp, pred_fp, scores_fp, report, split_name)

        all_errors_fo.append(err_fo)
        all_errors_fp.append(err_fp)

        metrics_fo = safe_global_metrics(y_fo, pred_fo)
        metrics_fp = safe_global_metrics(y_fp, pred_fp)

        print(f"flow_only       | " + " ".join(f"{k}={v}" for k, v in metrics_fo.items()))
        print(f"flow_plus_ja4   | " + " ".join(f"{k}={v}" for k, v in metrics_fp.items()))

        cm_by_group_fo = confusion_by_group(err_fo)
        cm_by_group_fp = confusion_by_group(err_fp)

        if not cm_by_group_fo.empty:
            path = outdir / f"errors_by_group_{split_name}_flow_only.csv"
            cm_by_group_fo.to_csv(path, index=False)
            print(f"\n  FP/FN по группам — flow_only:")
            print(cm_by_group_fo.to_string(index=False))

        if not cm_by_group_fp.empty:
            path = outdir / f"errors_by_group_{split_name}_flow_plus_ja4.csv"
            cm_by_group_fp.to_csv(path, index=False)
            print(f"\n  FP/FN по группам — flow_plus_ja4:")
            print(cm_by_group_fp.to_string(index=False))

        per_split_summary[split_name] = {
            "flow_only": metrics_fo,
            "flow_plus_ja4": metrics_fp,
            "by_group_flow_only": cm_by_group_fo.to_dict(orient="records") if not cm_by_group_fo.empty else [],
            "by_group_flow_plus_ja4": cm_by_group_fp.to_dict(orient="records") if not cm_by_group_fp.empty else [],
        }
        print()

    # Объединяем ошибки обоих splits
    err_fo_full = pd.concat(all_errors_fo, ignore_index=True)
    err_fp_full = pd.concat(all_errors_fp, ignore_index=True)

    err_fo_full[err_fo_full["error_type"] != "OK"].to_csv(outdir / "errors_flow_only.csv", index=False)
    err_fp_full[err_fp_full["error_type"] != "OK"].to_csv(outdir / "errors_flow_plus_ja4.csv", index=False)

    print("===== СРАВНЕНИЕ МОДЕЛЕЙ =====")
    compare_summary, compare_df = compare_models(err_fo_full, err_fp_full)
    print(json.dumps(compare_summary, indent=2, ensure_ascii=False))
    compare_df.to_csv(outdir / "models_disagreement.csv", index=False)
    print()

    # Топ источников ошибок
    print("===== TOP источников ошибок flow_only (TEST+VAL) =====")
    for et in ["FP", "FN"]:
        print(f"\n  {et} by source_file:")
        top = top_breakdown(err_fo_full, "source_file", et, top_n=10)
        if not top.empty:
            print(top.to_string(index=False))
        print(f"\n  {et} by family:")
        top = top_breakdown(err_fo_full, "family", et, top_n=10)
        if not top.empty:
            print(top.to_string(index=False))

    print("\n===== TOP источников ошибок flow_plus_ja4 (TEST+VAL) =====")
    for et in ["FP", "FN"]:
        print(f"\n  {et} by source_file:")
        top = top_breakdown(err_fp_full, "source_file", et, top_n=10)
        if not top.empty:
            print(top.to_string(index=False))
        print(f"\n  {et} by family:")
        top = top_breakdown(err_fp_full, "family", et, top_n=10)
        if not top.empty:
            print(top.to_string(index=False))

    # Summary JSON
    summary = {
        "thresholds": {
            "flow_only": thr_fo,
            "flow_plus_ja4": thr_fp,
        },
        "per_split": per_split_summary,
        "model_comparison": compare_summary,
    }
    (outdir / "errors_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\n[OK] всё записано в: {outdir}")


if __name__ == "__main__":
    main()
