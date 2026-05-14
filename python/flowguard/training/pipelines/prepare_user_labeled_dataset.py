#!/usr/bin/env python3
"""
Подготовка пользовательского размеченного набора данных для переобучения FlowGuard.

Принимает: каталог с двумя подпапками parsed_benign/ и parsed_malicious/,
каждая из которых содержит CSV-файлы, сформированные парсером FlowParser
(batch_parse_pcaps.py).

Производит:
  1. Добавление колонок label (0 для benign, 1 для malicious).
  2. Добавление синтетических колонок ja4_present, ja4_key, tool, group_name,
     source_file (того же вида, что используется в основных скриптах обучения).
  3. Стратифицированное разбиение на train/val/test (по умолчанию 70/15/15)
     с учётом классового баланса.
  4. Сохранение train.csv / val.csv / test.csv в указанный выходной каталог.

Использование:
    python3 prepare_user_labeled_dataset.py \\
        --parsed-dir <путь>/user_data_parsed \\
        --outdir <путь>/user_data_processed \\
        [--val-frac 0.15] [--test-frac 0.15] [--seed 42]
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd


# Колонки, которые ожидает feature_schema.json у эталонной модели
# и которых нет в базовом выходе C++-парсера — их нужно синтезировать
SYNTHETIC_COLUMNS = ["ja4_present", "ja4_key", "tool", "group_name", "source_file"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Prepare user-labeled dataset for FlowGuard retraining",
    )
    p.add_argument(
        "--parsed-dir", required=True,
        help="Directory with parsed CSVs organized as benign/ and malicious/ subdirs",
    )
    p.add_argument(
        "--outdir", required=True,
        help="Where to save train.csv / val.csv / test.csv",
    )
    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--test-frac", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--min-rows-per-class", type=int, default=20,
        help="Minimum rows per class in total (raise error if less)",
    )
    return p.parse_args()


def derive_ja4_present(df: pd.DataFrame) -> pd.Series:
    """Бинарный индикатор: в flow присутствует JA4-отпечаток."""
    # Приоритет 1: поле ja4 / ja4_cipher_suites есть и не пустое
    for col in ("ja4", "ja4_cipher_suites"):
        if col in df.columns:
            s = df[col].astype(str).str.lower().str.strip()
            return (~s.isin(["", "none", "nan", "<na>", "-"])).astype(int)

    # Приоритет 2: считаем по tls_client_hello_c2s
    if "tls_client_hello_c2s" in df.columns:
        return (pd.to_numeric(df["tls_client_hello_c2s"], errors="coerce").fillna(0) > 0).astype(int)

    # Приоритет 3: всё по нулям (не-TLS трафик)
    return pd.Series([0] * len(df), index=df.index, dtype=int)


def derive_ja4_key(df: pd.DataFrame) -> pd.Series:
    """
    Категориальный ключ JA4, используемый как признак в обученной модели.
    Формируется как укороченный SHA1-хэш от строки JA4 (ja4_cipher_suites + ja4_extensions).
    Для не-TLS потоков — константа "none".
    """

    def build_key(row) -> str:
        parts = []
        for col in ("ja4_cipher_suites", "ja4_extensions"):
            val = row.get(col, "")
            if pd.isna(val) or val == "":
                parts.append("-")
            else:
                parts.append(str(val))

        joined = "|".join(parts)
        if joined in ("|", "-|-"):
            return "none"

        return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:10]

    return df.apply(build_key, axis=1)


def load_and_label_directory(parsed_subdir: Path, label: int) -> pd.DataFrame:
    """Читает все CSV в поддиректории parsed_subdir, присваивает им одну и ту же метку."""
    if not parsed_subdir.exists():
        raise FileNotFoundError(f"Subdirectory not found: {parsed_subdir}")

    csv_files = sorted(parsed_subdir.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {parsed_subdir}. "
            f"Run batch_parse_pcaps.py first to produce CSVs from PCAPs."
        )

    frames = []
    for csv_path in csv_files:
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            print(f"[WARN] Could not read {csv_path}: {e}")
            continue

        if df.empty:
            print(f"[WARN] Empty CSV skipped: {csv_path}")
            continue

        # Относительный путь как идентификатор источника
        rel_source = str(csv_path.relative_to(parsed_subdir)).replace("\\", "/")

        df["label"] = int(label)
        df["source_file"] = rel_source
        df["group_name"] = "user_benign" if label == 0 else "user_malicious"
        df["tool"] = "user_data"

        df["ja4_present"] = derive_ja4_present(df)
        df["ja4_key"] = derive_ja4_key(df)

        frames.append(df)
        print(f"[OK]   loaded {len(df):>6} flows from {rel_source}  (label={label})")

    if not frames:
        raise ValueError(f"No usable CSVs found in {parsed_subdir}")

    return pd.concat(frames, ignore_index=True)


def stratified_split_by_source(
    df: pd.DataFrame,
    val_frac: float,
    test_frac: float,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Стратифицированное разбиение на train/val/test.
    Принцип: разбиваем внутри каждого класса отдельно (чтобы сохранить баланс),
    по возможности по source_file (чтобы один PCAP не оказался частично в train
    и частично в test — источники данных не пересекаются между выборками).
    Если в классе всего один source_file — используем случайное построчное разбиение
    этого источника.
    """
    rng = np.random.default_rng(seed)

    train_parts, val_parts, test_parts = [], [], []

    for label_value in sorted(df["label"].unique()):
        class_df = df[df["label"] == label_value].copy()
        sources = class_df["source_file"].unique().tolist()
        rng.shuffle(sources)

        # Если источник один — построчное стратифицированное разбиение
        if len(sources) == 1:
            class_df = class_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
            n = len(class_df)
            n_test = max(1, int(round(n * test_frac)))
            n_val = max(1, int(round(n * val_frac)))
            n_test = min(n_test, n - 2)
            n_val = min(n_val, n - n_test - 1)

            test_parts.append(class_df.iloc[:n_test])
            val_parts.append(class_df.iloc[n_test:n_test + n_val])
            train_parts.append(class_df.iloc[n_test + n_val:])
            continue

        # Несколько источников — разбиваем по источникам
        n_sources = len(sources)
        n_test_src = max(1, int(round(n_sources * test_frac)))
        n_val_src = max(1, int(round(n_sources * val_frac)))
        n_test_src = min(n_test_src, n_sources - 2)
        n_val_src = min(n_val_src, n_sources - n_test_src - 1)

        test_sources = set(sources[:n_test_src])
        val_sources = set(sources[n_test_src:n_test_src + n_val_src])
        train_sources = set(sources[n_test_src + n_val_src:])

        train_parts.append(class_df[class_df["source_file"].isin(train_sources)])
        val_parts.append(class_df[class_df["source_file"].isin(val_sources)])
        test_parts.append(class_df[class_df["source_file"].isin(test_sources)])

    train_df = pd.concat(train_parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    val_df = pd.concat(val_parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    test_df = pd.concat(test_parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)

    return train_df, val_df, test_df


def print_split_summary(name: str, df: pd.DataFrame) -> None:
    if df.empty:
        print(f"  {name:<6s}: empty")
        return
    pos = int((df["label"] == 1).sum())
    neg = int((df["label"] == 0).sum())
    src = df["source_file"].nunique()
    print(f"  {name:<6s}: {len(df):>6} flows   (benign={neg}, malicious={pos}, sources={src})")


def main() -> None:
    args = parse_args()

    parsed_dir = Path(args.parsed_dir).resolve()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    benign_dir = parsed_dir / "benign"
    malicious_dir = parsed_dir / "malicious"

    print(f"[INFO] Reading parsed CSVs from: {parsed_dir}")
    print(f"[INFO] Benign    subdir: {benign_dir}")
    print(f"[INFO] Malicious subdir: {malicious_dir}")
    print()

    benign_df = load_and_label_directory(benign_dir, label=0)
    malicious_df = load_and_label_directory(malicious_dir, label=1)

    print()
    print(f"[INFO] Loaded benign    rows: {len(benign_df)}")
    print(f"[INFO] Loaded malicious rows: {len(malicious_df)}")

    if len(benign_df) < args.min_rows_per_class:
        raise ValueError(
            f"Too few benign flows: {len(benign_df)} < {args.min_rows_per_class}. "
            f"Provide more benign PCAPs."
        )
    if len(malicious_df) < args.min_rows_per_class:
        raise ValueError(
            f"Too few malicious flows: {len(malicious_df)} < {args.min_rows_per_class}. "
            f"Provide more malicious PCAPs."
        )

    combined = pd.concat([benign_df, malicious_df], ignore_index=True)

    # Согласованность колонок (на случай если парсер выдал разные наборы для разных PCAP)
    for col in SYNTHETIC_COLUMNS + ["label"]:
        if col not in combined.columns:
            raise RuntimeError(f"Missing required column after labelling: {col}")

    print()
    print(f"[INFO] Splitting {len(combined)} flows into train/val/test "
          f"(val={args.val_frac}, test={args.test_frac}, seed={args.seed})")

    train_df, val_df, test_df = stratified_split_by_source(
        combined,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
    )

    print()
    print("[INFO] Split summary:")
    print_split_summary("train", train_df)
    print_split_summary("val",   val_df)
    print_split_summary("test",  test_df)

    # Sanity check: оба класса должны быть в каждой выборке
    for split_name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        classes = set(split_df["label"].unique().tolist())
        if classes != {0, 1}:
            print(f"[WARN] {split_name} contains only classes {classes}. "
                  f"Retraining may produce a degenerate model.")

    # Сохраняем разбиение
    train_path = outdir / "train.csv"
    val_path = outdir / "val.csv"
    test_path = outdir / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    print()
    print(f"[OK] wrote: {train_path}")
    print(f"[OK] wrote: {val_path}")
    print(f"[OK] wrote: {test_path}")


if __name__ == "__main__":
    main()
