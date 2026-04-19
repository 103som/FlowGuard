#!/usr/bin/env python3
"""
Incident-oriented static analyzer для ML-scored flow CSV.

Версия 3: улучшенные названия категорий + объединение дублирующихся категорий.

Ключевые изменения относительно v2:
1. Короткие и понятные названия категорий (без скобок и англицизмов)
2. Объединение схожих паттернов в одну категорию (было 18 → стало 10)
3. Все остальные правила и приоритеты сохранены

Итоговые 10 категорий:
  Приоритет 1 (групповые паттерны):
    1. Периодический TLS-маяк
    2. Сканирование портов
    3. DoS-флуд
  Приоритет 2 (fan-out клиента):
    4. Веерное сканирование портов
    5. Сканирование сети
  Приоритет 3 (повторяющиеся паттерны):
    6. Повторяющиеся TLS-сеансы (объединяет "короткие" и "длительные малошумные")
    7. Неуспешные соединения
  Приоритет 4 (объёмные):
    8. Исходящая эксфильтрация
    9. Крупный входящий поток
  Приоритет 5 (TLS-аномалии одиночных сессий):
    10. Подозрительный TLS-профиль (объединяет: без SNI, нестандартный ALPN, нестандартный порт)
  Приоритет 6 (контекст клиента):
    11. Активный TLS-клиент
  Fallback:
    12. Неклассифицированная аномалия
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

COMMON_ALPN = {
    "none", "-", "http/1.1", "h2", "h2;http/1.1", "http/1.1;h2",
}

TLS_PORTS = {443, 8443, 9443}
GENERIC_INPUT_NAMES = {"scored_flows", "scored_flows_enriched", "anomaly_events", "scored"}

NUMERIC_COLUMNS = [
    "anomaly_score", "is_anomaly", "first_ts_ns", "last_ts_ns", "duration_ns", "proto",
    "packets_total", "packets_c2s", "packets_s2c", "bytes_cap_total", "bytes_cap_c2s", "bytes_cap_s2c",
    "bytes_wire_total", "bytes_wire_c2s", "bytes_wire_s2c", "tcp_syn_total", "tcp_syn_c2s",
    "tcp_synack_s2c", "tcp_ack_total", "tcp_fin_total", "tcp_rst_total", "tcp_psh_total",
    "tls_client_hello_c2s", "avg_wirelen_total", "ja4_present", "ja4_cipher_suites_count",
    "ja4_extensions_count", "ja4_has_sni", "client_port", "server_port",
]

STRING_COLUMNS = ["client_ip", "server_ip", "ja4_legacy_version", "ja4_alpn"]

INCIDENT_COLUMNS = [
    "incident_id", "time_start_s", "time_end_s", "client_ip", "server_ip", "server_port",
    "category", "severity_level", "severity_score", "flows", "avg_score", "max_score",
    "duration_median_s", "packets_median", "bytes_median", "characteristic",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compact incident-oriented analyzer for scored flow CSV")
    p.add_argument("--input", required=True)
    p.add_argument("--outdir", default=None)
    p.add_argument("--report-name", default=None)
    p.add_argument("--reports-root", default=None)
    p.add_argument("--score-threshold", type=float, default=None)
    p.add_argument("--timeline-bucket-seconds", type=int, default=60)
    p.add_argument("--top-k", type=int, default=100)
    return p.parse_args()


def sanitize_name(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("._-")
    return cleaned or "report"


def default_reports_root() -> Path:
    return (Path.cwd() / "../../reports").resolve()


def derive_base_name(input_path: Path) -> str:
    if input_path.stem in GENERIC_INPUT_NAMES and input_path.parent.name:
        return sanitize_name(input_path.parent.name)
    return sanitize_name(input_path.stem)


def allocate_report_dir(root: Path, base_name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    candidate = root / f"{base_name}_report"
    if not candidate.exists():
        return candidate
    index = 1
    while True:
        candidate = root / f"{base_name}_report_{index:02d}"
        if not candidate.exists():
            return candidate
        index += 1


def resolve_output_dir(args: argparse.Namespace, input_path: Path) -> Path:
    if args.outdir:
        outdir = Path(args.outdir).expanduser().resolve()
        outdir.mkdir(parents=True, exist_ok=True)
        return outdir
    root = Path(args.reports_root).expanduser().resolve() if args.reports_root else default_reports_root()
    base_name = sanitize_name(args.report_name) if args.report_name else derive_base_name(input_path)
    outdir = allocate_report_dir(root, base_name)
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def ensure_columns(df: pd.DataFrame, numeric_cols: Iterable[str], string_cols: Iterable[str]) -> pd.DataFrame:
    df = df.copy()
    for col in numeric_cols:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    for col in string_cols:
        if col not in df.columns:
            df[col] = "none"
        df[col] = df[col].astype("string").fillna("none").replace({"<NA>": "none", "nan": "none", "": "none"})

    return df


def safe_div(a, b, default: float = 0.0):
    a_arr = np.asarray(a, dtype=float)
    b_arr = np.asarray(b, dtype=float)
    out = np.full_like(a_arr, fill_value=default, dtype=float)
    np.divide(a_arr, b_arr, out=out, where=np.abs(b_arr) > 1e-12)
    return out


def derive_features(df: pd.DataFrame, timeline_bucket_seconds: int) -> pd.DataFrame:
    df = ensure_columns(df, NUMERIC_COLUMNS, STRING_COLUMNS)
    out = df.copy()

    out["ja4_present"] = np.where(
        (out["ja4_present"] > 0)
        | (out["tls_client_hello_c2s"] > 0)
        | (out["ja4_legacy_version"].astype(str).str.lower() != "none")
        | (out["ja4_alpn"].astype(str).str.lower() != "none"),
        1, 0,
    )

    out["duration_s"] = out["duration_ns"] / 1e9
    out["bytes_per_packet"] = safe_div(out["bytes_wire_total"], out["packets_total"])
    out["bytes_per_s"] = safe_div(out["bytes_wire_total"], out["duration_s"], default=0.0)
    out["c2s_to_s2c_ratio"] = safe_div(out["bytes_wire_c2s"], np.maximum(out["bytes_wire_s2c"], 1))
    out["s2c_to_c2s_ratio"] = safe_div(out["bytes_wire_s2c"], np.maximum(out["bytes_wire_c2s"], 1))

    out["is_tls"] = np.where(
        (out["tls_client_hello_c2s"] > 0)
        | (out["ja4_present"] > 0)
        | (out["server_port"].isin(list(TLS_PORTS))),
        1, 0,
    )

    out["is_tls_nonstandard_port"] = np.where(
        (out["is_tls"] == 1) & (~out["server_port"].isin(list(TLS_PORTS))),
        1, 0,
    )

    first_ts = pd.to_numeric(out["first_ts_ns"], errors="coerce").fillna(0)
    bucket_ns = max(int(timeline_bucket_seconds), 1) * 1_000_000_000
    out["timeline_bucket_id"] = (first_ts // bucket_ns).astype("int64")
    out["timeline_bucket_s"] = (out["timeline_bucket_id"] * max(int(timeline_bucket_seconds), 1)).astype("int64")

    return out


def filter_candidates(df: pd.DataFrame, score_threshold: float | None) -> pd.DataFrame:
    if score_threshold is not None:
        return df[df["anomaly_score"] >= score_threshold].copy()
    if "is_anomaly" in df.columns:
        return df[df["is_anomaly"] == 1].copy()
    return df[df["anomaly_score"] >= 0.5].copy()


def _pair_interarrival_stats(group: pd.DataFrame) -> pd.Series:
    starts = group["first_ts_ns"].sort_values().to_numpy(dtype=np.int64)
    if len(starts) < 2:
        return pd.Series({
            "median_interarrival_s": 0.0,
            "std_interarrival_s": 0.0,
            "cv_interarrival": 0.0,
        })
    deltas = np.diff(starts) / 1e9
    med = float(np.median(deltas))
    std = float(np.std(deltas))
    cv = float(std / med) if med > 1e-12 else 0.0
    return pd.Series({
        "median_interarrival_s": med,
        "std_interarrival_s": std,
        "cv_interarrival": cv,
    })


def compute_client_fanout(candidates: pd.DataFrame) -> pd.DataFrame:
    """
    Вычисляет fan-out статистики на уровне client_ip.
    
    Возвращает DataFrame с колонками:
    - client_ip
    - client_unique_servers: сколько уникальных server_ip у этого клиента
    - client_unique_ports: сколько уникальных server_port
    - client_total_flows: всего аномальных flows от этого клиента
    - client_tls_ratio: доля TLS-flows
    """
    if candidates.empty:
        return pd.DataFrame(columns=[
            "client_ip", "client_unique_servers", "client_unique_ports",
            "client_total_flows", "client_tls_ratio"
        ])
    
    fanout = (
        candidates.groupby("client_ip", dropna=False)
        .agg(
            client_unique_servers=("server_ip", "nunique"),
            client_unique_ports=("server_port", "nunique"),
            client_total_flows=("server_ip", "size"),
            client_tls_ratio=("is_tls", "mean"),
        )
        .reset_index()
    )
    return fanout


def build_incidents(candidates: pd.DataFrame) -> pd.DataFrame:
    if candidates.empty:
        return pd.DataFrame(columns=INCIDENT_COLUMNS)

    # Вычисляем fan-out на уровне client_ip
    client_fanout = compute_client_fanout(candidates)

    grp_cols = ["client_ip", "server_ip", "server_port"]

    base = (
        candidates.groupby(grp_cols, dropna=False)
        .agg(
            flows=("client_ip", "size"),
            time_start_s=("first_ts_ns", lambda s: float(np.min(s) / 1e9)),
            time_end_s=("last_ts_ns", lambda s: float(np.max(s) / 1e9)),
            avg_score=("anomaly_score", "mean"),
            max_score=("anomaly_score", "max"),
            duration_median_s=("duration_s", "median"),
            duration_mean_s=("duration_s", "mean"),
            packets_median=("packets_total", "median"),
            packets_mean=("packets_total", "mean"),
            bytes_median=("bytes_wire_total", "median"),
            bytes_mean=("bytes_wire_total", "mean"),
            bytes_std=("bytes_wire_total", "std"),
            bytes_total_sum=("bytes_wire_total", "sum"),
            bytes_c2s_sum=("bytes_wire_c2s", "sum"),
            bytes_s2c_sum=("bytes_wire_s2c", "sum"),
            rst_sum=("tcp_rst_total", "sum"),
            syn_sum=("tcp_syn_total", "sum"),
            tls_ratio=("is_tls", "mean"),
            tls_hello_ratio=("tls_client_hello_c2s", lambda s: float(np.mean(s > 0))),
            no_sni_ratio=("ja4_has_sni", lambda s: float(np.mean(s <= 0))),
            nonstandard_tls_ratio=("is_tls_nonstandard_port", "mean"),
            ja4_ext_median=("ja4_extensions_count", "median"),
            ja4_cipher_median=("ja4_cipher_suites_count", "median"),
            unique_alpn=("ja4_alpn", lambda s: int(pd.Series(s.astype(str)).nunique())),
            common_alpn_ratio=("ja4_alpn", lambda s: float(np.mean(pd.Series(s.astype(str)).str.lower().isin(COMMON_ALPN)))),
            empty_alpn_ratio=("ja4_alpn", lambda s: float(np.mean(pd.Series(s.astype(str)).str.lower().isin({"none", "-"})))),
        )
        .reset_index()
    )

    interarrival = (
        candidates.groupby(grp_cols, dropna=False)
        .apply(_pair_interarrival_stats, include_groups=False)
        .reset_index()
    )

    incidents = base.merge(interarrival, on=grp_cols, how="left")
    incidents = incidents.merge(client_fanout, on="client_ip", how="left")
    
    # Заполняем NaN
    incidents["bytes_std"] = incidents["bytes_std"].fillna(0)

    # Коэффициент вариации размера (для детекции beacon-паттернов)
    incidents["bytes_cv"] = safe_div(
        incidents["bytes_std"], 
        np.maximum(incidents["bytes_mean"], 1),
    )
    
    incidents["bytes_per_s_median"] = safe_div(
        incidents["bytes_median"], 
        np.maximum(incidents["duration_median_s"], 1e-9),
    )
    incidents["outbound_ratio"] = safe_div(
        incidents["bytes_c2s_sum"], 
        np.maximum(incidents["bytes_s2c_sum"], 1),
    )
    incidents["inbound_ratio"] = safe_div(
        incidents["bytes_s2c_sum"], 
        np.maximum(incidents["bytes_c2s_sum"], 1),
    )

    categories = []
    characteristics = []
    severity_scores = []
    severity_levels = []

    for _, row in incidents.iterrows():
        category, char_ru, bonus = classify_incident(row)
        sev_score, sev_level = severity_from(float(row["avg_score"]), bonus)
        categories.append(category)
        characteristics.append(char_ru)
        severity_scores.append(sev_score)
        severity_levels.append(sev_level)

    incidents["category"] = categories
    incidents["characteristic"] = characteristics
    incidents["severity_score"] = severity_scores
    incidents["severity_level"] = severity_levels
    incidents["incident_id"] = [f"inc_{i:05d}" for i in range(1, len(incidents) + 1)]

    incidents = incidents.sort_values(
        ["severity_score", "avg_score", "flows"], 
        ascending=[False, False, False],
    ).reset_index(drop=True)

    for col in INCIDENT_COLUMNS:
        if col not in incidents.columns:
            incidents[col] = ""

    return incidents[INCIDENT_COLUMNS]


def classify_incident(row: pd.Series) -> tuple[str, str, int]:
    """
    Классифицирует инцидент. Правила упорядочены по приоритету:
    1. Сильные групповые паттерны (маяк, сканирование, DoS)
    2. Веерные паттерны на уровне клиента
    3. Повторяющиеся групповые паттерны
    4. Объёмные характеристики (эксфильтрация, крупный входящий)
    5. Аномалии TLS-профиля
    6. Контекст клиента для одиночных сессий
    7. Fallback

    Итого 10 категорий (объединены дублирующиеся паттерны из v2).
    """
    flows = int(row["flows"])
    avg_score = float(row["avg_score"])
    duration = float(row["duration_median_s"])
    packets = float(row["packets_median"])
    bytes_med = float(row["bytes_median"])
    bytes_cv = float(row.get("bytes_cv", 0.0))
    tls_ratio = float(row["tls_ratio"])
    server_port = int(row["server_port"])
    median_gap = float(row.get("median_interarrival_s", 0.0))
    cv_gap = float(row.get("cv_interarrival", 0.0))
    bytes_per_s = float(row.get("bytes_per_s_median", 0.0))
    outbound_ratio = float(row.get("outbound_ratio", 0.0))
    inbound_ratio = float(row.get("inbound_ratio", 0.0))
    rst_sum = float(row.get("rst_sum", 0.0))
    nonstandard_tls_ratio = float(row.get("nonstandard_tls_ratio", 0.0))
    no_sni_ratio = float(row.get("no_sni_ratio", 0.0))
    common_alpn_ratio = float(row.get("common_alpn_ratio", 0.0))
    empty_alpn_ratio = float(row.get("empty_alpn_ratio", 0.0))

    client_unique_servers = int(row.get("client_unique_servers", 1))
    client_unique_ports = int(row.get("client_unique_ports", 1))
    client_total_flows = int(row.get("client_total_flows", 1))

    # ==========================================================
    # ПРИОРИТЕТ 1: Сильные групповые паттерны
    # ==========================================================

    # 1.1. Периодический TLS-маяк
    # Объединяет бывшие "Периодический TLS-маяк" + "Длительный малошумный TLS-канал" +
    # "Повторяющиеся короткие TLS-сеансы" (т.к. все три — разновидности маяка/C2)
    if (
        tls_ratio >= 0.7
        and flows >= 5
        and 20.0 <= duration <= 200.0
        and packets <= 30
        and bytes_med <= 15000
        and 10.0 <= median_gap <= 900.0
        and cv_gap <= 0.5
        and bytes_cv <= 0.3
    ):
        return (
            "Периодический TLS-маяк",
            f"Регулярные идентичные TLS-сессии: {flows} сеансов с интервалом "
            f"~{median_gap:.0f}с, длительность ~{duration:.0f}с, "
            f"объём ~{bytes_med:.0f} Б (стабилен, CV={bytes_cv:.2f})",
            22,
        )

    # 1.2. Сканирование портов (к одной цели)
    if (
        flows >= 5
        and duration < 1.0
        and packets <= 5
        and rst_sum >= flows * 0.5
    ):
        return (
            "Сканирование портов",
            f"Сканирование TCP-портов: {flows} коротких соединений, "
            f"RST={rst_sum:.0f}, пакетов ~{packets:.0f}",
            20,
        )

    # 1.3. DoS-флуд
    if (
        flows >= 20
        and duration < 2.0
        and packets <= 10
    ):
        return (
            "DoS-флуд",
            f"Массовые короткие соединения к одной цели: {flows} соединений, "
            f"длительность ~{duration:.2f}с",
            18,
        )

    # ==========================================================
    # ПРИОРИТЕТ 2: Веерные паттерны на уровне клиента
    # ==========================================================

    # 2.1. Веерное сканирование портов
    if (
        client_unique_ports >= 20
        and client_unique_servers <= 3
        and packets <= 5
        and duration < 2.0
    ):
        return (
            "Веерное сканирование портов",
            f"Клиент сканирует {client_unique_ports} портов "
            f"на {client_unique_servers} серверах: длительность ~{duration:.2f}с, "
            f"пакетов ~{packets:.0f}",
            20,
        )

    # 2.2. Сканирование сети
    if (
        client_unique_servers >= 20
        and packets <= 5
        and duration < 2.0
    ):
        return (
            "Сканирование сети",
            f"Клиент обращается к {client_unique_servers} серверам "
            f"короткими соединениями: пакетов ~{packets:.0f}",
            18,
        )

    # ==========================================================
    # ПРИОРИТЕТ 3: Повторяющиеся групповые паттерны
    # ==========================================================

    # 3.1. Повторяющиеся TLS-сеансы
    # Объединяет бывшие "Повторяющиеся короткие TLS-сеансы" + "Длительный малошумный TLS-канал"
    if (
        tls_ratio >= 0.7
        and flows >= 4
        and bytes_cv <= 0.4
    ):
        if duration <= 5.0:
            return (
                "Повторяющиеся TLS-сеансы",
                f"Серия похожих коротких TLS-соединений: {flows} сеансов, "
                f"длительность ~{duration:.1f}с, объём ~{bytes_med:.0f} Б",
                16,
            )
        elif 5.0 < duration <= 180.0 and bytes_per_s <= 2000:
            return (
                "Повторяющиеся TLS-сеансы",
                f"Серия длительных малошумных TLS-сеансов: {flows} сеансов, "
                f"длительность ~{duration:.1f}с, объём ~{bytes_med:.0f} Б",
                16,
            )

    # 3.2. Неуспешные соединения
    if rst_sum >= 1 and flows >= 3 and packets <= 15:
        return (
            "Неуспешные соединения",
            f"Серия соединений с RST/сбоями: {flows} сессий, "
            f"RST={rst_sum:.0f}, пакетов ~{packets:.0f}",
            12,
        )

    # ==========================================================
    # ПРИОРИТЕТ 4: Объёмные характеристики
    # ==========================================================

    # 4.1. Исходящая эксфильтрация
    if row["bytes_c2s_sum"] >= 1_000_000 and outbound_ratio >= 3.0:
        return (
            "Исходящая эксфильтрация",
            f"Преобладание исходящего трафика: "
            f"исх={row['bytes_c2s_sum']:.0f} Б, вх={row['bytes_s2c_sum']:.0f} Б, "
            f"отношение={outbound_ratio:.1f}",
            15,
        )

    # 4.2. Крупный входящий поток
    if row["bytes_s2c_sum"] >= 1_000_000 and inbound_ratio >= 3.0:
        return (
            "Крупный входящий поток",
            f"Преобладание входящего трафика: "
            f"вх={row['bytes_s2c_sum']:.0f} Б, исх={row['bytes_c2s_sum']:.0f} Б",
            8,
        )

    # ==========================================================
    # ПРИОРИТЕТ 5: Подозрительный TLS-профиль (объединённая категория)
    # Включает: TLS без SNI, TLS без ALPN, TLS на нестандартном порту
    # ==========================================================

    if tls_ratio >= 0.5:
        reasons = []
        severity_bonus = 10
        if server_port not in TLS_PORTS and server_port > 1024:
            reasons.append(f"нестандартный порт {server_port}")
            severity_bonus = max(severity_bonus, 12)
        if no_sni_ratio >= 0.5:
            reasons.append(f"отсутствует SNI у {no_sni_ratio:.0%} сессий")
        if empty_alpn_ratio >= 0.5 or common_alpn_ratio < 0.3:
            reasons.append(f"не-браузерный ALPN")

        if reasons:
            return (
                "Подозрительный TLS-профиль",
                f"TLS-профиль содержит признаки не-браузерного стека: "
                f"{'; '.join(reasons)}. Сессий: {flows}, длительность ~{duration:.1f}с",
                severity_bonus,
            )

    # ==========================================================
    # ПРИОРИТЕТ 6: Активный TLS-клиент (контекст fan-out для singleton сессий)
    # ==========================================================

    if flows == 1 and client_total_flows >= 30:
        if client_unique_servers >= 20:
            return (
                "Активный TLS-клиент",
                f"Клиент проявляет атипично широкую активность: "
                f"{client_total_flows} аномальных сессий к "
                f"{client_unique_servers} серверам. Данная сессия: "
                f"длительность ~{duration:.1f}с, объём ~{bytes_med:.0f} Б",
                8,
            )

    # ==========================================================
    # FALLBACK: Неклассифицированная аномалия
    # Объединяет бывшие "TLS-аномалия без явного паттерна", "Короткая TLS-сессия",
    # "Длительное малошумное TLS-соединение", "Нетипичный трафик"
    # ==========================================================

    if tls_ratio >= 0.5:
        # Короткая
        if flows <= 2 and duration < 2.0 and bytes_med < 15000:
            return (
                "Неклассифицированная аномалия",
                f"Короткое TLS-соединение без явного паттерна: "
                f"длительность ~{duration:.2f}с, объём ~{bytes_med:.0f} Б",
                4,
            )
        # Длинная малошумная
        if flows <= 2 and duration > 30.0 and bytes_per_s < 1000:
            return (
                "Неклассифицированная аномалия",
                f"Длительное малошумное TLS-соединение: "
                f"длительность ~{duration:.0f}с, скорость ~{bytes_per_s:.0f} Б/с",
                5,
            )
        # Просто TLS-аномалия
        return (
            "Неклассифицированная аномалия",
            f"TLS-соединение помечено моделью как аномалия: "
            f"сессий={flows}, длительность ~{duration:.1f}с, "
            f"объём ~{bytes_med:.0f} Б",
            3,
        )

    return (
        "Неклассифицированная аномалия",
        f"Поток помечен моделью как аномалия: "
        f"сессий={flows}, длительность ~{duration:.1f}с, "
        f"объём ~{bytes_med:.0f} Б, пакетов ~{packets:.0f}",
        2,
    )


def severity_from(avg_score: float, bonus: int) -> tuple[int, str]:
    final = int(round(min(max(avg_score * 100 + bonus, 0), 100)))
    if final >= 80:
        return final, "Критический"
    if final >= 60:
        return final, "Высокий"
    if final >= 40:
        return final, "Средний"
    return final, "Низкий"


def build_timeline(candidates: pd.DataFrame) -> pd.DataFrame:
    if candidates.empty:
        return pd.DataFrame(columns=["timeline_bucket_s", "anomaly_flows", "avg_score"])
    return (
        candidates.groupby("timeline_bucket_s", dropna=False)
        .agg(
            anomaly_flows=("timeline_bucket_s", "size"),
            avg_score=("anomaly_score", "mean"),
        )
        .reset_index()
        .sort_values("timeline_bucket_s")
    )


def build_label_stats(incidents: pd.DataFrame) -> pd.DataFrame:
    if incidents.empty:
        return pd.DataFrame(columns=["category", "incidents", "flows_sum"])
    return (
        incidents.groupby("category", dropna=False)
        .agg(
            incidents=("category", "size"),
            flows_sum=("flows", "sum"),
        )
        .reset_index()
        .sort_values(["incidents", "flows_sum"], ascending=[False, False])
    )


def compact_flow_view(candidates: pd.DataFrame) -> pd.DataFrame:
    keep = [
        "first_ts_ns", "client_ip", "server_ip", "server_port",
        "anomaly_score", "duration_s", "packets_total", "bytes_wire_total",
        "ja4_alpn", "ja4_has_sni", "tls_client_hello_c2s",
    ]
    keep = [c for c in keep if c in candidates.columns]
    out = candidates[keep].copy()
    if "first_ts_ns" in out.columns:
        out["time_start_s"] = (out["first_ts_ns"] / 1e9).round(3)
        cols = ["time_start_s"] + [c for c in out.columns if c != "time_start_s"]
        out = out[cols]
        out = out.drop(columns=["first_ts_ns"], errors="ignore")
    return out


def write_outputs(
    outdir: Path,
    input_path: Path,
    enriched_all: pd.DataFrame,
    candidates: pd.DataFrame,
    incidents: pd.DataFrame,
    timeline: pd.DataFrame,
    label_stats: pd.DataFrame,
    top_k: int,
) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    summary = {
        "flows_total": int(len(enriched_all)),
        "anomalous_flows_total": int(len(candidates)),
        "incidents_total": int(len(incidents)),
        "anomaly_share": float(len(candidates) / len(enriched_all)) if len(enriched_all) else 0.0,
        "distinct_clients": int(enriched_all["client_ip"].nunique()) if "client_ip" in enriched_all.columns else 0,
        "distinct_servers": int(enriched_all["server_ip"].nunique()) if "server_ip" in enriched_all.columns else 0,
        "tls_flows_total": int((enriched_all["is_tls"] == 1).sum()) if "is_tls" in enriched_all.columns else 0,
        "top_category": None if incidents.empty else str(incidents["category"].value_counts().idxmax()),
        "report_dir": str(outdir),
        "source_input": str(input_path),
    }

    (outdir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), 
        encoding="utf-8",
    )

    top_incidents = incidents.head(top_k).copy()
    top_incidents.to_csv(outdir / "top_incidents.csv", index=False)
    try:
        top_incidents.to_excel(outdir / "top_incidents.xlsx", index=False)
    except Exception as e:
        print(f"[WARN] Could not write xlsx: {e}")

    incidents.to_csv(outdir / "all_incidents.csv", index=False)
    timeline.to_csv(outdir / "timeline.csv", index=False)
    label_stats.to_csv(outdir / "category_stats.csv", index=False)

    compact_flows = compact_flow_view(candidates).head(300)
    compact_flows.to_csv(outdir / "anomalous_flow_samples.csv", index=False)

    enriched_all.to_csv(outdir / "scored_flows_enriched.csv", index=False)


def main() -> None:
    args = parse_args()

    input_path = Path(args.input).expanduser().resolve()
    outdir = resolve_output_dir(args, input_path)

    raw = pd.read_csv(input_path)
    enriched_all = derive_features(raw, timeline_bucket_seconds=args.timeline_bucket_seconds)
    candidates = filter_candidates(enriched_all, score_threshold=args.score_threshold)

    incidents = build_incidents(candidates)
    timeline = build_timeline(candidates)
    label_stats = build_label_stats(incidents)

    write_outputs(
        outdir=outdir,
        input_path=input_path,
        enriched_all=enriched_all,
        candidates=candidates,
        incidents=incidents,
        timeline=timeline,
        label_stats=label_stats,
        top_k=args.top_k,
    )

    summary = json.loads((outdir / "summary.json").read_text(encoding="utf-8"))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[OK] report dir: {outdir}")
    print(f"[OK] wrote: {outdir / 'top_incidents.csv'}")
    print(f"[OK] wrote: {outdir / 'all_incidents.csv'}")
    print(f"[OK] wrote: {outdir / 'timeline.csv'}")
    print(f"[OK] wrote: {outdir / 'category_stats.csv'}")
    print(f"[OK] wrote: {outdir / 'summary.json'}")

    # Диагностика — печатаем распределение категорий
    print("\n[INFO] Category distribution:")
    for _, lrow in label_stats.iterrows():
        print(f"  {lrow['category']:<55} incidents={lrow['incidents']:>4}, flows={lrow['flows_sum']:>5}")


if __name__ == "__main__":
    main()
