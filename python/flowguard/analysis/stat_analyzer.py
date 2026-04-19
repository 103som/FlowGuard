#!/usr/bin/env python3
"""
Incident-oriented static analyzer для ML-scored flow CSV.

Версия 2: улучшенная классификация.

Ключевые улучшения:
1. Анализ на уровне client_ip (fan-out паттерны)
2. Классификация одиночных flows (не требует группировки)
3. Приоритизированная система правил
4. Снижение доли "ML-аномалия без объяснения" с ~90% до <20%
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
    1. Сильные групповые паттерны (beacon, scan) — highest priority
    2. Fan-out паттерны на уровне клиента
    3. Характеристики самого flow (TLS-аномалии, объём)
    4. Общие групповые правила (повторные соединения)
    5. Fallback: одиночный подозрительный TLS-flow
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
    
    # Fan-out статистики клиента
    client_unique_servers = int(row.get("client_unique_servers", 1))
    client_unique_ports = int(row.get("client_unique_ports", 1))
    client_total_flows = int(row.get("client_total_flows", 1))

    # ==========================================================
    # PRIORITY 1: Групповые паттерны — самые специфичные
    # ==========================================================

    # 1.1. Периодический TLS-маяк (C2 beacon)
    # Сильный паттерн: повторяющиеся одинаковые соединения с регулярным интервалом
    if (
        tls_ratio >= 0.7
        and flows >= 5
        and 20.0 <= duration <= 200.0
        and packets <= 30
        and bytes_med <= 15000
        and 10.0 <= median_gap <= 900.0
        and cv_gap <= 0.5
        and bytes_cv <= 0.3  # размер сессий стабилен
    ):
        return (
            "Периодический TLS-маяк (C2 beacon)",
            f"Регулярные идентичные TLS-сессии: flows={flows}, "
            f"интервал≈{median_gap:.0f}с, длительность≈{duration:.0f}с, "
            f"объём≈{bytes_med:.0f} Б (стабилен, CV={bytes_cv:.2f})",
            22,
        )

    # 1.2. Сканирование портов (scan к одному серверу)
    # Fan-out на уровне (client, server) но с разными портами, короткие соединения
    if (
        flows >= 5
        and duration < 1.0
        and packets <= 5
        and rst_sum >= flows * 0.5  # половина соединений с RST
    ):
        return (
            "Сканирование портов",
            f"Сканирование TCP-портов: flows={flows}, RST={rst_sum:.0f}, "
            f"длительность≈{duration:.2f}с, пакеты≈{packets:.0f}",
            20,
        )

    # 1.3. DDoS / flood к одной паре (client, server, port)
    if (
        flows >= 20
        and duration < 2.0
        and packets <= 10
    ):
        return (
            "DoS / flood к одной цели",
            f"Массовые короткие соединения к одной цели: flows={flows}, "
            f"длительность≈{duration:.2f}с",
            18,
        )

    # ==========================================================
    # PRIORITY 2: Fan-out паттерны на уровне клиента
    # ==========================================================

    # 2.1. Port scan (клиент → много портов на одном сервере)
    if (
        client_unique_ports >= 20
        and client_unique_servers <= 3
        and packets <= 5
        and duration < 2.0
    ):
        return (
            "Сканирование портов (fan-out)",
            f"Клиент сканирует {client_unique_ports} портов "
            f"на {client_unique_servers} серверах: flow_duration≈{duration:.2f}с, "
            f"packets≈{packets:.0f}",
            20,
        )

    # 2.2. Host discovery / network scan (клиент → много серверов)
    if (
        client_unique_servers >= 20
        and packets <= 5
        and duration < 2.0
    ):
        return (
            "Сканирование сети (host discovery)",
            f"Клиент обращается к {client_unique_servers} серверам "
            f"короткими соединениями: packets≈{packets:.0f}, duration≈{duration:.2f}с",
            18,
        )

    # 2.3. Активный клиент с большим числом TLS-соединений к разным серверам
    # (подозрительно если это не браузер — см. fallback ниже)
    # Здесь просто отмечаем для статистики, финальная классификация ниже

    # ==========================================================
    # PRIORITY 3: Повторяющиеся групповые паттерны (менее строгие)
    # ==========================================================

    # 3.1. Повторяющиеся TLS-сеансы к одному серверу
    if (
        tls_ratio >= 0.7
        and flows >= 4
        and bytes_cv <= 0.4  # размер сессий относительно стабилен
    ):
        # Различаем по длительности
        if duration <= 5.0:
            return (
                "Повторяющиеся короткие TLS-сеансы",
                f"Серия похожих коротких TLS-соединений: flows={flows}, "
                f"длительность≈{duration:.1f}с, объём≈{bytes_med:.0f} Б",
                16,
            )
        elif 5.0 < duration <= 180.0 and bytes_per_s <= 2000:
            return (
                "Длительный малошумный TLS-канал",
                f"Повторяющиеся длительные малошумные TLS-сеансы: flows={flows}, "
                f"длительность≈{duration:.1f}с, объём≈{bytes_med:.0f} Б",
                16,
            )

    # 3.2. Неуспешные соединения серией
    if rst_sum >= 1 and flows >= 3 and packets <= 15:
        return (
            "Неуспешные соединения",
            f"Серия соединений с RST/сбоями: flows={flows}, "
            f"rst_sum={rst_sum:.0f}, пакеты≈{packets:.0f}",
            12,
        )

    # ==========================================================
    # PRIORITY 4: Характеристики объёма / направления
    # ==========================================================

    # 4.1. Крупный исходящий поток (exfiltration)
    if row["bytes_c2s_sum"] >= 1_000_000 and outbound_ratio >= 3.0:
        return (
            "Крупный исходящий поток (возможная эксфильтрация)",
            f"Выраженное преобладание исходящего трафика: "
            f"c2s={row['bytes_c2s_sum']:.0f} Б, s2c={row['bytes_s2c_sum']:.0f} Б, "
            f"ratio={outbound_ratio:.1f}",
            15,
        )

    # 4.2. Крупный входящий поток (download)
    if row["bytes_s2c_sum"] >= 1_000_000 and inbound_ratio >= 3.0:
        return (
            "Крупный входящий поток",
            f"Выраженное преобладание входящего трафика: "
            f"s2c={row['bytes_s2c_sum']:.0f} Б, c2s={row['bytes_c2s_sum']:.0f} Б",
            8,
        )

    # ==========================================================
    # PRIORITY 5: Аномалии TLS (на уровне flow/пары)
    # ==========================================================

    # 5.1. TLS на нестандартном порту
    if tls_ratio >= 0.5 and (
        server_port not in TLS_PORTS
        and server_port > 1024
    ):
        return (
            "TLS на нестандартном порту",
            f"TLS-соединение на порту {server_port} (вне {sorted(TLS_PORTS)}): "
            f"flows={flows}, длительность≈{duration:.1f}с",
            12,
        )

    # 5.2. TLS без SNI
    if tls_ratio >= 0.5 and no_sni_ratio >= 0.5:
        return (
            "TLS без SNI",
            f"TLS-соединения без Server Name Indication: flows={flows}, "
            f"no_sni_ratio={no_sni_ratio:.0%}",
            10,
        )

    # 5.3. TLS без ALPN (или нестандартный ALPN)
    if tls_ratio >= 0.5 and (empty_alpn_ratio >= 0.5 or common_alpn_ratio < 0.3):
        return (
            "TLS без ALPN / нестандартный ALPN",
            f"Не-браузерный TLS-стек: flows={flows}, "
            f"empty_alpn={empty_alpn_ratio:.0%}, common_alpn={common_alpn_ratio:.0%}",
            10,
        )

    # ==========================================================
    # PRIORITY 6: Активный клиент / fan-out контекст (для singleton flows)
    # ==========================================================
    # Это одиночные flows (flows=1), но они относятся к клиенту
    # который имеет много других аномальных flows

    if flows == 1 and client_total_flows >= 30:
        # Клиент очень активный: много аномальных соединений к разным целям
        if client_unique_servers >= 20:
            return (
                "Активный клиент с множеством TLS-соединений",
                f"Клиент показывает атипичный паттерн: "
                f"{client_total_flows} аномальных flows к "
                f"{client_unique_servers} серверам. "
                f"Данное соединение: длительность≈{duration:.1f}с, "
                f"объём≈{bytes_med:.0f} Б, ALPN={row.get('unique_alpn', 'n/a')}",
                8,
            )

    # ==========================================================
    # PRIORITY 7: Одиночный flow с определёнными характеристиками
    # ==========================================================

    # 7.1. Короткое TLS-соединение с малым объёмом
    if tls_ratio >= 0.5 and flows <= 2 and duration < 2.0 and bytes_med < 15000:
        return (
            "Короткая TLS-сессия",
            f"Короткое TLS-соединение: длительность≈{duration:.2f}с, "
            f"объём≈{bytes_med:.0f} Б, пакеты≈{packets:.0f}",
            6,
        )

    # 7.2. Длинное TLS-соединение с малым объёмом (возможный idle tunnel)
    if (
        tls_ratio >= 0.5 and flows <= 2
        and duration > 30.0 and bytes_per_s < 1000
    ):
        return (
            "Длительное малошумное TLS-соединение",
            f"Длинное TLS-соединение с низкой активностью: "
            f"длительность≈{duration:.0f}с, скорость≈{bytes_per_s:.0f} Б/с, "
            f"объём≈{bytes_med:.0f} Б",
            8,
        )

    # ==========================================================
    # FALLBACK: TLS-соединение без явного паттерна
    # ==========================================================

    if tls_ratio >= 0.5:
        return (
            "TLS-аномалия без явного паттерна",
            f"TLS-соединение помечено моделью как аномалия: "
            f"flows={flows}, длительность≈{duration:.1f}с, "
            f"объём≈{bytes_med:.0f} Б, ALPN={row.get('unique_alpn', 0)} вариант(ов)",
            3,
        )

    return (
        "Нетипичный трафик",
        f"Поток помечен моделью как аномалия: "
        f"flows={flows}, длительность≈{duration:.1f}с, "
        f"объём≈{bytes_med:.0f} Б, пакеты≈{packets:.0f}",
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
