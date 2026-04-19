#!/usr/bin/env python3
"""
FlowGuard Dashboard (версия 4 — финальная).

Ключевые улучшения относительно v3:
1. Адаптивный масштаб временной шкалы (подписи не налезают друг на друга)
2. Упрощена таблица инцидентов: убран severity_score, packets_max, bytes_max
3. Синхронизированы высоты парных панелей (pie + heatmap)
4. Опциональное объединение схожих категорий (параметр --merge-categories)
5. Терминология: "инцидент" можно заменить на "кластер аномалий" (параметр --incident-label)
6. Убрана колонка severity_score из heatmap (там только severity_level)
7. Улучшена читаемость: меньше колонок, больше воздуха
"""
from __future__ import annotations

import argparse
import html
import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


SEVERITY_RU = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "Критический": "Критический",
    "Высокий": "Высокий",
    "Средний": "Средний",
    "Низкий": "Низкий",
}

# Локализация технических терминов в названиях категорий
CATEGORY_TERM_REPLACEMENTS = [
    ("(fan-out)", "(веерное)"),
    ("(C2 beacon)", "(C2-маяк)"),
    ("ML-аномалия потока", "Аномалия без явного паттерна"),
]

# Объединение схожих категорий (применяется если --merge-categories)
CATEGORY_MERGE_MAP = {
    # C2-взаимодействие
    "Периодический TLS-маяк (C2 beacon)": "C2-маяк (TLS)",
    "Периодический TLS-маяк (C2-маяк)": "C2-маяк (TLS)",
    "Длительный малошумный TLS-канал": "C2-маяк (TLS)",
    "Повторяющиеся короткие TLS-сеансы": "C2-маяк (TLS)",
    "Высокооценённый TLS-кластер": "C2-маяк (TLS)",

    # Сканирования
    "Сканирование портов (fan-out)": "Сканирование портов",
    "Сканирование портов (веерное)": "Сканирование портов",
    "Сканирование сети (host discovery)": "Сканирование сети",

    # Эксфильтрация
    "Крупный исходящий поток (возможная эксфильтрация)": "Эксфильтрация (исходящий поток)",
    "Крупный исходящий поток": "Эксфильтрация (исходящий поток)",

    # Подозрительные TLS-профили (объединяем 3 близких типа)
    "Подозрительный TLS-профиль": "Подозрительный TLS-профиль",
    "TLS без SNI": "Подозрительный TLS-профиль",
    "TLS без ALPN / нестандартный ALPN": "Подозрительный TLS-профиль",
    "TLS на нестандартном порту": "Подозрительный TLS-профиль",

    # Одиночные аномалии
    "Короткая TLS-сессия": "Одиночная TLS-аномалия",
    "Длительное малошумное TLS-соединение": "Одиночная TLS-аномалия",
    "Активный клиент с множеством TLS-соединений": "Одиночная TLS-аномалия",

    # Fallback
    "TLS-аномалия без явного паттерна": "Неклассифицированная аномалия",
    "Нетипичный трафик": "Неклассифицированная аномалия",
    "Аномалия без явного паттерна": "Неклассифицированная аномалия",
}

COLUMN_RU = {
    "incident_id": "ID",
    "time_start_s": "Время начала",
    "time_end_s": "Время окончания",
    "client_ip": "Источник",
    "server_ip": "Назначение",
    "server_port": "Порт",
    "category": "Категория",
    "severity_level": "Уровень",
    "severity_score": "Балл серьёзности",
    "avg_score": "Средняя оценка",
    "max_score": "Максимальная оценка",
    "flows": "Сессий",
    "flows_sum": "Сессий (сумма)",
    "incidents": "Инцидентов",
    "duration_median_s": "Длительность (медиана), с",
    "packets_median": "Пакеты (медиана)",
    "packets_mode": "Пакеты (мода)",
    "packets_max": "Пакеты (пик)",
    "bytes_median": "Байты (медиана)",
    "bytes_mode": "Байты (мода)",
    "bytes_max": "Байты (пик)",
    "characteristic": "Характеристика",
    "anomaly_flows": "Аномальных сессий",
    "unique_servers": "Уникальных назначений",
    "unique_clients": "Уникальных источников",
    "unique_ports": "Уникальных портов",
    "pair": "Источник → Назначение",
    "timeline_bucket_s": "Интервал",
    "anomaly_score": "Оценка аномальности",
    "duration_s": "Длительность, с",
    "packets_total": "Пакеты",
    "bytes_wire_total": "Байты",
    "top_category_in_pair": "Главная категория",
}

# Колонки главной таблицы — компактный набор
TOP_INCIDENTS_DISPLAY_COLS = [
    "incident_id",
    "time_start_s",
    "client_ip",
    "server_ip",
    "server_port",
    "category",
    "severity_level",
    "flows",
    "duration_median_s",
    "packets_median",
    "packets_mode",
    "bytes_median",
    "bytes_mode",
    "characteristic",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Генератор HTML-дашборда для отчётов FlowGuard")
    p.add_argument("--report-dir", required=True, help="Путь к папке с отчётом")
    p.add_argument("--output", default=None, help="Путь к выходному HTML")
    p.add_argument("--title", default="FlowGuard: анализ аномальной сетевой активности")
    p.add_argument("--top-n", type=int, default=200, help="Сколько инцидентов показать")
    p.add_argument("--merge-categories", action="store_true",
                   help="Объединить схожие категории (18 → ~10 для презентации)")
    p.add_argument("--incident-label", default="инцидент",
                   choices=["инцидент", "кластер", "взаимодействие"],
                   help="Как называть элементы таблицы")
    return p.parse_args()


def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        print(f"[ПРЕДУПРЕЖДЕНИЕ] Файл не найден: {path}")
        return pd.DataFrame()
    return pd.read_csv(path)


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def tr_col(value: str) -> str:
    return COLUMN_RU.get(str(value), str(value))


def tr_severity(value) -> str:
    if pd.isna(value):
        return ""
    return SEVERITY_RU.get(str(value).strip(), str(value))


def format_timestamp(value, include_date: bool = True) -> str:
    """Unix timestamp → формат даты и времени."""
    try:
        ts = float(value)
        if ts <= 0:
            return ""
        dt = datetime.fromtimestamp(ts)
        if include_date:
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        return dt.strftime("%H:%M:%S")
    except (ValueError, TypeError, OSError, OverflowError):
        return ""


def localize_category(value: str) -> str:
    """Заменяет англицизмы в названии категории на русские эквиваленты."""
    if not isinstance(value, str):
        return value
    result = value
    for src, dst in CATEGORY_TERM_REPLACEMENTS:
        result = result.replace(src, dst)
    return result


def merge_category(value: str) -> str:
    """Объединяет схожие категории в более общие (если включён режим merge)."""
    if not isinstance(value, str):
        return value
    localized = localize_category(value)
    return CATEGORY_MERGE_MAP.get(localized, CATEGORY_MERGE_MAP.get(value, localized))


def process_category(value: str, merge: bool) -> str:
    """Единая точка обработки названия категории."""
    if merge:
        return merge_category(value)
    return localize_category(value)


def translate_df(df: pd.DataFrame, merge_cats: bool = False) -> pd.DataFrame:
    """Переводит названия колонок и значения severity, форматирует даты, локализует категории."""
    out = df.copy()
    if out.empty:
        return out

    # Форматируем timestamps ДО переименования
    for col in ["time_start_s", "time_end_s"]:
        if col in out.columns:
            out[col] = out[col].map(format_timestamp)

    # Локализуем категории
    for col in ["category", "top_category_in_pair"]:
        if col in out.columns:
            out[col] = out[col].map(lambda v: process_category(v, merge_cats))

    out = out.rename(columns={c: tr_col(c) for c in out.columns})

    if "Уровень" in out.columns:
        out["Уровень"] = out["Уровень"].map(tr_severity)

    return out


def fmt_int(value) -> str:
    try:
        return f"{int(value):,}".replace(",", " ")
    except Exception:
        return "0"


def fmt_pct(value) -> str:
    try:
        return f"{100 * float(value):.2f}%"
    except Exception:
        return "0.00%"


def metric_card(title: str, value: str, subtitle: str = "", accent: str = "") -> str:
    subtitle_html = f'<div class="metric-subtitle">{html.escape(subtitle)}</div>' if subtitle else ""
    accent_cls = f" metric-card--{accent}" if accent else ""
    return f'''
    <div class="metric-card{accent_cls}">
      <div class="metric-title">{html.escape(title)}</div>
      <div class="metric-value">{html.escape(value)}</div>
      {subtitle_html}
    </div>
    '''


def fig_to_html(fig, include_js: bool = False) -> str:
    return fig.to_html(
        full_html=False,
        include_plotlyjs="inline" if include_js else False,
        config={
            "displaylogo": False,
            "responsive": True,
            "modeBarButtonsToRemove": ["lasso2d", "select2d", "autoScale2d"],
        },
    )


def chart_panel(title: str, note: str, inner_html: str, panel_id: str,
                tooltip: str = "", fixed_height: int = 0) -> str:
    tooltip_html = ""
    if tooltip:
        tooltip_html = f'<div class="panel-explainer">ℹ️ {html.escape(tooltip)}</div>'
    height_style = f' style="min-height: {fixed_height}px;"' if fixed_height > 0 else ""
    return f'''
    <div class="panel fullscreen-target" id="{panel_id}"{height_style}>
      <div class="panel-header">
        <div class="panel-title-block">
          <h2>{html.escape(title)}</h2>
          <div class="note">{html.escape(note)}</div>
        </div>
        <button class="action-btn" type="button" onclick="toggleFullscreen('{panel_id}')">Во весь экран</button>
      </div>
      {tooltip_html}
      <div class="chart-body">{inner_html}</div>
    </div>
    '''


def _format_cell(value) -> str:
    if pd.isna(value):
        return ""
    if isinstance(value, float):
        if abs(value) < 0.0001 and value != 0:
            return f"{value:.2e}"
        if abs(value - round(value)) < 0.0001:
            return str(int(round(value)))
        return f"{value:.4f}"
    return str(value)


def choose_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    cols = [c for c in desired if c in df.columns]
    if not cols:
        return df.copy()
    return df[cols].copy()


def frame_to_html(
    df: pd.DataFrame,
    table_id: str,
    max_rows: int = 50,
    height_px: int = 360,
    filterable: bool = False,
    merge_cats: bool = False,
) -> str:
    if df.empty:
        return '<div class="empty">Нет данных</div>'

    original_categories = []
    if filterable and "category" in df.columns:
        original_categories = (
            df.head(max_rows)["category"]
            .fillna("")
            .astype(str)
            .map(lambda v: process_category(v, merge_cats))
            .tolist()
        )

    view = translate_df(df.head(max_rows).copy(), merge_cats=merge_cats)
    cols = list(view.columns)
    thead_cells = []
    for col in cols:
        sort_type = "num" if pd.api.types.is_numeric_dtype(view[col]) else "str"
        thead_cells.append(
            f'<th data-col="{html.escape(col)}" data-sort-type="{sort_type}" title="Нажмите для сортировки">'
            f'{html.escape(col)}<span class="sort-indicator">↕</span></th>'
        )

    body_rows = []
    for idx, (_, row) in enumerate(view.iterrows()):
        cells = []
        for col in cols:
            raw = row[col]
            text = _format_cell(raw)
            sort_value = text
            if pd.api.types.is_numeric_dtype(view[col]):
                try:
                    sort_value = str(float(raw))
                except Exception:
                    sort_value = ""
            # Спец для severity level — цветные бейджи
            if col == "Уровень":
                css_class = {
                    "Критический": "badge-critical",
                    "Высокий": "badge-high",
                    "Средний": "badge-medium",
                    "Низкий": "badge-low",
                }.get(text, "")
                if css_class:
                    cells.append(
                        f'<td data-sort-value="{html.escape(sort_value)}">'
                        f'<span class="badge {css_class}">{html.escape(text)}</span></td>'
                    )
                    continue
            cells.append(f'<td data-sort-value="{html.escape(sort_value)}">{html.escape(text)}</td>')

        row_attrs = ""
        if filterable and idx < len(original_categories):
            row_attrs = f' data-category="{html.escape(original_categories[idx])}"'

        body_rows.append(f"<tr{row_attrs}>" + "".join(cells) + "</tr>")

    filter_attr = ' data-filterable="true"' if filterable else ""

    return f'''
    <div class="table-toolbar">
      <div class="small">Показано строк: {min(len(df), max_rows)} / {len(df)}. Нажимайте на заголовки столбцов для сортировки.</div>
    </div>
    <div class="table-scroll" style="max-height:{height_px}px;">
      <table id="{html.escape(table_id)}" class="data-table sortable-table"{filter_attr}>
        <thead><tr>{''.join(thead_cells)}</tr></thead>
        <tbody>{''.join(body_rows)}</tbody>
      </table>
    </div>
    '''


# ============================================================
# Вычисление статистик
# ============================================================

def compute_mode(series: pd.Series) -> float:
    if series.empty:
        return 0.0
    mode_values = series.mode()
    if mode_values.empty:
        return float(series.iloc[0])
    return float(mode_values.iloc[0])


def enrich_incidents_with_mode(incidents: pd.DataFrame, enriched: pd.DataFrame) -> pd.DataFrame:
    """Добавляет packets_mode, bytes_mode (и _max как справочные)."""
    if incidents.empty or enriched.empty:
        for col in ["packets_mode", "packets_max", "bytes_mode", "bytes_max"]:
            if col not in incidents.columns:
                incidents[col] = 0
        return incidents

    if "is_anomaly" in enriched.columns:
        anomalies = enriched[enriched["is_anomaly"] == 1].copy()
    else:
        anomalies = enriched.copy()

    grp_cols = ["client_ip", "server_ip", "server_port"]
    available_cols = [c for c in grp_cols if c in anomalies.columns]
    if len(available_cols) < 3:
        for col in ["packets_mode", "packets_max", "bytes_mode", "bytes_max"]:
            if col not in incidents.columns:
                incidents[col] = 0
        return incidents

    agg = (
        anomalies.groupby(grp_cols, dropna=False)
        .agg(
            packets_mode=("packets_total", compute_mode),
            packets_max=("packets_total", "max"),
            bytes_mode=("bytes_wire_total", compute_mode),
            bytes_max=("bytes_wire_total", "max"),
        )
        .reset_index()
    )

    out = incidents.merge(agg, on=grp_cols, how="left")
    for col in ["packets_mode", "packets_max", "bytes_mode", "bytes_max"]:
        if col in out.columns:
            out[col] = out[col].fillna(0).astype(int)
    return out


def compute_top_entities(enriched: pd.DataFrame, incidents: pd.DataFrame,
                          merge_cats: bool) -> dict:
    result = {
        "top_clients": pd.DataFrame(),
        "top_servers": pd.DataFrame(),
        "top_ports": pd.DataFrame(),
        "pair_stats": pd.DataFrame(),
    }

    if enriched.empty:
        return result

    if "is_anomaly" in enriched.columns:
        anomalies = enriched[enriched["is_anomaly"] == 1].copy()
    else:
        anomalies = enriched[enriched.get("anomaly_score", 0) >= 0.5].copy()

    if anomalies.empty:
        return result

    if "client_ip" in anomalies.columns:
        top_clients = (
            anomalies.groupby("client_ip", dropna=False)
            .agg(
                anomaly_flows=("client_ip", "size"),
                unique_servers=("server_ip", "nunique"),
                unique_ports=("server_port", "nunique"),
            )
            .reset_index()
            .sort_values("anomaly_flows", ascending=False)
        )
        result["top_clients"] = top_clients

    if "server_ip" in anomalies.columns:
        top_servers = (
            anomalies.groupby("server_ip", dropna=False)
            .agg(
                anomaly_flows=("server_ip", "size"),
                unique_clients=("client_ip", "nunique"),
            )
            .reset_index()
            .sort_values("anomaly_flows", ascending=False)
        )
        result["top_servers"] = top_servers

    if "server_port" in anomalies.columns:
        top_ports = (
            anomalies.groupby("server_port", dropna=False)
            .agg(
                anomaly_flows=("server_port", "size"),
                unique_servers=("server_ip", "nunique"),
            )
            .reset_index()
            .sort_values("anomaly_flows", ascending=False)
        )
        result["top_ports"] = top_ports

    if not incidents.empty and {"client_ip", "server_ip", "flows", "category"}.issubset(incidents.columns):
        pair_stats = incidents.copy()
        pair_stats["pair"] = (
            pair_stats["client_ip"].astype(str) + " → " + pair_stats["server_ip"].astype(str)
        )
        pair_agg = (
            pair_stats.groupby("pair")
            .agg(
                flows=("flows", "sum"),
                top_category_in_pair=(
                    "category",
                    lambda s: process_category(s.value_counts().idxmax(), merge_cats) if len(s) > 0 else ""
                ),
            )
            .reset_index()
            .sort_values("flows", ascending=False)
        )
        result["pair_stats"] = pair_agg

    return result


# ============================================================
# Графики
# ============================================================

def compute_adaptive_bucket_size(timeline: pd.DataFrame, default_bucket_s: int = 60) -> int:
    """Подбирает размер бакета для временной шкалы на основе общей длительности.
    Цель — получить не более ~30-40 точек на графике для читаемости."""
    if timeline.empty or "timeline_bucket_s" not in timeline.columns:
        return default_bucket_s

    total_span = float(timeline["timeline_bucket_s"].max() - timeline["timeline_bucket_s"].min())
    if total_span <= 0:
        return default_bucket_s

    current_bucket = default_bucket_s
    current_points = total_span / current_bucket

    # Хотим 20-40 точек для хорошей читаемости
    target_points = 30
    ideal_bucket = int(total_span / target_points)

    # Округляем к "красивым" значениям
    nice_values = [60, 120, 300, 600, 900, 1800, 3600]  # 1min, 2min, 5min, 10min, 15min, 30min, 1h
    for nv in nice_values:
        if nv >= ideal_bucket:
            return nv
    return nice_values[-1]


def rebucket_timeline(timeline: pd.DataFrame, target_bucket_s: int) -> pd.DataFrame:
    """Пересчитывает timeline к новому bucket size (агрегирует мелкие бакеты)."""
    if timeline.empty:
        return timeline

    src = timeline.copy()
    if "timeline_bucket_s" not in src.columns:
        return src

    # Округляем bucket к target размеру
    src["new_bucket"] = (src["timeline_bucket_s"] // target_bucket_s) * target_bucket_s

    rebucketed = (
        src.groupby("new_bucket")
        .agg(
            anomaly_flows=("anomaly_flows", "sum"),
            avg_score=("avg_score", "mean"),
        )
        .reset_index()
        .rename(columns={"new_bucket": "timeline_bucket_s"})
        .sort_values("timeline_bucket_s")
    )
    return rebucketed


def build_category_chart(category_stats: pd.DataFrame, merge_cats: bool) -> str:
    if category_stats.empty or "category" not in category_stats.columns:
        return '<div class="empty">Нет данных по категориям</div>'

    src = category_stats.copy()
    src["category"] = src["category"].map(lambda v: process_category(v, merge_cats))

    # Если объединили — пересчитываем
    if merge_cats:
        y_col = "incidents" if "incidents" in src.columns else "flows_sum"
        src = (
            src.groupby("category", as_index=False)[y_col].sum()
        )
    else:
        y_col = "incidents" if "incidents" in src.columns else "flows_sum"

    src = src.sort_values(y_col, ascending=True)

    fig = px.bar(
        src,
        x=y_col,
        y="category",
        orientation="h",
        labels={"category": "Категория", y_col: "Инцидентов"},
        text=y_col,
    )
    fig.update_traces(textposition="outside", marker_color="#5cb3ff")
    fig.update_layout(
        template="plotly_dark",
        height=max(300, 45 * len(src) + 120),
        margin=dict(l=10, r=40, t=20, b=40),
        showlegend=False,
    )
    return fig_to_html(fig, include_js=True)


def build_timeline_chart(timeline: pd.DataFrame) -> str:
    """Адаптивная временная шкала с автоматическим выбором размера бакета."""
    if timeline.empty or not {"timeline_bucket_s", "anomaly_flows"}.issubset(timeline.columns):
        return '<div class="empty">Нет данных временной шкалы</div>'

    # Адаптивный rebucketing
    target_bucket = compute_adaptive_bucket_size(timeline)
    src = rebucketize_if_needed(timeline, target_bucket)

    # Преобразуем timestamp в datetime для правильной оси времени
    src["datetime"] = pd.to_datetime(src["timeline_bucket_s"], unit="s")

    # Для подписи оси X (если коротко — показываем время, если длинно — дату+время)
    total_span_hours = (src["timeline_bucket_s"].max() - src["timeline_bucket_s"].min()) / 3600
    xaxis_format = "%H:%M" if total_span_hours < 24 else "%d.%m %H:%M"

    if len(src) <= 1:
        fig = px.bar(
            src,
            x="datetime",
            y="anomaly_flows",
            labels={"datetime": "Время", "anomaly_flows": "Аномальных сессий"},
        )
    else:
        fig = px.area(
            src,
            x="datetime",
            y="anomaly_flows",
            labels={"datetime": "Время", "anomaly_flows": "Аномальных сессий"},
        )
        fig.update_traces(line_color="#5cb3ff", fillcolor="rgba(92, 179, 255, 0.3)")

    fig.update_layout(
        template="plotly_dark",
        height=380,
        margin=dict(l=30, r=20, t=20, b=50),
        hovermode="x unified",
    )
    fig.update_xaxes(
        tickformat=xaxis_format,
        nticks=15,  # plotly сам выберет оптимальное число подписей
    )

    bucket_label = _format_bucket_label(target_bucket)
    return (
        f'<div class="chart-meta">Интервал усреднения: {bucket_label}</div>'
        + fig_to_html(fig, include_js=False)
    )


def rebucketize_if_needed(timeline: pd.DataFrame, target_bucket_s: int) -> pd.DataFrame:
    """Переагрегация timeline только если исходный bucket меньше target."""
    if timeline.empty or "timeline_bucket_s" not in timeline.columns:
        return timeline

    # Если у нас мало точек — ничего не делаем
    if len(timeline) <= 40:
        return timeline

    return rebucket_timeline(timeline, target_bucket_s)


def _format_bucket_label(bucket_s: int) -> str:
    if bucket_s < 60:
        return f"{bucket_s} с"
    if bucket_s < 3600:
        return f"{bucket_s // 60} мин"
    hours = bucket_s // 3600
    return f"{hours} ч"


def build_severity_chart(incidents: pd.DataFrame) -> str:
    if incidents.empty or "severity_level" not in incidents.columns:
        return '<div class="empty">Нет данных по серьёзности</div>'

    severity_counts = (
        incidents.groupby("severity_level")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    color_map = {
        "Критический": "#e04747",
        "Высокий": "#e89a3c",
        "Средний": "#e8c23c",
        "Низкий": "#5cb3ff",
    }
    colors = [color_map.get(lvl, "#888") for lvl in severity_counts["severity_level"]]

    fig = go.Figure(data=[go.Pie(
        labels=severity_counts["severity_level"],
        values=severity_counts["count"],
        marker_colors=colors,
        textinfo="label+percent",
        hovertemplate="%{label}<br>Инцидентов: %{value}<br>Доля: %{percent}<extra></extra>",
    )])
    fig.update_layout(
        template="plotly_dark",
        height=400,  # выровнено с heatmap высотой
        margin=dict(l=20, r=20, t=20, b=20),
    )
    return fig_to_html(fig, include_js=False)


def build_category_severity_heatmap(incidents: pd.DataFrame, merge_cats: bool) -> str:
    """Тепловая карта категория × серьёзность. Столбец Средний скрыт."""
    if incidents.empty or not {"category", "severity_level"}.issubset(incidents.columns):
        return '<div class="empty">Нет данных для тепловой карты</div>'

    pivot = (
        incidents.groupby(["category", "severity_level"])
        .size()
        .reset_index(name="count")
    )
    pivot["category"] = pivot["category"].map(lambda v: process_category(v, merge_cats))
    # Если merge_cats, заново группируем по упрощённым названиям
    if merge_cats:
        pivot = pivot.groupby(["category", "severity_level"], as_index=False)["count"].sum()

    pivot_matrix = pivot.pivot(index="category", columns="severity_level", values="count").fillna(0)

    severity_order = ["Критический", "Высокий", "Низкий"]  # Средний скрыт
    existing = [s for s in severity_order if s in pivot_matrix.columns]
    pivot_matrix = pivot_matrix[existing] if existing else pivot_matrix

    if pivot_matrix.empty:
        return '<div class="empty">Нет данных</div>'

    fig = go.Figure(data=go.Heatmap(
        z=pivot_matrix.values,
        x=pivot_matrix.columns,
        y=pivot_matrix.index,
        colorscale=[
            [0.0, "#0f1a33"],
            [0.5, "#3c77bd"],
            [1.0, "#e04747"],
        ],
        text=pivot_matrix.values.astype(int),
        texttemplate="%{text}",
        textfont={"size": 13},
        hovertemplate="Категория: %{y}<br>Уровень: %{x}<br>Инцидентов: %{z}<extra></extra>",
        colorbar=dict(title="Инцидентов"),
    ))
    fig.update_layout(
        template="plotly_dark",
        height=400,  # выровнено с severity pie
        margin=dict(l=10, r=40, t=20, b=40),
    )
    return fig_to_html(fig, include_js=False)


# ============================================================
# Фильтр-чипы
# ============================================================

def build_category_filter_chips(incidents: pd.DataFrame, table_target_id: str,
                                 merge_cats: bool) -> str:
    if incidents.empty or "category" not in incidents.columns:
        return ""

    localized_categories = incidents["category"].map(lambda v: process_category(v, merge_cats))
    counts = localized_categories.value_counts()

    chips = [
        f'<button class="chip chip-active" type="button" '
        f'onclick="filterIncidents(\'{table_target_id}\', null, this)" '
        f'data-category="">Все <span class="chip-count">{len(incidents)}</span></button>'
    ]
    for cat, count in counts.items():
        cat_esc = html.escape(str(cat))
        chips.append(
            f'<button class="chip" type="button" '
            f'onclick="filterIncidents(\'{table_target_id}\', \'{cat_esc}\', this)" '
            f'data-category="{cat_esc}">{cat_esc} <span class="chip-count">{count}</span></button>'
        )
    return '<div class="filter-chips">' + "".join(chips) + "</div>"


# ============================================================
# CSS
# ============================================================

CSS = """
:root {
  --bg: #091228;
  --panel: #0f1a33;
  --panel-border: #213250;
  --muted: #9fb0c9;
  --text: #edf2fb;
  --thead: #1a2f66;
  --critical: #e04747;
  --high: #e89a3c;
  --medium: #e8c23c;
  --low: #5cb3ff;
  --accent: #5cb3ff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, "Segoe UI", Arial, sans-serif;
}
.wrapper { max-width: 1680px; margin: 0 auto; padding: 18px; }
h1 { margin: 0 0 10px 0; font-size: 32px; }
.subtitle { color: var(--muted); margin-bottom: 18px; font-size: 14px; }
.subtitle b { color: var(--text); }

.metric-row {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}
.metric-card {
  background: linear-gradient(180deg, #0c1730 0%, #0b1630 100%);
  border: 1px solid var(--panel-border);
  border-radius: 18px;
  padding: 14px 16px;
  min-width: 0;
}
.metric-card--critical { border-color: rgba(224, 71, 71, 0.5); }
.metric-card--critical .metric-value { color: var(--critical); }
.metric-title { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
.metric-value { font-size: 26px; font-weight: 700; word-wrap: break-word; }
.metric-subtitle { color: var(--muted); margin-top: 6px; font-size: 12px; }

.panel {
  background: rgba(15, 26, 51, 0.95);
  border: 1px solid var(--panel-border);
  border-radius: 20px;
  padding: 18px;
  margin-bottom: 18px;
  overflow: hidden;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.panel-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  flex-shrink: 0;
}
.panel h2 { margin: 0; font-size: 20px; }
.panel h3 { margin: 0 0 10px 0; font-size: 16px; }
.note { color: var(--muted); margin-top: 6px; line-height: 1.45; font-size: 13px; }
.panel-explainer {
  background: rgba(92, 179, 255, 0.08);
  border: 1px solid rgba(92, 179, 255, 0.25);
  border-radius: 10px;
  padding: 10px 14px;
  margin-bottom: 14px;
  color: #b8d5f0;
  font-size: 13px;
  line-height: 1.5;
  flex-shrink: 0;
}
.action-btn {
  border: 1px solid #28477f;
  background: #0e1a37;
  color: var(--text);
  border-radius: 10px;
  padding: 8px 14px;
  cursor: pointer;
  font-size: 13px;
  white-space: nowrap;
}
.action-btn:hover { background: #152549; }
.chart-meta {
  color: var(--muted);
  font-size: 12px;
  padding: 6px 0;
  margin-bottom: 4px;
  font-style: italic;
}

.chart-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 18px;
  align-items: stretch;
}
.chart-grid > .panel {
  height: 100%;
}
.two-cols {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}
.one-col { display: block; }
.chart-body {
  width: 100%;
  min-width: 0;
  overflow: hidden;
  flex-grow: 1;
}
.chart-body .plotly-graph-div,
.chart-body .js-plotly-plot,
.chart-body .plot-container {
  width: 100% !important;
}

.small { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
.table-toolbar { margin-bottom: 8px; }
.table-scroll {
  overflow: auto;
  border: 1px solid #1b2c4e;
  border-radius: 12px;
}
.data-table {
  width: 100%;
  border-collapse: collapse;
  min-width: 720px;
}
.data-table th,
.data-table td {
  padding: 10px 12px;
  border-bottom: 1px solid #1a2948;
  text-align: left;
  vertical-align: top;
  font-size: 13px;
}
.data-table th {
  position: sticky;
  top: 0;
  background: var(--thead);
  cursor: pointer;
  z-index: 2;
  user-select: none;
}
.data-table th:hover { background: #24417d; }
.data-table tbody tr:nth-child(odd) { background: rgba(255,255,255,0.02); }
.data-table tbody tr:hover { background: rgba(92, 179, 255, 0.05); }
.data-table tbody tr.filtered-out { display: none; }
.sort-indicator { color: #9fb0c9; margin-left: 8px; font-size: 12px; }

.badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  color: #fff;
  white-space: nowrap;
}
.badge-critical { background: var(--critical); }
.badge-high { background: var(--high); }
.badge-medium { background: var(--medium); color: #2a2210; }
.badge-low { background: var(--low); color: #0e1a37; }
.empty { color: var(--muted); padding: 20px 0; }

.filter-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 14px;
  padding: 10px;
  background: rgba(92, 179, 255, 0.04);
  border-radius: 12px;
  border: 1px solid rgba(92, 179, 255, 0.15);
}
.chip {
  background: #0e1a37;
  border: 1px solid #28477f;
  color: var(--muted);
  border-radius: 20px;
  padding: 6px 14px;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.15s;
  font-family: inherit;
}
.chip:hover {
  border-color: var(--accent);
  color: var(--text);
}
.chip-active {
  background: rgba(92, 179, 255, 0.2);
  border-color: var(--accent);
  color: var(--text);
  font-weight: 600;
}
.chip-count {
  display: inline-block;
  background: rgba(255, 255, 255, 0.12);
  padding: 1px 8px;
  border-radius: 10px;
  margin-left: 6px;
  font-size: 11px;
}
.chip-active .chip-count {
  background: rgba(92, 179, 255, 0.35);
}

.fullscreen-target:fullscreen {
  padding: 24px;
  background: #081121;
  width: 100vw;
  height: 100vh;
  overflow: auto;
}
.fullscreen-target:fullscreen .chart-body { min-height: 78vh; }

@media (max-width: 1320px) {
  .metric-row { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 980px) {
  .chart-grid, .two-cols, .metric-row { grid-template-columns: 1fr; }
}
"""

SCRIPT = """
function toggleFullscreen(id) {
  const el = document.getElementById(id);
  if (!el) return;
  if (document.fullscreenElement) {
    document.exitFullscreen();
  } else if (el.requestFullscreen) {
    el.requestFullscreen();
  }
}

function initSortableTables() {
  document.querySelectorAll('.sortable-table').forEach((table) => {
    const headers = table.querySelectorAll('th');
    headers.forEach((header, idx) => {
      header.addEventListener('click', () => {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const current = header.getAttribute('data-order') || 'none';
        headers.forEach((h) => h.setAttribute('data-order', 'none'));
        const next = current === 'asc' ? 'desc' : 'asc';
        header.setAttribute('data-order', next);
        const type = header.getAttribute('data-sort-type') || 'str';
        rows.sort((a, b) => {
          const av = a.children[idx].getAttribute('data-sort-value') || a.children[idx].innerText;
          const bv = b.children[idx].getAttribute('data-sort-value') || b.children[idx].innerText;
          if (type === 'num') {
            const an = parseFloat(av);
            const bn = parseFloat(bv);
            const aa = Number.isNaN(an) ? -Infinity : an;
            const bb = Number.isNaN(bn) ? -Infinity : bn;
            return next === 'asc' ? aa - bb : bb - aa;
          }
          return next === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
        });
        rows.forEach((row) => tbody.appendChild(row));
      });
    });
  });
}

function filterIncidents(tableId, category, chipEl) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const rows = table.querySelectorAll('tbody tr');
  rows.forEach((row) => {
    const rowCat = row.getAttribute('data-category') || '';
    if (!category || rowCat === category) {
      row.classList.remove('filtered-out');
    } else {
      row.classList.add('filtered-out');
    }
  });
  const container = chipEl.parentElement;
  container.querySelectorAll('.chip').forEach((c) => c.classList.remove('chip-active'));
  chipEl.classList.add('chip-active');
}

window.addEventListener('load', initSortableTables);
"""


# ============================================================
# Пояснения
# ============================================================

INCIDENT_EXPLAINER_TEMPLATE = (
    "Под «{label}» понимается группа аномальных сетевых сессий, объединённых по тройке "
    "(источник, назначение, порт). Одна такая тройка = один {label_genitive}, даже если "
    "в ней было много сессий. Термин соответствует понятию 'incident candidate' "
    "в современных SIEM-системах — это первичная единица анализа для дальнейшего расследования."
)

INCIDENT_LABELS = {
    "инцидент": ("инцидент", "инцидента"),
    "кластер": ("кластер аномалий", "кластера"),
    "взаимодействие": ("аномальное взаимодействие", "взаимодействия"),
}

HEATMAP_EXPLAINER = (
    "Тепловая карта показывает распределение по категориям и уровням серьёзности. "
    "Столбец «Средний» скрыт для акцента на действительно важных случаях — "
    "критические и высокие угрозы требуют немедленного внимания."
)

MODE_VS_MEDIAN_EXPLAINER = (
    "В таблице показаны две статистики по пакетам и байтам: «медиана» (центральное значение — "
    "показывает стабильность) и «мода» (самое частое значение — показывает паттерн "
    "повторяющихся сессий, например C2-маяки с идентичным размером)."
)


def main() -> None:
    args = parse_args()
    report_dir = Path(args.report_dir).expanduser().resolve()
    output = Path(args.output).expanduser().resolve() if args.output else report_dir / "dashboard.html"
    merge_cats = args.merge_categories

    label, label_gen = INCIDENT_LABELS.get(args.incident_label, ("инцидент", "инцидента"))
    incident_explainer = INCIDENT_EXPLAINER_TEMPLATE.format(
        label=label, label_genitive=label_gen,
    )

    print(f"[ИНФО] Загрузка отчёта из: {report_dir}")
    if merge_cats:
        print(f"[ИНФО] Режим объединения категорий: включён")
    print(f"[ИНФО] Терминология: «{label}»")

    summary = load_json(report_dir / "summary.json")
    category_stats = load_csv(report_dir / "category_stats.csv")
    timeline = load_csv(report_dir / "timeline.csv")
    top_incidents = load_csv(report_dir / "top_incidents.csv")
    all_incidents = load_csv(report_dir / "all_incidents.csv")
    enriched = load_csv(report_dir / "scored_flows_enriched.csv")

    top_incidents = enrich_incidents_with_mode(top_incidents, enriched)
    all_incidents = enrich_incidents_with_mode(all_incidents, enriched)

    entities = compute_top_entities(enriched, all_incidents, merge_cats=merge_cats)
    top_clients = entities["top_clients"]
    top_servers = entities["top_servers"]
    top_ports = entities["top_ports"]
    pair_stats = entities["pair_stats"]

    top_category_raw = summary.get("top_category", "—")
    if top_category_raw is None or (isinstance(top_category_raw, float) and pd.isna(top_category_raw)):
        top_category_raw = "—"
    top_category_display = process_category(str(top_category_raw), merge_cats)

    critical_count = 0
    if not all_incidents.empty and "severity_level" in all_incidents.columns:
        critical_count = int((all_incidents["severity_level"] == "Критический").sum())

    label_cap = label.capitalize()

    metrics_html = "".join([
        metric_card("Всего сессий", fmt_int(summary.get("flows_total", 0))),
        metric_card("Аномальных сессий", fmt_int(summary.get("anomalous_flows_total", 0))),
        metric_card(f"{label_cap}", fmt_int(summary.get("incidents_total", 0))),
        metric_card("Критических", fmt_int(critical_count), accent="critical"),
        metric_card("Доля аномалий", fmt_pct(summary.get("anomaly_share", 0.0))),
        metric_card("Главная категория", top_category_display),
    ])

    # Ряд 1: категории + временная шкала
    charts_html_row1 = f'''
    <div class="chart-grid">
      {chart_panel(f"{label_cap} по категориям", f"Сколько {label_gen[:-1] + 'ов'} попало в каждую категорию интерпретации.", build_category_chart(category_stats, merge_cats), "chart_categories")}
      {chart_panel("Аномалии во времени", "Количество аномальных сессий по временным интервалам.", build_timeline_chart(timeline), "chart_timeline")}
    </div>
    '''

    # Ряд 2: pie + heatmap (синхронизированы по высоте)
    charts_html_row2 = f'''
    <div class="chart-grid">
      {chart_panel("Распределение по уровню серьёзности", "Доля критических, высоких и прочих инцидентов.", build_severity_chart(all_incidents), "chart_severity")}
      {chart_panel("Категория × серьёзность", "Пересечение категорий и уровней серьёзности.", build_category_severity_heatmap(all_incidents, merge_cats), "chart_heatmap", tooltip=HEATMAP_EXPLAINER)}
    </div>
    '''

    top_incidents_display = choose_columns(top_incidents, TOP_INCIDENTS_DISPLAY_COLS)
    top_incidents_table = frame_to_html(
        top_incidents_display, "top_incidents",
        max_rows=args.top_n, height_px=500,
        filterable=True, merge_cats=merge_cats,
    )
    filter_chips = build_category_filter_chips(top_incidents_display, "top_incidents", merge_cats)

    pair_stats_html = frame_to_html(pair_stats, "pair_stats", max_rows=30, height_px=400, merge_cats=merge_cats)
    top_clients_html = frame_to_html(top_clients, "top_clients", max_rows=30, height_px=380)
    top_servers_html = frame_to_html(top_servers, "top_servers", max_rows=30, height_px=380)
    top_ports_html = frame_to_html(top_ports, "top_ports", max_rows=30, height_px=320)
    category_stats_html = frame_to_html(category_stats, "category_stats", max_rows=50, height_px=400, merge_cats=merge_cats)

    html_text = f'''<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(args.title)}</title>
  <style>{CSS}</style>
</head>
<body>
  <div class="wrapper">
    <h1>{html.escape(args.title)}</h1>
    <div class="subtitle">Источник отчёта: {html.escape(str(report_dir))} · Главная категория: <b>{html.escape(top_category_display)}</b></div>

    <div class="metric-row">{metrics_html}</div>

    {charts_html_row1}
    {charts_html_row2}

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>Топ {label_gen[:-1] + 'ов'}</h2>
          <div class="note">Главная таблица для аналитика. Используйте фильтры сверху, чтобы сфокусироваться на конкретной категории атак.</div>
        </div>
      </div>
      <div class="panel-explainer">ℹ️ {html.escape(incident_explainer)}</div>
      <div class="panel-explainer">ℹ️ {html.escape(MODE_VS_MEDIAN_EXPLAINER)}</div>
      {filter_chips}
      {top_incidents_table}
    </div>

    <div class="panel">
      <div>
        <h2>Пары источник → назначение</h2>
        <div class="note">Самые активные направления в аномальном трафике. Устойчивые повторяющиеся пары — кандидаты на C2-взаимодействие или маяки.</div>
      </div>
      {pair_stats_html}
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>Топ сущностей в аномальном трафике</h2>
          <div class="note">Какие источники чаще всего генерировали аномалии и на какие назначения они были направлены.</div>
        </div>
      </div>
      <div class="two-cols">
        <div>
          <h3>Топ источников</h3>
          <div class="small">IP-адреса источника, сгенерировавшие больше всего аномальных сессий.</div>
          {top_clients_html}
        </div>
        <div>
          <h3>Топ назначений</h3>
          <div class="small">IP-адреса назначения, куда чаще всего шёл аномальный трафик.</div>
          {top_servers_html}
        </div>
      </div>
    </div>

    <div class="panel">
      <div>
        <h2>Топ портов</h2>
        <div class="note">Порты назначения, которые чаще всего встречаются среди аномальных сессий. Справочная информация.</div>
      </div>
      {top_ports_html}
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h2>Сводка по категориям</h2>
          <div class="note">Детерминистские категории, которые присваиваются правилами static-анализатора.</div>
        </div>
      </div>
      {category_stats_html}
    </div>

  </div>
  <script>{SCRIPT}</script>
</body>
</html>
'''

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_text, encoding="utf-8")
    print(f"[ОК] Дашборд записан: {output}")


if __name__ == "__main__":
    main()
