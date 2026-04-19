#!/usr/bin/env python3
"""
FlowGuard Web UI — Streamlit-приложение для интерактивного запуска pipeline.

Использование:
    streamlit run python/flowguard/ui/flowguard_ui.py
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="FlowGuard — анализ сетевого трафика",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Большой баннер — только для страницы \"О системе\" */
    .main-header {
        background: linear-gradient(135deg, #5cb3ff 0%, #3c77bd 100%);
        padding: 18px 28px;
        border-radius: 14px;
        margin-bottom: 24px;
        color: white;
    }
    .main-header h1 { margin: 0; font-size: 28px; color: white; }
    .main-header p { margin: 4px 0 0; opacity: 0.9; font-size: 14px; }

    /* Маленький заголовок страницы — на всех рабочих страницах */
    .page-title {
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 4px 0 18px 0;
        padding-bottom: 12px;
        border-bottom: 1px solid #213250;
    }
    .page-title h2 { margin: 0; font-size: 24px; }
    .page-title .page-subtitle {
        color: #9fb0c9;
        font-size: 13px;
        margin-left: auto;
    }

    .metric-card {
        background: rgba(92, 179, 255, 0.08);
        border: 1px solid rgba(92, 179, 255, 0.2);
        border-radius: 10px;
        padding: 14px 18px;
    }
    .metric-label {
        font-size: 12px;
        color: #9fb0c9;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 24px;
        font-weight: 700;
    }
    .success-box {
        background: rgba(71, 224, 130, 0.1);
        border-left: 4px solid #47e082;
        padding: 14px 18px;
        border-radius: 6px;
        margin: 12px 0;
    }
    .warning-box {
        background: rgba(232, 154, 60, 0.1);
        border-left: 4px solid #e89a3c;
        padding: 14px 18px;
        border-radius: 6px;
        margin: 12px 0;
    }
    /* Карточки запусков */
    .run-row {
        background: rgba(15, 26, 51, 0.6);
        border: 1px solid #213250;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 10px;
        transition: border-color 0.15s;
    }
    .run-row:hover {
        border-color: #5cb3ff;
    }
    .run-row-head {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        gap: 12px;
        margin-bottom: 8px;
    }
    .run-row-dataset {
        font-size: 16px;
        font-weight: 600;
    }
    .run-row-time {
        color: #9fb0c9;
        font-size: 12px;
        white-space: nowrap;
    }
    .run-row-stats {
        display: flex;
        gap: 18px;
        flex-wrap: wrap;
        font-size: 13px;
        color: #b8d5f0;
    }
    .run-row-stats b { color: #edf2fb; }
    .trend-up { color: #e89a3c; }
    .trend-down { color: #47e082; }
    .trend-flat { color: #9fb0c9; }
    code {
        background: rgba(255, 255, 255, 0.05);
        padding: 1px 6px;
        border-radius: 4px;
    }
    .stButton > button { width: 100%; }
</style>
""", unsafe_allow_html=True)

# ВАЖНО: файл лежит в python/flowguard/ui/, поэтому до корня проекта три уровня вверх.
ROOT = Path(__file__).resolve().parents[3]
RUNS_INDEX = ROOT / "reports" / "runs_index.json"
SCRIPT_PATH = ROOT / "scripts" / "flowguard.sh"


def format_int(value) -> str:
    try:
        return f"{int(value):,}".replace(",", " ")
    except Exception:
        return "0"


def format_duration(seconds) -> str:
    try:
        s = int(seconds)
    except (ValueError, TypeError):
        return "—"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h > 0:
        return f"{h}ч {m}м {sec}с"
    if m > 0:
        return f"{m}м {sec}с"
    return f"{sec}с"


def parse_run_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_run_timestamp(value: str | None) -> str:
    dt = parse_run_timestamp(value)
    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return str(value or "—")
    return dt.astimezone().strftime("%d.%m.%Y %H:%M")


def list_datasets() -> list[str]:
    raw_root = ROOT / "data" / "raw"
    if not raw_root.exists():
        return []
    result = []
    for p in raw_root.iterdir():
        if not p.is_dir():
            continue
        pcap_count = count_pcap_files(p)
        if pcap_count > 0:
            result.append(p.name)
    return sorted(result)


def list_models() -> list[str]:
    models_root = ROOT / "models" / "active"
    if not models_root.exists():
        return []
    return sorted([p.name for p in models_root.iterdir() if p.is_dir()])


def load_runs() -> list[dict]:
    if not RUNS_INDEX.exists():
        return []
    try:
        return json.loads(RUNS_INDEX.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def count_pcap_files(directory: Path) -> int:
    if not directory.exists():
        return 0
    return sum(
        1 for p in directory.rglob("*")
        if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}
    )


def get_directory_size_human(directory: Path) -> str:
    if not directory.exists():
        return "—"
    total_bytes = sum(
        p.stat().st_size for p in directory.rglob("*") if p.is_file()
    )
    if total_bytes >= 1024**3:
        return f"{total_bytes / 1024**3:.2f} ГБ"
    if total_bytes >= 1024**2:
        return f"{total_bytes / 1024**2:.1f} МБ"
    return f"{total_bytes / 1024:.1f} КБ"


with st.sidebar:
    st.markdown("""
    <div style="padding: 8px 0 14px 0; border-bottom: 1px solid #213250; margin-bottom: 16px;">
      <div style="font-size: 22px; font-weight: 700;">🛡️ FlowGuard</div>
      <div style="color: #9fb0c9; font-size: 12px; margin-top: 2px;">
        Анализ сетевых аномалий
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 📋 Разделы")
    page = st.radio(
        "Страница",
        ["🚀 Запустить анализ", "📊 История запусков", "🧪 Сравнение моделей", "ℹ️ О системе"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("### Статус системы")
    models = list_models()
    datasets = list_datasets()
    parser_bin = ROOT / "cpp" / "FlowParser" / "build" / "pcap_flow_parser"

    st.metric("Доступно моделей", len(models))
    st.metric("Доступно датасетов", len(datasets))

    if parser_bin.exists():
        st.success("Парсер найден")
    else:
        st.error("Парсер не найден")


if page == "🚀 Запустить анализ":
    st.markdown("""
    <div class="page-title">
      <h2>🚀 Настройка и запуск pipeline</h2>
      <span class="page-subtitle">Выберите источник, модель и запустите анализ</span>
    </div>
    """, unsafe_allow_html=True)

    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("### Источник данных")

        source_mode = st.radio(
            "Откуда брать PCAP-файлы",
            ["Из существующего датасета", "Свой путь к папке", "Загрузить файл"],
            horizontal=True,
        )

        dataset_name = "demo_showcase"
        custom_raw_dir = None

        if source_mode == "Из существующего датасета":
            if not datasets:
                st.warning("В data/raw/ нет датасетов с PCAP-файлами")
            else:
                default_index = datasets.index("demo_showcase") if "demo_showcase" in datasets else 0
                dataset_name = st.selectbox(
                    "Выберите датасет",
                    datasets,
                    index=default_index,
                )
                ds_path = ROOT / "data" / "raw" / dataset_name
                pcap_count = count_pcap_files(ds_path)
                size = get_directory_size_human(ds_path)
                st.info(f"📦 В датасете **{dataset_name}**: {pcap_count} PCAP-файлов, общий размер {size}")

        elif source_mode == "Свой путь к папке":
            custom_raw_dir = st.text_input(
                "Путь к папке с PCAP-файлами",
                value=str(ROOT / "data" / "raw" / "mydata"),
            )
            dataset_name = st.text_input(
                "Имя датасета (для группировки отчётов)",
                value=Path(custom_raw_dir).name if custom_raw_dir else "custom",
            )

            if custom_raw_dir:
                custom_path = Path(custom_raw_dir)
                if custom_path.exists():
                    pcap_count = count_pcap_files(custom_path)
                    size = get_directory_size_human(custom_path)
                    if pcap_count > 0:
                        st.success(f"📦 Найдено {pcap_count} PCAP-файлов, общий размер {size}")
                    else:
                        st.warning("В папке нет .pcap/.pcapng файлов")
                else:
                    st.error(f"Папка не существует: {custom_raw_dir}")

        else:
            uploaded_file = st.file_uploader(
                "Перетащите PCAP-файл сюда",
                type=["pcap", "pcapng"],
                help="Файл будет сохранён во временную папку датасета",
            )
            dataset_name = st.text_input("Имя для этого запуска", value="upload_" + datetime.now().strftime("%Y%m%d_%H%M%S"))

            if uploaded_file is not None:
                upload_dir = ROOT / "data" / "raw" / dataset_name
                upload_dir.mkdir(parents=True, exist_ok=True)
                save_path = upload_dir / uploaded_file.name
                with open(save_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                st.success(f"✓ Файл сохранён: `{save_path}`")
                st.info(f"Размер: {uploaded_file.size / 1024:.1f} КБ")

        st.markdown("### Модель")
        if not models:
            st.warning("В models/active/ нет моделей — сначала обучите модель")
            model_name = "flow_plus_ja4"
        else:
            default_model_index = models.index("flow_plus_ja4") if "flow_plus_ja4" in models else 0
            model_name = st.selectbox(
                "Выберите обученную модель",
                models,
                index=default_model_index,
            )

        st.markdown("### Куда сохранить отчёт")
        use_default_out = st.checkbox(
            "Использовать стандартный путь (reports/latest/<dataset>)",
            value=True,
        )
        custom_reports_dir = None
        if not use_default_out:
            custom_reports_dir = st.text_input(
                "Свой путь к папке отчётов",
                value=str(ROOT / "reports" / "custom" / dataset_name),
            )

        st.markdown("### Дополнительные опции")
        col_opt1, col_opt2 = st.columns(2)
        with col_opt1:
            auto_open = st.checkbox("Открыть dashboard после завершения", value=False)
        with col_opt2:
            verbose = st.checkbox("Подробный вывод в консоль", value=False)

    with col_right:
        st.markdown("### Обзор конфигурации")
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Датасет</div>
            <div class="metric-value" style="font-size:18px;">{dataset_name}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("")
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Модель</div>
            <div class="metric-value" style="font-size:18px;">{model_name}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### Этапы pipeline")
        st.markdown("""
        1. 📦 **Парсинг PCAP** — C++ парсер FlowParser
        2. 🤖 **Скоринг** — XGBoost на flow+JA4 признаках
        3. 🔍 **Правиловый анализ** — классификация инцидентов
        4. 📊 **Dashboard** — интерактивный HTML-отчёт
        """)

    st.markdown("---")

    col_run1, col_run2, col_run3 = st.columns([1, 2, 1])
    with col_run2:
        start_clicked = st.button("🚀 Запустить Pipeline", type="primary", use_container_width=True)

    if start_clicked:
        with st.spinner("Запускаем pipeline..."):
            cmd = ["bash", str(SCRIPT_PATH), dataset_name, model_name]
            if custom_raw_dir:
                cmd.extend(["--raw-dir", custom_raw_dir])
            if custom_reports_dir:
                cmd.extend(["--reports-dir", custom_reports_dir])
            if auto_open:
                cmd.append("--open")
            else:
                cmd.append("--no-open")

            env = os.environ.copy()
            env["SKIP_INTERACTIVE"] = "1"

            st.info(f"🔧 Команда: `{' '.join(cmd)}`")

            progress = st.progress(0)
            status_placeholder = st.empty()
            output_placeholder = st.empty()

            output_lines = []
            start_time = time.time()

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
                )

                for line in process.stdout:
                    output_lines.append(line.rstrip())
                    if "[1/4]" in line:
                        progress.progress(0.25)
                        status_placeholder.info("📦 Этап 1/4: Парсинг PCAP...")
                    elif "[2/4]" in line:
                        progress.progress(0.50)
                        status_placeholder.info("🤖 Этап 2/4: Скоринг flows...")
                    elif "[3/4]" in line:
                        progress.progress(0.75)
                        status_placeholder.info("🔍 Этап 3/4: Анализ аномалий...")
                    elif "[4/4]" in line:
                        progress.progress(0.90)
                        status_placeholder.info("📊 Этап 4/4: Построение dashboard...")
                    if verbose:
                        output_placeholder.code("\n".join(output_lines[-25:]))

                process.wait()
                progress.progress(1.0)

            except Exception as e:
                st.error(f"Ошибка запуска: {e}")
                st.stop()

            duration = time.time() - start_time

            if process.returncode == 0:
                status_placeholder.empty()
                st.markdown(f"""
                <div class="success-box">
                <strong>✓ Pipeline завершён успешно</strong><br>
                Время выполнения: {format_duration(int(duration))}
                </div>
                """, unsafe_allow_html=True)

                reports_dir = Path(custom_reports_dir) if custom_reports_dir else ROOT / "reports" / "latest" / dataset_name
                summary_files = list(reports_dir.rglob("summary.json"))
                dashboard_files = list(reports_dir.rglob("dashboard.html"))

                if summary_files:
                    summary_files = sorted(summary_files, key=lambda p: p.stat().st_mtime, reverse=True)
                    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
                    st.markdown("### 📊 Результаты анализа")

                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Всего сессий", format_int(summary.get("flows_total", 0)))
                    m2.metric("Аномальных", format_int(summary.get("anomalous_flows_total", 0)))
                    m3.metric("Инцидентов", format_int(summary.get("incidents_total", 0)))
                    m4.metric("Доля аномалий", f"{summary.get('anomaly_share', 0) * 100:.2f}%")
                    st.info(f"🏷 Главная категория: **{summary.get('top_category', '—')}**")

                if dashboard_files:
                    st.markdown("### 🔗 Открыть dashboard")
                    for df in dashboard_files:
                        st.markdown(f"- [Открыть {df.parent.name}](file://{df})")

                with st.expander("📜 Полный лог выполнения"):
                    st.code("\n".join(output_lines))
            else:
                st.markdown(f"""
                <div class="warning-box">
                <strong>✗ Pipeline завершился с ошибкой</strong><br>
                Код возврата: {process.returncode}
                </div>
                """, unsafe_allow_html=True)
                st.code("\n".join(output_lines))


elif page == "📊 История запусков":
    st.markdown("""
    <div class="page-title">
      <h2>📊 История запусков pipeline</h2>
      <span class="page-subtitle">Все выполненные анализы с результатами</span>
    </div>
    """, unsafe_allow_html=True)

    runs = load_runs()

    if not runs:
        st.info(
            "История пока пуста. Запустите pipeline хотя бы раз "
            "— и записи появятся здесь автоматически."
        )
    else:
        st.markdown("### Общая статистика")
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Запусков", len(runs))
        col2.metric("Датасетов", len({r.get("dataset") for r in runs}))
        col3.metric("Сессий всего", format_int(sum(r.get("flows_total", 0) for r in runs)))
        col4.metric("Аномалий всего", format_int(sum(r.get("anomalies_total", 0) for r in runs)))
        col5.metric("Инцидентов всего", format_int(sum(r.get("incidents_total", 0) for r in runs)))

        st.markdown("---")

        col_search, col_sort = st.columns([2, 1])
        with col_search:
            search_query = st.text_input(
                "🔎 Поиск по названию датасета",
                value="",
                placeholder="Введите часть названия (оставьте пустым — показать все)",
                label_visibility="collapsed",
            )
        with col_sort:
            sort_option = st.selectbox(
                "Сортировка",
                [
                    "Сначала новые",
                    "Сначала старые",
                    "Больше всего сессий",
                    "Больше всего аномалий",
                    "Больше всего инцидентов",
                    "Долгое выполнение",
                ],
                label_visibility="collapsed",
            )

        st.markdown(
            "<div style='color: #9fb0c9; font-size: 13px; margin-top: 6px;'>"
            "Период:</div>",
            unsafe_allow_html=True,
        )
        time_filter = st.radio(
            "Период",
            ["Всё время", "Сегодня", "7 дней", "30 дней"],
            horizontal=True,
            label_visibility="collapsed",
        )

        now_utc = datetime.now(timezone.utc)
        time_thresholds = {
            "Сегодня": now_utc - timedelta(hours=24),
            "7 дней": now_utc - timedelta(days=7),
            "30 дней": now_utc - timedelta(days=30),
        }

        filtered = list(runs)

        if search_query:
            q = search_query.lower().strip()
            filtered = [r for r in filtered if q in str(r.get("dataset", "")).lower()]

        if time_filter in time_thresholds:
            threshold = time_thresholds[time_filter]
            filtered = [r for r in filtered if parse_run_timestamp(r.get("timestamp")) >= threshold]

        sort_keys = {
            "Сначала новые":           (lambda r: parse_run_timestamp(r.get("timestamp")), True),
            "Сначала старые":          (lambda r: parse_run_timestamp(r.get("timestamp")), False),
            "Больше всего сессий":     (lambda r: r.get("flows_total", 0), True),
            "Больше всего аномалий":   (lambda r: r.get("anomalies_total", 0), True),
            "Больше всего инцидентов": (lambda r: r.get("incidents_total", 0), True),
            "Долгое выполнение":       (lambda r: r.get("duration_seconds", 0), True),
        }
        key_fn, reverse = sort_keys[sort_option]
        filtered.sort(key=key_fn, reverse=reverse)

        st.markdown(
            f"<div style='color: #9fb0c9; font-size: 13px; margin: 14px 0 10px;'>"
            f"Показано: <b style='color:#edf2fb;'>{len(filtered)}</b> из {len(runs)}"
            f"</div>",
            unsafe_allow_html=True,
        )

        if not filtered:
            st.info("По заданным фильтрам ничего не найдено.")
        else:
            trend_index = {}
            sorted_by_time = sorted(runs, key=lambda r: parse_run_timestamp(r.get("timestamp")))
            seen_keys = {}
            for r in sorted_by_time:
                key = (r.get("dataset"), r.get("model"))
                if key in seen_keys:
                    prev = seen_keys[key]
                    current_id = r.get("timestamp")
                    trend_index[current_id] = {
                        "anomalies_prev": prev.get("anomalies_total", 0),
                    }
                seen_keys[key] = r

            for run in filtered:
                ts = run.get("timestamp", "")
                ts_formatted = format_run_timestamp(ts)

                dataset = run.get("dataset", "—")
                model = run.get("model", "—")
                flows = run.get("flows_total", 0)
                anomalies = run.get("anomalies_total", 0)
                incidents = run.get("incidents_total", 0)
                top_cat = run.get("top_category", "—")
                duration = format_duration(run.get("duration_seconds", 0))

                anomaly_pct = ""
                if flows > 0:
                    anomaly_pct = f" ({anomalies / flows * 100:.1f}%)"

                trend_html = ""
                trend_info = trend_index.get(ts)
                if trend_info:
                    prev_anom = trend_info["anomalies_prev"]
                    if prev_anom > 0:
                        diff = anomalies - prev_anom
                        diff_pct = diff / prev_anom * 100
                        if abs(diff_pct) < 1:
                            trend_html = "<span class='trend-flat'>· без изменений</span>"
                        elif diff > 0:
                            trend_html = f"<span class='trend-up'>· ↑ +{diff_pct:.0f}% vs прошлый</span>"
                        else:
                            trend_html = f"<span class='trend-down'>· ↓ {diff_pct:.0f}% vs прошлый</span>"

                st.markdown(f"""
                <div class="run-row">
                  <div class="run-row-head">
                    <div class="run-row-dataset">{dataset} <span style="color:#9fb0c9; font-weight:400; font-size:13px;">· {model}</span></div>
                    <div class="run-row-time">🕐 {ts_formatted} · ⏱ {duration}</div>
                  </div>
                  <div class="run-row-stats">
                    <span>Сессий: <b>{format_int(flows)}</b></span>
                    <span>Аномалий: <b>{format_int(anomalies)}</b>{anomaly_pct} {trend_html}</span>
                    <span>Инцидентов: <b>{format_int(incidents)}</b></span>
                    <span>Главная категория: <b>{top_cat}</b></span>
                  </div>
                </div>
                """, unsafe_allow_html=True)


elif page == "🧪 Сравнение моделей":
    st.markdown("""
    <div class="page-title">
      <h2>🧪 Сравнение моделей на одном датасете</h2>
      <span class="page-subtitle">Сопоставление результатов двух моделей на одинаковых данных</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: rgba(92, 179, 255, 0.08); border: 1px solid rgba(92, 179, 255, 0.25);
                border-radius: 10px; padding: 14px 18px; margin-bottom: 20px; font-size: 14px;">
    <b>ℹ️ Что показывает этот раздел</b><br>
    Здесь можно <b>сравнить два запуска одного и того же датасета, выполненные разными моделями</b>.
    Такой режим помогает оценить, как выбор модели влияет на количество обнаруженных аномалий,
    число сформированных инцидентов, время выполнения и доминирующие категории.<br><br>
    <b>Сравнение на разных датасетах не выводится</b>, потому что абсолютные числа сильно зависят
    от состава трафика и не дают корректной интерпретации.
    </div>
    """, unsafe_allow_html=True)

    runs = load_runs()

    if len(runs) < 2:
        st.info("Нужно минимум 2 запуска в истории, чтобы сравнить модели.")
    else:
        from collections import defaultdict

        by_dataset = defaultdict(list)
        for r in runs:
            ds = r.get("dataset", "")
            if ds:
                by_dataset[ds].append(r)

        comparable_datasets = {}
        for ds, ds_runs in by_dataset.items():
            unique_models = {r.get("model") for r in ds_runs}
            if len(unique_models) >= 2:
                comparable_datasets[ds] = ds_runs

        if not comparable_datasets:
            st.warning(
                "Для сравнения нужен один и тот же датасет, прогнанный как минимум двумя моделями. "
                "Например, запустите существующий датасет сначала одной моделью, а затем второй.",
                icon="💡",
            )
            st.markdown("### Что сейчас есть в истории")
            for ds, ds_runs in by_dataset.items():
                models_used = sorted({r.get("model", "—") for r in ds_runs})
                status_icon = "✓" if len(models_used) >= 2 else "○"
                st.markdown(
                    f"- {status_icon} **{ds}** — {len(ds_runs)} запуск(ов), "
                    f"модели: {', '.join(models_used)}"
                )
            st.markdown("---")
            st.markdown(
                "**Подсказка:** чтобы получить пару для сравнения, достаточно "
                "ещё одного запуска существующего датасета с другой моделью."
            )
        else:
            ds_options = sorted(comparable_datasets.keys())
            chosen_ds = st.selectbox(
                "Датасет для сравнения",
                ds_options,
                help="Показаны только датасеты, где есть запуски разными моделями",
            )

            ds_runs = comparable_datasets[chosen_ds]

            latest_by_model = {}
            for r in sorted(ds_runs, key=lambda x: parse_run_timestamp(x.get("timestamp"))):
                latest_by_model[r.get("model")] = r

            model_names = sorted(latest_by_model.keys())

            col_a, col_b = st.columns(2)
            with col_a:
                model_a_name = st.selectbox(
                    "Модель A",
                    model_names,
                    index=0,
                )
            with col_b:
                remaining = [m for m in model_names if m != model_a_name] or model_names
                model_b_name = st.selectbox(
                    "Модель B",
                    remaining,
                    index=0,
                )

            model_a = latest_by_model[model_a_name]
            model_b = latest_by_model[model_b_name]

            st.markdown("---")
            st.markdown(f"""
            ### Результаты на датасете `{chosen_ds}`
            **{model_a_name}** ↔ **{model_b_name}**
            """)

            a_anom = model_a.get("anomalies_total", 0)
            b_anom = model_b.get("anomalies_total", 0)
            a_inc = model_a.get("incidents_total", 0)
            b_inc = model_b.get("incidents_total", 0)
            a_dur = model_a.get("duration_seconds", 0)
            b_dur = model_b.get("duration_seconds", 0)

            col_m1, col_m2, col_m3 = st.columns(3)
            with col_m1:
                delta_anom = b_anom - a_anom
                delta_anom_pct = (delta_anom / a_anom * 100) if a_anom > 0 else 0
                st.metric(
                    "Аномалий обнаружено",
                    format_int(b_anom),
                    delta=f"{delta_anom:+,} ({delta_anom_pct:+.1f}%)".replace(",", " "),
                    help=f"Модель A: {format_int(a_anom)}, модель B: {format_int(b_anom)}",
                )
            with col_m2:
                delta_inc = b_inc - a_inc
                delta_inc_pct = (delta_inc / a_inc * 100) if a_inc > 0 else 0
                st.metric(
                    "Инцидентов сформировано",
                    format_int(b_inc),
                    delta=f"{delta_inc:+,} ({delta_inc_pct:+.1f}%)".replace(",", " "),
                )
            with col_m3:
                delta_dur = b_dur - a_dur
                st.metric(
                    "Время выполнения",
                    format_duration(b_dur),
                    delta=f"{delta_dur:+d} с" if delta_dur else "без изменений",
                    delta_color="inverse",
                    help=f"Модель A: {format_duration(a_dur)}",
                )

            st.markdown("---")
            st.markdown("### Интерпретация результата")

            interpretation = []
            if delta_anom_pct > 10:
                interpretation.append(
                    f"📈 Модель B обнаружила на **{delta_anom_pct:+.1f}%** больше аномалий. "
                    f"Это означает, что на данном датасете она чувствительнее к подозрительным паттернам."
                )
            elif delta_anom_pct < -10:
                interpretation.append(
                    f"📉 Модель B обнаружила на **{abs(delta_anom_pct):.1f}%** меньше аномалий. "
                    f"Это может указывать на более консервативное поведение и меньшее число ложных срабатываний."
                )
            else:
                interpretation.append(
                    f"≈ Количество аномалий различается незначительно ({delta_anom_pct:+.1f}%). "
                    f"На этом датасете обе модели показывают близкий результат."
                )

            a_top = model_a.get("top_category", "—")
            b_top = model_b.get("top_category", "—")
            if a_top != b_top and a_top != "—" and b_top != "—":
                interpretation.append(
                    f"🏷 Поменялась главная категория: **{a_top}** → **{b_top}**. "
                    f"Это значит, что модели по-разному интерпретируют доминирующий паттерн трафика."
                )

            if a_dur > 0:
                time_overhead = (b_dur - a_dur) / a_dur * 100
                if abs(time_overhead) > 10:
                    interpretation.append(
                        f"⏱ Разница по времени выполнения составила **{time_overhead:+.0f}%**. "
                        f"Это полезно учитывать при выборе модели для практического использования."
                    )

            for text in interpretation:
                st.markdown(f"- {text}")

            st.markdown("---")
            with st.expander("📋 Полная таблица метрик"):
                def build_delta(base_val, exp_val):
                    try:
                        bv = float(base_val)
                        ev = float(exp_val)
                        if bv == 0:
                            return "—"
                        diff = ev - bv
                        pct = diff / bv * 100
                        sign = "+" if diff >= 0 else ""
                        return f"{sign}{diff:,.0f} ({sign}{pct:.1f}%)".replace(",", " ")
                    except (ValueError, TypeError):
                        return "—"

                rows = [
                    ("Датасет", chosen_ds, chosen_ds, "—"),
                    ("Модель", model_a_name, model_b_name, "—"),
                    ("Сессий", format_int(model_a.get("flows_total", 0)),
                     format_int(model_b.get("flows_total", 0)),
                     build_delta(model_a.get("flows_total", 0), model_b.get("flows_total", 0))),
                    ("Аномалий", format_int(a_anom), format_int(b_anom),
                     build_delta(a_anom, b_anom)),
                    ("Инцидентов", format_int(a_inc), format_int(b_inc),
                     build_delta(a_inc, b_inc)),
                    ("Длительность", format_duration(a_dur), format_duration(b_dur),
                     build_delta(a_dur, b_dur)),
                    ("Главная категория", model_a.get("top_category", "—"),
                     model_b.get("top_category", "—"), "—"),
                ]

                df_cmp = pd.DataFrame(
                    rows,
                    columns=["Метрика", model_a_name, model_b_name, "Δ"],
                )
                st.dataframe(df_cmp, use_container_width=True, hide_index=True)


elif page == "ℹ️ О системе":
    st.markdown("""
    <div class="main-header">
      <h1>🛡️ FlowGuard</h1>
      <p>Обнаружение аномалий сетевого трафика на основе ML и цифровых отпечатков JA4</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
### Что это

**FlowGuard** — система обнаружения аномалий сетевого трафика на основе машинного обучения
и цифровых отпечатков JA4.

### Архитектура pipeline

1. **C++ парсер (FlowParser)** — извлекает сетевые потоки и JA4-отпечатки из PCAP
2. **Python scorer (XGBoost)** — классифицирует каждый поток как нормальный/аномальный
3. **Static analyzer** — интерпретирует аномалии через набор детерминистских правил
4. **HTML Dashboard** — визуализация для аналитика

### Категории детекции
- 🚨 Периодический TLS-маяк
- 🔍 Сканирование портов
- 💥 DoS-флуд / burst-поведение
- 📡 Веерное сканирование портов
- 🌐 Сканирование сети
- 🔁 Повторяющиеся TLS-сеансы
- ❌ Неуспешные соединения
- 📤 Исходящая эксфильтрация
- 📥 Крупный входящий поток
- ⚠️ Подозрительный TLS-профиль
""")
