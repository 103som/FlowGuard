#!/usr/bin/env python3
"""
Генератор HTML-индекса всех запусков pipeline.

Читает runs_index.json и собирает красивую страницу со списком запусков,
ссылками на дашборды и агрегированной статистикой.

Использование:
    python3 runs_index_html.py --runs-json reports/runs_index.json --output reports/runs_index.html
"""
from __future__ import annotations

import argparse
import html
import json
from datetime import datetime
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Генератор HTML-индекса запусков FlowGuard")
    p.add_argument("--runs-json", required=True, help="Путь к runs_index.json")
    p.add_argument("--output", required=True, help="Путь к выходному HTML")
    p.add_argument("--title", default="FlowGuard: история запусков",
                   help="Заголовок страницы")
    return p.parse_args()


def format_timestamp(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%d.%m.%Y %H:%M:%S")
    except (ValueError, TypeError):
        return iso_str


def format_duration(seconds: int) -> str:
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


def format_int(value) -> str:
    try:
        return f"{int(value):,}".replace(",", " ")
    except Exception:
        return "0"


def format_pct(num, den) -> str:
    try:
        if float(den) == 0:
            return "—"
        return f"{100 * float(num) / float(den):.2f}%"
    except Exception:
        return "—"


def build_run_card(run: dict, is_latest: bool = False) -> str:
    """HTML-карточка одного запуска."""
    timestamp = format_timestamp(run.get("timestamp", ""))
    dataset = html.escape(str(run.get("dataset", "—")))
    model = html.escape(str(run.get("model", "—")))
    duration = format_duration(run.get("duration_seconds", 0))
    flows_total = run.get("flows_total", 0)
    anomalies = run.get("anomalies_total", 0)
    incidents = run.get("incidents_total", 0)
    top_category = html.escape(str(run.get("top_category", "—")))
    reports_dir = run.get("reports_dir", "")

    # Ищем dashboard.html — первый встретившийся
    dashboard_link = ""
    reports_path = Path(reports_dir)
    if reports_path.exists():
        html_files = list(reports_path.rglob("dashboard.html"))
        if html_files:
            rel_path = html_files[0]
            dashboard_link = f'<a href="file://{rel_path}" class="btn-open" target="_blank">🔗 Открыть dashboard</a>'
        else:
            dashboard_link = '<span class="btn-muted">Dashboard не найден</span>'

    latest_badge = '<span class="badge-latest">Последний</span>' if is_latest else ""

    anomaly_pct = format_pct(anomalies, flows_total)

    return f"""
    <div class="run-card {'run-card-latest' if is_latest else ''}">
      <div class="run-header">
        <div>
          <div class="run-timestamp">{html.escape(timestamp)} {latest_badge}</div>
          <div class="run-dataset">{dataset}</div>
        </div>
        <div class="run-duration">⏱ {html.escape(duration)}</div>
      </div>

      <div class="run-stats">
        <div class="stat-block">
          <div class="stat-value">{format_int(flows_total)}</div>
          <div class="stat-label">сессий</div>
        </div>
        <div class="stat-block">
          <div class="stat-value">{format_int(anomalies)}</div>
          <div class="stat-label">аномалий ({anomaly_pct})</div>
        </div>
        <div class="stat-block">
          <div class="stat-value">{format_int(incidents)}</div>
          <div class="stat-label">инцидентов</div>
        </div>
      </div>

      <div class="run-meta">
        <div><span class="meta-label">Модель:</span> {model}</div>
        <div><span class="meta-label">Главная категория:</span> {top_category}</div>
        <div><span class="meta-label">Отчёты:</span> <code>{html.escape(reports_dir)}</code></div>
      </div>

      <div class="run-actions">
        {dashboard_link}
      </div>
    </div>
    """


def build_aggregate_stats(runs: list) -> str:
    """Агрегированная статистика по всем запускам."""
    if not runs:
        return ""

    total_runs = len(runs)
    total_flows = sum(int(r.get("flows_total", 0)) for r in runs)
    total_anomalies = sum(int(r.get("anomalies_total", 0)) for r in runs)
    total_incidents = sum(int(r.get("incidents_total", 0)) for r in runs)
    total_duration_s = sum(int(r.get("duration_seconds", 0)) for r in runs)
    unique_datasets = len({r.get("dataset") for r in runs})

    # Самая частая категория
    categories = [r.get("top_category", "—") for r in runs]
    categories = [c for c in categories if c and c != "—"]
    most_common_cat = "—"
    if categories:
        from collections import Counter
        most_common_cat = Counter(categories).most_common(1)[0][0]

    return f"""
    <div class="agg-stats">
      <div class="agg-card">
        <div class="agg-value">{format_int(total_runs)}</div>
        <div class="agg-label">запусков</div>
      </div>
      <div class="agg-card">
        <div class="agg-value">{format_int(unique_datasets)}</div>
        <div class="agg-label">датасетов</div>
      </div>
      <div class="agg-card">
        <div class="agg-value">{format_int(total_flows)}</div>
        <div class="agg-label">сессий всего</div>
      </div>
      <div class="agg-card">
        <div class="agg-value">{format_int(total_anomalies)}</div>
        <div class="agg-label">аномалий всего</div>
      </div>
      <div class="agg-card">
        <div class="agg-value">{format_int(total_incidents)}</div>
        <div class="agg-label">инцидентов всего</div>
      </div>
      <div class="agg-card">
        <div class="agg-value">{format_duration(total_duration_s)}</div>
        <div class="agg-label">суммарное время</div>
      </div>
    </div>

    <div class="agg-insight">
      <strong>Наиболее частая главная категория:</strong> {html.escape(most_common_cat)}
    </div>
    """


CSS = """
:root {
  --bg: #091228;
  --panel: #0f1a33;
  --panel-border: #213250;
  --muted: #9fb0c9;
  --text: #edf2fb;
  --accent: #5cb3ff;
  --green: #47e082;
  --orange: #e89a3c;
  --red: #e04747;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, "Segoe UI", Arial, sans-serif;
  padding: 24px;
}
.wrapper { max-width: 1400px; margin: 0 auto; }
h1 { margin: 0 0 6px; font-size: 32px; }
.subtitle { color: var(--muted); margin-bottom: 28px; font-size: 15px; }

.agg-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
  margin-bottom: 20px;
}
.agg-card {
  background: linear-gradient(180deg, #0c1730, #0b1630);
  border: 1px solid var(--panel-border);
  border-radius: 16px;
  padding: 16px 18px;
}
.agg-value {
  font-size: 26px;
  font-weight: 700;
  color: var(--accent);
}
.agg-label {
  color: var(--muted);
  font-size: 13px;
  margin-top: 6px;
}
.agg-insight {
  background: rgba(92, 179, 255, 0.08);
  border: 1px solid rgba(92, 179, 255, 0.25);
  border-radius: 12px;
  padding: 12px 18px;
  margin-bottom: 28px;
  font-size: 14px;
}

.run-card {
  background: rgba(15, 26, 51, 0.95);
  border: 1px solid var(--panel-border);
  border-radius: 16px;
  padding: 20px 22px;
  margin-bottom: 14px;
  transition: border-color 0.15s, transform 0.15s;
}
.run-card:hover {
  border-color: var(--accent);
  transform: translateX(2px);
}
.run-card-latest {
  border-color: rgba(92, 179, 255, 0.6);
  box-shadow: 0 0 0 1px rgba(92, 179, 255, 0.25);
}
.run-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 14px;
  gap: 14px;
}
.run-timestamp {
  color: var(--muted);
  font-size: 13px;
  margin-bottom: 4px;
}
.run-dataset {
  font-size: 20px;
  font-weight: 600;
}
.run-duration {
  color: var(--muted);
  font-size: 14px;
  white-space: nowrap;
}
.badge-latest {
  display: inline-block;
  background: var(--green);
  color: #0e1a37;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  margin-left: 6px;
  vertical-align: middle;
}
.run-stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  background: rgba(0, 0, 0, 0.15);
  border-radius: 10px;
  padding: 12px;
  margin-bottom: 14px;
}
.stat-block {
  text-align: center;
}
.stat-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--accent);
}
.stat-label {
  color: var(--muted);
  font-size: 12px;
  margin-top: 2px;
}
.run-meta {
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 14px;
  display: grid;
  gap: 4px;
}
.meta-label {
  color: var(--text);
  font-weight: 500;
}
code {
  background: rgba(255,255,255,0.05);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 12px;
  color: #b8d5f0;
}
.run-actions { display: flex; gap: 8px; }
.btn-open, .btn-muted {
  display: inline-block;
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 13px;
  text-decoration: none;
  border: 1px solid var(--accent);
}
.btn-open {
  background: rgba(92, 179, 255, 0.15);
  color: var(--accent);
}
.btn-open:hover {
  background: rgba(92, 179, 255, 0.25);
}
.btn-muted {
  color: var(--muted);
  border-color: var(--panel-border);
  cursor: not-allowed;
}
.empty-state {
  text-align: center;
  color: var(--muted);
  padding: 60px 20px;
  border: 1px dashed var(--panel-border);
  border-radius: 16px;
}
"""


def main() -> None:
    args = parse_args()
    runs_json_path = Path(args.runs_json)
    output_path = Path(args.output)

    runs = []
    if runs_json_path.exists():
        try:
            runs = json.loads(runs_json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            runs = []

    # Карточки
    if runs:
        cards_html = "\n".join(
            build_run_card(run, is_latest=(i == 0))
            for i, run in enumerate(runs)
        )
    else:
        cards_html = """
        <div class="empty-state">
          <h3>История пока пуста</h3>
          <p>Запустите FlowGuard pipeline, и запуски появятся здесь.</p>
          <p><code>./flowguard.sh --preset demo</code></p>
        </div>
        """

    agg_html = build_aggregate_stats(runs)

    now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    html_text = f"""<!doctype html>
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
    <div class="subtitle">
      Полная история запусков FlowGuard pipeline.
      Последнее обновление: {now}.
    </div>

    {agg_html}

    <h2 style="margin-bottom: 14px;">Хронология запусков</h2>
    {cards_html}
  </div>
</body>
</html>
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_text, encoding="utf-8")
    print(f"[ОК] Индекс запусков: {output_path}")


if __name__ == "__main__":
    main()
