# FlowGuard — пользовательские сценарии

Этот документ — практический справочник по типовым сценариям использования FlowGuard. Каждый сценарий содержит команды, ожидаемый результат и подсказки.

---

## Содержание

1. [Первичная установка](#1-первичная-установка)
2. [Анализ сетевого дампа](#2-анализ-сетевого-дампа)
3. [Веб-интерфейс](#3-веб-интерфейс)
4. [Переобучение модели на своих данных](#4-переобучение-модели-на-своих-данных)
5. [Сравнение моделей](#5-сравнение-моделей)
6. [Запуск через Docker](#6-запуск-через-docker)
7. [Интеграция в существующий пайплайн](#7-интеграция-в-существующий-пайплайн)
8. [Очистка и обслуживание](#8-очистка-и-обслуживание)

---

## 1. Первичная установка

### Сценарий 1.1: Установка с нуля (5 минут)

**Когда использовать:** свежий клон репозитория, чистая Ubuntu.

```bash
git clone https://github.com/your-org/FlowGuard.git
cd FlowGuard
./install.sh
```

**Что произойдёт:**
1. Проверка системных зависимостей (Python, CMake, g++, libpcap, PcapPlusPlus)
2. Создание виртуального окружения `.venv/`
3. Установка Python-пакетов из `requirements.txt`
4. Сборка C++ парсера
5. Создание структуры каталогов `data/`, `models/`, `reports/`, `logs/`

**Ожидаемое время:** 3–5 минут (включая сборку парсера).

### Сценарий 1.2: Установка в существующее окружение

**Когда использовать:** есть свой venv, нужна только сборка и зависимости.

```bash
source ~/my_venv/bin/activate
./install.sh --skip-venv
```

### Сценарий 1.3: Только проверка состояния

**Когда использовать:** убедиться, что всё на месте после клонирования или перед демонстрацией.

```bash
./install.sh --check-only
# или
make check
```

**Выводит:** статус всех модулей, бинаря парсера, моделей, датасетов.

### Сценарий 1.4: Переустановка только Python-зависимостей

```bash
./install.sh --skip-build
```

Пропускает сборку C++ парсера (актуально, если изменились только Python-пакеты).

---

## 2. Анализ сетевого дампа

### Сценарий 2.1: Интерактивный анализ через CLI

**Когда использовать:** первое знакомство с системой, отладка.

```bash
./scripts/flowguard.sh
```

Запустится интерактивный мастер:
- покажет доступные датасеты в `data/raw/`
- покажет доступные модели в `models/active/`
- предложит выбрать оба параметра
- запустит пайплайн

**Результат:** отчёт в `reports/latest/<dataset>/<pcap_stem>/`.

### Сценарий 2.2: Анализ из командной строки

**Когда использовать:** скрипты автоматизации, CI/CD.

```bash
# Положите PCAP в data/raw/my_capture/
cp my_traffic.pcap data/raw/my_capture/

# Запустите анализ
./scripts/flowguard.sh my_capture flow_plus_ja4
```

**Аргументы:**
- `my_capture` — имя каталога с PCAP-файлами в `data/raw/`
- `flow_plus_ja4` — имя модели из `models/active/`

### Сценарий 2.3: Готовые пресеты

```bash
./scripts/flowguard.sh --preset demo       # быстрая демо
./scripts/flowguard.sh --preset full       # полный анализ
./scripts/flowguard.sh --preset benchmark  # замер производительности
```

### Сценарий 2.4: Анализ одного PCAP-файла без сохранения в data/raw

```bash
# Через веб-интерфейс — загрузить файл через виджет
make ui
# В UI: вкладка "Запустить анализ" → "Загрузить файл"
```

### Сценарий 2.5: Что делать с результатами

После выполнения в `reports/latest/<dataset>/<pcap_stem>/` появятся:

| Файл | Что внутри |
|---|---|
| `dashboard.html` | Интерактивный дашборд (открыть в браузере) |
| `top_incidents.csv` / `.xlsx` | Топ-100 наиболее значимых инцидентов |
| `all_incidents.csv` | Полный перечень инцидентов |
| `category_stats.csv` | Распределение инцидентов по категориям |
| `timeline.csv` | Аномальная активность во времени |
| `summary.json` | Ключевые показатели запуска (для автоматизации) |

Открыть дашборд:

```bash
xdg-open reports/latest/my_capture/my_traffic/dashboard.html
```

---

## 3. Веб-интерфейс

### Сценарий 3.1: Запустить веб-интерфейс

```bash
make ui
# или
streamlit run python/flowguard/ui/flowguard_ui.py
```

Откроется на `http://localhost:8501`.

### Сценарий 3.2: Анализ через UI

1. **Страница "Запустить анализ":**
   - Выберите датасет (один из трёх способов: каталог, путь, загрузка файла)
   - Выберите обученную модель
   - Нажмите "Запустить Pipeline"
   - Дождитесь завершения (лог выводится в реальном времени)
   - Кнопка "Открыть дашборд" — откроет HTML-отчёт

2. **Страница "История запусков":**
   - Все ранее выполненные анализы
   - Поиск, сортировка, фильтрация по дате
   - Открыть дашборд одним кликом

3. **Страница "Сравнить запуски":**
   - Автоматически находит пары запусков на одинаковом датасете
   - Показывает дельты ключевых метрик

4. **Страница "О системе":**
   - Справка, версии, технологии

### Сценарий 3.3: Веб-интерфейс на другом порту

В `flowguard.yaml`:
```yaml
ui:
  port: 9000
```

Или временно:
```bash
streamlit run python/flowguard/ui/flowguard_ui.py --server.port 9000
```

### Сценарий 3.4: Удалённый доступ к UI

```bash
streamlit run python/flowguard/ui/flowguard_ui.py \
  --server.address 0.0.0.0 \
  --server.port 8501
```

Затем `http://<IP_сервера>:8501`.

---

## 4. Переобучение модели на своих данных

### Сценарий 4.1: Подготовить данные

Создайте каталог со структурой:

```
my_company_data/
├── benign/
│   ├── monday_normal.pcap
│   ├── tuesday_normal.pcap
│   └── ...
└── malicious/
    ├── attack_2024_q1.pcap
    ├── attack_2024_q2.pcap
    └── ...
```

**Требования к данным:**
- Минимум 1000 потоков на класс (рекомендуется 5000+)
- PCAP/PCAPNG любых размеров
- Чем больше разнообразия источников — тем лучше

### Сценарий 4.2: Запустить переобучение

```bash
./scripts/flowguard_retrain.sh \
  --input-dir my_company_data \
  --model-name acme_corp \
  --feature-set both
```

**Параметр `--feature-set`:**
- `flow_only` — только flow-признаки
- `flow_plus_ja4` — flow + JA4 (рекомендуется)
- `both` — обучить две модели сразу (для сравнения)

**Что произойдёт:**
1. Парсинг входных PCAP (тот же C++ парсер)
2. Source-aware и family-aware разбиение train/val/test
3. Обучение XGBoost
4. Подбор оптимального порога классификации
5. Расчёт метрик качества
6. Регистрация модели в `models/active/acme_corp/`

**Ожидаемое время:** 5–30 минут в зависимости от объёма.

### Сценарий 4.3: Использовать переобученную модель

```bash
./scripts/flowguard.sh my_dataset acme_corp
```

Или через UI: на странице "Запустить анализ" в выпадающем списке "Модель" появится `acme_corp`.

### Сценарий 4.4: Изменить гиперпараметры обучения

В `flowguard.yaml`:

```yaml
retraining:
  hyperparams:
    n_estimators: 500       # было 300
    max_depth: 8            # было 6
    learning_rate: 0.05     # было 0.1
```

Затем повторите команду из сценария 4.2.

---

## 5. Сравнение моделей

### Сценарий 5.1: A/B-сравнение через UI

Полезно после переобучения, чтобы оценить прирост качества.

1. Запустите анализ на одном датасете с моделью А: `./scripts/flowguard.sh demo_showcase flow_only`
2. Запустите анализ с моделью Б: `./scripts/flowguard.sh demo_showcase flow_plus_ja4`
3. Откройте UI → страница "Сравнить запуски"
4. Выберите две модели в выпадающих списках
5. Получите дельты по precision, recall, F1, FPR, числу инцидентов

### Сценарий 5.2: Сравнение через сравнительный анализ

```bash
# Создаём две модели с разными гиперпараметрами
./scripts/flowguard_retrain.sh --input-dir my_data --model-name model_a --feature-set flow_plus_ja4
./scripts/flowguard_retrain.sh --input-dir my_data --model-name model_b --feature-set flow_plus_ja4

# Прогоняем на тестовом датасете
./scripts/flowguard.sh test_dataset model_a
./scripts/flowguard.sh test_dataset model_b

# Сравниваем через UI или вручную через reports/runs_index.json
```

---

## 6. Запуск через Docker

### Сценарий 6.1: Однокомандный запуск веб-интерфейса

**Когда использовать:** когда не хочется ставить зависимости в систему.

```bash
docker compose up
```

Контейнер соберётся (первый раз — 5-10 минут), затем UI будет доступен на `http://localhost:8501`.

Остановить: `Ctrl+C` или `docker compose down`.

### Сценарий 6.2: Запуск в фоне

```bash
docker compose up -d
docker compose logs -f flowguard  # смотреть логи
docker compose down                # остановить
```

### Сценарий 6.3: CLI-команды в контейнере

```bash
# Интерактивная оболочка
docker compose run --rm cli

# Внутри контейнера:
./scripts/flowguard.sh --preset demo
exit
```

### Сценарий 6.4: Прямой запуск анализа в контейнере

```bash
docker compose run --rm cli ./scripts/flowguard.sh demo_showcase flow_plus_ja4
```

Результаты автоматически появятся в локальном каталоге `./reports/` (через volume).

### Сценарий 6.5: Свой конфиг для контейнера

Локальный `flowguard.yaml` автоматически монтируется внутрь контейнера. Изменения в нём подхватываются при следующем запуске.

---

## 7. Интеграция в существующий пайплайн

### Сценарий 7.1: Использовать как CLI-инструмент

```bash
#!/bin/bash
# my_pipeline.sh — пример интеграции в скрипт SOC

for pcap in /captures/*.pcap; do
    dataset_name=$(basename "$pcap" .pcap)
    mkdir -p "data/raw/$dataset_name"
    cp "$pcap" "data/raw/$dataset_name/"

    ./scripts/flowguard.sh "$dataset_name" flow_plus_ja4

    # Передать summary.json в SIEM
    curl -X POST https://siem.local/api/events \
      -d @"reports/latest/$dataset_name/${dataset_name}/summary.json"
done
```

### Сценарий 7.2: Программный доступ к результатам

```python
import json
from pathlib import Path

# После анализа
summary_path = Path("reports/latest/my_capture/my_traffic/summary.json")
summary = json.loads(summary_path.read_text())

print(f"Аномальных потоков: {summary['anomalous_count']}")
print(f"Главная категория: {summary['top_category']}")
print(f"Критических инцидентов: {summary['critical_incidents']}")
```

### Сценарий 7.3: Программное обращение к признакам потоков

```python
import pandas as pd

flows = pd.read_csv("data/interim/my_capture/my_traffic.csv")

# Применить свою постобработку
suspicious = flows[
    (flows["anomaly_score"] > 0.7) &
    (flows["server_port"] == 443)
]
print(suspicious[["client_ip", "server_ip", "anomaly_score"]])
```

### Сценарий 7.4: Использование как Python-пакета

После `make install`:

```python
from flowguard.config import get_config
from flowguard.parsing import batch_parse_pcaps
# ... и т.д.

cfg = get_config()
print(cfg.model.default)
```

---

## 8. Очистка и обслуживание

### Сценарий 8.1: Очистка промежуточных данных

```bash
make clean
```

Удалит:
- `cpp/FlowParser/build/`
- `data/parsed/`, `data/interim/`, `data/retrain/`
- `reports/latest/*`
- Кеши Python

### Сценарий 8.2: Полная переустановка

```bash
make clean-all      # удалить venv + историю запусков
./install.sh        # установить заново
```

### Сценарий 8.3: Проверка статуса перед демонстрацией

```bash
make check
```

Покажет:
- Состояние Python-окружения и пакетов
- Доступность C++ парсера
- Список обученных моделей
- Список датасетов
- Историю запусков

### Сценарий 8.4: Запуск тестов

```bash
make test           # все тесты (verbose)
make test-fast      # быстрые
make test-cov       # с покрытием → htmlcov/index.html
```

### Сценарий 8.5: Линтинг и форматирование (для разработчиков)

```bash
make lint           # проверка кода через ruff
make format         # автоформатирование через black + isort
```

---

## Быстрая шпаргалка

| Что нужно | Команда |
|---|---|
| Установить с нуля | `./install.sh` |
| Проверить состояние | `make check` |
| Запустить анализ интерактивно | `./scripts/flowguard.sh` |
| Запустить анализ автоматически | `./scripts/flowguard.sh <dataset> <model>` |
| Веб-интерфейс | `make ui` |
| Переобучить модель | `./scripts/flowguard_retrain.sh --input-dir ... --model-name ...` |
| Запуск в Docker | `docker compose up` |
| Тесты | `make test` |
| Очистка | `make clean` |
| Полная очистка | `make clean-all` |
