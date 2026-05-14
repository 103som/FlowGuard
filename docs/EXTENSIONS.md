# FlowGuard — руководство по расширению

FlowGuard построен как **модульный конструктор**: ключевые компоненты можно заменить или расширить с минимальными изменениями кода. Этот документ описывает четыре основных сценария кастомизации.

---

## Содержание

1. [Замена ML-модели](#1-замена-ml-модели)
2. [Изменение признакового пространства](#2-изменение-признакового-пространства)
3. [Добавление правил категоризации инцидентов](#3-добавление-правил-категоризации-инцидентов)
4. [Настройка через `flowguard.yaml`](#4-настройка-через-flowguardyaml)

---

## 1. Замена ML-модели

FlowGuard может работать с любой моделью бинарной классификации, совместимой со sklearn-Pipeline. Замена не требует изменения кода в основном пайплайне.

### Вариант А: переобучить штатным сценарием

Этот вариант рекомендуется в большинстве случаев.

```bash
# Подготовьте данные:
my_data/
├── benign/        ← легитимные PCAP
└── malicious/     ← вредоносные PCAP

# Запустите переобучение:
./scripts/flowguard_retrain.sh \
  --input-dir my_data \
  --model-name my_model \
  --feature-set both
```

Новая модель появится в `models/active/my_model/` и сразу будет доступна:

```bash
./scripts/flowguard.sh <dataset> my_model
```

### Вариант Б: использовать свою архитектуру алгоритма

Если хотите заменить XGBoost на LightGBM/CatBoost/нейронную сеть — отредактируйте `python/flowguard/training/pipelines/train_xgb_experiment2.py` (или создайте новый скрипт обучения по аналогии).

**Главное требование:** сохранить три файла в `models/active/<model_name>/`:

| Файл | Содержимое |
|---|---|
| `model.joblib` | Сериализованный объект с методом `.predict_proba()` |
| `feature_schema.json` | Список ожидаемых признаков (см. ниже) |
| `metrics.json` | Метрики качества + `selected_threshold_from_val` |

**Пример сохранения произвольной модели:**

```python
import joblib
import json
from pathlib import Path
from sklearn.pipeline import Pipeline

# Ваша обученная модель
pipeline: Pipeline = ...  # должен иметь .predict_proba()

model_dir = Path("models/active/my_custom_model")
model_dir.mkdir(parents=True, exist_ok=True)

# 1. Модель
joblib.dump(pipeline, model_dir / "model.joblib")

# 2. Схема признаков
schema = {
    "flow_only_features": ["packets_total", "bytes_cap_total", ...],
    "flow_plus_ja4_features": ["packets_total", ..., "ja4_cipher_suites_count", ...],
}
(model_dir / "feature_schema.json").write_text(json.dumps(schema, indent=2))

# 3. Метрики и порог
metrics = {
    "precision": 0.95,
    "recall": 0.98,
    "f1": 0.96,
    "selected_threshold_from_val": 0.52,
}
(model_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
```

После этого модель работает с основным пайплайном без правок:

```bash
./scripts/flowguard.sh <dataset> my_custom_model
```

### Замена модели по умолчанию

В `flowguard.yaml`:

```yaml
model:
  default: my_custom_model
  feature_set: flow_plus_ja4    # или flow_only
```

---

## 2. Изменение признакового пространства

FlowGuard поддерживает две конфигурации признакового пространства из коробки: `flow_only` (24 признака) и `flow_plus_ja4` (30 признаков). Расширить пространство можно тремя способами.

### Способ А: добавить признак, который уже считает C++ парсер

Если парсер уже извлекает нужное значение, но оно не используется моделью:

1. Откройте `feature_schema.json` своей модели.
2. Добавьте имя колонки в массив `flow_plus_ja4_features`:

```json
{
  "flow_plus_ja4_features": [
    "packets_total",
    "bytes_cap_total",
    ...
    "my_new_feature"
  ]
}
```

3. Переобучите модель — она автоматически возьмёт новое поле.

### Способ Б: добавить новый признак в C++ парсер

Это требует правки кода парсера. Шаги:

1. **Добавить поле в `FlowTypes.h`** (структура `FlowState` или аналогичная):

```cpp
struct FlowState {
    // ... существующие поля ...
    uint32_t my_custom_counter = 0;
};
```

2. **Заполнять поле в `FlowParser.cpp`** при обработке пакета:

```cpp
// внутри processPacket():
if (some_condition) {
    state.my_custom_counter++;
}
```

3. **Добавить вывод в CSV** (в функции экспорта):

```cpp
out << state.my_custom_counter << ",";
```

4. **Обновить заголовок CSV** — соответствующий ему список колонок:

```cpp
const std::vector<std::string> CSV_HEADERS = {
    "packets_total", "bytes_cap_total", ..., "my_custom_counter"
};
```

5. **Пересобрать парсер**:

```bash
make build
```

6. **Добавить колонку в feature_schema.json** и переобучить модель.

### Способ В: производный признак на этапе Python (без правки парсера)

Если новый признак вычисляется из уже извлечённых полей, проще добавить его в Python-обёртке.

Создайте файл `python/flowguard/parsing/feature_engineering.py`:

```python
"""Производные признаки, вычисляемые после парсинга."""
import pandas as pd

def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # пример: отношение исходящего трафика к входящему
    df["bytes_ratio_fwd_bwd"] = (
        df["bytes_cap_fwd"] / df["bytes_cap_bwd"].clip(lower=1)
    )
    # пример: средний размер пакета
    df["avg_packet_size"] = (
        df["bytes_cap_total"] / df["packets_total"].clip(lower=1)
    )
    return df
```

Вызовите эту функцию в `python/flowguard/parsing/batch_parse_pcaps.py` после получения CSV. Затем добавьте новые признаки в `feature_schema.json` и переобучите модель.

---

## 3. Добавление правил категоризации инцидентов

Категоризация инцидентов — детерминированная (набор if-else правил), чтобы аналитик мог проследить логику решения.

### Где находится логика

Файл: `python/flowguard/analysis/stat_analyzer.py`
Функция: `classify_incident(incident: dict) -> str`

### Шаг 1. Добавить новую категорию

Откройте `stat_analyzer.py` и найдите функцию `classify_incident`. Добавьте новую ветку правила:

```python
def classify_incident(incident: dict) -> str:
    # ... существующие категории ...

    # --- новая категория: "Странный SNI" ---
    if (
        incident["is_tls"]
        and incident.get("unique_snis", 0) > 50
        and incident["avg_score"] > 0.7
    ):
        return "Странный SNI"

    # ... остальные категории ...

    return "Неклассифицированная аномалия"
```

### Шаг 2. Добавить бонус серьёзности (опционально)

В функции `calculate_severity(incident: dict) -> float`:

```python
def calculate_severity(incident: dict) -> float:
    base = incident["avg_score"]

    category_bonuses = {
        "Исходящая эксфильтрация": 0.35,
        "DoS-флуд": 0.40,
        # ...
        "Странный SNI": 0.20,   # ← новая
    }

    bonus = category_bonuses.get(incident["category"], 0.0)
    return min(base + bonus, 1.0)
```

### Шаг 3. Обновить документацию (для аналитика)

Добавьте описание категории в `docs/CATEGORIES.md` или README, чтобы пользователь видел список из 13 категорий вместо 12.

### Шаг 4. Через конфиг (для уже существующих категорий)

В `flowguard.yaml` можно настроить параметры существующих правил без изменения кода:

```yaml
analysis:
  categories:
    port_scan:
      enabled: true
      min_unique_ports: 15      # было 10
      severity_bonus: 0.30      # было 0.25
```

---

## 4. Настройка через `flowguard.yaml`

Файл `flowguard.yaml` в корне проекта — это **точка управления поведением системы без правок кода**.

### Что можно настроить

| Раздел | Что регулирует |
|---|---|
| `model.default` | Какая модель используется по умолчанию |
| `model.feature_set` | flow_only / flow_plus_ja4 |
| `model.threshold_override` | Подменить порог классификации (`null` → значение из модели) |
| `parser.binary` | Путь к C++ парсеру (если перенесли) |
| `analysis.min_anomaly_score` | Минимальный порог для попадания в инциденты |
| `analysis.aggregation_key` | Как группировать аномальные потоки |
| `analysis.categories.*` | Параметры детерминированных правил |
| `severity.thresholds` | Границы уровней (критический / высокий / средний / низкий) |
| `reporting.top_incidents_count` | Сколько инцидентов в топ-таблице |
| `ui.port` | Порт для Streamlit |
| `retraining.algorithm` | Алгоритм обучения (xgboost / lightgbm / random_forest) |
| `retraining.hyperparams` | Гиперпараметры обучения |

### Как использовать конфиг из Python-модуля

```python
from flowguard.config import get_config

cfg = get_config()
model_name = cfg.model.default
threshold = cfg.model.threshold_override or 0.5
top_n = cfg.reporting.top_incidents_count
```

### Указать свой конфиг для одного запуска

```bash
FLOWGUARD_CONFIG=/path/to/my.yaml ./scripts/flowguard.sh
```

Это удобно для A/B-сценариев или экспериментов без правки основного `flowguard.yaml`.

---

## Контрольные точки расширения — резюме

| Что меняем | Где править | Минимум правок? |
|---|---|---|
| **Модель ML** | переобучить через `flowguard_retrain.sh` | да (без кода) |
| **Параметры модели** | `flowguard.yaml` → `retraining.hyperparams` | да |
| **Алгоритм обучения** | `python/flowguard/training/pipelines/train_xgb_experiment2.py` | средне |
| **Новый признак из C++** | `cpp/FlowParser/src/*` + пересборка | средне |
| **Производный признак** | новый файл `parsing/feature_engineering.py` | да |
| **Новая категория инцидента** | `analysis/stat_analyzer.py` (функция `classify_incident`) | малая |
| **Параметры существующих категорий** | `flowguard.yaml` → `analysis.categories` | да (без кода) |
| **Уровни серьёзности** | `flowguard.yaml` → `severity.thresholds` | да |
| **Внешний вид дашборда** | `python/flowguard/reporting/dashboard_html.py` | средне |
| **Каталоги данных** | `flowguard.yaml` → `paths.*` | да |
| **Порог классификации** | `flowguard.yaml` → `model.threshold_override` | да |
| **Порт UI** | `flowguard.yaml` → `ui.port` | да |

---

## Принципы хорошего расширения

1. **Сохраняйте обратную совместимость.** Если меняете схему данных — добавляйте поле как опциональное.
2. **Документируйте новые категории/признаки** в README и `CHANGELOG.md`.
3. **Пишите тесты** в `tests/` для новых функций (хотя бы один smoke-тест).
4. **Используйте `flowguard.yaml`** для конфигурируемых значений — не «зашивайте» магические числа в код.
5. **При замене модели проверяйте** через `make check` и сравнительный анализ в UI (страница «Сравнить запуски»).
