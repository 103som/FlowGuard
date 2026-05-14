"""
FlowGuard — модуль чтения конфигурации.

Этот модуль — единая точка чтения flowguard.yaml для всех остальных компонентов.

Использование:
    from flowguard.config import get_config

    cfg = get_config()
    model_dir = cfg.model.default
    threshold = cfg.severity.thresholds.critical
    threshold_override = cfg.model.threshold_override  # None или float

Если flowguard.yaml не найден — возвращаются значения по умолчанию,
зашитые в DEFAULT_CONFIG ниже. Это позволяет системе работать
"из коробки" без явной конфигурации.

Любой модуль может переопределить путь к конфигу через переменную окружения:
    FLOWGUARD_CONFIG=/path/to/my.yaml python my_script.py
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# =============================================================================
# Значения по умолчанию
# =============================================================================
DEFAULT_CONFIG: dict[str, Any] = {
    "model": {
        "default": "flow_plus_ja4",
        "feature_set": "flow_plus_ja4",
        "models_dir": "models/active",
        "threshold_override": None,
    },
    "parser": {
        "binary": "cpp/FlowParser/build/pcap_flow_parser",
        "timeout_per_file": 600,
        "skip_existing": True,
    },
    "analysis": {
        "min_anomaly_score": 0.5,
        "min_flows_per_incident": 1,
        "aggregation_key": "client_server_port",
        "categories": {},
    },
    "severity": {
        "thresholds": {
            "critical": 0.85,
            "high": 0.65,
            "medium": 0.45,
            "low": 0.0,
        },
    },
    "reporting": {
        "top_incidents_count": 100,
        "formats": {
            "csv": True,
            "xlsx": True,
            "json": True,
            "html_dashboard": True,
        },
        "reports_dir": "reports/latest",
        "history_index": "reports/runs_index.json",
    },
    "ui": {
        "host": "0.0.0.0",
        "port": 8501,
        "open_browser": True,
    },
    "paths": {
        "raw_dir": "data/raw",
        "parsed_dir": "data/parsed",
        "interim_dir": "data/interim",
        "retrain_dir": "data/retrain",
    },
    "logging": {
        "level": "INFO",
        "log_dir": "logs",
        "console": True,
        "file": True,
    },
    "retraining": {
        "algorithm": "xgboost",
        "hyperparams": {
            "n_estimators": 300,
            "max_depth": 6,
            "learning_rate": 0.1,
            "random_state": 42,
        },
        "split": {
            "method": "source_aware_family_aware",
            "train_ratio": 0.6,
            "val_ratio": 0.2,
            "test_ratio": 0.2,
        },
        "threshold_selection": "f1_balanced",
    },
}


# =============================================================================
# Контейнер конфигурации с доступом через точку (config.model.default)
# =============================================================================
class ConfigSection:
    """Обёртка над dict, позволяющая обращаться к ключам через точку."""

    def __init__(self, data: dict[str, Any]):
        self._data = data
        for key, value in data.items():
            if isinstance(value, dict):
                setattr(self, key, ConfigSection(value))
            else:
                setattr(self, key, value)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return self._data


# =============================================================================
# Слияние словарей (для применения пользовательского конфига поверх дефолтного)
# =============================================================================
def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# =============================================================================
# Главная функция: get_config()
# =============================================================================
_cached_config: ConfigSection | None = None


def get_config(reload: bool = False) -> ConfigSection:
    """
    Возвращает текущую конфигурацию FlowGuard.

    Поиск файла:
      1. путь из FLOWGUARD_CONFIG (переменная окружения);
      2. ./flowguard.yaml (относительно текущего каталога);
      3. <корень репозитория>/flowguard.yaml;
      4. если ничего не найдено — DEFAULT_CONFIG.

    Args:
        reload: принудительно перечитать файл (даже если был закеширован).

    Returns:
        ConfigSection с доступом через точку.
    """
    global _cached_config
    if _cached_config is not None and not reload:
        return _cached_config

    candidates: list[Path] = []
    env_path = os.environ.get("FLOWGUARD_CONFIG")
    if env_path:
        candidates.append(Path(env_path))

    candidates.append(Path.cwd() / "flowguard.yaml")

    # Корень репо: подняться выше до маркера .git или install.sh
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "install.sh").exists() or (parent / ".git").exists():
            candidates.append(parent / "flowguard.yaml")
            break

    cfg_data = dict(DEFAULT_CONFIG)

    for path in candidates:
        if path.exists() and path.is_file():
            if not _HAS_YAML:
                print(f"[WARN] flowguard.yaml найден ({path}), но PyYAML не установлен")
                print("       Установите: pip install pyyaml")
                break
            with open(path, encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
            cfg_data = _deep_merge(DEFAULT_CONFIG, user_cfg)
            break

    _cached_config = ConfigSection(cfg_data)
    return _cached_config


def get_config_path() -> Path | None:
    """Возвращает путь к фактически загруженному файлу конфига (или None)."""
    env_path = os.environ.get("FLOWGUARD_CONFIG")
    if env_path and Path(env_path).exists():
        return Path(env_path)

    cwd_path = Path.cwd() / "flowguard.yaml"
    if cwd_path.exists():
        return cwd_path

    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "install.sh").exists() or (parent / ".git").exists():
            candidate = parent / "flowguard.yaml"
            if candidate.exists():
                return candidate
            break
    return None


if __name__ == "__main__":
    # Диагностический режим: показывает, что грузится
    cfg = get_config()
    path = get_config_path()
    print(f"Загружен конфиг: {path or 'значения по умолчанию (файл не найден)'}")
    print(f"Модель по умолчанию:    {cfg.model.default}")
    print(f"Признаковое пространство: {cfg.model.feature_set}")
    print(f"Порог critical:         {cfg.severity.thresholds.critical}")
    print(f"Каталог моделей:        {cfg.model.models_dir}")
    print(f"Порт UI:                {cfg.ui.port}")
