"""
Тесты модуля flowguard.config — централизованной конфигурации.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_config_module_imports():
    """Модуль конфигурации должен импортироваться."""
    from flowguard import config
    assert hasattr(config, "get_config")


def test_default_config_has_required_sections():
    """В DEFAULT_CONFIG должны быть все основные секции."""
    from flowguard.config import DEFAULT_CONFIG

    required = ["model", "parser", "analysis", "severity",
                "reporting", "ui", "paths", "logging", "retraining"]
    for section in required:
        assert section in DEFAULT_CONFIG, f"Отсутствует секция '{section}'"


def test_get_config_returns_section():
    """get_config() должен возвращать объект с доступом через точку."""
    from flowguard.config import get_config

    cfg = get_config(reload=True)
    # Должны быть атрибуты с доступом через точку
    assert hasattr(cfg, "model")
    assert hasattr(cfg.model, "default")
    assert hasattr(cfg, "severity")
    assert hasattr(cfg.severity, "thresholds")


def test_default_model_is_flow_plus_ja4():
    """По умолчанию модель должна быть flow_plus_ja4 (рекомендуемая)."""
    from flowguard.config import DEFAULT_CONFIG
    assert DEFAULT_CONFIG["model"]["default"] == "flow_plus_ja4"


def test_severity_thresholds_descending():
    """Пороги серьёзности должны убывать: critical > high > medium > low."""
    from flowguard.config import get_config

    cfg = get_config(reload=True)
    t = cfg.severity.thresholds
    assert t.critical > t.high
    assert t.high > t.medium
    assert t.medium >= t.low


def test_config_path_detection(project_root: Path):
    """get_config_path() должен находить flowguard.yaml."""
    from flowguard.config import get_config_path

    # Меняем cwd на корень проекта для поиска
    original_cwd = os.getcwd()
    try:
        os.chdir(project_root)
        path = get_config_path()
        if (project_root / "flowguard.yaml").exists():
            assert path is not None, "flowguard.yaml существует, но get_config_path вернул None"
            assert path.name == "flowguard.yaml"
    finally:
        os.chdir(original_cwd)


def test_env_variable_override(tmp_path: Path, monkeypatch):
    """FLOWGUARD_CONFIG должен переопределять путь к конфигу."""
    custom_config = tmp_path / "custom.yaml"
    custom_config.write_text("""
model:
  default: my_custom_model
  feature_set: flow_only
""")

    monkeypatch.setenv("FLOWGUARD_CONFIG", str(custom_config))
    from flowguard.config import get_config

    cfg = get_config(reload=True)
    assert cfg.model.default == "my_custom_model"
    assert cfg.model.feature_set == "flow_only"
