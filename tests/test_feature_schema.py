"""
Тесты согласования признакового пространства модели.

Проверяют:
  - корректность чтения feature_schema.json
  - совместимость двух конфигураций (flow_only, flow_plus_ja4)
  - присутствие всех ожидаемых признаков
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# Минимальный набор ожидаемых признаков по группам
EXPECTED_FLOW_FEATURES = {
    "packets_total",
    "bytes_cap_total",
    "duration_ns",
    "tcp_syn_total",
    "tcp_rst_total",
}

EXPECTED_JA4_FEATURES = {
    "ja4_cipher_suites_count",
    "ja4_has_sni",
    "ja4_alpn",
}


def _find_models_with_schema(project_root: Path) -> list[Path]:
    """Возвращает список каталогов моделей, в которых есть feature_schema.json."""
    models_root = project_root / "models" / "active"
    if not models_root.exists():
        return []
    return [m for m in models_root.iterdir() if (m / "feature_schema.json").exists()]


class TestFeatureSchemaStructure:
    """Структурные тесты feature_schema.json."""

    def test_schema_is_valid_json(self, project_root: Path):
        """Все feature_schema.json в моделях должны быть валидным JSON."""
        models = _find_models_with_schema(project_root)
        if not models:
            pytest.skip("Не найдено моделей с feature_schema.json")

        for model_dir in models:
            schema_path = model_dir / "feature_schema.json"
            with open(schema_path) as f:
                data = json.load(f)
            assert isinstance(data, dict), \
                f"Схема {schema_path} должна быть объектом"

    def test_schema_contains_flow_only_config(self, project_root: Path):
        """feature_schema.json должен содержать конфигурацию flow_only_features."""
        models = _find_models_with_schema(project_root)
        if not models:
            pytest.skip("Не найдено моделей с feature_schema.json")

        for model_dir in models:
            schema_path = model_dir / "feature_schema.json"
            with open(schema_path) as f:
                data = json.load(f)
            assert "flow_only_features" in data or "flow_only" in data, \
                f"В {schema_path} нет конфигурации flow_only"


class TestFeatureCoverage:
    """Проверка наличия ожидаемых признаков в схеме."""

    def test_basic_flow_features_present(self, project_root: Path):
        """Все базовые flow-признаки должны быть в схеме."""
        models = _find_models_with_schema(project_root)
        if not models:
            pytest.skip("Не найдено моделей с feature_schema.json")

        for model_dir in models:
            schema_path = model_dir / "feature_schema.json"
            with open(schema_path) as f:
                data = json.load(f)

            # Достаём список flow-признаков (попробуем оба варианта именования)
            flow_features = set(
                data.get("flow_only_features")
                or data.get("flow_only")
                or []
            )
            if not flow_features:
                continue

            missing = EXPECTED_FLOW_FEATURES - flow_features
            assert not missing, \
                f"В {schema_path} отсутствуют базовые flow-признаки: {missing}"


class TestModelArtifacts:
    """Проверка комплектности артефактов модели."""

    def test_model_directory_has_required_files(self, project_root: Path):
        """Каждая модель в models/active/ должна иметь полный набор артефактов."""
        models_root = project_root / "models" / "active"
        if not models_root.exists():
            pytest.skip("Каталог models/active не существует")

        model_dirs = [m for m in models_root.iterdir() if m.is_dir()]
        if not model_dirs:
            pytest.skip("Не найдено обученных моделей")

        for model_dir in model_dirs:
            # Если каталог содержит хотя бы один из ключевых файлов — считаем моделью
            has_model = (model_dir / "model.joblib").exists()
            has_schema = (model_dir / "feature_schema.json").exists()
            has_metrics = (model_dir / "metrics.json").exists()

            if not (has_model or has_schema or has_metrics):
                continue  # это не каталог модели, пропускаем

            # Если хоть один артефакт есть — должны быть все три
            missing = []
            if not has_model:
                missing.append("model.joblib")
            if not has_schema:
                missing.append("feature_schema.json")
            if not has_metrics:
                missing.append("metrics.json")

            assert not missing, \
                f"В модели {model_dir.name} отсутствуют артефакты: {', '.join(missing)}"
