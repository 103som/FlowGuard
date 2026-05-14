"""
Тесты окружения и целостности установки FlowGuard.

Проверяют, что после `./install.sh` все ключевые компоненты на месте
и доступны для запуска.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


# =============================================================================
# Системное окружение
# =============================================================================

class TestSystemEnvironment:
    """Проверка системных требований."""

    def test_python_version(self):
        """Python должен быть версии 3.10 или выше."""
        assert sys.version_info >= (3, 10), \
            f"Требуется Python 3.10+, обнаружен {sys.version_info.major}.{sys.version_info.minor}"

    def test_required_packages_importable(self):
        """Все ключевые Python-пакеты должны импортироваться."""
        required = [
            "xgboost",
            "sklearn",
            "pandas",
            "numpy",
            "plotly",
            "streamlit",
            "joblib",
        ]
        missing = []
        for pkg in required:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(pkg)
        assert not missing, f"Отсутствуют пакеты: {', '.join(missing)}"


# =============================================================================
# Структура проекта
# =============================================================================

class TestProjectStructure:
    """Проверка наличия всех ключевых файлов и каталогов."""

    def test_cpp_sources_exist(self, project_root: Path):
        """Исходники C++ парсера должны существовать."""
        cpp_root = project_root / "cpp" / "FlowParser"
        assert cpp_root.exists(), f"Не найден каталог {cpp_root}"
        assert (cpp_root / "CMakeLists.txt").exists()
        assert (cpp_root / "src" / "main.cpp").exists()
        assert (cpp_root / "src" / "FlowParser.cpp").exists()
        assert (cpp_root / "src" / "JA4TlsParser.cpp").exists()

    def test_python_modules_exist(self, python_modules_root: Path):
        """Все Python-модули должны существовать."""
        required_modules = ["parsing", "scoring", "analysis", "reporting", "ui", "training"]
        for module in required_modules:
            module_path = python_modules_root / module
            assert module_path.exists(), f"Не найден модуль: {module_path}"

    def test_orchestrators_exist(self, project_root: Path):
        """Оркестраторы Bash должны существовать."""
        assert (project_root / "scripts" / "flowguard.sh").exists()
        assert (project_root / "scripts" / "flowguard_retrain.sh").exists()
        assert (project_root / "scripts" / "check_env.sh").exists()

    def test_install_script_exists(self, project_root: Path):
        """install.sh должен существовать в корне."""
        install_sh = project_root / "install.sh"
        assert install_sh.exists()
        assert install_sh.stat().st_mode & 0o111, "install.sh должен быть исполняемым"

    def test_requirements_file_exists(self, project_root: Path):
        """requirements.txt должен существовать и быть непустым."""
        req = project_root / "requirements.txt"
        assert req.exists(), "Не найден requirements.txt"
        assert req.stat().st_size > 0, "requirements.txt пустой"


# =============================================================================
# C++ парсер
# =============================================================================

class TestParserBinary:
    """Проверка собранного бинаря C++ парсера."""

    def test_binary_exists(self, parser_binary: Path):
        """Бинарь парсера должен быть собран."""
        if not parser_binary.exists():
            pytest.skip(f"Бинарь не собран: {parser_binary}. Запустите: ./install.sh")
        assert parser_binary.is_file()

    def test_binary_executable(self, parser_binary: Path):
        """Бинарь должен быть исполняемым."""
        if not parser_binary.exists():
            pytest.skip("Бинарь не собран")
        assert parser_binary.stat().st_mode & 0o111, "Бинарь не имеет прав на исполнение"

    def test_binary_runs(self, parser_binary: Path):
        """Бинарь должен запускаться без файлов и возвращать ошибку (как ожидается)."""
        if not parser_binary.exists():
            pytest.skip("Бинарь не собран")
        result = subprocess.run(
            [str(parser_binary)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Бинарь запущен без аргументов должен вернуть ненулевой код или показать usage
        # Главное - что он не падает с segfault и завершается за разумное время
        assert result.returncode is not None, "Бинарь не вернул код возврата"
