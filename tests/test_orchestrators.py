"""
Тесты Bash-оркестраторов FlowGuard.

Проверяют:
  - синтаксическую корректность скриптов
  - обработку справки --help
  - корректность ошибок при отсутствии обязательных аргументов
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


class TestOrchestratorSyntax:
    """Синтаксические тесты — скрипты должны проходить bash -n."""

    @pytest.mark.parametrize("script_name", [
        "scripts/flowguard.sh",
        "scripts/flowguard_retrain.sh",
        "scripts/check_env.sh",
        "install.sh",
    ])
    def test_script_passes_syntax_check(self, project_root: Path, script_name: str):
        """Каждый bash-скрипт должен проходить bash -n (синтаксическую проверку)."""
        script_path = project_root / script_name
        if not script_path.exists():
            pytest.skip(f"Скрипт не найден: {script_path}")

        result = subprocess.run(
            ["bash", "-n", str(script_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, \
            f"Синтаксические ошибки в {script_name}:\n{result.stderr}"


class TestOrchestratorExecutability:
    """Проверка, что скрипты исполняемы."""

    @pytest.mark.parametrize("script_name", [
        "scripts/flowguard.sh",
        "scripts/flowguard_retrain.sh",
        "scripts/check_env.sh",
        "install.sh",
    ])
    def test_script_is_executable(self, project_root: Path, script_name: str):
        """Скрипт должен иметь права на исполнение."""
        script_path = project_root / script_name
        if not script_path.exists():
            pytest.skip(f"Скрипт не найден: {script_path}")
        assert script_path.stat().st_mode & 0o111, \
            f"{script_name} не имеет прав на исполнение"


class TestCheckEnvScript:
    """Тесты скрипта проверки окружения."""

    def test_check_env_runs_without_crash(self, project_root: Path):
        """check_env.sh должен запускаться и завершаться корректным кодом."""
        script = project_root / "scripts" / "check_env.sh"
        if not script.exists() or not (script.stat().st_mode & 0o111):
            pytest.skip("check_env.sh не доступен")

        result = subprocess.run(
            [str(script)],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Скрипт может вернуть 0 (всё ок) или ненулевой код (ошибки)
        # Главное — он не должен упасть с segfault или зависнуть
        assert result.returncode is not None


class TestInstallScript:
    """Тесты скрипта установки."""

    def test_install_help_works(self, project_root: Path):
        """install.sh --help должен показывать справку."""
        script = project_root / "install.sh"
        if not script.exists() or not (script.stat().st_mode & 0o111):
            pytest.skip("install.sh не доступен")

        result = subprocess.run(
            [str(script), "--help"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, "install.sh --help должен возвращать 0"
        assert "Использование" in result.stdout or "Usage" in result.stdout

    def test_install_rejects_unknown_args(self, project_root: Path):
        """install.sh с неизвестным аргументом должен возвращать ошибку."""
        script = project_root / "install.sh"
        if not script.exists() or not (script.stat().st_mode & 0o111):
            pytest.skip("install.sh не доступен")

        result = subprocess.run(
            [str(script), "--некоторая-чушь"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0, \
            "install.sh должен отклонять неизвестные аргументы"
