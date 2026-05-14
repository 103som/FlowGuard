"""
Общая конфигурация pytest для FlowGuard.

Регистрирует корень проекта в sys.path, чтобы можно было импортировать
модули FlowGuard как пакеты.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# --- регистрация корня проекта в sys.path ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_ROOT = PROJECT_ROOT / "python"

if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


# =============================================================================
# Общие фикстуры
# =============================================================================

@pytest.fixture(scope="session")
def project_root() -> Path:
    """Возвращает корневой каталог проекта."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def parser_binary(project_root: Path) -> Path:
    """Возвращает путь к собранному бинарю C++ парсера."""
    return project_root / "cpp" / "FlowParser" / "build" / "pcap_flow_parser"


@pytest.fixture(scope="session")
def python_modules_root(project_root: Path) -> Path:
    """Возвращает корень Python-модулей."""
    return project_root / "python" / "flowguard"


@pytest.fixture
def tmp_models_dir(tmp_path: Path) -> Path:
    """Создаёт временный каталог для тестовых моделей."""
    models_dir = tmp_path / "models" / "active"
    models_dir.mkdir(parents=True, exist_ok=True)
    return models_dir


@pytest.fixture
def sample_flow_record() -> dict:
    """Образец записи о сетевом потоке для тестов."""
    return {
        "client_ip": "192.168.1.10",
        "server_ip": "8.8.8.8",
        "server_port": 443,
        "proto": "TCP",
        "packets_total": 42,
        "bytes_cap_total": 5120,
        "duration_ns": 1_500_000_000,
        "tcp_syn_total": 1,
        "tcp_ack_total": 40,
        "tcp_fin_total": 1,
        "tcp_rst_total": 0,
        "tcp_psh_total": 5,
        "ja4_tls_version": "0x0303",
        "ja4_cipher_suites_count": 17,
        "ja4_extensions_count": 14,
        "ja4_has_sni": 1,
        "ja4_alpn": "h2",
    }
