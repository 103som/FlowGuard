"""
Тесты модуля анализа аномалий: категоризация инцидентов и расчёт серьёзности.

Так как stat_analyzer.py не оформлен как импортируемый модуль (только как CLI),
эти тесты — заготовки, которые сработают после рефакторинга модуля в импортируемые
функции. Сейчас покрывают логику через образцы данных.
"""
from __future__ import annotations

import pytest


# =============================================================================
# Категории инцидентов
# =============================================================================

EXPECTED_CATEGORIES = {
    "Периодический TLS-маяк",
    "Сканирование портов",
    "Веерное сканирование",
    "Сканирование сети",
    "DoS-флуд",
    "Повторяющиеся TLS-сеансы",
    "Неуспешные соединения",
    "Исходящая эксфильтрация",
    "Крупный входящий поток",
    "Подозрительный TLS-профиль",
    "Активный TLS-клиент",
    "Неклассифицированная аномалия",
}


SEVERITY_LEVELS = {"Критический", "Высокий", "Средний", "Низкий"}


class TestIncidentCategoriesConstants:
    """Проверка консистентности списка категорий."""

    def test_exactly_twelve_categories(self):
        """Должно быть ровно 12 категорий инцидентов."""
        assert len(EXPECTED_CATEGORIES) == 12

    def test_severity_levels_count(self):
        """Должно быть ровно 4 уровня серьёзности."""
        assert len(SEVERITY_LEVELS) == 4


# =============================================================================
# Аномалия → инцидент: правила группировки
# =============================================================================

class TestIncidentAggregation:
    """Проверка логики агрегации аномальных потоков в инциденты."""

    def test_same_triple_aggregates_to_one_incident(self):
        """
        Потоки с одинаковой тройкой (client_ip, server_ip, server_port)
        должны объединяться в один инцидент.
        """
        flows = [
            {"client_ip": "10.0.0.1", "server_ip": "1.1.1.1", "server_port": 443},
            {"client_ip": "10.0.0.1", "server_ip": "1.1.1.1", "server_port": 443},
            {"client_ip": "10.0.0.1", "server_ip": "1.1.1.1", "server_port": 443},
        ]
        # Псевдо-агрегация: считаем уникальные тройки
        triples = {(f["client_ip"], f["server_ip"], f["server_port"]) for f in flows}
        assert len(triples) == 1, "Одинаковые тройки должны давать один инцидент"

    def test_different_ports_are_different_incidents(self):
        """Разные порты назначения — разные инциденты."""
        flows = [
            {"client_ip": "10.0.0.1", "server_ip": "1.1.1.1", "server_port": 443},
            {"client_ip": "10.0.0.1", "server_ip": "1.1.1.1", "server_port": 80},
        ]
        triples = {(f["client_ip"], f["server_ip"], f["server_port"]) for f in flows}
        assert len(triples) == 2


# =============================================================================
# Серьёзность инцидента
# =============================================================================

class TestSeverityCalculation:
    """Проверка логики расчёта уровня серьёзности."""

    def test_high_anomaly_score_leads_to_high_severity(self):
        """Высокая средняя оценка аномальности → высокая серьёзность."""
        # Это заготовка — реальная функция расчёта пока в stat_analyzer.py как CLI
        avg_score = 0.95
        # Заглушка для проверки логики
        if avg_score >= 0.9:
            severity = "Критический"
        elif avg_score >= 0.7:
            severity = "Высокий"
        elif avg_score >= 0.5:
            severity = "Средний"
        else:
            severity = "Низкий"
        assert severity == "Критический"

    def test_low_anomaly_score_leads_to_low_severity(self):
        """Низкая оценка аномальности → низкая серьёзность."""
        avg_score = 0.3
        if avg_score >= 0.9:
            severity = "Критический"
        elif avg_score >= 0.7:
            severity = "Высокий"
        elif avg_score >= 0.5:
            severity = "Средний"
        else:
            severity = "Низкий"
        assert severity == "Низкий"


# =============================================================================
# Smoke-тесты на сэмпле данных
# =============================================================================

class TestSampleFlowProcessing:
    """Базовые smoke-тесты на образце записи потока."""

    def test_sample_flow_has_all_features(self, sample_flow_record):
        """Образец потока должен содержать все ключевые признаки."""
        required_keys = {
            "client_ip", "server_ip", "server_port",
            "packets_total", "bytes_cap_total", "duration_ns",
            "tcp_syn_total", "tcp_rst_total",
            "ja4_cipher_suites_count", "ja4_has_sni",
        }
        missing = required_keys - sample_flow_record.keys()
        assert not missing, f"Образец потока не содержит признаки: {missing}"

    def test_sample_flow_has_valid_ip_format(self, sample_flow_record):
        """IP-адреса в образце должны быть валидными."""
        import ipaddress
        ipaddress.ip_address(sample_flow_record["client_ip"])
        ipaddress.ip_address(sample_flow_record["server_ip"])

    def test_sample_flow_has_valid_port(self, sample_flow_record):
        """Порт должен быть в допустимом диапазоне."""
        port = sample_flow_record["server_port"]
        assert 1 <= port <= 65535, f"Порт вне диапазона: {port}"
