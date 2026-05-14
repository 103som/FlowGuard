# =============================================================================
# FlowGuard — Makefile
# Удобные shortcut-команды для типовых задач разработки и эксплуатации.
# =============================================================================

.PHONY: help install install-dev quickstart build clean clean-all check \
        ui run retrain test test-fast test-cov test-smoke lint format \
        docker docker-rebuild docker-up docker-down docker-logs docker-cli config-check

BLUE   := \033[0;34m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BOLD   := \033[1m
NC     := \033[0m

.DEFAULT_GOAL := help

# =============================================================================
# Справка
# =============================================================================

help:                ## Показать список доступных команд
	@echo ""
	@echo "$(BOLD)FlowGuard — команды Makefile:$(NC)"
	@echo ""
	@echo "$(BOLD)Установка:$(NC)"
	@echo "  $(BLUE)install$(NC)        Полная установка системы"
	@echo "  $(BLUE)install-dev$(NC)    Установка + dev-зависимости (тесты, линтеры)"
	@echo "  $(BLUE)quickstart$(NC)     Установка + проверка + краткая инструкция"
	@echo ""
	@echo "$(BOLD)Эксплуатация:$(NC)"
	@echo "  $(BLUE)check$(NC)          Проверить состояние системы"
	@echo "  $(BLUE)config-check$(NC)   Проверить конфиг (flowguard.yaml)"
	@echo "  $(BLUE)run$(NC)            Запустить пайплайн анализа (интерактивно)"
	@echo "  $(BLUE)ui$(NC)             Запустить веб-интерфейс"
	@echo "  $(BLUE)retrain$(NC)        Запустить переобучение модели"
	@echo ""
	@echo "$(BOLD)Тестирование:$(NC)"
	@echo "  $(BLUE)test$(NC)           Все тесты"
	@echo "  $(BLUE)test-fast$(NC)      Быстрые тесты (без slow)"
	@echo "  $(BLUE)test-cov$(NC)       Тесты с измерением покрытия"
	@echo "  $(BLUE)test-smoke$(NC)     Только smoke-тесты"
	@echo ""
	@echo "$(BOLD)Качество кода:$(NC)"
	@echo "  $(BLUE)lint$(NC)           Линтинг (ruff)"
	@echo "  $(BLUE)format$(NC)         Автоформатирование (black + isort)"
	@echo ""
	@echo "$(BOLD)Docker:$(NC)"
	@echo "  $(BLUE)docker$(NC)         Собрать образ"
	@echo "  $(BLUE)docker-rebuild$(NC) Пересобрать образ без кеша"
	@echo "  $(BLUE)docker-up$(NC)      Запустить UI в контейнере"
	@echo "  $(BLUE)docker-down$(NC)    Остановить"
	@echo "  $(BLUE)docker-logs$(NC)    Логи контейнера"
	@echo "  $(BLUE)docker-cli$(NC)     CLI-оболочка в контейнере"
	@echo ""
	@echo "$(BOLD)Очистка:$(NC)"
	@echo "  $(BLUE)clean$(NC)          Удалить артефакты сборки и промежуточные данные"
	@echo "  $(BLUE)clean-all$(NC)      Полная очистка (включая venv)"
	@echo ""

# =============================================================================
# Установка
# =============================================================================

install:             ## Полная установка системы (зависимости + сборка)
	@./install.sh

install-dev: install ## Установка + dev-зависимости (тесты, линтеры)
	@.venv/bin/pip install -r requirements-dev.txt --quiet
	@echo "$(GREEN)✓ Dev-зависимости установлены$(NC)"

quickstart:          ## Быстрый старт: установка + проверка + инструкция
	@./install.sh
	@echo ""
	@echo "$(BOLD)$(GREEN)Готово! Что дальше:$(NC)"
	@echo ""
	@echo "  1. Активируйте окружение:"
	@echo "       source .venv/bin/activate"
	@echo ""
	@echo "  2. Положите PCAP в data/raw/<имя_датасета>/"
	@echo ""
	@echo "  3. Запустите:"
	@echo "       make run    # CLI"
	@echo "       make ui     # Веб-интерфейс на http://localhost:8501"
	@echo ""

build:               ## Только пересборка C++ парсера
	@echo "$(BLUE)>>> Сборка C++ парсера$(NC)"
	@cd cpp/FlowParser && mkdir -p build && cd build && \
		cmake .. && make -j$$(nproc 2>/dev/null || echo 4)
	@echo "$(GREEN)✓ Сборка завершена$(NC)"

# =============================================================================
# Эксплуатация
# =============================================================================

check:               ## Проверить состояние установленной системы
	@./scripts/check_env.sh

config-check:        ## Показать текущую конфигурацию (flowguard.yaml)
	@python3 python/flowguard/config.py

run:                 ## Запустить основной пайплайн анализа (интерактивно)
	@./scripts/flowguard.sh

retrain:             ## Запустить сценарий переобучения модели
	@./scripts/flowguard_retrain.sh

ui:                  ## Запустить веб-интерфейс Streamlit (на :8501)
	@echo "$(BLUE)>>> Запуск веб-интерфейса FlowGuard$(NC)"
	@echo "$(BLUE)>>> URL: http://localhost:8501$(NC)"
	@streamlit run python/flowguard/ui/flowguard_ui.py

# =============================================================================
# Тестирование
# =============================================================================

test:                ## Запустить все тесты
	@pytest tests/ -v

test-fast:           ## Запустить быстрые тесты (без slow)
	@pytest tests/ -v -m "not slow"

test-cov:            ## Запустить тесты с измерением покрытия
	@pytest tests/ --cov=python/flowguard --cov-report=term-missing --cov-report=html
	@echo "$(GREEN)✓ Отчёт о покрытии: htmlcov/index.html$(NC)"

test-smoke:          ## Запустить только smoke-тесты
	@pytest tests/ -v -m smoke

# =============================================================================
# Качество кода
# =============================================================================

lint:                ## Проверить код линтером (ruff)
	@ruff check python/flowguard tests/ || true

format:              ## Отформатировать код (black + isort)
	@black python/flowguard tests/
	@isort python/flowguard tests/
	@echo "$(GREEN)✓ Код отформатирован$(NC)"

# =============================================================================
# Docker
# =============================================================================

docker:              ## Собрать Docker-образ
	@docker compose build

docker-rebuild:      ## Пересобрать Docker-образ без кеша
	@docker compose build --no-cache

docker-up:           ## Запустить FlowGuard в Docker (UI на :8501)
	@docker compose up -d flowguard
	@echo "$(GREEN)✓ FlowGuard запущен на http://localhost:8501$(NC)"
	@echo "  Логи:        make docker-logs"
	@echo "  Остановить:  make docker-down"

docker-down:         ## Остановить Docker-контейнеры
	@docker compose down --remove-orphans

docker-logs:         ## Показать логи Docker-контейнера
	@docker compose logs -f flowguard

docker-cli:          ## Открыть CLI-оболочку в контейнере
	@docker compose run --rm cli bash

# =============================================================================
# Очистка
# =============================================================================

clean:               ## Удалить артефакты сборки и промежуточные данные
	@echo "$(BLUE)>>> Очистка артефактов$(NC)"
	@rm -rf cpp/FlowParser/build
	@rm -rf data/parsed data/interim data/retrain
	@rm -rf reports/latest/*
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	@echo "$(GREEN)✓ Очистка завершена$(NC)"

clean-all: clean     ## Полная очистка (включая venv и историю запусков)
	@echo "$(BLUE)>>> Полная очистка окружения$(NC)"
	@rm -rf .venv
	@rm -f reports/runs_index.json reports/runs_index.html
	@echo "$(GREEN)✓ Окружение очищено. Для повторной установки: make install$(NC)"
