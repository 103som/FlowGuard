#!/usr/bin/env bash
# =============================================================================
# FlowGuard — проверка состояния установленной системы
# Запускается отдельно или через `make check`
# =============================================================================

# --- цвета вывода ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }

# --- проверка корневого каталога ---
if [ ! -d "cpp/FlowParser" ] || [ ! -d "python/flowguard" ]; then
    log_error "Скрипт должен запускаться из корня репозитория FlowGuard"
    exit 1
fi

echo -e "${BOLD}"
echo "============================================================"
echo "         FlowGuard — проверка состояния системы              "
echo "============================================================"
echo -e "${NC}"

ERRORS=0
WARNINGS=0

# =============================================================================
# Системные зависимости
# =============================================================================
echo -e "${BOLD}Системные зависимости:${NC}"

for cmd in python3 cmake g++ make git; do
    if command -v "$cmd" >/dev/null 2>&1; then
        log_ok "$cmd установлен"
    else
        log_error "$cmd не найден"
        ERRORS=$((ERRORS + 1))
    fi
done

if ldconfig -p 2>/dev/null | grep -q libpcap; then
    log_ok "libpcap установлен"
else
    log_warn "libpcap не обнаружен (проверьте установку libpcap-dev)"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -d "/usr/local/include/pcapplusplus" ] || \
   [ -d "/usr/include/pcapplusplus" ] || \
   pkg-config --exists PcapPlusPlus 2>/dev/null; then
    log_ok "PcapPlusPlus установлен"
else
    log_warn "PcapPlusPlus не обнаружен в стандартных путях"
    WARNINGS=$((WARNINGS + 1))
fi

# =============================================================================
# Виртуальное окружение
# =============================================================================
echo
echo -e "${BOLD}Python окружение:${NC}"

if [ -d ".venv" ]; then
    log_ok "Виртуальное окружение присутствует: .venv/"

    if [ -n "$VIRTUAL_ENV" ]; then
        log_ok "Виртуальное окружение активно: $VIRTUAL_ENV"
    else
        log_warn "Виртуальное окружение не активировано (запустите: source .venv/bin/activate)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    log_error "Виртуальное окружение .venv/ не найдено (запустите ./install.sh)"
    ERRORS=$((ERRORS + 1))
fi

# Проверка ключевых Python-пакетов
# Маппинг "имя пакета на PyPI → имя для import" — нужен, потому что у некоторых
# пакетов имена различаются (например, scikit-learn ставится как sklearn).
if [ -d ".venv" ]; then
    PYTHON_BIN=".venv/bin/python3"

    # Формат: "pypi_name:import_name"
    PACKAGES=(
        "xgboost:xgboost"
        "pandas:pandas"
        "numpy:numpy"
        "plotly:plotly"
        "streamlit:streamlit"
        "scikit-learn:sklearn"
        "joblib:joblib"
        "pyyaml:yaml"
    )

    for entry in "${PACKAGES[@]}"; do
        pypi_name="${entry%%:*}"
        import_name="${entry##*:}"

        if $PYTHON_BIN -c "import $import_name" 2>/dev/null; then
            VERSION=$($PYTHON_BIN -c "import $import_name; print($import_name.__version__)" 2>/dev/null || echo "?")
            log_ok "Python-пакет $pypi_name ($VERSION)"
        else
            log_error "Python-пакет $pypi_name не установлен (импортируется как $import_name)"
            ERRORS=$((ERRORS + 1))
        fi
    done
fi

# =============================================================================
# Бинарный парсер
# =============================================================================
echo
echo -e "${BOLD}C++ компонент:${NC}"

if [ -x "cpp/FlowParser/build/pcap_flow_parser" ]; then
    log_ok "Бинарный парсер собран: cpp/FlowParser/build/pcap_flow_parser"
else
    log_error "Бинарный парсер не найден (запустите: make build)"
    ERRORS=$((ERRORS + 1))
fi

# =============================================================================
# Оркестраторы
# =============================================================================
echo
echo -e "${BOLD}Оркестраторы:${NC}"

for script in scripts/flowguard.sh scripts/flowguard_retrain.sh; do
    if [ -x "$script" ]; then
        log_ok "$script доступен и исполняем"
    elif [ -f "$script" ]; then
        log_warn "$script существует, но не исполняем (запустите: chmod +x $script)"
        WARNINGS=$((WARNINGS + 1))
    else
        log_error "$script не найден"
        ERRORS=$((ERRORS + 1))
    fi
done

# =============================================================================
# Python-модули
# =============================================================================
echo
echo -e "${BOLD}Python-модули FlowGuard:${NC}"

for module in parsing scoring analysis reporting ui training; do
    if [ -d "python/flowguard/$module" ]; then
        log_ok "python/flowguard/$module"
    else
        log_error "Не найден модуль: python/flowguard/$module"
        ERRORS=$((ERRORS + 1))
    fi
done

# =============================================================================
# Каталоги данных
# =============================================================================
echo
echo -e "${BOLD}Каталоги данных:${NC}"

mkdir -p data/raw data/parsed data/interim data/retrain
mkdir -p models/active reports/latest

for dir in data/raw data/parsed data/interim models/active reports; do
    if [ -d "$dir" ]; then
        log_ok "$dir/"
    else
        log_error "Каталог $dir не существует"
        ERRORS=$((ERRORS + 1))
    fi
done

# =============================================================================
# Доступные модели
# =============================================================================
echo
echo -e "${BOLD}Обученные модели:${NC}"

MODEL_COUNT=$(find models/active -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [ "$MODEL_COUNT" -gt 0 ]; then
    log_ok "Доступно моделей: $MODEL_COUNT"
    while IFS= read -r model_dir; do
        model_name=$(basename "$model_dir")
        if [ -f "$model_dir/model.joblib" ] && \
           [ -f "$model_dir/feature_schema.json" ] && \
           [ -f "$model_dir/metrics.json" ]; then
            log_ok "  └── $model_name (полный комплект артефактов)"
        else
            log_warn "  └── $model_name (неполный комплект артефактов)"
            WARNINGS=$((WARNINGS + 1))
        fi
    done < <(find models/active -maxdepth 1 -mindepth 1 -type d)
else
    log_warn "Нет обученных моделей в models/active/"
    log_info "Запустите ./scripts/flowguard_retrain.sh для обучения модели"
    WARNINGS=$((WARNINGS + 1))
fi

# =============================================================================
# Доступные датасеты
# =============================================================================
echo
echo -e "${BOLD}Датасеты:${NC}"

DATASET_COUNT=$(find data/raw -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [ "$DATASET_COUNT" -gt 0 ]; then
    log_ok "Доступно датасетов: $DATASET_COUNT"
    while IFS= read -r dataset_dir; do
        dataset_name=$(basename "$dataset_dir")
        pcap_count=$(find "$dataset_dir" -type f \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | wc -l)
        log_ok "  └── $dataset_name ($pcap_count PCAP-файлов)"
    done < <(find data/raw -maxdepth 1 -mindepth 1 -type d)
else
    log_warn "Нет датасетов в data/raw/"
    log_info "Поместите PCAP-файлы в data/raw/<имя_датасета>/"
    WARNINGS=$((WARNINGS + 1))
fi

# =============================================================================
# История запусков
# =============================================================================
echo
echo -e "${BOLD}История запусков:${NC}"

if [ -f "reports/runs_index.json" ]; then
    RUN_COUNT=$(grep -c '"run_id"' reports/runs_index.json 2>/dev/null || echo 0)
    log_ok "Зарегистрировано запусков: $RUN_COUNT"
else
    log_info "История запусков пуста (reports/runs_index.json не создан)"
fi

# =============================================================================
# Итог
# =============================================================================
echo
echo -e "${BOLD}============================================================${NC}"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓  Все компоненты в порядке, FlowGuard готов к работе${NC}"
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}${BOLD}  ⚠  Система работоспособна, но есть $WARNINGS предупреждений${NC}"
else
    echo -e "${RED}${BOLD}  ✗  Обнаружено ошибок: $ERRORS, предупреждений: $WARNINGS${NC}"
    echo -e "${RED}     Запустите ./install.sh для устранения проблем${NC}"
fi

echo -e "${BOLD}============================================================${NC}"
echo

exit $ERRORS
