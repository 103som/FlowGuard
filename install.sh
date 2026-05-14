#!/usr/bin/env bash
# =============================================================================
# FlowGuard — скрипт установки
#
# Назначение: однокомандная установка программного комплекса с нуля
# Выполняет: проверку зависимостей → venv → Python-пакеты → C++ сборка → верификация
#
# Запуск:
#     ./install.sh                 # стандартная установка
#     ./install.sh --skip-build    # пропустить сборку C++ парсера
#     ./install.sh --skip-venv     # использовать текущее окружение
#     ./install.sh --check-only    # только проверка состояния
#     ./install.sh --help          # справка
# =============================================================================

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- цвета вывода ---
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

log_step()  { echo -e "\n${BLUE}${BOLD}>>> $*${NC}"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_fatal() { echo -e "${RED}${BOLD}[FATAL]${NC} $*" >&2; exit 1; }

# --- разбор аргументов ---
SKIP_BUILD=0
SKIP_VENV=0
CHECK_ONLY=0
VERBOSE=0

show_help() {
    cat <<EOF
FlowGuard — скрипт установки

Использование: $0 [OPTIONS]

Опции:
  --skip-build      Пропустить сборку C++ парсера
  --skip-venv       Не создавать virtualenv (использовать текущее окружение)
  --check-only      Только проверка состояния, без установки
  --verbose         Подробный вывод (для отладки)
  -h, --help        Показать эту справку

EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-venv)  SKIP_VENV=1; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        --verbose|-v) VERBOSE=1; shift ;;
        -h|--help)    show_help; exit 0 ;;
        *)            log_fatal "Неизвестный аргумент: $1. Используйте --help" ;;
    esac
done

# Если --verbose — включаем bash trace
if [ $VERBOSE -eq 1 ]; then
    set -x
fi

if [ ! -d "cpp/FlowParser" ] || [ ! -d "python/flowguard" ]; then
    log_fatal "Запускайте скрипт из корня репозитория FlowGuard"
fi

echo -e "${BOLD}"
cat <<'EOF'
============================================================
         FlowGuard — установка программного комплекса
         ML + JA4 Network Anomaly Detection System
============================================================
EOF
echo -e "${NC}"

if [ $CHECK_ONLY -eq 1 ]; then
    if [ -x "scripts/check_env.sh" ]; then
        exec ./scripts/check_env.sh
    elif [ -f "scripts/check_env.sh" ]; then
        exec bash ./scripts/check_env.sh
    else
        log_fatal "Скрипт scripts/check_env.sh не найден"
    fi
fi

# =============================================================================
# ШАГ 1. Проверка системных зависимостей
# =============================================================================
log_step "[1/7] Проверка системных зависимостей"

MISSING_DEPS=0

check_command() {
    local cmd=$1
    local install_hint=$2
    if command -v "$cmd" >/dev/null 2>&1; then
        # Получаем версию максимально безопасно:
        #   - временно отключаем pipefail, чтобы head не вызвал false-negative
        #   - сохраняем полный вывод, затем берём первую строку через bash-операции
        local version_output=""
        set +o pipefail
        version_output=$("$cmd" --version 2>&1 || true)
        set -o pipefail
        # Первая строка через параметр expansion (без head, без SIGPIPE):
        local version="${version_output%%$'\n'*}"
        log_ok "$cmd установлен: ${version:-(версия неопределена)}"
    else
        log_error "$cmd не найден. Установите: $install_hint"
        MISSING_DEPS=$((MISSING_DEPS + 1))
    fi
}

check_command "python3" "apt install python3 python3-venv python3-pip"
check_command "cmake"   "apt install cmake (минимум 3.16)"
check_command "g++"     "apt install build-essential"
check_command "make"    "apt install build-essential"
check_command "git"     "apt install git"

# --- libpcap: 4 способа обнаружить ---
detect_libpcap() {
    # 1. pkg-config (наиболее надёжно)
    if pkg-config --exists libpcap 2>/dev/null; then
        local v
        v=$(pkg-config --modversion libpcap 2>/dev/null || echo "?")
        log_ok "libpcap обнаружен через pkg-config (версия $v)"
        return 0
    fi
    # 2. dpkg на Debian/Ubuntu
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -s libpcap-dev >/dev/null 2>&1 || dpkg -s libpcap0.8 >/dev/null 2>&1; then
            log_ok "libpcap обнаружен через dpkg"
            return 0
        fi
    fi
    # 3. заголовочный файл pcap.h
    for inc_dir in /usr/include /usr/local/include /opt/homebrew/include; do
        if [ -f "$inc_dir/pcap.h" ] || [ -f "$inc_dir/pcap/pcap.h" ]; then
            log_ok "libpcap обнаружен по заголовкам в $inc_dir"
            return 0
        fi
    done
    # 4. ldconfig (для разных версий libpcap.so)
    if ldconfig -p 2>/dev/null | grep -qE "libpcap\.so"; then
        log_ok "libpcap обнаружен в ldconfig"
        return 0
    fi
    # 5. на macOS — libpcap встроена в систему
    if [ "$(uname)" = "Darwin" ]; then
        log_ok "libpcap встроена в macOS"
        return 0
    fi
    return 1
}

if detect_libpcap; then
    :
else
    log_error "libpcap не найден ни одним из методов"
    log_info "Установка: sudo apt install libpcap-dev"
    MISSING_DEPS=$((MISSING_DEPS + 1))
fi

# --- PcapPlusPlus ---
detect_pcap_plus_plus() {
    if pkg-config --exists PcapPlusPlus 2>/dev/null; then
        log_ok "PcapPlusPlus обнаружен через pkg-config"
        return 0
    fi
    for inc_dir in /usr/local/include /usr/include /opt/homebrew/include; do
        if [ -d "$inc_dir/pcapplusplus" ]; then
            log_ok "PcapPlusPlus обнаружен в $inc_dir/pcapplusplus"
            return 0
        fi
    done
    return 1
}

if detect_pcap_plus_plus; then
    :
else
    log_warn "PcapPlusPlus не обнаружен в стандартных путях"
    log_info "Если сборка C++ парсера завершится с ошибкой, установите PcapPlusPlus:"
    log_info "  git clone --depth 1 https://github.com/seladb/PcapPlusPlus.git"
    log_info "  cd PcapPlusPlus && cmake -S . -B build && cmake --build build -j"
    log_info "  sudo cmake --install build && sudo ldconfig"
fi

if [ $MISSING_DEPS -gt 0 ]; then
    log_fatal "Не хватает $MISSING_DEPS обязательных зависимостей."
fi

# --- версия Python ---
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]; }; then
    log_fatal "Требуется Python 3.10+, обнаружен $PYTHON_VERSION"
fi
log_ok "Python $PYTHON_VERSION соответствует требованиям"

# =============================================================================
# ШАГ 2. Виртуальное окружение
# =============================================================================
log_step "[2/7] Виртуальное окружение Python"

if [ $SKIP_VENV -eq 1 ]; then
    log_info "Пропускаем создание venv (--skip-venv)"
    if [ -z "${VIRTUAL_ENV:-}" ]; then
        log_warn "Виртуальное окружение не активировано. Зависимости установятся системно."
    else
        log_ok "Используется текущее окружение: $VIRTUAL_ENV"
    fi
else
    if [ -d ".venv" ]; then
        log_info "Виртуальное окружение уже существует, переиспользуем"
    else
        python3 -m venv .venv
        log_ok "Виртуальное окружение создано: .venv/"
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    log_ok "Виртуальное окружение активировано: ${VIRTUAL_ENV:-неизвестно}"
fi

# =============================================================================
# ШАГ 3. Python-зависимости
# =============================================================================
log_step "[3/7] Установка Python-зависимостей"

python3 -m pip install --upgrade pip --quiet
log_ok "pip обновлён до последней версии"

REQ_FILE=""
if [ -f "requirements.txt" ] && [ -s "requirements.txt" ]; then
    REQ_FILE="requirements.txt"
elif [ -f "docs/requirements.txt" ] && [ -s "docs/requirements.txt" ]; then
    REQ_FILE="docs/requirements.txt"
fi

if [ -z "$REQ_FILE" ]; then
    log_fatal "Не найден непустой requirements.txt"
fi

log_info "Используется файл зависимостей: $REQ_FILE"
python3 -m pip install -r "$REQ_FILE" --quiet
log_ok "Python-зависимости установлены"

if [ -f "pyproject.toml" ]; then
    log_info "Обнаружен pyproject.toml — устанавливаем проект в editable-режиме"
    python3 -m pip install -e . --quiet 2>/dev/null || log_warn "Editable-установка не удалась (некритично)"
fi

# =============================================================================
# ШАГ 4. Сборка C++ парсера
# =============================================================================
log_step "[4/7] Сборка модуля парсинга сетевого трафика (C++)"

if [ $SKIP_BUILD -eq 1 ]; then
    if [ -x "cpp/FlowParser/build/pcap_flow_parser" ]; then
        log_ok "Бинарь уже существует, пропускаем сборку (--skip-build)"
    else
        log_warn "Запрошен пропуск сборки, но бинарь не найден"
    fi
else
    (
        cd cpp/FlowParser
        mkdir -p build
        cd build

        log_info "Конфигурация CMake..."
        if ! cmake .. > /tmp/flowguard_cmake.log 2>&1; then
            log_error "Ошибка CMake. Последние 30 строк лога:"
            tail -30 /tmp/flowguard_cmake.log >&2
            exit 1
        fi
        log_ok "CMake конфигурация завершена"

        log_info "Компиляция..."
        CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
        if ! make -j"$CORES" > /tmp/flowguard_make.log 2>&1; then
            log_error "Ошибка компиляции. Последние 30 строк лога:"
            tail -30 /tmp/flowguard_make.log >&2
            exit 1
        fi
        log_ok "Компиляция успешно завершена ($CORES потоков)"
    )

    if [ -f "cpp/FlowParser/build/pcap_flow_parser" ]; then
        log_ok "Бинарь собран: cpp/FlowParser/build/pcap_flow_parser"
    else
        log_fatal "Бинарь парсера не найден после сборки"
    fi
fi

# =============================================================================
# ШАГ 5. Права на исполнение скриптов
# =============================================================================
log_step "[5/7] Настройка прав на исполнение скриптов"

EXEC_SCRIPTS=(
    "scripts/flowguard.sh"
    "scripts/flowguard_retrain.sh"
    "scripts/check_env.sh"
    "install.sh"
)

CHMOD_FAILED=0
for script in "${EXEC_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        if [ -x "$script" ]; then
            log_ok "$script (уже исполняем)"
        else
            if chmod +x "$script" 2>/dev/null; then
                log_ok "$script (права установлены)"
            else
                file_owner=$(stat -c '%U' "$script" 2>/dev/null || echo "unknown")
                log_warn "$script — не удалось установить права (владелец: $file_owner)"
                log_info "  Выполните: sudo chown \$USER:\$USER $script && chmod +x $script"
                CHMOD_FAILED=$((CHMOD_FAILED + 1))
            fi
        fi
    fi
done

# =============================================================================
# ШАГ 6. Создание структуры рабочих каталогов
# =============================================================================
log_step "[6/7] Создание структуры рабочих каталогов"

REQUIRED_DIRS=(
    "data/raw" "data/parsed" "data/interim" "data/retrain"
    "models/active" "reports/latest" "reports/archive" "logs"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        log_ok "$dir/ (существует)"
    else
        mkdir -p "$dir"
        touch "$dir/.gitkeep" 2>/dev/null || true
        log_ok "$dir/ (создан)"
    fi
done

# =============================================================================
# ШАГ 7. Финальная проверка целостности
# =============================================================================
log_step "[7/7] Проверка целостности установленной системы"

CHECK_FAILED=0

if [ -x "cpp/FlowParser/build/pcap_flow_parser" ]; then
    log_ok "Парсер: cpp/FlowParser/build/pcap_flow_parser"
else
    log_error "Парсер не найден или не исполняемый"
    CHECK_FAILED=$((CHECK_FAILED + 1))
fi

for module in parsing scoring analysis reporting ui training; do
    if [ -d "python/flowguard/$module" ]; then
        log_ok "Python-модуль: $module"
    else
        log_error "Не найден python-модуль: $module"
        CHECK_FAILED=$((CHECK_FAILED + 1))
    fi
done

for script in scripts/flowguard.sh scripts/flowguard_retrain.sh; do
    if [ -f "$script" ] && [ -x "$script" ]; then
        log_ok "Оркестратор: $script"
    elif [ -f "$script" ]; then
        log_warn "Оркестратор $script найден, но не исполняемый"
    else
        log_error "Оркестратор $script не найден"
        CHECK_FAILED=$((CHECK_FAILED + 1))
    fi
done

MODEL_COUNT=$(find models/active -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [ "$MODEL_COUNT" -gt 0 ]; then
    log_ok "Найдено обученных моделей: $MODEL_COUNT"
    find models/active -maxdepth 1 -mindepth 1 -type d -exec basename {} \; | sed 's/^/         - /'
else
    log_warn "Эталонных моделей не обнаружено в models/active/"
fi

DATASET_COUNT=$(find data/raw -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [ "$DATASET_COUNT" -gt 0 ]; then
    log_ok "Найдено датасетов в data/raw/: $DATASET_COUNT"
else
    log_warn "Датасетов не обнаружено в data/raw/"
fi

# =============================================================================
# Итог
# =============================================================================
echo
echo -e "${GREEN}${BOLD}============================================================${NC}"

if [ $CHECK_FAILED -eq 0 ] && [ $CHMOD_FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓  FlowGuard успешно установлен и готов к работе${NC}"
elif [ $CHECK_FAILED -eq 0 ]; then
    echo -e "${YELLOW}${BOLD}  ⚠  Установлен с предупреждениями ($CHMOD_FAILED chmod-проблем)${NC}"
else
    echo -e "${RED}${BOLD}  ✗  Установка завершена с ошибками ($CHECK_FAILED)${NC}"
fi

echo -e "${GREEN}${BOLD}============================================================${NC}"
echo
echo "  Дальнейшие шаги:"
echo
echo "    source .venv/bin/activate                          # активация venv"
echo "    ./scripts/flowguard.sh                             # анализ"
echo "    streamlit run python/flowguard/ui/flowguard_ui.py  # веб-UI"
echo

exit $CHECK_FAILED
