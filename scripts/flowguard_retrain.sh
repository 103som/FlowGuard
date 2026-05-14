#!/usr/bin/env bash
# =============================================================================
#  FlowGuard — переобучение модели на пользовательских данных
#
#  Назначение:
#    Позволяет пользователю обучить новую модель бинарной классификации
#    на собственном размеченном наборе PCAP/PCAPNG-файлов.
#
#  Входные требования:
#    Каталог с двумя подпапками:
#      <input-dir>/benign/
#      <input-dir>/malicious/
#
#  Использование:
#    ./scripts/flowguard_retrain.sh \
#        --input-dir <путь_к_каталогу_с_PCAP> \
#        --model-name <имя_новой_модели> \
#        [--feature-set flow_only|flow_plus_ja4|both]
#        [--seed 42]
#        [--work-dir <path>]         # reuse/resume existing workdir
#        [--keep-intermediates]
# =============================================================================

set -euo pipefail

# ============================================================
# Константы и цвета
# ============================================================

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

readonly C_RESET=$'\033[0m'
readonly C_BOLD=$'\033[1m'
readonly C_DIM=$'\033[2m'
readonly C_RED=$'\033[0;31m'
readonly C_GREEN=$'\033[0;32m'
readonly C_YELLOW=$'\033[0;33m'
readonly C_BLUE=$'\033[0;34m'
readonly C_CYAN=$'\033[0;36m'

log_info()   { printf "${C_CYAN}[INFO]${C_RESET}  %s\n" "$*"; }
log_ok()     { printf "${C_GREEN}[OK]${C_RESET}    %s\n" "$*"; }
log_warn()   { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*"; }
log_error()  { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; }
log_step()   { printf "\n${C_BOLD}${C_BLUE}>>> %s${C_RESET}\n" "$*"; }

print_divider() {
    printf "${C_DIM}%s${C_RESET}\n" "────────────────────────────────────────────────────────────────"
}

# ============================================================
# Пути внутри проекта
# ============================================================

PARSER_BIN="${ROOT}/cpp/FlowParser/build/pcap_flow_parser"

BATCH_PARSE_SCRIPT="${ROOT}/python/flowguard/parsing/batch_parse_pcaps.py"
PREPARE_SCRIPT="${ROOT}/python/flowguard/training/pipelines/prepare_user_labeled_dataset.py"
BUILD_INPUTS_SCRIPT="${ROOT}/python/flowguard/training/pipelines/build_experiment2_model_inputs.py"
TRAIN_SCRIPT="${ROOT}/python/flowguard/training/pipelines/train_xgb_experiment2.py"

MODELS_ACTIVE_DIR="${ROOT}/models/active"
WORK_ROOT="${ROOT}/data/retrain"

# ============================================================
# Аргументы
# ============================================================

INPUT_DIR=""
MODEL_NAME=""
FEATURE_SET="both"
SEED=42
KEEP_INTERMEDIATES=0
WORK_DIR_ARG=""

show_help() {
    cat <<EOF
Usage:
    ./scripts/flowguard_retrain.sh --input-dir <path> --model-name <name> [options]

Required:
    --input-dir <path>       Directory with benign/ and malicious/ subdirs
    --model-name <name>      Name of the new model (folder in models/active/)

Options:
    --feature-set <set>      flow_only | flow_plus_ja4 | both   (default: both)
    --seed <int>             Random seed                         (default: 42)
    --work-dir <path>        Reuse this work directory (resume parsing/training)
    --keep-intermediates     Do not delete intermediate files after retraining
    -h, --help               Show this help

Layout expected under --input-dir:
    <input-dir>/
    ├── benign/
    │   ├── file1.pcap
    │   └── ...
    └── malicious/
        ├── file1.pcap
        └── ...
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-dir)       INPUT_DIR="$2"; shift 2 ;;
        --model-name)      MODEL_NAME="$2"; shift 2 ;;
        --feature-set)     FEATURE_SET="$2"; shift 2 ;;
        --seed)            SEED="$2"; shift 2 ;;
        --work-dir)        WORK_DIR_ARG="$2"; shift 2 ;;
        --keep-intermediates) KEEP_INTERMEDIATES=1; shift ;;
        -h|--help)         show_help; exit 0 ;;
        *)                 log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

if [[ -z "${INPUT_DIR}" ]] || [[ -z "${MODEL_NAME}" ]]; then
    log_error "Both --input-dir and --model-name are required"
    show_help
    exit 1
fi

if ! [[ "${MODEL_NAME}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    log_error "Model name must contain only letters, digits, dashes and underscores"
    log_error "Got: '${MODEL_NAME}'"
    exit 1
fi

INPUT_DIR="$(cd "${INPUT_DIR}" 2>/dev/null && pwd)" || {
    log_error "Input directory not found: ${INPUT_DIR}"
    exit 1
}

BENIGN_DIR="${INPUT_DIR}/benign"
MALICIOUS_DIR="${INPUT_DIR}/malicious"

# ============================================================
# Проверки предусловий
# ============================================================

log_step "Проверка предусловий"

check_fail=0

if [[ ! -x "${PARSER_BIN}" ]]; then
    log_error "Парсер не найден или не исполняемый: ${PARSER_BIN}"
    log_info "Соберите парсер: cd cpp/FlowParser && mkdir -p build && cd build && cmake .. && make"
    check_fail=1
fi

for script in "${BATCH_PARSE_SCRIPT}" "${PREPARE_SCRIPT}" "${BUILD_INPUTS_SCRIPT}" "${TRAIN_SCRIPT}"; do
    if [[ ! -f "${script}" ]]; then
        log_error "Скрипт не найден: ${script}"
        check_fail=1
    fi
done

if [[ ! -d "${BENIGN_DIR}" ]]; then
    log_error "Не найдена папка: ${BENIGN_DIR}"
    log_info "Создайте её и разместите там PCAP/PCAPNG с нормальным трафиком"
    check_fail=1
fi

if [[ ! -d "${MALICIOUS_DIR}" ]]; then
    log_error "Не найдена папка: ${MALICIOUS_DIR}"
    log_info "Создайте её и разместите там PCAP/PCAPNG с аномальным трафиком"
    check_fail=1
fi

count_pcap() {
    find "$1" -type f \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | wc -l
}

if [[ -d "${BENIGN_DIR}" ]]; then
    BENIGN_PCAP_COUNT=$(count_pcap "${BENIGN_DIR}")
    if (( BENIGN_PCAP_COUNT == 0 )); then
        log_error "В ${BENIGN_DIR} нет файлов .pcap или .pcapng"
        check_fail=1
    fi
fi

if [[ -d "${MALICIOUS_DIR}" ]]; then
    MALICIOUS_PCAP_COUNT=$(count_pcap "${MALICIOUS_DIR}")
    if (( MALICIOUS_PCAP_COUNT == 0 )); then
        log_error "В ${MALICIOUS_DIR} нет файлов .pcap или .pcapng"
        check_fail=1
    fi
fi

TARGET_MODEL_DIR="${MODELS_ACTIVE_DIR}/${MODEL_NAME}"
if [[ -d "${TARGET_MODEL_DIR}" ]]; then
    log_warn "Модель с именем '${MODEL_NAME}' уже существует: ${TARGET_MODEL_DIR}"
    log_warn "При продолжении существующие файлы будут перезаписаны"
    printf "${C_CYAN}?${C_RESET} Продолжить? [y/N] "
    read -r reply || true
    if ! [[ "${reply,,}" =~ ^y(es)?$ ]]; then
        log_info "Отменено пользователем"
        exit 0
    fi
fi

if (( check_fail != 0 )); then
    log_error "Проверка предусловий не пройдена"
    exit 1
fi

log_ok "Все компоненты на месте"
log_ok "PCAP benign:    ${BENIGN_PCAP_COUNT}"
log_ok "PCAP malicious: ${MALICIOUS_PCAP_COUNT}"

# ============================================================
# Подготовка рабочих каталогов
# ============================================================

if [[ -n "${WORK_DIR_ARG}" ]]; then
    mkdir -p "${WORK_DIR_ARG}"
    WORK_DIR="$(cd "${WORK_DIR_ARG}" && pwd)"
    log_info "Используется существующий/заданный рабочий каталог: ${WORK_DIR}"
else
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    WORK_DIR="${WORK_ROOT}/${MODEL_NAME}_${TIMESTAMP}"
    mkdir -p "${WORK_DIR}"
    log_info "Создан новый рабочий каталог: ${WORK_DIR}"
fi

PARSED_DIR="${WORK_DIR}/parsed"
PROCESSED_DIR="${WORK_DIR}/processed"
TRAIN_PREPARED_DIR="${WORK_DIR}/train_prepared"
VAL_PREPARED_DIR="${WORK_DIR}/val_prepared"
TEST_PREPARED_DIR="${WORK_DIR}/test_prepared"
TRAIN_OUTDIR="${WORK_DIR}/train_output"

mkdir -p "${PARSED_DIR}/benign" "${PARSED_DIR}/malicious"
mkdir -p "${TRAIN_PREPARED_DIR}" "${VAL_PREPARED_DIR}" "${TEST_PREPARED_DIR}"
mkdir -p "${TRAIN_OUTDIR}"

# ============================================================
# Шаг 1 — Парсинг PCAP
# ============================================================

log_step "[1/4] Парсинг PCAP-файлов"

step1_start=$(date +%s)

log_info "Парсинг benign/ (с пропуском уже готовых CSV)..."
python3 "${BATCH_PARSE_SCRIPT}" \
    --parser-bin "${PARSER_BIN}" \
    --input-dir "${BENIGN_DIR}" \
    --output-dir "${PARSED_DIR}/benign" \
    --skip-existing

log_info "Парсинг malicious/ (с пропуском уже готовых CSV)..."
python3 "${BATCH_PARSE_SCRIPT}" \
    --parser-bin "${PARSER_BIN}" \
    --input-dir "${MALICIOUS_DIR}" \
    --output-dir "${PARSED_DIR}/malicious" \
    --skip-existing

log_ok "Парсинг завершён за $(($(date +%s) - step1_start)) с"

# ============================================================
# Шаг 2 — Разметка и разбиение на train/val/test
# ============================================================

log_step "[2/4] Разметка и формирование выборок"

step2_start=$(date +%s)

python3 "${PREPARE_SCRIPT}" \
    --parsed-dir "${PARSED_DIR}" \
    --outdir "${PROCESSED_DIR}" \
    --seed "${SEED}"

log_ok "Разметка завершена за $(($(date +%s) - step2_start)) с"

# ============================================================
# Шаг 3 — Построение модельных входов
# ============================================================

log_step "[3/4] Построение признаковых наборов"

step3_start=$(date +%s)

log_info "Сборка train..."
python3 "${BUILD_INPUTS_SCRIPT}" \
    --input "${PROCESSED_DIR}/train.csv" \
    --outdir "${TRAIN_PREPARED_DIR}"

log_info "Сборка val..."
python3 "${BUILD_INPUTS_SCRIPT}" \
    --input "${PROCESSED_DIR}/val.csv" \
    --outdir "${VAL_PREPARED_DIR}"

log_info "Сборка test..."
python3 "${BUILD_INPUTS_SCRIPT}" \
    --input "${PROCESSED_DIR}/test.csv" \
    --outdir "${TEST_PREPARED_DIR}"

log_ok "Признаковые наборы построены за $(($(date +%s) - step3_start)) с"

# ============================================================
# Шаг 4 — Обучение модели
# ============================================================

log_step "[4/4] Обучение модели"

step4_start=$(date +%s)

python3 "${TRAIN_SCRIPT}" \
    --train-dir "${TRAIN_PREPARED_DIR}" \
    --val-dir "${VAL_PREPARED_DIR}" \
    --test-dir "${TEST_PREPARED_DIR}" \
    --outdir "${TRAIN_OUTDIR}" \
    --feature-set "${FEATURE_SET}" \
    --seed "${SEED}"

log_ok "Обучение завершено за $(($(date +%s) - step4_start)) с"

# ============================================================
# Копирование артефактов в models/active/<MODEL_NAME>/
# ============================================================

log_step "Регистрация модели в models/active/"

mkdir -p "${TARGET_MODEL_DIR}"

register_model() {
    local src_dir="$1"
    local dst_name="$2"
    local dst_dir="${MODELS_ACTIVE_DIR}/${dst_name}"

    if [[ ! -f "${src_dir}/model.joblib" ]]; then
        log_warn "Модель не найдена в ${src_dir} — пропускаем"
        return
    fi

    mkdir -p "${dst_dir}"
    cp "${src_dir}/model.joblib"  "${dst_dir}/"
    cp "${src_dir}/metrics.json"  "${dst_dir}/"

    local schema_src="${TRAIN_PREPARED_DIR}/feature_schema.json"
    if [[ -f "${schema_src}" ]]; then
        cp "${schema_src}" "${dst_dir}/feature_schema.json"
    else
        log_warn "feature_schema.json не найден, модель может быть неприменима в пайплайне"
    fi

    log_ok "Модель зарегистрирована: ${dst_dir}"
}

if [[ "${FEATURE_SET}" == "both" ]]; then
    register_model "${TRAIN_OUTDIR}/flow_only"     "${MODEL_NAME}_flow_only"
    register_model "${TRAIN_OUTDIR}/flow_plus_ja4" "${MODEL_NAME}"
    log_info "Создано две модели: ${MODEL_NAME} (flow_plus_ja4) и ${MODEL_NAME}_flow_only"
else
    register_model "${TRAIN_OUTDIR}/${FEATURE_SET}" "${MODEL_NAME}"
fi

# ============================================================
# Итог
# ============================================================

print_divider
printf "${C_BOLD}${C_GREEN}✓ Переобучение успешно завершено${C_RESET}\n"
print_divider

if [[ -f "${TARGET_MODEL_DIR}/metrics.json" ]]; then
    log_info "Ключевые метрики обученной модели ${MODEL_NAME} (test set):"
    python3 <<PY
import json
from pathlib import Path
metrics_path = Path("${TARGET_MODEL_DIR}/metrics.json")
data = json.loads(metrics_path.read_text())
test = data.get("test_metrics", {})
print(f"  F1:         {test.get('f1', 0):.4f}")
print(f"  Precision:  {test.get('precision', 0):.4f}")
print(f"  Recall:     {test.get('recall', 0):.4f}")
print(f"  ROC AUC:    {test.get('roc_auc', 0):.4f}" if test.get('roc_auc') else "  ROC AUC:    (недоступно)")
print(f"  Threshold:  {test.get('threshold', 0):.4f}")
cm = test.get("confusion_matrix", {})
if cm:
    print(f"  Confusion:  TN={cm.get('tn')} FP={cm.get('fp')} FN={cm.get('fn')} TP={cm.get('tp')}")
PY
    echo
fi

log_info "Как использовать новую модель:"
echo "  ./scripts/flowguard.sh <dataset> ${MODEL_NAME}"
echo "  или выберите '${MODEL_NAME}' в веб-интерфейсе"

if (( KEEP_INTERMEDIATES == 0 )); then
    log_info "Промежуточные файлы сохранены в ${WORK_DIR}"
    log_info "Если хочешь потом вручную удалить их — удали каталог:"
    echo "  rm -rf \"${WORK_DIR}\""
else
    log_info "Промежуточные файлы сохранены: ${WORK_DIR}"
fi
