#!/usr/bin/env bash
# =============================================================================
#  FlowGuard Pipeline Runner
#
#  Запускает полный pipeline: PCAP -> parse -> score -> analyze -> dashboard
#
#  Режимы работы:
#    1. Интерактивный (без аргументов):
#         ./flowguard.sh
#    2. Автоматический:
#         ./flowguard.sh <dataset> <model> [raw-dir] [reports-dir]
#    3. Быстрые пресеты:
#         ./flowguard.sh --preset demo      # быстрая демонстрация
#         ./flowguard.sh --preset full      # полный анализ
#         ./flowguard.sh --preset benchmark # замер производительности
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

readonly C_RESET=$'\033[0m'
readonly C_BOLD=$'\033[1m'
readonly C_DIM=$'\033[2m'
readonly C_RED=$'\033[0;31m'
readonly C_GREEN=$'\033[0;32m'
readonly C_YELLOW=$'\033[0;33m'
readonly C_BLUE=$'\033[0;34m'
readonly C_CYAN=$'\033[0;36m'
readonly C_MAGENTA=$'\033[0;35m'

log_info()    { printf "${C_CYAN}[INFO]${C_RESET}  %s\n" "$*"; }
log_ok()      { printf "${C_GREEN}[OK]${C_RESET}    %s\n" "$*"; }
log_warn()    { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*"; }
log_error()   { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; }
log_step()    { printf "\n${C_BOLD}${C_BLUE}>>> %s${C_RESET}\n" "$*"; }
log_result()  { printf "${C_BOLD}${C_GREEN}✓${C_RESET} %s\n" "$*"; }

print_divider() {
    printf "${C_DIM}%s${C_RESET}\n" "────────────────────────────────────────────────────────────────"
}

print_banner() {
    printf "${C_BOLD}${C_CYAN}"
    cat <<'EOF'
 ╔══════════════════════════════════════════════════════════╗
 ║              F l o w G u a r d   P i p e l i n e          ║
 ║      ML + JA4 Network Anomaly Detection System            ║
 ╚══════════════════════════════════════════════════════════╝
EOF
    printf "${C_RESET}\n"
}

PARSER_BIN="${ROOT}/cpp/FlowParser/build/pcap_flow_parser"
PARSE_SCRIPT="${ROOT}/python/flowguard/parsing/batch_parse_pcaps.py"
SCORE_SCRIPT="${ROOT}/python/flowguard/scoring/quick_score.py"
ANALYZE_SCRIPT="${ROOT}/python/flowguard/analysis/stat_analyzer.py"
DASHBOARD_SCRIPT="${ROOT}/python/flowguard/reporting/dashboard_html.py"

RUNS_INDEX="${ROOT}/reports/runs_index.json"
RUNS_INDEX_HTML="${ROOT}/reports/runs_index.html"

DATASET_NAME="demo_showcase"
MODEL_NAME="flow_plus_ja4"
CUSTOM_RAW_DIR=""
CUSTOM_REPORTS_DIR=""
PRESET=""
OPEN_DASHBOARD="auto"

parse_args() {
    local positional=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --preset)
                PRESET="$2"
                shift 2
                ;;
            --raw-dir)
                CUSTOM_RAW_DIR="$2"
                shift 2
                ;;
            --reports-dir)
                CUSTOM_REPORTS_DIR="$2"
                shift 2
                ;;
            --no-open)
                OPEN_DASHBOARD="no"
                shift
                ;;
            --open)
                OPEN_DASHBOARD="yes"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --*)
                log_error "Unknown option: $1"
                exit 1
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    if [[ ${#positional[@]} -ge 1 ]]; then DATASET_NAME="${positional[0]}"; fi
    if [[ ${#positional[@]} -ge 2 ]]; then MODEL_NAME="${positional[1]}"; fi
    if [[ ${#positional[@]} -ge 3 ]]; then CUSTOM_RAW_DIR="${positional[2]}"; fi
    if [[ ${#positional[@]} -ge 4 ]]; then CUSTOM_REPORTS_DIR="${positional[3]}"; fi

    apply_preset
}

show_help() {
    cat <<EOF
${C_BOLD}FlowGuard Pipeline${C_RESET}

${C_BOLD}ИСПОЛЬЗОВАНИЕ:${C_RESET}
    ./flowguard.sh                          # Интерактивный режим
    ./flowguard.sh <dataset> [model]        # Автоматический режим
    ./flowguard.sh --preset <name>          # Готовый пресет

${C_BOLD}АРГУМЕНТЫ:${C_RESET}
    dataset                   Название датасета (папка в data/raw/)
    model                     Название модели (папка в models/active/)

${C_BOLD}ОПЦИИ:${C_RESET}
    --raw-dir <path>          Кастомный путь к PCAP-файлам
    --reports-dir <path>      Кастомный путь для отчётов
    --preset <name>           Использовать пресет: demo / full / benchmark
    --open                    Автоматически открыть dashboard
    --no-open                 Не открывать dashboard
    -h, --help                Показать эту справку

${C_BOLD}ПРЕСЕТЫ:${C_RESET}
    demo        Быстрая демо: demo_showcase + flow_plus_ja4
    full        Полный анализ всех датасетов из data/raw/
    benchmark   Режим замера производительности

${C_BOLD}ПРИМЕРЫ:${C_RESET}
    ./flowguard.sh
    ./flowguard.sh demo_showcase flow_plus_ja4
    ./flowguard.sh --preset demo
    ./flowguard.sh mydata flow_plus_ja4 /tmp/my_pcaps
EOF
}

apply_preset() {
    case "${PRESET}" in
        "")
            ;;
        demo)
            DATASET_NAME="demo_showcase"
            MODEL_NAME="flow_plus_ja4"
            OPEN_DASHBOARD="yes"
            log_info "Preset: demo (быстрая демонстрация)"
            ;;
        full)
            MODEL_NAME="flow_plus_ja4"
            OPEN_DASHBOARD="yes"
            log_info "Preset: full (полный анализ)"
            ;;
        benchmark)
            DATASET_NAME="benchmark"
            MODEL_NAME="flow_plus_ja4"
            OPEN_DASHBOARD="no"
            log_info "Preset: benchmark (замер производительности)"
            ;;
        *)
            log_error "Неизвестный preset: ${PRESET}"
            log_info "Доступные: demo, full, benchmark"
            exit 1
            ;;
    esac
}

is_interactive() {
    [[ -t 0 ]] && [[ -t 1 ]] && [[ -z "${PRESET}" ]] \
        && [[ "${SKIP_INTERACTIVE:-}" != "1" ]]
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    local reply
    local hint="[Y/n]"
    [[ "${default}" == "n" ]] && hint="[y/N]"

    printf "${C_CYAN}?${C_RESET} ${prompt} ${hint} "
    read -r reply || true
    reply="${reply:-${default}}"
    [[ "${reply,,}" =~ ^y(es)?$ ]]
}

ask_text() {
    local prompt="$1"
    local default="$2"
    local reply
    printf "${C_CYAN}?${C_RESET} ${prompt} ${C_DIM}[${default}]${C_RESET}: "
    read -r reply || true
    echo "${reply:-${default}}"
}

list_available_datasets() {
    local raw_root="${ROOT}/data/raw"
    if [[ ! -d "${raw_root}" ]]; then
        return
    fi

    local found_any=0
    while IFS= read -r -d '' dir; do
        local count
        count=$(find "${dir}" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | wc -l)
        if (( count > 0 )); then
            found_any=1
            printf "%s\n" "$(basename "${dir}")"
        fi
    done < <(find "${raw_root}" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

    return 0
}

list_available_models() {
    local model_root="${ROOT}/models/active"
    if [[ ! -d "${model_root}" ]]; then
        return
    fi
    find "${model_root}" -mindepth 1 -maxdepth 1 -type d -printf "%f\n" 2>/dev/null | sort
}

interactive_wizard() {
    print_banner

    echo -e "${C_BOLD}Добро пожаловать в мастер настройки FlowGuard!${C_RESET}"
    echo -e "${C_DIM}Настройте параметры анализа или нажимайте Enter для использования значений по умолчанию.${C_RESET}"
    print_divider

    local available_datasets
    mapfile -t available_datasets < <(list_available_datasets)

    if [[ ${#available_datasets[@]} -gt 0 ]]; then
        echo
        echo -e "${C_BOLD}Доступные датасеты в data/raw/:${C_RESET}"
        local default_index=1
        local i=1
        for ds in "${available_datasets[@]}"; do
            local pcap_count
            pcap_count=$(find "${ROOT}/data/raw/${ds}" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | wc -l)
            printf "  %d. %s ${C_DIM}(%d файлов)${C_RESET}\n" "${i}" "${ds}" "${pcap_count}"
            if [[ "${ds}" == "${DATASET_NAME}" ]]; then
                default_index="${i}"
            fi
            ((i++))
        done
        echo "  ${i}. [Указать свой путь]"

        printf "${C_CYAN}?${C_RESET} Выберите датасет [1-${i}] или введите имя ${C_DIM}[${default_index}]${C_RESET}: "
        read -r reply || true
        reply="${reply:-${default_index}}"
        if [[ "${reply}" =~ ^[0-9]+$ ]]; then
            if (( reply >= 1 )) && (( reply <= ${#available_datasets[@]} )); then
                DATASET_NAME="${available_datasets[$((reply-1))]}"
            elif (( reply == i )); then
                CUSTOM_RAW_DIR=$(ask_text "Путь к папке с PCAP" "${ROOT}/data/raw/mydata")
                DATASET_NAME=$(basename "${CUSTOM_RAW_DIR}")
            fi
        else
            DATASET_NAME="${reply}"
        fi
    else
        log_warn "В data/raw/ нет датасетов с PCAP-файлами"
        CUSTOM_RAW_DIR=$(ask_text "Путь к папке с PCAP" "${ROOT}/data/raw/mydata")
        DATASET_NAME=$(basename "${CUSTOM_RAW_DIR}")
    fi

    local available_models
    mapfile -t available_models < <(list_available_models)

    if [[ ${#available_models[@]} -gt 0 ]]; then
        echo
        echo -e "${C_BOLD}Доступные модели:${C_RESET}"
        local default_model_index=1
        local i=1
        for m in "${available_models[@]}"; do
            printf "  %d. %s\n" "${i}" "${m}"
            if [[ "${m}" == "${MODEL_NAME}" ]]; then
                default_model_index="${i}"
            fi
            ((i++))
        done
        printf "${C_CYAN}?${C_RESET} Выберите модель [1-${#available_models[@]}] ${C_DIM}[${default_model_index}]${C_RESET}: "
        read -r reply || true
        reply="${reply:-${default_model_index}}"
        if [[ "${reply}" =~ ^[0-9]+$ ]] && (( reply >= 1 )) && (( reply <= ${#available_models[@]} )); then
            MODEL_NAME="${available_models[$((reply-1))]}"
        fi
    else
        log_warn "В models/active/ нет обученных моделей"
        MODEL_NAME=$(ask_text "Имя модели" "${MODEL_NAME}")
    fi

    echo
    if ask_yes_no "Использовать стандартный путь для отчётов (reports/latest/${DATASET_NAME})?" "y"; then
        CUSTOM_REPORTS_DIR=""
    else
        CUSTOM_REPORTS_DIR=$(ask_text "Путь для отчётов" "${ROOT}/reports/custom/${DATASET_NAME}")
    fi

    echo
    if ask_yes_no "Открыть dashboard в браузере после завершения?" "y"; then
        OPEN_DASHBOARD="yes"
    else
        OPEN_DASHBOARD="no"
    fi

    echo
    print_divider
    echo -e "${C_BOLD}Итоговая конфигурация:${C_RESET}"
    echo -e "  Датасет:        ${C_GREEN}${DATASET_NAME}${C_RESET}"
    echo -e "  Модель:         ${C_GREEN}${MODEL_NAME}${C_RESET}"
    echo -e "  Отчёты в:       ${C_GREEN}${CUSTOM_REPORTS_DIR:-reports/latest/${DATASET_NAME}}${C_RESET}"
    echo -e "  Открыть в бр.:  ${C_GREEN}${OPEN_DASHBOARD}${C_RESET}"
    print_divider

    if ! ask_yes_no "Запустить pipeline?" "y"; then
        log_info "Отменено пользователем"
        exit 0
    fi
}

collect_pcap_metadata() {
    local raw_dir="$1"
    local meta_file="$2"

    local total_files total_size_bytes
    total_files=$(find "${raw_dir}" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" \) | wc -l)
    total_size_bytes=$(find "${raw_dir}" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" \) \
        -printf "%s\n" 2>/dev/null | awk '{s+=$1} END {print s+0}')

    local total_size_human
    if (( total_size_bytes > 1024*1024*1024 )); then
        total_size_human="$(awk "BEGIN {printf \"%.2f ГБ\", ${total_size_bytes}/1073741824}")"
    elif (( total_size_bytes > 1024*1024 )); then
        total_size_human="$(awk "BEGIN {printf \"%.1f МБ\", ${total_size_bytes}/1048576}")"
    else
        total_size_human="$(awk "BEGIN {printf \"%.1f КБ\", ${total_size_bytes}/1024}")"
    fi

    local files_json="["
    local first=true
    while IFS= read -r -d '' f; do
        [[ "${first}" == "true" ]] || files_json+=","
        first=false
        local fname fsize
        fname=$(basename "${f}")
        fsize=$(stat -c%s "${f}" 2>/dev/null || stat -f%z "${f}" 2>/dev/null || echo 0)
        files_json+="$(printf '{"name":"%s","size_bytes":%d}' "${fname}" "${fsize}")"
    done < <(find "${raw_dir}" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" \) -print0 2>/dev/null)
    files_json+="]"

    cat > "${meta_file}" <<EOF
{
  "total_files": ${total_files},
  "total_size_bytes": ${total_size_bytes},
  "total_size_human": "${total_size_human}",
  "files": ${files_json}
}
EOF

    echo
    echo -e "${C_BOLD}Метаданные входных данных:${C_RESET}"
    printf "  %-20s ${C_GREEN}%d${C_RESET}\n" "PCAP-файлов:" "${total_files}"
    printf "  %-20s ${C_GREEN}%s${C_RESET}\n" "Общий размер:" "${total_size_human}"
    echo
}

check_prerequisites() {
    local raw_dir="$1"
    local model_dir="$2"

    if [[ ! -x "${PARSER_BIN}" ]]; then
        log_error "Parser binary не найден или не исполняемый: ${PARSER_BIN}"
        log_info "Соберите его: cd cpp/FlowParser && mkdir build && cd build && cmake .. && make"
        return 1
    fi

    if [[ ! -d "${raw_dir}" ]]; then
        log_error "Папка с PCAP не существует: ${raw_dir}"
        return 1
    fi

    local pcap_count
    pcap_count=$(find "${raw_dir}" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | wc -l)
    if (( pcap_count == 0 )); then
        log_error "В ${raw_dir} нет PCAP-файлов"
        return 1
    fi

    for f in "${model_dir}/model.joblib" "${model_dir}/metrics.json" "${model_dir}/feature_schema.json"; do
        if [[ ! -f "${f}" ]]; then
            log_error "Файл модели не найден: ${f}"
            return 1
        fi
    done

    for script in "${PARSE_SCRIPT}" "${SCORE_SCRIPT}" "${ANALYZE_SCRIPT}" "${DASHBOARD_SCRIPT}"; do
        if [[ ! -f "${script}" ]]; then
            log_error "Скрипт не найден: ${script}"
            return 1
        fi
    done

    log_ok "Все компоненты на месте"
    return 0
}

STEP_CURRENT=0
STEP_TOTAL=4

progress_header() {
    STEP_CURRENT=$((STEP_CURRENT + 1))
    local title="$1"
    local icon="$2"
    printf "\n${C_BOLD}${C_BLUE}[%d/%d] %s %s${C_RESET}\n" \
        "${STEP_CURRENT}" "${STEP_TOTAL}" "${icon}" "${title}"
    print_divider
}

append_to_runs_index() {
    local dataset="$1"
    local model="$2"
    local reports_dir="$3"
    local duration_s="$4"

    local timestamp
    timestamp=$(date -Iseconds)

    mkdir -p "$(dirname "${RUNS_INDEX}")"

    python3 <<PY
import json
from pathlib import Path

reports_dir = Path("${reports_dir}")
summary_files = list(reports_dir.rglob("summary.json"))

flows_total = 0
anomalies_total = 0
incidents_total = 0
top_categories = []

for summary_path in summary_files:
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        continue
    flows_total += int(data.get("flows_total", 0))
    anomalies_total += int(data.get("anomalous_flows_total", data.get("anomalies_total", 0)))
    incidents_total += int(data.get("incidents_total", 0))
    cat = data.get("top_category")
    if cat and cat != "—":
        top_categories.append(cat)

top_category = "—"
if top_categories:
    from collections import Counter
    top_category = Counter(top_categories).most_common(1)[0][0]

index_path = Path("${RUNS_INDEX}")
if index_path.exists():
    try:
        runs = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        runs = []
else:
    runs = []

runs.insert(0, {
    "timestamp": "${timestamp}",
    "dataset": "${dataset}",
    "model": "${model}",
    "reports_dir": str(reports_dir),
    "duration_seconds": int(${duration_s}),
    "flows_total": flows_total,
    "anomalies_total": anomalies_total,
    "incidents_total": incidents_total,
    "top_category": top_category,
})

runs = runs[:50]
index_path.write_text(json.dumps(runs, ensure_ascii=False, indent=2), encoding="utf-8")
PY

    log_ok "История запусков обновлена: ${RUNS_INDEX}"
}

generate_runs_index_html() {
    python3 "${ROOT}/python/flowguard/reporting/runs_index_html.py" \
        --runs-json "${RUNS_INDEX}" \
        --output "${RUNS_INDEX_HTML}" 2>/dev/null || {
        log_warn "Скрипт runs_index_html.py не найден — индекс не сгенерирован"
        return 0
    }
    log_ok "Индекс запусков: ${RUNS_INDEX_HTML}"
}

open_in_browser() {
    local path="$1"
    if [[ "${OPEN_DASHBOARD}" == "no" ]]; then return; fi

    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${path}" 2>/dev/null &
    elif command -v open >/dev/null 2>&1; then
        open "${path}" 2>/dev/null &
    elif command -v start >/dev/null 2>&1; then
        start "${path}" 2>/dev/null &
    else
        return
    fi
    log_ok "Открыт в браузере: ${path}"
}

run_pipeline() {
    local start_time
    start_time=$(date +%s)

    local raw_dir="${CUSTOM_RAW_DIR:-${ROOT}/data/raw/${DATASET_NAME}}"
    local parsed_dir="${ROOT}/data/parsed/${DATASET_NAME}"
    local interim_dir="${ROOT}/data/interim/${DATASET_NAME}"
    local reports_dir="${CUSTOM_REPORTS_DIR:-${ROOT}/reports/latest/${DATASET_NAME}}"
    local model_dir="${ROOT}/models/active/${MODEL_NAME}"

    print_divider
    log_info "ROOT:        ${ROOT}"
    log_info "DATASET:     ${DATASET_NAME}"
    log_info "MODEL:       ${MODEL_NAME}"
    log_info "RAW_DIR:     ${raw_dir}"
    log_info "PARSED_DIR:  ${parsed_dir}"
    log_info "INTERIM_DIR: ${interim_dir}"
    log_info "REPORTS_DIR: ${reports_dir}"
    log_info "MODEL_DIR:   ${model_dir}"
    print_divider

    if ! check_prerequisites "${raw_dir}" "${model_dir}"; then
        exit 1
    fi

    mkdir -p "${parsed_dir}" "${interim_dir}" "${reports_dir}"

    collect_pcap_metadata "${raw_dir}" "${reports_dir}/pcap_metadata.json"

    progress_header "Парсинг PCAP-файлов" "📦"
    local step_start
    step_start=$(date +%s)
    python3 "${PARSE_SCRIPT}" \
        --parser-bin "${PARSER_BIN}" \
        --input-dir "${raw_dir}" \
        --output-dir "${parsed_dir}"
    log_result "Парсинг завершён за $(($(date +%s) - step_start)) с"

    local total_flows=0
    if command -v wc >/dev/null 2>&1; then
        total_flows=$(find "${parsed_dir}" -maxdepth 1 -name "*.csv" -exec wc -l {} + 2>/dev/null | tail -n1 | awk '{print $1 - 1}')
        [[ -z "${total_flows}" ]] && total_flows=0
        log_ok "Распарсено flow: ${total_flows}"
    fi

    progress_header "Скоринг flow через ML-модель" "🤖"
    step_start=$(date +%s)

    shopt -s nullglob
    local csv_files=("${parsed_dir}"/*.csv)
    if (( ${#csv_files[@]} == 0 )); then
        log_error "Нет распарсенных CSV в ${parsed_dir}"
        exit 1
    fi

    for csv in "${csv_files[@]}"; do
        local name
        name="$(basename "${csv}" .csv)"
        local outdir="${interim_dir}/${name}"
        printf "  ${C_DIM}[SCORE]${C_RESET} %s\n" "${name}"
        python3 "${SCORE_SCRIPT}" \
            --flows-csv "${csv}" \
            --model-dir "${model_dir}" \
            --feature-set "${MODEL_NAME}" \
            --outdir "${outdir}"
    done
    log_result "Скоринг завершён за $(($(date +%s) - step_start)) с"

    progress_header "Формирование отчётов аномалий" "🔍"
    step_start=$(date +%s)

    local report_dirs=()
    local first_summary=""
    for csv in "${csv_files[@]}"; do
        local name
        name="$(basename "${csv}" .csv)"
        local scored_csv="${interim_dir}/${name}/scored.csv"
        local report_out="${reports_dir}/${name}"

        if [[ ! -f "${scored_csv}" ]]; then
            log_warn "scored.csv не найден для ${name} — пропускаем"
            continue
        fi
        printf "  ${C_DIM}[ANALYZE]${C_RESET} %s\n" "${name}"
        python3 "${ANALYZE_SCRIPT}" \
            --input "${scored_csv}" \
            --outdir "${report_out}"
        report_dirs+=("${report_out}")

        if [[ -z "${first_summary}" ]] && [[ -f "${report_out}/summary.json" ]]; then
            first_summary="${report_out}/summary.json"
        fi
    done
    log_result "Анализ завершён за $(($(date +%s) - step_start)) с"

    progress_header "Построение HTML-дашбордов" "📊"
    step_start=$(date +%s)

    local dashboard_paths=()
    if (( ${#report_dirs[@]} == 0 )); then
        log_warn "Нет папок отчётов — пропускаем dashboard"
    else
        for report_dir in "${report_dirs[@]}"; do
            local name
            name="$(basename "${report_dir}")"
            local output_html="${report_dir}/dashboard.html"
            printf "  ${C_DIM}[DASHBOARD]${C_RESET} %s\n" "${name}"
            python3 "${DASHBOARD_SCRIPT}" \
                --report-dir "${report_dir}" \
                --output "${output_html}"
            dashboard_paths+=("${output_html}")
        done
    fi
    log_result "Dashboard'ы собраны за $(($(date +%s) - step_start)) с"

    local total_duration=$(($(date +%s) - start_time))

    echo
    print_divider
    echo -e "${C_BOLD}${C_GREEN}✓ Pipeline завершён успешно${C_RESET}"
    print_divider

    if [[ -n "${first_summary}" ]] && [[ -f "${first_summary}" ]]; then
        echo -e "${C_BOLD}Результаты анализа:${C_RESET}"
        python3 <<PY
import json
from pathlib import Path
summary = json.loads(Path("${first_summary}").read_text())
print(f"  Всего flow:            {summary.get('flows_total', 0):>10,}".replace(",", " "))
print(f"  Аномальных:            {summary.get('anomalous_flows_total', 0):>10,}".replace(",", " "))
print(f"  Инцидентов:            {summary.get('incidents_total', 0):>10,}".replace(",", " "))
print(f"  Доля аномалий:         {summary.get('anomaly_share', 0) * 100:>9.2f}%")
print(f"  Уникальных клиентов:   {summary.get('distinct_clients', 0):>10,}".replace(",", " "))
print(f"  Уникальных серверов:   {summary.get('distinct_servers', 0):>10,}".replace(",", " "))
print(f"  Главная категория:     {summary.get('top_category', '—')}")
PY
        echo
    fi

    echo -e "${C_BOLD}Сгенерированные файлы:${C_RESET}"
    echo -e "  Папка отчётов:   ${C_GREEN}${reports_dir}${C_RESET}"
    if (( ${#dashboard_paths[@]} > 0 )); then
        for p in "${dashboard_paths[@]}"; do
            echo -e "  Dashboard:       ${C_GREEN}${p}${C_RESET}"
        done
    fi
    echo
    echo -e "${C_BOLD}Время выполнения:${C_RESET} ${C_CYAN}$(format_duration ${total_duration})${C_RESET}"
    print_divider

    append_to_runs_index "${DATASET_NAME}" "${MODEL_NAME}" "${reports_dir}" "${total_duration}"
    generate_runs_index_html

    if [[ "${OPEN_DASHBOARD}" != "no" ]] && (( ${#dashboard_paths[@]} > 0 )); then
        if [[ "${OPEN_DASHBOARD}" == "auto" ]]; then
            if is_interactive && ask_yes_no "Открыть dashboard в браузере?" "y"; then
                open_in_browser "${dashboard_paths[0]}"
            fi
        elif [[ "${OPEN_DASHBOARD}" == "yes" ]]; then
            open_in_browser "${dashboard_paths[0]}"
        fi
    fi
}

format_duration() {
    local s=$1
    local h=$((s / 3600))
    local m=$(( (s % 3600) / 60 ))
    local sec=$((s % 60))
    if (( h > 0 )); then
        printf "%dч %dм %dс" "$h" "$m" "$sec"
    elif (( m > 0 )); then
        printf "%dм %dс" "$m" "$sec"
    else
        printf "%dс" "$sec"
    fi
}

main() {
    parse_args "$@"

    if [[ $# -eq 0 ]] && is_interactive; then
        interactive_wizard
    fi

    run_pipeline
}

main "$@"
