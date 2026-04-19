#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DATASET_NAME="${1:-demo_showcase}"
MODEL_NAME="${2:-flow_plus_ja4}"

PARSER_BIN="${ROOT}/cpp/FlowParser/build/pcap_flow_parser"

RAW_DIR="${ROOT}/data/raw/${DATASET_NAME}"
PARSED_DIR="${ROOT}/data/parsed/${DATASET_NAME}"
INTERIM_DIR="${ROOT}/data/interim/${DATASET_NAME}"
REPORTS_DIR="${ROOT}/reports/latest/${DATASET_NAME}"
MODEL_DIR="${ROOT}/models/active/${MODEL_NAME}"

PARSE_SCRIPT="${ROOT}/python/flowguard/parsing/batch_parse_pcaps.py"
SCORE_SCRIPT="${ROOT}/python/flowguard/scoring/quick_score.py"
ANALYZE_SCRIPT="${ROOT}/python/flowguard/analysis/stat_analyzer.py"
DASHBOARD_SCRIPT="${ROOT}/python/flowguard/reporting/dashboard_html.py"

echo "[INFO] ROOT:        ${ROOT}"
echo "[INFO] DATASET:     ${DATASET_NAME}"
echo "[INFO] MODEL:       ${MODEL_NAME}"
echo "[INFO] RAW_DIR:     ${RAW_DIR}"
echo "[INFO] PARSED_DIR:  ${PARSED_DIR}"
echo "[INFO] INTERIM_DIR: ${INTERIM_DIR}"
echo "[INFO] REPORTS_DIR: ${REPORTS_DIR}"
echo "[INFO] MODEL_DIR:   ${MODEL_DIR}"
echo

if [[ ! -x "${PARSER_BIN}" ]]; then
  echo "[ERROR] Parser binary not found or not executable: ${PARSER_BIN}"
  exit 1
fi

if [[ ! -d "${RAW_DIR}" ]]; then
  echo "[ERROR] Raw input dir not found: ${RAW_DIR}"
  exit 1
fi

if [[ ! -f "${MODEL_DIR}/model.joblib" ]]; then
  echo "[ERROR] model.joblib not found: ${MODEL_DIR}/model.joblib"
  exit 1
fi

if [[ ! -f "${MODEL_DIR}/metrics.json" ]]; then
  echo "[ERROR] metrics.json not found: ${MODEL_DIR}/metrics.json"
  exit 1
fi

if [[ ! -f "${MODEL_DIR}/feature_schema.json" ]]; then
  echo "[ERROR] feature_schema.json not found: ${MODEL_DIR}/feature_schema.json"
  exit 1
fi

mkdir -p "${PARSED_DIR}" "${INTERIM_DIR}" "${REPORTS_DIR}"

echo "[1/4] Parsing PCAP files..."
python3 "${PARSE_SCRIPT}" \
  --parser-bin "${PARSER_BIN}" \
  --input-dir "${RAW_DIR}" \
  --output-dir "${PARSED_DIR}"

echo
echo "[2/4] Scoring parsed CSV files..."

shopt -s nullglob
CSV_FILES=("${PARSED_DIR}"/*.csv)

if (( ${#CSV_FILES[@]} == 0 )); then
  echo "[ERROR] No parsed CSV files found in ${PARSED_DIR}"
  exit 1
fi

for csv in "${CSV_FILES[@]}"; do
  name="$(basename "${csv}" .csv)"
  outdir="${INTERIM_DIR}/${name}"

  echo "  [SCORE] ${name}"

  python3 "${SCORE_SCRIPT}" \
    --flows-csv "${csv}" \
    --model-dir "${MODEL_DIR}" \
    --feature-set "${MODEL_NAME}" \
    --outdir "${outdir}"
done

echo
echo "[3/4] Building anomaly reports..."

REPORT_DIRS=()

for csv in "${CSV_FILES[@]}"; do
  name="$(basename "${csv}" .csv)"
  scored_csv="${INTERIM_DIR}/${name}/scored.csv"
  report_out="${REPORTS_DIR}/${name}"

  if [[ ! -f "${scored_csv}" ]]; then
    echo "[WARN] scored.csv not found for ${name}, skipping analyze step"
    continue
  fi

  echo "  [ANALYZE] ${name}"

  python3 "${ANALYZE_SCRIPT}" \
    --input "${scored_csv}" \
    --outdir "${report_out}"

  REPORT_DIRS+=("${report_out}")
done

echo
echo "[4/4] Building HTML dashboards..."

if (( ${#REPORT_DIRS[@]} == 0 )); then
  echo "[WARN] No report directories created, skipping dashboard build"
else
  for report_dir in "${REPORT_DIRS[@]}"; do
    name="$(basename "${report_dir}")"
    output_html="${report_dir}/dashboard.html"

    echo "  [DASHBOARD] ${name}"

    python3 "${DASHBOARD_SCRIPT}" \
      --report-dir "${report_dir}" \
      --output "${output_html}"
  done
fi

echo
echo "[OK] Pipeline finished"
echo "[OK] Reports root: ${REPORTS_DIR}"
