#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SOC AI Pipeline — Start Script
#  Chạy: bash /opt/soc_ai/start.sh
#  Stop: bash /opt/soc_ai/stop.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

BASE_DIR="/home/ubuntu/soc_ai"
LOG_DIR="${BASE_DIR}/logs"
PID_DIR="${BASE_DIR}/pids"
VENV="${BASE_DIR}/venv"
ENV_FILE="${BASE_DIR}/.env"

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ── Kiểm tra điều kiện ───────────────────────────────────────────
header "SOC AI Pipeline Startup"
echo -e "  Base dir : ${BASE_DIR}"
echo -e "  Python   : $(python3 --version 2>&1)"
echo -e "  Time     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# Kiểm tra .env
if [[ ! -f "${ENV_FILE}" ]]; then
    error ".env file not found at ${ENV_FILE}"
    error "Copy .env.example to .env and fill in your API keys"
    exit 1
fi

# Load env vars
set -a; source "${ENV_FILE}"; set +a

# Kiểm tra API keys
if [[ "${GROQ_API_KEY}" == "YOUR_GROQ_API_KEY_HERE" || -z "${GROQ_API_KEY}" ]]; then
    error "GROQ_API_KEY is not set in .env"
    exit 1
fi
if [[ "${ABUSEIPDB_API_KEY}" == "YOUR_ABUSEIPDB_API_KEY_HERE" || -z "${ABUSEIPDB_API_KEY}" ]]; then
    warn "ABUSEIPDB_API_KEY not set — enricher will run without API lookups"
fi

# ── Tạo thư mục cần thiết ────────────────────────────────────────
header "Creating directories"
mkdir -p "${LOG_DIR}" "${PID_DIR}" "${BASE_DIR}/data"
success "Directories ready"

# ── Virtual environment ───────────────────────────────────────────
header "Python virtual environment"
if [[ ! -d "${VENV}" ]]; then
    info "Creating venv at ${VENV}..."
    python3 -m venv "${VENV}"
    success "Venv created"
fi

# Cài packages nếu chưa có
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet httpx pydantic python-dotenv
success "Dependencies installed"
PYTHON="${VENV}/bin/python3"

# ── Kiểm tra raw log file ─────────────────────────────────────────
header "Checking raw log file"
RAW_LOG="${RAW_LOG_PATH:-${LOG_DIR}/raw_sample.json}"
if [[ ! -f "${RAW_LOG}" ]]; then
    warn "Raw log file not found: ${RAW_LOG}"
    warn "Creating empty file — paste your logs here to start processing"
    touch "${RAW_LOG}"
else
    LINE_COUNT=$(wc -l < "${RAW_LOG}")
    success "Raw log file found: ${RAW_LOG} (${LINE_COUNT} lines)"
fi

# ── Stop existing processes ───────────────────────────────────────
header "Stopping any existing processes"
for svc in normalize dedup enricher ai_alert; do
    PID_FILE="${PID_DIR}/${svc}.pid"
    if [[ -f "${PID_FILE}" ]]; then
        PID=$(cat "${PID_FILE}" 2>/dev/null || echo "")
        if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
            kill "${PID}" 2>/dev/null && info "Stopped ${svc} (pid=${PID})"
        fi
        rm -f "${PID_FILE}"
    fi
done
sleep 1
success "Old processes cleared"

# ── Hàm khởi động service ─────────────────────────────────────────
start_service() {
    local NAME="$1"
    local SCRIPT="$2"
    local LOG_FILE="${LOG_DIR}/${NAME}.log"
    local PID_FILE="${PID_DIR}/${NAME}.pid"

    info "Starting ${NAME}..."

    # Chạy với env vars đã load
    env $(cat "${ENV_FILE}" | grep -v '^#' | grep -v '^$' | xargs) \
        "${PYTHON}" "${SCRIPT}" \
        >> "${LOG_FILE}" 2>&1 &

    local PID=$!
    echo "${PID}" > "${PID_FILE}"

    # Chờ 2 giây kiểm tra xem có crash ngay không
    sleep 2
    if kill -0 "${PID}" 2>/dev/null; then
        success "${NAME} started (pid=${PID}) — log: ${LOG_FILE}"
    else
        error "${NAME} crashed on startup! Check: tail -50 ${LOG_FILE}"
        cat "${LOG_FILE}" | tail -20
        exit 1
    fi
}

# ── Khởi động từng service ────────────────────────────────────────
header "Starting pipeline services"

# 0. pre processor
start_service "preprocessor" "${BASE_DIR}/pre-processor.py"
sleep 1

start_service "normalize" "${BASE_DIR}/normalize-service.py"
# 1. Normalize
sleep 1

# 2. Dedup
start_service "dedup" "${BASE_DIR}/dedup-service.py"
sleep 1

# 3. Enricher
start_service "enricher" "${BASE_DIR}/malicious-enricher.py"
sleep 1

# 4. AI Alert
start_service "ai_alert" "${BASE_DIR}/AI_alert/run.py"

# ── Summary ───────────────────────────────────────────────────────
header "Pipeline Status"
echo ""
printf "  %-12s %-8s %-40s\n" "SERVICE" "PID" "LOG FILE"
printf "  %-12s %-8s %-40s\n" "-------" "---" "--------"
for svc in normalize dedup enricher ai_alert; do
    PID_FILE="${PID_DIR}/${svc}.pid"
    if [[ -f "${PID_FILE}" ]]; then
        PID=$(cat "${PID_FILE}")
        if kill -0 "${PID}" 2>/dev/null; then
            STATUS="${GREEN}RUNNING${NC}"
        else
            STATUS="${RED}STOPPED${NC}"
        fi
        printf "  %-12s " "${svc}"
        printf "%-8s " "${PID}"
        echo -e "${STATUS}  ${LOG_DIR}/${svc}.log"
    fi
done

echo ""
echo -e "${BOLD}Data flow:${NC}"
echo "  raw_sample.json"
echo "    → [normalize] → log_normalized.json"
echo "    → [dedup]     → log_dedup.json"
echo "    → [enricher]  → log_enriched.json"
echo "    → [ai_alert]  → data/alerts.jsonl + Telegram"
echo ""
echo -e "${BOLD}Useful commands:${NC}"
echo "  # Xem log realtime của từng service:"
echo "  tail -f ${LOG_DIR}/normalize.log"
echo "  tail -f ${LOG_DIR}/dedup.log"
echo "  tail -f ${LOG_DIR}/enricher.log"
echo "  tail -f ${LOG_DIR}/ai_alert.log"
echo ""
echo "  # Xem alerts đã tạo:"
echo "  tail -f ${BASE_DIR}/data/alerts.jsonl | python3 -m json.tool"
echo ""
echo "  # Thêm log mới vào pipeline:"
echo "  echo '{\"your\":\"log\"}' >> ${RAW_LOG}"
echo ""
echo "  # Dừng pipeline:"
echo "  bash ${BASE_DIR}/stop.sh"
echo ""
success "Pipeline started successfully!"
