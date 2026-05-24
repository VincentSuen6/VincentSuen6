#!/usr/bin/env bash
# =============================================================================
# check_soc_health.sh — SOC Infrastructure Health Validator
# =============================================================================
# Verifies all daemons in the pipeline are responsive before running the SOAR
# hub. Run this first whenever you bring the Ubuntu VM back up.
#
# Usage:
#   chmod +x check_soc_health.sh
#   ./check_soc_health.sh
#
# Exit codes:
#   0 — all services healthy
#   1 — one or more services degraded (check the summary at the bottom)
# =============================================================================

set -euo pipefail

# ── Colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Service config (matches .env defaults) ────────────────────────────────────
WAZUH_IP="${WAZUH_IP:-127.0.0.1}"
WAZUH_PORT="${WAZUH_PORT:-55000}"
WAZUH_USER="${WAZUH_API_USER:-wazuh}"
WAZUH_PASS="${WAZUH_API_PASS:-}"

ELASTIC_HOST="${ELASTIC_HOST:-localhost}"
ELASTIC_PORT="${ELASTIC_PORT:-9201}"
ELASTIC_USER="${ELASTIC_USER:-elastic}"
ELASTIC_PASS="${ELASTIC_PASS:-SFU2026}"

SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
SPLUNK_PORT="${SPLUNK_PORT:-8089}"

SOAR_HOST="${SOAR_HOST:-127.0.0.1}"
SOAR_PORT="${SOAR_PORT:-8000}"

TIMEOUT=5
declare -A RESULTS
OVERALL=0

# ── Helper functions ──────────────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}✅ OK${RESET}      $*"; }
warn() { echo -e "  ${YELLOW}⚠️  WARN${RESET}   $*"; }
fail() { echo -e "  ${RED}❌ FAIL${RESET}    $*"; OVERALL=1; }
hdr()  { echo -e "\n${CYAN}${BOLD}── $* ──${RESET}"; }

check_tcp() {
    # Returns 0 if TCP port is open, 1 otherwise
    timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$1/$2" 2>/dev/null
}

# ── 1. Wazuh Manager API ──────────────────────────────────────────────────────
hdr "Wazuh Manager API (${WAZUH_IP}:${WAZUH_PORT})"

if check_tcp "$WAZUH_IP" "$WAZUH_PORT"; then
    # Attempt JWT authentication
    if [[ -n "$WAZUH_PASS" ]]; then
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" \
            -X POST "https://${WAZUH_IP}:${WAZUH_PORT}/security/user/authenticate" \
            -u "${WAZUH_USER}:${WAZUH_PASS}" 2>/dev/null || echo "000")
        if [[ "$HTTP_CODE" == "200" ]]; then
            ok "Wazuh API authenticated (HTTP 200)"
            RESULTS["wazuh"]="healthy"
        else
            warn "Wazuh port open but auth returned HTTP ${HTTP_CODE} (check WAZUH_API_PASS)"
            RESULTS["wazuh"]="degraded"
        fi
    else
        ok "Wazuh port ${WAZUH_PORT} is open (set WAZUH_API_PASS to test auth)"
        RESULTS["wazuh"]="port-open"
    fi
else
    fail "Wazuh API port ${WAZUH_PORT} unreachable on ${WAZUH_IP}"
    echo -e "       ${YELLOW}→ sudo docker ps | grep wazuh${RESET}"
    echo -e "       ${YELLOW}→ sudo docker start single-node-wazuh.manager-1${RESET}"
    RESULTS["wazuh"]="down"
    OVERALL=1
fi

# ── 2. Elasticsearch ──────────────────────────────────────────────────────────
hdr "Elasticsearch (${ELASTIC_HOST}:${ELASTIC_PORT})"

if check_tcp "$ELASTIC_HOST" "$ELASTIC_PORT"; then
    CLUSTER_RESP=$(curl -sk --max-time "$TIMEOUT" \
        -u "${ELASTIC_USER}:${ELASTIC_PASS}" \
        "http://${ELASTIC_HOST}:${ELASTIC_PORT}/_cluster/health" 2>/dev/null || echo "{}")
    CLUSTER_STATUS=$(echo "$CLUSTER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")

    case "$CLUSTER_STATUS" in
        green)  ok  "Elasticsearch cluster health: ${GREEN}GREEN${RESET}"; RESULTS["elastic"]="healthy" ;;
        yellow) warn "Elasticsearch cluster health: ${YELLOW}YELLOW${RESET} (replica shards unassigned — normal for single-node)"; RESULTS["elastic"]="yellow" ;;
        red)    fail "Elasticsearch cluster health: ${RED}RED${RESET} — data loss or missing primary shards"; RESULTS["elastic"]="red"; OVERALL=1 ;;
        *)      warn "Elasticsearch port open but cluster health unknown (check credentials)"; RESULTS["elastic"]="degraded" ;;
    esac
else
    fail "Elasticsearch port ${ELASTIC_PORT} unreachable on ${ELASTIC_HOST}"
    echo -e "       ${YELLOW}→ sudo docker ps | grep elasticsearch${RESET}"
    echo -e "       ${YELLOW}→ sudo docker start es01${RESET}"
    RESULTS["elastic"]="down"
    OVERALL=1
fi

# ── 3. Splunk ─────────────────────────────────────────────────────────────────
hdr "Splunk Management API (${SPLUNK_HOST}:${SPLUNK_PORT})"

if check_tcp "$SPLUNK_HOST" "$SPLUNK_PORT"; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" \
        "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" =~ ^(200|401|403)$ ]]; then
        ok "Splunk management port ${SPLUNK_PORT} responsive (HTTP ${HTTP_CODE})"
        RESULTS["splunk"]="healthy"
    else
        warn "Splunk port open but service returned HTTP ${HTTP_CODE}"
        RESULTS["splunk"]="degraded"
    fi
else
    fail "Splunk port ${SPLUNK_PORT} unreachable on ${SPLUNK_HOST}"
    echo -e "       ${YELLOW}→ sudo docker ps | grep splunk${RESET}"
    echo -e "       ${YELLOW}→ sudo docker start splunk${RESET}"
    RESULTS["splunk"]="down"
    OVERALL=1
fi

# Also check HEC port 8088
if check_tcp "$SPLUNK_HOST" "8088"; then
    ok "Splunk HEC port 8088 open (event ingestion ready)"
else
    warn "Splunk HEC port 8088 not reachable — splunk_hec.py will fail silently"
fi

# ── 4. SOAR FastAPI Hub ───────────────────────────────────────────────────────
hdr "SOAR FastAPI Hub (${SOAR_HOST}:${SOAR_PORT})"

if check_tcp "$SOAR_HOST" "$SOAR_PORT"; then
    HEALTH_RESP=$(curl -s --max-time "$TIMEOUT" \
        "http://${SOAR_HOST}:${SOAR_PORT}/health" 2>/dev/null || echo "{}")
    HUB_STATUS=$(echo "$HEALTH_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")

    if [[ "$HUB_STATUS" == "ok" ]]; then
        ok "SOAR hub is up and healthy"
        RESULTS["soar_hub"]="healthy"
    else
        warn "SOAR hub port open but /health returned: ${HUB_STATUS}"
        RESULTS["soar_hub"]="degraded"
    fi
else
    fail "SOAR hub not running on ${SOAR_HOST}:${SOAR_PORT}"
    echo -e "       ${YELLOW}→ cd ~/VincentSuen6/agentic-SOC-operator/soar-hub${RESET}"
    echo -e "       ${YELLOW}→ source venv/bin/activate${RESET}"
    echo -e "       ${YELLOW}→ uvicorn main:app --host 0.0.0.0 --port 8000${RESET}"
    RESULTS["soar_hub"]="down"
    OVERALL=1
fi

# ── 5. Python environment ─────────────────────────────────────────────────────
hdr "Python Environment"

PYTHON_BIN=$(which python3 2>/dev/null || echo "")
if [[ -n "$PYTHON_BIN" ]]; then
    PY_VER=$("$PYTHON_BIN" --version 2>&1)
    ok "Python: ${PY_VER}"
else
    fail "python3 not found in PATH"
    OVERALL=1
fi

for pkg in fastapi uvicorn requests anthropic langgraph dotenv; do
    if python3 -c "import ${pkg//-/_}" 2>/dev/null; then
        ok "Package ${pkg} importable"
    else
        warn "Package ${pkg} not installed — run: pip install ${pkg}"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  SOC INFRASTRUCTURE HEALTH SUMMARY${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
echo ""
printf "  %-25s %s\n" "Service" "Status"
printf "  %-25s %s\n" "─────────────────────────" "──────────"

for svc in wazuh elastic splunk soar_hub; do
    status="${RESULTS[$svc]:-unknown}"
    case "$status" in
        healthy|port-open) icon="${GREEN}● HEALTHY${RESET}" ;;
        yellow|degraded)   icon="${YELLOW}● DEGRADED${RESET}" ;;
        down|red)          icon="${RED}● DOWN${RESET}" ;;
        *)                 icon="${YELLOW}● UNKNOWN${RESET}" ;;
    esac
    printf "  %-25s " "$svc"
    echo -e "$icon"
done

echo ""
if [[ "$OVERALL" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✅ All services healthy — pipeline ready to run.${RESET}"
else
    echo -e "  ${RED}${BOLD}❌ One or more services are down. Fix the issues above before starting the pipeline.${RESET}"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
echo ""

exit "$OVERALL"
