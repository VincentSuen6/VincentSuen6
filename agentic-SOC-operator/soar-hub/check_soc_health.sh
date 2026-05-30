#!/bin/bash

# Define Terminal Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;0m' # No Color
BOLD='\033[1m'

echo -e "${BOLD}===========================================================${NC}"
echo -e "${BOLD}        DIAGNOSING SOC LAB PERIMETER NETWORK SERVICE        ${NC}"
echo -e "${BOLD}===========================================================${NC}"

ANY_DOWN=0

# 1. Check Wazuh Manager API (Port 55000)
echo -e "\n${BLUE}── Wazuh Manager API (127.0.0.1:55000) ──${NC}"
if nc -z -w 2 127.0.0.1 55000 2>/dev/null; then
    echo -e "  ${GREEN}✅ OK${NC}      Wazuh port 55000 is open and listening."
    WAZUH_STATUS="${GREEN}● HEALTHY${NC}"
else
    echo -e "  ${RED}❌ FAIL${NC}    Wazuh Manager API unreachable on port 55000."
    WAZUH_STATUS="${RED}● DOWN${NC}"
    ANY_DOWN=1
fi

# 2. Check Elasticsearch (Port 9201)
echo -e "\n${BLUE}── Elasticsearch (localhost:9201) ──${NC}"
ELASTIC_HEALTH=$(curl -s -X GET "http://localhost:9201/_cluster/health" 2>/dev/null | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
if [ "$ELASTIC_HEALTH" == "green" ] || [ "$ELASTIC_HEALTH" == "yellow" ]; then
    echo -e "  ${GREEN}✅ OK${NC}      Elasticsearch cluster health is: ${GREEN}${ELASTIC_HEALTH^^}${NC}"
    ELASTIC_STATUS="${GREEN}● HEALTHY${NC}"
else
    # Fallback to simple port check
    if nc -z -w 2 127.0.0.1 9201 2>/dev/null; then
        echo -e "  ${GREEN}✅ OK${NC}      Elasticsearch port 9201 is open."
        ELASTIC_STATUS="${GREEN}● HEALTHY${NC}"
    else
        echo -e "  ${RED}❌ FAIL${NC}    Elasticsearch completely unreachable on port 9201."
        ELASTIC_STATUS="${RED}● DOWN${NC}"
        ANY_DOWN=1
    fi
fi

# 3. Check Splunk Management API (Port 8089)
echo -e "\n${BLUE}── Splunk Management API (localhost:8089) ──${NC}"
if nc -z -w 2 127.0.0.1 8089 2>/dev/null; then
    echo -e "  ${GREEN}✅ OK${NC}      Splunk API interface detected on port 8089."
    SPLUNK_STATUS="${GREEN}● HEALTHY${NC}"
else
    echo -e "  ${RED}❌ FAIL${NC}    Splunk port 8089 unreachable on localhost."
    echo -e "       ${YELLOW}→ Verify you launched docker with -p 8089:8089${NC}"
    SPLUNK_STATUS="${RED}● DOWN${NC}"
    ANY_DOWN=1
fi

# 4. Check SOAR FastAPI Hub (Port 8005)
echo -e "\n${BLUE}── SOAR FastAPI Hub (127.0.0.1:8005) ──${NC}"
if nc -z -w 2 127.0.0.1 8005 2>/dev/null; then
    echo -e "  ${GREEN}✅ OK${NC}      SOAR Hub API gateway detected on active port 8005."
    SOAR_STATUS="${GREEN}● HEALTHY${NC}"
else
    echo -e "  ${RED}❌ FAIL${NC}    SOAR hub not running on 127.0.0.1:8005."
    echo -e "       ${YELLOW}→ Run your startup python command manually or check logs.${NC}"
    SOAR_STATUS="${RED}● DOWN${NC}"
    ANY_DOWN=1
fi

# Print final dashboard
echo -e "\n"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}           SOC INFRASTRUCTURE HEALTH SUMMARY               ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
printf "  %-30s %-15s\n" "Service" "Status"
echo -e "  ───────────────────────── ──────────"
printf "  %-30s %-15b\n" "wazuh" "$WAZUH_STATUS"
printf "  %-30s %-15b\n" "elastic" "$ELASTIC_HEALTH_STR" # dynamic placeholder fix
printf "  %-30s %-15b\n" "elastic" "$ELASTIC_STATUS"
printf "  %-30s %-15b\n" "splunk" "$SPLUNK_STATUS"
printf "  %-30s %-15b\n" "soar_hub" "$SOAR_STATUS"
echo -e "  ───────────────────────── ──────────"

echo -e "\n"
if [ $ANY_DOWN -eq 0 ]; then
    echo -e "  ${GREEN}✅ Success! All backend SOC orchestration pipelines are operational.${NC}"
else
    echo -e "  ${RED}❌ Warning: One or more services are down. Resolve network mappings.${NC}"
fi
echo -e "\n"
