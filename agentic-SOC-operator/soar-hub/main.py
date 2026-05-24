import os
import sys
from pathlib import Path
from fastapi import FastAPI, Request
import uvicorn
from dotenv import load_dotenv

load_dotenv()

# Make the parent vuln-intel-agent package importable from soar-hub/
sys.path.insert(0, str(Path(__file__).parent.parent / "SOAR-sentinel" / "vuln-intel-agent"))

from response.soar_graph import compiled_soc_graph, run_soar_graph

app = FastAPI(title="Multi-Vendor Agentic SOAR Hub Framework")


@app.post("/alerts")
async def receive_alerts(request: Request):
    alert_payload = await request.json()
    print("\n" + "═"*60)
    print("🚨 [SOAR HUB] INBOUND DATA DETECTED FROM ELASTIC/WAZUH PIPELINE")
    print("═"*60)

    # run_soar_graph builds the correct SOCAgentState blank slate internally,
    # so the alert dict is passed as-is without manual field mapping.
    final_state = run_soar_graph(alert_payload)

    print("═"*60 + "\n")
    return {
        "status":      "success",
        "message":     "Alert processed through LangGraph.",
        "containment": final_state.get("containment_status"),
    }


@app.post("/alerts/splunk")
async def receive_splunk_webhook(request: Request):
    splunk_payload = await request.json()
    print("\n" + "═"*60)
    print("🚨 [SOAR HUB] INBOUND DATA DETECTED FROM SPLUNK WEBHOOK ENGINE")
    print("═"*60)

    result_block = splunk_payload.get("result", {})

    # Translate Splunk parameters into standard alert dict
    normalized_alert = {
        "kibana.alert.rule.name": splunk_payload.get("search_name", "Splunk Triggered Rule"),
        "message":                result_block.get("_raw", "Raw Splunk Event Telemetry Logs"),
        "source":                 {"ip": result_block.get("src_ip", "")},
        "@timestamp":             splunk_payload.get("_time", ""),
    }

    final_state = run_soar_graph(normalized_alert)

    print("═"*60 + "\n")
    return {
        "status":      "success",
        "message":     "Splunk payload normalized and routed.",
        "containment": final_state.get("containment_status"),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "graph": "6-node SOAR pipeline active"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
