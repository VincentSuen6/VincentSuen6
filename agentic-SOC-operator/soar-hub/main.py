import os
from fastapi import FastAPI, Request
import uvicorn
from dotenv import load_dotenv
from response.soar_graph import compiled_soc_graph

load_dotenv()

app = FastAPI(title="Multi-Vendor Agentic SOAR Hub Framework")

@app.post("/alerts")
async def receive_alerts(request: Request):
    alert_payload = await request.json()
    print("\n" + "═"*60)
    print("🚨 [SOAR HUB] INBOUND DATA DETECTED FROM ELASTIC/WAZUH PIPELINE")
    print("═"*60)
    
    # Pack into initial graph dictionary structure
    initial_input = {
        "raw_alert": alert_payload, "source_ip": "", "alert_type": "",
        "threat_intel_score": 0, "mitre_technique_id": "", "mitre_tactic": "",
        "containment_status": "", "summary_markdown": "", "notification_sent": False, "audit_trail": []
    }
    
    # Invoke LangGraph State Engine
    final_state = compiled_soc_graph.invoke(initial_input)
    print("═"*60 + "\n")
    return {"status": "success", "message": "Alert processed through LangGraph.", "containment": final_state.get("containment_status")}

@app.post("/alerts/splunk")
async def receive_splunk_webhook(request: Request):
    splunk_payload = await request.json()
    print("\n" + "═"*60)
    print("🚨 [SOAR HUB] INBOUND DATA DETECTED FROM SPLUNK WEBHOOK ENGINE")
    print("═"*60)
    
    result_block = splunk_payload.get("result", {})
    
    # Translate Splunk parameters into standard tracking parameters
    normalized_alert = {
        "kibana.alert.rule.name": splunk_payload.get("search_name", "Splunk Triggered Rule"),
        "message": result_block.get("_raw", "Raw Splunk Event Telemetry Logs"),
        "source": {"ip": result_block.get("src_ip", "185.220.101.5")}
    }
    
    initial_input = {
        "raw_alert": normalized_alert, "source_ip": "", "alert_type": "",
        "threat_intel_score": 0, "mitre_technique_id": "", "mitre_tactic": "",
        "containment_status": "", "summary_markdown": "", "notification_sent": False, "audit_trail": []
    }
    
    final_state = compiled_soc_graph.invoke(initial_input)
    print("═"*60 + "\n")
    return {"status": "success", "message": "Splunk payload normalized and routed.", "containment": final_state.get("containment_status")}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
