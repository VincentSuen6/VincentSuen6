import json
import os

# Define relative paths based on your repository architecture
log_path = "response/audit_trail.jsonl"
readme_path = "README.md"

def calculate_metrics():
    if not os.path.exists(log_path):
        print("[!] No audit trail found yet. Run an ingestion to generate stats.")
        return 0, "0%"
    
    total_alerts = 0
    successful_containments = 0
    
    with open(log_path, "r") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                total_alerts += 1
                # Check your specific state schema for success flags
                if data.get("containment_verdict") == "SUCCESS" or data.get("containment_status") == "SUCCESS_HOST_CONTAINED_VIA_IPTABLES":
                    successful_containments += 1
            except json.JSONDecodeError:
                continue

    success_rate = (successful_containments / total_alerts * 100) if total_alerts > 0 else 0
    return total_alerts, f"{success_rate:.1f}%"

def update_readme(total, rate):
    if not os.path.exists(readme_path):
        # Create a basic template if one doesn't exist yet
        with open(readme_path, "w") as f:
            f.write("# Agentic SOC Operator\n\n## Core Live Metrics\n")

    with open(readme_path, "r") as f:
        content = f.read()

    # Create the text block we want to update
    metric_marker_start = ""
    metric_marker_end = ""
    
    new_metrics_block = f"""{metric_marker_start}
### 📊 Live Pipeline Performance Metrics
* **Total Automated Alerts Ingested:** {total}
* **Successful Multi-Agent Containment Rate:** {rate}
* **Last Pipeline Telemetry Sync:** 2026 Sandbox Environment
{metric_marker_end}"""

    if metric_marker_start in content and metric_marker_end in content:
        # Splice the new metrics into the existing markdown tags
        before = content.split(metric_marker_start)[0]
        after = content.split(metric_marker_end)[1]
        updated_content = before + new_metrics_block + after
    else:
        # Append to the end of the file if tags are missing
        updated_content = content + "\n\n" + new_metrics_block

    with open(readme_path, "w") as f:
        f.write(updated_content)
    print(f"[+] Successfully updated README.md with {total} alerts at a {rate} success rate.")

if __name__ == "__main__":
    total, rate = calculate_metrics()
    if total > 0:
        update_readme(total, rate)
