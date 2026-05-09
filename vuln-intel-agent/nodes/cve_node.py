import nvdlib
from state import AgentState


def cve_node(state: AgentState) -> AgentState:
    """Pulls structured CVE data from NVD API."""
    try:
        cve_id = state["cve_id"]
        print(f"[CVE Node] Fetching {cve_id}...")

        results = nvdlib.searchCVE(cveId=cve_id)
        if not results:
            state["errors"].append(f"CVE {cve_id} not found in NVD")
            return state

        cve = results[0]

        state["cve_description"] = cve.descriptions[0].value
        state["cve_cvss_score"] = float(
            cve.score[1] if hasattr(cve, "score") and cve.score else 0.0
        )
        state["cve_severity"] = (
            cve.score[2] if hasattr(cve, "score") and cve.score else "UNKNOWN"
        )
        state["cve_published_date"] = str(cve.published)

        products = []
        if hasattr(cve, "cpe") and cve.cpe:
            for cpe in cve.cpe:
                products.append(cpe.criteria)
        state["affected_products"] = products[:10]

        state["processing_status"] = "cve_complete"
        print(f"[CVE Node] Done. CVSS: {state['cve_cvss_score']} ({state['cve_severity']})")

    except Exception as e:
        state["errors"].append(f"CVE Node error: {str(e)}")
        print(f"[CVE Node] ERROR: {e}")

    return state
