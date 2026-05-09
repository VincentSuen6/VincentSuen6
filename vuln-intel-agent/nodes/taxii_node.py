from taxii2client.v21 import Server
from state import AgentState


def taxii_node(state: AgentState) -> AgentState:
    """Pulls STIX threat intelligence from MITRE ATT&CK TAXII server."""
    try:
        print("[TAXII Node] Querying MITRE ATT&CK threat intel feeds...")

        server = Server(
            "https://attack-taxii.mitre.org/taxii2/",
            user="guest",
            password="guest",
        )

        api_root = server.api_roots[0]
        collections = api_root.collections

        taxii_ttps = []

        for collection in collections[:3]:
            try:
                bundle = collection.get_objects()
                for obj in bundle.get("objects", []):
                    if obj.get("type") == "attack-pattern":
                        name = obj.get("name", "")
                        for ref in obj.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                technique_id = ref.get("external_id", "")
                                if technique_id:
                                    taxii_ttps.append({
                                        "technique_id": technique_id,
                                        "name": name,
                                    })
            except Exception:
                continue

        state["taxii_ttps"] = [t["technique_id"] for t in taxii_ttps[:20]]
        state["stix_indicators"] = []
        state["processing_status"] = "taxii_complete"
        print(f"[TAXII Node] Done. TTPs found: {len(state['taxii_ttps'])}")

    except Exception as e:
        state["errors"].append(f"TAXII Node error: {str(e)}")
        state["taxii_ttps"] = []
        print(f"[TAXII Node] ERROR (non-fatal): {e}")

    return state
