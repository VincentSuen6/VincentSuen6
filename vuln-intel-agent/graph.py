from langgraph.graph import StateGraph, END
from state import AgentState
from nodes.cve_node import cve_node
from nodes.osint_node import osint_node
from nodes.taxii_node import taxii_node
from nodes.validator_node import validator_node
from nodes.mitre_mapper import mitre_mapper_node
from nodes.siem_generator import siem_generator_node
from nodes.malware_behavior_node import malware_behavior_node


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("cve_decomposition", cve_node)
    graph.add_node("osint_gathering", osint_node)
    graph.add_node("taxii_intel", taxii_node)
    graph.add_node("cross_validation", validator_node)
    graph.add_node("mitre_mapping", mitre_mapper_node)
    graph.add_node("malware_behavior", malware_behavior_node)
    graph.add_node("siem_generation", siem_generator_node)

    graph.set_entry_point("cve_decomposition")

    # CVE → parallel OSINT + TAXII
    graph.add_edge("cve_decomposition", "osint_gathering")
    graph.add_edge("cve_decomposition", "taxii_intel")

    # Both feed into cross-validation
    graph.add_edge("osint_gathering", "cross_validation")
    graph.add_edge("taxii_intel", "cross_validation")

    # Linear from cross-validation onward
    graph.add_edge("cross_validation", "mitre_mapping")
    graph.add_edge("mitre_mapping", "malware_behavior")
    graph.add_edge("malware_behavior", "siem_generation")
    graph.add_edge("siem_generation", END)

    return graph.compile()
