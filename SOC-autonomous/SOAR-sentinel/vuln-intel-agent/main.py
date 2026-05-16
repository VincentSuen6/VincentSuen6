import os
import sys
import json
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from graph import build_graph
from state import AgentState

load_dotenv()
console = Console()


def run_agent(cve_id: str) -> AgentState:
    console.print(Panel(
        Text.assemble(
            ("Vulnerability Intelligence Agent\n", "bold cyan"),
            ("Processing: ", "white"),
            (cve_id, "bold yellow"),
        ),
        subtitle="LangGraph · NVD · Claude · MITRE ATT&CK · Wazuh · Splunk",
        box=box.DOUBLE,
    ))

    initial_state: AgentState = {
        "cve_id": cve_id,
        "cve_description": "",
        "cve_severity": "",
        "cve_cvss_score": 0.0,
        "affected_products": [],
        "cve_published_date": "",
        "exploit_references": [],
        "poc_available": False,
        "threat_actor_mentions": [],
        "osint_summary": "",
        "stix_indicators": [],
        "related_campaigns": [],
        "taxii_ttps": [],
        "cross_referenced_ttps": [],
        "confidence_score": 0.0,
        "validation_notes": "",
        "mitre_techniques": [],
        "mitre_tactics": [],
        "attack_chain": [],
        "wazuh_rule": "",
        "splunk_query": "",
        "alert_severity": "",
        "malware_families": [],
        "behavior_timeline": [],
        "ransomware_complexity_trend": "",
        "exploit_timing_analysis": "",
        "attacker_adaptation_notes": "",
        "behavior_mitre_mapping": [],
        "errors": [],
        "processing_status": "started",
    }

    graph = build_graph()
    result = graph.invoke(initial_state)

    display_results(result)
    save_outputs(result)

    return result


def display_results(state: AgentState) -> None:
    console.rule("[bold cyan]Analysis Complete")

    # CVE summary
    console.print(Panel(
        f"[bold]{state['cve_id']}[/bold]  CVSS [red]{state['cve_cvss_score']}[/red]"
        f"  Severity [red]{state['cve_severity']}[/red]\n"
        f"{state['cve_description'][:300]}...",
        title="CVE Summary",
    ))

    # MITRE ATT&CK techniques table
    t = Table(title="MITRE ATT&CK Mapping", box=box.ROUNDED)
    t.add_column("Technique ID", style="cyan", no_wrap=True)
    t.add_column("Name", style="white")
    t.add_column("Tactic", style="green")
    t.add_column("Confidence", style="yellow")
    t.add_column("Rationale", style="dim")
    for tech in state.get("mitre_techniques", []):
        t.add_row(
            tech.get("id", ""),
            tech.get("name", ""),
            tech.get("tactic", ""),
            tech.get("confidence", ""),
            tech.get("rationale", "")[:60],
        )
    console.print(t)

    # Attack chain
    chain = " → ".join(state.get("attack_chain", []))
    console.print(f"\n[bold]Attack Chain:[/bold] [cyan]{chain}[/cyan]")
    console.print(f"[bold]Confidence Score:[/bold] [green]{state['confidence_score']:.0%}[/green]")
    console.print(f"[bold]PoC Available:[/bold] {'[red]YES[/red]' if state['poc_available'] else '[green]No[/green]'}")
    console.print(f"[bold]Alert Severity:[/bold] [red]{state['alert_severity'].upper()}[/red]")

    # OSINT
    if state.get("osint_summary"):
        console.print(Panel(state["osint_summary"], title="OSINT Summary"))

    if state.get("threat_actor_mentions"):
        console.print(
            f"[bold]Threat Actors:[/bold] {', '.join(state['threat_actor_mentions'])}"
        )

    # Malware behavior analysis
    if state.get("ransomware_complexity_trend"):
        console.print(Panel(
            f"[bold]Ransomware Complexity Trend:[/bold]\n{state['ransomware_complexity_trend']}\n\n"
            f"[bold]Exploit Timing:[/bold]\n{state['exploit_timing_analysis']}\n\n"
            f"[bold]Defender-Driven Adaptation:[/bold]\n{state['attacker_adaptation_notes']}",
            title="10-Year Malware Behavior Analysis",
        ))

    # Behavior timeline table
    if state.get("behavior_timeline"):
        bt = Table(title="Malware Evolution Timeline", box=box.SIMPLE)
        bt.add_column("Year", style="cyan", no_wrap=True)
        bt.add_column("Family", style="yellow")
        bt.add_column("Key Shift", style="white")
        bt.add_column("Techniques", style="dim")
        for entry in state["behavior_timeline"]:
            bt.add_row(
                str(entry.get("year", "")),
                entry.get("family", ""),
                entry.get("key_shift", "")[:60],
                ", ".join(entry.get("mitre_techniques", [])),
            )
        console.print(bt)

    # Detection rules preview
    if state.get("wazuh_rule"):
        console.print(Panel(
            f"[dim]{state['wazuh_rule'][:400]}...[/dim]",
            title="Wazuh Rule (preview)",
        ))
    if state.get("splunk_query"):
        console.print(Panel(
            f"[dim]{state['splunk_query']}[/dim]",
            title="Splunk Query",
        ))

    # Errors
    if state.get("errors"):
        console.print(f"\n[yellow]Warnings / Errors:[/yellow]")
        for err in state["errors"]:
            console.print(f"  [yellow]⚠[/yellow]  {err}")


def save_outputs(state: AgentState) -> None:
    cve_id = state["cve_id"].replace("-", "_")
    os.makedirs("output/siem-rules", exist_ok=True)

    if state["wazuh_rule"]:
        with open(f"output/siem-rules/{cve_id}_wazuh.xml", "w") as f:
            f.write(state["wazuh_rule"])

    if state["splunk_query"]:
        with open(f"output/siem-rules/{cve_id}_splunk.spl", "w") as f:
            f.write(state["splunk_query"])

    with open(f"output/{cve_id}_report.json", "w") as f:
        json.dump(state, f, indent=2, default=str)

    console.print(f"\n[cyan]Outputs saved → output/{cve_id}_report.json[/cyan]")
    console.print(f"[cyan]SIEM rules   → output/siem-rules/{cve_id}_wazuh.xml[/cyan]")
    console.print(f"[cyan]             → output/siem-rules/{cve_id}_splunk.spl[/cyan]")


if __name__ == "__main__":
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3400"
    run_agent(cve)
