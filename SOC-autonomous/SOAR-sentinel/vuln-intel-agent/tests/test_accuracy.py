"""
Accuracy validation suite.
Runs the full agent against CVEs with known ground-truth ATT&CK mappings
and measures technique-level accuracy.

Usage:
    python tests/test_accuracy.py                   # runs all 15 CVEs
    python tests/test_accuracy.py --cve CVE-2021-44228  # single CVE
    python tests/test_accuracy.py --quick            # first 5 CVEs only

Results are saved to output/accuracy_report.json
"""
import sys
import os
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import run_agent
from utils.mitre_loader import GROUND_TRUTH, list_test_cves

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    console = Console()
    USE_RICH = True
except ImportError:
    USE_RICH = False


def technique_matches(predicted: list[dict], ground_truth: str) -> tuple[bool, str]:
    """Returns (match, matched_technique_id)."""
    predicted_ids = {t.get("id", "").strip() for t in predicted}
    # Exact match
    if ground_truth in predicted_ids:
        return True, ground_truth
    # Sub-technique match: T1190 matches T1190.001
    base = ground_truth.split(".")[0]
    for pid in predicted_ids:
        if pid.startswith(base):
            return True, pid
    return False, ""


def run_accuracy_suite(cve_ids: list[str]) -> dict:
    results = []
    correct = 0

    for i, cve_id in enumerate(cve_ids):
        truth = GROUND_TRUTH[cve_id]
        print(f"\n[{i+1}/{len(cve_ids)}] Testing {cve_id} (expected: {truth['technique']})")

        try:
            state = run_agent(cve_id)
            matched, matched_id = technique_matches(
                state.get("mitre_techniques", []),
                truth["technique"],
            )
            confidence = state.get("confidence_score", 0.0)
            predicted_ids = [t.get("id", "") for t in state.get("mitre_techniques", [])]

            result = {
                "cve_id": cve_id,
                "expected_technique": truth["technique"],
                "expected_tactic": truth["tactic"],
                "predicted_techniques": predicted_ids,
                "matched": matched,
                "matched_id": matched_id,
                "confidence_score": confidence,
                "errors": state.get("errors", []),
            }
            results.append(result)
            if matched:
                correct += 1
                print(f"  PASS — matched {matched_id} (confidence {confidence:.0%})")
            else:
                print(f"  FAIL — predicted {predicted_ids}, expected {truth['technique']}")

        except Exception as e:
            results.append({
                "cve_id": cve_id,
                "expected_technique": truth["technique"],
                "predicted_techniques": [],
                "matched": False,
                "matched_id": "",
                "confidence_score": 0.0,
                "errors": [str(e)],
            })
            print(f"  ERROR — {e}")

    accuracy = correct / len(cve_ids) if cve_ids else 0.0
    report = {
        "run_timestamp": datetime.now().isoformat(),
        "total_cves": len(cve_ids),
        "correct": correct,
        "accuracy": accuracy,
        "results": results,
    }
    return report


def print_report(report: dict) -> None:
    if USE_RICH:
        t = Table(title="Accuracy Validation Results", box=box.ROUNDED)
        t.add_column("CVE", style="cyan", no_wrap=True)
        t.add_column("Expected", style="white")
        t.add_column("Predicted", style="dim")
        t.add_column("Match", style="bold")
        t.add_column("Confidence", style="yellow")
        for r in report["results"]:
            t.add_row(
                r["cve_id"],
                r["expected_technique"],
                ", ".join(r["predicted_techniques"]),
                "[green]PASS[/green]" if r["matched"] else "[red]FAIL[/red]",
                f"{r['confidence_score']:.0%}",
            )
        console.print(t)
        console.print(
            f"\n[bold]Accuracy: [green]{report['correct']}/{report['total_cves']}"
            f" ({report['accuracy']:.0%})[/green][/bold]"
        )
    else:
        for r in report["results"]:
            status = "PASS" if r["matched"] else "FAIL"
            print(f"{status}  {r['cve_id']}  expected={r['expected_technique']}  got={r['predicted_techniques']}")
        print(f"\nAccuracy: {report['correct']}/{report['total_cves']} ({report['accuracy']:.0%})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Accuracy validation suite")
    parser.add_argument("--cve", type=str, help="Test a single CVE ID")
    parser.add_argument("--quick", action="store_true", help="Run first 5 CVEs only")
    args = parser.parse_args()

    if args.cve:
        if args.cve not in GROUND_TRUTH:
            print(f"ERROR: {args.cve} not in ground truth dataset")
            sys.exit(1)
        cve_ids = [args.cve]
    elif args.quick:
        cve_ids = list_test_cves()[:5]
    else:
        cve_ids = list_test_cves()

    report = run_accuracy_suite(cve_ids)
    print_report(report)

    os.makedirs("output", exist_ok=True)
    with open("output/accuracy_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved → output/accuracy_report.json")
