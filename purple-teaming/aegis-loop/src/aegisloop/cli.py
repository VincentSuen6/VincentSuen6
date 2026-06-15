from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console

from .core.models import AssessmentConfig
from .pipeline import AssessmentRunner, correlate
from .reporting import write_layer, write_report

load_dotenv()
app = typer.Typer(help="AegisLoop — Purple Team Control Validation Pipeline")
console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)


def _config_from_env() -> AssessmentConfig:
    return AssessmentConfig(
        target_url=os.environ.get("AEGIS_TARGET_URL", "http://localhost:8080"),
        request_timeout=int(os.environ.get("AEGIS_REQUEST_TIMEOUT", 10)),
        rate_limit_delay=float(os.environ.get("AEGIS_RATE_LIMIT_DELAY", 0.5)),
        max_workers=int(os.environ.get("AEGIS_MAX_WORKERS", 5)),
        assessor=os.environ.get("AEGIS_ASSESSOR", "Purple Team"),
        report_dir=os.environ.get("AEGIS_REPORT_DIR", "./reports"),
        navigator_dir=os.environ.get("AEGIS_NAVIGATOR_DIR", "./navigator-data"),
        waf_log_path=os.environ.get("AEGIS_WAF_LOG_PATH", "./waf-logs/access.log"),
    )


@app.command()
def run(
    target: str = typer.Option(None, "--target", "-t", help="Override target URL"),
    no_waf_correlation: bool = typer.Option(False, "--no-waf", help="Skip WAF log correlation"),
) -> None:
    """Run the full assessment suite and generate reports."""
    config = _config_from_env()
    if target:
        config.target_url = target

    runner = AssessmentRunner(config)
    findings = runner.run()

    if not no_waf_correlation:
        console.print("\n[cyan]Correlating WAF telemetry...[/cyan]")
        findings = correlate(findings, config.waf_log_path)

    risk_score = runner._compute_risk_score(findings)
    prev_gaps = runner._load_previous_gap_count()
    gap_count = sum(1 for f in findings if f.is_gap)
    if prev_gaps is not None:
        delta = gap_count - prev_gaps
        trend_str = f"{'↑' if delta > 0 else '↓' if delta < 0 else '='} {delta:+d} vs last run"
    else:
        trend_str = ""

    navigator_path = write_layer(findings, config.navigator_dir, config.assessment_id)
    report_path = write_report(
        findings, config.report_dir, config.assessment_id, config.target_url,
        risk_score=risk_score, trend_str=trend_str,
    )

    console.print(f"\n  Navigator layer : [bold]{navigator_path}[/bold]")
    console.print(f"  HTML report     : [bold]{report_path}[/bold]")
    console.print(
        f"\n  Load the layer at [bold]http://localhost:8082[/bold] → "
        "Open Existing Layer → Upload from File"
    )


@app.command()
def report(raw_file: str = typer.Argument(..., help="Path to raw JSON results file")) -> None:
    """Re-generate Navigator layer and HTML report from a raw results file."""
    config = _config_from_env()
    path = Path(raw_file)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {raw_file}")
        sys.exit(1)

    payload = json.loads(path.read_text())
    from .core.models import FindingResult  # local import to avoid circular

    findings = [FindingResult(**f) for f in payload["findings"]]
    aid = payload.get("assessment_id", config.assessment_id)

    findings = correlate(findings, config.waf_log_path)
    write_layer(findings, config.navigator_dir, aid)
    write_report(findings, config.report_dir, aid, payload.get("target", config.target_url))
    console.print("[green]Reports regenerated.[/green]")
