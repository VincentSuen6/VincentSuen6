from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Type

from rich.console import Console
from rich.table import Table

from ..core import AssessmentConfig, BaseModule, FindingResult, build_session
from ..modules import ALL_MODULES

console = Console()
log = logging.getLogger(__name__)


class AssessmentRunner:
    def __init__(self, config: AssessmentConfig) -> None:
        self.config = config
        self.session = build_session(timeout=config.request_timeout)
        self._module_classes: list[Type[BaseModule]] = list(ALL_MODULES)

    def register(self, module_class: Type[BaseModule]) -> None:
        self._module_classes.append(module_class)

    def run(self) -> list[FindingResult]:
        console.rule("[bold cyan]AegisLoop — Adversarial Assessment")
        console.print(f"Target       : [bold]{self.config.target_url}[/bold]")
        console.print(f"Assessment ID: [dim]{self.config.assessment_id}[/dim]")
        console.print(f"Modules      : {len(self._module_classes)}")
        console.print()

        results: list[FindingResult] = []

        for cls in self._module_classes:
            module = cls(self.session, self.config)
            console.print(f"  [cyan]>[/cyan] [{module.technique_id}] {module.technique_name}")
            result = module.execute()
            results.append(result)

            status_tag = {
                "BLOCKED":  "[green]BLOCKED[/green]",
                "BYPASSED": "[red]BYPASSED[/red]",
                "PARTIAL":  "[yellow]PARTIAL[/yellow]",
                "UNTESTED": "[dim]UNTESTED[/dim]",
            }[result.control_status]

            console.print(
                f"       status: {status_tag}  "
                f"HTTP {result.status_code or '—'}  "
                f"{result.response_time_ms:.0f} ms"
            )
            if result.evidence:
                console.print(f"       [bold red]evidence:[/bold red] {result.evidence}")

            time.sleep(self.config.rate_limit_delay)

        self._print_summary(results)
        self._save_raw(results)
        return results

    def _print_summary(self, results: list[FindingResult]) -> None:
        console.print()
        console.rule("[bold]Assessment Summary")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Technique", style="cyan", no_wrap=True)
        table.add_column("Severity")
        table.add_column("CVSS")
        table.add_column("Status")
        table.add_column("HTTP")

        for r in results:
            sev_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}
            table.add_row(
                r.technique_id,
                f"[{sev_color[r.severity]}]{r.severity}[/{sev_color[r.severity]}]",
                str(r.cvss_score),
                r.control_status,
                str(r.status_code or "—"),
            )

        console.print(table)
        gaps = [r for r in results if r.is_gap]
        console.print(f"\n  Gaps identified: [bold red]{len(gaps)}[/bold red] / {len(results)}")

    def _save_raw(self, results: list[FindingResult]) -> None:
        path = Path(self.config.report_dir) / f"raw_{self.config.assessment_id[:8]}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "assessment_id": self.config.assessment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.config.target_url,
            "findings": [r.model_dump(mode="json") for r in results],
        }
        path.write_text(json.dumps(payload, indent=2))
        log.info("Raw results saved to %s", path)
