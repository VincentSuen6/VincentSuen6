from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Type

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from ..core import AssessmentConfig, BaseModule, FindingResult, build_session
from ..modules import ALL_MODULES

console = Console()
log = logging.getLogger(__name__)

# Thread-safe console lock for live output from concurrent modules
_console_lock = threading.Lock()

_SEV_COLOR: dict[str, str] = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

_STATUS_TAG: dict[str, str] = {
    "BLOCKED": "[green]BLOCKED[/green]",
    "BYPASSED": "[red]BYPASSED[/red]",
    "PARTIAL": "[yellow]PARTIAL[/yellow]",
    "UNTESTED": "[dim]UNTESTED[/dim]",
}


class AssessmentRunner:
    def __init__(self, config: AssessmentConfig) -> None:
        self.config = config
        self._module_classes: list[Type[BaseModule]] = list(ALL_MODULES)

    def register(self, module_class: Type[BaseModule]) -> None:
        self._module_classes.append(module_class)

    def run(self) -> list[FindingResult]:
        console.rule("[bold cyan]AegisLoop — Adversarial Assessment")
        console.print(f"Target       : [bold]{self.config.target_url}[/bold]")
        console.print(f"Assessment ID: [dim]{self.config.assessment_id}[/dim]")
        console.print(f"Modules      : {len(self._module_classes)}")
        console.print(f"Workers      : {self.config.max_workers}")
        console.print()

        results: list[FindingResult] = []
        completed = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Running modules…", total=len(self._module_classes))

            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                future_to_cls = {}
                for i, cls in enumerate(self._module_classes):
                    if i > 0:
                        time.sleep(self.config.rate_limit_delay)
                    future_to_cls[executor.submit(self._run_module, cls)] = cls

                for future in as_completed(future_to_cls):
                    result = future.result()
                    results.append(result)
                    completed += 1

                    with _console_lock:
                        status_tag = _STATUS_TAG[result.control_status]
                        console.print(
                            f"  [cyan]>[/cyan] [{result.technique_id}] {result.technique_name}"
                        )
                        console.print(
                            f"       status: {status_tag}  "
                            f"HTTP {result.status_code or '—'}  "
                            f"{result.response_time_ms:.0f} ms"
                        )
                        if result.evidence:
                            console.print(
                                f"       [bold red]evidence:[/bold red] {result.evidence}"
                            )

                    progress.update(task, advance=1)

        # Sort by technique_id for deterministic report order
        results.sort(key=lambda r: r.technique_id)

        prev_gaps = self._load_previous_gap_count()
        risk_score = self._compute_risk_score(results)
        self._print_summary(results, risk_score, prev_gaps)
        self._save_raw(results)
        return results

    # ------------------------------------------------------------------ #

    def _run_module(self, cls: Type[BaseModule]) -> FindingResult:
        session = build_session(timeout=self.config.request_timeout)
        module = cls(session, self.config)
        return module.execute()

    def _compute_risk_score(self, results: list[FindingResult]) -> float:
        """CVSS-weighted residual risk in 0–10 range (gaps only, normalized by total count)."""
        if not results:
            return 0.0
        gap_cvss = sum(r.cvss_score for r in results if r.is_gap)
        return round(gap_cvss / len(results), 1)

    def _load_previous_gap_count(self) -> int | None:
        """Load gap count from the most recent prior run for trend analysis."""
        report_dir = Path(self.config.report_dir)
        if not report_dir.exists():
            return None
        raw_files = sorted(
            report_dir.glob("raw_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not raw_files:
            return None
        try:
            data = json.loads(raw_files[0].read_text(encoding="utf-8"))
            return sum(
                1
                for f in data.get("findings", [])
                if f.get("control_status") in ("BYPASSED", "UNTESTED")
            )
        except Exception:
            return None

    def _print_summary(
        self,
        results: list[FindingResult],
        risk_score: float,
        prev_gaps: int | None,
    ) -> None:
        console.print()
        console.rule("[bold]Assessment Summary")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Technique", style="cyan", no_wrap=True)
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("CVSS")
        table.add_column("Status")
        table.add_column("HTTP")

        for r in results:
            color = _SEV_COLOR.get(r.severity, "white")
            table.add_row(
                r.technique_id,
                r.technique_name[:55],
                f"[{color}]{r.severity}[/{color}]",
                str(r.cvss_score),
                _STATUS_TAG[r.control_status],
                str(r.status_code or "—"),
            )

        console.print(table)
        gaps = [r for r in results if r.is_gap]
        gap_count = len(gaps)

        # Trend indicator
        if prev_gaps is not None:
            delta = gap_count - prev_gaps
            if delta > 0:
                trend = f"[red]↑ +{delta} vs last run[/red]"
            elif delta < 0:
                trend = f"[green]↓ {delta} vs last run[/green]"
            else:
                trend = "[dim]= no change vs last run[/dim]"
            trend_str = f"  {trend}"
        else:
            trend_str = "  [dim](first run — no trend data)[/dim]"

        risk_color = "red" if risk_score >= 7 else "yellow" if risk_score >= 4 else "green"
        console.print(
            f"\n  Gaps identified  : [bold red]{gap_count}[/bold red] / {len(results)}{trend_str}"
        )
        console.print(
            f"  Residual risk    : [{risk_color}]{risk_score}[/{risk_color}] / 10.0  "
            f"[dim](CVSS-weighted, normalized)[/dim]"
        )

    def _save_raw(self, results: list[FindingResult]) -> None:
        path = Path(self.config.report_dir) / f"raw_{self.config.assessment_id[:8]}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "assessment_id": self.config.assessment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.config.target_url,
            "risk_score": self._compute_risk_score(results),
            "findings": [r.model_dump(mode="json") for r in results],
        }
        path.write_text(json.dumps(payload, indent=2))
        log.info("Raw results saved to %s", path)
