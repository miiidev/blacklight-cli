"""Terminal rendering and file export of scan findings."""

import json
from dataclasses import asdict
from pathlib import Path

import jinja2
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blacklight import __version__
from blacklight.cve_matcher import Finding
from blacklight.scoring import host_risk_score

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "white",
    "unknown": "dim",
}

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _load_template(name: str, autoescape: bool = False) -> jinja2.Template:
    text = (_TEMPLATES_DIR / name).read_text(encoding="utf-8")
    return jinja2.Template(text, autoescape=autoescape)


def _severity_key(finding: Finding) -> float:
    return finding.cvss_score if finding.cvss_score is not None else -1.0


def findings_table(findings: list[Finding]) -> Table:
    """Rich table of findings sorted by CVSS score, descending."""
    table = Table(title="Findings", expand=True)
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("CVE")
    table.add_column("CVSS")
    table.add_column("Severity")
    table.add_column("EPSS")
    table.add_column("KEV")
    for finding in sorted(findings, key=_severity_key, reverse=True):
        kev = "[red]KEV[/red]" if finding.in_kev else ""
        table.add_row(
            finding.host,
            str(finding.port),
            finding.service,
            finding.version,
            finding.cve_id,
            f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "-",
            finding.severity,
            f"{finding.epss:.3f}" if finding.epss is not None else "-",
            kev,
            style=SEVERITY_STYLE.get(finding.severity, ""),
        )
    return table


def host_risk_table(findings: list[Finding]) -> list[dict]:
    """Per-host risk rows {host, score, findings} sorted by score descending."""
    by_host: dict[str, list[Finding]] = {}
    for finding in findings:
        by_host.setdefault(finding.host, []).append(finding)
    rows = [
        {"host": host, "score": host_risk_score(fs), "findings": len(fs)}
        for host, fs in by_host.items()
    ]
    return sorted(rows, key=lambda row: row["score"], reverse=True)


def render_terminal(findings: list[Finding], meta: dict, console: Console | None = None) -> None:
    """Render the rich terminal report."""
    console = console or Console()
    console.print(
        Panel(
            f"[bold]blacklight-cli[/] v{__version__} - scan report\n"
            f"Targets: [bold]{meta['targets']}[/] | Hosts scanned: {meta['hosts_scanned']} | "
            f"Services found: {meta['services_found']} | Findings: {meta['findings_count']}",
            title="Summary",
        )
    )
    hosts = host_risk_table(findings)
    if hosts:
        score_table = Table(title="Host risk scores", expand=True)
        score_table.add_column("Host")
        score_table.add_column("Risk score (0-100)")
        score_table.add_column("Findings")
        for row in hosts:
            score_table.add_row(row["host"], f"{row['score']:.1f}", str(row["findings"]))
        console.print(score_table)
    if findings:
        console.print(findings_table(findings))
    console.print(
        Panel(
            "Risk score: severity-weighted base (capped at 60) + 10 per KEV finding "
            "(capped at 20) + max EPSS x 10, capped at 100.\n"
            "For use only on systems you own or are authorized to test.",
            title="Notes",
        )
    )


def export_report(findings: list[Finding], meta: dict, fmt: str, output: Path) -> Path:
    """Write the report in html, markdown, or json format."""
    payload = {
        "meta": meta,
        "findings": [f.to_dict() for f in findings],
        "hosts": host_risk_table(findings),
    }
    if fmt == "json":
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "html":
        output.write_text(
            _load_template("report.html.j2", autoescape=True).render(**payload),
            encoding="utf-8",
        )
    elif fmt == "markdown":
        output.write_text(
            _load_template("report.md.j2").render(**payload),
            encoding="utf-8",
        )
    else:
        raise ValueError(f"Unknown format: {fmt}")
    return output
