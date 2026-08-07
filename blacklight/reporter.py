"""Terminal rendering and file export of scan findings."""

import json
from dataclasses import asdict
from pathlib import Path

import jinja2
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blacklight import __version__, theme
from blacklight.cve_matcher import Finding
from blacklight.scoring import host_risk_score, web_risk_score
from blacklight.theme import ACCENT, CYAN, PURPLE, SEVERITY_STYLE, risk_gauge
from blacklight.tls import TlsFinding
from blacklight.web.models import WebFinding

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _load_template(name: str, autoescape: bool = False) -> jinja2.Template:
    text = (_TEMPLATES_DIR / name).read_text(encoding="utf-8")
    return jinja2.Template(text, autoescape=autoescape)


def _severity_key(finding: Finding) -> float:
    return finding.cvss_score if finding.cvss_score is not None else -1.0


def findings_table(findings: list[Finding]) -> Table:
    """Rich table of findings sorted by CVSS score, descending."""
    table = Table(
        title="Findings",
        expand=True,
        border_style=CYAN,
        header_style=f"bold {PURPLE}",
    )
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


def tls_findings_table(tls_findings: list[TlsFinding]) -> Table:
    """Rich table of TLS findings, most severe first."""
    table = Table(
        title="TLS findings",
        expand=True,
        border_style=CYAN,
        header_style=f"bold {PURPLE}",
    )
    for col in ("Host", "Port", "Service", "Category", "Severity", "Detail", "Evidence"):
        table.add_column(col)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    for finding in sorted(tls_findings, key=lambda f: order.get(f.severity, 4)):
        detail = finding.detail
        if finding.cve_id:
            detail = f"{finding.cve_id}: {detail}"
        table.add_row(finding.host, str(finding.port), finding.service, finding.category,
                      finding.severity, detail, finding.evidence,
                      style=SEVERITY_STYLE.get(finding.severity, ""))
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


def web_findings_table(web_findings: list[WebFinding]) -> Table:
    """Rich table of web findings grouped by severity."""
    table = Table(
        title="Web findings",
        expand=True,
        border_style=CYAN,
        header_style=f"bold {PURPLE}",
    )
    table.add_column("Category")
    table.add_column("URL")
    table.add_column("Severity")
    table.add_column("Detail")
    table.add_column("Evidence")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    for finding in sorted(web_findings, key=lambda f: order.get(f.severity, 4)):
        detail = finding.detail
        evidence = finding.evidence
        if finding.cve_id:
            detail = f"{finding.cve_id}: {detail}"
            kev = " [red]KEV[/red]" if finding.in_kev else ""
            epss = f"{finding.epss:.3f}" if finding.epss is not None else "-"
            evidence = f"{evidence} (EPSS {epss}{kev})"
        table.add_row(
            finding.category, finding.url, finding.severity, detail, evidence,
            style=SEVERITY_STYLE.get(finding.severity, ""),
        )
    return table


def _web_summary_text(web_findings: list[WebFinding], meta) -> str:
    return (
        f"[bold {ACCENT}]blacklight-cli[/] v{__version__} - web report\n"
        f"URL: [bold]{meta.url}[/] ({meta.resolved_ip}) | "
        f"Checks run: {meta.checks_run} | Checks errored: {meta.checks_errored} | "
        f"Web findings: {len(web_findings)} | Web risk score: {web_risk_score(web_findings):.1f}"
    )


def render_terminal(result, console: Console | None = None) -> None:
    """Render the rich terminal report from a typed ScanResult.

    ``result`` only needs the ScanResult contract (kind, findings,
    web_findings, meta); engine is not imported here to avoid a cycle.
    """
    console = console or theme.make_console()
    if result.kind == "web":
        console.print(
            Panel(
                _web_summary_text(result.web_findings, result.meta),
                title="Summary",
                border_style=PURPLE,
                title_align="center",
            )
        )
        if result.web_findings:
            console.print(web_findings_table(result.web_findings))
    else:
        meta = result.meta
        console.print(
            Panel(
                f"[bold {ACCENT}]blacklight-cli[/] v{__version__} - scan report\n"
                f"Targets: [bold]{meta.targets}[/] | Hosts scanned: {meta.hosts_scanned} | "
                f"Services found: {meta.services_found} | Findings: {meta.findings_count} | "
                f"TLS findings: {getattr(meta, 'tls_findings_count', 0)}",
                title="Summary",
                border_style=PURPLE,
                title_align="center",
            )
        )
    hosts = host_risk_table(result.findings)
    if hosts:
        score_table = Table(
            title="Host risk scores",
            expand=True,
            border_style=CYAN,
            header_style=f"bold {PURPLE}",
        )
        score_table.add_column("Host")
        score_table.add_column("Risk score (0-100)")
        score_table.add_column("Findings")
        for row in hosts:
            score_table.add_row(row["host"], risk_gauge(row["score"]), str(row["findings"]))
        console.print(score_table)
    if result.findings:
        console.print(findings_table(result.findings))
    if result.tls_findings:
        console.print(tls_findings_table(result.tls_findings))
    console.print(
        Panel(
            "Risk score: severity-weighted base (capped at 60) + 10 per KEV finding "
            "(capped at 20) + max EPSS x 10, capped at 100.\n"
            "For use only on systems you own or are authorized to test.\n"
            f"[cyan]●[/] [bold {ACCENT}]Scan complete[/] — report written by blacklight-cli",
            title="Notes",
            border_style=PURPLE,
        )
    )


def export_report(result, fmt: str, output: Path) -> Path:
    """Write the report in html, markdown, or json format from a ScanResult."""
    meta = result.meta
    payload = {
        "meta": asdict(meta),
        "findings": [f.to_dict() for f in result.findings],
        "hosts": host_risk_table(result.findings),
        "tls": [f.to_dict() for f in result.tls_findings],
        "web": (
            {"meta": asdict(meta), "findings": [f.to_dict() for f in result.web_findings]}
            if result.kind == "web"
            else None
        ),
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
