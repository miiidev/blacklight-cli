# blacklight-cli Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build blacklight-cli, a local CLI network vulnerability scanner (nmap service detection → NVD CVE matching → EPSS/KEV enrichment → host risk scores → rich terminal + HTML/Markdown/JSON reports).

**Architecture:** Four-stage pipeline — `scanner.py` shells out to `nmap -sV -oX -` and parses XML with stdlib ElementTree; `cpe_map.py` maps service names to CPE strings; `cve_matcher.py` queries the NVD API 2.0 (cached, rate-limited, optional free API key) and produces `Finding` records; `enrichment.py` overlays EPSS probabilities and CISA KEV membership; `scoring.py` computes a 0-100 host risk score; `reporter.py` renders rich terminal output and exports HTML/Markdown/JSON; `cli.py` (typer) orchestrates it all behind authorization guardrails.

**Tech Stack:** Python 3.11+, typer, rich, jinja2, requests, pytest, setuptools. Console command: `blacklight`.

## Global Constraints

- Python >= 3.11. Runtime deps: `typer>=0.12`, `rich>=13.7`, `jinja2>=3.1`, `requests>=2.31`. Dev dep: `pytest>=8`.
- PyPI name: `blacklight-cli`. Python package directory: `blacklight/`. Console script: `blacklight = "blacklight.cli:app"`.
- No LLM/AI usage, no `python-nmap` — nmap is invoked via subprocess and XML parsed with stdlib `xml.etree.ElementTree`.
- NVD API 2.0: query by `cpeName` at `https://services.nvd.nist.gov/rest/json/cves/2.0`; optional free key via env var `BLACKLIGHT_NVD_KEY` (50 req/30s with key, 5 req/30s without); lookups cached in `~/.blacklight/cache/` keyed by CPE string, TTL 7 days; `--no-cache` bypasses.
- EPSS: `https://api.first.org/data/v1/epss`, keyless, batch by CVE IDs (100/request), cached in `~/.blacklight/cache/epss.json`. KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, keyless, cached in `~/.blacklight/cache/kev.json`, refreshed after 24h.
- Guardrails (default-deny): only RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback (`127.0.0.0/8`) are scannable by default; public targets are blocked unless `--i-have-permission`; even with the flag, public targets require an interactive `y` confirmation; checks are per-target-network (a range containing any public address is blocked); every scan is appended to `~/.blacklight/scan.log`.
- Risk score formula (per host, 0-100, transparent): base = sum of severity weights (critical=20, high=10, medium=4, low=1, unknown=0) capped at 60; +10 per KEV finding capped at +20; + up to 10 scaled by max EPSS among the host's findings (epss * 10); total capped at 100. Formula documented in README and shown in report footer.
- nmap binary is a system dependency: detect at runtime, print per-OS install hints (`apt install nmap`, `brew install nmap`, `choco install nmap`) and exit cleanly when missing.
- Severity mapping from CVSS v3 base score: >=9.0 critical, >=7.0 high, >=4.0 medium, else low; missing score → "unknown".
- Version extraction: nmap version strings like `9.6p1` → `9.6` (first dotted numeric run, up to 4 components); versionless services map to CPE version `*`.
- Every task: TDD — write the failing test first, run it (must fail), implement, run (must pass), commit.

---

## File Structure

```
(repo root: D:\Syahmi\MyCode\TBD — pyproject.toml lives here)
├── pyproject.toml              # Task 1
├── README.md                   # Task 1 (stub) / Task 10 (full)
├── .gitignore                  # Task 10
├── blacklight/
│   ├── __init__.py             # Task 1 — __version__ = "0.1.0"
│   ├── paths.py                # Task 1 — ~/.blacklight home/cache/log paths
│   ├── cli.py                  # Task 1 stub (version cmd) / Task 9 (full)
│   ├── guardrails.py           # Task 2 — IP checks, permission verdicts
│   ├── scanner.py              # Task 3 — nmap subprocess + XML parse
│   ├── cpe_map.py              # Task 4 — service → CPE mapping table
│   ├── cve_matcher.py          # Task 5 — NvdClient, CVE/Finding dataclasses
│   ├── enrichment.py           # Task 6 — EPSS + KEV overlay
│   ├── scoring.py              # Task 7 — host risk scores
│   ├── reporter.py             # Task 8 — rich terminal + export
│   └── templates/
│       ├── report.html.j2      # Task 8
│       └── report.md.j2        # Task 8
├── tests/
│   ├── conftest.py             # Task 1 — shared fixtures
│   ├── fixtures/
│   │   ├── nmap_sv.xml         # Task 3 — sample nmap -sV -oX output
│   │   └── nvd_cves.json       # Task 5 — sample NVD API response
│   ├── test_cli.py             # Task 1 / Task 9
│   ├── test_guardrails.py      # Task 2
│   ├── test_scanner.py         # Task 3
│   ├── test_cpe_map.py         # Task 4
│   ├── test_cve_matcher.py     # Task 5
│   ├── test_enrichment.py      # Task 6
│   ├── test_scoring.py         # Task 7
│   └── test_reporter.py        # Task 8
└── examples/
    ├── make_sample.py          # Task 10 — generates sample report
    └── sample_report.html      # Task 10 (generated artifact)
```

Key data contracts (defined in Task 5, consumed by Tasks 6-10):

```python
@dataclass CVE:
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str          # critical|high|medium|low|unknown
    fixed_version: str | None

@dataclass Finding:
    host: str; port: int; service: str; version: str; cpe: str
    cve_id: str; description: str; cvss_score: float | None
    severity: str; fixed_version: str | None
    epss: float | None = None      # set by enrichment, 0.0 when unknown
    in_kev: bool = False           # set by enrichment
    def to_dict(self) -> dict      # asdict(self)
```

---

### Task 1: Project Scaffolding (pyproject, package skeleton, stub CLI)

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `blacklight/__init__.py`
- Create: `blacklight/paths.py`
- Create: `blacklight/cli.py`
- Create: `tests/conftest.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Produces: `blacklight.__version__ == "0.1.0"`; `blacklight.paths.CACHE_DIR`, `blacklight.paths.SCAN_LOG`, `blacklight.paths.ensure_dirs()`; typer app `blacklight.cli.app` with a `version` subcommand.

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py`:

```python
from typer.testing import CliRunner

from blacklight.cli import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "blacklight-cli 0.1.0" in result.output
```

`tests/conftest.py`:

```python
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nmap_xml() -> str:
    return (FIXTURES / "nmap_sv.xml").read_text(encoding="utf-8")


@pytest.fixture
def nvd_payload() -> dict:
    return json.loads((FIXTURES / "nvd_cves.json").read_text(encoding="utf-8"))
```

Note: fixtures `nmap_sv.xml` and `nvd_cves.json` are created in Tasks 3 and 5; conftest only imports them lazily, so it is safe now.

- [ ] **Step 2: Run test to verify it fails**

Run: `pip install -e ".[dev]"` then `pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight'`

- [ ] **Step 3: Create the scaffolding**

`pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "blacklight-cli"
version = "0.1.0"
description = "Network vulnerability scanner: nmap service detection + NVD CVE matching with EPSS/KEV enrichment"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
keywords = ["security", "vulnerability", "nmap", "cve", "nvd", "scanning"]
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "jinja2>=3.1",
    "requests>=2.31",
]

[project.optional-dependencies]
dev = ["pytest>=8"]

[project.scripts]
blacklight = "blacklight.cli:app"

[tool.setuptools]
packages = ["blacklight"]

[tool.setuptools.package-data]
blacklight = ["templates/*.j2"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

`README.md` (stub — expanded in Task 10):

```markdown
# blacklight-cli

Local network vulnerability scanner: nmap service detection, NVD CVE matching,
EPSS/KEV enrichment, host risk scores, rich terminal output and HTML/Markdown/JSON reports.

**Warning:** use only on systems you own or are explicitly authorized to test.
```

`blacklight/__init__.py`:

```python
"""blacklight-cli: local network vulnerability scanner."""

__version__ = "0.1.0"
```

`blacklight/paths.py`:

```python
"""Filesystem locations for blacklight state (cache, scan log)."""

from pathlib import Path

HOME_DIR = Path.home() / ".blacklight"
CACHE_DIR = HOME_DIR / "cache"
SCAN_LOG = HOME_DIR / "scan.log"


def ensure_dirs() -> None:
    """Create ~/.blacklight and ~/.blacklight/cache if missing."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
```

`blacklight/cli.py`:

```python
"""blacklight-cli entry point."""

import typer
from rich.console import Console

from blacklight import __version__

console = Console()

app = typer.Typer(
    help="blacklight-cli: scan networks for vulnerable services. "
    "For use only on systems you own or are authorized to test."
)


@app.command()
def version() -> None:
    """Show the installed version."""
    console.print(f"blacklight-cli {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (1 passed)

Also verify the console script: `blacklight version` → prints `blacklight-cli 0.1.0`.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml README.md blacklight/ tests/
git commit -m "feat: scaffold blacklight-cli package with typer entry point"
```

---

### Task 2: Guardrails (default-deny target validation)

**Files:**
- Create: `blacklight/guardrails.py`
- Create: `tests/test_guardrails.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `guardrails.is_private(target: str) -> bool`; `guardrails.verify_targets(targets: list[str], permission_granted: bool) -> Verdict` where `Verdict` is a dataclass with `allowed: list[str]`, `needs_confirmation: list[str]`, `blocked: list[str]`.

- [ ] **Step 1: Write the failing test**

`tests/test_guardrails.py`:

```python
import pytest

from blacklight.guardrails import is_private, verify_targets


@pytest.mark.parametrize(
    "target,expected",
    [
        ("192.168.1.5", True),
        ("192.168.1.0/24", True),
        ("192.168.0.0/16", True),
        ("10.0.0.1", True),
        ("10.0.0.0/8", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("172.16.0.0/12", True),
        ("127.0.0.1", True),
        ("127.0.0.0/8", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("192.169.0.1", False),
        ("172.32.0.1", False),
        ("192.168.0.0/15", False),
        ("not-an-ip", False),
    ],
)
def test_is_private(target, expected):
    assert is_private(target) is expected


def test_verify_targets_blocks_public_without_permission():
    verdict = verify_targets(["192.168.1.5", "8.8.8.8"], permission_granted=False)
    assert verdict.allowed == ["192.168.1.5"]
    assert verdict.needs_confirmation == []
    assert verdict.blocked == ["8.8.8.8"]


def test_verify_targets_requires_confirmation_with_permission():
    verdict = verify_targets(["8.8.8.8"], permission_granted=True)
    assert verdict.allowed == []
    assert verdict.needs_confirmation == ["8.8.8.8"]
    assert verdict.blocked == []


def test_verify_targets_rejects_garbage():
    verdict = verify_targets(["garbage"], permission_granted=True)
    assert verdict.blocked == ["garbage"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_guardrails.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.guardrails'`

- [ ] **Step 3: Write the implementation**

`blacklight/guardrails.py`:

```python
"""Authorization guardrails: default-deny scanning of non-private targets."""

import ipaddress
from dataclasses import dataclass

PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


@dataclass
class Verdict:
    """Result of validating scan targets.

    allowed: safe to scan immediately (fully private).
    needs_confirmation: public targets the user claimed permission for;
        the CLI must still prompt before scanning.
    blocked: rejected (public without permission, or unparseable).
    """

    allowed: list[str]
    needs_confirmation: list[str]
    blocked: list[str]

    @property
    def has_public_targets(self) -> bool:
        return bool(self.needs_confirmation)


def is_private(target: str) -> bool:
    """True if the whole target (host or CIDR) falls inside private ranges.

    Uses subnet containment, so a CIDR that includes any public address
    (e.g. 192.168.0.0/15) is correctly treated as not private.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return any(net.subnet_of(private) for private in PRIVATE_NETWORKS)


def verify_targets(targets: list[str], permission_granted: bool) -> Verdict:
    """Classify each target into allowed / needs_confirmation / blocked."""
    allowed: list[str] = []
    needs_confirmation: list[str] = []
    blocked: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        if is_private(target):
            allowed.append(target)
        elif permission_granted:
            needs_confirmation.append(target)
        else:
            blocked.append(target)
    return Verdict(allowed=allowed, needs_confirmation=needs_confirmation, blocked=blocked)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_guardrails.py -v`
Expected: PASS (18 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/guardrails.py tests/test_guardrails.py
git commit -m "feat: add default-deny guardrails for scan targets"
```

---

### Task 3: Scanner (nmap subprocess + XML parsing)

**Files:**
- Create: `tests/fixtures/nmap_sv.xml`
- Create: `blacklight/scanner.py`
- Create: `tests/test_scanner.py`

**Interfaces:**
- Consumes: nothing (records feed `cpe_map`/`cve_matcher` later).
- Produces: `scanner.find_nmap() -> str | None`; `scanner.scan_hosts(targets: list[str], ports: str, timeout: int) -> list[ScanRecord]`; `scanner.parse_nmap_xml(xml_text: str) -> list[ScanRecord]`; `ScanRecord` dataclass with fields `host: str, port: int, protocol: str, service: str, version: str`. `service` = nmap's `product` attribute when present (e.g. "OpenSSH"), else the `name` attribute (e.g. "ssh"); `version` = nmap's `version` attribute (e.g. "9.6p1").

- [ ] **Step 1: Write the failing test**

`tests/fixtures/nmap_sv.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sV -oX - 192.168.1.10">
<host><address addr="192.168.1.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.24.0" method="probed"/></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" method="probed"/></port>
</ports></host>
<host><address addr="192.168.1.11" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.58" method="probed"/></port>
</ports></host>
</nmaprun>
```

`tests/test_scanner.py`:

```python
import pytest

from blacklight.scanner import ScanRecord, parse_nmap_xml


def test_parse_nmap_xml_skips_closed_ports(nmap_xml):
    records = parse_nmap_xml(nmap_xml)
    assert records == [
        ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1"),
        ScanRecord(host="192.168.1.10", port=443, protocol="tcp", service="nginx", version="1.24.0"),
        ScanRecord(host="192.168.1.10", port=3306, protocol="tcp", service="mysql", version=""),
        ScanRecord(host="192.168.1.11", port=8080, protocol="tcp", service="Apache httpd", version="2.4.58"),
    ]


def test_parse_nmap_xml_empty_scan():
    assert parse_nmap_xml("<nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/><ports/></host></nmaprun>") == []


def test_parse_nmap_xml_rejects_non_xml():
    with pytest.raises(ValueError):
        parse_nmap_xml("not xml at all")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.scanner'`

- [ ] **Step 3: Write the implementation**

`blacklight/scanner.py`:

```python
"""Scan engine: shell out to nmap -sV and parse the XML output."""

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class ScanRecord:
    """One open port with detected service information."""

    host: str
    port: int
    protocol: str
    service: str
    version: str


def find_nmap() -> str | None:
    """Return the nmap executable name if available, else None."""
    try:
        result = subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True, timeout=15
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return "nmap" if result.returncode == 0 else None


def scan_hosts(targets: list[str], ports: str = "1-1024", timeout: int = 30) -> list[ScanRecord]:
    """Run nmap with service/version detection and return parsed records.

    Raises RuntimeError if nmap produced no XML output.
    """
    cmd = [
        "nmap", "-sV", "-p", ports, "-oX", "-",
        "--host-timeout", f"{timeout}s", "--", *targets,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 2 + 120)
    if not proc.stdout.strip():
        stderr_tail = proc.stderr.strip()[-500:]
        raise RuntimeError(f"nmap produced no output. stderr: {stderr_tail}")
    return parse_nmap_xml(proc.stdout)


def parse_nmap_xml(xml_text: str) -> list[ScanRecord]:
    """Parse nmap -oX XML into ScanRecord list (open ports only)."""
    root = ET.fromstring(xml_text)  # raises ValueError on malformed XML
    records: list[ScanRecord] = []
    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        addr = address.get("addr", "")
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = ""
            version = ""
            if service is not None:
                name = service.get("product") or service.get("name") or ""
                version = service.get("version") or ""
            records.append(
                ScanRecord(
                    host=addr,
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    service=name,
                    version=version,
                )
            )
    return records
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scanner.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/scanner.py tests/test_scanner.py tests/fixtures/nmap_sv.xml
git commit -m "feat: add nmap scan engine with XML parsing"
```

---

### Task 4: CPE Mapping (service → CPE)

**Files:**
- Create: `blacklight/cpe_map.py`
- Create: `tests/test_cpe_map.py`

**Interfaces:**
- Consumes: `ScanRecord` shape (Task 3) conceptually, but `cpe_map` functions take plain strings.
- Produces: `cpe_map.extract_version(version: str) -> str | None` (first dotted numeric run, e.g. `9.6p1` → `9.6`); `cpe_map.service_to_cpe(service: str, version: str | None) -> str | None` producing `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*` (version `*` when None).

- [ ] **Step 1: Write the failing test**

`tests/test_cpe_map.py`:

```python
import pytest

from blacklight.cpe_map import SERVICE_CPE, extract_version, service_to_cpe


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("9.6p1", "9.6"),
        ("1.24.0", "1.24.0"),
        ("2.4.58-1ubuntu", "2.4.58"),
        ("10.2.3.4", "10.2.3.4"),
        ("", None),
        ("nginx", None),
    ],
)
def test_extract_version(raw, expected):
    assert extract_version(raw) == expected


def test_service_to_cpe_openssh():
    assert service_to_cpe("OpenSSH", "9.6") == "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"


def test_service_to_cpe_apache_httpd():
    assert service_to_cpe("Apache httpd", "2.4.58") == "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"


def test_service_to_cpe_versionless_uses_wildcard():
    assert service_to_cpe("mysql", None) == "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"


def test_service_to_cpe_unknown_service():
    assert service_to_cpe("weird-service", "1.0") is None


def test_mapping_table_covers_common_services():
    for service in ("openssh", "apache httpd", "nginx", "mysql", "postgresql",
                    "redis", "vsftpd", "postfix", "dovecot", "bind", "openvpn"):
        assert service in SERVICE_CPE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cpe_map.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.cpe_map'`

- [ ] **Step 3: Write the implementation**

`blacklight/cpe_map.py`:

```python
"""Map nmap service names to NVD CPE vendor:product identifiers."""

import re

# nmap service name (lowercase, product preferred) -> (CPE vendor, CPE product)
SERVICE_CPE: dict[str, tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "memcached": ("memcached", "memcached"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "iis": ("microsoft", "internet_information_server"),
    "microsoft-httpd": ("microsoft", "httpd"),
    "opensmtpd": ("openbsd", "opensmtpd"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "unbound": ("nlnetlabs", "unbound"),
    "openvpn": ("openvpn", "openvpn"),
    "openssl": ("openssl", "openssl"),
    "samba": ("samba", "samba"),
    "samba smbd": ("samba", "samba"),
    "isc-dhcp-server": ("isc", "dhcp"),
    "snmp": ("net-snmp", "net-snmp"),
    "ntp": ("ntp", "ntp"),
    "openldap": ("openldap", "openldap"),
    "slapd": ("openldap", "openldap"),
    "zabbix": ("zabbix", "zabbix"),
    "grafana": ("grafana", "grafana"),
    "prometheus": ("prometheus", "prometheus"),
    "jenkins": ("cloudbees", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "haproxy": ("haproxy", "haproxy"),
    "squid": ("squid-cache", "squid"),
    "varnish": ("varnish-cache", "varnish"),
    "cups": ("apple", "cups"),
    "apache-couchdb": ("apache", "couchdb"),
    "couchdb": ("apache", "couchdb"),
    "h2 database": ("h2database", "h2"),
    "docker": ("docker", "docker"),
    "docker registry": ("docker", "distribution"),
    "kubernetes": ("kubernetes", "kubernetes"),
}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def extract_version(version: str) -> str | None:
    """Pull the first dotted numeric run out of a version string.

    Examples: "9.6p1" -> "9.6", "2.4.58-1ubuntu" -> "2.4.58", "" -> None.
    """
    match = _VERSION_RE.search(version)
    return match.group(1) if match else None


def service_to_cpe(service: str, version: str | None) -> str | None:
    """Build a CPE 2.3 URI for a service name + version, or None if unmapped."""
    key = service.strip().lower()
    pair = SERVICE_CPE.get(key)
    if pair is None:
        return None
    vendor, product = pair
    ver = version or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cpe_map.py -v`
Expected: PASS (13 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/cpe_map.py tests/test_cpe_map.py
git commit -m "feat: add service-to-CPE mapping table"
```

---

### Task 5: CVE Matcher (NVD client + findings)

**Files:**
- Create: `tests/fixtures/nvd_cves.json`
- Create: `blacklight/cve_matcher.py`
- Create: `tests/test_cve_matcher.py`

**Interfaces:**
- Consumes: `ScanRecord` (Task 3), `extract_version`/`service_to_cpe` (Task 4), `paths.CACHE_DIR` (Task 1).
- Produces: dataclasses `CVE` and `Finding` (exact shapes in File Structure section above), `cve_matcher.severity_from_score(score: float | None) -> str`, `cve_matcher.NvdClient(api_key: str | None, cache_dir: Path | None, no_cache: bool)` with `NvdClient.lookup(cpe: str) -> list[CVE]`, and `cve_matcher.build_findings(records: list[ScanRecord], client: NvdClient) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

`tests/fixtures/nvd_cves.json` (a realistic NVD API 2.0 response):

```json
{
  "resultsPerPage": 2,
  "totalResults": 2,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-12345",
        "descriptions": [
          {"lang": "en", "value": "A sample vulnerability in OpenSSH allowing code execution."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
          ]
        },
        "configurations": {
          "nodes": [
            {"cpeMatch": [{"vulnerable": true, "cpe22Uri": "cpe:/a:openbsd:openssh:9.6", "versionEndExcluding": "9.7"}]}
          ]
        }
      }
    },
    {
      "cve": {
        "id": "CVE-2023-99999",
        "descriptions": [
          {"lang": "en", "value": "A sample information disclosure in OpenSSH."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}
          ]
        },
        "configurations": {
          "nodes": [
            {"cpeMatch": [{"vulnerable": true, "cpe22Uri": "cpe:/a:openbsd:openssh:9.6", "versionEndExcluding": "9.7"}]}
          ]
        }
      }
    }
  ]
}
```

`tests/test_cve_matcher.py`:

```python
from pathlib import Path

import pytest

from blacklight.cve_matcher import (
    CVE,
    Finding,
    NvdClient,
    build_findings,
    severity_from_score,
)
from blacklight.scanner import ScanRecord


def test_severity_from_score():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(9.0) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(1.2) == "low"
    assert severity_from_score(None) == "unknown"


def test_nvd_lookup_parses_payload(nvd_payload, tmp_path, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return nvd_payload

    monkeypatch.setattr(client.session, "get", lambda *a, **k: FakeResponse())
    cves = client.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
    assert [c.cve_id for c in cves] == ["CVE-2024-12345", "CVE-2023-99999"]
    assert cves[0].cvss_score == 9.8
    assert cves[0].severity == "critical"
    assert cves[0].fixed_version == "9.7"
    assert cves[1].severity == "medium"


def test_nvd_lookup_uses_cache(tmp_path, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)
    cache_file = tmp_path / "nvd_cpe_2.3_a_openbsd_openssh_9.6_star_star_star_star_star_star_star_star_star_star.json"
    cache_file.write_text(
        '{"fetched_at": "2030-01-01T00:00:00+00:00", "cves": [{"cve_id": "CVE-2024-12345", '
        '"description": "cached", "cvss_score": 9.8, "severity": "critical", "fixed_version": null}]}'
    )

    def fail(*args, **kwargs):
        raise AssertionError("network should not be hit when cache is fresh")

    monkeypatch.setattr(client.session, "get", fail)
    cves = client.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
    assert cves[0].cve_id == "CVE-2024-12345"


def test_nvd_lookup_rate_limits(tmp_path, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)
    calls = []

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(client.session, "get", lambda *a, **k: calls.append(1) or FakeResponse())
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("blacklight.cve_matcher.time.sleep", fake_sleep)
    client.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
    client.lookup("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")
    assert len(calls) == 2
    assert len(sleeps) == 1
    assert sleeps[0] >= 6.0


def test_build_findings_skips_unmapped_services(tmp_path):
    client = NvdClient(cache_dir=tmp_path)
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    findings = build_findings(records, client)
    assert findings == []


def test_build_findings_returns_findings(tmp_path, nvd_payload, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return nvd_payload

    monkeypatch.setattr(client.session, "get", lambda *a, **k: FakeResponse())
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    findings = build_findings(records, client)
    assert len(findings) == 2
    assert findings[0].host == "192.168.1.10"
    assert findings[0].port == 22
    assert findings[0].cve_id == "CVE-2024-12345"
    assert findings[0].cpe == "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cve_matcher.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.cve_matcher'`

- [ ] **Step 3: Write the implementation**

`blacklight/cve_matcher.py`:

```python
"""CVE matching via the NVD API 2.0 (CPE-based lookup) with local caching."""

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from blacklight import paths
from blacklight.cpe_map import extract_version, service_to_cpe
from blacklight.scanner import ScanRecord

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_DAYS = 7
KEYED_REQUESTS_PER_SECOND = 50 / 30.0
UNKEYED_REQUESTS_PER_SECOND = 5 / 30.0


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class CVE:
    """A single vulnerability record from NVD."""

    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    fixed_version: str | None


@dataclass
class Finding:
    """A vulnerability matched to a specific host/port/service."""

    host: str
    port: int
    service: str
    version: str
    cpe: str
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    fixed_version: str | None
    epss: float | None = None
    in_kev: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class NvdClient:
    """NVD API client with disk cache and request throttling."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_dir: Path | None = None,
        no_cache: bool = False,
    ):
        self.api_key = api_key
        self.cache_dir = cache_dir or paths.CACHE_DIR
        self.no_cache = no_cache
        self.session = requests.Session()
        rate = KEYED_REQUESTS_PER_SECOND if api_key else UNKEYED_REQUESTS_PER_SECOND
        self._min_interval = 1.0 / rate
        self._last_request = 0.0

    def lookup(self, cpe: str) -> list[CVE]:
        """Return CVEs affecting the given CPE, using cache when possible."""
        cached = self._load_cache(cpe)
        if cached is not None:
            return cached
        cves = self._fetch(cpe)
        self._save_cache(cpe, cves)
        return cves

    def _fetch(self, cpe: str) -> list[CVE]:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = self.session.get(
            NVD_API_URL,
            params={"cpeName": cpe, "resultsPerPage": 100},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 403:
            raise RuntimeError("NVD API returned 403 - check your BLACKLIGHT_NVD_KEY.")
        resp.raise_for_status()
        return [_parse_cve(item) for item in resp.json().get("vulnerabilities", [])]

    def _cache_path(self, cpe: str) -> Path:
        safe = cpe.replace(":", "_").replace("/", "_").replace("*", "star")
        return self.cache_dir / f"nvd_{safe}.json"

    def _load_cache(self, cpe: str) -> list[CVE] | None:
        if self.no_cache:
            return None
        path = self._cache_path(cpe)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(data["fetched_at"])
            if datetime.now(timezone.utc) - fetched > timedelta(days=CACHE_TTL_DAYS):
                return None
            return [CVE(**item) for item in data["cves"]]
        except (ValueError, KeyError, TypeError, OSError):
            return None

    def _save_cache(self, cpe: str, cves: list[CVE]) -> None:
        path = self._cache_path(cpe)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cpe": cpe,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "cves": [asdict(c) for c in cves],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_cve(item: dict) -> CVE:
    cve = item["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    score, base_severity = _extract_cvss(cve.get("metrics", {}))
    return CVE(
        cve_id=cve["id"],
        description=description,
        cvss_score=score,
        severity=(base_severity or "").lower() or severity_from_score(score),
        fixed_version=_extract_fixed_version(cve.get("configurations")),
    )


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        return float(data["baseScore"]), data.get("baseSeverity") or data.get("severity")
    return None, None


def _extract_fixed_version(configurations: dict | None) -> str | None:
    """Best-effort fixed version from NVD configurations.

    Returns the smallest versionEndExcluding (or versionEndIncluding) found.
    """
    if not configurations:
        return None
    excluding: list[str] = []
    including: list[str] = []
    for node in configurations.get("nodes", []):
        for match in node.get("cpeMatch", []):
            if match.get("versionEndExcluding"):
                excluding.append(match["versionEndExcluding"])
            elif match.get("versionEndIncluding"):
                including.append(match["versionEndIncluding"])
    if excluding:
        return min(excluding)
    if including:
        return f"<={min(including)}"
    return None


def build_findings(records: list[ScanRecord], client: NvdClient) -> list[Finding]:
    """Match scan records against CVEs, returning one Finding per CVE hit."""
    findings: list[Finding] = []
    for record in records:
        version = extract_version(record.version)
        cpe = service_to_cpe(record.service, version)
        if cpe is None:
            continue
        for cve in client.lookup(cpe):
            findings.append(
                Finding(
                    host=record.host,
                    port=record.port,
                    service=record.service,
                    version=record.version,
                    cpe=cpe,
                    cve_id=cve.cve_id,
                    description=cve.description,
                    cvss_score=cve.cvss_score,
                    severity=cve.severity,
                    fixed_version=cve.fixed_version,
                )
            )
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cve_matcher.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/cve_matcher.py tests/test_cve_matcher.py tests/fixtures/nvd_cves.json
git commit -m "feat: add NVD CVE matcher with cache and rate limiting"
```

---

### Task 6: Enrichment (EPSS + KEV)

**Files:**
- Create: `blacklight/enrichment.py`
- Create: `tests/test_enrichment.py`

**Interfaces:**
- Consumes: `Finding` (Task 5), `paths.CACHE_DIR` (Task 1).
- Produces: `enrichment.fetch_epss_scores(cve_ids: list[str], cache_dir: Path | None) -> dict[str, float]` (0.0 for CVEs without an EPSS score); `enrichment.load_kev_ids(cache_dir: Path | None, force_refresh: bool = False) -> set[str]` (fresh cache ≤ 24h skips download); `enrichment.enrich_findings(findings: list[Finding], cache_dir: Path | None) -> list[Finding]` (mutates and returns the same list, setting `epss` and `in_kev`).

- [ ] **Step 1: Write the failing test**

`tests/test_enrichment.py`:

```python
import json
from pathlib import Path

from blacklight.cve_matcher import Finding
from blacklight.enrichment import enrich_findings, fetch_epss_scores, load_kev_ids


def _finding(cve_id: str) -> Finding:
    return Finding(
        host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", cve_id=cve_id,
        description="desc", cvss_score=9.8, severity="critical",
        fixed_version=None,
    )


def test_fetch_epss_scores_queries_and_caches(tmp_path, monkeypatch):
    calls = []

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": [
                    {"cve": "CVE-2024-12345", "epss": "0.98765"},
                    {"cve": "CVE-2023-99999", "epss": "0.00123"},
                ]
            }

    monkeypatch.setattr(
        "blacklight.enrichment.requests.get",
        lambda *a, **k: calls.append(k) or FakeResponse(),
    )
    scores = fetch_epss_scores(["CVE-2024-12345", "CVE-2023-99999"], tmp_path)
    assert scores == {"CVE-2024-12345": 0.98765, "CVE-2023-99999": 0.00123}
    assert len(calls) == 1
    assert "cve" in calls[0]["params"]
    assert (tmp_path / "epss.json").exists()


def test_fetch_epss_scores_skips_network_when_cached(tmp_path, monkeypatch):
    (tmp_path / "epss.json").write_text(json.dumps({"CVE-2024-12345": "0.5"}))
    fail = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network hit"))  # noqa: E731
    monkeypatch.setattr("blacklight.enrichment.requests.get", fail)
    assert fetch_epss_scores(["CVE-2024-12345"], tmp_path) == {"CVE-2024-12345": 0.5}


def test_fetch_epss_scores_returns_zero_for_missing(tmp_path, monkeypatch):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": []}

    monkeypatch.setattr("blacklight.enrichment.requests.get", lambda *a, **k: FakeResponse())
    assert fetch_epss_scores(["CVE-2020-0001"], tmp_path) == {"CVE-2020-0001": 0.0}


def test_load_kev_ids_uses_fresh_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "kev.json"
    cache_file.write_text(
        json.dumps(
            {
                "fetched_at": "2030-01-01T00:00:00+00:00",
                "cve_ids": ["CVE-2024-12345"],
            }
        )
    )
    fail = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network hit"))  # noqa: E731
    monkeypatch.setattr("blacklight.enrichment.requests.get", fail)
    assert load_kev_ids(tmp_path) == {"CVE-2024-12345"}


def test_load_kev_ids_refreshes_stale_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "kev.json"
    cache_file.write_text(
        json.dumps(
            {
                "fetched_at": "2000-01-01T00:00:00+00:00",
                "cve_ids": ["CVE-2024-99999"],
            }
        )
    )

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}

    monkeypatch.setattr("blacklight.enrichment.requests.get", lambda *a, **k: FakeResponse())
    assert load_kev_ids(tmp_path) == {"CVE-2024-12345"}


def test_enrich_findings_sets_epss_and_kev(tmp_path, monkeypatch):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"cve": "CVE-2024-12345", "epss": "0.9"}]}

    monkeypatch.setattr("blacklight.enrichment.requests.get", lambda *a, **k: FakeResponse())
    findings = enrich_findings([_finding("CVE-2024-12345"), _finding("CVE-2023-99999")], tmp_path)
    assert findings[0].epss == 0.9
    assert findings[0].in_kev is True
    assert findings[1].epss == 0.0
    assert findings[1].in_kev is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_enrichment.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.enrichment'`

- [ ] **Step 3: Write the implementation**

`blacklight/enrichment.py`:

```python
"""Enrich findings with EPSS exploitation probability and CISA KEV membership."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from blacklight import paths
from blacklight.cve_matcher import Finding

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH_SIZE = 100
EPSS_MAX_AGE = timedelta(days=7)
KEV_MAX_AGE = timedelta(hours=24)


def fetch_epss_scores(cve_ids: list[str], cache_dir: Path | None = None) -> dict[str, float]:
    """Return {cve_id: probability} using the cached score when available.

    CVEs with no EPSS score in the response map to 0.0.
    """
    cache_dir = cache_dir or paths.CACHE_DIR
    cache_file = cache_dir / "epss.json"
    cached: dict[str, float] = {}
    if cache_file.exists():
        try:
            cached = {
                cve_id: float(score)
                for cve_id, score in json.loads(cache_file.read_text(encoding="utf-8")).items()
            }
        except (ValueError, TypeError, OSError):
            cached = {}
    missing = [cve_id for cve_id in cve_ids if cve_id not in cached]
    for start in range(0, len(missing), EPSS_BATCH_SIZE):
        batch = missing[start : start + EPSS_BATCH_SIZE]
        resp = requests.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=30)
        resp.raise_for_status()
        for item in resp.json().get("data", []):
            cached[item["cve"]] = float(item["epss"])
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cached), encoding="utf-8")
    return {cve_id: cached.get(cve_id, 0.0) for cve_id in cve_ids}


def load_kev_ids(cache_dir: Path | None = None, force_refresh: bool = False) -> set[str]:
    """Return the set of CVE IDs in CISA's Known Exploited Vulnerabilities list.

    Downloads the feed when the cache is missing or older than 24 hours.
    """
    cache_dir = cache_dir or paths.CACHE_DIR
    cache_file = cache_dir / "kev.json"
    if not force_refresh and cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(data["fetched_at"])
            if datetime.now(timezone.utc) - fetched <= KEV_MAX_AGE:
                return set(data["cve_ids"])
        except (ValueError, KeyError, TypeError, OSError):
            pass
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    cve_ids = {entry["cveID"] for entry in resp.json().get("vulnerabilities", [])}
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(
            {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "cve_ids": sorted(cve_ids),
            }
        ),
        encoding="utf-8",
    )
    return cve_ids


def enrich_findings(findings: list[Finding], cache_dir: Path | None = None) -> list[Finding]:
    """Set epss and in_kev on each finding; returns the same list."""
    if not findings:
        return findings
    scores = fetch_epss_scores([f.cve_id for f in findings], cache_dir)
    kev_ids = load_kev_ids(cache_dir)
    for finding in findings:
        finding.epss = scores.get(finding.cve_id, 0.0)
        finding.in_kev = finding.cve_id in kev_ids
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_enrichment.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/enrichment.py tests/test_enrichment.py
git commit -m "feat: add EPSS and KEV enrichment"
```

---

### Task 7: Risk Scoring (host risk scores)

**Files:**
- Create: `blacklight/scoring.py`
- Create: `tests/test_scoring.py`

**Interfaces:**
- Consumes: `Finding` (Task 5).
- Produces: `scoring.SEVERITY_WEIGHTS` (dict, exact values in Global Constraints), `scoring.host_risk_score(findings: list[Finding]) -> float` (0-100 per the formula).

- [ ] **Step 1: Write the failing test**

`tests/test_scoring.py`:

```python
from blacklight.cve_matcher import Finding
from blacklight.scoring import SEVERITY_WEIGHTS, host_risk_score


def _finding(severity="low", epss=0.0, in_kev=False) -> Finding:
    return Finding(
        host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", cve_id="CVE-2024-12345",
        description="desc", cvss_score=None, severity=severity,
        fixed_version=None, epss=epss, in_kev=in_kev,
    )


def test_weights_match_spec():
    assert SEVERITY_WEIGHTS == {"critical": 20, "high": 10, "medium": 4, "low": 1, "unknown": 0}


def test_empty_findings_score_zero():
    assert host_risk_score([]) == 0.0


def test_single_low_is_one():
    assert host_risk_score([_finding("low")]) == 1.0


def test_base_caps_at_60():
    findings = [_finding("critical") for _ in range(5)]
    assert host_risk_score(findings) == 60.0


def test_kev_bonus_capped_at_20():
    assert host_risk_score([_finding("high", in_kev=True), _finding("high", in_kev=True)]) == 40.0
    assert host_risk_score([_finding("high", in_kev=True) for _ in range(3)]) == 50.0


def test_epss_bonus_scales_with_max():
    assert host_risk_score([_finding("low", epss=1.0)]) == 11.0
    assert host_risk_score([_finding("low", epss=0.5)]) == 6.0
    assert host_risk_score([_finding("low", epss=0.0)]) == 1.0


def test_total_capped_at_100():
    findings = [
        _finding("critical", epss=1.0, in_kev=True),
        _finding("critical", epss=1.0, in_kev=True),
        _finding("critical", epss=1.0, in_kev=True),
        _finding("critical", epss=1.0, in_kev=True),
    ]
    assert host_risk_score(findings) == 90.0
    assert host_risk_score(findings) <= 100.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.scoring'`

- [ ] **Step 3: Write the implementation**

`blacklight/scoring.py`:

```python
"""Host risk scoring: a transparent 0-100 formula per host."""

from blacklight.cve_matcher import Finding

SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 4,
    "low": 1,
    "unknown": 0,
}
MAX_BASE = 60
KEV_BONUS = 10
MAX_KEV_BONUS = 20
MAX_EPSS_BONUS = 10


def host_risk_score(findings: list[Finding]) -> float:
    """Score a host 0-100 from its findings.

    base = sum of severity weights, capped at MAX_BASE
    + KEV_BONUS per KEV finding, capped at MAX_KEV_BONUS
    + (max EPSS among findings) * MAX_EPSS_BONUS
    total capped at 100.
    """
    base = min(sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings), MAX_BASE)
    kev_count = sum(1 for f in findings if f.in_kev)
    kev_bonus = min(kev_count * KEV_BONUS, MAX_KEV_BONUS)
    epss_values = [f.epss or 0.0 for f in findings]
    epss_bonus = (max(epss_values) if epss_values else 0.0) * MAX_EPSS_BONUS
    return round(min(base + kev_bonus + epss_bonus, 100), 1)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scoring.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/scoring.py tests/test_scoring.py
git commit -m "feat: add host risk scoring"
```

---

### Task 8: Reporter (rich terminal + HTML/Markdown/JSON export)

**Files:**
- Create: `blacklight/reporter.py`
- Create: `blacklight/templates/report.html.j2`
- Create: `blacklight/templates/report.md.j2`
- Create: `tests/test_reporter.py`

**Interfaces:**
- Consumes: `Finding` (Task 5), `host_risk_score` (Task 7), `__version__` (Task 1).
- Produces: `reporter.findings_table(findings: list[Finding]) -> Table` (rich Table, sorted by CVSS desc, severity-styled); `reporter.render_terminal(findings: list[Finding], meta: dict, console: Console | None = None) -> None`; `reporter.host_risk_table(findings: list[Finding]) -> list[dict]` (rows `{host, score, findings}` sorted by score desc); `reporter.export_report(findings: list[Finding], meta: dict, fmt: str, output: Path) -> Path` where fmt is one of `html|markdown|json` (raises ValueError otherwise).

- [ ] **Step 1: Write the failing test**

`tests/test_reporter.py`:

```python
import json

import pytest
from rich.console import Console

from blacklight.cve_matcher import Finding
from blacklight.reporter import export_report, findings_table, host_risk_table, render_terminal

META = {"targets": "192.168.1.10", "hosts_scanned": 1, "services_found": 2,
        "findings_count": 2, "generated": "2030-01-01T00:00:00+00:00"}


def _finding(host="192.168.1.10", cve_id="CVE-2024-12345", severity="critical",
             cvss=9.8, epss=0.9, in_kev=True) -> Finding:
    return Finding(
        host=host, port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", cve_id=cve_id,
        description="Sample <vuln> & description", cvss_score=cvss, severity=severity,
        fixed_version="9.7", epss=epss, in_kev=in_kev,
    )


def test_render_terminal_prints_summary():
    console = Console(record=True)
    render_terminal([_finding()], META, console=console)
    text = console.export_text()
    assert "Summary" in text
    assert "CVE-2024-12345" in text
    assert "critica" in text


def test_findings_table_sorted_by_cvss_desc():
    low = _finding(cve_id="CVE-2023-0001", severity="low", cvss=2.0)
    high = _finding(cve_id="CVE-2023-0002", severity="critical", cvss=10.0)
    rows = findings_table([low, high]).rows
    first = rows[0].cells
    assert "CVE-2023-0002" in first


def test_host_risk_table_sorted_by_score_desc():
    rows = host_risk_table([_finding(host="10.0.0.2"), _finding(host="10.0.0.1")])
    assert rows[0]["host"] == "10.0.0.2"
    assert rows[1]["host"] == "10.0.0.1"


def test_export_json(tmp_path):
    out = export_report([_finding()], META, "json", tmp_path / "report.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["targets"] == "192.168.1.10"
    assert data["findings"][0]["cve_id"] == "CVE-2024-12345"
    assert data["hosts"][0]["score"] > 0


def test_export_html_escapes_and_renders(tmp_path):
    out = export_report([_finding()], META, "html", tmp_path / "report.html")
    html = out.read_text(encoding="utf-8")
    assert "&lt;vuln&gt;" in html
    assert "CVE-2024-12345" in html
    assert "Host risk scores" in html


def test_export_markdown(tmp_path):
    out = export_report([_finding()], META, "markdown", tmp_path / "report.md")
    md = out.read_text(encoding="utf-8")
    assert "| CVE |" in md
    assert "CVE-2024-12345" in md


def test_export_unknown_format_raises(tmp_path):
    with pytest.raises(ValueError):
        export_report([], META, "pdf", tmp_path / "report.pdf")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporter.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.reporter'`

- [ ] **Step 3: Write the implementation**

`blacklight/templates/report.html.j2`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>blacklight-cli scan report</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;margin:2rem auto;max-width:1100px;color:#1a1a1a}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:.9rem;vertical-align:top}
th{background:#f4f4f4}
.critical{background:#fdecea}.high{background:#fff3e0}.medium{background:#fffde7}.low{background:#f5f5f5}
.badge{display:inline-block;background:#d32f2f;color:#fff;border-radius:3px;padding:0 4px;font-size:.75rem}
footer{margin-top:2rem;font-size:.8rem;color:#666}
</style>
</head>
<body>
<h1>blacklight-cli scan report</h1>
<p>Targets: <strong>{{ meta.targets }}</strong> &middot; Hosts scanned: {{ meta.hosts_scanned }}
&middot; Services found: {{ meta.services_found }} &middot; Findings: {{ meta.findings_count }}
&middot; Generated: {{ meta.generated }}</p>

<h2>Host risk scores</h2>
<table>
<tr><th>Host</th><th>Risk score (0-100)</th><th>Findings</th></tr>
{% for host in hosts %}
<tr><td>{{ host.host }}</td><td>{{ host.score }}</td><td>{{ host.findings }}</td></tr>
{% endfor %}
</table>

<h2>Findings</h2>
{% if findings %}
<table>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>CVE</th>
<th>CVSS</th><th>Severity</th><th>EPSS</th><th>KEV</th><th>Description</th></tr>
{% for f in findings %}
<tr class="{{ f.severity }}">
<td>{{ f.host }}</td><td>{{ f.port }}</td><td>{{ f.service }}</td><td>{{ f.version }}</td>
<td><a href="https://nvd.nist.gov/vuln/detail/{{ f.cve_id }}">{{ f.cve_id }}</a></td>
<td>{{ f.cvss_score }}</td><td>{{ f.severity }}</td><td>{{ f.epss }}</td>
<td>{% if f.in_kev %}<span class="badge">KEV</span>{% endif %}</td>
<td>{{ f.description }}{% if f.fixed_version %} <em>(fixed in {{ f.fixed_version }})</em>{% endif %}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No findings.</p>
{% endif %}

<footer>Generated by blacklight-cli. Risk score: severity-weighted base (capped at 60)
+ 10 per KEV finding (capped at 20) + max EPSS &times; 10, capped at 100.
For use only on systems you own or are authorized to test.</footer>
</body>
</html>
```

`blacklight/templates/report.md.j2`:

```markdown
# blacklight-cli scan report

- Targets: {{ meta.targets }}
- Hosts scanned: {{ meta.hosts_scanned }}
- Services found: {{ meta.services_found }}
- Findings: {{ meta.findings_count }}
- Generated: {{ meta.generated }}

## Host risk scores

| Host | Risk score (0-100) | Findings |
|------|--------------------|----------|
{% for host in hosts %}| {{ host.host }} | {{ host.score }} | {{ host.findings }} |
{% endfor %}
## Findings

| Host | Port | Service | Version | CVE | CVSS | Severity | EPSS | KEV | Description |
|------|------|---------|---------|-----|------|----------|------|-----|-------------|
{% for f in findings %}| {{ f.host }} | {{ f.port }} | {{ f.service }} | {{ f.version }} | [{{ f.cve_id }}](https://nvd.nist.gov/vuln/detail/{{ f.cve_id }}) | {{ f.cvss_score }} | {{ f.severity }} | {{ f.epss }} | {% if f.in_kev %}YES{% endif %} | {{ f.description }}{% if f.fixed_version %} (fixed in {{ f.fixed_version }}){% endif %} |
{% endfor %}
```

`blacklight/reporter.py`:

```python
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
            title="blacklight",
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporter.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/reporter.py blacklight/templates/ tests/test_reporter.py
git commit -m "feat: add rich terminal reporter and HTML/Markdown/JSON export"
```

---

### Task 9: CLI Wiring (scan command, permission flow, logging)

**Files:**
- Modify: `blacklight/cli.py` (replace stub)
- Modify: `tests/test_cli.py` (extend)

**Interfaces:**
- Consumes: everything from Tasks 1-8.
- Produces: `cli.app` typer app with `scan` and `version` subcommands; `cli.run_scan(targets: list[str], ports: str, timeout: int, no_cache: bool) -> dict` returning `{"findings": list[Finding], "meta": dict}` with meta keys `targets, hosts_scanned, services_found, findings_count, generated`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
from blacklight.cli import app, run_scan
from blacklight.cve_matcher import Finding
from blacklight.scanner import ScanRecord


def test_scan_blocks_public_target_without_permission(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nmap should not run for blocked targets")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", fail)
    result = runner.invoke(app, ["scan", "8.8.8.8"])
    assert result.exit_code == 1
    assert "Blocked" in result.output


def test_scan_prompts_for_public_target_with_permission(monkeypatch):
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: [])
    monkeypatch.setattr("blacklight.cli.typer.confirm", lambda *a, **k: False)
    result = runner.invoke(app, ["scan", "8.8.8.8", "--i-have-permission"])
    assert result.exit_code == 1
    assert "Aborted" in result.output


def test_scan_end_to_end_private_target(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings", lambda findings, **k: findings)
    result = runner.invoke(app, ["scan", "192.168.1.10", "--ports", "22"])
    assert result.exit_code == 0
    assert "scan report" in result.output
    assert "Hosts scanned: 1" in result.output
    assert (tmp_path / "scan.log").exists()


def test_scan_exports_json_output(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: [])
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "report.json"

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings", lambda findings, **k: findings)
    result = runner.invoke(app, ["scan", "192.168.1.10", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "Report written to" in result.output


def test_run_scan_builds_meta(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    result = run_scan(["192.168.1.10"], "22", 30, False)
    assert result["meta"]["hosts_scanned"] == 1
    assert result["meta"]["services_found"] == 1
    assert result["meta"]["findings_count"] == 0
    assert result["findings"] == []


def test_scan_reports_missing_nmap(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: None)
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    result = runner.invoke(app, ["scan", "192.168.1.10"])
    assert result.exit_code == 1
    assert "nmap not found" in result.output
    assert "apt install nmap" in result.output
```

Note: `run_scan` calls `enrichment.enrich_findings` at the end, which would hit the network — the tests above monkeypatch it to an identity function (or leave findings empty, which short-circuits it).

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL — new tests fail (no `scan` command / wrong behavior); existing `test_version_command` still passes.

- [ ] **Step 3: Rewrite the CLI**

Replace `blacklight/cli.py` entirely:

```python
"""blacklight-cli entry point: scan command with authorization guardrails."""

import os
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import __version__, paths
from blacklight import enrichment, guardrails, scanner
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.reporter import export_report, render_terminal

console = Console()

app = typer.Typer(
    help="blacklight-cli: scan networks for vulnerable services. "
    "For use only on systems you own or are authorized to test."
)


@app.command()
def scan(
    target: list[str] = typer.Argument(..., help="Target host(s) or CIDR(s)."),
    ports: str = typer.Option("1-1024", "--ports", "-p", help="Port range(s) to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export report to a file."),
    fmt: str = typer.Option("html", "--format", help="Export format: html, markdown, json."),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Confirm you are authorized to scan these targets.",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the local NVD/EPSS cache."),
    timeout: int = typer.Option(30, "--timeout", help="Per-host nmap scan timeout in seconds."),
) -> None:
    """Scan targets for vulnerable services and report findings."""
    paths.ensure_dirs()
    verdict = guardrails.verify_targets(list(target), i_have_permission)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} is not a private address. "
                      "Pass --i-have-permission to allow scanning non-private targets.")
    if verdict.needs_confirmation:
        names = ", ".join(verdict.needs_confirmation)
        if not typer.confirm(f"Target(s) {names} are public. "
                             "Are you authorized to scan them?"):
            console.print("[yellow]Aborted.[/]")
            raise typer.Exit(code=1)
    targets = verdict.allowed + verdict.needs_confirmation
    if not targets:
        console.print("[red]No scannable targets.[/]")
        raise typer.Exit(code=1)
    if scanner.find_nmap() is None:
        console.print("[red]nmap not found.[/] Install it with one of:\n"
                      "  apt:   sudo apt install nmap\n"
                      "  brew:  brew install nmap\n"
                      "  choco: choco install nmap")
        raise typer.Exit(code=1)
    if fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        raise typer.Exit(code=1)
    if output is not None and fmt == "html" and output.suffix in (".md", ".json"):
        fmt = "markdown" if output.suffix == ".md" else "json"

    result = run_scan(targets, ports, timeout, no_cache)
    _log_scan(targets, i_have_permission, result["meta"])
    render_terminal(result["findings"], result["meta"])
    if output is not None:
        export_report(result["findings"], result["meta"], fmt, output)
        console.print(f"Report written to [bold]{output}[/]")


@app.command()
def version() -> None:
    """Show the installed version."""
    console.print(f"blacklight-cli {__version__}")


def run_scan(targets: list[str], ports: str, timeout: int, no_cache: bool) -> dict:
    """Run the full pipeline: scan -> CVE match -> enrich -> score metadata."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        progress.add_task("Scanning hosts with nmap...", total=None)
        records = scanner.scan_hosts(targets, ports, timeout)
        phase = progress.add_task("Matching CVEs against NVD...", total=len(records))
        client = NvdClient(api_key=os.environ.get("BLACKLIGHT_NVD_KEY"), no_cache=no_cache)
        findings: list[Finding] = []
        for record in records:
            findings.extend(build_findings([record], client))
            progress.advance(phase)
        progress.add_task("Enriching with EPSS/KEV...", total=None)
        findings = enrichment.enrich_findings(findings)
    hosts_scanned = len({record.host for record in records})
    return {
        "findings": findings,
        "meta": {
            "targets": ", ".join(targets),
            "hosts_scanned": hosts_scanned,
            "services_found": len(records),
            "findings_count": len(findings),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


def _log_scan(targets: list[str], permission: bool, meta: dict) -> None:
    """Append one line per scan to ~/.blacklight/scan.log."""
    line = (
        f"{meta['generated']} target={','.join(targets)} "
        f"permission={permission} hosts={meta['hosts_scanned']} "
        f"services={meta['services_found']} findings={meta['findings_count']}\n"
    )
    with paths.SCAN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (7 passed)

Run full suite: `pytest -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add blacklight/cli.py tests/test_cli.py
git commit -m "feat: wire up scan command with guardrails, logging, and export"
```

---

### Task 10: README, .gitignore, and Sample Report

**Files:**
- Modify: `README.md` (replace stub)
- Create: `.gitignore`
- Create: `examples/make_sample.py`
- Create: `examples/sample_report.html` (generated by make_sample.py)

**Interfaces:**
- Consumes: `export_report` (Task 8), `Finding` (Task 5).

- [ ] **Step 1: Write the generator script**

`examples/make_sample.py`:

```python
"""Generate examples/sample_report.html + .md from sample findings."""

from pathlib import Path

from blacklight.cve_matcher import Finding
from blacklight.reporter import export_report

SAMPLES = [
    Finding(host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
            cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
            cve_id="CVE-2024-6387", description="regreSSHion: remote code execution "
            "in OpenSSH server (signal handler race).", cvss_score=8.1,
            severity="high", fixed_version="9.7p1", epss=0.9999, in_kev=True),
    Finding(host="192.168.1.10", port=80, service="Apache httpd", version="2.4.54",
            cpe="cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
            cve_id="CVE-2023-25690", description="HTTP request smuggling in Apache "
            "httpd mod_proxy.", cvss_score=9.8, severity="critical",
            fixed_version="2.4.56", epss=0.95, in_kev=False),
    Finding(host="192.168.1.11", port=3306, service="MySQL", version="5.7.42",
            cpe="cpe:2.3:a:oracle:mysql:5.7.42:*:*:*:*:*:*:*",
            cve_id="CVE-2023-21912", description="Multiple unspecified "
            "vulnerabilities in MySQL Server.", cvss_score=4.9, severity="medium",
            fixed_version="5.7.43", epss=0.01, in_kev=False),
]

META = {
    "targets": "192.168.1.0/24",
    "hosts_scanned": 2,
    "services_found": 3,
    "findings_count": len(SAMPLES),
    "generated": "2030-01-01T00:00:00+00:00",
}


def main() -> None:
    export_report(SAMPLES, META, "html", Path(__file__).parent / "sample_report.html")
    export_report(SAMPLES, META, "markdown", Path(__file__).parent / "sample_report.md")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it to produce the sample report**

Run: `python examples/make_sample.py`
Expected: creates `examples/sample_report.html` and `examples/sample_report.md`; open the HTML in a browser to eyeball the styling.

- [ ] **Step 3: Write README and .gitignore**

`.gitignore`:

```gitignore
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/
build/
dist/
.pytest_cache/
.blacklight/
```

`README.md`:

```markdown
# blacklight-cli

Local network vulnerability scanner. Runs nmap service/version detection
(`-sV`), matches detected services against the NVD CVE database, overlays
exploitation intelligence (FIRST EPSS + CISA KEV), scores every host
0-100 by risk, and prints a severity-ranked report in the terminal with
optional HTML/Markdown/JSON export.

> **Warning:** use only on systems you own or are explicitly authorized to
> test (e.g. a home lab, Metasploitable VM, or your own infrastructure).
> Scanning networks without authorization may be illegal. Every scan is
> logged to `~/.blacklight/scan.log`.

## Install

Requires **Python 3.11+** and the **nmap** binary (system package):

- Debian/Ubuntu: `sudo apt install nmap`
- macOS: `brew install nmap`
- Windows: `choco install nmap`

Then install the package (recommended: into an isolated environment):

```bash
pipx install blacklight-cli        # isolated env, recommended
# or: pip install blacklight-cli   # into your current env
```

## Usage

```bash
# Scan a private subnet (default-deny: public ranges are blocked
# unless you pass --i-have-permission)
blacklight scan 192.168.1.0/24

# Scan specific ports, export an HTML report
blacklight scan 192.168.1.10 --ports 22,80,443 -o report.html

# Scan a public host you are authorized to test (interactive confirmation)
blacklight scan scanme.nmap.org --i-have-permission

# JSON export for scripting
blacklight scan 192.168.1.0/24 --format json -o scan.json
```

### NVD API key (optional)

A free NVD API key raises the rate limit from 5 to 50 requests per 30
seconds. Set it once: `export BLACKLIGHT_NVD_KEY=your-key`
(Request one at https://nvd.nist.gov/developers/request-an-api-key)

## How it works

1. **Scan** — shells out to `nmap -sV -oX -`, parses host/port/service/version.
2. **Match** — maps each service to a CPE identifier and queries NVD for
   affected CVEs (cached in `~/.blacklight/cache/`, refreshed weekly).
3. **Enrich** — adds FIRST EPSS exploitation probability and a badge for
   CVEs on the CISA Known Exploited Vulnerabilities list (feed refreshed
   daily).
4. **Score** — each host gets a 0-100 risk score:
   severity-weighted base (critical=20, high=10, medium=4, low=1, capped at
   60) + 10 per KEV finding (capped at 20) + max EPSS x 10; total capped at
   100.
5. **Report** — rich terminal table sorted by CVSS, summary panel, and
   HTML/Markdown/JSON export.

## Guardrails

- Only private RFC1918 ranges and loopback are scannable by default.
- Public targets require `--i-have-permission` plus an interactive
  confirmation.
- Every scan is logged with timestamp, target, and outcome to
  `~/.blacklight/scan.log`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
```

- [ ] **Step 4: Verify end to end**

Run: `pytest -v`
Expected: PASS (all tests)

Run: `blacklight version` → `blacklight-cli 0.1.0`
Run: `python examples/make_sample.py` and confirm both sample files regenerate.

- [ ] **Step 5: Commit**

```bash
git add README.md .gitignore examples/
git commit -m "docs: add README, gitignore, and sample report"
```

---

## Self-Review Notes

- **Spec coverage:** milestones 1-9 all mapped to Tasks 1-10 (scan engine=3, guardrails=2, CVE matching=5, enrichment=6, risk scoring=7, rich output=8, export=8, packaging=1, README/demo=10). Stretch goals (PDF, TUI, Docker) intentionally excluded per spec.
- **Type consistency:** `Finding`/`CVE` shapes defined once in Task 5 and referenced verbatim by Tasks 6-9; `host_risk_score` signature fixed in Task 7 and used in Task 8; `ScanRecord` fields fixed in Task 3, consumed by Tasks 5 and 9; `meta` dict keys consistent across Tasks 8-10 (`targets, hosts_scanned, services_found, findings_count, generated`).
- **Testing note:** all network-dependent tests use monkeypatched `requests.get`/sessions or cache files; no live network in CI.
