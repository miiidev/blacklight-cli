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
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise ValueError("nmap output is not valid XML")
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
