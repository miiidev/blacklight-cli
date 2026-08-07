"""TLS port classification: cert expiry, legacy protocols, weak ciphers.

Pure module: takes the parsed nmap script output (scanner.TlsData) and returns
TlsFinding objects. No I/O, no network.
"""

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from blacklight.scanner import TlsData

EXPIRY_WINDOW_DAYS = 30

_NOT_AFTER_RE = re.compile(
    r"(?i)(?:not\s*valid\s*after|notafter)\s*[:=]\s*"
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]?[0-9:]*[+Z]?)"
)
_FIELD_RE = re.compile(
    r"(?i)(?:^|(?<=\s))(?P<key>subject|issuer)\s*[:=]\s*(?P<value>.*?)"
    r"(?=(?:\s+(?:subject|issuer|not\s+valid\s+before|not\s+valid\s+after|"
    r"notafter)\s*[:=])|$)"
)
_CN_RE = re.compile(r"(?i)commonname\s*=\s*([^/,;]+)")


@dataclass
class TlsFinding:
    host: str
    port: int
    service: str
    category: str
    detail: str
    evidence: str
    severity: str
    cve_id: str
    epss: float | None = None
    in_kev: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _common_name(value: str) -> str:
    match = _CN_RE.search(value or "")
    return (match.group(1) if match else value or "").strip().lower()


def _parse_not_after(output: str) -> datetime | None:
    match = _NOT_AFTER_RE.search(output or "")
    if not match:
        return None
    try:
        dt = datetime.fromisoformat(match.group(1).strip())
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_subject_issuer(output: str) -> tuple[str | None, str | None]:
    text = re.sub(r"\s+", " ", output or "").strip()
    subject = issuer = None
    for match in _FIELD_RE.finditer(text):
        key = match.group("key").lower()
        value = match.group("value").strip()
        if key == "subject" and subject is None:
            subject = value
        elif key == "issuer" and issuer is None:
            issuer = value
    return subject, issuer


def _cert_findings(host, port, service, cert_output, now) -> list["TlsFinding"]:
    findings: list[TlsFinding] = []
    not_after = _parse_not_after(cert_output)
    if not_after is not None:
        days_left = (not_after - now).days
        evidence = f"notAfter {not_after.date().isoformat()}"
        if days_left < 0:
            findings.append(TlsFinding(
                host, port, service, "expiry",
                f"Certificate expired on {not_after.date().isoformat()}",
                evidence, "high", "TLS-EXPIRED"))
        elif days_left <= EXPIRY_WINDOW_DAYS:
            findings.append(TlsFinding(
                host, port, service, "expiry",
                f"Certificate expires within {EXPIRY_WINDOW_DAYS} days",
                evidence, "low", "TLS-EXPIRING"))
    subject, issuer = _parse_subject_issuer(cert_output)
    if subject and issuer and _common_name(subject) == _common_name(issuer):
        findings.append(TlsFinding(
            host, port, service, "self-signed",
            "Certificate is self-signed",
            f"subject {subject}",
            "low", "TLS-SELF-SIGNED"))
    return findings


def classify(host: str, port: int, service: str, tls: TlsData,
             now: datetime | None = None) -> list[TlsFinding]:
    """Produce TLS findings for one host:port from raw nmap script output."""
    now = now or datetime.now(timezone.utc)
    return _cert_findings(host, port, service, tls.ssl_cert_output, now)
