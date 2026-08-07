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


_HEADER_RE = re.compile(r"(SSLv3|TLSv1\.\d):")
_CIPHER_RE = re.compile(r"\b(?:TLS|SSL|ADH|AECDH)_[A-Z0-9_]+")


def _cipher_sections(output: str) -> dict[str, set[str]]:
    text = output or ""
    matches = [
        (m.start(), "h", m.group(1)) for m in _HEADER_RE.finditer(text)
    ] + [
        (m.start(), "c", m.group(0)) for m in _CIPHER_RE.finditer(text)
    ]
    sections: dict[str, set[str]] = {}
    current: str | None = None
    for _, kind, value in sorted(matches):
        if kind == "h":
            current = value
            sections.setdefault(current, set())
        elif current is not None:
            sections[current].add(value)
    return sections


def _protocol_findings(host, port, service, ciphers_output) -> list[TlsFinding]:
    sections = _cipher_sections(ciphers_output)
    if not sections:
        return []
    findings: list[TlsFinding] = []
    legacy = [
        ("SSLv3", "TLS-PROTO-SSLV3", "high"),
        ("TLSv1.0", "TLS-PROTO-TLSV1.0", "medium"),
        ("TLSv1.1", "TLS-PROTO-TLSV1.1", "low"),
    ]
    for name, cve_id, severity in legacy:
        if name in sections:
            findings.append(TlsFinding(
                host, port, service, "protocol",
                f"supports {name}", name, severity, cve_id))
    if not {"TLSv1.2", "TLSv1.3"} & set(sections):
        findings.append(TlsFinding(
            host, port, service, "protocol",
            "Does not offer TLS 1.2 or TLS 1.3",
            ", ".join(sorted(sections)), "high", "TLS-PROTO-NO-MODERN"))
    return findings


def _cipher_findings(host, port, service, ciphers_output) -> list[TlsFinding]:
    ciphers: set[str] = set()
    for section in _cipher_sections(ciphers_output).values():
        ciphers |= section
    if not ciphers:
        return []
    findings: list[TlsFinding] = []
    anon = [c for c in ciphers if "NULL" in c or "EXPORT" in c
            or c.startswith(("ADH_", "AECDH_")) or "_ANON_" in c]
    weak = [c for c in ciphers if "RC4" in c or ("_DES_" in c and "3DES" not in c)]
    if anon:
        findings.append(TlsFinding(
            host, port, service, "weak-cipher",
            "Supports NULL/EXPORT/anonymous ciphers",
            ", ".join(sorted(anon)[:5]), "high", "TLS-CIPHER-ANON"))
    if weak:
        findings.append(TlsFinding(
            host, port, service, "weak-cipher",
            "Supports RC4 or single-DES ciphers",
            ", ".join(sorted(weak)), "medium", "TLS-CIPHER-WEAK"))
    return findings


def classify(host: str, port: int, service: str, tls: TlsData,
             now: datetime | None = None) -> list[TlsFinding]:
    """Produce all TLS findings for one host:port from nmap script output."""
    now = now or datetime.now(timezone.utc)
    findings: list[TlsFinding] = []
    findings.extend(_cert_findings(host, port, service, tls.ssl_cert_output, now))
    findings.extend(_protocol_findings(host, port, service, tls.ssl_ciphers_output))
    findings.extend(_cipher_findings(host, port, service, tls.ssl_ciphers_output))
    return findings
