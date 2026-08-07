from datetime import datetime, timezone

from blacklight.scanner import TlsData
from blacklight.tls import classify

NOW = datetime(2030, 1, 15, tzinfo=timezone.utc)


def _cert_output(**overrides):
    lines = {
        "subject": "Subject: commonName=example.com",
        "issuer": "Issuer: C=US, O=Example Corp",
        "not_before": "Not valid before: 2024-01-01T00:00:00",
        "not_after": "Not valid after:  2031-01-01T00:00:00",
    }
    lines.update(overrides)
    return "\n".join(lines.values())


def _classify(cert="", ciphers="", now=NOW):
    return classify("192.168.1.10", 443, "https",
                    TlsData(ssl_cert_output=cert, ssl_ciphers_output=ciphers),
                    now=now)


def test_expired_cert_is_high():
    findings = _classify(cert=_cert_output(not_after="Not valid after:  2029-12-31T23:59:59"))
    assert len(findings) == 1
    assert findings[0].category == "expiry"
    assert findings[0].severity == "high"
    assert findings[0].cve_id == "TLS-EXPIRED"


def test_expiring_cert_within_window_is_low():
    findings = _classify(cert=_cert_output(not_after="Not valid after:  2030-02-01T00:00:00"))
    assert findings[0].cve_id == "TLS-EXPIRING"
    assert findings[0].severity == "low"
    assert findings[0].evidence.startswith("notAfter")


def test_long_valid_cert_no_expiry_finding():
    assert _classify(cert=_cert_output()) == []


def test_self_signed_cert_is_low():
    findings = _classify(cert=_cert_output(issuer="Issuer: commonName=example.com"))
    assert [f.cve_id for f in findings] == ["TLS-SELF-SIGNED"]
    assert findings[0].severity == "low"


def test_parse_failures_never_crash():
    assert _classify(cert="not a date at all") == []
    assert _classify() == []


def test_space_joined_cert_parses_same_as_newline_joined():
    newline = _cert_output()
    space = " ".join(newline.split("\n"))
    assert _classify(cert=space) == _classify(cert=newline)
    assert _classify(cert=space) == []


def test_space_joined_expired_cert_still_high():
    newline = _cert_output(not_after="Not valid after:  2029-12-31T23:59:59")
    space = " ".join(newline.split("\n"))
    findings = _classify(cert=space)
    assert findings == _classify(cert=newline)
    assert len(findings) == 1
    assert findings[0].category == "expiry"
    assert findings[0].severity == "high"
    assert findings[0].cve_id == "TLS-EXPIRED"


def test_space_joined_self_signed_still_detected():
    newline = _cert_output(issuer="Issuer: commonName=example.com")
    space = " ".join(newline.split("\n"))
    assert _classify(cert=space) == _classify(cert=newline)
    assert [f.cve_id for f in _classify(cert=space)] == ["TLS-SELF-SIGNED"]
