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


CIPHER_OUTPUT_LEGACY = """SSLv3:
  cipher suites:
    TLS_RSA_WITH_NULL_SHA (rsa 2048) - C
TLSv1.0:
  cipher suites:
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (secp256r1) - C
TLSv1.1:
  cipher suites:
    TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
"""


def test_legacy_protocols_and_weak_ciphers():
    findings = _classify(ciphers=CIPHER_OUTPUT_LEGACY)
    ids = {f.cve_id for f in findings}
    assert {"TLS-PROTO-SSLV3", "TLS-PROTO-TLSV1.0", "TLS-PROTO-TLSV1.1",
            "TLS-PROTO-NO-MODERN", "TLS-CIPHER-ANON", "TLS-CIPHER-WEAK"} <= ids
    by_id = {f.cve_id: f.severity for f in findings}
    assert by_id["TLS-PROTO-SSLV3"] == "high"
    assert by_id["TLS-PROTO-TLSV1.0"] == "medium"


def test_modern_only_no_protocol_findings():
    modern = """TLSv1.2:
  cipher suites:
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
"""
    assert _classify(ciphers=modern) == []


def test_anon_cipher_and_no_modern_tls():
    output = """TLSv1.0:
  cipher suites:
    ADH_AES_128_GCM_SHA256 (rsa 2048) - C
"""
    findings = _classify(ciphers=output)
    ids = {f.cve_id for f in findings}
    assert "TLS-PROTO-NO-MODERN" in ids
    assert "TLS-CIPHER-ANON" in ids


def test_space_joined_cipher_output_matches_newline_joined():
    space = " ".join(CIPHER_OUTPUT_LEGACY.split("\n"))
    assert sorted(f.cve_id for f in _classify(ciphers=space)) == \
        sorted(f.cve_id for f in _classify(ciphers=CIPHER_OUTPUT_LEGACY))
