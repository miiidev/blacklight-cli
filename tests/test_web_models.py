from blacklight.web.models import WebFinding


def test_web_finding_defaults():
    f = WebFinding(url="http://example.com/", category="security_header",
                   detail="Missing X-Frame-Options", severity="low", evidence="")
    assert f.cve_id == ""
    assert f.epss is None
    assert f.in_kev is False


def test_web_finding_to_dict():
    f = WebFinding(url="http://example.com/", category="sqli",
                   detail="SQL error", severity="high", evidence="SQL syntax",
                   cve_id="CVE-2024-0001", epss=0.95, in_kev=True)
    d = f.to_dict()
    assert d["type"] == "web"
    assert d["cve_id"] == "CVE-2024-0001"
    assert d["epss"] == 0.95
    assert d["in_kev"] is True
    assert d["url"] == "http://example.com/"
