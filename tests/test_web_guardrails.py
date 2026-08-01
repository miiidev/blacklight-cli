from blacklight.guardrails import normalize_web_url, resolve_hostname, verify_web_target


def test_normalize_web_url_adds_https():
    assert normalize_web_url("example.com") == "https://example.com"
    assert normalize_web_url("http://example.com") == "http://example.com"
    assert normalize_web_url("https://example.com:8080") == "https://example.com:8080"


def test_resolve_hostname_returns_ipv4(monkeypatch):
    fake = [("AF_INET", 1, 6, "", ("192.168.1.10", 0)),
            ("AF_INET6", 10, 6, "", ("::1", 0, 0, 0))]
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: fake)
    assert resolve_hostname("myhost") == "192.168.1.10"


def test_resolve_hostname_returns_none_on_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("name or service not known")

    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo", boom)
    assert resolve_hostname("does-not-exist.invalid") is None


def test_verify_web_target_private_allowed(monkeypatch):
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("127.0.0.1", 0))])
    verdict = verify_web_target("http://127.0.0.1:8080", False)
    assert verdict.allowed == ["http://127.0.0.1:8080"]
    assert verdict.needs_confirmation == []
    assert verdict.blocked == []


def test_verify_web_target_public_without_permission_blocked(monkeypatch):
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("8.8.8.8", 0))])
    verdict = verify_web_target("https://example.com", False)
    assert verdict.blocked == ["https://example.com"]
    assert verdict.allowed == []


def test_verify_web_target_public_with_permission_needs_confirmation(monkeypatch):
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("8.8.8.8", 0))])
    verdict = verify_web_target("https://example.com", True)
    assert verdict.needs_confirmation == ["https://example.com"]


def test_verify_web_target_rejects_bad_scheme():
    verdict = verify_web_target("ftp://example.com", True)
    assert verdict.blocked == ["ftp://example.com"]


def test_verify_web_target_rejects_unresolvable(monkeypatch):
    def boom(*a, **k):
        raise OSError("no such host")

    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo", boom)
    verdict = verify_web_target("https://does-not-exist.invalid", True)
    assert verdict.blocked == ["https://does-not-exist.invalid"]
