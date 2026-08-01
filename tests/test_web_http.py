import requests

from blacklight.web.http import Page, ProbeResult, fetch_page, probe


def test_page_header_is_case_insensitive():
    page = Page(url="http://example.com/", status=200,
                headers={"X-Frame-Options": "DENY", "Server": "Apache"}, text="")
    assert page.header("x-frame-options") == "DENY"
    assert page.header("SERVER") == "Apache"
    assert page.header("Missing") is None


def test_fetch_page_parses_response(monkeypatch):
    class FakeResp:
        url = "http://example.com/"
        status_code = 200
        headers = {"Server": "Apache/2.4.49"}
        text = "<html>hi</html>"

        def raise_for_status(self):
            pass

    monkeypatch.setattr("blacklight.web.http.requests.get",
                        lambda *a, **k: FakeResp())
    page = fetch_page("http://example.com/")
    assert page.status == 200
    assert page.text == "<html>hi</html>"
    assert page.header("server") == "Apache/2.4.49"


def test_probe_passes_params(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200
        text = "hello"

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        return FakeResp()

    monkeypatch.setattr("blacklight.web.http.requests.get", fake_get)
    result = probe("http://example.com/search", params={"q": "x"})
    assert isinstance(result, ProbeResult)
    assert result.status == 200
    assert result.text == "hello"
    assert captured["url"] == "http://example.com/search"
    assert captured["params"] == {"q": "x"}


def test_fetch_page_raises_on_http_error(monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            raise requests.HTTPError("404")

    monkeypatch.setattr("blacklight.web.http.requests.get",
                        lambda *a, **k: FakeResp())
    try:
        fetch_page("http://example.com/missing")
    except requests.HTTPError:
        return
    raise AssertionError("expected HTTPError")
