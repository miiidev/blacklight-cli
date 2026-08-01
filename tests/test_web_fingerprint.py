from blacklight.web.fingerprint import Fingerprint, fingerprint_page
from blacklight.web.http import Page


def _page(headers=None, text=""):
    return Page(url="https://example.com/", status=200, headers=headers or {}, text=text)


def test_apache_server_header():
    fps = fingerprint_page(_page(headers={"Server": "Apache/2.4.49 (Ubuntu)"}))
    assert Fingerprint("apache httpd", "2.4.49") in fps


def test_nginx_server_header():
    fps = fingerprint_page(_page(headers={"Server": "nginx/1.18.0"}))
    assert Fingerprint("nginx", "1.18.0") in fps


def test_iis_server_header():
    fps = fingerprint_page(_page(headers={"Server": "Microsoft-IIS/10.0"}))
    assert Fingerprint("iis", "10.0") in fps


def test_php_powered_by():
    fps = fingerprint_page(_page(headers={"X-Powered-By": "PHP/7.4.33"}))
    assert Fingerprint("php", "7.4.33") in fps


def test_unknown_server_skipped():
    fps = fingerprint_page(_page(headers={"Server": "Cowboy"}))
    assert all(f.service != "cowboy" for f in fps)


def test_wordpress_marker():
    text = '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/x.css">'
    fps = fingerprint_page(_page(text=text))
    assert Fingerprint("wordpress", "6.4.2") in fps


def test_phpmyadmin_marker():
    fps = fingerprint_page(_page(text="phpMyAdmin 5.2.1 - Documentation"))
    assert Fingerprint("phpmyadmin", "5.2.1") in fps


def test_no_markers_no_fingerprints():
    assert fingerprint_page(_page(text="just a page")) == []


def test_server_without_version_has_empty_version():
    fps = fingerprint_page(_page(headers={"Server": "Apache"}))
    assert Fingerprint("apache httpd", "") in fps
