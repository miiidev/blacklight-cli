import pytest

from blacklight.cpe_map import (
    SERVICE_CPE,
    cpe_to_match_string,
    extract_version,
    normalize_cpe,
    service_to_cpe,
)


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


def test_php_maps_to_php():
    assert "cpe:2.3:a:php:php:7.4.33:*:*:*:*:*:*:*" in (
        service_to_cpe("php", "7.4.33")
    )


def test_cpe_to_match_string_known_version():
    assert cpe_to_match_string("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*") == (
        "cpe:2.3:a:openbsd:openssh:9.6"
    )


def test_cpe_to_match_string_unknown_version_drops_wildcards():
    assert cpe_to_match_string("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*") == (
        "cpe:2.3:a:oracle:mysql"
    )


def test_normalize_cpe_uri_binding_full_count():
    assert normalize_cpe("cpe:/a:nginx:nginx:1.24.0") == (
        "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    )


def test_normalize_cpe_uri_binding_fills_missing_version():
    assert normalize_cpe("cpe:/a:nginx:nginx", version="1.24.0") == (
        "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    )


def test_normalize_cpe_2_3_passthrough():
    assert normalize_cpe("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*") == (
        "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    )


def test_normalize_cpe_keeps_wildcard_version_without_version_arg():
    assert normalize_cpe("cpe:/a:nginx:nginx") == (
        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    )


def test_normalize_cpe_rejects_non_cpe():
    assert normalize_cpe("not-a-cpe") is None
    assert normalize_cpe("cpe://broken") is None
    assert normalize_cpe("cpe:/x:foo:bar") is None
