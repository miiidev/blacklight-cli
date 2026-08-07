import pytest

from blacklight.scanner import ScanRecord, TlsData, parse_nmap_xml


def test_parse_nmap_xml_skips_closed_ports(nmap_xml):
    records = parse_nmap_xml(nmap_xml)
    assert records == [
        ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH",
                   version="9.6p1", cpe="cpe:/a:openbsd:openssh:9.6p1"),
        ScanRecord(host="192.168.1.10", port=443, protocol="tcp", service="nginx",
                   version="1.24.0", cpe="cpe:/a:nginx:nginx:1.24.0",
                   tls=TlsData(
                       ssl_cert_output=(
                           "Subject: commonName=localhost.localdomain\n"
                           "Issuer: commonName=localhost.localdomain\n"
                           "Not valid before: 2024-01-01T00:00:00\n"
                           "Not valid after:  2034-01-01T00:00:00\n"
                       ),
                       ssl_ciphers_output=(
                           "TLSv1.2:\n"
                           "  compressors:\n"
                           "    NULL\n"
                           "  cipher preference: server\n"
                           "  cipher suites:\n"
                           "    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A\n"
                       ),
                   )),
        ScanRecord(host="192.168.1.10", port=3306, protocol="tcp", service="mysql", version=""),
        ScanRecord(host="192.168.1.11", port=8080, protocol="tcp", service="Apache httpd", version="2.4.58"),
    ]


def test_scripts_only_populate_tls_ports(nmap_xml):
    by_port = {r.port: r for r in parse_nmap_xml(nmap_xml)}
    assert by_port[443].tls is not None
    assert by_port[22].tls is None
    assert by_port[3306].tls is None


def test_parse_nmap_xml_empty_scan():
    assert parse_nmap_xml("<nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/><ports/></host></nmaprun>") == []


def test_parse_nmap_xml_rejects_non_xml():
    with pytest.raises(ValueError):
        parse_nmap_xml("not xml at all")
