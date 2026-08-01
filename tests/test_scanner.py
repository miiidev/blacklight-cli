import pytest

from blacklight.scanner import ScanRecord, parse_nmap_xml


def test_parse_nmap_xml_skips_closed_ports(nmap_xml):
    records = parse_nmap_xml(nmap_xml)
    assert records == [
        ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1"),
        ScanRecord(host="192.168.1.10", port=443, protocol="tcp", service="nginx", version="1.24.0"),
        ScanRecord(host="192.168.1.10", port=3306, protocol="tcp", service="mysql", version=""),
        ScanRecord(host="192.168.1.11", port=8080, protocol="tcp", service="Apache httpd", version="2.4.58"),
    ]


def test_parse_nmap_xml_empty_scan():
    assert parse_nmap_xml("<nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/><ports/></host></nmaprun>") == []


def test_parse_nmap_xml_rejects_non_xml():
    with pytest.raises(ValueError):
        parse_nmap_xml("not xml at all")
