"""Map nmap service names to NVD CPE vendor:product identifiers."""

import re

# nmap service name (lowercase, product preferred) -> (CPE vendor, CPE product)
SERVICE_CPE: dict[str, tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "php": ("php", "php"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "memcached": ("memcached", "memcached"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "iis": ("microsoft", "internet_information_server"),
    "microsoft-httpd": ("microsoft", "httpd"),
    "opensmtpd": ("openbsd", "opensmtpd"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "unbound": ("nlnetlabs", "unbound"),
    "openvpn": ("openvpn", "openvpn"),
    "openssl": ("openssl", "openssl"),
    "samba": ("samba", "samba"),
    "samba smbd": ("samba", "samba"),
    "isc-dhcp-server": ("isc", "dhcp"),
    "snmp": ("net-snmp", "net-snmp"),
    "ntp": ("ntp", "ntp"),
    "openldap": ("openldap", "openldap"),
    "slapd": ("openldap", "openldap"),
    "zabbix": ("zabbix", "zabbix"),
    "grafana": ("grafana", "grafana"),
    "prometheus": ("prometheus", "prometheus"),
    "jenkins": ("cloudbees", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "haproxy": ("haproxy", "haproxy"),
    "squid": ("squid-cache", "squid"),
    "varnish": ("varnish-cache", "varnish"),
    "cups": ("apple", "cups"),
    "apache-couchdb": ("apache", "couchdb"),
    "couchdb": ("apache", "couchdb"),
    "h2 database": ("h2database", "h2"),
    "docker": ("docker", "docker"),
    "docker registry": ("docker", "distribution"),
    "kubernetes": ("kubernetes", "kubernetes"),
}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def extract_version(version: str) -> str | None:
    """Pull the first dotted numeric run out of a version string.

    Examples: "9.6p1" -> "9.6", "2.4.58-1ubuntu" -> "2.4.58", "" -> None.
    """
    match = _VERSION_RE.search(version)
    return match.group(1) if match else None


def service_to_cpe(service: str, version: str | None) -> str | None:
    """Build a CPE 2.3 URI for a service name + version, or None if unmapped."""
    key = service.strip().lower()
    pair = SERVICE_CPE.get(key)
    if pair is None:
        return None
    vendor, product = pair
    ver = version or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def cpe_to_match_string(cpe: str) -> str:
    """Reduce a CPE 2.3 URI to a CPE match string for NVD's API.

    NVD's cpeName parameter rejects wildcards in the version component;
    virtualMatchString accepts match strings with missing/wildcarded
    components. A concrete version is kept for precision.
    """
    parts = cpe.split(":")
    if len(parts) < 6 or parts[5] == "*":
        return ":".join(parts[:5])
    return ":".join(parts[:6])
