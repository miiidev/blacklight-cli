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


def normalize_cpe(cpe: str, version: str | None = None) -> str | None:
    """Convert an nmap CPE string (URI or 2.3 binding) to the NVD cpe:2.3 form.

    nmap emits either the legacy URI binding ("cpe:/a:apache:http_server:2.4.58")
    or a full "cpe:2.3:" binding. Both are normalized to the 13-component
    cpe:2.3 form padded with "*". When the CPE has no version and a raw version
    string is passed, the first dotted numeric run is spliced in. Returns None
    for anything that is not a CPE binding.
    """
    value = cpe.strip()
    if not value.startswith("cpe:"):
        return None
    rest = value[4:]
    if rest.startswith("/"):
        parts = rest[1:].split(":")
    elif rest.startswith("2.3:"):
        parts = rest[4:].split(":")
    else:
        return None
    if not parts or parts[0] not in ("a", "o", "h"):
        return None
    padded = (parts + ["*"] * 11)[:11]
    if padded[3] == "*" and version:
        extracted = extract_version(version)
        if extracted:
            padded[3] = extracted
    return "cpe:2.3:" + ":".join(padded)
