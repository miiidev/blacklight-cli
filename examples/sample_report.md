# blacklight-cli scan report

- Targets: 192.168.1.0/24
- Hosts scanned: 2
- Services found: 3
- Findings: 3
- Generated: 2030-01-01T00:00:00+00:00

## Host risk scores

| Host | Risk score (0-100) | Findings |
|------|--------------------|----------|
| 192.168.1.10 | 50.0 | 2 |
| 192.168.1.11 | 4.1 | 1 |

## Findings

| Host | Port | Service | Version | CVE | CVSS | Severity | EPSS | KEV | Description |
|------|------|---------|---------|-----|------|----------|------|-----|-------------|
| 192.168.1.10 | 22 | OpenSSH | 9.6p1 | [CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387) | 8.1 | high | 0.9999 | YES | regreSSHion: remote code execution in OpenSSH server (signal handler race). (fixed in 9.7p1) |
| 192.168.1.10 | 80 | Apache httpd | 2.4.54 | [CVE-2023-25690](https://nvd.nist.gov/vuln/detail/CVE-2023-25690) | 9.8 | critical | 0.95 |  | HTTP request smuggling in Apache httpd mod_proxy. (fixed in 2.4.56) |
| 192.168.1.11 | 3306 | MySQL | 5.7.42 | [CVE-2023-21912](https://nvd.nist.gov/vuln/detail/CVE-2023-21912) | 4.9 | medium | 0.01 |  | Multiple unspecified vulnerabilities in MySQL Server. (fixed in 5.7.43) |
