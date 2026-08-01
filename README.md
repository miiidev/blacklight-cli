# blacklight-cli

Local network vulnerability scanner. Runs nmap service/version detection
(`-sV`), matches detected services against the NVD CVE database, overlays
exploitation intelligence (FIRST EPSS + CISA KEV), scores every host
0-100 by risk, and prints a severity-ranked report in the terminal with
optional HTML/Markdown/JSON export.

> **Warning:** use only on systems you own or are explicitly authorized to
> test (e.g. a home lab, Metasploitable VM, or your own infrastructure).
> Scanning networks without authorization may be illegal. Every scan is
> logged to `~/.blacklight/scan.log`.

## Install

Requires **Python 3.11+** and the **nmap** binary (system package):

- Debian/Ubuntu: `sudo apt install nmap`
- macOS: `brew install nmap`
- Windows: `choco install nmap`

Then install the package (recommended: into an isolated environment):

```bash
pipx install blacklight-cli        # isolated env, recommended
# or: pip install blacklight-cli   # into your current env
```

## Usage

```bash
# Scan a private subnet (default-deny: public ranges are blocked
# unless you pass --i-have-permission)
blacklight scan 192.168.1.0/24

# Scan specific ports, export an HTML report
blacklight scan 192.168.1.10 --ports 22,80,443 -o report.html

# Scan a public host you are authorized to test (interactive confirmation)
blacklight scan scanme.nmap.org --i-have-permission

# JSON export for scripting
blacklight scan 192.168.1.0/24 --format json -o scan.json
```

### NVD API key (optional)

A free NVD API key raises the rate limit from 5 to 50 requests per 30
seconds. Set it once: `export BLACKLIGHT_NVD_KEY=your-key`
(Request one at https://nvd.nist.gov/developers/request-an-api-key)

## How it works

1. **Scan** — shells out to `nmap -sV -oX -`, parses host/port/service/version.
2. **Match** — maps each service to a CPE identifier and queries NVD for
   affected CVEs (cached in `~/.blacklight/cache/`, refreshed weekly).
3. **Enrich** — adds FIRST EPSS exploitation probability and a badge for
   CVEs on the CISA Known Exploited Vulnerabilities list (feed refreshed
   daily).
4. **Score** — each host gets a 0-100 risk score:
   severity-weighted base (critical=20, high=10, medium=4, low=1, capped at
   60) + 10 per KEV finding (capped at 20) + max EPSS x 10; total capped at
   100.
5. **Report** — rich terminal table sorted by CVSS, summary panel, and
   HTML/Markdown/JSON export.

## Guardrails

- Only private RFC1918 ranges and loopback are scannable by default.
- Public targets require `--i-have-permission` plus an interactive
  confirmation.
- Every scan is logged with timestamp, target, and outcome to
  `~/.blacklight/scan.log`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
