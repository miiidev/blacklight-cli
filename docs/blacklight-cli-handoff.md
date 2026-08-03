# blacklight-cli — Review & Roadmap Handoff

**Repo:** [github.com/miiidev/blacklight-cli](https://github.com/miiidev/blacklight-cli)
**Date:** 2026-08-03

---

## 1. What the tool does today

`blacklight-cli` is a local network vulnerability scanner (Python 3.11+, MIT license).

**Pipeline:**
1. **Scan** — shells out to `nmap -sV -oX -`, parses host/port/service/version.
2. **Match** — maps each service to a CPE identifier (`cpe_map.py`) and queries the NVD CVE database, cached in `~/.blacklight/cache/` and refreshed weekly.
3. **Enrich** — adds FIRST EPSS exploitation probability and a CISA KEV (Known Exploited Vulnerabilities) badge, refreshed daily.
4. **Score** — each host gets a 0–100 risk score: severity-weighted base (capped 60) + KEV bonus (capped 20) + max EPSS × 10, capped at 100.
5. **Report** — terminal table + optional HTML/Markdown/JSON export.

There's also a `blacklight web` subcommand: passive web-app scanning (missing security headers, exposed files like `.env`/`.git/config`, directory listing, error-based SQLi/XSS/command-injection probes, tech fingerprinting fed through the same CVE pipeline).

**Guardrails already in place** (in `guardrails.py`):
- Only private RFC1918 ranges + loopback are scannable by default.
- Public targets require `--i-have-permission` plus an interactive confirmation prompt.
- Every scan is logged (timestamp, target, outcome) to `~/.blacklight/scan.log`.

**Module map:**
| File | Responsibility |
|---|---|
| `cli.py` | Typer entry point — `scan` and `web` commands |
| `scanner.py` | nmap invocation/parsing |
| `cve_matcher.py` | NVD lookups, `Finding` model |
| `enrichment.py` | EPSS + KEV enrichment, caching |
| `scoring.py` | 0–100 host/web risk scoring |
| `cpe_map.py` | service-name → CPE vendor/product dict |
| `guardrails.py` | private/public target validation |
| `reporter.py` | terminal + HTML/Markdown/JSON export |
| `theme.py` | banner, gradient text, severity styles, risk gauge |

---

## 2. Banner bug — root cause + fix

**Problem:** the ASCII banner in `theme.py` doesn't spell "BLACKLIGHT." The block-letter rows have inconsistent lengths, so columns don't align into recognizable glyphs.

**Original (broken):**
```python
BANNER = """\
         ▄▄▄▄▄▄▄▄▄▄
        ▐████████████▌
        ▐█ ▄▄█▀▀█▄▄ █▌
         ▀▀▀▀▀▀▀▀▀▀▀▀
███ █    █   ██ █ █ █   ███  ██ █ █ ███
█ █ █  █ █ █   █ █ █ █    █ █   █ █ █ █  █
███ █  ███ █   ██  █    █  █ ██ ███  █
█ █ █  █ █ █   █ █ █ █    █  █ █ █ █  █
███ ███ █ █  ██ █ █ ███ ███  ██ █ █  █
       scan · find · illuminate"""
```

**Fix:** rebuilt the wordmark with a consistent 3-wide × 5-tall block font, one glyph per letter, single-space gutters:
```
██  █    █   ██ █ █ █   ███  ██ █ █ ███ 
█ █ █   █ █ █   ██  █    █  █   █ █  █  
██  █   ███ █   █   █    █  █ █ ███  █  
█ █ █   █ █ █   ██  █    █  █ █ █ █  █  
██  ███ █ █  ██ █ █ ███ ███  ██ █ █  █  
```
Spells **B L A C K L I G H T** cleanly. Torch icon and tagline above/below are unchanged; only the wordmark block needs replacing in `theme.py`. Renders through the existing `gradient_text()` / `print_banner()` styling with no other changes needed.

**Status:** proposed, not yet committed. Straightforward drop-in replacement of the `BANNER` string.

---

## 3. Proposed: interactive console mode (Metasploit-style)

**Motivation:** today, every invocation is a one-shot CLI command (`blacklight scan ...` / `blacklight web ...`). The ask is a `msfconsole`-style flow: launch once, `use` a module, `set` options, `run`, stay in an interactive session.

### Mockup session
```
$ blacklight

██  █    █   ██ █ █ █   ███  ██ █ █ ███
█ █ █   █ █ █   ██  █    █  █   █ █  █
██  █   ███ █   █   █    █  █ █ ███  █
█ █ █   █ █ █   ██  █    █  █ █ █ █  █
██  ███ █ █  ██ █ █ ███ ███  ██ █ █  █
       scan · find · illuminate

blacklight-cli v0.3.0 — 2 modules loaded (scan, web)
Type 'help' for commands, 'modules' to list scan types.

blacklight > modules

  Name    Description
  ----    -----------
  scan    nmap service/version scan → CVE + EPSS + KEV risk report
  web     Passive web app misconfig / injection probe

blacklight > use scan
blacklight (scan) > show options

  Option        Current Setting   Required  Description
  ------        ---------------   --------  -----------
  TARGET                          yes       Host(s) or CIDR(s)
  PORTS         1-1024            no        Port range(s)
  OUTPUT                          no        Report export path
  FORMAT        html              no        html, markdown, json
  NO_CACHE      false             no        Bypass NVD/EPSS cache
  TIMEOUT       30                no        Per-host scan timeout (s)

blacklight (scan) > set TARGET 192.168.1.0/24
TARGET => 192.168.1.0/24

blacklight (scan) > set PORTS 22,80,443
PORTS => 22,80,443

blacklight (scan) > run

[private range — no confirmation needed]
Scanning 192.168.1.0/24 on ports 22,80,443 ...
⠋ Fingerprinting services...  ████████████████░░░░  82%

blacklight (scan) > back
blacklight > use web
blacklight (web) > set TARGET https://example.com
TARGET => https://example.com

blacklight (web) > run

Public target — blacklight (web) > set TARGET requires authorization.
Confirm you are authorized to test https://example.com? [y/N]:
```

### Mapping to existing code
| msf-style concept | blacklight equivalent |
|---|---|
| `modules` | lists `scan` and `web` — same two entry points that exist today as `typer` commands |
| `use <module>` | sets active-module state; prompt changes to `blacklight (module) >` |
| `show options` | reflects each command's existing `typer.Option` params as a table |
| `set OPTION value` | stores into a per-module options dict, replacing CLI flags |
| `run` | calls the *same* underlying functions (`scanner`, `guardrails.verify_targets`, `run_web_scan`) already used by `scan()`/`web()` — no scan logic changes |
| `back` / `exit` | pop module / quit the REPL |

Guardrails (private/public split, authorization confirmation, scan logging) stay identical since they already live in `guardrails.py`, separated from CLI parsing.

### Implementation plan
- New `blacklight/console.py` using `prompt_toolkit` (history, tab-completion on module/option names, arrow-key recall).
- Keep `scan`/`web` as direct one-shot commands too — non-breaking for scripting/CI use.
- Bare `blacklight` (no subcommand) drops into the console.
- Reuses `theme.py`, `guardrails.py`, `scanner.py`, `reporter.py` untouched.

**Status:** design agreed, not yet implemented. Awaiting go-ahead to build `console.py`.

---

## 4. Feature suggestions (beyond the console redesign)

Grouped by what they build on in the existing codebase:

### State & history (highest priority — biggest current gap)
Scans are stateless today beyond the append-only scan log. Add a local store (`~/.blacklight/history.db`, SQLite) to enable:
- **Diffing** — "what's new since last scan" / "what got fixed" for the same target.
- **Trend a host's risk score** over time instead of a single snapshot.
- **Accept/suppress a finding** with a reason + expiry, so re-scans stop re-flagging triaged items.

This also gives the console a natural extra command, e.g. `blacklight > history example.com`.

### Coverage
- **TLS/cert module** — expiry, weak protocol versions (SSLv3/TLS1.0), weak ciphers. Same severity-scoring pattern as the CVE pipeline, different checker.
- **Better CPE matching** — `cpe_map.py` is a hand-maintained service-name dict; nmap's `-sV` output already emits CPE strings for many services directly. Use those when present, fall back to the dict.
- **Target-file input** (`--targets-file hosts.txt`) — small effort, commonly requested once scanning more than a handful of hosts.

### CI/automation
- **SARIF export** alongside HTML/Markdown/JSON, for GitHub/GitLab code-scanning integration.
- **`--fail-on critical` / `--fail-on-score 80`** exit codes so a pipeline can gate on results.

### Notifications
- Webhook/Slack/Discord alert on new KEV-listed or critical findings — pairs well with a future scheduled/periodic scan mode.

### Workflow/config
- **Named profiles** — save a target list + ports + options under a name (`blacklight profile save homelab`). Also maps cleanly onto the console redesign as a saved module-option set.

### Deliberately out of scope
Credentialed/authenticated scanning or active exploitation checks — that shifts the tool from "vulnerability scanner with guardrails" into pentest-framework territory, a much bigger scope and trust-boundary change than the above.

### Suggested sequencing
1. Console UX (already scoped above)
2. Scan history/diffing (highest value, natural console integration)
3. TLS module
4. CI export (SARIF + fail-on thresholds)
5. Notifications, profiles, target-file input as they come up

---

## 5. Open items / next decisions

- [ ] Approve banner fix → commit to `theme.py`
- [ ] Approve console design → begin `console.py` (prompt_toolkit-based)
- [ ] Confirm feature sequencing above, or reprioritize
- [ ] Decide on persistence backend for history/diffing (SQLite assumed above)
