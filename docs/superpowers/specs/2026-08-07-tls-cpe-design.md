# blacklight-cli — TLS checks + native CPE matching design

**Date:** 2026-08-07

Two coverage-depth improvements to the network scan pipeline, delivered in one
plan:

1. **Native CPE matching** — use the CPE strings nmap emits for each service
   instead of only the hand-maintained service-name dict; fall back to the dict
   when nmap emits none.
2. **TLS module** — check TLS ports (cert expiry, legacy protocols, weak
   ciphers) inline in `blacklight scan`, scored and reported like the rest of
   the network findings.

Both build on the existing scan-pipeline seam (`engine.run` /
`NetworkScan` / typed `ScanResult`) — no new commands, no new dependencies,
only the `--script ssl-cert,ssl-enum-ciphers` nmap invocation change.

---

## 1. Native CPE matching

### Problem

`cpe_map.SERVICE_CPE` is a hand-maintained `service-name → (vendor, product)`
dict. nmap's `-sV` already emits a CPE identifier for many services, but
`parse_nmap_xml` discards those `<cpe>` elements (scanner.py reads only
`product`/`name`/`version`). Mapping through the dict:
- misses services not in the dict (no CVEs found at all), and
- can map a service to the wrong vendor/product when the name is ambiguous.

### Design

- `ScanRecord` gains `cpe: str = ""` (default keeps the web-path constructor
  and existing tests valid).
- `parse_nmap_xml` captures the first `<cpe>` child of each `<service>`
  element. nmap emits CPE 2.2 URI-binding strings, e.g.
  `cpe:/a:nginx:nginx:1.24.0`.
- New helper in `cpe_map.py`:
  `normalize_cpe(cpe: str) -> str | None` — converts an nmap CPE 2.2 URI to the
  NVD `cpe:2.3:` form padded to 13 components (`part:vendor:product:version:
  update:edition:language:sw_edition:target_sw:target_hw:other`) with `*`
  fillers. Returns `None` for unparseable input. If the nmap CPE is versionless
  (empty version component) but the matched `ScanRecord.version` yields a
  numeric version via `extract_version`, splice it into the version component.
- `build_findings` (cve_matcher.py) resolves each record's CPE as:
  `record.cpe and normalize_cpe(record.cpe) or service_to_cpe(...)` — nmap CPE
  first, dict fallback second.
- No other behavior change: `cpe_to_match_string`, caching, `Finding.cpe`,
  history fingerprints (`host|port|service|cve_id`) are all untouched. The CVE
  cache key is already per-CPE, so finer-grained CPEs just produce finer cache
  entries.

### Tests

- `test_cpe_map.py`: `normalize_cpe` for a full URI, a versionless URI, a
  malformed string (`None`).
- `tests/fixtures/nmap_sv.xml` gains `<cpe>` children; `test_scanner.py`
  asserts the parsed `record.cpe`.
- `test_cve_matcher.py`: `build_findings` uses the record's nmap CPE over the
  dict, and falls back to the dict when `record.cpe` is empty.

---

## 2. TLS module (inline in `scan`)

### Data source

`scanner.scan_hosts` appends `--script ssl-cert,ssl-enum-ciphers` to the nmap
invocation. nmap only runs these scripts on ports it detects as SSL/TLS; all
other ports produce no TLS output, so the extra cost is bounded to TLS ports.

New opt-out: CLI/console/TUI pass `--no-tls-checks` (setternally
`ScanParams.tls_checks: bool = True`). When off, the scripts are omitted and no
TLS parsing/classify happens — identical to today's nmap run.

### Parsing

- `ScanRecord` gains `tls: TlsData | None = None` where

  ```python
  @dataclass
  class TlsData:
      ssl_cert_output: str   # raw script output textf ssl-cert
      ssl_ciphers_output: str  # raw script output text of ssl-enum-ciphers
  ```

  `parse_nmap_xml` reads the `<script id="ssl-cert">` / `<script
  id="ssl-enum-ciphers">` elements nested under each open port and populates
  `TlsData` when either is present. The web-path `ScanRecord` constructor is
  unaffected (`tls` defaults to `None`).

- For engine tests, a fake `TlsData` can be attached to monkeypatched records;
  no real nmap needed.

### Classification — new `blacklight/tls.py` (pure, no I/O)

API:
```
classify(host, port, service, tls) -> list[TlsFinding]
```

Rules (severities follow `SEVERITY_WEIGHTS` in scoring.py; each rule emits at
most one finding per host:port:service so history diff fingerprints stay
stable):

| Rule | Source | Severity |
|---|---|---|
| Certificate expired (`notAfter` < now) | ssl-cert output | high |
| Certificate expires within 30 days | ssl-cert output | low |
| Self-signed (subject == issuer, normalized) | ssl-cert output | low |
| SSLv3 negotiated | ssl-enum-ciphers section | high |
| TLSv1.0 negotiated | ssl-enum-ciphers section | medium |
| TLSv1.1 negotiated | ssl-enum-ciphers section | low |
| Neither TLSv1.2 nor TLSv1.3 offered | ssl-enum-ciphers sections | high |
| Supports NULL/EXPORT/anonymous ciphers | ssl-enum-ciphers cipher names | high |
| Supports RC4 or single-DES ciphers | ssl-enum-ciphers cipher names | medium |

Parsing is targeted regex against the free-text script `output` — 
`notAfter:<date>`, `Subject:`/`Issuer:` lines, protocol section headers
(`SSLv3:`, `TLSv1.0:`, ...), and cipher names in each section. Unparseable
output → no findings for that rule (never crash).

Deliberately out of scope for v1: hostname/SAN mismatch checking (IP-first
scanning makes it noisy) and TLS 1.3-only-negotiation checks (no data).

### New typed result — `TlsFinding`

Follows the existing one-typed-findings-per-kind pattern (like `WebFinding`);
does NOT reuse the CVE `Finding`.

```python
@dataclass
class TlsFinding:
    host: str
    port: int
    service: str
    category: str        # "expiry" | "self-signed" | "protocol" | "weak-cipher"
    detail: str
    evidence: str        # e.g. "notAfter 2026-02-01", "SSLv3"
    severity: str        # critical|high|medium|low|unknown
    cve_id: str          # stable id, e.g. "TLS-EXPIRED" - used as the history
                         # diff fingerprint component, never an actual CVE id
    epss: float | None = None
    in_kev: bool = False
```

- `ScanResult` gains `tls_findings: list[TlsFinding] = field(default_factory=list)`.
- `NetworkMeta` gains `tls_findings_count: int`.

### Engine integration

`NetworkScan.run` (engine.py):
1. After `scan_hosts`, when `params.tls_checks` on, collect records that have
   `tls` data.
2. Progress phase: `on_progress("tls", current, total)`.
3. Append `tls.classify(...)` results to `ScanResult.tls_findings`; set
   `tls_findings_count`.
4. `module-results` unchanged; CVE findings and enrichment untouched.

### Reporting

- `reporter.py`: new `tls_findings_table(tls_findings) -> Table` rendered as a
  separate "TLS findings" section after the network findings table
  (terminal `render_terminal`). Panel summary notes the TLS finding count.
- `export_report` payload gains `"tls": [t.to_dict() for t in result
  .tls_findings]` for html/markdown/json; both `report.html.j2` and
  `report.md.j2` templates gain a TLS section.
- `host_risk_score` needs no change: `history` already reconstructs findings —
  see below.

### History / diff / trend

- `history.record_scan`: writes TLS rows into the shared `findings` table with
  `kind="scan"`, `category="tls"`, and the stable `cve_id` (e.g.
  `TLS-EXPIRED`) so the `_network_fingerprint` (`host|port|service|cve_id`)
  remains stable across scans.
- `_network_score`/`diff_for_target`/`trend_for_target` need no change: they
  already read all of a scan's findings, and TLS severities feed the existing
  severity-weight scoring. TLS rows carry `epss=0`, `in_kev=0` so those bonuses
  are unaffected.
- Diff renders TLS rows in the same network findings table (CVE ID column
  shows `TLS-EXPIRED`), which is acceptable — the stable id identifies it.

### Console / TUI

- `CommandRunner` scan options gain `NO_TLS_CHECKS` (true/false) alongside
  `NO_CACHE`/`PERMISSION`; the TUI module table gets the same option.
- Both are thin pass-throughs to `ScanParams.tls_checks`, consistent with the
  existing injection seam — no new code paths.

---

## 3. Files touched

| File | Change |
|---|---|
| `blacklight/scanner.py` | `ScanRecord.cpe`, `ScanRecord.tls` (new `TlsData`), `<cpe>` + `<script>` parsing, `--script ssl-cert,ssl-enum-ciphers`, `tls_checks` param |
| `blacklight/cpe_map.py` | `normalize_cpe()` |
| `blacklight/cve_matcher.py` | `build_findings` prefers `record.cpe` |
| `blacklight/tls.py` | NEW — `TlsData`? (no: TlsData lives in scanner or tls.py — see note), `TlsFinding`, `classify()` |
| `blacklight/engine.py` | `ScanParams.tls_checks`, `ScanResult.tls_findings`, `NetworkMeta.tls_findings_count`, engine wiring |
| `blacklight/reporter.py` | TLS table + export payload + summary |
| `blacklight/templates/report.html.j2` | TLS section |
| `blacklight/templates/report.md.j2` | TLS section |
| `blacklight/history.py` | `record_scan` stores TLS rows (only change) |
| `blacklight/cli.py` | `--no-tls-checks` flag |
| `blacklight/console.py` | `NO_TLS_CHECKS` option |
| `blacklight/tui/` | `NO_TLS_CHECKS` option (option table) |
| `docs/superpowers/specs/2026-08-07-tls-cpe-design.md` | this spec |
| docs/superpowers/plan to come | implementation plan |

> NOTE (decision): the `TlsData` dataclass lives in `scanner.py` (it is a
> parsed shape of nmap output, produced by `parse_nmap_xml`) and `tls.py`
> imports it from there — avoids a scanner→tls import. `cpe_map.py` needs no
> import of scanner.

## 4. Out of scope

- Hostname/SAN mismatch validation (IP-based scans make it noisy).
- `blacklight tls <host>` standalone command — TLS runs inline in `scan` only.
- Credentialed / active TLS exploitation checks (trust-boundary unchanged).
- Non-nmap TLS data source (e.g. sslyze) — this spec is nmap-NSE-only.