# blacklight-cli domain glossary

Terms as used in the codebase and its architecture reviews. Names for good
seams. Keep this current when modules are added or renamed.

- **scan** — a run of the infra pipeline: nmap → CPE match → NVD/EPSS/KEV enrich
  → score. Produces network **Findings** (host/port/service/CVSS).
- **web scan** — a run of the web pipeline: fetch page → checks → fingerprint →
  CVE match → enrich. Produces **WebFindings** (url/category/detail/evidence).
- **target** — what gets scanned: a host/CIDR for a scan, a URL for a web scan.
  The same concept, stored in the `target` column of history, regardless of kind.
- **Finding** (network) vs **WebFinding** (web) — deliberately two result types
  behind one result envelope (the typed `ScanResult`); do not unify.
- **ScanResult** — the typed output of a scan pipeline run: `kind`, the target,
  `generated`, findings, and a per-kind typed meta payload (`NetworkMeta` /
  `WebMeta`). One shape for history, reporter, log, and export.
- **scan pipeline (orchestrator)** — the single seam that runs an entire scan:
  guardrails verify → confirm → execute → log → record → render → export. One
  entry (`engine.run(executor, targets, params, confirm, on_progress)`), two
  executor adapters (network, web) that each expose `verify(...) -> Verdict`
  and `run(...) -> ScanResult`. Lives in a new `blacklight/engine.py`.
- **executor adapter** — `NetworkScan` / `WebScan`; the two genuine variants
  behind the orchestrator seam. Two adapters make the seam real.
- **permission** — the authorization signal: `--i-have-permission`,
  `PERMISSION` option, `permission_granted` kwarg, `permission` DB column. One
  concept, unified spelling to `permission`/`permission_granted`.
- **confirm** — the injected authorization prompt, always a
  `Callable[[str], bool]` (typer.confirm, REPL prompt, TUI modal bridge).
- **on_progress** — the injected `(stage, current, total)` callback; declared
  once on the orchestrator entry, never re-declared by consumers.
- **guardrails** — target validation returning `Verdict(allowed,
  needs_confirmation, blocked)`; the policy module. Pure: never prompts.
- **history** — the SQLite store of scans. The *store* is a deep seam; callers
  must not leak `sqlite3.Error` into their contracts (reopen pending).
- **scope**: per-target risk score is currently computed three ways (history
  flatten, trend max, reporter per-host) — one score per record is the goal.