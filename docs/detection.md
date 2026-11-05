# Detection & triage

The scanning phases write raw evidence; the triage phase (T, `recon/phases/triage.py`)
turns that evidence into **findings**. A finding is a tuple of
`(severity, key, title, evidence, target)`:

- **severity** — `critical` / `high` / `medium` / `low` / `info`.
- **key** — a stable, prefixed identifier (e.g. `takeover:<host>`,
  `traversal:<url>`) used for de-duplication and for aging in
  `findings_history.json`.
- **target** — the IP, host, or URL the finding is about; for breach/leak
  findings, a constructable lookup URI.

Findings are de-duplicated (URL- and host-folding for noisy categories), sorted by
severity, and written to `findings_auto.md` / `.tsv` and into the reports.

## What triage looks at

Triage reads the outputs of every phase that ran. Beyond the DNS/TLS/header/CVE
checks, these are the dedicated detectors:

| Finding prefix | Source | Phase | Tools |
|---|---|---|---|
| `nuclei:` | nuclei template matches | 8 | `nuclei` |
| `sensitive-path:` | curated sensitive-path probe | 8 (nuclei fallback) | native |
| `takeover:` | dangling-CNAME subdomain takeover | 2 | `dig` |
| `secret-leak:` | secrets in public repos | 9 | `gitleaks` / `trufflehog` |
| `content-disc:` | exposed panels/docs/config/backups | C | `gobuster` / native |
| `traversal:` | signature-confirmed path traversal | C | native |

Each prefix also maps to the tool(s) that confirm it, so the diff can tell
"actually re-checked and gone" from "the tool didn't run this time". See
[outputs.md](outputs.md#findings-diff-and-history).

## Subdomain takeover (`takeover:`)

For each subdomain whose CNAME points at a service, Scylax checks for the classic
takeover condition: the target resolves to **NXDOMAIN** (or is otherwise
unclaimed) **and** the live response matches a known "unclaimed" fingerprint for
that provider. Both signals must agree, which keeps false positives down.
Candidates are written to `osint/takeover_candidates.tsv`.

## Sensitive-path probe (`sensitive-path:`)

Phase 8 normally uses nuclei. If nuclei is missing or fails, Scylax falls back to
a **native, signature-gated** probe of a curated list of ~70 sensitive paths
(`recon/sensitive_paths.py`) — `.git/config`, `.env`, actuator endpoints, admin
panels, and so on. A hit is reported only when the response matches the path's
signature, not on status code alone.

## Content discovery (phase C, `content-disc:`)

An **opt-in** active check (`recon/phases/content.py`) for paths that should not be
reachable: control panels, API docs (Swagger/FastAPI), source control, config,
backups, telemetry. It uses `gobuster` when available, otherwise a native threaded
probe. Results are bucketed by severity:

- **high** — `.git`, `.env`, backups, dumps, `.sql`, secrets, SSH/AWS creds,
  `wp-config`, heapdumps, `actuator/env`.
- **medium** — admin/console/manager panels, phpMyAdmin/Adminer, Jenkins,
  Grafana, Kibana, Solr, Jolokia, actuator/metrics, phpinfo, `wp-admin`.
- **low** — everything else that merely responded.

The bundled wordlist is `recon/data/content_discovery.txt` (curated, ~250 paths);
override it with `content_discovery.wordlist`. Rate is capped (`content_discovery.rate`,
default 20 req/s/host) and there is a hard request budget per run.

## Path traversal (phase C, `traversal:`)

Alongside content discovery, Scylax sends a small set of path-traversal / LFI
payloads (encoded `../` variants for `/etc/passwd` and `windows/win.ini`). A
finding is recorded **only when the response body matches the file's signature**
(e.g. a `root:...:0:0:` line for `/etc/passwd`), never on status code — so a hit
means content was actually returned. One confirmed traversal per host is enough;
it stops there. Results go to `web/path_traversal.tsv`.

## The non-intrusive boundary

Scylax is reconnaissance, not exploitation. Everything above is observational or
GET-based and confirmed by content signatures. Scylax deliberately does **not**:

- run DAST, SQL injection, or any injection fuzzing;
- brute-force credentials or directories beyond a bounded, rate-limited wordlist;
- send destructive, state-changing, or exploit payloads;
- download datasets (data probes read ~4 KB — a header row or schema — at most).

The line is: *actively checking whether something that should be closed is open*
(an exposed panel, readable `/etc/passwd`, a dangling CNAME) is in scope;
*attacking* it is not.

## Alerts

If `alert_webhook` (or `SCYLAX_ALERT_WEBHOOK`) is set, new and reappeared
**high/critical** findings are posted to the Teams/JSON endpoint after a run
(`recon/notify.py`). Persisting and lower-severity findings are not pushed, to
keep the channel signal-heavy.
