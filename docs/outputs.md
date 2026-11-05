# Outputs

Every run writes to `runs/<scope>/<date>/`, next to a per-scope
`findings_history.json`. The triage phase (T) turns the raw evidence into
findings, a diff against the previous run, and the reports.

```text
runs/<scope>/
  findings_history.json    Every finding key + the run dates it was seen on (ages persisting/reappearing findings)
  assets.json              Asset-id registry: maps each asset to a stable id (ROUTER-001…), persisted across runs
runs/<scope>/<date>/
  report.html              Interactive dark-mode dashboard (tabs + CLI terminal explorer + Assets tab)
  report.md                Full Markdown report with collapsible CLI evidence
  report_data.json         Consolidated, versioned export: assets + findings + relations + meta (see below)
  ai_bundle.md             Compact, self-contained companion for LLM analysis (see below)
  findings_auto.md / .tsv  Prioritised finding candidates (Asset ID + Target columns; rows grouped by asset)
  assets.tsv               Asset inventory: id, type, label, key, product/version, open ports, findings, CVEs
  diff.md                  New / Reappeared / Resolved / Not re-checked / Persisting vs. previous run
  run.meta                 Scope, date, authorisation, phases, Docker mode, egress IP
  tool_versions.txt        Detected tool versions / Docker images
  gaps.txt                 Missing optional tools, skipped checks, API timeouts
  tool_failures.tsv        Tools that could not run; their findings are "not re-checked", never "resolved"
  console/
    commands.jsonl         Structured log: every command, exit code, duration, output
    <phase>.log            Plain-text "$ command + output" per phase
  osint/                   Subdomains, CT first-seen, skipped targets, DNS posture, WHOIS, apex, IP orgs,
                           discovered targets, Wayback, entry points, Shodan, breaches, service CVEs,
                           takeover candidates, secret leaks
  web/                     httpx results, exposed API/config paths, CORS/cookies, directory listings,
                           tech, nuclei, sensitive paths, content discovery + path traversal, root data, API endpoints
  scan/                    nmap outputs (.nmap/.xml/.gnmap) for HVTs, discovered IPs, edge devices
  azure/ gcp/ aws/         Cloud public IPs, Internet-facing rules, scans, posture findings, coverage
  saas/                    SaaS posture findings + raw API responses per provider
```

## Findings, diff, and history

A **finding** has a stable key, a severity, and a **Target** (the IP, host, URL,
or — for breach/leak findings — a constructable lookup URI). Findings are written
to `findings_auto.md` / `.tsv`.

`findings_history.json` records, per finding key, the dates it was observed. From
that, `diff.md` classifies each finding relative to the previous run:

| Bucket | Meaning |
|---|---|
| **New** | First seen this run. |
| **Reappeared** | Seen before, absent last run, back now. |
| **Resolved** | Present last run, gone now — **only** if the producing phase ran in both runs. |
| **Not re-checked** | The phase/tool that would confirm it didn't run (see `tool_failures.tsv`). Never counted as resolved. |
| **Persisting** | Present in both runs. |

This "not re-checked ≠ resolved" rule is what makes the diff trustworthy across
runs where a tool was temporarily unavailable.

## Assets

Every target is aggregated into an **asset** (keyed by IP or host) and given a
**stable, human-readable identifier** — `ROUTER-001`, `WEB-004`, `K8S-002`, and so
on. The id is assigned on first sight and persisted in `runs/<scope>/assets.json`,
so an asset keeps the same id across runs — the anchor a risk tracker or a forensic
timeline needs. The type is re-evaluated each run (a host can become a web asset),
but the id never changes.

An asset gathers everything known about it: reverse DNS / org, cloud resource
name, open ports and services, product/versions, correlated CVEs, and the findings
that reference it. Types are classified from that evidence:
`ROUTER, FW, VPN, K8S, LB, MAIL, DB, DC, WEB, CLOUD, HOST, DOMAIN, ASSET`.

**Asset ↔ finding is many-to-many.** A finding that names several targets (a
shared rule, a wildcard cert, a CVE on a service present on several hosts) links
to **every** asset it affects and appears under each in the inventory. A finding
with no host/IP target (org- or tenant-level: M365/identity, breaches, DNS/mail
posture) is grouped under a pseudo-asset — `TENANT-001` (SaaS / identity) or
`ORG-001` (organization-wide) — so it is still inventoried and carries a stable id.

- `assets.tsv` — the full inventory (one row per asset).
- `findings_auto.*` carry an **Asset ID** column (all affected ids) and rows are
  **grouped by asset** (by the finding's primary asset; assets ordered by their
  worst finding severity).

## The HTML dashboard (`report.html`)

A single self-contained dark-mode page; no server or network needed — open the
file. Tabs cover findings, assets, hosts/CVEs, the web surface, cloud/SaaS/DNS
posture, and a **CLI terminal explorer** for every captured command and its output.

Built for triage and forensics:

- **Assets tab** — one row per asset (id, type, label + key, product/version, open
  ports, its findings as severity badges, and its CVEs) with a search box and a
  **type filter**.
- **Findings grouped by asset**, each row showing its Asset ID (and `+N` when a
  finding affects several assets); clicking the id jumps to that asset's row in the
  Assets tab and highlights it.
- **Clickable severity KPI cards** ("Critical 3" …) jump straight to the Findings
  tab filtered to that severity.
- **Search boxes** on the findings, assets, hosts/CVEs, web, cloud and CLI tabs.

## The consolidated export (`report_data.json`)

A single, versioned JSON document that captures everything a *downstream* consumer
needs without re-parsing the individual artifacts: run metadata, the KPIs, the full
asset inventory, every finding, and — explicitly — the many-to-many
asset↔finding relations. It is written on every run and regenerated by
`--export`.

It is the stable **contract** for a separate, human-curated report generator (and
for any tracker or script): only derived, structured data, no HTML or console
dumps. It carries a `schema_version` — consumers check the major component and
ignore unknown fields.

```text
{
  "schema_version": "1.0",
  "generator": "scylax",
  "generated_at": "2026-11-05T12:00:00Z",
  "meta":     { engagement, scope, date, authorised_by, authorisation_ref, phases, egress_ip, use_docker },
  "kpis":     { critical, high, …, subdomains, live_web_hosts, cves_total, … },
  "summary":  { total_findings, total_assets, total_relations, severity_counts },
  "diff":     { "New": [...], "Reappeared": [...], "Resolved": [...], "Not re-checked": [...], "Persisting": [...] },
  "assets":   [ { id, type, type_label, key, label, pseudo, cloud, ports, cves, finding_ids, worst_severity, … } ],
  "findings": [ { id, key, severity, title, evidence, target, asset_id, asset_ids, asset_keys } ],
  "relations":[ { finding_id, asset_id, primary } ]
}
```

- **`relations`** is the join table: one edge per affected asset, `primary: true`
  on the finding's primary asset. A finding on several hosts has several edges; a
  target-less finding points at a `TENANT-001` / `ORG-001` pseudo-asset.
- **`finding_ids`** on each asset and **`asset_ids`** on each finding are the same
  relation, denormalised both ways so a consumer can walk it from either side.

Regenerate it for an existing run without re-scanning:

```bash
python3 scylax.py --export runs/<scope>/<date>/
```

## The AI bundle (`ai_bundle.md`)

A compact, **self-contained** Markdown companion built for LLM analysis:

- Run metadata and coverage gaps up front.
- Every structured source file embedded, each tagged with its path
  (`<!-- scylax-file: path (meta) -->` fenced blocks).
- Core files are included verbatim; large ones are capped; console logs and huge
  dumps are left out to fit a model's context window.

Because it carries the structured evidence, the reports can be rebuilt from it
alone:

```bash
python3 scylax.py --report-from-bundle runs/<scope>/<date>/ai_bundle.md
```

## Notable raw files

| File | Contents |
|---|---|
| `assets.tsv` | Asset inventory: id, type, label, key, product/version, open ports, findings, CVEs. |
| `report_data.json` | Consolidated, versioned export: meta, KPIs, assets, findings, and asset↔finding relations. |
| `../assets.json` | Scope-level asset-id registry (stable ids across runs). |
| `osint/new_subdomains.txt` | Subdomains first seen this run. |
| `osint/ct_first_seen.tsv` | First certificate seen per host (certspotter fallback). |
| `osint/skipped_targets.tsv` | Resolved IPs outside ownership — recorded, never scanned. |
| `osint/hibp_breaches.tsv` | Domain/account breach exposure. |
| `osint/service_cves.tsv` | CVE correlation with CVSS and CISA KEV status. |
| `osint/takeover_candidates.tsv` | Dangling-CNAME subdomain-takeover checks. |
| `osint/secret_leaks.tsv` | Secrets found in the org's public repos. |
| `web/sensitive_paths.tsv` | Curated sensitive-path probe (nuclei fallback). |
| `web/content_discovery.tsv` | Phase C: exposed panels/docs/config/backups. |
| `web/path_traversal.tsv` | Phase C: signature-confirmed path traversal. |
| `web/root_data.tsv` | Data files served at a web root (type, size, columns, sensitive fields). |
| `web/api_endpoints.tsv` | Parameterless GET endpoints from published OpenAPI schemas. |

Data probes read at most ~4 KB per URL (header row / schema) and never download
datasets; sizes come from `Content-Range` / `Content-Length`.
