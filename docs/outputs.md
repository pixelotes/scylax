# Outputs

Every run writes to `runs/<scope>/<date>/`, next to a per-scope
`findings_history.json`. The triage phase (T) turns the raw evidence into
findings, a diff against the previous run, and the reports.

```text
runs/<scope>/
  findings_history.json    Every finding key + the run dates it was seen on (ages persisting/reappearing findings)
runs/<scope>/<date>/
  report.html              Interactive dark-mode dashboard (tabs + CLI terminal explorer)
  report.md                Full Markdown report with collapsible CLI evidence
  ai_bundle.md             Compact, self-contained companion for LLM analysis (see below)
  findings_auto.md / .tsv  Prioritised finding candidates (with Target column)
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

## The HTML dashboard (`report.html`)

A single self-contained dark-mode page: tabbed views of findings, the attack
surface, cloud/SaaS posture, and the diff, plus a **CLI terminal explorer** that
lets you browse every captured command and its output from `console/`. No server
or network needed — open the file.

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
