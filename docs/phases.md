# Phases

A run is a sequence of phases. Each writes raw evidence into the run directory;
the final phase (T) reads it all and produces the findings, diff, and reports.

- **Passive** — observation only (OSINT, DNS, public data). No packets to targets.
- **Active (light)** — GET-based probing / single-request fingerprinting, rate
  limited.
- **Active** — port scanning and service detection.

Active phases need [authorization](usage.md#authorization-gate). Cloud (A/G/W),
SaaS posture (S), content discovery (C), and SaaS exposure (E) are opt-in. To run
a ready-made group of phases, use a [profile](usage.md#profiles).

| # | Phase | What it does | Tools | Mode |
|---|---|---|---|---|
| `1` | Subdomain enumeration | Passive enumeration from CT logs and OSINT; diff vs. previous run | `subfinder`, `amass -passive`, `crt.sh` | Passive |
| `2` | DNS posture & IP auto-discovery | Resolves all subdomains; checks NS, MX, SPF, DMARC, CAA, DNSKEY, AXFR, wildcard, WHOIS, apex ownership; classifies IP ASNs; auto-discovers non-CDN target IPs | `dnsx`, `dig`, `whois` | Passive |
| `3` | Live web hosts & entry surface | Probes resolving hosts; detects directory listings; checks well-known API/config paths (Swagger/OpenAPI, Actuator, `.env`, `.git`) and CORS/cookie hygiene | `httpx` (native fallback) | Active (light) |
| `4` | HVT & discovered-IP scan | Two-pass scan on `hvt_ips` + discovered targets (excluding `edge_ips`/`exclude_ips`): full TCP discovery then `-sV` with safe NSE scripts | `nmap` | Active |
| `4b` | Edge device fingerprint | Slow, safe banner fingerprint (`-T2 --max-rate 40 -sV --script banner`) on `edge_ips`/`edge_ports` only | `nmap` | Active (light) |
| `5` | Technology fingerprint | Tech stack from `httpx` plus single-request `whatweb -a 1` | `httpx`, `whatweb` | Active (light) |
| `6` | Historical URLs & entry points | Wayback CDX; filters sensitive extensions; classifies parameter entry points (IDOR, LFI, Open Redirect, SQLi candidates) | Wayback CDX | Passive |
| `7` | Shodan + CVE / CISA KEV | Shodan host API (if key set); correlates nmap CPEs/versions against Shodan CVEDB for CVSS and **CISA KEV** status | Shodan API & CVEDB (NVD fallback) | Passive |
| `8` | Vulnerability detection | Non-intrusive `nuclei` templates (medium/high/critical) against live web hosts and HVTs (`edge_ips` excluded) | `nuclei` | Active (light) |
| `9` | Leaked credentials & breaches | Enumerates corporate emails (theHarvester, amass, SpiderFoot, PGP/WHOIS/Wayback) and correlates with HaveIBeenPwned; scans public repos for secrets; checks dangling-CNAME takeover | `theharvester`, `amass`, `spiderfoot`, `hibp`, `xposedornot`, `gitleaks`/`trufflehog`, `gh` | Passive / Intel |
| `A` | Azure annex (grey-box) | Inventories public IPs and Internet-facing NSG rules via Azure Resource Graph, then two-pass `nmap` (+ optional posture) | `az`, `nmap`, `prowler` | Active (opt-in) |
| `G` | GCP annex (grey-box) | Inventories VM IPs, forwarding rules, and `0.0.0.0/0` VPC firewall rules, then two-pass `nmap` (+ optional posture) | `gcloud`, `nmap`, `prowler` | Active (opt-in) |
| `W` | AWS annex (grey-box) | Inventories Elastic/EC2 IPs, ALBs, public RDS, and Internet-facing Security Groups, then two-pass `nmap` (+ optional posture) | `aws`, `nmap`, `prowler` | Active (opt-in) |
| `C` | Content discovery | Checks for exposed control panels, API docs, source/config, backups, telemetry on owned hosts, plus signature-confirmed path traversal | `gobuster` (native fallback) | Active (opt-in) |
| `E` | Third-party SaaS exposure | Anonymous, read-only checks against `<org>.atlassian.net` (Jira/Confluence Cloud): whether issues, projects, users, dashboards, spaces or pages answer without login. Only counts are kept, never record contents. Optional `misconfig-mapper` on the same exact names | native HTTP, optional `misconfig-mapper` | Active (opt-in) |
| `S` | SaaS security posture | Authenticated read-only config audit of M365/Entra ID, GitHub org, Google Workspace | Graph API, `gh`, `gam` | Authenticated (opt-in) |
| `T` | Triage, diff & reporting | Evaluates all outputs → `findings_auto.*`, `diff.md`, `report.md`, `report.html`, `ai_bundle.md` | Python stdlib | Offline |

## Dependencies and graceful degradation

Each phase declares **required** and **optional** tools
(`recon/deps.py`, see [plugins-and-architecture.md](plugins-and-architecture.md)):

- A missing **required** tool skips that phase and records the gap. Only phases
  2 (`dig`, `whois`), 4 and 4b (`nmap`) have hard requirements.
- A missing **optional** tool runs the phase with reduced coverage, recorded in
  `gaps.txt`.
- A tool that fails at runtime (Docker down, timeout) is logged in
  `tool_failures.tsv`; the findings it would have re-checked are marked
  **"not re-checked"** in the diff, never silently "resolved".

## Active-phase scoping (safety)

- Phase 4 scans only `hvt_ips` and auto-discovered **owned** IPs, always excluding
  `edge_ips` and `exclude_ips`.
- Edge devices are handled only by 4b, with a slow, safe profile.
- Auto-discovered IPs outside `owned_ranges` / `owned_ips_file` /
  `*_inventory_file` are recorded in `osint/skipped_targets.tsv` and never
  scanned.
- `nuclei` (phase 8) excludes `edge_ips` and runs non-intrusive templates only.

See [detection.md](detection.md) for how phases 3, 8, 9 and C turn evidence into
findings, and for the non-intrusive boundary.
