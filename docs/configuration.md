# Scope configuration (`.toml`)

A **scope** file defines what Scylax is authorized to look at and how. One file
per engagement; the filename (without `.toml`) becomes the scope name and the
`runs/<scope>/` folder. Copy [`scopes/example.toml`](../scopes/example.toml) and
edit it.

Real scope files are git-ignored because they contain targets and authorization
details. Validate any scope with:

```bash
python3 scylax.py -s scopes/acme.toml --check-config
```

`--check-config` reports **errors** (which would stop a run — e.g. no domains, a
missing `owned_ips_file`) and **warnings** (hygiene — unknown keys, empty
sections) and exits.

## How values are resolved

Each setting can come from three places, in order of precedence:

1. **CLI flag** (e.g. `--shodan-key`, `--prowler`) — highest.
2. **Environment variable** (e.g. `SHODAN_API_KEY`, `CLOUD_POSTURE=1`).
3. **Scope file** value.

File paths in the scope (`owned_ips_file`, `*_inventory_file`,
`content_discovery.wordlist`) are resolved **relative to the scope file**, so runs
behave the same wherever you launch Scylax from.

## Sections and keys

Keys may be written flat (top-level) or inside their `[section]`; both are
accepted. The canonical form is shown below.

### `[engagement]`

| Key | Type | Meaning |
|---|---|---|
| `engagement` | string | Human-readable engagement name (shown in reports). |
| `scope_owner` | string | Who owns the scope. |
| `authorised_by` | string | **Required for active phases.** Written-authorization string. |
| `authorisation_ref` | string | **Required for active phases.** Ticket / reference. |
| `runs_dir` | string | Where `runs/<scope>/<date>/` is written. Absolute, or relative to the scope file. Empty → `<cwd>/runs`. |
| `alert_webhook` | string | Teams/JSON incoming webhook; new & reappeared high/critical findings are posted after a run. Also `SCYLAX_ALERT_WEBHOOK`. Empty disables alerts. |
| `suppressions_file` | string | Auditor suppressions file (see [Finding suppressions](#finding-suppressions-suppressionstoml)). Resolved like `owned_ips_file`. Empty → `<scope dir>/<scope-name>.suppressions.toml` when that file exists. |

### `[targets]`

| Key | Type | Meaning |
|---|---|---|
| `domains` | list | **Required.** Root domains to assess. |
| `www_url` | string | Main site for header checks (default `https://www.<first domain>/`). |
| `auto_discover_targets` | bool | Add in-scope IPs discovered during passive enumeration (default `true`). |
| `hvt_ips` | list | High-value IPs: full TCP scan + service fingerprint + nuclei. |
| `edge_ips` | list | Fragile edge devices: slow, light banner scan only (no nuclei). |
| `edge_ports` | string | Ports for edge scans (default `21,22,23,53,80,443,8291`). |
| `exclude_ips` | list | IPs **never** actively scanned (third-party / shared PaaS). |
| `owned_ranges` | list | Ownership allowlist (IPs/CIDRs). Auto-discovered IPs outside this (and the files below) are recorded in `osint/skipped_targets.tsv`, never scanned. |
| `owned_ips_file` | string | File of owned IPs (one per line, optional comment). Resolved relative to the scope file. |
| `apex_trusted_orgs` | list | Orgs trusted to host apex domains (avoids flagging known CDN/SaaS as rogue apex). |
| `skip_portscan_orgs` | list | Org/netname patterns (from WHOIS) to skip aggressive port scans for (shared edge/WAF). |

> **Ownership matters.** `owned_ranges` + `owned_ips_file` are what keep Scylax
> from port-scanning CDNs, SaaS, or shared-cloud front-ends that merely resolve
> under your domains. Keep them current (see [CTEM runs](usage.md#monthly-runs-ctem)).

### `[azure]` / `[gcp]` / `[aws]` — cloud annexes (opt-in)

Cloud phases **A / G / W run only when their section is configured** (or the phase
is named explicitly with `-p`). An empty section means the annex is skipped.

| Section | Keys |
|---|---|
| `[azure]` | `subscriptions` (list), `inventory_file` (string) |
| `[gcp]` | `projects` (list), `inventory_file` (string) |
| `[aws]` | `profiles` (list), `regions` (list), `inventory_file` (string) |

An `inventory_file` is a static list of public IPs (one per line, optional
`TAB name`) used when live cloud queries aren't available.

### `[cloud_posture]`

| Key | Type | Meaning |
|---|---|---|
| `cloud_posture` | bool | Run native CSPM checks during A/G/W (storage, KeyVault, SQL, IAM/MFA, firewalls). Also `--cloud-posture` / `CLOUD_POSTURE=1`. |
| `use_prowler` | bool | Deep Prowler CIS scan (requires `cloud_posture = true`). Also `--prowler` / `USE_PROWLER=1`. |

### `[saas]` — SaaS posture (opt-in)

| Key | Type | Meaning |
|---|---|---|
| `saas_posture` | bool | Run the authenticated read-only SaaS audit (phase S). Also `--saas-posture` / `SAAS_POSTURE=1`. |
| `providers` | list | Which tenants to audit: `m365`, `github`, `google` (default: all three). |

Credentials come from the environment: `M365_TENANT_ID` / `M365_CLIENT_ID` /
`M365_CLIENT_SECRET`, `GITHUB_ORG` + an authenticated `gh`, and `gam` for Google.

### `[intelligence]`

| Key | Type | Meaning |
|---|---|---|
| `shodan_api_key` | string | Shodan host lookups (phase 7). Prefer `SHODAN_API_KEY` env. |
| `hibp_api_key` | string | HaveIBeenPwned domain/account audit (phase 9). Prefer `HIBP_API_KEY` env. |

> **Casing matters.** Keys in the file must be lower-case (`shodan_api_key`), the
> canonical schema name. An upper-case `SHODAN_API_KEY` **inside the toml** is not
> read as the key — set the environment variable (also upper-case) or use
> `--shodan-key` instead.

### `[content_discovery]` — phase C (opt-in)

| Key | Type | Meaning |
|---|---|---|
| `enabled` | bool | Turn phase C on. Also runnable with `-p C`. Default `false`. |
| `wordlist` | string | Custom wordlist (relative to the scope file). Empty → the bundled `recon/data/content_discovery.txt`. |
| `rate` | int | Requests/second per host (default `20`). |

### `[limits]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `nmap_max_rate` | int | `400` | Packets/sec for HVT & cloud scans. |
| `edge_max_rate` | int | `40` | Packets/sec for fragile edge fingerprinting. |
| `nuclei_rate` | int | `50` | Nuclei requests/sec. |
| `httpx_rate` | int | `50` | httpx requests/sec. |
| `use_amass` | bool | `true` | Use amass in phases 1 & 9. |
| `amass_timeout_min` | int | `10` | Amass enumeration timeout. |
| `jobs` | int | `1` | Independent phases run at once (`--jobs` overrides). Active phases never overlap. |

### `[thresholds]`

Minimum acceptable versions used by triage flags — update per assessment cycle:
`min_apache` (`2.4.65`), `min_nginx` (`1.26.0`), `min_routeros` (`7.15`).

## Finding suppressions (`.suppressions.toml`)

Scylax reports *candidates*; a suppression records the auditor's decision about
one of them — accepted risk, false positive or compensating control — with an
owner, a reason and an expiry date. Suppressed findings never disappear
silently: they leave the active outputs (`findings_auto.*`, `findings.jsonl`,
KPIs and severity counts) and are listed in `suppressed.md` and in the report's
**Suppressed** table. When the expiry date passes they are active again.

The file is `scopes/<scope-name>.suppressions.toml` next to the scope (picked up
automatically) or whatever `suppressions_file` names. Real suppression files are
git-ignored like scope files; `scopes/example.suppressions.toml` is the tracked
example.

```toml
[[suppress]]
key = "dnssec:fabrikam.io"          # exact finding key (findings_auto.tsv column 2), or:
reason = "Accepted risk: registrar has no DNSSEC; migration planned"   # required
owner = "jdoe"                      # required
expires = 2027-06-30                # required TOML date, inclusive
ticket = "SEC-1042"                 # optional

[[suppress]]
rule = "cors"                       # rule id = the key up to the first ':' (globs ok: "cve-*")
target = "*.dev.contoso.com"        # optional glob on the target, its hostname, or the key's resource
reason = "Compensating control: VPN + WAF in front of dev hosts"
owner = "asmith"
expires = 2027-03-31
```

| Field | Required | Meaning |
|---|---|---|
| `key` | one of `key`/`rule` | Exact finding key. |
| `rule` | one of `key`/`rule` | Rule id: the key prefix before the first `:` (`spf`, `cors`, `mgmt`, `cve-high`, `az-storage-public`…). Glob patterns allowed. |
| `target` | no | Glob matched (case-insensitive) against the finding's target, its URL hostname, its `host`/`ip` without port, and the resource part of the key. |
| `reason`, `owner` | yes | Who decided and why. |
| `expires` | yes | TOML date (`2027-03-31`, not quoted). Valid through that day. |
| `ticket` | no | Tracker reference. |

Behaviour during triage (all messages go to `gaps.txt`):

- invalid entries (missing `reason`/`owner`/`expires`, no `key`/`rule`, bad date) are ignored with a warning; a broken file never stops the run;
- an expired suppression no longer applies: `suppression expired on <date> for <key>`;
- a suppression expiring within 14 days, or more than a year ahead, is warned about;
- an entry that matched no finding is reported as a **stale suppression**, so the file stays clean.

`--check-config` validates the file too (same warnings, nothing applied).

## Environment variables

Most flags have an env fallback; the common ones:

| Variable | Equivalent |
|---|---|
| `SCOPE` | `-s` |
| `PHASES` | `-p` |
| `RUN_DATE` | `-d` |
| `SKIP_ACTIVE=1` | `-P` |
| `SKIP_CLOUD=1` / `SKIP_AZURE=1` | `-n` |
| `CLOUD_POSTURE=1` | `--cloud-posture` |
| `SAAS_POSTURE=1` | `--saas-posture` |
| `USE_PROWLER=1` | `--prowler` |
| `QUICK=1` / `QUICK=2` | `-q` / `-qq` |
| `TOP_PORTS` | `--top-ports` |
| `YES=1` | `-y` |
| `USE_DOCKER=1` | `-D` / `--docker` |
| `NO_VENV=1` | `--no-venv` |
| `SHODAN_API_KEY` / `HIBP_API_KEY` | `--shodan-key` / `--hibp-key` |
| `NVD_API_KEY` | CVE correlation fallback (phase 7) |
| `SCYLAX_ALERT_WEBHOOK` | `alert_webhook` |
