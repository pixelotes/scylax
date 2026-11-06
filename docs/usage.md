# Usage

```bash
python3 scylax.py -s scopes/<name>.toml [options]
```

With no `-p`, Scylax runs the full default phase list. Cloud (A/G/W), SaaS (S),
and content discovery (C) are **opt-in** and auto-skip unless configured or named
explicitly. See [phases.md](phases.md) for what each phase does.

## CLI flags

| Flag | Env | Meaning |
|---|---|---|
| `-s`, `--scope` | `SCOPE` | Scope TOML file (default `scopes/default.toml`). |
| `--profile` | `PROFILE` | Phase-group preset (sets phases + posture toggles). See [Profiles](#profiles). `--profile list` prints them. |
| `-p`, `--phases` | `PHASES` | Space-separated phases to run (default: all). An explicit `-p` overrides a profile's phases. |
| `-d`, `--date` | `RUN_DATE` | Run folder name (default: today, `YYYY-MM-DD`). |
| `-P`, `--passive-only` | `SKIP_ACTIVE=1` | Skip active phases (3, 4, 4b, 5, 8, A, G, W, C). |
| `-n`, `--no-cloud` | `SKIP_CLOUD=1` | Skip cloud annexes A, G, W. |
| `--cloud-posture` | `CLOUD_POSTURE=1` | Enable CSPM checks in A/G/W. |
| `--saas-posture` | `SAAS_POSTURE=1` | Enable the SaaS audit (phase S). |
| `--prowler` | `USE_PROWLER=1` | Deep Prowler CSPM (needs cloud posture). |
| `-q`, `--quick` | `QUICK=1/2` | `-q` top-1000 ports, `-qq` top-100 (default: all 65535). |
| `--top-ports N` | `TOP_PORTS` | Scan the top N ports. |
| `-y`, `--yes` | `YES=1` | Don't prompt before active phases. |
| `--authorised-by` | `AUTHORISED_BY` | Override the authorization string. |
| `--authorisation-ref` | `AUTHORISATION_REF` | Override the authorization reference. |
| `-D`, `--docker` | `USE_DOCKER=1` | Run supported tools from containers. |
| `--shodan-key` | `SHODAN_API_KEY` | Shodan API key (phase 7). |
| `--hibp-key` | `HIBP_API_KEY` | HaveIBeenPwned key (phase 9). |
| `--check-deps` | — | Show tool availability (native/Docker) and exit. |
| `--check-config` | — | Validate the scope file and exit. |
| `--report-only DIR` | — | Rebuild `report.md`/`.html` for an existing run and exit. |
| `--report-from-bundle FILE` | — | Rebuild the reports from an `ai_bundle.md` and exit. |
| `--export DIR` | — | Write `report_data.json` (assets + findings + relations) for an existing run and exit. |
| `--no-venv` | `NO_VENV=1` | Don't create/use a managed `.venv`. |

## Selecting phases

The default phase string is:

```
1 2 3 4 4b 5 6 7 8 9 A G W S C E T
```

Pass a subset with `-p`. Examples:

```bash
# Passive reconnaissance only
python3 scylax.py -s scopes/acme.toml -p "1 2 6 9 T"

# Just re-triage an existing run's outputs (no scanning)
python3 scylax.py -s scopes/acme.toml -p "T"

# Default run plus content discovery
python3 scylax.py -s scopes/acme.toml -p "1 2 3 4 4b 5 6 7 8 9 C T"

# Azure annex + triage only
python3 scylax.py -s scopes/acme.toml -p "A T"
```

Naming a normally-opt-in phase (A/G/W/S/C/E) with `-p` forces it to run even if its
section is empty — e.g. `-p "A T"` queries every subscription in the active Azure
tenant.

## Profiles

A **profile** is a named phase group that also sets the matching posture toggles,
so you don't have to spell out phases and `--cloud-posture` / `--saas-posture` by
hand. Select one with `--profile <name>` (or `PROFILE=<name>`); `--profile list`
prints every profile with its phases and description.

```bash
python3 scylax.py -s scopes/acme.toml --profile light
python3 scylax.py -s scopes/acme.toml --profile blueteam
python3 scylax.py --profile list
```

| Profile | Phases | Toggles | Purpose |
|---|---|---|---|
| `passive` | `1 2 6 7 9` | — | Zero-touch OSINT; no authorization needed. |
| `light` | `1 2 3 5 6 7 8 9 E` | — | Safe active recon, **no** nmap port scans. Good for frequent/CTEM runs. |
| `external` | `1 2 3 4 4b 5 6 7 8 9 C E` | — | Full external attack surface (attacker's view). |
| `blueteam` | `1 2 6 7 9 E A G W S` | cloud + SaaS posture | Defender posture of your own cloud/SaaS tenants; minimal scanning. |
| `purpleteam` | `1 2 3 4 4b 5 6 7 8 9 A G W C E S` | cloud + SaaS posture | Everything: offense + defense. |
| `full` | all | cloud + SaaS posture + Prowler | Maximum coverage, deep CSPM. |
| `web` | `2 3 5 6 8 C` | — | Web-facing surface only. |
| `cloud` | `A G W` | cloud posture | Cloud annexes only. |
| `intel` | `6 7 9` | — | Historical URLs, Shodan/CVE, breaches, secret leaks. |
| `saas` | `E S` | SaaS posture | Anonymous exposure + authenticated SaaS posture. |

Aliases: `osint → passive`, `redteam`/`attacker → external`, `leaks → intel`.

Behavior:

- Phase `T` (triage/report) is always appended.
- A profile treats its phases as **explicit**, so opt-in phases (cloud `A/G/W`,
  content `C`, SaaS exposure `E`) run even without provider config — e.g.
  `blueteam` queries the active Azure tenant.
- Posture toggles (`cloud_posture`, `saas_posture`, `use_prowler`) are turned on
  as the profile specifies; a scope value or CLI flag that enables them still
  applies too.
- An explicit `-p` **overrides** the profile's phase list (the toggles still
  apply). Combine with other flags freely, e.g. `--profile external -q -y`.

## Authorization gate

Active phases (3, 4, 4b, 5, 8, A, G, W, C) require authorization. Scylax checks
that `authorised_by` and `authorisation_ref` are set (in the scope or via
`--authorised-by` / `--authorisation-ref`) and then **prompts for confirmation**
before the first active phase. To run unattended, pass `-y` (or `YES=1`).

Use `-P` (passive-only) for a first pass that does no active scanning at all.

## Worked examples

```bash
# First contact: validate, then passive-only
python3 scylax.py -s scopes/acme.toml --check-config
python3 scylax.py -s scopes/acme.toml -P

# Full monthly run (authorized), unattended
python3 scylax.py -s scopes/acme.toml -y

# Fast ad-hoc check (top 1000 ports), no cloud
python3 scylax.py -s scopes/acme.toml -q -n -y

# Full run including the Azure annex with posture checks
python3 scylax.py -s scopes/acme.toml --cloud-posture -p "1 2 3 4 4b 5 6 7 8 9 A C T" -y

# Containerized tools instead of native binaries
python3 scylax.py -s scopes/acme.toml --docker -y
```

### Running against a scope kept outside the repo

`owned_ips_file` and other file paths resolve relative to the scope file, so you
can keep private scopes and runs in a separate folder. Set `runs_dir` in the
scope (or `cd` into the folder where you want `runs/`):

```bash
cd ~/engagements/acme
python3 /path/to/scylax/scylax.py -s scopes/acme.toml -y
```

## Re-generating reports

No re-scan needed:

```bash
# Rebuild report.md + report.html from an existing run's raw outputs
python3 scylax.py --report-only runs/acme/2026-11-04

# Rebuild the reports from just the AI bundle
python3 scylax.py --report-from-bundle runs/acme/2026-11-04/ai_bundle.md

# Write the consolidated report_data.json contract (assets + findings + relations)
python3 scylax.py --export runs/acme/2026-11-04
```

`report_data.json` is produced on every run too; `--export` just regenerates it on
its own. See [outputs](outputs.md#the-consolidated-export-report_datajson) for the schema.

## When a run is interrupted or a phase fails

The pipeline is built so you never lose work:

- **A phase whose code crashes** is contained — the remaining phases still run, and
  the crash is recorded in `tool_failures.tsv` so triage marks that phase's findings
  *not re-checked*, never *resolved*. The run finishes and still produces a report.
- **Ctrl-C** stops cleanly and still builds a report from the evidence collected so
  far (exit code `130`), instead of leaving the run half-written with no report.
- Either way, Scylax prints the exact **recovery commands** on exit:

```bash
# continue the phases that didn't finish (completed phases are skipped)
python3 scylax.py -s scopes/acme.toml -d 2026-11-04 --resume

# or just rebuild the report from whatever was collected
python3 scylax.py --report-only runs/acme/2026-11-04
```

## Monthly runs (CTEM)

Scylax is built for continuous threat-exposure management: run it on a schedule
and read the diff.

- Use a fresh `runs/<scope>/<date>/` per run so `diff.md` and
  `findings_history.json` have a baseline to compare against.
- Keep `owned_ips_file` current (e.g. an Azure public-IP export) so
  CDN/SaaS/shared-cloud IPs are recorded but never scanned.
- Prefer a **full** run (no `-q`/`-qq`) once a month; quick modes are for ad-hoc
  checks.
- Export `NVD_API_KEY` when `*.shodan.io` is blocked — CVE correlation then uses
  NVD at roughly 10× the keyless rate.
- Set `alert_webhook` to get new/reappeared high & critical findings pushed to
  Teams after each run.

See [outputs.md](outputs.md) for how the diff classifies findings across runs.
