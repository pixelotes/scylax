# Scylax documentation

Scylax is a pure-Python (stdlib-only) **Digital Attack Surface Cartography &
Reconnaissance** pipeline. It enumerates an organization's external footprint,
probes it non-intrusively, correlates the results against breach/CVE
intelligence, and produces diffable Markdown/HTML reports for continuous
threat-exposure management (CTEM).

The top-level [`README.md`](../README.md) is the quick overview. This folder is
the deep-dive reference.

## Contents

| Page | What it covers |
|---|---|
| [installation.md](installation.md) | Dependencies, the `.venv` manager, Docker mode, the all-in-one Docker image, and the `--doctor` / `--check-deps` health checks. |
| [configuration.md](configuration.md) | The scope `.toml` file: every key by section, environment variables, and `--check-config`. |
| [usage.md](usage.md) | CLI flags, phase selection, passive vs. active runs, authorization gates, and worked examples. |
| [phases.md](phases.md) | What each phase (1–9, A/G/W, S, C, T) does, its tools, and its mode. |
| [outputs.md](outputs.md) | The run directory layout, findings/diff/history model, the HTML dashboard, and the AI bundle. |
| [detection.md](detection.md) | How findings are produced: triage rules, subdomain takeover, sensitive-path probes, content discovery, and path traversal — and the non-intrusive boundary. |
| [plugins-and-architecture.md](plugins-and-architecture.md) | Module layout, the plugin/provider model, phase dependencies, and how to add a tool. |

## Five-minute start

```bash
# 1. Install the core tools (macOS / Homebrew)
brew install nmap subfinder dnsx httpx nuclei amass gobuster gitleaks trufflehog theharvester

# 2. Create a scope
cp scopes/example.toml scopes/acme.toml   # then edit domains, authorisation, owned IPs

# 3. Check what's installed and validate the scope
python3 scylax.py --check-deps
python3 scylax.py -s scopes/acme.toml --check-config

# 4. Passive-only first run (no active scanning)
python3 scylax.py -s scopes/acme.toml -P

# 5. Full run once you have written authorization
python3 scylax.py -s scopes/acme.toml
```

Or pick a [profile](usage.md#profiles) instead of listing phases by hand:

```bash
python3 scylax.py --profile list                      # see all presets
python3 scylax.py -s scopes/acme.toml --profile light # safe active recon, no port scans
```

Open `runs/acme/<date>/report.html` for the dashboard.

## Golden rules

- **Authorization is mandatory** for active phases. Set `authorised_by` and
  `authorisation_ref` in the scope (or pass `--authorised-by` / `--authorisation-ref`).
- **Cloud (A/G/W) and SaaS (S) annexes are opt-in** — they run only when their
  section is configured or the phase is named explicitly with `-p`.
- **Scylax is non-intrusive.** It does GET-based probing, signature-confirmed
  checks, and rate-limited scans. It does not do DAST, SQLi, brute-force, or any
  exploitation. See [detection.md](detection.md#the-non-intrusive-boundary).
- **Never port-scan what you don't own.** Keep `owned_ranges` / `owned_ips_file`
  current so CDN/SaaS/shared-cloud IPs are recorded but never scanned.
