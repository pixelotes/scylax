# Installation & dependencies

Scylax itself is **pure Python standard library** — no `pip install` is required
to run the pipeline. What it needs are the external reconnaissance tools it
orchestrates. Every tool is optional in the sense that a missing tool degrades
the affected phase gracefully (and is recorded in `gaps.txt` /
`tool_failures.tsv`) rather than aborting the run — but coverage drops.

- Python 3.12+ (3.12 and 3.13 are tested in CI).
- The tools below, installed natively, via Docker (`--docker`), or baked into the
  [all-in-one image](#all-in-one-docker-image).

Run `python3 scylax.py --check-deps` at any time to see what is installed, which
mode (native vs. Docker) each tool will use, and the detected versions.

## Tools by role

### Core (required for a full non-cloud run)

Everything below is in Homebrew:

```bash
brew install nmap subfinder dnsx httpx nuclei amass gobuster gitleaks trufflehog theharvester
```

| Tool | Phase(s) | Role |
|---|---|---|
| `dig` | 2 | DNS records (ships with macOS; `brew install bind` otherwise) |
| `whois` | 2 | Registration / apex ownership (pre-installed on macOS) |
| `subfinder` | 1 | Passive subdomain enumeration |
| `amass` | 1, 9 | Passive subdomains + email intel (`amass intel -whois`) |
| `dnsx` | 2 | Bulk DNS resolution |
| `httpx` | 3, 5 | Live-host probing and tech fingerprint |
| `nmap` | 4, 4b, A/G/W | Port scan and service fingerprint |
| `nuclei` | 8 | Non-intrusive vulnerability templates |
| `gobuster` | C | Content discovery (optional phase) |
| `theharvester` | 9 | Corporate email enumeration |
| `gitleaks` / `trufflehog` | 9 | Secret scanning of public repos |

`dig` and `whois` normally come with macOS. If `dig` is missing: `brew install bind`.

### Not in Homebrew (optional → Docker)

```bash
docker pull spiderfoot/spiderfoot      # SpiderFoot — extra email intel (phase 9)
docker pull bberastegui/whatweb:latest # WhatWeb — web fingerprint (phase 5)
```

With `--docker`, Scylax runs these from the container. Without them, the relevant
sub-checks are skipped and noted in `gaps.txt`.

### Cloud / SaaS (opt-in — phases A/G/W/S only)

Install these **only if** you analyze those clouds/tenants:

```bash
brew install azure-cli awscli gh
brew install --cask google-cloud-sdk
pipx install prowler                    # deep CSPM, optional (needs cloud_posture)
```

- `gam` (Google Workspace, phase S) is not in brew:
  `bash <(curl -s -S -L https://gam-shortn.appspot.com/gam-install)`
- Authenticate before use: `az login` · `aws configure` · `gcloud auth login` ·
  `gh auth login`.

See [configuration.md](configuration.md) for how these phases are gated.

### API keys (environment, not brew)

```bash
export SHODAN_API_KEY=...   # phase 7 host lookups (CVE correlation works without it)
export HIBP_API_KEY=...     # phase 9 breach audit (optional)
export NVD_API_KEY=...      # CVE correlation fallback when *.shodan.io is blocked
```

XposedOrNot (phase 9) needs no key. For M365 (phase S) set `M365_TENANT_ID`,
`M365_CLIENT_ID`, `M365_CLIENT_SECRET`.

## Automatic virtual environment (`.venv`)

Some optional tools (theHarvester, SpiderFoot, Prowler) are Python packages. When
they are needed and not present on the system, Scylax offers to create and manage
a local `.venv` for them. Disable this with `--no-venv` (or `NO_VENV=1`) to use
only what is already on `PATH`.

## Docker mode (`--docker`)

Instead of installing native binaries, run supported tools from their official
containers:

```bash
# See which tools resolve to a container
python3 scylax.py --check-deps --docker

# Run the pipeline using containers for supported tools
python3 scylax.py -s scopes/acme.toml --docker
```

Docker mode needs a running Docker daemon. Tools without a container image
(or where native is preferred) still run natively.

## All-in-one Docker image

The repository ships a multi-stage [`Dockerfile`](../Dockerfile) that bakes in
every dependency (Go tools, Python tools, cloud CLIs). Component versions are
pinned for reproducible builds; override any with `--build-arg`.

```bash
# Core image: recon tools (no cloud CLIs)
docker build -t scylax:core --target core .

# Full image: core + azure-cli, awscli, google-cloud-sdk, gh, prowler
docker build -t scylax:full --target full .

# Run (mount a scopes dir and a runs dir)
docker run --rm -v "$PWD/scopes:/app/scopes" -v "$PWD/runs:/app/runs" \
  scylax:core -s scopes/acme.toml -P
```

CI builds the `core` target on every pull request, so a green build means the
image assembles cleanly.

## Verifying your setup

```bash
python3 scylax.py --doctor -s scopes/acme.toml   # everything at once: tools + scope + keys + egress + next step
python3 scylax.py --check-deps                   # just tools, mode, versions
python3 scylax.py -s scopes/acme.toml --check-config   # just validate the scope file
python3 -m unittest discover -s tests -v               # run the test suite (no network)
```

`--doctor` is the one-shot check: it runs the dependency table and the scope
validation together, lists which API-key integrations are active, shows your egress
IP, and prints the command to run next. It exits `0` when nothing blocks a run and
`1` otherwise, so it also works as a pre-flight gate in a script.
