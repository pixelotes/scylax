# Plugins & architecture

## Module layout

```text
scylax.py                 Thin entrypoint → recon.cli.main()
recon/
  cli.py                  Argument parsing, preflight, phase dispatch
  config.py               ScopeConfig, RunContext, phase gating, scope validation
  deps.py                 DependencyManager + PHASE_DEPENDENCIES
  runner.py               Command execution, logging, tool-failure recording, http_get
  scope.py                ScopeGuard — ownership allowlist enforcement
  webprobe.py             Native HTTP probing helpers
  nvd.py                  NVD/CVE correlation
  takeover.py             Subdomain-takeover fingerprints
  sensitive_paths.py      Curated sensitive-path probe (nuclei fallback)
  notify.py               Teams/JSON webhook alerts
  ai_bundle.py            Build/parse ai_bundle.md; rebuild reports from it
  report.py               report.md / report.html generation
  venv_manager.py         Optional managed .venv for Python tools
  plugins/
    base.py               Plugin, PluginKind, PluginStatus
    __init__.py           The plugin registry (one Plugin per tool)
  phases/
    osint.py              Phases 1, 2, 6, 7, 9
    active.py             Phases 3, 4, 4b, 5, 8
    cloud.py              Phases A, G, W
    content.py            Phase C
    saas.py               Phase S
    triage.py             Phase T
  data/
    content_discovery.txt Bundled content-discovery wordlist
  saas/                   SaaS provider audit modules
```

A run flows: `cli.main` → load `ScopeConfig` → build `RunContext` → `preflight`
(deps + authorization) → dispatch each requested phase → phase T reads all raw
outputs and writes findings/diff/reports.

## The plugin model

Every external tool is a `Plugin` (`recon/plugins/base.py`), registered in
`recon/plugins/__init__.py`. A plugin declares how to find the tool, how to run it
natively or in Docker, and how to install it.

```python
@dataclass
class Plugin:
    id: str                      # "nuclei"
    name: str                    # "Nuclei"
    kind: PluginKind             # BINARY | DOCKER | API | HYBRID
    description: str
    phases: tuple[str, ...]      # phases that use it, e.g. ("8",)
    required_env: tuple[str, ...] # env vars for API plugins
    native_bin: str | None       # binary name on PATH
    version_args: tuple[str, ...] # how to print its version
    docker_image: str | None     # official image for Docker mode / fallback
    prefer_docker_when_missing: bool  # auto-fall back to Docker if no native binary
    install_macos: str           # shown by --check-deps
    install_linux: str
    custom_checker: Callable | None   # for non-standard availability checks (gh auth, gam)
```

### Plugin kinds

| Kind | Meaning | Examples |
|---|---|---|
| `BINARY` | Native executable | `nmap`, `dig`, `whois`, `subfinder`, `dnsx`, `httpx` |
| `DOCKER` | Can run containerized as primary or fallback | `amass`, `nuclei`, `whatweb`, `gobuster`, `gitleaks`, `trufflehog`, `theharvester`, `spiderfoot`, `prowler` |
| `API` | Remote HTTP API (needs `required_env`, or public) | `shodan`, `hibp`, `xposedornot`, `m365_graph` |
| `HYBRID` | CLI that also fronts an API | `gh`, `az`, `gcloud`, `aws` |

### Availability & command building

- `check_availability(use_docker)` returns `(available, provider, detail)` where
  provider is `native`, `docker`, `api`, or `missing`. API plugins check their
  `required_env`; others check `PATH`, then Docker.
- `build_cmd(args, use_docker, mount_dir)` returns the exact argv — either the
  native binary or a `docker run` invocation. For cloud tools it mounts the host
  credential dirs (`~/.azure`, `~/.config/gcloud`, `~/.aws`) and rewrites
  run-directory paths to the container's `/data` mount.
- `DependencyManager` (`recon/deps.py`) wraps the registry: `is_available(id)`,
  `build_cmd(id, args)`, and the `--check-deps` report.

## Phase dependencies

`PHASE_DEPENDENCIES` in `recon/deps.py` maps each phase to
`(required, optional)` tool tuples:

```python
PHASE_DEPENDENCIES = {
    "1":  ((),            ("subfinder", "amass")),
    "2":  (("dig","whois"), ("dnsx", "hibp")),
    "3":  ((),            ("httpx",)),
    "4":  (("nmap",),     ()),
    "4b": (("nmap",),     ()),
    "5":  ((),            ("httpx", "whatweb")),
    "6":  ((),            ("hibp",)),
    "7":  ((),            ("shodan",)),
    "8":  ((),            ("nuclei",)),
    "9":  ((),            ("theharvester","amass","spiderfoot","hibp","xposedornot","trufflehog","gh")),
    "A":  ((),            ("az","nmap","prowler")),
    "G":  ((),            ("gcloud","nmap","prowler")),
    "W":  ((),            ("aws","nmap","prowler")),
    "S":  ((),            ("m365_graph","gh","gam")),
    "C":  ((),            ("gobuster",)),
    "T":  ((),            ()),
}
```

- **Required** missing → the phase is skipped and the gap recorded. Only 2, 4, 4b
  have hard requirements.
- **Optional** missing → the phase runs with reduced coverage (noted in
  `gaps.txt`).
- A tool that **fails at runtime** is recorded in `tool_failures.tsv` so the diff
  marks its findings "not re-checked" rather than "resolved".

## ScopeGuard — ownership enforcement

`recon/scope.py` builds an allowlist from `owned_ranges`, `owned_ips_file`,
`hvt_ips`, and any cloud `*_inventory_file`. Before any active scan, a target must
pass the guard; auto-discovered IPs outside it are written to
`osint/skipped_targets.tsv` and never scanned. This is the mechanism that keeps
Scylax from port-scanning CDNs, SaaS, or shared-cloud infrastructure that merely
resolves under your domains.

## Adding a new tool

1. Add a `Plugin(...)` entry to the registry in `recon/plugins/__init__.py`
   (set `kind`, `native_bin`/`docker_image`, `version_args`, and the `install_*`
   strings so `--check-deps` is helpful).
2. Reference it from the phase code via `dm.is_available("<id>")` and
   `dm.build_cmd("<id>", [...])`, and run it through `ev(...)` so the command,
   exit code, duration, and output are logged and runtime failures are recorded.
3. List it in the relevant phase's `PHASE_DEPENDENCIES` tuple (required or
   optional).
4. If it produces findings, add a triage rule in `recon/phases/triage.py` with a
   stable key prefix, and map that prefix to its confirming tool(s) so the diff
   handles it correctly.
5. Add a test under `tests/` (mock the tool/network — the suite runs offline).

## Testing

The suite is pure offline (synthetic data, all tools/network mocked):

```bash
python3 -m unittest discover -s tests -v
```

A smoke test also guards against committing client data to the public repo. CI
runs the suite on Python 3.12 and 3.13 and builds the `core` Docker image on every
pull request.
