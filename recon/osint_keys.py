"""Third-party OSINT API keys: collection from the scope file / environment and
generation of the provider config files that subfinder and amass read.

Keys live in the scope's [intelligence] section (or the environment variable of
the same name, upper-cased). They are written to a private, throw-away directory
for the duration of phase 1 and deleted afterwards, so they never end up in a
run's evidence folder.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, Dict

# Scope keys (section [intelligence]) read in addition to shodan_api_key / hibp_api_key.
INTEL_KEY_FIELDS: tuple[str, ...] = (
    "securitytrails_api_key",
    "virustotal_api_key",
    "binaryedge_api_key",
    "fullhunt_api_key",
    "chaos_api_key",
    "bevigil_api_key",
    "urlscan_api_key",
    "leakix_api_key",
    "netlas_api_key",
    "github_token",
    "passivetotal_username",
    "passivetotal_api_key",
    "censys_api_id",
    "censys_api_secret",
    "nvd_api_key",
)

# subfinder provider -> scope keys joined with ":" (its provider-config.yaml format)
_SUBFINDER: dict[str, tuple[str, ...]] = {
    "shodan": ("shodan_api_key",),
    "securitytrails": ("securitytrails_api_key",),
    "virustotal": ("virustotal_api_key",),
    "binaryedge": ("binaryedge_api_key",),
    "fullhunt": ("fullhunt_api_key",),
    "chaos": ("chaos_api_key",),
    "bevigil": ("bevigil_api_key",),
    "urlscan": ("urlscan_api_key",),
    "leakix": ("leakix_api_key",),
    "netlas": ("netlas_api_key",),
    "github": ("github_token",),
    "passivetotal": ("passivetotal_username", "passivetotal_api_key"),
    "censys": ("censys_api_id", "censys_api_secret"),
}

# amass data source -> (credential account name, {amass field: scope key}); amass has no Censys source
_AMASS: dict[str, tuple[str, dict[str, str]]] = {
    "Shodan": ("account", {"apikey": "shodan_api_key"}),
    "SecurityTrails": ("account", {"apikey": "securitytrails_api_key"}),
    "VirusTotal": ("account", {"apikey": "virustotal_api_key"}),
    "BinaryEdge": ("account", {"apikey": "binaryedge_api_key"}),
    "FullHunt": ("account", {"apikey": "fullhunt_api_key"}),
    "Chaos": ("account", {"apikey": "chaos_api_key"}),
    "BeVigil": ("account", {"apikey": "bevigil_api_key"}),
    "URLScan": ("account", {"apikey": "urlscan_api_key"}),
    "LeakIX": ("account", {"apikey": "leakix_api_key"}),
    "Netlas": ("account", {"apikey": "netlas_api_key"}),
    "GitHub": ("accountname", {"apikey": "github_token"}),
    "PassiveTotal": ("account", {"username": "passivetotal_username", "apikey": "passivetotal_api_key"}),
}


def _clean(value: object) -> str:
    return str(value or "").replace("\r", "").replace("\n", "").strip()


def collect_keys(scope: object, shodan_api_key: str = "") -> Dict[str, str]:
    """Scope [intelligence] keys, falling back to the same-named environment variable."""
    keys: dict[str, str] = {}
    scope_keys = getattr(scope, "intel_keys", {}) or {}
    for name in INTEL_KEY_FIELDS:
        value = _clean(scope_keys.get(name)) or _clean(os.environ.get(name.upper()))
        if value:
            keys[name] = value
    shodan = _clean(shodan_api_key) or _clean(getattr(scope, "shodan_api_key", "")) or _clean(
        os.environ.get("SHODAN_API_KEY")
    )
    if shodan:
        keys["shodan_api_key"] = shodan
    return keys


def _q(value: str) -> str:
    """YAML double-quoted scalar (JSON strings are valid YAML)."""
    return json.dumps(value)


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def write_configs(
    keys: Dict[str, str],
    dest: Path,
    path_for: Callable[[Path], str] = str,
) -> tuple[str | None, str | None, list[str]]:
    """Write subfinder's provider config and amass' config + datasources into ``dest``.

    ``path_for`` converts a host path into the path the tool sees (differs in docker mode).
    Returns (subfinder_config, amass_config, source_names); a config is None when no key
    applies to that tool. Key values are never returned or logged.
    """
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o700)

    sf_lines: list[str] = []
    sources: list[str] = []
    for provider, fields in _SUBFINDER.items():
        if all(f in keys for f in fields):
            sf_lines.append(f"{provider}: [{_q(':'.join(keys[f] for f in fields))}]")
            sources.append(provider)

    am_lines: list[str] = ["datasources:"]
    am_count = 0
    for source, (account, fields) in _AMASS.items():
        if all(scope_key in keys for scope_key in fields.values()):
            am_lines.append(f"  - name: {source}")
            am_lines.append("    creds:")
            am_lines.append(f"      {account}:")
            for field, scope_key in fields.items():
                am_lines.append(f"        {field}: {_q(keys[scope_key])}")
            am_count += 1

    sf_path = am_path = None
    if sf_lines:
        p = dest / "subfinder-provider.yaml"
        _write_private(p, "\n".join(sf_lines) + "\n")
        sf_path = path_for(p)
    if am_count:
        ds = dest / "amass-datasources.yaml"
        _write_private(ds, "\n".join(am_lines) + "\n")
        cfg = dest / "amass-config.yaml"
        _write_private(cfg, f"options:\n  datasources: {_q(path_for(ds))}\n")
        am_path = path_for(cfg)
    return sf_path, am_path, sources
