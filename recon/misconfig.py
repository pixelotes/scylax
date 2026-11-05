"""Optional wrapper around Intigriti's misconfig-mapper (opt-in, phase E).

misconfig-mapper checks a company name against ~20 SaaS services using templates.
Scylax keeps it inside its intrusiveness ceiling by construction:

- name permutations are always off (``-permutations false``): only the exact
  tenant names Scylax derived are tried, never a generated list of variants;
- the services passed to the tool are selected here from its own services.json and
  limited to plain GET templates without request body or custom headers, so
  templates that POST a payload (e.g. GraphQL introspection) are never run;
- templates are read from a local folder and never auto-updated by Scylax;
- a delay between requests is always set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

Finding = tuple[str, str, str, str, str, str, str]  # severity, key, service, resource, title, detail, target


def find_templates_dir(configured: str = "") -> Path | None:
    """Folder holding services.json: the configured one, else ./templates."""
    for cand in ([Path(configured).expanduser()] if configured else []) + [Path.cwd() / "templates"]:
        if (cand / "services.json").is_file():
            return cand
    return None


def load_services(templates_dir: Path) -> list[dict[str, Any]]:
    data = json.loads((templates_dir / "services.json").read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def is_plain_get(service: dict[str, Any]) -> bool:
    req = service.get("request") or {}
    return (
        str(req.get("method", "")).upper() == "GET"
        and not req.get("body")
        and not req.get("headers")
    )


def select_services(
    services: list[dict[str, Any]], wanted: Iterable[str] = ()
) -> tuple[list[dict[str, Any]], list[str]]:
    """Plain-GET services to run (all of them, or those matching ``wanted`` by name or id)
    plus a list of requested services that were refused or unknown."""
    wanted = [w.strip().lower() for w in wanted if w.strip()]
    chosen: list[dict[str, Any]] = []
    refused: list[str] = []
    for w in wanted:
        matches = [
            s for s in services
            if str(s.get("id")) == w or str((s.get("metadata") or {}).get("service", "")).lower() == w
        ]
        if not matches:
            refused.append(f"{w} (unknown service)")
        for s in matches:
            if is_plain_get(s):
                chosen.append(s)
            else:
                refused.append(f"{w} (id {s.get('id')}: not a plain GET template)")
    if not wanted:
        chosen = [s for s in services if is_plain_get(s)]
        refused = [
            f"id {s.get('id')} {(s.get('metadata') or {}).get('serviceName', '')} (not a plain GET template)"
            for s in services if not is_plain_get(s)
        ]
    seen: set[Any] = set()
    unique = [s for s in chosen if not (s.get("id") in seen or seen.add(s.get("id")))]
    return unique, refused


def request_count(services: list[dict[str, Any]]) -> int:
    return sum(len((s.get("request") or {}).get("path") or [""]) for s in services)


def build_args(slug: str, templates_dir: Path, service_ids: list[Any], delay_ms: int) -> list[str]:
    """misconfig-mapper arguments for one tenant name (permutations off, JSON lines, delay)."""
    return [
        "-target", slug,
        "-service", ",".join(str(i) for i in service_ids),
        "-permutations", "false",
        "-delay", str(max(1, int(delay_ms))),
        "-timeout", "7000",
        "-max-redirects", "3",
        "-verbose", "0",
        "-output-json",
        "-templates", str(templates_dir),
    ]


def parse_results(stdout: str, slug: str) -> tuple[list[Finding], list[tuple[str, str, str]]]:
    """JSON-lines results -> (findings for vulnerable instances, tenants that merely exist)."""
    findings: list[Finding] = []
    tenants: list[tuple[str, str, str]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        meta = (r.get("service") or {}).get("metadata") or {}
        name = meta.get("serviceName") or meta.get("service") or "service"
        url = r.get("url", "")
        sid = r.get("serviceid", "")
        if r.get("vulnerable"):
            refs = meta.get("references") or []
            detail = f"{meta.get('description', name)} at {url} (misconfig-mapper template {sid})"
            if refs:
                detail += f"; ref: {refs[0]}"
            findings.append(("medium", f"saas-exposure:mm-{sid}:{slug}", "saas", url, f"{name}: possible misconfiguration",
                             detail, url))
        elif r.get("exists"):
            tenants.append((slug, str(meta.get("service", name)), f"exists ({url})"))
    return findings, tenants
