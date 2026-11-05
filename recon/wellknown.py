"""Well-known file pivots: security.txt (RFC 9116) and OpenID discovery.

Only two fixed paths are requested, on the scope's registered domains and (up to a cap)
on hosts already found live. Each response is read once, capped, and reduced to the
hostnames it names and a few facts about security.txt; the content itself is not kept.
Hostnames that belong to the scope but were missing from subdomain enumeration become
pivots for the auditor to look at.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable

SECURITY_TXT = "/.well-known/security.txt"
OIDC = "/.well-known/openid-configuration"
MAX_BYTES = 32768
DEFAULT_MAX_HOSTS = 100

_HOST_RE = re.compile(r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b")
_FIELD_RE = re.compile(r"^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$")


def hostnames(text: str, domains: Iterable[str]) -> set[str]:
    """Hostnames in ``text`` that are the scope domains or their subdomains."""
    doms = [d.lower() for d in domains]
    found = set()
    for m in _HOST_RE.findall(text or ""):
        h = m.lower()
        if any(h == d or h.endswith("." + d) for d in doms):
            found.add(h)
    return found


def analyse_security_txt(text: str, today: str) -> list[tuple[str, str, str]]:
    """(severity, code, problem) for a security.txt body; [] when it is fine."""
    fields: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = _FIELD_RE.match(line)
        if m:
            fields.setdefault(m.group(1).lower(), []).append(m.group(2))
    problems: list[tuple[str, str, str]] = []
    if "contact" not in fields:
        problems.append(("low", "no-contact", "security.txt has no Contact field"))
    expires = (fields.get("expires") or [""])[0][:10]
    if not expires:
        problems.append(("low", "no-expires", "security.txt has no Expires field (required by RFC 9116)"))
    elif re.match(r"\d{4}-\d{2}-\d{2}$", expires) and expires < today:
        problems.append(("low", "expired", f"security.txt expired on {expires}"))
    return problems


def _json_strings(node: Any) -> Iterable[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _json_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _json_strings(v)


def run(
    domains: list[str],
    live_hosts: list[str],
    known: set[str],
    fetch: Callable[..., Any],
    today: str,
    *,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> tuple[list[tuple[str, str, str, str, str, str, str]], list[tuple[str, str, str, str, str]]]:
    """Returns (findings, pivots).

    findings: severity, key, service, resource, title, detail, target
    pivots:   source_host, path, hostname, in_scope, known_subdomain
    """
    findings: list[tuple[str, str, str, str, str, str, str]] = []
    pivots: dict[tuple[str, str], tuple[str, str, str, str, str]] = {}
    known = set(known) | {d.lower() for d in domains}

    def pivot(source: str, path: str, names: set[str]) -> None:
        for n in sorted(names):
            pivots.setdefault((source, n), (source, path, n, "yes", "yes" if n in known else "no"))

    for d in domains:
        base = f"https://{d}"
        resp = fetch(base + SECURITY_TXT, timeout=8.0, verify_ssl=True, follow_redirects=True, max_bytes=MAX_BYTES)
        body = getattr(resp, "body", "") or ""
        if getattr(resp, "status", 0) == 200 and re.search(r"(?im)^\s*contact\s*:", body):
            for sev, code, problem in analyse_security_txt(body, today):
                findings.append((sev, f"wellknown:security-txt:{d}:{code}", "web", d, problem,
                                 f"{base}{SECURITY_TXT}", base + SECURITY_TXT))
            pivot(d, SECURITY_TXT, hostnames(body, domains))
        elif getattr(resp, "status", 0) in (404, 403, 200):
            findings.append(("info", f"wellknown:security-txt:{d}", "web", d,
                             "No security.txt (RFC 9116) published",
                             f"{base}{SECURITY_TXT} returned HTTP {getattr(resp, 'status', 0)} without a Contact field",
                             base + SECURITY_TXT))

    for url in sorted(set(live_hosts))[:max_hosts]:
        base = url.rstrip("/")
        host = re.sub(r"^https?://", "", base).split("/")[0]
        resp = fetch(base + OIDC, timeout=8.0, verify_ssl=False, follow_redirects=False, max_bytes=MAX_BYTES)
        if getattr(resp, "status", 0) != 200:
            continue
        try:
            doc = json.loads(resp.body)
        except (ValueError, TypeError):
            continue
        if isinstance(doc, dict) and "issuer" in doc:
            pivot(host, OIDC, hostnames(" ".join(_json_strings(doc)), domains))

    return findings, list(pivots.values())
