"""Anonymous-exposure checks for third-party SaaS tenants named after the organisation.

Scope of this module is deliberately narrow: for each candidate tenant (e.g.
``<org>.atlassian.net``) a handful of fixed, unauthenticated, read-only GET requests
test whether the tenant answers anonymous users. No wordlists, no payloads, no
guessing of identifiers. Requests ask for counts or a single record (maxResults=0/1)
and only the count / a yes-no is kept, never the data.

Currently: Atlassian Cloud (Jira, Confluence). Findings are candidates: some
tenants are public on purpose (open-source projects), the auditor decides.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

MAX_BYTES = 4096
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

Finding = tuple[str, str, str, str, str, str, str]  # severity, key, service, resource, title, detail, target
Fetch = Callable[..., Any]
Trace = Callable[[str, str], None]  # (reproducible command, summary of what came back)


def candidate_slugs(domains: Iterable[str], extra: Iterable[str] = ()) -> list[str]:
    """Tenant names to try: configured org names plus the first label of each public domain."""
    out: list[str] = []
    for raw in [*extra, *(d.split(".")[0] for d in domains if "." in d)]:
        s = raw.strip().lower()
        if _SLUG_RE.match(s) and s not in out:
            out.append(s)
    return out


@dataclass
class Probe:
    status: int
    data: Any  # parsed JSON or None


def _get(fetch: Fetch, url: str, trace: Trace) -> Probe:
    resp = fetch(url, timeout=10.0, verify_ssl=True, follow_redirects=False, max_bytes=MAX_BYTES)
    status = int(getattr(resp, "status", 0) or 0)
    data: Any = None
    if status == 200:
        try:
            data = json.loads(getattr(resp, "body", "") or "")
        except ValueError:
            data = None
    kind = "JSON" if data is not None else "non-JSON/empty"
    trace(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'", f"HTTP {status} ({kind})")
    return Probe(status, data)


def _count(data: Any, list_key: str) -> int:
    if not isinstance(data, dict):
        return 0
    total = data.get("total")
    if isinstance(total, int):
        return total
    items = data.get(list_key)
    return len(items) if isinstance(items, list) else 0


def check_atlassian(slug: str, fetch: Fetch, trace: Trace) -> tuple[list[tuple[str, str, str]], list[Finding]]:
    """Returns (tenants, findings); tenants are (slug, product, state)."""
    host = f"{slug}.atlassian.net"
    base = f"https://{host}"
    tenants: list[tuple[str, str, str]] = []
    findings: list[Finding] = []

    def add(sev: str, kind: str, title: str, detail: str, url: str) -> None:
        findings.append((sev, f"saas-exposure:{kind}:{slug}", "saas", host, title, detail, url))

    info = _get(fetch, f"{base}/rest/api/2/serverInfo", trace)
    jira = isinstance(info.data, dict) and ("deploymentType" in info.data or "baseUrl" in info.data)
    if jira:
        tenants.append((slug, "jira", "exists"))
        # 1. issues visible to anonymous users
        url = f"{base}/rest/api/2/search?maxResults=0"
        r = _get(fetch, url, trace)
        n = _count(r.data, "issues")
        if r.status in (404, 410):  # classic search endpoint retired: ask the new one for a single id
            url = f"{base}/rest/api/3/search/jql?jql=created%20%3E%3D%20-36500d&maxResults=1&fields=id"
            r = _get(fetch, url, trace)
            n = _count(r.data, "issues")
        if r.status == 200 and n > 0:
            add("high", "jira-issues", "Anonymous users can search Jira issues",
                f"{host}: issues readable without authentication ({n}{'+' if r.data and 'total' not in r.data else ''} visible)", url)
        # 2. projects
        url = f"{base}/rest/api/2/project/search?maxResults=1"
        r = _get(fetch, url, trace)
        n = _count(r.data, "values")
        if r.status == 200 and n > 0:
            add("high", "jira-projects", "Anonymous users can list Jira projects",
                f"{host}: {n} project(s) listed without authentication", url)
        # 3. users (the 'Browse users and groups' permission granted to Anyone)
        url = f"{base}/rest/api/2/user/picker?query=a&maxResults=1"
        r = _get(fetch, url, trace)
        if r.status == 200 and isinstance(r.data, dict) and r.data.get("users"):
            add("medium", "jira-users", "Anonymous users can search Jira user accounts",
                f"{host}: user picker answers without authentication", url)
        # 4. dashboards shared with everyone
        url = f"{base}/rest/api/2/dashboard/search?maxResults=1"
        r = _get(fetch, url, trace)
        if r.status == 200 and _count(r.data, "values") > 0:
            add("medium", "jira-dashboards", "Anonymous users can list Jira dashboards",
                f"{host}: dashboards shared publicly", url)

    url = f"{base}/wiki/rest/api/space?limit=1"
    conf = _get(fetch, url, trace)
    if conf.status == 200 and isinstance(conf.data, dict) and "results" in conf.data:
        tenants.append((slug, "confluence", "exists"))
        if conf.data.get("results"):
            add("high", "confluence-spaces", "Anonymous users can list Confluence spaces",
                f"{host}: spaces readable without authentication", url)
            url = f"{base}/wiki/rest/api/content?limit=1&type=page"
            pages = _get(fetch, url, trace)
            if pages.status == 200 and isinstance(pages.data, dict) and pages.data.get("results"):
                add("high", "confluence-pages", "Anonymous users can read Confluence pages",
                    f"{host}: page content API answers without authentication", url)
    elif conf.status in (401, 403):
        tenants.append((slug, "confluence", "exists (anonymous access denied)"))
    return tenants, findings
