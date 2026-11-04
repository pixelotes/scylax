"""Non-intrusive web probes that classify responses without downloading data.

Every probe reads at most a few KB (``Range`` request + capped read): enough
to recognise a CSV header, an API schema or an app-generated 404, never the
dataset itself.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Callable, List, Optional

from recon.runner import HttpResponse

PROBE_BYTES = 4096

# Column / key names that make an unauthenticated data file a personal-data or
# secret exposure rather than a mere information leak.
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)^(e-?mail|mail|othermails|upn|userprincipalname|displayname|"
    r"(first|last|given|sur|full)_?name|phone|mobile|address|birth(date|day)?|dob|"
    r"manager|jobtitle|employee\w*|entrydate|hiredate|terminationdate|lastdayofwork|"
    r"salary|iban|ssn|passport|national_?id|signinactivity|lastsignin\w*|"
    r"password|passwd|secret|token|api_?key|private_?key|credential\w*)$"
)

# Where API frameworks publish their own description.
API_SCHEMA_PATHS = ("/openapi.json", "/v3/api-docs", "/v2/api-docs", "/swagger.json", "/api/openapi.json")


@dataclass
class RootData:
    url: str
    content_type: str
    size: str
    columns: List[str]
    sensitive: List[str]


@dataclass
class ApiEndpoint:
    url: str
    status: int
    content_type: str
    size: str
    sensitive: List[str]


def total_size(resp: HttpResponse) -> str:
    """Full resource size from Content-Range (206) or Content-Length, else '?'."""
    cr = resp.headers.get("content-range", "")
    m = re.search(r"/(\d+)\s*$", cr)
    if m:
        return m.group(1)
    return resp.headers.get("content-length", "?") or "?"


def is_ingress_default_404(status: int, content_type: str, title: str, server: str) -> bool:
    """True for the generic 404 of an ingress / reverse proxy with no matching route.

    Anything else (JSON 404s from FastAPI/Spring/Express, custom HTML) means an
    application is listening and its other routes are worth checking.
    """
    if status != 404:
        return False
    ct = (content_type or "").lower()
    if "json" in ct:
        return False
    t = (title or "").strip().lower()
    return (not ct or "html" in ct) and (t in ("", "404 not found", "not found")) and (
        not server or "nginx" in server.lower() or "envoy" in server.lower() or "traefik" in server.lower()
    )


def _split_header(line: str) -> List[str]:
    delim = max((";", ",", "\t", "|"), key=line.count)
    return [c.strip().strip('"').strip("'") for c in line.split(delim) if c.strip()]


def sniff_root_data(url: str, resp: HttpResponse) -> Optional[RootData]:
    """Recognise a data file (CSV/TSV/JSON array/download) served at a URL."""
    if resp.status not in (200, 206):
        return None
    ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    disp = resp.headers.get("content-disposition", "").lower()
    body = resp.body.lstrip("﻿").lstrip()
    if "html" in ct or body[:15].lower().startswith(("<!doctype", "<html")):
        return None

    columns: List[str] = []
    if ct in ("text/csv", "text/tab-separated-values", "text/plain", "application/csv") or "attachment" in disp:
        first = body.splitlines()[0] if body else ""
        cols = _split_header(first)
        if len(cols) >= 2 and all(len(c) <= 64 for c in cols):
            columns = cols
        elif ct == "text/plain" and "attachment" not in disp:
            return None
    elif "json" in ct:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None  # truncated by the probe: fall back to key sniffing
        if isinstance(data, list) and data and isinstance(data[0], dict):
            columns = list(data[0].keys())
        elif data is None and body.startswith("[{"):
            columns = re.findall(r'"([A-Za-z_][\w-]{0,40})"\s*:', body[:2048])
        if not columns:
            return None
    elif ct in ("application/octet-stream", "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"):
        columns = []
    else:
        return None

    seen: List[str] = []
    for c in columns:
        if c not in seen:
            seen.append(c)
    sensitive = [c for c in seen if SENSITIVE_FIELD_RE.match(c.replace(" ", ""))]
    return RootData(url=url, content_type=ct or disp, size=total_size(resp), columns=seen, sensitive=sensitive)


def openapi_get_paths(schema_text: str) -> List[str]:
    """GET paths without path parameters from an OpenAPI/Swagger document."""
    try:
        doc = json.loads(schema_text)
    except json.JSONDecodeError:
        return []
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict):
        return []
    out = []
    for p, ops in paths.items():
        if isinstance(ops, dict) and "get" in ops and "{" not in p:
            out.append(p)
    return out


def discover_api(base_url: str, get: Callable[..., HttpResponse], max_endpoints: int = 25) -> tuple[str, List[ApiEndpoint]]:
    """Find a published API schema and check its parameterless GET endpoints.

    Returns (schema_url or "", endpoints). Each endpoint is fetched with a
    capped read: status, type and size only, never the dataset.
    """
    for path in API_SCHEMA_PATHS:
        schema_url = f"{base_url}{path}"
        resp = get(schema_url, timeout=8.0, verify_ssl=False, follow_redirects=False, max_bytes=256 * 1024)
        if resp.status != 200 or not re.search(r'"(openapi|swagger)"\s*:', resp.body):
            continue
        endpoints: List[ApiEndpoint] = []
        for ep in openapi_get_paths(resp.body)[:max_endpoints]:
            ep_url = urllib.parse.urljoin(base_url + "/", ep.lstrip("/"))
            r = get(ep_url, timeout=15.0, verify_ssl=False, follow_redirects=False, max_bytes=PROBE_BYTES)
            data = sniff_root_data(ep_url, r)
            endpoints.append(ApiEndpoint(
                url=ep_url,
                status=r.status,
                content_type=r.headers.get("content-type", "").split(";")[0],
                size=total_size(r),
                sensitive=data.sensitive if data else [],
            ))
        return schema_url, endpoints
    return "", []


def is_hash_label(host: str) -> bool:
    """First DNS label looks machine-generated (hex digest / UUID): an
    'unguessable URL' used instead of authentication."""
    label = host.split(".", 1)[0].lower()
    return bool(re.fullmatch(r"[0-9a-f]{24,64}", label) or re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", label))
