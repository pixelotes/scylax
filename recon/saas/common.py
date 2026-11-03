"""Shared helpers for SaaS posture modules (Microsoft 365 / Entra ID, GitHub, Google Workspace).

Contract used by every provider module in this package::

    def run(ctx: RunContext, log: Logger, out_dir: Path) -> list[Finding]

* ``out_dir`` is ``<run>/saas/<provider>``; raw API exports go under ``out_dir / "raw"``.
* Providers must be read-only (GET requests / list commands only).
* Missing credentials are NOT an error: log a warning via ``log.warn(...)`` and return ``[]``.
* Never write secrets (client secrets, tokens) to logs, console records or raw files.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Finding:
    """One posture finding. Same columns as ``<cloud_dir>/posture_findings.tsv``."""

    severity: str  # one of SEVERITIES (lowercase)
    key: str  # stable across runs, e.g. "m365-ca-no-mfa-all"
    service: str  # e.g. "EntraID", "ConditionalAccess", "GitHub", "Workspace"
    resource: str  # affected object ("tenant", "org/repo", "user@domain", ...)
    title: str
    detail: str = ""
    iso: str = ""  # optional ISO 27001:2022 Annex A controls, e.g. "A.8.5, A.5.16"

    def row(self) -> tuple[str, str, str, str, str, str]:
        sev = self.severity.lower()
        if sev not in SEVERITIES:
            sev = "info"
        detail = self.detail.strip()
        if self.iso:
            detail = f"{detail} [ISO 27001: {self.iso}]".strip()
        clean = lambda s: re.sub(r"[\t\r\n]+", " ", str(s))
        return (sev, clean(self.key), clean(self.service), clean(self.resource), clean(self.title), clean(detail))


def redact(text: str, *secrets: str) -> str:
    """Remove secret values and bearer tokens from text destined for logs/evidence."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1***", text)
    text = re.sub(r"(?i)(client_secret=)[^&\s]+", r"\1***", text)
    text = re.sub(r"(?i)(access_token\"?\s*[:=]\s*\"?)[A-Za-z0-9._\-]+", r"\1***", text)
    return text


def http_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    form: Mapping[str, str] | None = None,
    timeout: float = 60.0,
    retries: int = 3,
) -> tuple[int, Any]:
    """Minimal stdlib HTTP client returning ``(status, parsed_json_or_text)``.

    Retries on 429/5xx honouring ``Retry-After``. Status 0 means a network error.
    """
    data = None
    hdrs = {"User-Agent": "recon-pipeline/1.0", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if form is not None:
        from urllib.parse import urlencode

        data = urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    ctx = ssl.create_default_context()
    last: tuple[int, Any] = (0, None)
    for attempt in range(max(1, retries)):
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, _parse(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            last = (exc.code, _parse(raw))
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                try:
                    wait = float(exc.headers.get("Retry-After", 2 ** attempt))
                except (TypeError, ValueError):
                    wait = 2 ** attempt
                time.sleep(min(wait, 30))
                continue
            return last
        except Exception as exc:  # network/DNS/timeout
            last = (0, str(exc))
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    return last


def _parse(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def save_raw(out_dir: Path, name: str, data: Any) -> Path:
    """Persist raw API output as evidence (``out_dir/raw/<name>``). Caller must pass redacted data."""
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / name
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        path.write_text(str(data), encoding="utf-8")
    return path


def cap_list(items: list[str], n: int = 10) -> str:
    """Join up to ``n`` items, appending ``(+N more)`` — keeps finding details short."""
    shown = ", ".join(items[:n])
    return f"{shown} (+{len(items) - n} more)" if len(items) > n else shown

