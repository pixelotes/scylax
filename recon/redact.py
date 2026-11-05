"""Keep secrets out of evidence: console logs, commands.jsonl, warnings, gaps.

Register every secret value once (API keys, tokens); ``redact`` then masks those
exact values plus the usual ``?key=...`` / ``Authorization: Bearer ...`` shapes.
"""

from __future__ import annotations

import re
from typing import Iterable

_MIN_LEN = 6
_secrets: set[str] = set()

_URL_PARAM_RE = re.compile(
    r"(?i)([?&](?:key|api_?key|apikey|token|access_token|secret|client_secret|password)=)[^&\s\"'<>]+"
)
_AUTH_HEADER_RE = re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)[^\s\"']+")


def register(*values: str | None) -> None:
    for v in values:
        v = (v or "").strip()
        if len(v) >= _MIN_LEN:
            _secrets.add(v)


def register_many(values: Iterable[str | None]) -> None:
    register(*values)


def clear() -> None:
    _secrets.clear()


def redact(text: str) -> str:
    if not text:
        return text
    # longest first so a secret containing another one is fully masked
    for s in sorted(_secrets, key=len, reverse=True):
        if s in text:
            text = text.replace(s, "[REDACTED]")
    text = _URL_PARAM_RE.sub(r"\1[REDACTED]", text)
    return _AUTH_HEADER_RE.sub(r"\1[REDACTED]", text)
