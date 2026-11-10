"""Keyless CVE correlation fallback: NIST NVD API 2.0 + CISA KEV catalogue.

Used when Shodan CVEDB is unreachable (e.g. egress firewalls blocking *.shodan.io).
NVD allows ~5 requests / 30 s without a key; set NVD_API_KEY for ~50 / 30 s.
"""

from __future__ import annotations

import os
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Set

from recon.runner import http_get_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_last_call = 0.0
_rate_lock = threading.Lock()  # phases may run concurrently (--jobs): keep the NVD pace global


def cpe_to_23(cpe: str) -> str | None:
    """Convert an nmap CPE (``cpe:/a:vendor:product:version``) to a full CPE 2.3 name.

    Returns None when the CPE has no version: an unversioned product matches
    every CVE ever published for it, which is noise, not correlation.
    """
    c = cpe.strip()
    if c.startswith("cpe:2.3:"):
        parts = c[len("cpe:2.3:"):].split(":")
    elif c.startswith("cpe:/"):
        parts = c[len("cpe:/"):].split(":")
    else:
        return None
    if len(parts) < 4 or not parts[3] or parts[3] in ("*", "-"):
        return None
    parts = (parts + ["*"] * 11)[:11]
    return "cpe:2.3:" + ":".join(p or "*" for p in parts)


def _score(metrics: Dict[str, Any]) -> tuple[str, bool]:
    """Best available CVSS base score and whether it is v3+ (v2-only CVEs are legacy noise)."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            score = primary.get("cvssData", {}).get("baseScore")
            return (str(score) if score is not None else ""), key != "cvssMetricV2"
    return "", False


def nvd_cves_for_cpe(cpe23: str, api_key: str | None = None) -> tuple[int, List[Dict[str, Any]]]:
    """Return (http_status, [{cve_id, cvss, summary}]) for a versioned CPE 2.3 name."""
    global _last_call
    api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "").strip()
    gap = 0.7 if api_key else 6.5
    with _rate_lock:
        wait = _last_call + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()

    url = f"{NVD_URL}?cpeName={urllib.parse.quote(cpe23, safe=':*')}"
    headers = {"apiKey": api_key} if api_key else None
    st, data = http_get_json(url, headers=headers, timeout=60)
    if st in (0, 403, 429, 503):
        # NVD throttles with 403/429/503 and drops slow connections: one backoff retry
        with _rate_lock:
            time.sleep(gap * 2)
            _last_call = time.monotonic()
        st, data = http_get_json(url, headers=headers, timeout=60)
    items: List[Dict[str, Any]] = []
    if st != 200 or not isinstance(data, dict):
        return st, items
    for vuln in data.get("vulnerabilities") or []:
        cve = vuln.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        cvss, modern = _score(cve.get("metrics") or {})
        if not modern:
            continue
        desc = next(
            (d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
            "",
        )
        items.append({"cve_id": cid, "cvss": cvss, "is_kev": False, "summary": desc.strip()})
    return st, items


def load_kev_ids() -> Set[str]:
    """CVE IDs in the CISA Known Exploited Vulnerabilities catalogue (empty on failure)."""
    st, data = http_get_json(KEV_URL, timeout=60)
    if st != 200 or not isinstance(data, dict):
        return set()
    return {
        str(v.get("cveID")).strip()
        for v in data.get("vulnerabilities") or []
        if v.get("cveID")
    }
