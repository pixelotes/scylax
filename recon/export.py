"""Machine-readable exports: findings.jsonl and assets.jsonl (one JSON object per line).

For importing the run into a findings tracker (Faraday, Dradis, DefectDojo, a
spreadsheet) or scripting over it. Findings are candidates, flagged as such, with the
evidence text as collected; they carry no verdict.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Iterable


def write_findings_jsonl(
    run_dir: Path,
    rows: Iterable[tuple[str, str, str, str]],
    *,
    engagement: str,
    run_date: str,
    target_of: Callable[[str], str],
    phase_of: Callable[[str], str | None],
    tools_of: Callable[[str], tuple[str, ...]],
) -> int:
    """rows are (severity, key, title, evidence). Returns the number written."""
    n = 0
    with (run_dir / "findings.jsonl").open("w", encoding="utf-8") as f:
        for sev, key, title, evidence in rows:
            f.write(json.dumps({
                "type": "finding",
                "status": "candidate",
                "engagement": engagement,
                "run_date": run_date,
                "severity": sev,
                "key": key,
                "title": title,
                "evidence": evidence,
                "target": target_of(key),
                "phase": phase_of(key),
                "tools": list(tools_of(key)),
            }, ensure_ascii=False) + "\n")
            n += 1
    return n


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]


def write_assets_jsonl(run_dir: Path) -> int:
    """Hostnames, live web URLs and open TCP ports collected by the run."""
    out: list[dict] = []
    for h in _lines(run_dir / "osint" / "subdomains.txt"):
        out.append({"type": "hostname", "value": h})

    httpx_json = run_dir / "web" / "httpx_all.json"
    for line in _lines(httpx_json):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append({
            "type": "url",
            "value": item.get("url", ""),
            "status": item.get("status_code") or item.get("status-code"),
            "title": item.get("title", ""),
            "server": item.get("webserver", ""),
        })

    scan = run_dir / "scan"
    if scan.is_dir():
        for nm in sorted(scan.glob("full_*.nmap")):
            ip = nm.stem[len("full_"):]
            for line in nm.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
                if m:
                    out.append({"type": "port", "ip": ip, "port": int(m.group(1)), "proto": "tcp", "service": m.group(2)})

    with (run_dir / "assets.jsonl").open("w", encoding="utf-8") as f:
        for item in out:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    return len(out)
