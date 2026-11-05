"""Machine-readable exports.

Two shapes, for two jobs:

* ``findings.jsonl`` / ``assets.jsonl`` — one JSON object per line, for importing
  the run into a findings tracker (Faraday, Dradis, DefectDojo, a spreadsheet) or
  scripting over it. Findings are candidates, flagged as such, with the evidence
  text as collected; they carry no verdict.
* ``report_data.json`` — a single consolidated document (metadata, KPIs, the asset
  inventory, every finding, and the explicit many-to-many asset<->finding
  relations), versioned with ``schema_version``. This is the stable **contract**
  for a separate, human-curated report generator built on top of Scylax.
"""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List

from recon.assets import SEV_RANK, asset_label, asset_ports, asset_product


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


# =====================================================================
# Consolidated export (report_data.json) — the report-generator contract
# =====================================================================

# Bump the MINOR version for backwards-compatible additions (new fields), the
# MAJOR version when an existing field changes meaning or is removed. Consumers
# should check the major component and ignore unknown fields.
SCHEMA_VERSION = "1.0"

_SEV_BY_RANK = {v: k for k, v in SEV_RANK.items()}


def _sorted_list(value: Any) -> List[str]:
    """A set/iterable of strings as a sorted, de-duplicated list."""
    return sorted({str(v) for v in (value or []) if str(v)})


def _worst_severity(findings: List[Dict[str, Any]]) -> str:
    rank = min((SEV_RANK.get(f.get("severity", "INFO").upper(), 4) for f in findings),
               default=4)
    return _SEV_BY_RANK.get(rank, "INFO")


def _finding_id(finding: Dict[str, Any], index: int) -> str:
    """A stable per-run id for a finding: its key, or a positional fallback."""
    return finding.get("key") or f"finding-{index:04d}"


def _cve_entry(cve: Dict[str, Any]) -> Dict[str, Any]:
    """A trimmed CVE record for the export (drops unknown/raw fields)."""
    out: Dict[str, Any] = {}
    for src in ("cve", "cvss", "service", "version", "port"):
        val = str(cve.get(src, "")).strip()
        if val and val != "-":
            out[src] = val
    out["is_kev"] = bool(cve.get("is_kev"))
    return out


def build_report_data(data: Any) -> Dict[str, Any]:
    """Build the consolidated export document from a built ``RunData``.

    Assets and findings must already be correlated (``RunData`` does this via
    :func:`recon.assets.build_assets` in its constructor), so this only reshapes
    the in-memory objects into a stable, versioned JSON structure.
    """
    # Map each finding (by identity) to a stable id so relations can reference it.
    finding_ids: Dict[int, str] = {}
    findings_out: List[Dict[str, Any]] = []
    for i, f in enumerate(getattr(data, "findings", [])):
        fid = _finding_id(f, i)
        finding_ids[id(f)] = fid
        findings_out.append({
            "id": fid,
            "key": f.get("key", ""),
            "severity": f.get("severity", "INFO").upper(),
            "title": f.get("title", ""),
            "evidence": f.get("evidence", ""),
            "target": f.get("target", ""),
            "asset_id": f.get("asset_id", ""),
            "asset_ids": list(f.get("asset_ids", [])),
            "asset_keys": list(f.get("asset_keys", [])),
        })

    assets_out: List[Dict[str, Any]] = []
    for a in getattr(data, "assets", []):
        a_findings = a.get("findings", [])
        fids = [finding_ids[id(f)] for f in a_findings if id(f) in finding_ids]
        assets_out.append({
            "id": a.get("id", ""),
            "type": a.get("prefix", ""),
            "type_label": a.get("type", ""),
            "key": a.get("key", ""),
            "label": asset_label(a),
            "pseudo": bool(a.get("pseudo")),
            "is_ip": bool(a.get("is_ip")),
            "is_web": bool(a.get("is_web")),
            "cloud": a.get("cloud", ""),
            "cloud_name": a.get("cloud_name", ""),
            "org": a.get("org", ""),
            "ptr": a.get("ptr", ""),
            "names": _sorted_list(a.get("names")),
            "product": asset_product(a),
            "products": _sorted_list(a.get("products")),
            "services": _sorted_list(a.get("services")),
            "open_ports": asset_ports(a),
            "ports": dict(a.get("ports", {})),
            "cves": [_cve_entry(c) for c in a.get("cves", []) if c.get("cve")],
            "finding_ids": fids,
            "worst_severity": _worst_severity(a_findings),
        })

    # Explicit many-to-many edges; primary = the finding's first/primary asset.
    relations: List[Dict[str, Any]] = []
    for f_out in findings_out:
        ids = f_out["asset_ids"] or ([f_out["asset_id"]] if f_out["asset_id"] else [])
        for aid in ids:
            relations.append({
                "finding_id": f_out["id"],
                "asset_id": aid,
                "primary": aid == f_out["asset_id"],
            })

    kpis = dict(getattr(data, "kpis", {}) or {})
    meta = getattr(data, "meta", {}) or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "scylax",
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "meta": {
            "engagement": meta.get("engagement", ""),
            "scope": meta.get("scope", ""),
            "date": meta.get("date", ""),
            "authorised_by": meta.get("authorised_by", ""),
            "authorisation_ref": meta.get("authorisation_ref", ""),
            "phases": meta.get("phases", ""),
            "egress_ip": meta.get("egress_ip", ""),
            "use_docker": meta.get("use_docker", "0") in ("1", "true", "True"),
        },
        "kpis": kpis,
        "summary": {
            "total_findings": len(findings_out),
            "total_assets": len(assets_out),
            "total_relations": len(relations),
            "severity_counts": {
                sev.lower(): kpis.get(sev.lower(), 0)
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
        },
        "diff": {k: list(v) for k, v in (getattr(data, "diff_summary", {}) or {}).items()},
        "assets": assets_out,
        "findings": findings_out,
        "relations": relations,
    }


def write_report_data(data: Any, run_dir: Path) -> Path:
    """Write ``report_data.json`` into ``run_dir`` and return its path."""
    doc = build_report_data(data)
    path = Path(run_dir) / "report_data.json"
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def export_report_data(run_dir: Path | str) -> Path:
    """Load a run directory and write its ``report_data.json`` (standalone entry)."""
    from recon.report import RunData  # local import to avoid a cycle at module load

    path = Path(run_dir).resolve()
    data = RunData(path)
    return write_report_data(data, path)
