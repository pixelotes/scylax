"""Standard output formats (SARIF 2.1.0 and CSV) built from ``report_data.json``.

Both are pure functions of the dict returned by :func:`recon.export.build_report_data`,
so the versioned contract stays the single source of truth. Findings are
*candidates* for a human to interpret, never verdicts, and are flagged as such.

SARIF location mapping
----------------------
SARIF is source-code oriented (file + region); Scylax findings are about network
assets. Trackers (GitHub code scanning, DefectDojo, ...) need a
``physicalLocation.artifactLocation.uri`` to show a result, so every result gets one:

* a target that is already a URL (``https://host/path``) is used as is;
* a bare host / IP / ``host:port`` becomes ``host:<target>`` (a valid RFC 3986
  URI with the scheme ``host``, e.g. ``host:203.0.113.45:22``);
* a finding with no target (tenant / org level) uses ``host:<asset label>`` or,
  failing that, ``scylax:tenant``.

Additionally each result carries ``logicalLocations`` whose ``fullyQualifiedName``
is the Scylax asset label (kind ``resource``), which is the semantically right
location for an infrastructure finding. No ``region`` is ever emitted.

``partialFingerprints`` come from the finding key (the rule key plus target, which
Scylax already keeps stable across runs), never from run-specific data.

CSV
---
RFC 4180 via :mod:`csv`, UTF-8 **without** BOM (a BOM breaks many importers;
Excel users can use "Data > From Text/CSV" with UTF-8). Multi-values are joined
with ``"; "``. Cells beginning with ``= + - @ TAB CR`` are prefixed with ``'`` to
neutralise spreadsheet formula injection: evidence comes from untrusted internet
data.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/pixelotes/scylax"

LEVEL_BY_SEVERITY = {
    "CRITICAL": "error", "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note", "INFO": "note",
}
# GitHub "security-severity" (CVSS-like 0-10) so severities sort in code scanning.
_SECURITY_SEVERITY = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 0.0}

CSV_COLUMNS = ["id", "severity", "title", "rule", "asset_ids", "assets", "targets",
               "cves", "phase", "status", "first_seen", "age_days", "evidence"]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_EVIDENCE_IN_MESSAGE = 1000


# ---------------------------------------------------------------- helpers

def rule_id(key: str) -> str:
    """The rule a finding key belongs to: its prefix (``cors:<url>`` -> ``cors``);
    nuclei keys keep the template (``nuclei:<template>:<host>`` -> ``nuclei:<template>``)."""
    parts = (key or "").split(":")
    if parts[0] == "nuclei" and len(parts) > 1:
        return f"nuclei:{parts[1]}"
    return parts[0] or "finding"


def severity_level(severity: str) -> str:
    return LEVEL_BY_SEVERITY.get((severity or "").upper(), "note")


def split_targets(target: str) -> List[str]:
    """A finding's ``target`` string as a list (they may be comma separated)."""
    return [t for t in re.split(r"[,\s]+", target or "") if t]


def _phase_of(key: str) -> str:
    try:  # lazy: triage pulls in a lot, and this is best-effort metadata
        from recon.phases.triage import finding_phase
        return finding_phase(key) or ""
    except Exception:
        return ""


def _cves_of(finding: Dict[str, Any]) -> List[str]:
    text = " ".join(str(finding.get(k, "")) for k in ("key", "title", "evidence"))
    return sorted({m.upper() for m in _CVE_RE.findall(text)})


def _location_uri(target: str) -> str:
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        return quote(target, safe=":/?#[]@!$&'()*+,;=%-._~")
    return "host:" + quote(target, safe=":/[]@-._~")


def _fingerprint(finding: Dict[str, Any]) -> str:
    basis = finding.get("key") or "\x00".join(
        str(finding.get(k, "")) for k in ("title", "target"))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def _asset_labels(doc: Dict[str, Any]) -> Dict[str, str]:
    return {a.get("id", ""): a.get("label") or a.get("key") or a.get("id", "")
            for a in doc.get("assets", [])}


def _asset_ids(finding: Dict[str, Any]) -> List[str]:
    return list(finding.get("asset_ids") or ([finding["asset_id"]] if finding.get("asset_id") else []))


def _history(run_dir: Optional[Path]) -> Dict[str, Any]:
    """Scope-level findings_history.json (first_seen per key), if present."""
    if run_dir is None:
        return {}
    try:
        return json.loads((Path(run_dir).parent / "findings_history.json")
                          .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# ------------------------------------------------------------------ SARIF

def build_sarif(doc: Dict[str, Any]) -> Dict[str, Any]:
    labels = _asset_labels(doc)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in doc.get("findings", []):
        sev = (f.get("severity") or "INFO").upper()
        rid = rule_id(f.get("key", ""))
        phase = _phase_of(f.get("key", ""))
        title = f.get("title", "") or rid
        score = _SECURITY_SEVERITY.get(sev, 0.0)
        rule = rules.get(rid)
        if rule is None:
            tags = ["scylax", "external-attack-surface", "candidate"]
            if phase:
                tags.append(f"phase-{phase}")
            rules[rid] = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]+", " ", rid).title().replace(" ", "") or "Finding",
                "shortDescription": {"text": title},
                "help": {"text": "Scylax finding candidate: automated evidence for a human "
                                 "to validate, not a verdict."},
                "defaultConfiguration": {"level": severity_level(sev)},
                "properties": {"tags": tags, "security-severity": f"{score:.1f}"},
            }
        elif score > float(rule["properties"]["security-severity"]):  # rule keeps its worst severity
            rule["properties"]["security-severity"] = f"{score:.1f}"
            rule["defaultConfiguration"]["level"] = severity_level(sev)

        targets = split_targets(f.get("target", ""))
        asset_ids = _asset_ids(f)
        uris = [_location_uri(t) for t in targets]
        if not uris:
            names = [labels[a] for a in asset_ids if labels.get(a)]
            uris = [_location_uri(names[0])] if names else ["scylax:tenant"]
        locations: List[Dict[str, Any]] = [
            {"physicalLocation": {"artifactLocation": {"uri": u}}} for u in uris]
        logical = [{"fullyQualifiedName": labels.get(a, a), "kind": "resource"} for a in asset_ids]
        if logical:
            locations[0]["logicalLocations"] = logical

        text = title
        evidence = (f.get("evidence") or "").strip()
        if evidence:
            text += "\n\nEvidence: " + evidence[:_EVIDENCE_IN_MESSAGE]
        results.append({
            "ruleId": rid,
            "level": severity_level(sev),
            "message": {"text": text},
            "locations": locations,
            "partialFingerprints": {"scylaxFindingKey/v1": _fingerprint(f)},
            "properties": {
                "severity": sev,
                "findingId": f.get("id", ""),
                "assetIds": asset_ids,
                "targets": targets,
                "cves": _cves_of(f),
                "phase": phase,
                "status": "candidate",
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "Scylax",
                "informationUri": INFORMATION_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


# -------------------------------------------------------------------- CSV

def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection in a cell."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(_FORMULA_PREFIXES) else s


def _age_days(first_seen: str, run_date: str) -> str:
    try:
        d0 = datetime.date.fromisoformat(first_seen)
        d1 = datetime.date.fromisoformat(run_date)
    except ValueError:
        return ""
    return str(max((d1 - d0).days, 0))


def build_csv(doc: Dict[str, Any], run_dir: Optional[Path] = None) -> str:
    labels = _asset_labels(doc)
    history = _history(run_dir)
    run_date = (doc.get("meta") or {}).get("date", "")
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\r\n")  # RFC 4180: CRLF
    w.writerow(CSV_COLUMNS)
    for f in doc.get("findings", []):
        key = f.get("key", "")
        asset_ids = _asset_ids(f)
        first = (history.get(key) or {}).get("first_seen", "")
        row = [
            f.get("id", ""), (f.get("severity") or "INFO").upper(), f.get("title", ""),
            rule_id(key), "; ".join(asset_ids),
            "; ".join(labels.get(a, a) for a in asset_ids),
            "; ".join(split_targets(f.get("target", ""))),
            "; ".join(_cves_of(f)), _phase_of(key), "candidate",
            first, _age_days(first, run_date) if first else "",
            f.get("evidence", ""),
        ]
        w.writerow([csv_safe(c) for c in row])
    return buf.getvalue()


# ------------------------------------------------------------------ files

def write_findings_exports(doc: Dict[str, Any], run_dir: Path) -> List[Path]:
    """Write ``findings.sarif`` and ``findings.csv``. Best-effort: each exporter's
    failure is logged as a warning and never propagates."""
    run_dir = Path(run_dir)
    written: List[Path] = []
    jobs = (
        ("findings.sarif", lambda: json.dumps(build_sarif(doc), indent=2, ensure_ascii=False) + "\n"),
        ("findings.csv", lambda: build_csv(doc, run_dir)),
    )
    for name, render in jobs:
        try:
            content = render()
            path = run_dir / name
            with path.open("w", encoding="utf-8", newline="") as fh:
                fh.write(content)
            written.append(path)
        except Exception as exc:  # noqa: BLE001 - exporters must not break a run
            try:
                from recon.runner import Logger
                Logger().warn(f"Could not write {name}: {exc}")
            except Exception:
                pass
    return written
