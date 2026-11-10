"""Report generation module for Recon Pipeline.

Generates self-contained Markdown and interactive HTML5 reports from a run directory.
Pure Python 3 standard library implementation.
"""

from __future__ import annotations

import csv
import datetime
import html
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from recon import trends as trends_mod
from recon.suppressions import load_suppressed
from recon.assets import (
    SEV_RANK,
    asset_label,
    asset_ports,
    asset_product,
    build_assets,
)


# =====================================================================
# Phase Name Normalization
# =====================================================================

PHASE_LABELS: dict[str, str] = {
    "1": "Phase 1: Subdomains",
    "phase 1": "Phase 1: Subdomains",
    "phase 1: subdomains": "Phase 1: Subdomains",
    "2": "Phase 2: DNS",
    "phase 2": "Phase 2: DNS",
    "phase 2: dns": "Phase 2: DNS",
    "3": "Phase 3: Web",
    "phase 3": "Phase 3: Web",
    "phase 3: web": "Phase 3: Web",
    "4": "Phase 4: HVT Scan",
    "phase 4": "Phase 4: HVT Scan",
    "phase 4: hvt scan": "Phase 4: HVT Scan",
    "4b": "Phase 4b: Edge",
    "phase 4b": "Phase 4b: Edge",
    "phase 4b: edge": "Phase 4b: Edge",
    "5": "Phase 5: Tech",
    "phase 5": "Phase 5: Tech",
    "phase 5: tech": "Phase 5: Tech",
    "6": "Phase 6: Wayback",
    "phase 6": "Phase 6: Wayback",
    "phase 6: wayback": "Phase 6: Wayback",
    "7": "Phase 7: Shodan & CVEs",
    "phase 7": "Phase 7: Shodan & CVEs",
    "phase 7: shodan & cves": "Phase 7: Shodan & CVEs",
    "8": "Phase 8: Nuclei",
    "phase 8": "Phase 8: Nuclei",
    "phase 8: nuclei": "Phase 8: Nuclei",
    "9": "Phase 9: Secrets",
    "phase 9": "Phase 9: Secrets",
    "phase 9: secrets": "Phase 9: Secrets",
    "a": "Annex A: Azure",
    "annex a": "Annex A: Azure",
    "annex a: azure": "Annex A: Azure",
    "g": "Annex G: GCP",
    "annex g": "Annex G: GCP",
    "annex g: gcp": "Annex G: GCP",
    "w": "Annex W: AWS",
    "annex w": "Annex W: AWS",
    "annex w: aws": "Annex W: AWS",
    "e": "Phase E: SaaS Exposure",
    "phase e": "Phase E: SaaS Exposure",
    "t": "Phase T: Triage",
    "phase t": "Phase T: Triage",
    "phase t: triage": "Phase T: Triage",
}

ALL_KNOWN_PHASES: list[str] = [
    "Phase 1: Subdomains",
    "Phase 2: DNS",
    "Phase 3: Web",
    "Phase 4: HVT Scan",
    "Phase 4b: Edge",
    "Phase 5: Tech",
    "Phase 6: Wayback",
    "Phase 7: Shodan & CVEs",
    "Phase 8: Nuclei",
    "Phase 9: Secrets",
    "Annex A: Azure",
    "Annex G: GCP",
    "Annex W: AWS",
]


def normalize_phase(raw: str) -> str:
    """Normalize phase key to human-readable label."""
    s = str(raw).strip()
    return PHASE_LABELS.get(s.lower(), s if s else "General")


# =====================================================================
# Safe File Helpers
# =====================================================================

def _safe_read_text(path: Path) -> str:
    """Read file content as text, returning empty string if missing or unreadable."""
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _safe_read_lines(path: Path) -> list[str]:
    """Read non-empty stripped lines from file."""
    text = _safe_read_text(path)
    return [line.strip() for line in text.splitlines() if line.strip()]


def _escape_md_cell(text: str) -> str:
    """Escape vertical pipes and newlines for markdown tables."""
    return text.replace("|", "\\|").replace("\r", "").replace("\n", " ")


def nsg_ports(raw: str) -> str:
    """NSG port field as '22' or '443,80'.

    Runs before the fix stored destinationPortRange glued to the JSON text of
    destinationPortRanges ('22[]', '["443","80"]')."""
    raw = raw.strip()
    if "[" not in raw:
        return raw
    single, _, rest = raw.partition("[")
    try:
        ranges = [str(x) for x in json.loads("[" + rest) if x]
    except ValueError:
        ranges = []
    return ",".join([single] if single else ranges)


def _finding_asset_cell(f: dict) -> str:
    """Findings-table Asset cell: the primary asset id as a jump link, plus a
    compact '+N' (the rest in its tooltip) when a finding affects several assets."""
    ids = f.get("asset_ids") or ([f["asset_id"]] if f.get("asset_id") else [])
    if not ids:
        return '<span class="muted">-</span>'
    primary = ids[0]
    cell = (f'<a class="asset-link" href="#" data-asset-id="{html.escape(primary)}">'
            f'<code class="pill">{html.escape(primary)}</code></a>')
    if len(ids) > 1:
        rest = ", ".join(ids[1:])
        cell += f' <span class="muted" title="also affects: {html.escape(rest)}">+{len(ids) - 1}</span>'
    return cell


def _target_html(target: str) -> str:
    """Finding target cell: URLs become links, anything else stays as code."""
    if not target:
        return "-"
    out = []
    for t in (x.strip() for x in target.split(", ")):
        esc = html.escape(t)
        if t.startswith(("http://", "https://")):
            out.append(f'<a href="{esc}" target="_blank" rel="noopener noreferrer">{esc}</a>')
        else:
            out.append(f"<code>{esc}</code>")
    return "<br>".join(out)


# =====================================================================
# Data Loader
# =====================================================================

class RunData:
    """Holds all structured artifacts loaded from a run directory."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir.resolve()
        self.meta: dict[str, str] = self._load_meta()
        self.findings: list[dict[str, str]] = self._load_findings()
        # Auditor-suppressed candidates (still observed; listed with reason/owner/expiry)
        self.suppressed: list[dict[str, str]] = load_suppressed(self.run_dir)
        self.diff_content, self.diff_summary = self._load_diff()
        # Trend metrics written by triage next to diff.md ({} without a previous run)
        self.trends: dict[str, Any] = self._load_trends()
        self.gaps: list[str] = self._load_gaps()
        self.tool_versions: list[str] = self._load_tool_versions()
        self.subdomain_counts: list[tuple[str, int]] = self._load_subdomain_counts()
        self.subdomains: list[str] = _safe_read_lines(self.run_dir / "osint" / "subdomains.txt")
        self.new_subdomains: list[str] = _safe_read_lines(self.run_dir / "osint" / "new_subdomains.txt")
        self.gone_subdomains: list[str] = _safe_read_lines(self.run_dir / "osint" / "gone_subdomains.txt")
        self.resolved_hosts: list[str] = _safe_read_lines(self.run_dir / "osint" / "resolved.txt")
        self.ip_orgs: list[dict[str, str]] = self._load_ip_orgs()
        self.discovered_targets: list[str] = _safe_read_lines(self.run_dir / "osint" / "discovered_targets.txt")
        self.dns_posture: list[dict[str, Any]] = self._load_dns_posture()
        self.apex_ownership: list[dict[str, str]] = self._load_apex()
        self.service_cves: list[dict[str, Any]] = self._load_service_cves()
        self.entry_points: list[dict[str, str]] = self._load_entry_points()
        self.httpx_all: list[dict[str, str]] = self._load_httpx_all()
        self.exposed_paths: list[dict[str, str]] = self._load_exposed_paths()
        self.cors_cookies: list[dict[str, str]] = self._load_cors_cookies()
        self.dir_listings: list[str] = _safe_read_lines(self.run_dir / "web" / "dir_listings.txt")
        self.azure_public_ips: list[dict[str, str]] = self._load_azure_public_ips()
        self.azure_nsg_rules: list[dict[str, str]] = self._load_azure_nsg_rules()
        self.azure_coverage: str = _safe_read_text(self.run_dir / "azure" / "coverage.txt").strip()
        self.azure_posture: list[dict[str, str]] = self._load_posture("azure")
        self.gcp_public_ips: list[dict[str, str]] = self._load_gcp_public_ips()
        self.gcp_firewall_rules: list[dict[str, str]] = self._load_gcp_firewall_rules()
        self.gcp_coverage: str = _safe_read_text(self.run_dir / "gcp" / "coverage.txt").strip()
        self.gcp_posture: list[dict[str, str]] = self._load_posture("gcp")
        self.aws_public_ips: list[dict[str, str]] = self._load_aws_public_ips()
        self.aws_public_endpoints: list[dict[str, str]] = self._load_aws_public_endpoints()
        self.aws_sg_rules: list[dict[str, str]] = self._load_aws_sg_rules()
        self.aws_coverage: str = _safe_read_text(self.run_dir / "aws" / "coverage.txt").strip()
        self.aws_posture: list[dict[str, str]] = self._load_posture("aws")
        self.all_posture: list[dict[str, str]] = self.azure_posture + self.gcp_posture + self.aws_posture
        self.saas_posture: list[dict[str, str]] = self._load_saas_posture()
        self.commands: list[dict[str, Any]] = self._load_commands()
        # Asset inventory: assigns stable ids, tags each finding with asset_id,
        # then regroups findings so same-asset rows are consecutive (assets with
        # the most severe finding first).
        self.assets: list[dict[str, Any]] = build_assets(self)
        self._regroup_findings_by_asset()
        self.kpis: dict[str, Any] = self._calculate_kpis()

    def _regroup_findings_by_asset(self) -> None:
        # Group rows that share an asset so they appear consecutively, and order
        # groups by their worst finding severity. A finding with no asset is its
        # own one-row group ranked by its own severity, so an org/tenant-level
        # critical is not buried below low-severity asset rows. At equal severity,
        # asset groups come before solo rows.
        def group_key(f: dict[str, str]) -> str:
            aid = f.get("asset_id", "")
            return aid if aid else ("￿solo:" + f.get("key", ""))

        group_rank: dict[str, int] = {}
        for f in self.findings:
            r = SEV_RANK.get(f.get("severity", "INFO").upper(), 4)
            gk = group_key(f)
            group_rank[gk] = min(group_rank.get(gk, 9), r)

        def sort_key(f: dict[str, str]) -> tuple:
            gk = group_key(f)
            return (
                group_rank[gk],                        # group's worst severity
                0 if f.get("asset_id") else 1,         # assets before solo rows
                gk,                                    # keep an asset's rows together
                SEV_RANK.get(f.get("severity", "INFO").upper(), 4),
                f.get("title", "").lower(),
            )

        self.findings.sort(key=sort_key)

    def _load_meta(self) -> dict[str, str]:
        meta_path = self.run_dir / "run.meta"
        lines = _safe_read_lines(meta_path)
        meta: dict[str, str] = {}
        for line in lines:
            if line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            meta[k.strip().lower()] = v.strip()

        parent_name = self.run_dir.parent.name if self.run_dir.parent else "default"
        meta.setdefault("engagement", meta.get("scope") or parent_name)
        meta.setdefault("scope", parent_name)
        meta.setdefault("date", self.run_dir.name or datetime.date.today().isoformat())
        meta.setdefault("authorised_by", "")
        meta.setdefault("authorisation_ref", "")
        meta.setdefault("phases", "All")
        meta.setdefault("skip_active", "0")
        meta.setdefault("use_docker", "0")
        meta.setdefault("egress_ip", "unknown")
        return meta

    def _load_findings(self) -> list[dict[str, str]]:
        path = self.run_dir / "findings_auto.tsv"
        findings: list[dict[str, str]] = []
        if not path.is_file():
            return findings

        order_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for line in _safe_read_lines(path):
            parts = line.split("\t")
            if len(parts) >= 4:
                sev = parts[0].strip().upper()
                findings.append({
                    "severity": sev,
                    "key": parts[1].strip(),
                    "title": parts[2].strip(),
                    "evidence": parts[3].strip(),
                    "target": parts[4].strip() if len(parts) > 4 else "",
                })
            elif len(parts) >= 2:
                sev = parts[0].strip().upper()
                findings.append({
                    "severity": sev,
                    "key": parts[1].strip(),
                    "title": parts[2].strip() if len(parts) > 2 else parts[1].strip(),
                    "evidence": parts[3].strip() if len(parts) > 3 else "",
                    "target": "",
                })

        findings.sort(key=lambda f: (order_map.get(f["severity"], 99), f["title"].lower()))
        return findings

    def _load_trends(self) -> dict[str, Any]:
        try:
            t = json.loads(_safe_read_text(self.run_dir / "trends.json") or "{}")
        except ValueError:
            return {}
        return t if isinstance(t, dict) and t.get("counts") and t.get("totals") else {}

    def _load_diff(self) -> tuple[str, dict[str, list[str]]]:
        diff_path = self.run_dir / "diff.md"
        content = _safe_read_text(diff_path)
        summary: dict[str, list[str]] = {"New": [], "Reappeared": [], "Resolved": [], "Not re-checked": [], "Persisting": []}
        # Suppression buckets appear in diff.md only when suppressions are in play
        extra_sections = ("Reactivated (suppression expired)", "Suppressed (accepted)")
        if content:
            cur_section = ""
            for line in content.splitlines():
                s = line.strip()
                if s.startswith("## Summary"):
                    cur_section = ""
                elif s.startswith("## New"):
                    cur_section = "New"
                elif s.startswith("## Resolved"):
                    cur_section = "Resolved"
                elif s.startswith("## Persisting"):
                    cur_section = "Persisting"
                elif s.startswith("## Reappeared"):
                    cur_section = "Reappeared"
                elif s.startswith("## Not re-checked"):
                    cur_section = "Not re-checked"
                elif s.startswith("## ") and s[3:].startswith(extra_sections):
                    cur_section = next(x for x in extra_sections if s[3:].startswith(x))
                    summary.setdefault(cur_section, [])
                elif cur_section and s.startswith("- "):
                    summary[cur_section].append(s[2:].strip())
        return content, summary

    def _load_gaps(self) -> list[str]:
        path = self.run_dir / "gaps.txt"
        lines = _safe_read_lines(path)
        seen: set[str] = set()
        deduped: list[str] = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                deduped.append(line)
        return deduped

    def _load_tool_versions(self) -> list[str]:
        return _safe_read_lines(self.run_dir / "tool_versions.txt")

    def _load_subdomain_counts(self) -> list[tuple[str, int]]:
        path = self.run_dir / "osint" / "subdomain_counts.txt"
        counts: list[tuple[str, int]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = re.split(r"[\s:]+", line.strip())
                if len(parts) >= 2:
                    try:
                        counts.append((parts[0], int(parts[1])))
                    except ValueError:
                        pass
        return counts

    def _load_ip_orgs(self) -> list[dict[str, str]]:
        path = self.run_dir / "osint" / "ip_orgs.tsv"
        rows: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rows.append({
                    "ip": parts[0].strip() if len(parts) > 0 else "",
                    "org": parts[1].strip() if len(parts) > 1 else "",
                    "ptr": parts[2].strip() if len(parts) > 2 else "",
                    "sample_hosts": parts[3].strip() if len(parts) > 3 else "",
                })
        return rows

    def _load_apex(self) -> list[dict[str, str]]:
        path = self.run_dir / "osint" / "apex.txt"
        entries: list[dict[str, str]] = []
        if not path.is_file():
            return entries

        text = _safe_read_text(path)
        cur: dict[str, str] | None = None
        for line in text.splitlines():
            if " apex " in line and not line.startswith(" "):
                if cur:
                    entries.append(cur)
                parts = line.strip().split()
                cur = {
                    "domain": parts[0] if len(parts) > 0 else "",
                    "ip": parts[2] if len(parts) > 2 else "",
                    "ptr": "",
                    "org": "",
                    "raw": line,
                }
            elif cur is not None:
                cur["raw"] += "\n" + line
                s = line.strip()
                if s.startswith("ptr:"):
                    cur["ptr"] = s.partition(":")[2].strip()
                elif any(s.lower().startswith(p) for p in ("org-name:", "netname:", "orgname:")):
                    if not cur["org"]:
                        cur["org"] = s.partition(":")[2].strip()
        if cur:
            entries.append(cur)
        return entries

    def _load_dns_posture(self) -> list[dict[str, Any]]:
        dns_files = sorted(self.run_dir.glob("osint/dns_*.txt"))
        results: list[dict[str, Any]] = []
        for df in dns_files:
            dom = df.stem.replace("dns_", "")
            content = _safe_read_text(df)
            has_spf = "v=spf1" in content
            has_dmarc = "v=DMARC1" in content or "p=reject" in content or "p=quarantine" in content
            dmarc_reject = "p=reject" in content
            has_caa = bool(re.search(r"\bCAA\b|\bissue\b", content, re.IGNORECASE))
            has_dnssec = bool(re.search(r"\bDNSKEY\b|\bRRSIG\b", content))
            axfr_allowed = "AXFR ALLOWED" in content

            results.append({
                "domain": dom,
                "spf": has_spf,
                "dmarc": has_dmarc,
                "dmarc_reject": dmarc_reject,
                "caa": has_caa,
                "dnssec": has_dnssec,
                "axfr_allowed": axfr_allowed,
            })
        return results

    def _load_service_cves(self) -> list[dict[str, Any]]:
        path = self.run_dir / "osint" / "service_cves.tsv"
        cves: list[dict[str, Any]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                if len(parts) >= 8 and parts[0].strip().lower() == "ip" and parts[4].strip().lower() == "cve":
                    continue  # header row
                if len(parts) >= 8:
                    try:
                        cvss_val = float(parts[5].strip()) if parts[5].strip() else 0.0
                    except ValueError:
                        cvss_val = 0.0
                    is_kev = parts[6].strip().lower() in ("true", "1", "yes", "kev")
                    cves.append({
                        "ip": parts[0].strip(),
                        "port": parts[1].strip(),
                        "service": parts[2].strip(),
                        "version": parts[3].strip(),
                        "cve": parts[4].strip(),
                        "cvss": cvss_val,
                        "cvss_str": parts[5].strip() or "N/A",
                        "is_kev": is_kev,
                        "summary": parts[7].strip(),
                    })
        # Check azure/cve_cvss.csv as fallback if service_cves was absent
        if not cves:
            csv_path = self.run_dir / "azure" / "cve_cvss.csv"
            if csv_path.is_file():
                try:
                    with csv_path.open("r", encoding="utf-8", errors="replace") as f:
                        for row in csv.DictReader(f):
                            cve_id = row.get("cve", "").strip()
                            if not cve_id:
                                continue
                            cvss_str = row.get("cvss", "").strip()
                            try:
                                cvss_val = float(cvss_str) if cvss_str else 0.0
                            except ValueError:
                                cvss_val = 0.0
                            cves.append({
                                "ip": row.get("ip", "").strip(),
                                "port": "-",
                                "service": "-",
                                "version": "-",
                                "cve": cve_id,
                                "cvss": cvss_val,
                                "cvss_str": cvss_str or "N/A",
                                "is_kev": False,
                                "summary": "Correlated via Shodan CVEDB",
                            })
                except Exception:
                    pass

        cves.sort(key=lambda x: (not x["is_kev"], -x["cvss"], x["cve"]))
        return cves

    def _load_entry_points(self) -> list[dict[str, str]]:
        path = self.run_dir / "osint" / "entry_points.tsv"
        entries: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                if len(parts) >= 3:
                    entries.append({
                        "category": parts[0].strip(),
                        "param_or_pattern": parts[1].strip(),
                        "sample_url": parts[2].strip(),
                    })
                elif len(parts) == 2:
                    entries.append({
                        "category": parts[0].strip(),
                        "param_or_pattern": parts[1].strip(),
                        "sample_url": "",
                    })
        return entries

    def _load_httpx_all(self) -> list[dict[str, str]]:
        path = self.run_dir / "web" / "httpx_all.txt"
        hosts: list[dict[str, str]] = []
        if not path.is_file():
            return hosts

        pattern = re.compile(r"^(\S+)\s+\[(\d+)\](?:\s+\[(.*?)\])?(?:\s+\[(.*?)\])?(?:\s+\[(.*?)\])?")
        for line in _safe_read_lines(path):
            m = pattern.match(line)
            if m:
                hosts.append({
                    "url": m.group(1),
                    "status": m.group(2),
                    "title": m.group(3) or "",
                    "server": m.group(4) or "",
                    "location": m.group(5) or "",
                    "raw": line,
                })
            else:
                parts = line.split()
                hosts.append({
                    "url": parts[0] if parts else line,
                    "status": "-",
                    "title": "",
                    "server": "",
                    "location": "",
                    "raw": line,
                })
        return hosts

    def _load_exposed_paths(self) -> list[dict[str, str]]:
        path = self.run_dir / "web" / "exposed_paths.tsv"
        paths: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                paths.append({
                    "url": parts[0].strip() if len(parts) > 0 else "",
                    "category": parts[1].strip() if len(parts) > 1 else "Exposed Path",
                    "snippet": parts[2].strip() if len(parts) > 2 else "",
                })
        return paths

    def _load_cors_cookies(self) -> list[dict[str, str]]:
        path = self.run_dir / "web" / "cors_cookies.tsv"
        items: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                items.append({
                    "url": parts[0].strip() if len(parts) > 0 else "",
                    "issue_type": parts[1].strip() if len(parts) > 1 else "Configuration",
                    "detail": parts[2].strip() if len(parts) > 2 else "",
                })
        return items

    def _load_azure_public_ips(self) -> list[dict[str, str]]:
        path = self.run_dir / "azure" / "public_ips.tsv"
        rows: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rows.append({
                    "ip": parts[0].strip() if len(parts) > 0 else "",
                    "name": parts[1].strip() if len(parts) > 1 else "",
                    "resource_group": parts[2].strip() if len(parts) > 2 else "",
                    "attached_to": parts[3].strip() if len(parts) > 3 else "",
                })
        return rows

    def _load_azure_nsg_rules(self) -> list[dict[str, str]]:
        path = self.run_dir / "azure" / "nsg_internet_rules.tsv"
        rules: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rules.append({
                    "nsg": parts[0].strip() if len(parts) > 0 else "",
                    "resource_group": parts[1].strip() if len(parts) > 1 else "",
                    "rule": parts[2].strip() if len(parts) > 2 else "",
                    "ports": nsg_ports(parts[3]) if len(parts) > 3 else "",
                    "attached_nics": parts[4].strip() if len(parts) > 4 else "0",
                })
        return rules

    def _load_gcp_public_ips(self) -> list[dict[str, str]]:
        path = self.run_dir / "gcp" / "public_ips.tsv"
        rows: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rows.append({
                    "ip": parts[0].strip() if len(parts) > 0 else "",
                    "name": parts[1].strip() if len(parts) > 1 else "",
                    "project": parts[2].strip() if len(parts) > 2 else "",
                    "region_type": parts[3].strip() if len(parts) > 3 else "",
                })
        return rows

    def _load_gcp_firewall_rules(self) -> list[dict[str, str]]:
        path = self.run_dir / "gcp" / "firewall_internet_rules.tsv"
        rules: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rules.append({
                    "name": parts[0].strip() if len(parts) > 0 else "",
                    "project": parts[1].strip() if len(parts) > 1 else "",
                    "network": parts[2].strip() if len(parts) > 2 else "",
                    "direction_priority": parts[3].strip() if len(parts) > 3 else "",
                    "action": parts[4].strip() if len(parts) > 4 else "",
                    "source_ranges": parts[5].strip() if len(parts) > 5 else "",
                    "allowed": parts[6].strip() if len(parts) > 6 else "",
                })
        return rules

    def _load_aws_public_ips(self) -> list[dict[str, str]]:
        path = self.run_dir / "aws" / "public_ips.tsv"
        rows: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rows.append({
                    "ip": parts[0].strip() if len(parts) > 0 else "",
                    "name": parts[1].strip() if len(parts) > 1 else "",
                    "region": parts[2].strip() if len(parts) > 2 else "",
                    "resource_type": parts[3].strip() if len(parts) > 3 else "",
                })
        return rows

    def _load_aws_public_endpoints(self) -> list[dict[str, str]]:
        path = self.run_dir / "aws" / "public_endpoints.tsv"
        rows: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rows.append({
                    "hostname": parts[0].strip() if len(parts) > 0 else "",
                    "resource_type": parts[1].strip() if len(parts) > 1 else "",
                    "region": parts[2].strip() if len(parts) > 2 else "",
                    "detail": parts[3].strip() if len(parts) > 3 else "",
                })
        return rows

    def _load_aws_sg_rules(self) -> list[dict[str, str]]:
        path = self.run_dir / "aws" / "sg_internet_rules.tsv"
        rules: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                rules.append({
                    "group_id": parts[0].strip() if len(parts) > 0 else "",
                    "group_name": parts[1].strip() if len(parts) > 1 else "",
                    "region": parts[2].strip() if len(parts) > 2 else "",
                    "ports": parts[3].strip() if len(parts) > 3 else "",
                    "cidr": parts[4].strip() if len(parts) > 4 else "",
                })
        return rules

    def _load_posture(self, cloud_name: str) -> list[dict[str, str]]:
        path = self.run_dir / cloud_name / "posture_findings.tsv"
        items: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                if len(parts) >= 5:
                    items.append({
                        "cloud": cloud_name,
                        "severity": parts[0].strip().upper() if parts[0].strip() else "INFO",
                        "key": parts[1].strip() if len(parts) > 1 else "",
                        "service": parts[2].strip() if len(parts) > 2 else "",
                        "resource": parts[3].strip() if len(parts) > 3 else "",
                        "title": parts[4].strip() if len(parts) > 4 else "",
                        "detail": parts[5].strip() if len(parts) > 5 else "",
                    })
        return items

    def _load_saas_posture(self) -> list[dict[str, str]]:
        path = self.run_dir / "saas" / "posture_findings.tsv"
        items: list[dict[str, str]] = []
        if path.is_file():
            for line in _safe_read_lines(path):
                parts = line.split("\t")
                if len(parts) >= 5:
                    key = parts[1].strip() if len(parts) > 1 else ""
                    if key.startswith("m365-"):
                        provider = "M365"
                    elif key.startswith("gh-"):
                        provider = "GitHub"
                    elif key.startswith("gws-"):
                        provider = "Google"
                    else:
                        provider = "SaaS"
                    items.append({
                        "severity": parts[0].strip().upper() if parts[0].strip() else "INFO",
                        "key": key,
                        "service": parts[2].strip() if len(parts) > 2 else "",
                        "resource": parts[3].strip() if len(parts) > 3 else "",
                        "title": parts[4].strip() if len(parts) > 4 else "",
                        "detail": parts[5].strip() if len(parts) > 5 else "",
                        "provider": provider,
                    })
        return items

    def _load_commands(self) -> list[dict[str, Any]]:
        jsonl_path = self.run_dir / "console" / "commands.jsonl"
        cmds: list[dict[str, Any]] = []
        if jsonl_path.is_file():
            for line in _safe_read_lines(jsonl_path):
                try:
                    rec = json.loads(line)
                    if isinstance(rec, dict) and "cmd" in rec:
                        rec["phase"] = normalize_phase(rec.get("phase", "General"))
                        rec.setdefault("title", rec.get("cmd", "").split()[0] if rec.get("cmd") else "command")
                        rec.setdefault("output", "")
                        rec.setdefault("returncode", 0)
                        rec.setdefault("duration_ms", 0)
                        rec.setdefault("timestamp", "")
                        cmds.append(rec)
                except Exception:
                    continue

        if cmds:
            return cmds

        # Fallback: parse console/*.log
        console_dir = self.run_dir / "console"
        if not console_dir.is_dir():
            return cmds

        log_files = sorted(console_dir.glob("*.log"), key=lambda p: (len(p.stem), p.stem))
        for lf in log_files:
            stem = lf.stem
            phase_label = normalize_phase(stem)
            text = _safe_read_text(lf)
            if not text.strip():
                continue

            blocks = re.split(r"(?m)^(?=\$ )", text)
            for blk in blocks:
                blk = blk.strip()
                if not blk.startswith("$ "):
                    continue
                first_nl = blk.find("\n")
                if first_nl == -1:
                    cmd_str = blk[2:].strip()
                    out_str = ""
                else:
                    cmd_str = blk[2:first_nl].strip()
                    out_str = blk[first_nl + 1:].strip()

                title = cmd_str.split()[0] if cmd_str.split() else "command"
                cmds.append({
                    "phase": phase_label,
                    "title": title,
                    "cmd": cmd_str,
                    "output": out_str,
                    "returncode": 0,
                    "duration_ms": 0,
                    "timestamp": "",
                })
        return cmds

    def _calculate_kpis(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            s = f.get("severity", "INFO").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        subdomains_cnt = len(self.subdomains)
        if subdomains_cnt == 0 and self.subdomain_counts:
            subdomains_cnt = sum(c[1] for c in self.subdomain_counts)

        resolving_cnt = len(self.resolved_hosts)
        if resolving_cnt == 0:
            resolving_cnt = max(len(self.ip_orgs), subdomains_cnt)

        live_web_cnt = len(self.httpx_all)

        scanned_ips: set[str] = set()
        for r in self.ip_orgs:
            if r.get("ip"):
                scanned_ips.add(r["ip"])
        for r in self.azure_public_ips:
            if r.get("ip"):
                scanned_ips.add(r["ip"])
        for r in self.gcp_public_ips:
            if r.get("ip"):
                scanned_ips.add(r["ip"])
        for r in self.aws_public_ips:
            if r.get("ip"):
                scanned_ips.add(r["ip"])
        for t in self.discovered_targets:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", t.strip()):
                scanned_ips.add(t.strip())
        targets_scanned_cnt = len(scanned_ips) if scanned_ips else max(len(self.ip_orgs), len(self.azure_public_ips))

        cve_ids = {c["cve"] for c in self.service_cves if c.get("cve")}
        kev_count = sum(1 for c in self.service_cves if c.get("is_kev"))

        azure_ips_cnt = len(self.azure_public_ips)
        gcp_ips_cnt = len(self.gcp_public_ips)
        aws_ips_cnt = len(self.aws_public_ips)
        cloud_ips_total = azure_ips_cnt + gcp_ips_cnt + aws_ips_cnt

        return {
            "critical": sev_counts["CRITICAL"],
            "high": sev_counts["HIGH"],
            "medium": sev_counts["MEDIUM"],
            "low": sev_counts["LOW"],
            "info": sev_counts["INFO"],
            "total_findings": len(self.findings),
            "suppressed": len(self.suppressed),
            "subdomains": subdomains_cnt,
            "new_subdomains": len(self.new_subdomains),
            "gone_subdomains": len(self.gone_subdomains),
            "resolving_hosts": resolving_cnt,
            "live_web_hosts": live_web_cnt,
            "targets_scanned": targets_scanned_cnt,
            "cves_total": len(cve_ids),
            "cves_kev": kev_count,
            "cloud_ips_azure": azure_ips_cnt,
            "cloud_ips_gcp": gcp_ips_cnt,
            "cloud_ips_aws": aws_ips_cnt,
            "cloud_ips_total": cloud_ips_total,
            "posture_findings_total": len(self.all_posture),
            "open_services": len(self.service_cves),
        }


# =====================================================================
# Markdown Report Generator
# =====================================================================

def _suppressed_markdown(data: RunData) -> list[str]:
    """'Suppressed' table (section 2a): auditor-accepted candidates, still observed."""
    if not data.suppressed:
        return []
    lines = [
        "## 2a. Suppressed (accepted by the auditor)",
        "",
        "*Still observed this run; excluded from the counts above by a recorded decision. "
        "They become active again when the suppression expires.*",
        "",
        "| Severity | Finding Title | Target | Reason | Owner | Expires | Ticket | Rule Key |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in data.suppressed:
        lines.append(
            f"| `{f['severity'].upper()}` | {_escape_md_cell(f['title'])} | {_escape_md_cell(f['target']) or '-'} "
            f"| {_escape_md_cell(f['reason'])} | {_escape_md_cell(f['owner'])} | {_escape_md_cell(f['expires'])} "
            f"| {_escape_md_cell(f['ticket']) or '-'} | `{_escape_md_cell(f['key'])}` |"
        )
    lines.append("")
    return lines


def _suppressed_html(data: RunData) -> str:
    """'Suppressed' card for the Findings tab ('' when nothing is suppressed)."""
    if not data.suppressed:
        return ""
    rows = "".join(
        f"<tr><td><span class=\"badge badge-{html.escape(f['severity'].lower())}\">{html.escape(f['severity'].upper())}</span></td>"
        f"<td><strong>{html.escape(f['title'])}</strong></td>"
        f"<td class=\"mono\">{_target_html(f['target'])}</td>"
        f"<td>{html.escape(f['reason'])}</td><td>{html.escape(f['owner'])}</td>"
        f"<td class=\"mono\">{html.escape(f['expires'])}</td><td>{html.escape(f['ticket']) or '-'}</td>"
        f"<td><code class=\"pill\">{html.escape(f['key'])}</code></td></tr>"
        for f in data.suppressed
    )
    return f"""<div class="card" id="suppressed-findings">
      <div class="card-header">
        <span class="card-title">Suppressed ({len(data.suppressed)}) &mdash; accepted by the auditor, still observed</span>
      </div>
      <div class="card-body">
        <div class="table-responsive">
          <table id="suppressed-table">
            <thead><tr><th style="width: 110px;">Severity</th><th>Finding Title</th><th>Target</th><th>Reason</th>
            <th>Owner</th><th>Expires</th><th>Ticket</th><th style="width: 220px;">Rule Key</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
      </div>
    </div>"""


def _changes_markdown(data: RunData) -> list[str]:
    """'What changed since <date>' block ([] without a previous run)."""
    t = data.trends
    if not t:
        return []
    tot = t["totals"]
    lines = [f"## What Changed Since {t['previous_run']}", "",
             f"Net change: **{trends_mod.signed(tot['net'])}** active findings "
             f"({tot['previous']} -> {tot['current']}); {tot['new']} new, {tot['resolved']} resolved, "
             f"{tot['reappeared']} reappeared, {tot['reactivated']} reactivated.", "",
             "| Severity | Now | Net | New | Resolved |", "|---|---|---|---|---|"]
    for s in t["severities"]:
        lines.append(f"| `{s.upper()}` | {t['current'][s]} | {trends_mod.signed(t['net'][s])} | "
                     f"{t['counts']['new'][s]} | {t['counts']['resolved'][s]} |")
    lines += ["", f"MTTR (last {t['mttr']['window_days']} days): {trends_mod.mttr_text(t)}", ""]
    if t["oldest_open"]:
        lines += ["Oldest open critical/high:", ""]
        lines += [f"- **{o['severity'].upper()}** {_escape_md_cell(o['title'])} - {o['age_days']} days" for o in t["oldest_open"]]
        lines.append("")
    return lines


def _changes_html(data: RunData) -> str:
    """'What changed since <date>' card for the top of the Overview tab ('' without a previous run)."""
    t = data.trends
    if not t:
        return ""
    tot = t["totals"]

    def net_cell(n: int) -> str:
        arrow = "&uarr;" if n > 0 else ("&darr;" if n < 0 else "=")
        color = "var(--critical)" if n > 0 else ("var(--accent)" if n < 0 else "var(--text-secondary)")
        return f"<span style=\"color: {color}; font-weight: 600;\">{arrow} {abs(n)}</span>"

    rows = "".join(
        f"<tr><td><span class=\"badge badge-{s}\">{s.upper()}</span></td><td class=\"mono\">{t['current'][s]}</td>"
        f"<td>{net_cell(t['net'][s])}</td><td class=\"mono\">{t['counts']['new'][s]}</td>"
        f"<td class=\"mono\">{t['counts']['resolved'][s]}</td></tr>"
        for s in t["severities"])
    oldest = "".join(
        f"<tr><td><span class=\"badge badge-{html.escape(o['severity'])}\">{html.escape(o['severity'].upper())}</span></td>"
        f"<td>{html.escape(o['title'])}</td><td class=\"mono\">{o['age_days']} days</td></tr>"
        for o in t["oldest_open"]) or "<tr><td colspan='3' class='empty-state'>No open high/critical findings</td></tr>"
    return f"""<div class="card" id="what-changed">
      <div class="card-header">
        <span class="card-title">What changed since {html.escape(t['previous_run'])}</span>
        <span class="card-subtitle">{net_cell(tot['net'])} active findings ({tot['previous']} &rarr; {tot['current']}) &bull;
          {tot['new']} new &bull; {tot['resolved']} resolved &bull; {tot['reappeared']} reappeared &bull; {tot['reactivated']} reactivated</span>
      </div>
      <div class="card-body">
        <div class="grid-2">
          <div class="table-responsive">
            <table>
              <thead><tr><th>Severity</th><th>Now</th><th>Net</th><th>New</th><th>Resolved</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
          <div class="table-responsive">
            <p style="color: var(--text-secondary); margin-bottom: 0.5rem;">MTTR (resolved in last {t['mttr']['window_days']} days): <strong>{html.escape(trends_mod.mttr_text(t))}</strong></p>
            <table>
              <thead><tr><th>Oldest open</th><th>Finding</th><th>Age</th></tr></thead>
              <tbody>{oldest}</tbody>
            </table>
          </div>
        </div>
      </div>
    </div>"""


def generate_markdown(data: RunData) -> str:
    """Generate detailed GitHub Flavored Markdown assessment report."""
    m = data.meta
    k = data.kpis

    auth_str = m.get("authorised_by") or "None"
    if m.get("authorisation_ref"):
        auth_str += f" ({m['authorisation_ref']})"

    lines: list[str] = []

    # Title & Executive Metadata Table
    lines.append(f"# External Attack Surface Assessment Report: {m.get('engagement', 'Recon Assessment')}")
    lines.append("")
    lines.append("## Executive Metadata")
    lines.append("")
    lines.append("| Parameter | Detail |")
    lines.append("|---|---|")
    lines.append(f"| **Engagement** | {_escape_md_cell(m.get('engagement', ''))} |")
    lines.append(f"| **Date** | {_escape_md_cell(m.get('date', ''))} |")
    lines.append(f"| **Scope** | `{_escape_md_cell(m.get('scope', ''))}` |")
    lines.append(f"| **Authorised By** | {_escape_md_cell(auth_str)} |")
    lines.append(f"| **Egress IP** | `{_escape_md_cell(m.get('egress_ip', 'unknown'))}` |")
    lines.append(f"| **Phases Run** | `{_escape_md_cell(m.get('phases', 'All'))}` (Skip Active: {m.get('skip_active')}, Docker: {m.get('use_docker')}) |")
    lines.append("")

    lines.extend(_changes_markdown(data))

    # Section 1: Executive Summary & KPIs
    lines.append("## 1. Executive Summary & KPIs")
    lines.append("")
    lines.append("This report presents the findings and asset inventory resulting from automated external attack surface reconnaissance. "
                 "All passive discovery and active scanning procedures adhered strictly to the engagement scope and authorization terms.")
    lines.append("")
    lines.append("### Finding Candidates Counts")
    lines.append("")
    lines.append("| Severity | Count | Primary Impact |")
    lines.append("|---|---|---|")
    lines.append(f"| `CRITICAL` | **{k['critical']}** | Remote code execution, credential exposure, or open management interfaces |")
    lines.append(f"| `HIGH` | **{k['high']}** | Directory listings, unauthenticated APIs, DNS zone transfers, end-of-life daemons |")
    lines.append(f"| `MEDIUM` | **{k['medium']}** | Email security omissions (SPF/DMARC), public SSH, weak TLS/SSH ciphers, cloud NSG rules |")
    lines.append(f"| `LOW` | **{k['low']}** | Missing defensive HTTP security headers, public WHOIS registrant disclosures |")
    lines.append(f"| `INFO` | **{k['info']}** | Service banners, technology version footprints, informational reconnaissance data |")
    lines.append(f"| **TOTAL** | **{k['total_findings']}** | **Total candidate findings identified** |")
    lines.append("")
    lines.append("### Perimeter Attack Surface KPIs")
    lines.append("")
    lines.append("| Perimeter Metric | Count | Operational Notes |")
    lines.append("|---|---|---|")
    sub_detail = f"{k['subdomains']} total"
    if k['new_subdomains'] or k['gone_subdomains']:
        sub_detail += f" (+{k['new_subdomains']} new, -{k['gone_subdomains']} decommissioned)"
    lines.append(f"| **Subdomains Discovered** | **{k['subdomains']}** | {sub_detail} |")
    lines.append(f"| **Resolving Hosts** | **{k['resolving_hosts']}** | Public DNS A/AAAA records verified |")
    lines.append(f"| **Live Web Hosts** | **{k['live_web_hosts']}** | Responsive HTTP/HTTPS endpoints detected via httpx probe |")
    lines.append(f"| **Target IPs Scanned** | **{k['targets_scanned']}** | External infrastructure endpoints scanned |")
    cve_detail = f"{k['cves_total']} unique CVEs"
    if k['cves_kev'] > 0:
        cve_detail += f" (**{k['cves_kev']} CISA Known Exploited [KEV]**)"
    lines.append(f"| **CVEs Identified** | **{k['cves_total']}** | {cve_detail} |")
    lines.append(f"| **Cloud Public IPs** | **{k['cloud_ips_total']}** | {k['cloud_ips_azure']} Azure + {k['cloud_ips_gcp']} GCP + {k['cloud_ips_aws']} AWS |")
    lines.append("")

    # Section 2: Finding Candidates (Prioritised)
    lines.append("## 2. Finding Candidates (Prioritised)")
    lines.append("")
    lines.append("*All findings are automated candidates to validate through manual review, not definitive penetration test conclusions.*\n")
    if data.findings:
        lines.append("| Severity | Asset | Finding Title | Target | Evidence | Rule Key |")
        lines.append("|---|---|---|---|---|---|")
        for f in data.findings:
            sev_badge = f"`{f['severity']}`"
            asset_id = ", ".join(f"`{a}`" for a in f.get("asset_ids", [])) or "-"
            title = _escape_md_cell(f["title"])
            evidence = _escape_md_cell(f["evidence"])
            key = f"`{_escape_md_cell(f['key'])}`" if f["key"] else "-"
            target = _escape_md_cell(f.get("target", "")) or "-"
            lines.append(f"| {sev_badge} | {asset_id} | {title} | {target} | `{evidence}` | {key} |")
    else:
        lines.append("*No automated finding candidates identified for this run.*")
    lines.append("")
    lines.extend(_suppressed_markdown(data))

    # Section 2b: Asset inventory
    lines.append("## 2b. Asset Inventory")
    lines.append("")
    lines.append("*Stable identifiers (persisted per scope) group tests, findings and CVEs by asset for risk review and forensics.*\n")
    if data.assets:
        lines.append("| ID | Type | Asset | Product / Version | Open Ports | Findings | CVEs |")
        lines.append("|---|---|---|---|---|---|---|")
        for a in data.assets:
            fcount = len(a["findings"])
            fcell = _escape_md_cell("; ".join(f.get("title", "") for f in a["findings"])) if fcount else "-"
            fcell = f"{fcount} — {fcell}" if fcount else "-"
            cves = ", ".join(sorted({c["cve"] for c in a["cves"] if c.get("cve")})) or "-"
            lines.append(
                f"| `{a['id']}` | {a['type']} | {_escape_md_cell(asset_label(a))} "
                f"(`{_escape_md_cell(a['key'])}`) | {_escape_md_cell(asset_product(a))} "
                f"| {_escape_md_cell(asset_ports(a))} | {fcell} | {_escape_md_cell(cves)} |"
            )
    else:
        lines.append("*No assets identified for this run.*")
    lines.append("")

    # Section 3: Service Inventory & CVE / CISA KEV Correlation
    lines.append("## 3. Service Inventory & CVE / CISA KEV Correlation")
    lines.append("")
    if data.service_cves:
        lines.append("| IP:Port | Service & Version | CVEs | Summary |")
        lines.append("|---|---|---|---|")
        for sc in data.service_cves:
            endpoint = f"{sc['ip']}:{sc['port']}"
            svc = f"{sc['service']} {sc['version']}".strip() or "-"
            cve_str = f"`{sc['cve']}`"
            if sc.get("cvss_str") and sc["cvss_str"] != "N/A":
                cve_str += f" ({sc['cvss_str']})"
            if sc.get("is_kev"):
                cve_str += " **[KEV]**"
            summary = _escape_md_cell(sc["summary"])
            lines.append(f"| `{endpoint}` | `{_escape_md_cell(svc)}` | {cve_str} | {summary} |")
    else:
        lines.append("*No correlated CVEs or known exploited vulnerabilities identified on exposed services.*")
    lines.append("")

    # Section 4: Web Surface & Potential Entry Points
    lines.append("## 4. Web Surface & Potential Entry Points")
    lines.append("")
    lines.append("### 4.1 Exposed Well-Known Paths / API Schemas")
    lines.append("")
    if data.exposed_paths:
        lines.append("| Target URL | Category | Evidence Snippet |")
        lines.append("|---|---|---|")
        for ep in data.exposed_paths:
            lines.append(f"| `{_escape_md_cell(ep['url'])}` | **{_escape_md_cell(ep['category'])}** | `{_escape_md_cell(ep['snippet'])}` |")
    else:
        lines.append("*No sensitive well-known paths or exposed API schemas detected.*")
    lines.append("")

    lines.append("### 4.2 CORS & Cookie Weaknesses")
    lines.append("")
    if data.cors_cookies:
        lines.append("| Target URL | Issue Type | Detail |")
        lines.append("|---|---|---|")
        for cc in data.cors_cookies:
            lines.append(f"| `{_escape_md_cell(cc['url'])}` | **{_escape_md_cell(cc['issue_type'])}** | {_escape_md_cell(cc['detail'])} |")
    else:
        lines.append("*No insecure CORS configurations or missing cookie security flags detected.*")
    lines.append("")

    lines.append("### 4.3 Potential Parameter Entry Points")
    lines.append("")
    if data.entry_points:
        lines.append("| Category | Parameter or Pattern | Sample URL |")
        lines.append("|---|---|---|")
        for ent in data.entry_points:
            lines.append(f"| **{_escape_md_cell(ent['category'])}** | `{_escape_md_cell(ent['param_or_pattern'])}` | `{_escape_md_cell(ent['sample_url'])}` |")
    else:
        lines.append("*No dynamic parameter entry points extracted from historical or crawling logs.*")
    lines.append("")

    lines.append("### 4.4 Directory Listings")
    lines.append("")
    if data.dir_listings:
        for url in data.dir_listings:
            lines.append(f"- `{_escape_md_cell(url)}`")
    else:
        lines.append("*No unauthenticated directory listings identified.*")
    lines.append("")

    # Section 5: Cloud Perimeter (Grey-Box)
    lines.append("## 5. Cloud Perimeter (Grey-Box)")
    lines.append("")
    lines.append("### 5.1 Microsoft Azure Public IPs & Internet NSG Rules")
    lines.append("")
    if data.azure_public_ips:
        lines.append("| Public IP | Name | Resource Group | Attached Resource |")
        lines.append("|---|---|---|---|")
        for ip_row in data.azure_public_ips:
            lines.append(f"| `{ip_row['ip']}` | {_escape_md_cell(ip_row['name'])} | {_escape_md_cell(ip_row['resource_group'])} | {_escape_md_cell(ip_row['attached_to'])} |")
    else:
        lines.append("*No Azure public IP assets discovered or Azure Annex skipped.*")
    lines.append("")

    if data.azure_nsg_rules:
        lines.append("#### Azure Internet NSG Rules")
        lines.append("")
        lines.append("| NSG Name | Resource Group | Rule | Inbound Ports | Attached NICs |")
        lines.append("|---|---|---|---|---|")
        for rule in data.azure_nsg_rules:
            lines.append(f"| `{_escape_md_cell(rule['nsg'])}` | {_escape_md_cell(rule['resource_group'])} | {_escape_md_cell(rule['rule'])} | `{_escape_md_cell(rule['ports'])}` | {rule['attached_nics']} |")
        lines.append("")

    if data.azure_coverage:
        lines.append(f"**Azure Coverage**: `{data.azure_coverage}`\n")

    lines.append("### 5.2 Google Cloud (GCP) Public IPs & VPC Firewall Rules")
    lines.append("")
    if data.gcp_public_ips:
        lines.append("| Public IP | Name | Project | Region / Type |")
        lines.append("|---|---|---|---|")
        for g_row in data.gcp_public_ips:
            lines.append(f"| `{g_row['ip']}` | {_escape_md_cell(g_row['name'])} | {_escape_md_cell(g_row['project'])} | {_escape_md_cell(g_row['region_type'])} |")
    else:
        lines.append("*No GCP public IP assets discovered or GCP Annex skipped.*")
    lines.append("")

    if data.gcp_firewall_rules:
        lines.append("#### GCP Firewall Internet Rules")
        lines.append("")
        lines.append("| Rule Name | Project | Network | Direction / Priority | Action | Source Ranges | Allowed Ports |")
        lines.append("|---|---|---|---|---|---|---|")
        for f_row in data.gcp_firewall_rules:
            lines.append(f"| `{_escape_md_cell(f_row['name'])}` | {_escape_md_cell(f_row['project'])} | {_escape_md_cell(f_row['network'])} | {_escape_md_cell(f_row['direction_priority'])} | {_escape_md_cell(f_row['action'])} | `{_escape_md_cell(f_row['source_ranges'])}` | `{_escape_md_cell(f_row['allowed'])}` |")
        lines.append("")

    if data.gcp_coverage:
        lines.append(f"**GCP Coverage**: `{data.gcp_coverage}`\n")

    lines.append("### 5.3 Amazon Web Services (AWS) Public IPs, Endpoints & Security Groups")
    lines.append("")
    if data.aws_public_ips:
        lines.append("#### AWS Public IPs")
        lines.append("")
        lines.append("| Public IP | Name / Allocation ID | Region / Account | Resource Type |")
        lines.append("|---|---|---|---|")
        for a_row in data.aws_public_ips:
            lines.append(f"| `{a_row['ip']}` | {_escape_md_cell(a_row['name'])} | {_escape_md_cell(a_row['region'])} | {_escape_md_cell(a_row['resource_type'])} |")
        lines.append("")
    else:
        lines.append("*No AWS public IP assets discovered or AWS Annex skipped.*")
        lines.append("")

    if data.aws_public_endpoints:
        lines.append("#### AWS Public Endpoints")
        lines.append("")
        lines.append("| Endpoint / Hostname | Resource Type | Region | Detail |")
        lines.append("|---|---|---|---|")
        for ep_row in data.aws_public_endpoints:
            lines.append(f"| `{_escape_md_cell(ep_row['hostname'])}` | {_escape_md_cell(ep_row['resource_type'])} | {_escape_md_cell(ep_row['region'])} | {_escape_md_cell(ep_row['detail'])} |")
        lines.append("")

    if data.aws_sg_rules:
        lines.append("#### AWS Internet Security Group Rules")
        lines.append("")
        lines.append("| Group ID | Group Name | Region | Inbound Ports | Source CIDR |")
        lines.append("|---|---|---|---|---|")
        for s_row in data.aws_sg_rules:
            lines.append(f"| `{_escape_md_cell(s_row['group_id'])}` | {_escape_md_cell(s_row['group_name'])} | {_escape_md_cell(s_row['region'])} | `{_escape_md_cell(s_row['ports'])}` | `{_escape_md_cell(s_row['cidr'])}` |")
        lines.append("")

    if data.aws_coverage:
        lines.append(f"**AWS Coverage**: `{data.aws_coverage}`\n")

    # Section 6: Cloud Security Posture
    lines.append("## 6. Cloud Security Posture")
    lines.append("")
    lines.append("*Automated cloud security configuration checks (candidates to validate, not definitive penetration test conclusions).*\n")

    lines.append("### 6.1 Azure Security Posture")
    lines.append("")
    if data.azure_posture:
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in data.azure_posture:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
    else:
        lines.append("*No Azure security posture findings recorded.*")
    lines.append("")

    lines.append("### 6.2 GCP Security Posture")
    lines.append("")
    if data.gcp_posture:
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in data.gcp_posture:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
    else:
        lines.append("*No GCP security posture findings recorded.*")
    lines.append("")

    lines.append("### 6.3 AWS Security Posture")
    lines.append("")
    if data.aws_posture:
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in data.aws_posture:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
    else:
        lines.append("*No AWS security posture findings recorded.*")
    lines.append("")

    # Section 7: SaaS Security Posture
    lines.append("## 7. SaaS Security Posture")
    lines.append("")
    lines.append("*Automated SaaS security configuration checks (candidates to validate, not definitive penetration test conclusions).*\n")

    m365_posture = [p for p in data.saas_posture if p.get("key", "").startswith("m365-")]
    gh_posture = [p for p in data.saas_posture if p.get("key", "").startswith("gh-")]
    gws_posture = [p for p in data.saas_posture if p.get("key", "").startswith("gws-")]
    other_saas = [p for p in data.saas_posture if not (p.get("key", "").startswith("m365-") or p.get("key", "").startswith("gh-") or p.get("key", "").startswith("gws-"))]

    lines.append("### 7.1 Microsoft 365 Posture")
    lines.append("")
    if m365_posture:
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in m365_posture:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
    else:
        lines.append("*No Microsoft 365 security posture findings recorded.*")
    lines.append("")

    lines.append("### 7.2 GitHub Posture")
    lines.append("")
    if gh_posture:
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in gh_posture:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
    else:
        lines.append("*No GitHub security posture findings recorded.*")
    lines.append("")

    lines.append("### 7.3 Google Workspace Posture")
    lines.append("")
    if gws_posture:
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in gws_posture:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
    else:
        lines.append("*No Google Workspace security posture findings recorded.*")
    lines.append("")

    if other_saas:
        lines.append("### 7.4 Other SaaS Posture")
        lines.append("")
        lines.append("| Severity | Service | Resource | Title | Detail |")
        lines.append("|---|---|---|---|---|")
        for p in other_saas:
            lines.append(f"| `{p['severity']}` | {_escape_md_cell(p['service'])} | {_escape_md_cell(p['resource'])} | {_escape_md_cell(p['title'])} | {_escape_md_cell(p['detail'])} |")
        lines.append("")

    # Section 8: Changes vs Previous Run
    lines.append("## 8. Changes vs Previous Run (`Diff`)")
    lines.append("")
    if data.diff_content.strip():
        lines.append(data.diff_content.strip())
    elif any(data.diff_summary.values()):
        for sec in ("New", "Resolved", "Persisting"):
            items = data.diff_summary[sec]
            lines.append(f"### {sec} ({len(items)})")
            lines.append("")
            if items:
                for it in items:
                    lines.append(f"- {it}")
            else:
                lines.append("*(None)*")
            lines.append("")
    else:
        lines.append("*No previous baseline run available for comparison.*")
    lines.append("")

    # Section 9: CLI Evidence & Tool Outputs
    lines.append("## 9. CLI Evidence & Tool Outputs")
    lines.append("")
    if data.commands:
        for cmd in data.commands:
            phase = cmd.get("phase", "General")
            title = cmd.get("title", "command")
            cmd_str = cmd.get("cmd", "")
            out_str = cmd.get("output", "")
            lines.append(f"<details><summary>{phase} — {title} (<code>$ {_escape_md_cell(cmd_str)}</code>)</summary>\n")
            lines.append("```console")
            lines.append(f"$ {cmd_str}")
            if out_str:
                lines.append(out_str)
            lines.append("```")
            lines.append("</details>\n")
    else:
        lines.append("*No command outputs recorded in console logs.*")
    lines.append("")

    # Section 10: Gaps & Tool Versions
    lines.append("## 10. Gaps & Tool Versions")
    lines.append("")
    lines.append("### 10.1 Tool Failures and Environmental Gaps")
    lines.append("")
    if data.gaps:
        for g in data.gaps:
            lines.append(f"- {g}")
    else:
        lines.append("*No tool failures or execution gaps recorded during this assessment cycle.*")
    lines.append("")

    lines.append("### 10.2 Tool Versions & Runtime Dependencies")
    lines.append("")
    if data.tool_versions:
        lines.append("| Tool / Utility | Discovered Version |")
        lines.append("|---|---|")
        for tv in data.tool_versions:
            parts = tv.split(maxsplit=1)
            t_name = parts[0] if parts else tv
            t_ver = parts[1] if len(parts) > 1 else "-"
            lines.append(f"| **{_escape_md_cell(t_name)}** | `{_escape_md_cell(t_ver)}` |")
    else:
        lines.append("*No tool versions logged.*")
    lines.append("")

    return "\n".join(lines)


# =====================================================================
# Interactive HTML5 Application Generator
# =====================================================================

def generate_html(data: RunData) -> str:
    """Generate modern, interactive tabbed dark-mode HTML5 application."""
    m = data.meta
    k = data.kpis

    engagement_title = html.escape(m.get("engagement") or "External Reconnaissance Assessment")
    run_date = html.escape(m.get("date") or datetime.date.today().isoformat())
    scope_name = html.escape(m.get("scope") or "default")
    egress_ip = html.escape(m.get("egress_ip") or "unknown")

    auth_by = m.get("authorised_by", "")
    auth_ref = m.get("authorisation_ref", "")
    if auth_by:
        auth_badge = f"""<span class="badge badge-auth" title="Authorised By">{html.escape(auth_by)} ({html.escape(auth_ref or 'Ref N/A')})</span>"""
    else:
        auth_badge = """<span class="badge badge-passive" title="Passive / Unauthorised">Passive / Self-Assessment</span>"""

    # Extract unique phases from recorded commands
    command_phases: list[str] = []
    seen_phases: set[str] = set()
    for c in data.commands:
        p = c.get("phase", "General")
        if p not in seen_phases:
            seen_phases.add(p)
            command_phases.append(p)

    # --- Asset inventory tab (precomputed rows + type-filter options) ---
    _asset_types = sorted({a["type"] for a in data.assets})
    asset_type_options = "".join(
        f'<option value="{html.escape(t)}">{html.escape(t)}</option>' for t in _asset_types
    )

    def _asset_row(a: dict) -> str:
        findings = sorted(a["findings"], key=lambda f: SEV_RANK.get(f.get("severity", "INFO").upper(), 4))
        if findings:
            fcell = "".join(
                f'<span class="badge badge-{f["severity"].lower()}" title="{html.escape(f.get("title",""))}">'
                f'{html.escape(f.get("title",""))}</span> '
                for f in findings
            )
        else:
            fcell = '<span class="muted">none</span>'
        cve_ids = sorted({c["cve"] for c in a["cves"] if c.get("cve")})
        has_kev = any(c.get("is_kev") for c in a["cves"])
        if cve_ids:
            kev = ' <span class="badge badge-kev">KEV</span>' if has_kev else ""
            ccell = f'<span class="mono">{html.escape(", ".join(cve_ids))}</span>{kev}'
        else:
            ccell = '<span class="muted">-</span>'
        worst = min((SEV_RANK.get(f.get("severity", "INFO").upper(), 4) for f in findings), default=4)
        worst_name = ["critical", "high", "medium", "low", "info"][worst]
        search_blob = " ".join([
            a["id"], a["type"], asset_label(a), a["key"], asset_product(a), asset_ports(a),
            " ".join(f.get("title", "") for f in findings), " ".join(cve_ids),
        ]).lower()
        return (
            f'<tr class="asset-row" id="asset-{html.escape(a["id"])}" '
            f'data-type="{html.escape(a["type"])}" data-text="{html.escape(search_blob)}">'
            f'<td><code class="pill pill-{worst_name}">{html.escape(a["id"])}</code></td>'
            f'<td><span class="badge badge-info">{html.escape(a["type"])}</span></td>'
            f'<td><strong>{html.escape(asset_label(a))}</strong><br><span class="mono muted">{html.escape(a["key"])}</span></td>'
            f'<td class="mono">{html.escape(asset_product(a))}</td>'
            f'<td class="mono">{html.escape(asset_ports(a))}</td>'
            f'<td>{fcell}</td>'
            f'<td>{ccell}</td>'
            f'</tr>'
        )

    asset_rows_html = "".join(_asset_row(a) for a in data.assets) or \
        "<tr><td colspan='7' class='empty-state'>No assets identified</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{engagement_title} — Attack Surface Assessment Report</title>
<style>
  :root {{
    --bg-page: #0b0f19;
    --bg-card: #111827;
    --bg-card-hover: #162032;
    --bg-terminal: #05080f;
    --border: #1f2937;
    --border-bright: #374151;
    --text-primary: #f9fafb;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --critical: #ef4444;
    --critical-bg: rgba(239, 68, 68, 0.15);
    --high: #f97316;
    --high-bg: rgba(249, 115, 22, 0.15);
    --medium: #eab308;
    --medium-bg: rgba(234, 179, 8, 0.15);
    --low: #3b82f6;
    --low-bg: rgba(59, 130, 246, 0.15);
    --info: #6b7280;
    --info-bg: rgba(107, 114, 128, 0.15);
    --accent: #10b981;
    --accent-bg: rgba(16, 185, 129, 0.15);
    --radius: 8px;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: var(--bg-page);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    padding-bottom: 4rem;
  }}

  /* Top Navigation Bar */
  header {{
    background: #0f172a;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 50;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
  }}
  .header-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.75rem;
    flex-wrap: wrap;
    gap: 1rem;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }}
  .shield-icon {{
    width: 30px;
    height: 30px;
    fill: var(--accent);
  }}
  .brand-title h1 {{
    font-size: 1.15rem;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -0.01em;
  }}
  .brand-title .subtitle {{
    font-size: 0.75rem;
    color: var(--text-secondary);
  }}
  .header-pills {{
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
  }}

  /* Navigation Tabs */
  .nav-tabs {{
    display: flex;
    padding: 0 1.75rem;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    overflow-x: auto;
    background: #0d1322;
  }}
  .nav-tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
    padding: 0.75rem 1.1rem;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.45rem;
    white-space: nowrap;
    transition: all 0.15s ease;
  }}
  .nav-tab:hover {{
    color: #ffffff;
    background: rgba(255, 255, 255, 0.02);
  }}
  .nav-tab.active {{
    color: #ffffff;
    border-bottom-color: var(--accent);
    background: rgba(16, 185, 129, 0.06);
  }}
  .nav-tab .tab-badge {{
    background: rgba(255, 255, 255, 0.1);
    color: var(--text-primary);
    padding: 0.1rem 0.45rem;
    border-radius: 9999px;
    font-size: 0.7rem;
  }}

  /* Container */
  .container {{
    max-width: 1400px;
    margin: 1.5rem auto;
    padding: 0 1.5rem;
  }}

  /* Badges */
  .badge {{
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.55rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }}
  .badge-critical {{ background: var(--critical-bg); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); }}
  .badge-high {{ background: var(--high-bg); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.5); }}
  .badge-medium {{ background: var(--medium-bg); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.5); }}
  .badge-low {{ background: var(--low-bg); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.5); }}
  .badge-info {{ background: var(--info-bg); color: #d1d5db; border: 1px solid rgba(107, 114, 128, 0.5); }}
  .badge-auth {{ background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.4); }}
  .badge-passive {{ background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3); }}
  .badge-egress {{ background: #1e293b; color: #93c5fd; border: 1px solid #334155; font-family: monospace; }}

  /* Pulse animation for CISA KEV */
  @keyframes pulse-kev {{
    0% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); transform: scale(1); }}
    50% {{ box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); transform: scale(1.03); }}
    100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); transform: scale(1); }}
  }}
  .badge-kev {{
    background: #7f1d1d !important;
    color: #fee2e2 !important;
    border: 1px solid #ef4444 !important;
    animation: pulse-kev 2s infinite ease-in-out;
  }}

  /* KPI Grid */
  .kpi-section-title {{
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 700;
    margin-bottom: 0.65rem;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }}
  .kpi-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }}
  .kpi-card:hover {{
    transform: translateY(-2px);
    border-color: var(--border-bright);
  }}
  .kpi-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }}
  .kpi-label {{
    font-size: 0.75rem;
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .kpi-value {{
    font-size: 1.75rem;
    font-weight: 800;
    color: #ffffff;
  }}
  .kpi-subtext {{
    font-size: 0.72rem;
    color: var(--text-muted);
    margin-top: 0.25rem;
  }}
  .kpi-card.kpi-critical {{ border-left: 4px solid var(--critical); }}
  .kpi-card.kpi-high {{ border-left: 4px solid var(--high); }}
  .kpi-card.kpi-medium {{ border-left: 4px solid var(--medium); }}
  .kpi-card.kpi-low {{ border-left: 4px solid var(--low); }}
  .kpi-card.kpi-accent {{ border-left: 4px solid var(--accent); }}

  /* Cards */
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}
  .card-header {{
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(255, 255, 255, 0.015);
    flex-wrap: wrap;
    gap: 0.75rem;
  }}
  .card-title {{
    font-size: 0.95rem;
    font-weight: 700;
    color: #ffffff;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .card-body {{
    padding: 1.25rem;
  }}

  /* Tables */
  .table-responsive {{
    width: 100%;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    font-size: 0.84rem;
  }}
  th {{
    background: #151d2e;
    color: var(--text-secondary);
    font-weight: 600;
    padding: 0.65rem 0.9rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    text-transform: uppercase;
    font-size: 0.72rem;
    letter-spacing: 0.04em;
  }}
  th.sortable {{
    cursor: pointer;
    user-select: none;
    position: relative;
    padding-right: 1.5rem;
  }}
  th.sortable:hover {{ color: #fff; background: #1a2438; }}
  th.sortable::after {{
    content: "\\2195";
    position: absolute;
    right: 0.55rem;
    opacity: 0.3;
    font-size: 0.85em;
  }}
  th.sortable[data-sort-dir="asc"]::after {{ content: "\\25B2"; opacity: 0.9; }}
  th.sortable[data-sort-dir="desc"]::after {{ content: "\\25BC"; opacity: 0.9; }}
  td {{
    padding: 0.65rem 0.9rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    color: #d1d5db;
    vertical-align: middle;
  }}
  tr:hover td {{
    background: rgba(255, 255, 255, 0.02);
  }}
  td.mono {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.78rem;
    color: #e2e8f0;
  }}
  code.pill {{
    background: #1e293b;
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.76rem;
    color: #93c5fd;
    border: 1px solid #334155;
  }}

  /* Asset inventory helpers */
  .muted {{ color: var(--text-secondary); opacity: 0.75; }}
  .card-subtitle {{ color: var(--text-secondary); font-size: 0.8rem; font-weight: 400; margin-left: 0.5rem; }}
  a.asset-link {{ text-decoration: none; }}
  a.asset-link:hover code.pill {{ border-color: var(--accent); color: var(--accent); }}
  tr.asset-flash {{ animation: assetFlash 1.6s ease; }}
  @keyframes assetFlash {{ 0% {{ background: rgba(56,189,248,0.25); }} 100% {{ background: transparent; }} }}
  code.pill.pill-critical {{ color: #fca5a5; border-color: rgba(239,68,68,0.5); }}
  code.pill.pill-high {{ color: #fdba74; border-color: rgba(249,115,22,0.5); }}
  code.pill.pill-medium {{ color: #fde047; border-color: rgba(234,179,8,0.5); }}
  code.pill.pill-low {{ color: #93c5fd; border-color: rgba(59,130,246,0.5); }}
  code.pill.pill-info {{ color: #d1d5db; border-color: rgba(107,114,128,0.5); }}
  .kpi-card.clickable {{ cursor: pointer; }}
  .kpi-card.clickable:hover {{ border-color: var(--border-bright); transform: translateY(-2px); }}

  /* Filter Controls */
  .filter-bar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }}
  .filter-pills {{
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }}
  .filter-pill {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    border-radius: 9999px;
    padding: 0.3rem 0.75rem;
    font-size: 0.76rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
  }}
  .filter-pill:hover {{
    border-color: var(--border-bright);
    color: var(--text-primary);
  }}
  .filter-pill.active {{
    background: var(--accent);
    color: #05080f;
    border-color: var(--accent);
    font-weight: 700;
  }}
  .search-input {{
    background: #0d1322;
    border: 1px solid var(--border);
    color: #ffffff;
    border-radius: 6px;
    padding: 0.4rem 0.85rem;
    font-size: 0.82rem;
    min-width: 260px;
    outline: none;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }}
  .search-input:focus {{
    border-color: #3b82f6;
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
  }}

  /* CLI Terminal Window */
  .terminal-window {{
    background: var(--bg-terminal);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 1.25rem;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.4);
  }}
  .terminal-header {{
    background: #141c2c;
    border-bottom: 1px solid var(--border);
    padding: 0.5rem 0.85rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    flex-wrap: wrap;
  }}
  .terminal-left {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }}
  .terminal-dots {{
    display: flex;
    gap: 5px;
  }}
  .terminal-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }}
  .dot-red {{ background: #ff5f56; }}
  .dot-yellow {{ background: #ffbd2e; }}
  .dot-green {{ background: #27c93f; }}
  .terminal-title-text {{
    font-size: 0.78rem;
    font-weight: 700;
    color: #e2e8f0;
  }}
  .terminal-right {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .btn-terminal {{
    background: #1f2937;
    border: 1px solid var(--border-bright);
    color: #d1d5db;
    border-radius: 4px;
    font-size: 0.7rem;
    padding: 0.2rem 0.55rem;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.15s ease;
  }}
  .btn-terminal:hover {{
    background: #374151;
    color: #ffffff;
  }}
  .btn-terminal.copied {{
    background: #065f46;
    border-color: #10b981;
    color: #a7f3d0;
  }}
  .terminal-body {{
    padding: 1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.8rem;
    line-height: 1.5;
    color: #e2e8f0;
    max-height: 480px;
    overflow-y: auto;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .prompt, .terminal-prompt {{
    color: var(--accent);
    font-weight: 700;
    margin-right: 0.4rem;
  }}
  .cmd-text, .terminal-cmd {{
    color: #ffffff;
    font-weight: 600;
  }}
  .terminal-out {{
    margin-top: 0.5rem;
    color: #94a3b8;
    white-space: pre-wrap;
    word-break: break-word;
  }}

  /* Tab View Transitions */
  .tab-content {{
    display: none;
  }}
  .tab-content.active {{
    display: block;
    animation: fadeIn 0.15s ease;
  }}
  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(4px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}

  /* Empty state */
  .empty-state {{
    text-align: center;
    padding: 2.5rem 1rem;
    color: var(--text-muted);
    font-style: italic;
  }}

  /* Sub cards */
  .grid-2 {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
    gap: 1.25rem;
  }}
</style>
</head>
<body>

<header>
  <div class="header-top">
    <div class="brand">
      <svg class="shield-icon" viewBox="0 0 24 24">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
      </svg>
      <div class="brand-title">
        <h1>{engagement_title}</h1>
        <div class="subtitle">Scope: <strong>{scope_name}</strong> &bull; Assessment Date: {run_date}</div>
      </div>
    </div>
    <div class="header-pills">
      {auth_badge}
      <span class="badge badge-egress" title="Testing Egress IP">Egress: {egress_ip}</span>
    </div>
  </div>

  <nav class="nav-tabs" id="main-nav">
    <button class="nav-tab active" data-tab="tab-overview">
      Overview
    </button>
    <button class="nav-tab" data-tab="tab-findings">
      Findings &amp; Weaknesses <span class="tab-badge">{k['total_findings']}</span>
    </button>
    <button class="nav-tab" data-tab="tab-assets">
      Assets <span class="tab-badge">{len(data.assets)}</span>
    </button>
    <button class="nav-tab" data-tab="tab-hosts">
      Hosts, Services &amp; CVEs <span class="tab-badge">{k['cves_total']}</span>
    </button>
    <button class="nav-tab" data-tab="tab-web">
      Web &amp; Entry Points
    </button>
    <button class="nav-tab" data-tab="tab-cloud">
      Cloud &amp; DNS Posture
    </button>
    <button class="nav-tab" data-tab="tab-cli">
      CLI Explorer <span class="tab-badge">{len(data.commands)}</span>
    </button>
  </nav>
</header>

<main class="container">

  <!-- ================================================================= -->
  <!-- TAB 1: OVERVIEW -->
  <!-- ================================================================= -->
  <section id="tab-overview" class="tab-content active">
    
    {_changes_html(data)}

    <div class="kpi-section-title">Severity KPI Cards</div>
    <div class="kpi-grid">
      <div class="kpi-card kpi-critical clickable" data-jump-sev="CRITICAL" title="Show critical findings">
        <div class="kpi-top">
          <span class="kpi-label">Critical</span>
          <span class="badge badge-critical">Critical</span>
        </div>
        <div class="kpi-value">{k['critical']}</div>
        <div class="kpi-subtext">RCE / Exposed Mgmt</div>
      </div>
      <div class="kpi-card kpi-high clickable" data-jump-sev="HIGH" title="Show high findings">
        <div class="kpi-top">
          <span class="kpi-label">High</span>
          <span class="badge badge-high">High</span>
        </div>
        <div class="kpi-value">{k['high']}</div>
        <div class="kpi-subtext">Direct Takeover / Gaps</div>
      </div>
      <div class="kpi-card kpi-medium clickable" data-jump-sev="MEDIUM" title="Show medium findings">
        <div class="kpi-top">
          <span class="kpi-label">Medium</span>
          <span class="badge badge-medium">Medium</span>
        </div>
        <div class="kpi-value">{k['medium']}</div>
        <div class="kpi-subtext">Email / TLS / Service Posture</div>
      </div>
      <div class="kpi-card kpi-low clickable" data-jump-sev="LOW" title="Show low findings">
        <div class="kpi-top">
          <span class="kpi-label">Low</span>
          <span class="badge badge-low">Low</span>
        </div>
        <div class="kpi-value">{k['low']}</div>
        <div class="kpi-subtext">Defensive Headers / Hardening</div>
      </div>
      <div class="kpi-card clickable" data-jump-sev="ALL" title="Show all findings">
        <div class="kpi-top">
          <span class="kpi-label">Info / Total</span>
          <span class="badge badge-info">Total</span>
        </div>
        <div class="kpi-value">{k['total_findings']}</div>
        <div class="kpi-subtext">{k['info']} Informational Findings</div>
      </div>
    </div>

    <div class="kpi-section-title">Perimeter KPI Cards</div>
    <div class="kpi-grid">
      <div class="kpi-card kpi-accent">
        <div class="kpi-top">
          <span class="kpi-label">Subdomains</span>
          <span class="badge badge-auth">OSINT</span>
        </div>
        <div class="kpi-value">{k['subdomains']}</div>
        <div class="kpi-subtext">+{k['new_subdomains']} new &bull; -{k['gone_subdomains']} removed</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top">
          <span class="kpi-label">Live Web Hosts</span>
          <span class="badge badge-info">HTTP(S)</span>
        </div>
        <div class="kpi-value">{k['live_web_hosts']}</div>
        <div class="kpi-subtext">From {k['resolving_hosts']} resolving hosts</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top">
          <span class="kpi-label">Open Ports / Services</span>
          <span class="badge badge-info">Scanned</span>
        </div>
        <div class="kpi-value">{k['open_services']}</div>
        <div class="kpi-subtext">On {k['targets_scanned']} target IPs</div>
      </div>
      <div class="kpi-card {'kpi-critical' if k['cves_kev'] > 0 else ''}">
        <div class="kpi-top">
          <span class="kpi-label">CVEs / CISA KEVs</span>
          <span class="badge {'badge-kev' if k['cves_kev'] > 0 else 'badge-info'}">KEV: {k['cves_kev']}</span>
        </div>
        <div class="kpi-value">{k['cves_total']}</div>
        <div class="kpi-subtext">CISA Known Exploited: {k['cves_kev']}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top">
          <span class="kpi-label">Cloud Public IPs</span>
          <span class="badge badge-info">Multi-Cloud</span>
        </div>
        <div class="kpi-value">{k['cloud_ips_total']}</div>
        <div class="kpi-subtext">{k['cloud_ips_azure']} Azure &bull; {k['cloud_ips_gcp']} GCP &bull; {k['cloud_ips_aws']} AWS</div>
      </div>
    </div>

    <div class="grid-2">
      <!-- Domain Summary Table -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Domain Summary Table</span>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Root / Apex Domain</th>
                <th>Discovered Subdomains</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f"<tr><td><strong>{html.escape(c[0])}</strong></td><td class='mono'>{c[1]}</td></tr>" for c in data.subdomain_counts) if data.subdomain_counts else "<tr><td colspan='2' class='empty-state'>No subdomain count data available</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Execution Metadata -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Execution Metadata</span>
        </div>
        <div class="card-body">
          <table style="border: none;">
            <tr><td style="width: 140px; color: var(--text-secondary);">Engagement</td><td><strong>{engagement_title}</strong></td></tr>
            <tr><td style="color: var(--text-secondary);">Target Scope</td><td><code>{scope_name}</code></td></tr>
            <tr><td style="color: var(--text-secondary);">Run Date</td><td>{run_date}</td></tr>
            <tr><td style="color: var(--text-secondary);">Authorised By</td><td>{html.escape(auth_by or 'None')}</td></tr>
            <tr><td style="color: var(--text-secondary);">Authorisation Ref</td><td>{html.escape(auth_ref or 'None')}</td></tr>
            <tr><td style="color: var(--text-secondary);">Egress IP</td><td><code>{egress_ip}</code></td></tr>
            <tr><td style="color: var(--text-secondary);">Phases Run</td><td><code>{html.escape(m.get('phases', 'All'))}</code> (Active: {m.get('skip_active')}, Docker: {m.get('use_docker')})</td></tr>
          </table>
        </div>
      </div>
    </div>

    <!-- Gaps & Warnings Box -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Gaps / Warnings &amp; Tool Versions</span>
      </div>
      <div class="card-body">
        <div style="margin-bottom: 1rem;">
          <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.4rem;">Gaps / Tool Failures</h4>
          {"<ul style='padding-left: 1.25rem; color: #fca5a5; font-size: 0.82rem;'>" + "".join(f"<li>{html.escape(g)}</li>" for g in data.gaps) + "</ul>" if data.gaps else "<p style='color: var(--accent); font-size: 0.82rem;'>No tool failures or execution gaps recorded.</p>"}
        </div>
        <div>
          <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.4rem;">Tool Versions</h4>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            {"".join(f"<span class='badge badge-info' style='font-family: monospace;'>{html.escape(tv)}</span>" for tv in data.tool_versions) if data.tool_versions else "<span class='empty-state'>No tool versions logged</span>"}
          </div>
        </div>
      </div>
    </div>

  </section>

  <!-- ================================================================= -->
  <!-- TAB 2: FINDINGS & WEAKNESSES -->
  <!-- ================================================================= -->
  <section id="tab-findings" class="tab-content">
    <div class="card">
      <div class="card-header">
        <span class="card-title">Finding Candidates &amp; Exposure Weaknesses</span>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <div class="filter-pills" id="findings-severity-filters">
            <button class="filter-pill active" data-filter="ALL">All ({k['total_findings']})</button>
            <button class="filter-pill" data-filter="CRITICAL">Critical ({k['critical']})</button>
            <button class="filter-pill" data-filter="HIGH">High ({k['high']})</button>
            <button class="filter-pill" data-filter="MEDIUM">Medium ({k['medium']})</button>
            <button class="filter-pill" data-filter="LOW">Low ({k['low']})</button>
            <button class="filter-pill" data-filter="INFO">Info ({k['info']})</button>
          </div>
          <input type="text" class="search-input" id="finding-search-input" placeholder="Search title, target, key, evidence...">
        </div>

        <div class="table-responsive">
          <table id="findings-table">
            <thead>
              <tr>
                <th style="width: 110px;">Severity</th>
                <th style="width: 110px;">Asset</th>
                <th>Finding Title</th>
                <th>Target</th>
                <th>Affected Asset / Evidence</th>
                <th style="width: 220px;">Rule Key</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr class="finding-row" data-severity="{f['severity']}" data-asset="{html.escape(f.get('asset_id',''))}" data-text="{html.escape(f['title'].lower())} {html.escape(f.get('target', '').lower())} {html.escape(f['key'].lower())} {html.escape(f['evidence'].lower())} {html.escape(' '.join(f.get('asset_ids', [])).lower())}">
                <td><span class="badge badge-{f['severity'].lower()}">{f['severity']}</span></td>
                <td>{_finding_asset_cell(f)}</td>
                <td><strong>{html.escape(f['title'])}</strong></td>
                <td class="mono">{_target_html(f.get('target', ''))}</td>
                <td class="mono"><code>{html.escape(f['evidence'])}</code></td>
                <td><code class="pill">{html.escape(f['key'])}</code></td>
              </tr>''' for f in data.findings) if data.findings else "<tr><td colspan='6' class='empty-state'>No candidate findings identified</td></tr>"}
            </tbody>
          </table>
          <div id="findings-no-results" class="empty-state" style="display: none;">No findings match your filter criteria.</div>
        </div>
      </div>
    </div>
    {_suppressed_html(data)}
  </section>

  <!-- ================================================================= -->
  <!-- TAB: ASSET INVENTORY -->
  <!-- ================================================================= -->
  <section id="tab-assets" class="tab-content">
    <div class="card">
      <div class="card-header">
        <span class="card-title">Asset Inventory</span>
        <span class="card-subtitle">Stable identifiers group tests, findings and CVEs per asset for risk review and forensics.</span>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <select class="search-input" id="asset-type-filter" style="max-width: 220px;">
            <option value="ALL">All types ({len(data.assets)})</option>
            {asset_type_options}
          </select>
          <input type="text" class="search-input" id="asset-search-input" placeholder="Search id, type, name, IP, product, port, finding, CVE...">
        </div>
        <div class="table-responsive">
          <table id="assets-table">
            <thead>
              <tr>
                <th style="width: 110px;">ID</th>
                <th style="width: 120px;">Type</th>
                <th>Asset</th>
                <th>Product / Version</th>
                <th>Open Ports</th>
                <th>Findings</th>
                <th>CVEs</th>
              </tr>
            </thead>
            <tbody>
              {asset_rows_html}
            </tbody>
          </table>
          <div id="assets-no-results" class="empty-state" style="display: none;">No assets match your filter criteria.</div>
        </div>
      </div>
    </div>
  </section>

  <!-- ================================================================= -->
  <!-- TAB 3: HOSTS, SERVICES & CVES -->
  <!-- ================================================================= -->
  <section id="tab-hosts" class="tab-content">
    
    <!-- CVE & CISA KEV Correlation Table -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">CVE &amp; CISA KEV Correlation Table</span>
        <input type="text" class="search-input" id="cve-search-input" placeholder="Search CVEs, services, hosts...">
      </div>
      <div class="table-responsive">
        <table id="cve-table">
          <thead>
            <tr>
              <th style="width: 140px;">CVE ID</th>
              <th style="width: 100px;">CVSS</th>
              <th style="width: 130px;">CISA KEV</th>
              <th>Affected Asset</th>
              <th>Service / Version</th>
              <th>CVE Description</th>
            </tr>
          </thead>
          <tbody>
            {"".join(f'''<tr class="cve-row" data-text="{html.escape(sc['cve'].lower())} {html.escape(sc['ip'])} {html.escape(sc['service'].lower())} {html.escape(sc['summary'].lower())}">
              <td class="mono"><strong>{html.escape(sc['cve'])}</strong></td>
              <td><span class="badge {'badge-critical' if sc['cvss'] >= 9.0 else ('badge-high' if sc['cvss'] >= 7.0 else ('badge-medium' if sc['cvss'] >= 4.0 else 'badge-low'))}">{sc['cvss_str']}</span></td>
              <td>{('<span class="badge badge-kev">CISA KEV</span>' if sc['is_kev'] else '<span style="color: var(--text-muted); font-size: 0.75rem;">No</span>')}</td>
              <td class="mono">{html.escape(sc['ip'])}:{html.escape(sc['port'])}</td>
              <td><code>{html.escape(sc['service'])} {html.escape(sc['version'])}</code></td>
              <td>{html.escape(sc['summary'])}</td>
            </tr>''' for sc in data.service_cves) if data.service_cves else "<tr><td colspan='6' class='empty-state'>No correlated CVEs or known exploited vulnerabilities identified</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Host Inventory Table -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Host Inventory (IPs &amp; Organizations)</span>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th style="width: 150px;">IP Address</th>
              <th>Organization / ASN</th>
              <th>PTR Record</th>
              <th>Associated Hostnames</th>
            </tr>
          </thead>
          <tbody>
            {"".join(f'''<tr>
              <td class="mono"><strong>{html.escape(r['ip'])}</strong></td>
              <td>{html.escape(r['org'])}</td>
              <td class="mono">{html.escape(r['ptr'])}</td>
              <td class="mono">{html.escape(r['sample_hosts'])}</td>
            </tr>''' for r in data.ip_orgs) if data.ip_orgs else "<tr><td colspan='4' class='empty-state'>No IP organization mapping available</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- ================================================================= -->
  <!-- TAB 4: WEB & ENTRY POINTS -->
  <!-- ================================================================= -->
  <section id="tab-web" class="tab-content">

    <div class="filter-bar">
      <input type="text" class="search-input" id="web-search-input" placeholder="Filter web tables: path, URL, parameter, host...">
    </div>

    <div class="grid-2">
      <!-- Exposed Paths -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Exposed APIs &amp; Well-Known Paths</span>
          <span class="badge badge-high">{len(data.exposed_paths)}</span>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Target URL</th>
                <th>Category</th>
                <th>Snippet</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono"><a href="{html.escape(p['url'])}" target="_blank" rel="noopener" style="color: #93c5fd;">{html.escape(p['url'])}</a></td>
                <td><span class="badge badge-high">{html.escape(p['category'])}</span></td>
                <td class="mono">{html.escape(p['snippet'])}</td>
              </tr>''' for p in data.exposed_paths) if data.exposed_paths else "<tr><td colspan='3' class='empty-state'>No exposed sensitive paths identified</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Parameter Entry Points -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Potential Parameter Entry Points (IDOR / LFI / Redirect / SQLi)</span>
          <span class="badge badge-medium">{len(data.entry_points)}</span>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Parameter / Pattern</th>
                <th>Sample URL</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td><span class="badge badge-medium">{html.escape(ep['category'])}</span></td>
                <td class="mono"><code>{html.escape(ep['param_or_pattern'])}</code></td>
                <td class="mono">{html.escape(ep['sample_url'])}</td>
              </tr>''' for ep in data.entry_points) if data.entry_points else "<tr><td colspan='3' class='empty-state'>No parameter entry points discovered</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <!-- CORS & Cookie Weaknesses -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">CORS &amp; Cookie Hygiene</span>
          <span class="badge badge-low">{len(data.cors_cookies)}</span>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Target URL</th>
                <th>Issue Type</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono">{html.escape(c['url'])}</td>
                <td><span class="badge badge-low">{html.escape(c['issue_type'])}</span></td>
                <td>{html.escape(c['detail'])}</td>
              </tr>''' for c in data.cors_cookies) if data.cors_cookies else "<tr><td colspan='3' class='empty-state'>No CORS or cookie issues flagged</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Directory Listings -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Directory Listings</span>
          <span class="badge badge-high">{len(data.dir_listings)}</span>
        </div>
        <div class="card-body">
          {"<ul style='padding-left: 1.25rem; font-family: monospace; font-size: 0.82rem;'>" + "".join(f"<li style='margin-bottom: 0.35rem;'><a href='{html.escape(u)}' target='_blank' rel='noopener' style='color: #fca5a5;'>{html.escape(u)}</a></li>" for u in data.dir_listings) + "</ul>" if data.dir_listings else "<div class='empty-state'>No unauthenticated directory listings discovered</div>"}
        </div>
      </div>
    </div>

    <!-- Live Web Hosts -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Live Web Hosts Discovery (httpx)</span>
        <span class="badge badge-info">{len(data.httpx_all)}</span>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>URL</th>
              <th style="width: 80px;">Status</th>
              <th>Page Title</th>
              <th>Server</th>
              <th>Redirect Location</th>
            </tr>
          </thead>
          <tbody>
            {"".join(f'''<tr>
              <td class="mono"><a href="{html.escape(h['url'])}" target="_blank" rel="noopener" style="color: #93c5fd;">{html.escape(h['url'])}</a></td>
              <td><span class="badge {'badge-auth' if h['status'] in ('200','204') else ('badge-medium' if h['status'].startswith('3') else 'badge-low')}">{h['status']}</span></td>
              <td>{html.escape(h['title'])}</td>
              <td><code>{html.escape(h['server'])}</code></td>
              <td class="mono">{html.escape(h['location'])}</td>
            </tr>''' for h in data.httpx_all[:150]) if data.httpx_all else "<tr><td colspan='5' class='empty-state'>No live web hosts recorded</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- ================================================================= -->
  <!-- TAB 5: CLOUD & DNS POSTURE -->
  <!-- ================================================================= -->
  <section id="tab-cloud" class="tab-content">

    <div class="filter-bar">
      <input type="text" class="search-input" id="cloud-search-input" placeholder="Filter cloud/DNS tables: IP, resource, rule, domain...">
    </div>

    <!-- DNS & Mail Posture -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">DNS &amp; Mail Posture Summary</span>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>SPF (v=spf1)</th>
              <th>DMARC</th>
              <th>DNSSEC</th>
              <th>CAA Record</th>
              <th>Zone Transfer (AXFR)</th>
            </tr>
          </thead>
          <tbody>
            {"".join(f'''<tr>
              <td><strong>{html.escape(dp['domain'])}</strong></td>
              <td>{('<span class="badge badge-auth">Present</span>' if dp['spf'] else '<span class="badge badge-medium">Missing</span>')}</td>
              <td>{('<span class="badge badge-auth">Reject</span>' if dp['dmarc_reject'] else ('<span class="badge badge-low">Configured</span>' if dp['dmarc'] else '<span class="badge badge-medium">Missing</span>'))}</td>
              <td>{('<span class="badge badge-auth">Signed</span>' if dp['dnssec'] else '<span class="badge badge-low">Unsigned</span>')}</td>
              <td>{('<span class="badge badge-auth">Configured</span>' if dp['caa'] else '<span class="badge badge-low">Missing</span>')}</td>
              <td>{('<span class="badge badge-critical">ALLOWED</span>' if dp['axfr_allowed'] else '<span class="badge badge-auth">Refused</span>')}</td>
            </tr>''' for dp in data.dns_posture) if data.dns_posture else "<tr><td colspan='6' class='empty-state'>No DNS posture files found</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Apex Ownership -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Apex Domain Ownership</span>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Apex Domain</th>
              <th>Resolved IP</th>
              <th>Reverse DNS (PTR)</th>
              <th>Hosting Org / Netname</th>
            </tr>
          </thead>
          <tbody>
            {"".join(f'''<tr>
              <td><strong>{html.escape(a['domain'])}</strong></td>
              <td class="mono">{html.escape(a['ip'])}</td>
              <td class="mono">{html.escape(a['ptr'])}</td>
              <td>{html.escape(a['org'])}</td>
            </tr>''' for a in data.apex_ownership) if data.apex_ownership else "<tr><td colspan='4' class='empty-state'>No apex ownership data available</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Azure Perimeter -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Azure Public IPs &amp; Internet NSG Rules</span>
        <span class="badge badge-info">{len(data.azure_public_ips)} IPs</span>
      </div>
      <div class="card-body">
        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Azure Public IPs</h4>
        <div class="table-responsive" style="margin-bottom: 1.25rem;">
          <table>
            <thead>
              <tr>
                <th>Public IP</th>
                <th>Name</th>
                <th>Resource Group</th>
                <th>Attached Resource</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono"><strong>{html.escape(r['ip'])}</strong></td>
                <td>{html.escape(r['name'])}</td>
                <td>{html.escape(r['resource_group'])}</td>
                <td class="mono">{html.escape(r['attached_to'])}</td>
              </tr>''' for r in data.azure_public_ips) if data.azure_public_ips else "<tr><td colspan='4' class='empty-state'>No Azure public IPs discovered</td></tr>"}
            </tbody>
          </table>
        </div>

        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Azure Internet NSG Rules</h4>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>NSG Name</th>
                <th>Resource Group</th>
                <th>Rule Name</th>
                <th>Open Inbound Ports</th>
                <th>Attached NICs</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td><strong>{html.escape(nr['nsg'])}</strong></td>
                <td>{html.escape(nr['resource_group'])}</td>
                <td>{html.escape(nr['rule'])}</td>
                <td class="mono"><span class="badge badge-medium">{html.escape(nr['ports'])}</span></td>
                <td>{html.escape(nr['attached_nics'])}</td>
              </tr>''' for nr in data.azure_nsg_rules) if data.azure_nsg_rules else "<tr><td colspan='5' class='empty-state'>No Internet-exposed NSG rules recorded</td></tr>"}
            </tbody>
          </table>
        </div>
        {f"<p style='margin-top: 0.75rem; font-size: 0.78rem; color: var(--text-muted);'>Coverage: {html.escape(data.azure_coverage)}</p>" if data.azure_coverage else ""}
      </div>
    </div>

    <!-- GCP Perimeter -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Google Cloud (GCP) Public IPs &amp; Firewall Rules</span>
        <span class="badge badge-info">{len(data.gcp_public_ips)} IPs</span>
      </div>
      <div class="card-body">
        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">GCP Public IPs</h4>
        <div class="table-responsive" style="margin-bottom: 1.25rem;">
          <table>
            <thead>
              <tr>
                <th>Public IP</th>
                <th>Name</th>
                <th>Project</th>
                <th>Region / Type</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono"><strong>{html.escape(gr['ip'])}</strong></td>
                <td>{html.escape(gr['name'])}</td>
                <td>{html.escape(gr['project'])}</td>
                <td>{html.escape(gr['region_type'])}</td>
              </tr>''' for gr in data.gcp_public_ips) if data.gcp_public_ips else "<tr><td colspan='4' class='empty-state'>No GCP public IPs discovered</td></tr>"}
            </tbody>
          </table>
        </div>

        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">GCP VPC Firewall Inbound Rules</h4>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Project</th>
                <th>Network</th>
                <th>Direction / Priority</th>
                <th>Action</th>
                <th>Source Ranges</th>
                <th>Allowed Ports</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td><strong>{html.escape(fr['name'])}</strong></td>
                <td>{html.escape(fr['project'])}</td>
                <td>{html.escape(fr['network'])}</td>
                <td>{html.escape(fr['direction_priority'])}</td>
                <td><span class="badge {'badge-auth' if fr['action'].upper()=='ALLOW' else 'badge-low'}">{html.escape(fr['action'])}</span></td>
                <td class="mono">{html.escape(fr['source_ranges'])}</td>
                <td class="mono"><span class="badge badge-medium">{html.escape(fr['allowed'])}</span></td>
              </tr>''' for fr in data.gcp_firewall_rules) if data.gcp_firewall_rules else "<tr><td colspan='7' class='empty-state'>No GCP firewall rules recorded</td></tr>"}
            </tbody>
          </table>
        </div>
        {f"<p style='margin-top: 0.75rem; font-size: 0.78rem; color: var(--text-muted);'>Coverage: {html.escape(data.gcp_coverage)}</p>" if data.gcp_coverage else ""}
      </div>
    </div>

    <!-- AWS Perimeter -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Amazon Web Services (AWS) Public IPs, Endpoints &amp; Security Groups</span>
        <span class="badge badge-info">{len(data.aws_public_ips)} IPs</span>
      </div>
      <div class="card-body">
        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">AWS Public IPs</h4>
        <div class="table-responsive" style="margin-bottom: 1.25rem;">
          <table>
            <thead>
              <tr>
                <th>Public IP</th>
                <th>Name / Allocation ID</th>
                <th>Region / Account</th>
                <th>Resource Type</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono"><strong>{html.escape(ar['ip'])}</strong></td>
                <td>{html.escape(ar['name'])}</td>
                <td>{html.escape(ar['region'])}</td>
                <td class="mono">{html.escape(ar['resource_type'])}</td>
              </tr>''' for ar in data.aws_public_ips) if data.aws_public_ips else "<tr><td colspan='4' class='empty-state'>No AWS public IPs discovered</td></tr>"}
            </tbody>
          </table>
        </div>

        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">AWS Public Endpoints</h4>
        <div class="table-responsive" style="margin-bottom: 1.25rem;">
          <table>
            <thead>
              <tr>
                <th>Endpoint / Hostname</th>
                <th>Resource Type</th>
                <th>Region</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono"><strong>{html.escape(ep['hostname'])}</strong></td>
                <td><span class="badge badge-info">{html.escape(ep['resource_type'])}</span></td>
                <td>{html.escape(ep['region'])}</td>
                <td class="mono">{html.escape(ep['detail'])}</td>
              </tr>''' for ep in data.aws_public_endpoints) if data.aws_public_endpoints else "<tr><td colspan='4' class='empty-state'>No AWS public endpoints discovered</td></tr>"}
            </tbody>
          </table>
        </div>

        <h4 style="font-size: 0.82rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">AWS Security Groups Open to Internet</h4>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Group ID</th>
                <th>Group Name</th>
                <th>Region</th>
                <th>Inbound Ports</th>
                <th>Source CIDR</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr>
                <td class="mono"><strong>{html.escape(sr['group_id'])}</strong></td>
                <td>{html.escape(sr['group_name'])}</td>
                <td>{html.escape(sr['region'])}</td>
                <td class="mono"><span class="badge badge-medium">{html.escape(sr['ports'])}</span></td>
                <td class="mono">{html.escape(sr['cidr'])}</td>
              </tr>''' for sr in data.aws_sg_rules) if data.aws_sg_rules else "<tr><td colspan='5' class='empty-state'>No Internet-exposed AWS Security Groups recorded</td></tr>"}
            </tbody>
          </table>
        </div>
        {f"<p style='margin-top: 0.75rem; font-size: 0.78rem; color: var(--text-muted);'>Coverage: {html.escape(data.aws_coverage)}</p>" if data.aws_coverage else ""}
      </div>
    </div>

    <!-- Cloud Security Posture (CSPM) -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Cloud Security Posture</span>
        <span class="badge badge-info">{len(data.all_posture)} Candidates</span>
      </div>
      <div class="card-body">
        <p style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 1rem;">
          Automated configuration posture checks across cloud providers (candidates for validation, not definitive penetration test conclusions).
        </p>

        <div class="filter-bar">
          <div class="filter-pills" id="posture-cloud-filters">
            <button class="filter-pill active" data-cloud-filter="ALL">All ({len(data.all_posture)})</button>
            <button class="filter-pill" data-cloud-filter="AZURE">Azure ({len(data.azure_posture)})</button>
            <button class="filter-pill" data-cloud-filter="GCP">GCP ({len(data.gcp_posture)})</button>
            <button class="filter-pill" data-cloud-filter="AWS">AWS ({len(data.aws_posture)})</button>
          </div>
          <input type="text" class="search-input" id="posture-search-input" placeholder="Search posture checks, resources, services...">
        </div>

        <div class="table-responsive">
          <table id="posture-table">
            <thead>
              <tr>
                <th style="width: 100px;">Severity</th>
                <th style="width: 90px;">Cloud</th>
                <th style="width: 130px;">Service</th>
                <th style="width: 170px;">Resource</th>
                <th>Finding Title</th>
                <th>Configuration Detail</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr class="posture-row" data-cloud="{p['cloud'].upper()}" data-text="{html.escape(p['cloud'].lower())} {html.escape(p['severity'].lower())} {html.escape(p['service'].lower())} {html.escape(p['resource'].lower())} {html.escape(p['title'].lower())} {html.escape(p['detail'].lower())}">
                <td><span class="badge badge-{p['severity'].lower()}">{p['severity']}</span></td>
                <td><span class="badge badge-info">{p['cloud'].upper()}</span></td>
                <td><code>{html.escape(p['service'])}</code></td>
                <td class="mono">{html.escape(p['resource'])}</td>
                <td><strong>{html.escape(p['title'])}</strong></td>
                <td class="mono">{html.escape(p['detail'])}</td>
              </tr>''' for p in data.all_posture) if data.all_posture else "<tr><td colspan='6' class='empty-state'>No cloud security posture findings recorded</td></tr>"}
            </tbody>
          </table>
          <div id="posture-no-results" class="empty-state" style="display: none;">No posture findings match your filter criteria.</div>
        </div>
      </div>
    </div>

    <!-- SaaS Security Posture -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">SaaS Security Posture</span>
        <span class="badge badge-info">{len(data.saas_posture)} Candidates</span>
      </div>
      <div class="card-body">
        <p style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 1rem;">
          Automated configuration posture checks across SaaS tenants (candidates for validation, not definitive penetration test conclusions).
        </p>

        <div class="filter-bar">
          <div class="filter-pills" id="saas-posture-filters">
            <button class="filter-pill active" data-saas-filter="ALL">All ({len(data.saas_posture)})</button>
            <button class="filter-pill" data-saas-filter="m365-">Microsoft 365 ({len([p for p in data.saas_posture if p.get('key', '').startswith('m365-')])})</button>
            <button class="filter-pill" data-saas-filter="gh-">GitHub ({len([p for p in data.saas_posture if p.get('key', '').startswith('gh-')])})</button>
            <button class="filter-pill" data-saas-filter="gws-">Google Workspace ({len([p for p in data.saas_posture if p.get('key', '').startswith('gws-')])})</button>
          </div>
          <input type="text" class="search-input" id="saas-posture-search-input" placeholder="Search SaaS posture checks, resources, services...">
        </div>

        <div class="table-responsive">
          <table id="saas-posture-table">
            <thead>
              <tr>
                <th style="width: 100px;">Severity</th>
                <th style="width: 90px;">Provider</th>
                <th style="width: 130px;">Service</th>
                <th style="width: 170px;">Resource</th>
                <th>Finding Title</th>
                <th>Configuration Detail</th>
              </tr>
            </thead>
            <tbody>
              {"".join(f'''<tr class="saas-posture-row" data-prefix="{"m365-" if p.get('key', '').startswith('m365-') else ("gh-" if p.get('key', '').startswith('gh-') else ("gws-" if p.get('key', '').startswith('gws-') else "other"))}" data-text="{html.escape(p.get('provider', '').lower())} {html.escape(p.get('key', '').lower())} {html.escape(p['severity'].lower())} {html.escape(p['service'].lower())} {html.escape(p['resource'].lower())} {html.escape(p['title'].lower())} {html.escape(p['detail'].lower())}">
                <td><span class="badge badge-{p['severity'].lower()}">{p['severity']}</span></td>
                <td><span class="badge badge-info">{html.escape(p.get('provider', 'SaaS'))}</span></td>
                <td><code>{html.escape(p['service'])}</code></td>
                <td class="mono">{html.escape(p['resource'])}</td>
                <td><strong>{html.escape(p['title'])}</strong></td>
                <td class="mono">{html.escape(p['detail'])}</td>
              </tr>''' for p in data.saas_posture) if data.saas_posture else "<tr><td colspan='6' class='empty-state'>No SaaS security posture findings recorded</td></tr>"}
            </tbody>
          </table>
          <div id="saas-posture-no-results" class="empty-state" style="display: none;">No SaaS posture findings match your filter criteria.</div>
        </div>
      </div>
    </div>
  </section>

  <!-- ================================================================= -->
  <!-- TAB 6: CLI EXPLORER -->
  <!-- ================================================================= -->
  <section id="tab-cli" class="tab-content">
    <div class="card">
      <div class="card-header">
        <span class="card-title">CLI Command Explorer &amp; Tool Output Terminals</span>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <div class="filter-pills" id="cli-phase-filters">
            <button class="filter-pill active" data-phase="ALL">All Phases ({len(data.commands)})</button>
            {"".join(f'<button class="filter-pill" data-phase="{html.escape(p)}">{html.escape(p)}</button>' for p in command_phases)}
          </div>
          <input type="text" class="search-input" id="cli-search-input" placeholder="Search commands or output text...">
        </div>

        <div id="cli-terminals-container">
          {"".join(f'''
          <div class="terminal-window" data-phase="{html.escape(c.get('phase', 'General'))}" data-text="{html.escape(c.get('cmd', '').lower())} {html.escape(c.get('title', '').lower())} {html.escape(c.get('output', '').lower())}">
            <div class="terminal-header">
              <div class="terminal-left">
                <div class="terminal-dots">
                  <div class="terminal-dot dot-red"></div>
                  <div class="terminal-dot dot-yellow"></div>
                  <div class="terminal-dot dot-green"></div>
                </div>
                <span class="badge badge-info">{html.escape(c.get('phase', 'General'))}</span>
                <span class="terminal-title-text">{html.escape(c.get('title', 'command'))}</span>
              </div>
              <div class="terminal-right">
                <span class="badge {'badge-auth' if c.get('returncode', 0) == 0 else 'badge-critical'}">exit {c.get('returncode', 0)}</span>
                {f"<span class='badge badge-info'>{c['duration_ms'] / 1000.0:.1f}s</span>" if c.get('duration_ms', 0) >= 1000 else (f"<span class='badge badge-info'>{c['duration_ms']}ms</span>" if c.get('duration_ms') else "")}
                <button class="btn-terminal" onclick="copyTerminalCmd(this)">Copy Command</button>
                <button class="btn-terminal" onclick="copyTerminalOut(this)">Copy Output</button>
              </div>
            </div>
            <div class="terminal-body">
              <div><span class="prompt terminal-prompt">$</span> <span class="cmd-text terminal-cmd">{html.escape(c.get('cmd', ''))}</span></div>
              <div class="terminal-out">{html.escape(c.get('output', ''))}</div>
            </div>
          </div>
          ''' for c in data.commands) if data.commands else "<div class='empty-state'>No recorded CLI commands found in console logs</div>"}
        </div>
      </div>
    </div>
  </section>

</main>

<script>
  // Tab Switching Logic
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabContents = document.querySelectorAll('.tab-content');

  function activateTab(targetId) {{
    navTabs.forEach(t => t.classList.toggle('active', t.getAttribute('data-tab') === targetId));
    tabContents.forEach(c => c.classList.toggle('active', c.id === targetId));
  }}

  navTabs.forEach(tab => {{
    tab.addEventListener('click', () => activateTab(tab.getAttribute('data-tab')));
  }});

  // Findings Filtering Logic
  const findingPills = document.querySelectorAll('#findings-severity-filters .filter-pill');
  const findingSearch = document.getElementById('finding-search-input');
  const findingRows = document.querySelectorAll('.finding-row');
  const findingNoRes = document.getElementById('findings-no-results');
  let currentSev = 'ALL';

  function filterFindings() {{
    const query = (findingSearch ? findingSearch.value.trim().toLowerCase() : '');
    let visibleCount = 0;

    findingRows.forEach(row => {{
      const sev = row.getAttribute('data-severity');
      const text = row.getAttribute('data-text');
      const matchesSev = (currentSev === 'ALL' || sev === currentSev);
      const matchesText = (!query || text.includes(query));

      if (matchesSev && matchesText) {{
        row.style.display = '';
        visibleCount++;
      }} else {{
        row.style.display = 'none';
      }}
    }});

    if (findingNoRes) {{
      findingNoRes.style.display = (visibleCount === 0 && findingRows.length > 0) ? 'block' : 'none';
    }}
  }}

  findingPills.forEach(pill => {{
    pill.addEventListener('click', () => {{
      findingPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentSev = pill.getAttribute('data-filter');
      filterFindings();
    }});
  }});

  if (findingSearch) {{
    findingSearch.addEventListener('input', filterFindings);
  }}

  // CVE Table Search
  const cveSearch = document.getElementById('cve-search-input');
  if (cveSearch) {{
    cveSearch.addEventListener('input', () => {{
      const q = cveSearch.value.trim().toLowerCase();
      document.querySelectorAll('.cve-row').forEach(row => {{
        const text = row.getAttribute('data-text');
        row.style.display = (!q || text.includes(q)) ? '' : 'none';
      }});
    }});
  }}

  // CLI Explorer Filtering
  const cliPills = document.querySelectorAll('#cli-phase-filters .filter-pill');
  const cliSearch = document.getElementById('cli-search-input');
  const cliTerminals = document.querySelectorAll('.terminal-window');
  let currentPhase = 'ALL';

  function filterCli() {{
    const q = (cliSearch ? cliSearch.value.trim().toLowerCase() : '');
    cliTerminals.forEach(term => {{
      const phase = term.getAttribute('data-phase');
      const text = term.getAttribute('data-text');
      const matchesPhase = (currentPhase === 'ALL' || phase === currentPhase);
      const matchesText = (!q || text.includes(q));

      term.style.display = (matchesPhase && matchesText) ? '' : 'none';
    }});
  }}

  cliPills.forEach(pill => {{
    pill.addEventListener('click', () => {{
      cliPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentPhase = pill.getAttribute('data-phase');
      filterCli();
    }});
  }});

  if (cliSearch) {{
    cliSearch.addEventListener('input', filterCli);
  }}

  // Cloud Posture Filtering Logic
  const posturePills = document.querySelectorAll('#posture-cloud-filters .filter-pill');
  const postureSearch = document.getElementById('posture-search-input');
  const postureRows = document.querySelectorAll('.posture-row');
  const postureNoRes = document.getElementById('posture-no-results');
  let currentCloud = 'ALL';

  function filterPosture() {{
    const q = (postureSearch ? postureSearch.value.trim().toLowerCase() : '');
    let visibleCount = 0;

    postureRows.forEach(row => {{
      const cloud = row.getAttribute('data-cloud');
      const text = row.getAttribute('data-text');
      const matchesCloud = (currentCloud === 'ALL' || cloud === currentCloud);
      const matchesText = (!q || text.includes(q));

      if (matchesCloud && matchesText) {{
        row.style.display = '';
        visibleCount++;
      }} else {{
        row.style.display = 'none';
      }}
    }});

    if (postureNoRes) {{
      postureNoRes.style.display = (visibleCount === 0 && postureRows.length > 0) ? 'block' : 'none';
    }}
  }}

  posturePills.forEach(pill => {{
    pill.addEventListener('click', () => {{
      posturePills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentCloud = pill.getAttribute('data-cloud-filter');
      filterPosture();
    }});
  }});

  if (postureSearch) {{
    postureSearch.addEventListener('input', filterPosture);
  }}

  // SaaS Posture Filtering Logic
  const saasPills = document.querySelectorAll('#saas-posture-filters .filter-pill');
  const saasSearch = document.getElementById('saas-posture-search-input');
  const saasRows = document.querySelectorAll('.saas-posture-row');
  const saasNoRes = document.getElementById('saas-posture-no-results');
  let currentSaas = 'ALL';

  function filterSaas() {{
    const q = (saasSearch ? saasSearch.value.trim().toLowerCase() : '');
    let visibleCount = 0;

    saasRows.forEach(row => {{
      const prefix = row.getAttribute('data-prefix');
      const text = row.getAttribute('data-text');
      const matchesPrefix = (currentSaas === 'ALL' || prefix === currentSaas);
      const matchesText = (!q || text.includes(q));

      if (matchesPrefix && matchesText) {{
        row.style.display = '';
        visibleCount++;
      }} else {{
        row.style.display = 'none';
      }}
    }});

    if (saasNoRes) {{
      saasNoRes.style.display = (visibleCount === 0 && saasRows.length > 0) ? 'block' : 'none';
    }}
  }}

  saasPills.forEach(pill => {{
    pill.addEventListener('click', () => {{
      saasPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentSaas = pill.getAttribute('data-saas-filter');
      filterSaas();
    }});
  }});

  if (saasSearch) {{
    saasSearch.addEventListener('input', filterSaas);
  }}

  // Copy to Clipboard Helpers
  function copyTextToClipboard(btn, text) {{
    if (!navigator.clipboard) {{
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showCopied(btn);
      return;
    }}
    navigator.clipboard.writeText(text).then(() => {{
      showCopied(btn);
    }}).catch(() => {{
      showCopied(btn);
    }});
  }}

  function copyTerminalCmd(btn) {{
    const term = btn.closest('.terminal-window');
    if (!term) return;
    const cmdEl = term.querySelector('.terminal-cmd');
    if (cmdEl) copyTextToClipboard(btn, cmdEl.innerText || cmdEl.textContent || '');
  }}

  function copyTerminalOut(btn) {{
    const term = btn.closest('.terminal-window');
    if (!term) return;
    const outEl = term.querySelector('.terminal-out');
    if (outEl) copyTextToClipboard(btn, outEl.innerText || outEl.textContent || '');
  }}

  function copySnippet(btn, text) {{
    copyTextToClipboard(btn, text);
  }}

  function showCopied(btn) {{
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{
      btn.innerText = orig;
      btn.classList.remove('copied');
    }}, 1800);
  }}

  // --- KPI severity cards jump to the filtered Findings tab ---
  document.querySelectorAll('.kpi-card.clickable').forEach(card => {{
    card.addEventListener('click', () => {{
      const sev = card.getAttribute('data-jump-sev') || 'ALL';
      activateTab('tab-findings');
      const pill = document.querySelector('#findings-severity-filters .filter-pill[data-filter="' + sev + '"]');
      if (pill) pill.click();
      const tf = document.getElementById('tab-findings');
      if (tf) tf.scrollIntoView({{behavior: 'smooth', block: 'start'}});
    }});
  }});

  // --- Asset id links (in Findings) jump to the matching Assets row ---
  document.querySelectorAll('a.asset-link').forEach(link => {{
    link.addEventListener('click', (e) => {{
      e.preventDefault();
      const id = link.getAttribute('data-asset-id');
      activateTab('tab-assets');
      const row = document.getElementById('asset-' + id);
      if (row) {{
        row.scrollIntoView({{behavior: 'smooth', block: 'center'}});
        row.classList.remove('asset-flash');
        void row.offsetWidth;  // restart the flash animation
        row.classList.add('asset-flash');
      }}
    }});
  }});

  // --- Assets tab: free-text search + type filter ---
  const assetSearch = document.getElementById('asset-search-input');
  const assetType = document.getElementById('asset-type-filter');
  const assetRows = document.querySelectorAll('.asset-row');
  const assetNoRes = document.getElementById('assets-no-results');
  function filterAssets() {{
    const q = (assetSearch ? assetSearch.value.trim().toLowerCase() : '');
    const t = (assetType ? assetType.value : 'ALL');
    let vis = 0;
    assetRows.forEach(row => {{
      const okType = (t === 'ALL' || row.getAttribute('data-type') === t);
      const okText = (!q || (row.getAttribute('data-text') || '').includes(q));
      if (okType && okText) {{ row.style.display = ''; vis++; }} else {{ row.style.display = 'none'; }}
    }});
    if (assetNoRes) assetNoRes.style.display = (vis === 0 && assetRows.length > 0) ? 'block' : 'none';
  }}
  if (assetSearch) assetSearch.addEventListener('input', filterAssets);
  if (assetType) assetType.addEventListener('change', filterAssets);

  // --- Tab-level search over every table in a tab (Web & Cloud) ---
  function wireTabSearch(inputId, tabId) {{
    const inp = document.getElementById(inputId);
    const tab = document.getElementById(tabId);
    if (!inp || !tab) return;
    const rows = tab.querySelectorAll('table tbody tr');
    inp.addEventListener('input', () => {{
      const q = inp.value.trim().toLowerCase();
      rows.forEach(r => {{
        r.style.display = (!q || r.textContent.toLowerCase().includes(q)) ? '' : 'none';
      }});
    }});
  }}
  wireTabSearch('web-search-input', 'tab-web');
  wireTabSearch('cloud-search-input', 'tab-cloud');

  // --- Click-to-sort on every data table's column headers ---
  const SEV_ORDER = {{ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }};
  const NUM_RE = /^-?\\d+(\\.\\d+)?$/;

  function makeSortable(table) {{
    const head = table.tHead;
    const body = table.tBodies[0];
    if (!head || !body || !head.rows.length) return;
    const headerRow = head.rows[head.rows.length - 1];
    Array.from(headerRow.cells).forEach((th, idx) => {{
      th.classList.add('sortable');
      th.addEventListener('click', () => {{
        const dir = th.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';
        Array.from(headerRow.cells).forEach(c => {{
          if (c !== th) c.removeAttribute('data-sort-dir');
        }});
        th.setAttribute('data-sort-dir', dir);

        const rows = Array.from(body.rows).filter(r => r.cells.length > idx);
        const raw = rows.map(r => (r.cells[idx] ? r.cells[idx].textContent.trim() : ''));
        const nonEmpty = raw.filter(v => v && v !== '-');
        const isSev = nonEmpty.length > 0 && nonEmpty.every(v => v.toUpperCase() in SEV_ORDER);
        const isNum = !isSev && nonEmpty.length > 0 &&
                      nonEmpty.every(v => NUM_RE.test(v.replace(/,/g, '')));

        function keyOf(v) {{
          if (isSev) return SEV_ORDER[v.toUpperCase()];
          if (isNum) return parseFloat(v.replace(/,/g, ''));
          return v.toLowerCase();
        }}

        const factor = dir === 'asc' ? 1 : -1;
        rows.sort((a, b) => {{
          const va = (a.cells[idx] ? a.cells[idx].textContent.trim() : '');
          const vb = (b.cells[idx] ? b.cells[idx].textContent.trim() : '');
          const ea = (!va || va === '-'), eb = (!vb || vb === '-');
          if (ea && eb) return 0;
          if (ea) return 1;          // empties always sink to the bottom
          if (eb) return -1;
          const ka = keyOf(va), kb = keyOf(vb);
          if (ka < kb) return -1 * factor;
          if (ka > kb) return 1 * factor;
          return 0;
        }});
        rows.forEach(r => body.appendChild(r));
      }});
    }});
  }}
  document.querySelectorAll('table').forEach(makeSortable);
</script>

</body>
</html>
"""


# =====================================================================
# Main Public Entrypoint
# =====================================================================

def generate_reports(run_dir: Path | str) -> tuple[Path, Path]:
    """Generate comprehensive Markdown and interactive HTML5 reports in run_dir.

    Args:
        run_dir: Path to assessment run directory containing outputs.

    Returns:
        tuple[Path, Path]: (md_path, html_path)
    """
    path = Path(run_dir).resolve()
    path.mkdir(parents=True, exist_ok=True)

    data = RunData(path)

    md_content = generate_markdown(data)
    md_path = path / "report.md"
    md_path.write_text(md_content, encoding="utf-8")

    html_content = generate_html(data)
    html_path = path / "report.html"
    html_path.write_text(html_content, encoding="utf-8")

    # Consolidated, versioned JSON — the stable contract for a downstream,
    # human-curated report generator. A convenience; never fail reports over it.
    try:
        from recon.export import write_report_data
        write_report_data(data, path)
    except Exception:
        pass

    # Compact, self-contained companion for LLM analysis / report regeneration.
    try:
        from recon.ai_bundle import build_ai_bundle
        build_ai_bundle(path)
    except Exception:
        pass  # the bundle is a convenience; never fail report generation over it

    return md_path, html_path


if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    m_p, h_p = generate_reports(target)
    print(f"Generated Markdown report: {m_p}")
    print(f"Generated HTML report:     {h_p}")
