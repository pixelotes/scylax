"""Asset inventory and stable asset identifiers.

Aggregates every target seen in a run into a single asset (keyed by IP or
hostname) and enriches it from the structured artifacts: reverse DNS / org
(ip_orgs), the cloud public-IP inventories, open ports / services / versions and
CVEs (service_cves), live web hosts (httpx), and the findings themselves.

Each asset gets a stable, human-readable identifier such as ``ROUTER-001`` or
``WEB-004``. IDs are persisted per scope in ``runs/<scope>/assets.json`` so the
same asset keeps its identifier across runs — the anchor an analyst or a forensic
timeline needs. Type is re-evaluated every run (a host can become a web asset),
but the identifier assigned on first sight never changes.

This module is pure standard library and has no side effects beyond reading and
writing that one registry file.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Classification rules: (prefix, label, keyword tuple). First match wins, so the
# most specific device classes are listed before the generic host/web ones.
_TYPE_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("VPN", "VPN gateway", ("vpn", "ravpn", "anyconnect", "ipsec", "wireguard", "openvpn", " asa", "asa-", "sslvpn")),
    ("ROUTER", "Router", ("mikrotik", "routeros", "edgeos", "edgerouter", "router")),
    ("FW", "Firewall", ("opnsense", "pfsense", "firewall", "fortigate", "fortinet", "palo alto", "panos", "sonicwall", "checkpoint", "-fw", "fw-")),
    ("K8S", "Kubernetes ingress", ("kubernetes", "k8s", "aks", "ingress")),
    ("LB", "Load balancer", ("loadbalancer", "load-balancer", "appgw", "application gateway", "haproxy", "-lb", "lb-", "-alb", "-elb")),
    ("MAIL", "Mail server", ("smtp", "imap", "postfix", "exchange", "mail-", "-mail", "mx-", "-mx")),
    ("DB", "Database", ("mysql", "mariadb", "postgres", "postgresql", "mongodb", "redis", "rds", "oracle-db", "rabbitmq", "mssql")),
    ("DC", "Directory / identity", ("domain controller", "ldap", "kerberos", "active directory", "aadds", "-dc", "dc-")),
)

_WEB_PORTS = {"80", "443", "8080", "8443", "8000", "8888"}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_key(target: str) -> str:
    """Reduce a finding target (IP, host or URL) to a bare asset key.

    A URL becomes its hostname; a ``host:port`` loses the port; everything is
    lower-cased. Multi-target cells (``a, b``) are keyed on their first entry.
    """
    if not target:
        return ""
    first = target.split(",")[0].strip()
    if "://" in first:
        host = urlparse(first).hostname or ""
        if host:
            return host.lower()
    first = first.rstrip("/")
    # strip a trailing :port when the left side is a host/IP, not a scheme
    if first.count(":") == 1 and not _is_ip(first):
        left, _, right = first.partition(":")
        if right.isdigit():
            first = left
    return first.lower()


def _split_hosts(blob: str) -> List[str]:
    return [h.strip().lower() for h in re.split(r"[\s,]+", blob or "") if h.strip()]


def _classify(asset: Dict[str, Any]) -> tuple[str, str]:
    """Return (prefix, label) for an asset from its gathered attributes."""
    blob = " ".join([
        asset["key"], asset.get("ptr", ""), asset.get("org", ""),
        asset.get("cloud_name", ""), " ".join(sorted(asset.get("names", set()))),
        " ".join(sorted(asset.get("services", set()))),
        " ".join(sorted(asset.get("products", set()))),
    ]).lower()
    for prefix, label, keywords in _TYPE_RULES:
        if any(k in blob for k in keywords):
            return prefix, label
    ports = set(asset.get("ports", {}).keys())
    if asset.get("is_web") or (ports & _WEB_PORTS):
        return "WEB", "Web service"
    if asset.get("cloud"):
        return "CLOUD", "Cloud host"
    if ports:
        return "HOST", "Host"
    if not asset.get("is_ip"):
        return "DOMAIN", "Domain / name"
    return "ASSET", "Asset"


class AssetRegistry:
    """Persistent map of asset key -> stable identifier (PREFIX-NNN)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.assigned: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.assigned = dict(data.get("assigned", {}))
            self.counters = {k: int(v) for k, v in data.get("counters", {}).items()}
        except Exception:
            self.assigned, self.counters = {}, {}

    def id_for(self, key: str, prefix: str) -> str:
        """Return the existing id for key, or assign the next one for prefix."""
        existing = self.assigned.get(key)
        if existing:
            return existing
        nxt = self.counters.get(prefix, 0) + 1
        self.counters[prefix] = nxt
        asset_id = f"{prefix}-{nxt:03d}"
        self.assigned[key] = asset_id
        return asset_id

    def save(self) -> None:
        try:
            self.path.write_text(
                json.dumps({"assigned": self.assigned, "counters": self.counters},
                           indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception:
            pass


def _worst_sev(findings: List[Dict[str, str]]) -> int:
    return min((SEV_RANK.get(f.get("severity", "INFO").upper(), 4) for f in findings), default=4)


def build_assets(data: Any) -> List[Dict[str, Any]]:
    """Build the asset inventory for a RunData, assign stable ids, and tag each
    finding with its ``asset_id`` / ``asset_key``. Returns the asset list sorted
    by risk (worst finding severity, then id). Also writes ``assets.tsv`` next to
    the other run outputs."""
    assets: Dict[str, Dict[str, Any]] = {}

    def get(key: str) -> Dict[str, Any]:
        a = assets.get(key)
        if a is None:
            a = {
                "key": key, "is_ip": _is_ip(key), "is_web": False,
                "names": set(), "ptr": "", "org": "", "cloud": "", "cloud_name": "",
                "ports": {}, "services": set(), "products": set(),
                "cves": [], "findings": [],
            }
            assets[key] = a
        return a

    for r in getattr(data, "ip_orgs", []):
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue
        a = get(ip)
        if r.get("ptr"):
            a["ptr"] = r["ptr"]
        if r.get("org"):
            a["org"] = r["org"]
        for h in _split_hosts(r.get("sample_hosts", "")):
            a["names"].add(h)

    for cloud, rows in (("azure", getattr(data, "azure_public_ips", [])),
                        ("gcp", getattr(data, "gcp_public_ips", [])),
                        ("aws", getattr(data, "aws_public_ips", []))):
        for r in rows:
            ip = (r.get("ip") or "").strip()
            if not ip:
                continue
            a = get(ip)
            a["cloud"] = cloud
            if r.get("name"):
                a["cloud_name"] = r["name"]

    for c in getattr(data, "service_cves", []):
        key = (c.get("ip") or "").strip().lower()
        if not key:
            continue
        a = get(key)
        port = (c.get("port") or "").strip()
        svc = (c.get("service") or "").strip()
        ver = (c.get("version") or "").strip()
        if port and port not in ("-", ""):
            a["ports"][port] = f"{port}/{svc}" if svc and svc != "-" else port
        if svc and svc != "-":
            a["services"].add(svc)
        if svc and svc != "-" and ver and ver != "-":
            a["products"].add(f"{svc} {ver}".strip())
        if c.get("cve"):
            a["cves"].append(c)

    for h in getattr(data, "httpx_all", []):
        host = normalize_key(h.get("url", ""))
        if not host:
            continue
        a = get(host)
        a["is_web"] = True
        a["names"].add(host)
        if h.get("server"):
            a["products"].add(h["server"])

    # Attach findings (creating asset entries for targets not otherwise seen).
    for f in getattr(data, "findings", []):
        key = normalize_key(f.get("target", ""))
        f["asset_key"] = key
        f["asset_id"] = ""
        if key:
            get(key)["findings"].append(f)

    # Classify, then assign stable ids in a deterministic (prefix, key) order.
    for a in assets.values():
        a["prefix"], a["type"] = _classify(a)

    registry_path = Path(getattr(data, "run_dir")).parent / "assets.json"
    registry = AssetRegistry(registry_path)
    for key in sorted(assets, key=lambda k: (assets[k]["prefix"], k)):
        a = assets[key]
        a["id"] = registry.id_for(key, a["prefix"])
    registry.save()

    for f in getattr(data, "findings", []):
        if f.get("asset_key"):
            f["asset_id"] = assets[f["asset_key"]]["id"]

    asset_list = sorted(
        assets.values(),
        key=lambda a: (_worst_sev(a["findings"]), a["prefix"], a["id"]),
    )

    _write_tsv(Path(getattr(data, "run_dir")) / "assets.tsv", asset_list)
    return asset_list


def asset_label(asset: Dict[str, Any]) -> str:
    """Best human label for an asset: cloud resource name, PTR, hostname, or key."""
    if asset.get("cloud_name"):
        return asset["cloud_name"]
    if asset.get("ptr"):
        return asset["ptr"]
    names = sorted(asset.get("names", set()))
    if names:
        return names[0]
    return asset["key"]


def asset_product(asset: Dict[str, Any]) -> str:
    return ", ".join(sorted(asset.get("products", set()))) or "-"


def asset_ports(asset: Dict[str, Any]) -> str:
    def _p(x: str) -> int:
        try:
            return int(x)
        except ValueError:
            return 10 ** 9
    return ", ".join(asset["ports"][p] for p in sorted(asset["ports"], key=_p)) or "-"


def _write_tsv(path: Path, asset_list: List[Dict[str, Any]]) -> None:
    try:
        rows = ["id\ttype\tlabel\tkey\tproduct\topen_ports\tfindings\tcves"]
        for a in asset_list:
            fid = ", ".join(sorted({f["asset_id"] for f in a["findings"] if f.get("asset_id")}) or [])
            find_titles = "; ".join(f.get("title", "") for f in a["findings"]) or "-"
            cves = ", ".join(sorted({c["cve"] for c in a["cves"] if c.get("cve")})) or "-"
            rows.append("\t".join([
                a["id"], a["type"], asset_label(a).replace("\t", " "), a["key"],
                asset_product(a).replace("\t", " "), asset_ports(a).replace("\t", " "),
                find_titles.replace("\t", " "), cves,
            ]))
        path.write_text("".join(r + "\n" for r in rows), encoding="utf-8")
    except Exception:
        pass
