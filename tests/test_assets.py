"""Tests for the asset inventory and stable identifiers (recon.assets)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon.assets import AssetRegistry, build_assets, normalize_all, normalize_key


class _FakeData:
    """Minimal stand-in for RunData with just what build_assets reads."""

    def __init__(self, run_dir: Path, **kw) -> None:
        self.run_dir = run_dir
        self.ip_orgs = kw.get("ip_orgs", [])
        self.azure_public_ips = kw.get("azure_public_ips", [])
        self.gcp_public_ips = kw.get("gcp_public_ips", [])
        self.aws_public_ips = kw.get("aws_public_ips", [])
        self.service_cves = kw.get("service_cves", [])
        self.httpx_all = kw.get("httpx_all", [])
        self.findings = kw.get("findings", [])


class TestNormalizeKey(unittest.TestCase):
    def test_url_to_host(self) -> None:
        self.assertEqual(normalize_key("https://www.example.com/a/b?x=1"), "www.example.com")

    def test_host_port_stripped(self) -> None:
        self.assertEqual(normalize_key("host.example.com:8443"), "host.example.com")

    def test_ip_preserved(self) -> None:
        self.assertEqual(normalize_key("198.51.100.10"), "198.51.100.10")

    def test_multi_target_uses_first(self) -> None:
        self.assertEqual(normalize_key("203.0.113.9, 203.0.113.10"), "203.0.113.9")

    def test_normalize_all_returns_every_key(self) -> None:
        self.assertEqual(
            normalize_all("203.0.113.9, https://a.example.com/x, host.example.com:8443"),
            ["203.0.113.9", "a.example.com", "host.example.com"],
        )

    def test_empty(self) -> None:
        self.assertEqual(normalize_key(""), "")
        self.assertEqual(normalize_all(""), [])


class TestAssetRegistry(unittest.TestCase):
    def test_assign_and_persist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "assets.json"
            reg = AssetRegistry(p)
            a = reg.id_for("1.1.1.1", "ROUTER")
            b = reg.id_for("2.2.2.2", "ROUTER")
            c = reg.id_for("1.1.1.1", "ROUTER")  # same key -> same id
            self.assertEqual(a, "ROUTER-001")
            self.assertEqual(b, "ROUTER-002")
            self.assertEqual(c, "ROUTER-001")
            reg.save()
            reg2 = AssetRegistry(p)
            self.assertEqual(reg2.id_for("1.1.1.1", "ROUTER"), "ROUTER-001")
            self.assertEqual(reg2.id_for("3.3.3.3", "WEB"), "WEB-001")


class TestBuildAssets(unittest.TestCase):
    def _run(self, **kw) -> tuple[list, Path]:
        td = Path(tempfile.mkdtemp()) / "scope" / "2026-11-05"
        td.mkdir(parents=True)
        data = _FakeData(td, **kw)
        return build_assets(data), td, data

    def test_classifies_and_assigns_ids(self) -> None:
        assets, run_dir, data = self._run(
            ip_orgs=[{"ip": "203.0.113.45", "org": "ISP", "ptr": "mikrotik-gw.isp.net", "sample_hosts": ""}],
            azure_public_ips=[{"ip": "20.1.1.1", "name": "kubernetes-ingress-prod"}],
            httpx_all=[{"url": "https://www.example.com", "server": "nginx"}],
            service_cves=[{"ip": "203.0.113.45", "port": "8291", "service": "winbox",
                           "version": "6.48", "cve": "CVE-2023-0001", "is_kev": True}],
            findings=[{"severity": "CRITICAL", "key": "x", "title": "EOL RouterOS",
                       "evidence": "e", "target": "203.0.113.45"}],
        )
        by_type = {a["key"]: a for a in assets}
        self.assertEqual(by_type["203.0.113.45"]["prefix"], "ROUTER")
        self.assertEqual(by_type["20.1.1.1"]["prefix"], "K8S")
        self.assertEqual(by_type["www.example.com"]["prefix"], "WEB")
        # every asset got an id of the right shape
        for a in assets:
            self.assertRegex(a["id"], r"^[A-Z0-9]+-\d{3}$")
        # the finding was tagged with the router's id
        self.assertEqual(data.findings[0]["asset_id"], by_type["203.0.113.45"]["id"])
        # the router aggregated its port and CVE
        self.assertIn("8291", by_type["203.0.113.45"]["ports"])
        self.assertEqual(len(by_type["203.0.113.45"]["cves"]), 1)

    def test_writes_artifacts(self) -> None:
        assets, run_dir, data = self._run(
            ip_orgs=[{"ip": "198.51.100.10", "org": "Org", "ptr": "", "sample_hosts": "a.example.com"}],
        )
        self.assertTrue((run_dir / "assets.tsv").is_file())
        self.assertTrue((run_dir.parent / "assets.json").is_file())
        reg = json.loads((run_dir.parent / "assets.json").read_text())
        self.assertIn("198.51.100.10", reg["assigned"])

    def test_ids_stable_across_rebuilds(self) -> None:
        assets1, run_dir, data = self._run(
            httpx_all=[{"url": "https://a.example.com", "server": "nginx"},
                       {"url": "https://b.example.com", "server": "nginx"}],
        )
        ids1 = {a["key"]: a["id"] for a in assets1}
        # rebuild against the same scope registry (new RunData, same run dir)
        data2 = _FakeData(run_dir, httpx_all=[{"url": "https://a.example.com", "server": "nginx"},
                                              {"url": "https://b.example.com", "server": "nginx"}])
        assets2 = build_assets(data2)
        ids2 = {a["key"]: a["id"] for a in assets2}
        self.assertEqual(ids1, ids2)

    def test_finding_affects_multiple_assets(self) -> None:
        assets, run_dir, data = self._run(
            findings=[{"severity": "HIGH", "key": "nsg1", "title": "NSG allows 22 from Internet",
                       "evidence": "e", "target": "203.0.113.9, 203.0.113.10"}],
        )
        f = data.findings[0]
        self.assertEqual(len(f["asset_ids"]), 2)
        self.assertEqual(f["asset_id"], f["asset_ids"][0])  # primary = first
        # the finding appears under both assets' inventories
        for a in assets:
            if a["key"] in ("203.0.113.9", "203.0.113.10"):
                self.assertIn(f, a["findings"])

    def test_targetless_finding_gets_pseudo_asset(self) -> None:
        assets, run_dir, data = self._run(
            findings=[
                {"severity": "CRITICAL", "key": "m365-admin-no-mfa",
                 "title": "Global Administrators without MFA", "evidence": "e", "target": ""},
                {"severity": "MEDIUM", "key": "dns",
                 "title": "No CAA on example.com", "evidence": "e", "target": ""},
            ],
        )
        self.assertEqual(data.findings[0]["asset_id"], "TENANT-001")
        self.assertEqual(data.findings[1]["asset_id"], "ORG-001")


if __name__ == "__main__":
    unittest.main()
