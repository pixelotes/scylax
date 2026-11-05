"""Tests for the consolidated report_data.json export (recon.export)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon.assets import build_assets
from recon.export import SCHEMA_VERSION, build_report_data, write_report_data
from recon.report import RunData
from recon.sample_generator import build_sample_run


class _FakeData:
    """Minimal RunData stand-in: assets/findings correlated by build_assets."""

    def __init__(self, run_dir: Path, **kw) -> None:
        self.run_dir = run_dir
        self.ip_orgs = kw.get("ip_orgs", [])
        self.azure_public_ips = kw.get("azure_public_ips", [])
        self.gcp_public_ips = kw.get("gcp_public_ips", [])
        self.aws_public_ips = kw.get("aws_public_ips", [])
        self.service_cves = kw.get("service_cves", [])
        self.httpx_all = kw.get("httpx_all", [])
        self.findings = kw.get("findings", [])
        self.meta = kw.get("meta", {})
        self.diff_summary = kw.get("diff_summary", {})
        self.kpis = kw.get("kpis", {})
        # correlate (mutates findings with asset ids, returns the asset list)
        self.assets = build_assets(self)


def _make(**kw) -> _FakeData:
    td = Path(tempfile.mkdtemp()) / "scope" / "2026-11-05"
    td.mkdir(parents=True)
    return _FakeData(td, **kw)


class TestBuildReportData(unittest.TestCase):
    def test_schema_and_top_level_shape(self) -> None:
        data = _make(
            meta={"engagement": "Example Corp", "scope": "example",
                  "date": "2026-11-05", "use_docker": "1"},
            kpis={"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0},
            findings=[{"severity": "CRITICAL", "key": "x", "title": "EOL",
                       "evidence": "e", "target": "203.0.113.45"}],
            ip_orgs=[{"ip": "203.0.113.45", "org": "ISP", "ptr": "gw.isp.net"}],
        )
        doc = build_report_data(data)
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION)
        self.assertEqual(doc["generator"], "scylax")
        self.assertTrue(doc["generated_at"].endswith("Z"))
        for section in ("meta", "kpis", "summary", "assets", "findings", "relations", "diff"):
            self.assertIn(section, doc)
        self.assertEqual(doc["meta"]["engagement"], "Example Corp")
        self.assertIs(doc["meta"]["use_docker"], True)
        self.assertEqual(doc["summary"]["total_findings"], 1)
        self.assertEqual(doc["summary"]["severity_counts"]["critical"], 1)

    def test_many_to_many_relations(self) -> None:
        data = _make(
            findings=[{"severity": "HIGH", "key": "nsg1",
                       "title": "NSG allows 22 from Internet", "evidence": "e",
                       "target": "203.0.113.9, 203.0.113.10"}],
        )
        doc = build_report_data(data)
        rels = [r for r in doc["relations"] if r["finding_id"] == "nsg1"]
        self.assertEqual(len(rels), 2)
        self.assertEqual(sum(1 for r in rels if r["primary"]), 1)
        # the finding lists both asset ids; primary is the first
        f = next(f for f in doc["findings"] if f["id"] == "nsg1")
        self.assertEqual(len(f["asset_ids"]), 2)
        primary = next(r for r in rels if r["primary"])
        self.assertEqual(primary["asset_id"], f["asset_id"])
        # each referenced asset lists the finding back
        for a in doc["assets"]:
            if a["id"] in f["asset_ids"]:
                self.assertIn("nsg1", a["finding_ids"])

    def test_pseudo_asset_exported(self) -> None:
        data = _make(
            findings=[{"severity": "CRITICAL", "key": "m365-no-mfa",
                       "title": "Global Administrators without MFA",
                       "evidence": "e", "target": ""}],
        )
        doc = build_report_data(data)
        tenant = [a for a in doc["assets"] if a["id"] == "TENANT-001"]
        self.assertEqual(len(tenant), 1)
        self.assertTrue(tenant[0]["pseudo"])
        self.assertEqual(tenant[0]["type"], "TENANT")
        self.assertIn("m365-no-mfa", tenant[0]["finding_ids"])

    def test_targetless_finding_without_key_gets_fallback_id(self) -> None:
        data = _make(
            findings=[{"severity": "LOW", "key": "", "title": "stray",
                       "evidence": "e", "target": ""}],
        )
        doc = build_report_data(data)
        self.assertEqual(doc["findings"][0]["id"], "finding-0000")

    def test_write_report_data_is_valid_json(self) -> None:
        data = _make(
            findings=[{"severity": "MEDIUM", "key": "k", "title": "t",
                       "evidence": "e", "target": "a.example.com"}],
        )
        out = write_report_data(data, data.run_dir)
        self.assertEqual(out.name, "report_data.json")
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION)


class TestExportEndToEnd(unittest.TestCase):
    def test_sample_run_export_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "sample" / "2026-11-05"
            run_dir.mkdir(parents=True)
            build_sample_run(run_dir)
            data = RunData(run_dir)
            doc = build_report_data(data)

            self.assertEqual(doc["schema_version"], SCHEMA_VERSION)
            self.assertTrue(doc["assets"])
            self.assertTrue(doc["findings"])
            self.assertTrue(doc["relations"])
            self.assertEqual(doc["summary"]["total_assets"], len(doc["assets"]))

            asset_ids = {a["id"] for a in doc["assets"]}
            finding_ids = {f["id"] for f in doc["findings"]}
            # every relation points at a real finding and a real asset
            for r in doc["relations"]:
                self.assertIn(r["finding_id"], finding_ids)
                self.assertIn(r["asset_id"], asset_ids)
            # exactly one primary relation per finding that has an asset
            with_asset = [f for f in doc["findings"] if f["asset_id"]]
            primaries = [r for r in doc["relations"] if r["primary"]]
            self.assertEqual(len(primaries), len(with_asset))


if __name__ == "__main__":
    unittest.main()
