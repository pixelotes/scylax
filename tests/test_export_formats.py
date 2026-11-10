"""Tests for the SARIF / CSV exports (recon.export_formats)."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from recon.export import build_report_data, export_report_data
from recon.export_formats import (
    build_csv, build_sarif, csv_safe, CSV_COLUMNS, rule_id, severity_level,
)
from recon.sample_generator import build_sample_run
try:
    from test_export import _make
except ImportError:  # run as a package
    from tests.test_export import _make

FINDINGS = [
    {"severity": "CRITICAL", "key": "cors:https://a.example.com/", "title": "CORS reflects origin",
     "evidence": "=HYPERLINK(\"http://evil\")", "target": "https://a.example.com/"},
    {"severity": "HIGH", "key": "cors:https://b.example.com/", "title": "CORS reflects origin",
     "evidence": "e", "target": "https://b.example.com/"},
    {"severity": "MEDIUM", "key": "cve-high:203.0.113.9:22", "title": "OpenSSH CVE-2023-38408",
     "evidence": "+cmd; CVE-2023-38408", "target": "203.0.113.9:22"},
    {"severity": "LOW", "key": "spf:example.com", "title": "SPF soft fail", "evidence": "", "target": "example.com"},
    {"severity": "INFO", "key": "m365-no-mfa", "title": "No MFA", "evidence": "e", "target": ""},
]


def _doc() -> dict:
    return build_report_data(_make(findings=[dict(f) for f in FINDINGS]))


class TestSarif(unittest.TestCase):
    def test_level_mapping(self) -> None:
        for sev, lvl in (("CRITICAL", "error"), ("HIGH", "error"), ("MEDIUM", "warning"),
                         ("LOW", "note"), ("INFO", "note"), ("weird", "note")):
            self.assertEqual(severity_level(sev), lvl)

    def test_required_structure(self) -> None:
        sarif = build_sarif(_doc())
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "Scylax")
        self.assertTrue(driver["informationUri"].startswith("https://"))
        rule_ids = {r["id"] for r in driver["rules"]}
        self.assertEqual(len(run["results"]), len(FINDINGS))
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids)
            self.assertIn(res["level"], ("error", "warning", "note"))
            self.assertTrue(res["message"]["text"])
            self.assertTrue(res["locations"])
            for loc in res["locations"]:
                self.assertTrue(loc["physicalLocation"]["artifactLocation"]["uri"])
            self.assertEqual(res["properties"]["status"], "candidate")
            self.assertTrue(res["partialFingerprints"])
        json.dumps(sarif)  # serialisable

    def test_levels_and_locations(self) -> None:
        results = {r["properties"]["findingId"]: r for r in build_sarif(_doc())["runs"][0]["results"]}
        self.assertEqual(results["cors:https://a.example.com/"]["level"], "error")
        self.assertEqual(results["cve-high:203.0.113.9:22"]["level"], "warning")
        uri = results["cve-high:203.0.113.9:22"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "host:203.0.113.9:22")
        self.assertEqual(results["cve-high:203.0.113.9:22"]["properties"]["cves"], ["CVE-2023-38408"])
        self.assertEqual(
            results["cors:https://a.example.com/"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://a.example.com/")
        # targetless finding still has a location and a logical (asset) location
        loc = results["m365-no-mfa"]["locations"][0]
        self.assertTrue(loc["physicalLocation"]["artifactLocation"]["uri"])
        self.assertTrue(loc["logicalLocations"][0]["fullyQualifiedName"])

    def test_rules_deduped(self) -> None:
        run = build_sarif(_doc())["runs"][0]
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids.count("cors"), 1)
        self.assertEqual(len(ids), 4)  # cors, cve-high, spf, m365-no-mfa
        cors = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "cors")
        self.assertEqual(cors["properties"]["security-severity"], "9.5")  # worst severity wins
        self.assertEqual(cors["defaultConfiguration"]["level"], "error")
        self.assertIn("scylax", cors["properties"]["tags"])

    def test_fingerprints_stable_across_builds(self) -> None:
        def fps() -> list:
            return [r["partialFingerprints"] for r in build_sarif(_doc())["runs"][0]["results"]]
        a, b = fps(), fps()
        self.assertEqual(a, b)
        self.assertEqual(len({json.dumps(x) for x in a}), len(FINDINGS))  # distinct per finding

    def test_nuclei_rule_keeps_template(self) -> None:
        self.assertEqual(rule_id("nuclei:CVE-2021-1:host.example.com"), "nuclei:CVE-2021-1")
        self.assertEqual(rule_id("cors:https://x/"), "cors")
        self.assertEqual(rule_id(""), "finding")


class TestCsv(unittest.TestCase):
    def test_formula_neutralisation(self) -> None:
        for bad in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"):
            self.assertEqual(csv_safe(bad), "'" + bad)
        self.assertEqual(csv_safe("safe"), "safe")
        self.assertEqual(csv_safe(""), "")

    def test_round_trip(self) -> None:
        text = build_csv(_doc())
        self.assertFalse(text.startswith("﻿"))
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        self.assertEqual(list(rows[0].keys()), CSV_COLUMNS)
        self.assertEqual(len(rows), len(FINDINGS))
        by_id = {r["id"]: r for r in rows}
        a = by_id["cors:https://a.example.com/"]
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertEqual(a["rule"], "cors")
        self.assertEqual(a["status"], "candidate")
        self.assertTrue(a["evidence"].startswith("'="))  # neutralised
        cve = by_id["cve-high:203.0.113.9:22"]
        self.assertEqual(cve["cves"], "CVE-2023-38408")
        self.assertTrue(cve["evidence"].startswith("'+"))
        self.assertEqual(cve["targets"], "203.0.113.9:22")

    def test_multi_values_and_history(self) -> None:
        data = _make(meta={"date": "2026-11-10"}, findings=[
            {"severity": "HIGH", "key": "nsg1", "title": "NSG, \"open\"", "evidence": "l1\nl2",
             "target": "203.0.113.9, 203.0.113.10"}])
        scope = data.run_dir.parent
        (scope / "findings_history.json").write_text(
            json.dumps({"nsg1": {"first_seen": "2026-11-01", "seen": ["2026-11-01"]}}))
        row = next(csv.DictReader(io.StringIO(build_csv(build_report_data(data), data.run_dir), newline="")))
        self.assertEqual(row["targets"], "203.0.113.9; 203.0.113.10")
        self.assertEqual(len(row["asset_ids"].split("; ")), 2)
        self.assertEqual(row["first_seen"], "2026-11-01")
        self.assertEqual(row["age_days"], "9")
        self.assertEqual(row["title"], 'NSG, "open"')
        self.assertEqual(row["evidence"], "l1\nl2")


class TestFilesWritten(unittest.TestCase):
    def test_export_report_data_writes_both(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "sample" / "2026-11-05"
            run_dir.mkdir(parents=True)
            build_sample_run(run_dir)
            export_report_data(run_dir)
            sarif = json.loads((run_dir / "findings.sarif").read_text(encoding="utf-8"))
            with (run_dir / "findings.csv").open(encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
            doc = json.loads((run_dir / "report_data.json").read_text(encoding="utf-8"))
            self.assertEqual(len(sarif["runs"][0]["results"]), len(doc["findings"]))
            self.assertEqual(len(rows), len(doc["findings"]))
            self.assertTrue(doc["findings"])

    def test_exporter_failure_does_not_break(self) -> None:
        from unittest import mock
        from recon import export_formats
        data = _make(findings=[dict(FINDINGS[0])])
        with mock.patch.object(export_formats, "build_sarif", side_effect=RuntimeError("boom")):
            from recon.export import write_report_data
            out = write_report_data(data, data.run_dir)
        self.assertTrue(out.is_file())
        self.assertFalse((data.run_dir / "findings.sarif").exists())
        self.assertTrue((data.run_dir / "findings.csv").is_file())


if __name__ == "__main__":
    unittest.main()
