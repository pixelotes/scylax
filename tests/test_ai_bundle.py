"""Tests for the AI analysis bundle (recon.ai_bundle)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon.ai_bundle import build_ai_bundle, extract_files, report_from_bundle


def _make_run(root: Path) -> Path:
    rd = root / "runs" / "acme" / "2026-11-04"
    (rd / "osint").mkdir(parents=True)
    (rd / "azure").mkdir(parents=True)
    (rd / "console").mkdir(parents=True)
    (rd / "run.meta").write_text(
        "scope=scopes/acme.toml\ndate=2026-11-04\nphases=1 2 T\n", encoding="utf-8")
    (rd / "findings_auto.tsv").write_text(
        "high\tnsg:x:ssh\tAzure NSG allows 22 from Internet\tx rule ssh\t203.0.113.5\n"
        "medium\tspf:acme.com\tacme.com has no SPF record\tdig TXT acme.com\tacme.com\n",
        encoding="utf-8")
    (rd / "diff.md").write_text("# Changes\n\n## New (1)\n\n- **high** NSG - x\n", encoding="utf-8")
    (rd / "gaps.txt").write_text("nuclei not available\n", encoding="utf-8")
    (rd / "tool_failures.tsv").write_text("8\tnuclei\ttimed out\n", encoding="utf-8")
    (rd / "azure" / "nsg_internet_rules.tsv").write_text("x\trg\tssh\t22\t1\t\tid\n", encoding="utf-8")
    (rd / "console" / "8.log").write_text("x" * 5000, encoding="utf-8")  # must NOT be embedded
    return rd


class TestAiBundle(unittest.TestCase):
    def test_build_contains_tagged_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rd = _make_run(Path(td))
            text = build_ai_bundle(rd).read_text(encoding="utf-8")
            self.assertIn("scylax-file: run.meta", text)
            self.assertIn("scylax-file: findings_auto.tsv", text)
            self.assertIn("scylax-file: azure/nsg_internet_rules.tsv", text)
            self.assertIn("nuclei", text)  # failed-tool note in the glance section

    def test_extract_roundtrip_excludes_console(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rd = _make_run(Path(td))
            files = extract_files(build_ai_bundle(rd).read_text(encoding="utf-8"))
            self.assertIn("findings_auto.tsv", files)
            self.assertIn("azure/nsg_internet_rules.tsv", files)
            self.assertNotIn("console/8.log", files)
            self.assertIn("Azure NSG allows 22 from Internet", files["findings_auto.tsv"])

    def test_report_from_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rd = _make_run(Path(td))
            bundle = build_ai_bundle(rd)
            out = Path(td) / "rebuilt"
            md, html = report_from_bundle(bundle, out)
            self.assertTrue(md.is_file() and html.is_file())
            self.assertIn("Azure NSG allows 22 from Internet", md.read_text(encoding="utf-8"))

    def test_rejects_non_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "x.md"
            bad.write_text("# just markdown, no scylax-file blocks\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                report_from_bundle(bad)


if __name__ == "__main__":
    unittest.main()
