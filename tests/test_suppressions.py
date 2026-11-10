"""Expiring finding suppressions: matching, expiry, validation, outputs and diff."""

import datetime
import json
import tempfile
import unittest
from pathlib import Path

from recon import suppressions
from recon.config import RunContext, ScopeConfig, validate_scope
from recon.deps import DependencyManager
from recon.phases.triage import phaseT
from recon.report import RunData, generate_markdown, generate_html
from recon.runner import Logger

RUN_DATE = "2026-11-03"
TODAY = datetime.date(2026, 11, 3)

CORS_PROD = "https://app.example.com/"
CORS_DEV = "https://api.dev.example.com/"
INTERNAL = "internal-db.example.com"


class _Run:
    """A synthetic phaseT run with three findings: two CORS (one on a dev host)
    and an internal hostname."""

    def __init__(self, td: str, sup_toml: str | None, prev: dict | None = None) -> None:
        root = Path(td)
        (root / "scopes").mkdir()
        scope = ScopeConfig(path=root / "scopes" / "synthetic.toml", name="synthetic",
                            engagement="Synthetic", domains=["example.com"])
        if sup_toml is not None:
            (root / "scopes" / "synthetic.suppressions.toml").write_text(sup_toml, encoding="utf-8")
        self.ctx = RunContext(root=root, scope=scope, run_date=RUN_DATE, phases=["T"], skip_active=True)
        if prev is not None:
            pdir = self.ctx.runs_root / "synthetic" / "2026-10-01"
            pdir.mkdir(parents=True)
            (pdir / "findings_auto.tsv").write_text(prev.get("active", ""), encoding="utf-8")
            (pdir / "suppressed.tsv").write_text(prev.get("suppressed", ""), encoding="utf-8")
        self.ctx.ensure_dirs()
        (self.ctx.web_dir / "cors_cookies.tsv").write_text(
            f"{CORS_PROD}\tcors\tACAO: *\n{CORS_DEV}\tcors\tACAO: *\n", encoding="utf-8")
        (self.ctx.osint_dir / "resolved.txt").write_text(f"{INTERNAL}\n", encoding="utf-8")
        self.gaps = self.ctx.run_dir / "gaps.txt"
        phaseT(self.ctx, DependencyManager(use_docker=False, run_dir=self.ctx.run_dir), Logger(self.gaps))
        rd = self.ctx.run_dir
        self.active = {l.split("\t")[1] for l in (rd / "findings_auto.tsv").read_text().splitlines()}
        self.suppressed = {r["key"]: r for r in suppressions.load_suppressed(rd)}
        self.warnings = self.gaps.read_text().splitlines() if self.gaps.is_file() else []
        self.diff = (rd / "diff.md").read_text() if (rd / "diff.md").is_file() else ""

    def warned(self, text: str) -> bool:
        return any(text in w for w in self.warnings)


def _entry(expires: str = "2027-03-31", **kw) -> str:
    body = "".join(f'{k} = "{v}"\n' for k, v in kw.items())
    return f"[[suppress]]\n{body}expires = {expires}\n\n"


OK = {"reason": "Accepted: staging behind WAF", "owner": "jdoe"}


class TestSuppressionsTriage(unittest.TestCase):
    def test_key_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(key=f"cors:{CORS_PROD}", ticket="SEC-1", **OK))
            self.assertNotIn(f"cors:{CORS_PROD}", r.active)
            self.assertIn(f"cors:{CORS_DEV}", r.active)
            row = r.suppressed[f"cors:{CORS_PROD}"]
            self.assertEqual((row["owner"], row["expires"], row["ticket"], row["severity"]),
                             ("jdoe", "2027-03-31", "SEC-1", "medium"))

    def test_rule_and_target_glob(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(rule="cors", target="*.dev.example.com", **OK))
            self.assertEqual(set(r.suppressed), {f"cors:{CORS_DEV}"})
            self.assertIn(f"cors:{CORS_PROD}", r.active)
            self.assertIn(f"internal-name:{INTERNAL}", r.active)

    def test_suppressed_not_in_active_outputs_but_listed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(rule="internal-name", **OK))
            rd = r.ctx.run_dir
            key = f"internal-name:{INTERNAL}"
            self.assertNotIn(key, r.active)
            self.assertNotIn(key, (rd / "findings.jsonl").read_text())
            self.assertNotIn(key, (rd / "findings_auto.md").read_text().split("suppressed candidate")[0])
            self.assertIn(key, (rd / "suppressed.md").read_text())
            self.assertIn("Accepted: staging behind WAF", (rd / "suppressed.md").read_text())
            data = RunData(rd)
            self.assertEqual(data.kpis["total_findings"], 2)
            self.assertEqual(data.kpis["suppressed"], 1)
            self.assertIn("Suppressed (accepted by the auditor)", generate_markdown(data))
            self.assertIn('id="suppressed-table"', generate_html(data))
            # Still observed: the history keeps recording it
            hist = json.loads((r.ctx.runs_root / "synthetic" / "findings_history.json").read_text())
            self.assertIn(RUN_DATE, hist[key]["seen"])

    def test_expired_is_active_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(expires="2026-10-31", key=f"cors:{CORS_PROD}", **OK))
            self.assertIn(f"cors:{CORS_PROD}", r.active)
            self.assertEqual(r.suppressed, {})
            self.assertTrue(r.warned(f"suppression expired on 2026-10-31 for cors:{CORS_PROD}"))

    def test_near_expiry_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(expires="2026-11-10", key=f"cors:{CORS_PROD}", **OK))
            self.assertIn(f"cors:{CORS_PROD}", r.suppressed)
            self.assertTrue(r.warned("expires on 2026-11-10 (in 7 days"))

    def test_invalid_entries_ignored(self) -> None:
        toml = (
            _entry(key=f"cors:{CORS_PROD}", owner="jdoe")                       # no reason
            + _entry(expires='"next year"', key=f"cors:{CORS_DEV}", **OK)        # bad date
            + f'[[suppress]]\nkey = "internal-name:{INTERNAL}"\nreason = "x"\nowner = "y"\n\n'  # no expires
            + _entry(**OK)                                                        # no key/rule
        )
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, toml)
            self.assertEqual(r.suppressed, {})
            self.assertEqual(len(r.active), 3)
            self.assertTrue(r.warned("suppression #1 in synthetic.suppressions.toml ignored: missing reason"))
            self.assertTrue(r.warned("suppression #2 in synthetic.suppressions.toml ignored: bad expires"))
            self.assertTrue(r.warned("suppression #3 in synthetic.suppressions.toml ignored: missing expires"))
            self.assertTrue(r.warned("suppression #4 in synthetic.suppressions.toml ignored: missing key or rule"))

    def test_broken_toml_never_crashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, "[[suppress]\nkey = ")
            self.assertEqual(len(r.active), 3)
            self.assertTrue(r.warned("unreadable, no suppression applied"))

    def test_stale_entry_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(key="spf:gone.example.com", **OK))
            self.assertTrue(r.warned("stale suppression #1 (spf:gone.example.com)"))

    def test_horizon_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, _entry(expires="2028-12-31", key=f"cors:{CORS_PROD}", **OK))
            self.assertIn(f"cors:{CORS_PROD}", r.suppressed)
            self.assertTrue(r.warned("more than a year ahead"))

    def test_diff_buckets(self) -> None:
        prod, dev = f"cors:{CORS_PROD}", f"cors:{CORS_DEV}"
        prev = {
            # prod was active last run and is suppressed now; internal was active and still is
            "active": f"medium\t{prod}\tPermissive CORS\tx\t\nmedium\tinternal-name:{INTERNAL}\tInternal\tx\t\n",
            # dev was suppressed last run; its suppression has expired now
            "suppressed": f"medium\t{dev}\tPermissive CORS\tx\t{CORS_DEV}\tok\tjdoe\t2026-10-31\t\n",
        }
        toml = _entry(key=prod, **OK) + _entry(expires="2026-10-31", key=dev, **OK)
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, toml, prev=prev)
            sections = {}
            cur = None
            for line in r.diff.splitlines():
                if line.startswith("## "):
                    cur = line[3:].rsplit(" (", 1)[0]
                    sections[cur] = []
                elif line.startswith("- ") and cur:
                    sections[cur].append(line)
            self.assertEqual(sections["Resolved"], [])
            self.assertEqual(sections["New"], [])
            self.assertEqual(len(sections["Suppressed (accepted)"]), 1)
            self.assertIn("accepted by jdoe until 2027-03-31", sections["Suppressed (accepted)"][0])
            self.assertEqual(len(sections["Reactivated (suppression expired)"]), 1)
            self.assertIn(CORS_DEV, sections["Reactivated (suppression expired)"][0])
            self.assertEqual(len(sections["Persisting"]), 1)
            data = RunData(r.ctx.run_dir)
            self.assertEqual(len(data.diff_summary["Suppressed (accepted)"]), 1)
            self.assertEqual(len(data.diff_summary["Reactivated (suppression expired)"]), 1)
            self.assertEqual(data.diff_summary["Persisting"][0].count("internal"), 1)


class TestSuppressionMatching(unittest.TestCase):
    def _s(self, **kw) -> suppressions.Suppression:
        return suppressions.Suppression(index=1, reason="r", owner="o", expires=TODAY, **kw)

    def test_rule_glob_and_ip_port_target(self) -> None:
        s = self._s(rule="cve-*", target="10.0.0.*")
        self.assertTrue(s.matches("cve-high:10.0.0.5:443", "10.0.0.5:443"))
        self.assertFalse(s.matches("mgmt:10.0.0.5:3389", "10.0.0.5:3389"))
        self.assertFalse(s.matches("cve-kev:192.0.2.1:443", "192.0.2.1:443"))

    def test_expiry_is_inclusive(self) -> None:
        applied = suppressions.apply([("low", "caa:example.com", "No CAA", "")],
                                     [self._s(key="caa:example.com")], lambda k: "", TODAY, lambda m: None)
        self.assertEqual(len(applied.suppressed), 1)


class TestCheckConfig(unittest.TestCase):
    def test_check_config_reports_bad_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "s.toml").write_text(
                'suppressions_file = "s.supp.toml"\n[targets]\ndomains = ["example.com"]\n', encoding="utf-8")
            (root / "s.supp.toml").write_text(_entry(key="spf:example.com", owner="x"), encoding="utf-8")
            errors, warnings = validate_scope(root / "s.toml")
            self.assertEqual(errors, [])
            self.assertFalse(any("unknown" in w and "suppressions_file" in w for w in warnings))
            self.assertTrue(any("missing reason" in w for w in warnings))

    def test_example_file_is_valid(self) -> None:
        path = Path(__file__).resolve().parent.parent / "scopes" / "example.suppressions.toml"
        sups, warnings = suppressions.parse_file(path, TODAY)
        self.assertGreaterEqual(len(sups), 2)
        self.assertFalse([w for w in warnings if "ignored" in w])


if __name__ == "__main__":
    unittest.main()
