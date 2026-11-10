"""Diff trends: age buckets, MTTR, history compatibility, summary and report card."""

import json
import tempfile
import unittest
from pathlib import Path

from recon import trends
from recon.config import RunContext, ScopeConfig
from recon.deps import DependencyManager
from recon.phases.triage import phaseT
from recon.report import RunData, generate_html, generate_markdown
from recon.runner import Logger

RUN = "2026-11-10"


def _hist(**kw):
    return {k: {"first_seen": v[0], "seen": v[1], "severity": v[2], "title": k} for k, v in kw.items()}


def _compute(history, buckets=None, curr=None, prev=None, **kw):
    return trends.compute_trends(run_date=RUN, prev_date="2026-11-03", history=history,
                                 buckets=buckets or {}, curr_sev=curr or {}, prev_sev=prev or {}, **kw)


class TestAge(unittest.TestCase):
    def test_bucket_edges(self) -> None:
        got = [trends.age_bucket(d) for d in (0, 29, 30, 90, 91, 180, 181)]
        self.assertEqual(got, ["<30", "<30", "30-90", "30-90", "90-180", "90-180", ">180"])

    def test_age_days_and_per_severity_buckets(self) -> None:
        h = _hist(a=("2026-11-05", ["2026-11-05", RUN], "high"),
                  b=("2026-07-01", ["2026-07-01", RUN], "high"),
                  c=("2025-01-01", ["2025-01-01", RUN], "critical"),
                  d=("2026-10-01", ["2026-10-01", RUN], "low"))
        t = _compute(h, curr={"a": "high", "b": "high", "c": "critical", "d": "low"},
                     buckets={"persisting": "abcd"})
        self.assertEqual(t["age_buckets"]["high"], {"<30": 1, "30-90": 0, "90-180": 1, ">180": 0})
        self.assertEqual(t["age_buckets"]["critical"][">180"], 1)
        self.assertEqual(t["age_buckets"]["low"]["30-90"], 1)  # 40 days
        self.assertEqual([o["key"] for o in t["oldest_open"]], ["c", "b", "a"])
        self.assertEqual(t["oldest_open"][0]["age_days"],
                         (trends.parse_day(RUN) - trends.parse_day("2025-01-01")).days)

    def test_oldest_limited_to_five_and_high_critical_only(self) -> None:
        h = _hist(**{f"k{i}": (f"2026-0{i}-01", [RUN], "high") for i in range(1, 8)},
                  m=("2020-01-01", [RUN], "medium"))
        curr = {k: "high" for k in h}
        curr["m"] = "medium"
        t = _compute(h, curr=curr)
        self.assertEqual(len(t["oldest_open"]), 5)
        self.assertNotIn("m", [o["key"] for o in t["oldest_open"]])


class TestMttr(unittest.TestCase):
    def test_median_per_severity_and_window(self) -> None:
        h = _hist(
            r1=("2026-10-01", ["2026-10-01", "2026-10-11"], "high"),   # resolved 10-18 -> 17d
            r2=("2026-09-01", ["2026-09-01", "2026-10-11"], "high"),   # resolved 10-18 -> 47d
            r3=("2026-10-10", ["2026-10-10"], "low"),                  # resolved 10-11 -> 1d
            old=("2025-01-01", ["2025-01-01", "2025-02-01"], "high"),  # resolved long ago
        )
        h[trends.RUNS_KEY] = [{"date": d} for d in ("2025-02-15", "2026-10-11", "2026-10-18", RUN)]
        t = _compute(h)
        self.assertEqual(t["mttr"]["by_severity"]["high"], {"n": 2, "median_days": 32.0})
        self.assertEqual(t["mttr"]["by_severity"]["low"], {"n": 1, "median_days": 1.0})
        self.assertEqual(t["mttr"]["n"], 3)  # "old" is outside the 90-day window

    def test_resolution_waits_for_a_run_that_checked_it(self) -> None:
        h = _hist(x=("2026-10-01", ["2026-10-01"], "high"))
        h[trends.RUNS_KEY] = [
            {"date": "2026-10-08", "phases": ["1"]},       # phase 3 did not run
            {"date": "2026-10-15", "phases": ["1", "3"], "failed_tools": []},
        ]
        ev = trends.resolution_events(h, RUN, [], phase_of=lambda k: "3")
        self.assertEqual(ev[0]["resolved_at"], "2026-10-15")
        self.assertEqual(ev[0]["days"], 14)
        h[trends.RUNS_KEY][1]["failed_tools"] = ["nuclei"]
        ev = trends.resolution_events(h, RUN, [], phase_of=lambda k: "3", tools_of=lambda k: ("nuclei",))
        self.assertEqual(ev, [])  # tool failed: nothing proves it is gone

    def test_not_rechecked_is_not_resolved(self) -> None:
        h = _hist(x=("2026-10-01", ["2026-10-01", "2026-11-03"], "high"))
        h[trends.RUNS_KEY] = [{"date": "2026-11-03", "phases": ["3"]}, {"date": RUN, "phases": ["1"]}]
        t = _compute(h, buckets={"not_rechecked": ["x"]}, prev={"x": "high"}, phase_of=lambda k: "3")
        self.assertEqual(t["totals"]["resolved"], 0)
        self.assertEqual(t["totals"]["not_rechecked"], 1)
        self.assertEqual(t["mttr"]["n"], 0)

    def test_resolved_now_without_runs_uses_run_date(self) -> None:
        h = _hist(x=("2026-11-01", ["2026-11-01", "2026-11-03"], "medium"))
        h.pop(trends.RUNS_KEY, None)
        t = _compute(h, buckets={"resolved": ["x"]}, prev={"x": "medium"})
        self.assertEqual(t["mttr"]["by_severity"]["medium"], {"n": 1, "median_days": 9.0})

    def test_still_open_not_resolved(self) -> None:
        h = _hist(x=("2026-10-01", ["2026-10-01", RUN], "high"))
        self.assertEqual(trends.resolution_events(h, RUN, []), [])


class TestHistoryCompat(unittest.TestCase):
    def test_old_history_without_runs_key(self) -> None:
        h = _hist(a=("2026-10-01", ["2026-10-01", "2026-10-08"], "high"),
                  b=("2026-10-01", ["2026-10-01", "2026-10-08", RUN], "high"))
        self.assertNotIn(trends.RUNS_KEY, h)
        self.assertEqual([r["date"] for r in trends.known_runs(h)], ["2026-10-01", "2026-10-08", RUN])
        ev = trends.resolution_events(h, RUN, [])
        self.assertEqual([(e["key"], e["resolved_at"], e["days"]) for e in ev], [("a", RUN, 40)])

    def test_record_run_and_reserved_key_ignored(self) -> None:
        h = _hist(a=("2026-10-01", ["2026-10-01"], "high"))
        trends.record_run(h, RUN, {"3", "1"}, {"nmap"})
        trends.record_run(h, RUN, {"1"}, set())  # replaces, not duplicates
        self.assertEqual(h[trends.RUNS_KEY], [{"date": RUN, "phases": ["1"], "failed_tools": []}])
        self.assertEqual(list(trends.finding_entries(h)), ["a"])

    def test_corrupt_runs_value_tolerated(self) -> None:
        h = _hist(a=("2026-10-01", ["2026-10-01"], "high"))
        h[trends.RUNS_KEY] = "garbage"
        trends.record_run(h, RUN, [], [])
        self.assertEqual(len(h[trends.RUNS_KEY]), 1)


class TestSummaryMd(unittest.TestCase):
    def test_net_and_table(self) -> None:
        t = _compute(_hist(n=("2026-11-10", [RUN], "high")), curr={"n": "high"},
                     prev={"g": "high", "h": "high"}, buckets={"new": ["n"], "resolved": ["g", "h"]})
        text = "\n".join(trends.render_summary_md(t))
        self.assertIn("Net change: **-1**", text)
        self.assertIn("| high | 1 | 0 | 0 | 2 | 0 | -1 |", text)
        self.assertEqual(t["net"]["high"], -1)


class _Run:
    """Synthetic phaseT run with one CORS finding, optionally against a previous run."""

    def __init__(self, td: str, with_prev: bool) -> None:
        root = Path(td)
        (root / "scopes").mkdir()
        scope = ScopeConfig(path=root / "scopes" / "syn.toml", name="syn", engagement="Syn",
                            domains=["example.com"])
        self.ctx = RunContext(root=root, scope=scope, run_date=RUN, phases=["T"], skip_active=True)
        scope_dir = self.ctx.runs_root / "syn"
        if with_prev:
            p = scope_dir / "2026-11-03"
            p.mkdir(parents=True)
            (p / "findings_auto.tsv").write_text(
                "high\tcors:https://gone.example.com/\tCORS gone\tx\n"
                "high\tcors:https://app.example.com/\tCORS app\tx\n", encoding="utf-8")
            (scope_dir / "findings_history.json").write_text(json.dumps({
                "cors:https://gone.example.com/": {"first_seen": "2026-10-04", "seen": ["2026-10-04", "2026-11-03"],
                                                   "severity": "high", "title": "CORS gone"},
                "cors:https://app.example.com/": {"first_seen": "2026-05-01", "seen": ["2026-05-01", "2026-11-03"],
                                                  "severity": "high", "title": "CORS app"},
            }))
        self.ctx.ensure_dirs()
        (self.ctx.web_dir / "cors_cookies.tsv").write_text(
            "https://app.example.com/\tcors\tACAO: *\n", encoding="utf-8")
        phaseT(self.ctx, DependencyManager(use_docker=False, run_dir=self.ctx.run_dir),
               Logger(self.ctx.run_dir / "gaps.txt"))
        self.rd = self.ctx.run_dir
        self.hist_path = scope_dir / "findings_history.json"


class TestEndToEnd(unittest.TestCase):
    def test_diff_summary_report_card_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, with_prev=True)
            diff = (r.rd / "diff.md").read_text()
            self.assertTrue(diff.startswith("# Changes 2026-11-03 -> " + RUN))
            self.assertIn("## Summary", diff)
            self.assertLess(diff.index("## Summary"), diff.index("## Resolved"))
            self.assertIn("Net change: **-1**", diff)
            self.assertIn("MTTR", diff)
            self.assertIn("Oldest open critical/high", diff)
            data = RunData(r.rd)
            # Existing bucket parsing is unaffected by the Summary block
            self.assertEqual(len(data.diff_summary["Resolved"]), 1)
            self.assertEqual(len(data.diff_summary["Persisting"]), 1)
            self.assertEqual(data.trends["mttr"]["by_severity"]["high"]["median_days"], 37.0)
            html_doc, md = generate_html(data), generate_markdown(data)
            self.assertIn('id="what-changed"', html_doc)
            self.assertIn("What changed since 2026-11-03", html_doc)
            self.assertLess(html_doc.index('id="what-changed"'), html_doc.index("Severity KPI Cards"))
            self.assertIn("## What Changed Since 2026-11-03", md)
            exported = json.loads((r.rd / "report_data.json").read_text())
            self.assertEqual(exported["trends"]["previous_run"], "2026-11-03")
            self.assertEqual(exported["schema_version"], "1.0")
            hist = json.loads(r.hist_path.read_text())
            self.assertEqual(hist[trends.RUNS_KEY][-1]["date"], RUN)

    def test_no_previous_run_no_summary_or_card(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _Run(td, with_prev=False)
            self.assertFalse((r.rd / "diff.md").exists())
            self.assertFalse((r.rd / "trends.json").exists())
            data = RunData(r.rd)
            self.assertEqual(data.trends, {})
            self.assertNotIn("what-changed", generate_html(data))
            self.assertNotIn("What Changed Since", generate_markdown(data))
            self.assertEqual(json.loads((r.rd / "report_data.json").read_text())["trends"], {})


if __name__ == "__main__":
    unittest.main()
