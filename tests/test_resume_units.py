"""Intra-phase resume: a phase that did not finish skips the units it already completed (--resume)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import recon.cli as cli
from recon import checkpoint
from recon.config import RunContext, ScopeConfig
from recon.phases import active, osint
from recon.runner import CmdResult, Logger, load_tool_failures, record_tool_failure


def _ctx(d: Path, resume: bool = False, phases=("4",), **kw) -> RunContext:
    toml = d / "s.toml"
    if not toml.exists():
        toml.write_text(
            f'[engagement]\nengagement="t"\nruns_dir="{d}/runs"\n[targets]\ndomains=["acme.com"]\n'
            'hvt_ips=["203.0.113.1","203.0.113.2"]\n'
        )
    ctx = RunContext(root=d, scope=ScopeConfig.load(toml), run_date="2026-11-04", phases=list(phases), resume=resume, **kw)
    ctx.ensure_dirs()
    return ctx


class UnitApiTests(unittest.TestCase):
    def test_mark_done_clear_and_sig_invalidation(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            checkpoint.mark_unit(run, "4", "a:1", "sigA", {"x": 1})
            self.assertTrue(checkpoint.unit_done(run, "4", "a:1", "sigA"))
            self.assertEqual(checkpoint.unit_data(run, "4", "a:1", "sigA"), {"x": 1})
            self.assertFalse(checkpoint.unit_done(run, "4", "a:1", "sigB"))  # scope edited
            self.assertFalse(checkpoint.unit_done(run, "4", "a:2", "sigA"))
            self.assertFalse(checkpoint.unit_done(run, "8", "a:1", "sigA"))  # per phase
            checkpoint.clear_units(run, "4")
            self.assertFalse(checkpoint.unit_done(run, "4", "a:1", "sigA"))

    def test_units_helper_only_counts_under_resume_and_scope_edit_invalidates(self):
        with tempfile.TemporaryDirectory() as d:
            off = _ctx(Path(d))
            checkpoint.Units(off, "4").mark("k")
            self.assertFalse(checkpoint.Units(off, "4").done("k"))  # resume off ignores markers
            on = _ctx(Path(d), resume=True)
            self.assertTrue(checkpoint.Units(on, "4").done("k"))
            (Path(d) / "s.toml").write_text((Path(d) / "s.toml").read_text() + "\n# edit\n")
            on2 = _ctx(Path(d), resume=True)
            self.assertFalse(checkpoint.Units(on2, "4").done("k"))

    def test_mark_is_noop_in_dry_run(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = _ctx(Path(d), resume=True)
            with mock.patch("recon.runner.dry_run_active", return_value=True):
                checkpoint.Units(ctx, "4").mark("k")
            self.assertFalse(checkpoint.Units(ctx, "4").done("k"))


class Phase4Tests(unittest.TestCase):
    def _run(self, ctx, rc=0, timed_out=False):
        calls = []

        def fake_ev(console_dir, phase, args, **kw):
            args = list(args)
            calls.append(args)
            prefix = Path(args[args.index("-oA") + 1])  # like nmap -oA
            Path(str(prefix) + ".nmap").write_text("22/tcp   open  ssh\n", encoding="utf-8")
            return CmdResult(args=args, returncode=rc, stdout="", stderr="", timed_out=timed_out)

        dm = SimpleNamespace(run_dir=ctx.run_dir, is_available=lambda t: True, build_cmd=lambda tool, a: [tool, *a],
                             get_provider=lambda t: "native")
        with mock.patch.object(active, "ev", fake_ev), \
             mock.patch.object(active, "_collect_tls", lambda *a, **k: None), \
             mock.patch.object(active.os, "geteuid", lambda: 1000):
            active.phase4(ctx, dm, mock.Mock())
        return calls

    def test_resume_skips_finished_ips_and_fresh_run_redoes_everything(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(len(self._run(_ctx(Path(d)))), 4)  # 2 IPs x (full + svc)
            self.assertEqual(self._run(_ctx(Path(d), resume=True)), [])
            self.assertEqual(len(self._run(_ctx(Path(d)))), 4)  # no --resume: everything again

    def test_partial_nmap_file_without_marker_is_rerun(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = _ctx(Path(d), resume=True)
            (ctx.scan_dir / "full_203.0.113.1.nmap").write_text("22/tcp   open  ssh\n")  # a killed nmap left this
            calls = self._run(ctx)
            full_scans = [c for c in calls if "-p-" in c]
            self.assertEqual(len(full_scans), 2)  # both IPs scanned: the partial file did not count

    def test_failed_or_timed_out_scan_is_never_marked(self):
        with tempfile.TemporaryDirectory() as d:
            self._run(_ctx(Path(d)), rc=124, timed_out=True)
            self.assertFalse((_ctx(Path(d)).run_dir / ".checkpoints" / "4.units").exists())
            self.assertTrue(len(self._run(_ctx(Path(d), resume=True))) >= 2)

    def test_only_unfinished_ip_reruns(self):
        with tempfile.TemporaryDirectory() as d:
            self._run(_ctx(Path(d)))
            ctx = _ctx(Path(d), resume=True)
            for f in (ctx.run_dir / ".checkpoints" / "4.units").iterdir():  # IP .2 was interrupted
                if "203.0.113.2" in json.loads(f.read_text())["key"]:
                    f.unlink()
            calls = self._run(ctx)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(c[-1] == "203.0.113.2" for c in calls))


class Phase9Tests(unittest.TestCase):
    def test_resume_reuses_account_results_without_requerying(self):
        urls = []

        def fake(url, headers=None, timeout=0):
            urls.append(url)
            if "breachedaccount/bob" in url:
                return 200, [{"Name": "L", "Title": "Leak", "BreachDate": "2020-01-01", "PwnCount": 5,
                              "DataClasses": ["Passwords"]}]
            return 404, None

        with tempfile.TemporaryDirectory() as d, \
             mock.patch("recon.phases.osint.time.sleep"), mock.patch("recon.phases.osint.http_get_json", fake):
            emails = ["bob@acme.com", "eve@acme.com"]
            _, acc1 = osint.run_hibp_breaches(_ctx(Path(d), hibp_api_key="k"), Logger(), emails=emails)
            n_first = len([u for u in urls if "breachedaccount" in u])
            self.assertEqual((n_first, len(acc1)), (2, 1))
            ctx2 = _ctx(Path(d), resume=True, hibp_api_key="k")
            _, acc2 = osint.run_hibp_breaches(ctx2, Logger(), emails=emails)
            self.assertEqual(len([u for u in urls if "breachedaccount" in u]), n_first)  # not re-queried
            self.assertEqual(acc2, acc1)  # aggregate rebuilt from reused units
            self.assertIn("bob@acme.com", (ctx2.osint_dir / "hibp_account_breaches.tsv").read_text())

    def test_failed_lookup_is_not_marked_and_reruns(self):
        calls = []

        def fake(url, headers=None, timeout=0):
            if "breachedaccount" in url:
                calls.append(url)
                return 500, None
            return 404, None

        with tempfile.TemporaryDirectory() as d, \
             mock.patch("recon.phases.osint.time.sleep"), mock.patch("recon.phases.osint.http_get_json", fake):
            osint.run_hibp_breaches(_ctx(Path(d), hibp_api_key="k"), Logger(), emails=["a@acme.com"])
            n = len(calls)
            osint.run_hibp_breaches(_ctx(Path(d), resume=True, hibp_api_key="k"), Logger(), emails=["a@acme.com"])
            self.assertEqual(len(calls), 2 * n)


class CliPrologueTests(unittest.TestCase):
    def setUp(self):
        self._orig = (cli.PHASE_MAP, cli.preflight)
        cli.preflight = lambda *a, **k: None

    def tearDown(self):
        cli.PHASE_MAP, cli.preflight = self._orig

    def _run(self, scope, *extra):
        seen = {}

        def phase6(ctx, dm, log):
            seen["log"] = (ctx.console_dir / "6.log").is_file()
            seen["unit"] = checkpoint.Units(ctx, "6").done("u")
            checkpoint.Units(ctx, "6").mark("u")
            (ctx.console_dir / "6.log").write_text("evidence\n")
            record_tool_failure(ctx.run_dir, "6", "x", "boom")  # the phase never completes cleanly

        cli.PHASE_MAP = {**cli.PHASE_MAP, "6": phase6}
        cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "6", "-y", "--no-venv", *extra])
        return seen

    def test_resume_keeps_console_log_and_units_but_fresh_run_wipes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = root / "s.toml"
            scope.write_text(f'[engagement]\nengagement="restest"\nruns_dir="{root}/runs"\n'
                             '[targets]\ndomains=["t.example.com"]\n')
            self.assertEqual(self._run(scope), {"log": False, "unit": False})
            run_dir = root / "runs" / "s" / "2026-11-06"
            self.assertEqual(load_tool_failures(run_dir)[0][1], "x")
            self.assertEqual(self._run(scope, "--resume"), {"log": True, "unit": True})
            self.assertEqual(self._run(scope), {"log": False, "unit": False})


if __name__ == "__main__":
    unittest.main()
