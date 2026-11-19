"""Resume / scheduler gaps: second Ctrl-C force-exits, prologue crashes are
recorded, phase C does not checkpoint abandoned hosts, phase 7 reuses lookups."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import recon.cli as cli
from recon import runner, scheduler
from recon.phases import content, osint
from recon.resilience import AdaptiveLimiter
from recon.runner import HttpResponse, Logger, load_tool_failures, run_cmd, terminate_children
from recon.scheduler import ForcedExit, run_phases

from tests.test_resume_units import _ctx


def _ctrl_c_on_calls(n: int):
    """A scheduler.wait stand-in raising KeyboardInterrupt on its first ``n`` calls."""
    orig = scheduler.wait
    calls = {"n": 0}

    def fake(*a, **kw):
        calls["n"] += 1
        if calls["n"] <= n:
            raise KeyboardInterrupt
        return orig(*a, **kw)

    return fake


class SecondCtrlCTests(unittest.TestCase):
    def test_second_ctrl_c_stops_waiting(self):
        release = threading.Event()
        self.addCleanup(release.set)
        flagged = threading.Event()

        def run_one(p):
            if p == "6":
                release.wait(5)  # a phase that ignores STOP for a long time
            return scheduler.OK

        t0 = time.monotonic()
        with mock.patch.object(scheduler, "wait", _ctrl_c_on_calls(2)):
            with self.assertRaises(ForcedExit) as cm:
                run_phases(["6", "1"], run_one, jobs=2, on_interrupt=flagged.set)
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertTrue(flagged.is_set())  # the first Ctrl-C was the graceful one
        self.assertIn("6", cm.exception.running)

    def test_first_ctrl_c_still_drains(self):
        with mock.patch.object(scheduler, "wait", _ctrl_c_on_calls(1)):
            outcomes, interrupted = run_phases(["6", "1"], lambda p: (time.sleep(0.05), scheduler.OK)[1], jobs=2)
        self.assertTrue(interrupted)
        self.assertEqual(sorted(outcomes), ["1", "6"])

    def test_cli_exits_130_without_waiting_or_salvaging(self):
        release = threading.Event()
        started = threading.Event()

        def slow6(ctx, dm, log):
            started.set()
            release.wait(5)

        orig = (cli.PHASE_MAP, cli.preflight)
        cli.preflight = lambda *a, **k: None
        cli.PHASE_MAP = {**cli.PHASE_MAP, "1": lambda c, d, l: None, "6": slow6, "9": lambda c, d, l: None}
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.addCleanup(lambda: [t.join(5) for t in threading.enumerate() if t.name.startswith("scylax-phase")])
        self.addCleanup(release.set)
        root = Path(td.name)
        scope = root / "s.toml"
        scope.write_text(f'[engagement]\nengagement="force"\nruns_dir="{root}/runs"\n'
                         '[targets]\ndomains=["t.example.com"]\n')
        exits: list[int] = []

        def hard_exit(code):
            exits.append(code)
            raise SystemExit(code)

        orig_wait = scheduler.wait
        calls = {"n": 0}

        def wait_then_ctrl_c(*a, **kw):  # Ctrl-C twice once phase 6 is running
            if started.is_set() and calls["n"] < 2:
                calls["n"] += 1
                raise KeyboardInterrupt
            return orig_wait(*a, **kw)

        t0 = time.monotonic()
        try:
            with mock.patch.object(cli, "_hard_exit", hard_exit), \
                 mock.patch.object(scheduler, "wait", wait_then_ctrl_c), \
                 mock.patch.object(cli, "terminate_children", return_value=0) as term, \
                 self.assertRaises(SystemExit) as cm:
                cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "1 6 9 T", "-y", "--no-venv", "--jobs", "3"])
        finally:
            cli.PHASE_MAP, cli.preflight = orig
        self.assertEqual(cm.exception.code, 130)
        self.assertEqual(exits, [130])
        self.assertLess(time.monotonic() - t0, 3.0)
        term.assert_called_once()
        self.assertFalse((root / "runs" / "s" / "2026-11-06" / "report.html").exists())  # no salvage

    @unittest.skipIf(sys.platform == "win32", "POSIX sleep")
    def test_terminate_children_kills_running_commands(self):
        res = {}
        t = threading.Thread(target=lambda: res.update(r=run_cmd(["sleep", "30"], timeout=60)))
        t.start()
        deadline = time.monotonic() + 2
        while not runner._LIVE_PROCS and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(terminate_children(), 1)
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertNotEqual(res["r"].returncode, 0)
        self.assertFalse(runner._LIVE_PROCS)

    def test_run_cmd_still_captures_and_times_out(self):
        ok = run_cmd([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"])
        self.assertEqual((ok.returncode, ok.stdout.strip(), ok.stderr.strip(), ok.timed_out), (0, "out", "err", False))
        slow = run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.3)
        self.assertEqual((slow.returncode, slow.timed_out), (124, True))
        self.assertEqual(run_cmd(["/nonexistent/scylax-tool"]).returncode, 127)


class PrologueCrashTests(unittest.TestCase):
    def setUp(self):
        self._orig = (cli.PHASE_MAP, cli.preflight, cli._clear_tool_failures)
        cli.preflight = lambda *a, **k: None

    def tearDown(self):
        cli.PHASE_MAP, cli.preflight, cli._clear_tool_failures = self._orig

    def _run(self, jobs: str):
        ran: list[str] = []
        real_clear = self._orig[2]

        def clear(run_dir, phase):
            if phase == "6":
                raise OSError("disk says no")
            real_clear(run_dir, phase)

        cli._clear_tool_failures = clear
        cli.PHASE_MAP = {**cli.PHASE_MAP, **{p: (lambda p: lambda c, d, l: ran.append(p))(p) for p in "169"}}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = root / "s.toml"
            scope.write_text(f'[engagement]\nengagement="pro"\nruns_dir="{root}/runs"\n'
                             '[targets]\ndomains=["t.example.com"]\n')
            rc = cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "1 6 9 T", "-y", "--no-venv", "--jobs", jobs])
            run_dir = root / "runs" / "s" / "2026-11-06"
            failures = load_tool_failures(run_dir)
            log6 = (run_dir / "console" / "6.log").read_text()
            report = (run_dir / "report.html").is_file()
        return rc, sorted(ran), failures, log6, report

    def test_prologue_crash_recorded_in_worker_and_sequentially(self):
        for jobs in ("3", "1"):
            with self.subTest(jobs=jobs):
                rc, ran, failures, log6, report = self._run(jobs)
                self.assertEqual(rc, 2)  # counted as crashed
                self.assertEqual(ran, ["1", "9"])  # phase 6 never started, the rest ran
                self.assertIn(("6", "phase-6"), [(p, t) for p, t, _ in failures])
                self.assertIn("phase 6 crashed", log6)
                self.assertIn("disk says no", log6)
                self.assertTrue(report)


class PhaseCAbandonedHostTests(unittest.TestCase):
    DEAD = "203.0.113.1"
    revived = False

    def _run(self, ctx):
        hits: dict[str, int] = {}

        def fake_get(url, **kw):
            host = url.split("/")[2]
            hits[host] = hits.get(host, 0) + 1
            status = 0 if host == self.DEAD and not self.revived else 404
            return HttpResponse(status=status, body="", headers={}, final_url=url, redirect_url="")

        dm = SimpleNamespace(is_available=lambda t: False)
        with mock.patch.object(content, "http_get", fake_get), \
             mock.patch.object(content.time, "sleep"), \
             mock.patch.object(content, "AdaptiveLimiter",
                               lambda **kw: AdaptiveLimiter(sleep=lambda s: None, **kw)):
            content.phaseC(ctx, dm, Logger(ctx.run_dir / "gaps.txt"))
        return hits

    @staticmethod
    def _unit_keys(ctx):
        d = ctx.run_dir / ".checkpoints" / "C.units"
        return [json.loads(f.read_text())["key"] for f in d.iterdir()] if d.is_dir() else []

    def test_abandoned_host_not_marked_and_retried_on_resume(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = _ctx(Path(d), phases=("C",))
            hits = self._run(ctx)
            self.assertGreater(hits["203.0.113.2"], 10)
            tools = {(p, t) for p, t, _ in load_tool_failures(ctx.run_dir)}
            self.assertEqual(tools, {("C", "content-probe"), ("C", "traversal-probe")})
            self.assertIn(self.DEAD, (ctx.run_dir / "gaps.txt").read_text())
            marked = self._unit_keys(ctx)
            self.assertTrue(all(self.DEAD not in k for k in marked))
            self.assertEqual(len(marked), 2)  # native + traversal for the healthy host

            self.revived = True
            ctx2 = _ctx(Path(d), resume=True, phases=("C",))
            hits2 = self._run(ctx2)
            self.assertNotIn("203.0.113.2", hits2)  # finished host reused
            self.assertGreater(hits2[self.DEAD], 10)  # abandoned host retried in full
            self.assertEqual(len(self._unit_keys(ctx2)), 4)


_XML = """<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.0">
<cpe>cpe:/a:openbsd:openssh:8.0</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4.1">
<cpe>cpe:/a:apache:http_server:2.4.1</cpe></service></port>
</ports></host></nmaprun>"""


class Phase7LookupUnitTests(unittest.TestCase):
    def _run(self, ctx, *, cve2_ok: bool, cvedb_up: bool = True, nvd_ok=("openssh", "http_server")):
        urls: list[str] = []

        def fake_json(url, headers=None, timeout=0):
            urls.append(url)
            if not cvedb_up:
                return 0, None
            if "cves?cpe23=" in url:
                if "openssh" in url:
                    return 200, {"cves": ["CVE-2020-0001", "CVE-2020-0002"]}
                return 200, {"cves": [{"cve_id": "CVE-2020-0003", "cvss": 9.8, "summary": "apache bug"}]}
            if url.endswith("CVE-2020-0001"):
                return 200, {"cvss": 7.5, "summary": "ssh one"}
            if url.endswith("CVE-2020-0002"):
                return (200, {"cvss": 5.0, "summary": "ssh two"}) if cve2_ok else (503, None)
            return 404, None

        def fake_nvd(cpe):
            urls.append(f"nvd:{cpe}")
            if any(n in cpe for n in nvd_ok):
                return 200, [{"cve_id": f"CVE-NVD-{cpe.split(':')[4]}", "cvss": "8.1", "is_kev": False, "summary": "n"}]
            return 429, []

        (ctx.scan_dir / "full.xml").write_text(_XML, encoding="utf-8")
        with mock.patch.object(osint, "http_get_json", fake_json), \
             mock.patch.object(osint, "nvd_cves_for_cpe", fake_nvd), \
             mock.patch.object(osint, "load_kev_ids", return_value={"CVE-2020-0003"}), \
             mock.patch.object(osint.time, "sleep"):
            osint.phase7(ctx, mock.Mock(), mock.Mock())
        out = {n: p.read_text() for n, p in (("tsv", ctx.osint_dir / "service_cves.tsv"),
                                              ("csv", ctx.azure_dir / "cve_cvss.csv"),
                                              ("sum", ctx.azure_dir / "cve_summary.txt"))}
        return urls, out

    def test_successful_lookups_reused_failed_ones_retried(self):
        with tempfile.TemporaryDirectory() as fresh_d:
            _, fresh = self._run(_ctx(Path(fresh_d), phases=("7",)), cve2_ok=True)
        with tempfile.TemporaryDirectory() as d:
            urls1, out1 = self._run(_ctx(Path(d), phases=("7",)), cve2_ok=False)
            self.assertEqual(len(urls1), 4)
            self.assertNotEqual(out1["tsv"], fresh["tsv"])  # CVE-2 details missing
            urls2, out2 = self._run(_ctx(Path(d), resume=True, phases=("7",)), cve2_ok=True)
            # apache CPE and CVE-1 reused; the openssh CPE (incomplete: CVE-2 failed) and CVE-2 re-queried
            self.assertEqual(len(urls2), 2)
            self.assertTrue(any("openssh" in u for u in urls2))
            self.assertTrue(any(u.endswith("CVE-2020-0002") for u in urls2))
            self.assertEqual(out2, fresh)  # identical to a clean fresh run
            urls3, out3 = self._run(_ctx(Path(d), resume=True, phases=("7",)), cve2_ok=False)
            self.assertEqual(urls3, [])  # everything is now a unit
            self.assertEqual(out3, fresh)
            urls4, _ = self._run(_ctx(Path(d), phases=("7",)), cve2_ok=True)
            self.assertEqual(len(urls4), 4)  # no --resume: units ignored

    def test_nvd_fallback_lookups_reused_and_throttled_not_saved(self):
        with tempfile.TemporaryDirectory() as fresh_d:
            _, fresh = self._run(_ctx(Path(fresh_d), phases=("7",)), cve2_ok=True, cvedb_up=False)
        with tempfile.TemporaryDirectory() as d:
            urls1, _ = self._run(_ctx(Path(d), phases=("7",)), cve2_ok=True, cvedb_up=False, nvd_ok=("openssh",))
            self.assertEqual(sum(u.startswith("nvd:") for u in urls1), 2)
            urls2, out2 = self._run(_ctx(Path(d), resume=True, phases=("7",)), cve2_ok=True, cvedb_up=False)
            self.assertEqual(urls2, ["nvd:cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"])  # only the throttled one
            self.assertEqual(out2, fresh)


if __name__ == "__main__":
    unittest.main()
