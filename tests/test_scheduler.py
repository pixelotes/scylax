"""Phase scheduler (--jobs): dependency order, the active traffic lane, and the
thread-safety of the shared run files. No network."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from recon import scheduler
from recon.config import ACTIVE_PHASES, DEFAULT_PHASES
from recon.runner import Logger, load_tool_failures, record_tool_failure, record_virtual_cmd, reset_phase_console
from recon.scheduler import ACTIVE_LANE, CRASHED, INTERRUPTED, OK, effective_deps, run_phases


class _Recorder:
    """run_one stand-in: logs start/end order and peak concurrency per group."""

    def __init__(self, delay: float = 0.02, outcomes: dict[str, str] | None = None) -> None:
        self.delay = delay
        self.outcomes = outcomes or {}
        self.lock = threading.Lock()
        self.starts: list[str] = []
        self.ends: list[str] = []
        self.running: set[str] = set()
        self.max_lane = 0
        self.max_total = 0
        self.overlap_with_t = False

    def __call__(self, p: str) -> str:
        with self.lock:
            self.starts.append(p)
            if "T" in self.running or (p == "T" and self.running):
                self.overlap_with_t = True
            self.running.add(p)
            self.max_lane = max(self.max_lane, len(self.running & ACTIVE_LANE))
            self.max_total = max(self.max_total, len(self.running))
        time.sleep(self.delay)
        with self.lock:
            self.running.discard(p)
            self.ends.append(p)
        out = self.outcomes.get(p, OK)
        if out == "raise":
            raise RuntimeError("boom")
        return out


class TestScheduler(unittest.TestCase):
    def test_jobs1_runs_in_input_order(self):
        rec = _Recorder(delay=0)
        order = list(DEFAULT_PHASES)
        outcomes, interrupted = run_phases(order, rec, jobs=1)
        self.assertEqual(rec.starts, order)
        self.assertFalse(interrupted)
        self.assertEqual(list(outcomes), order)

    def test_jobs1_runnable_is_lazy_and_filters(self):
        seen: list[str] = []
        calls: list[str] = []

        def runnable(p):
            seen.append(f"check {p}")
            return p != "3"

        def run_one(p):
            seen.append(f"run {p}")
            calls.append(p)
            return OK

        run_phases(["1", "3", "5"], run_one, jobs=1, runnable=runnable)
        self.assertEqual(seen, ["check 1", "run 1", "check 3", "check 5", "run 5"])
        self.assertEqual(calls, ["1", "5"])

    def test_jobs1_interrupt_stops(self):
        rec = _Recorder(delay=0, outcomes={"2": INTERRUPTED})
        outcomes, interrupted = run_phases(["1", "2", "3"], rec, jobs=1)
        self.assertTrue(interrupted)
        self.assertEqual(rec.starts, ["1", "2"])

    def test_dependencies_respected(self):
        rec = _Recorder()
        order = list(DEFAULT_PHASES)
        run_phases(order, rec, jobs=8)
        self.assertEqual(sorted(rec.starts), sorted(order))
        need = effective_deps(order)
        for p, deps in need.items():
            for d in deps:
                self.assertLess(rec.ends.index(d), rec.starts.index(p), f"{p} started before {d} ended")

    def test_active_lane_never_overlaps(self):
        rec = _Recorder(delay=0.03)
        run_phases(list(DEFAULT_PHASES), rec, jobs=8)
        self.assertEqual(rec.max_lane, 1)
        self.assertGreater(rec.max_total, 1, "passive phases should run alongside")

    def test_active_lane_matches_active_phases(self):
        self.assertEqual(set(ACTIVE_LANE), set(ACTIVE_PHASES))

    def test_unselected_deps_ignored(self):
        # 5 depends on 3, which is not selected: 5 must not wait for anything.
        self.assertEqual(effective_deps(["5", "6"]), {"5": set(), "6": set()})
        rec = _Recorder()
        outcomes, _ = run_phases(["5", "8"], rec, jobs=4)
        self.assertEqual(set(outcomes), {"5", "8"})

    def test_filtered_out_phase_imposes_no_wait(self):
        rec = _Recorder()
        run_phases(["3", "5", "C"], rec, jobs=4, runnable=lambda p: p != "3")
        self.assertEqual(sorted(rec.starts), ["5", "C"])

    def test_crash_releases_dependents(self):
        rec = _Recorder(outcomes={"1": "raise", "3": CRASHED})
        outcomes, interrupted = run_phases(["1", "2", "3", "5"], rec, jobs=4)
        self.assertFalse(interrupted)
        self.assertEqual(outcomes["1"], CRASHED)
        self.assertEqual(outcomes["3"], CRASHED)
        self.assertEqual(outcomes["5"], OK)
        self.assertLess(rec.ends.index("3"), rec.starts.index("5"))

    def test_t_runs_last_and_alone(self):
        rec = _Recorder()
        order = ["T", "1", "6", "4b", "S"]  # even when listed first
        run_phases(order, rec, jobs=8)
        self.assertEqual(rec.starts[-1], "T")
        self.assertFalse(rec.overlap_with_t)

    def test_ready_phases_start_in_input_order(self):
        rec = _Recorder(delay=0.05)
        run_phases(["6", "1", "S", "4b"], rec, jobs=2)
        self.assertEqual(rec.starts[:2], ["6", "1"])

    def test_interrupt_outcome_stops_new_phases(self):
        rec = _Recorder(outcomes={"1": INTERRUPTED})
        outcomes, interrupted = run_phases(["1", "2", "3"], rec, jobs=4)
        self.assertTrue(interrupted)
        self.assertEqual(rec.starts, ["1"])

    def test_keyboard_interrupt_in_main_drains_running(self):
        flagged = threading.Event()
        rec = _Recorder(delay=0.3)
        orig_wait = scheduler.wait
        calls = {"n": 0}

        def fake_wait(*a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise KeyboardInterrupt
            return orig_wait(*a, **kw)

        scheduler.wait = fake_wait
        try:
            outcomes, interrupted = run_phases(["1", "6", "2"], rec, jobs=4, on_interrupt=flagged.set)
        finally:
            scheduler.wait = orig_wait
        self.assertTrue(interrupted)
        self.assertTrue(flagged.is_set())
        self.assertEqual(sorted(outcomes), ["1", "6"])  # ran to completion; 2 never started


class TestRunFileLocks(unittest.TestCase):
    def test_gaps_dedupe_under_threads(self):
        with tempfile.TemporaryDirectory() as d:
            log = Logger(gaps_file=Path(d) / "gaps.txt")
            import io
            import sys
            err, sys.stderr = sys.stderr, io.StringIO()
            try:
                threads = [threading.Thread(target=lambda i=i: [log.warn(f"gap {j % 5}") for j in range(40)])
                           for i in range(8)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            finally:
                sys.stderr = err
            lines = (Path(d) / "gaps.txt").read_text().splitlines()
            self.assertEqual(sorted(lines), [f"gap {j}" for j in range(5)])

    def test_console_and_tool_failures_no_lost_lines(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = Path(d)
            console = run_dir / "console"

            def work(ph):
                for i in range(30):
                    record_virtual_cmd(console, ph, f"echo {i}", "x")
                    record_tool_failure(run_dir, ph, f"tool{i}", "timed out")

            def resetter():
                for _ in range(30):
                    reset_phase_console(console, "Z")

            threads = [threading.Thread(target=work, args=(ph,)) for ph in ("1", "6", "9")]
            threads.append(threading.Thread(target=resetter))
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            jsonl = (console / "commands.jsonl").read_text().splitlines()
            self.assertEqual(len(jsonl), 90)
            self.assertEqual(len(load_tool_failures(run_dir)), 90)


class TestCliJobs(unittest.TestCase):
    """--jobs through recon.cli.main: crash containment, Ctrl-C and T last."""

    def setUp(self) -> None:
        import recon.cli as cli
        self.cli = cli
        self._orig = (cli.PHASE_MAP, cli.preflight)
        cli.preflight = lambda *a, **k: None  # type: ignore[assignment]

    def tearDown(self) -> None:
        self.cli.PHASE_MAP, self.cli.preflight = self._orig  # type: ignore[assignment]

    def _run(self, phases: dict, argv_extra: list[str]) -> tuple[int, Path]:
        patched = dict(self._orig[0])
        patched.update(phases)
        self.cli.PHASE_MAP = patched  # type: ignore[assignment]
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        scope = root / "jobs.toml"
        scope.write_text(
            '[engagement]\nengagement = "Jobs"\nauthorised_by = "T"\nauthorisation_ref = "R"\n'
            f'runs_dir = "{(root / "runs").as_posix()}"\n[targets]\ndomains = ["test.example.com"]\n',
            encoding="utf-8",
        )
        rc = self.cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "1 6 9 T", "-y", "--no-venv", *argv_extra])
        return rc, root / "runs" / "jobs" / "2026-11-06"

    def test_crash_in_worker_contained(self):
        order: list[str] = []

        def boom(ctx, dm, log):
            order.append("6")
            raise RuntimeError("kaboom")

        rc, run_dir = self._run({
            "1": lambda c, d, l: order.append("1"),
            "6": boom,
            "9": lambda c, d, l: order.append("9"),
        }, ["--jobs", "3"])
        self.assertEqual(rc, 2)
        self.assertTrue((run_dir / "report.html").is_file())
        self.assertEqual(sorted(order), ["1", "6", "9"])
        self.assertTrue(any(ph == "6" for ph, _t, _w in load_tool_failures(run_dir)))

    def test_interrupt_in_worker_exits_130(self):
        def stop(ctx, dm, log):
            raise KeyboardInterrupt

        rc, run_dir = self._run({"1": lambda c, d, l: None, "6": stop, "9": lambda c, d, l: None}, ["--jobs", "2"])
        self.assertEqual(rc, 130)
        self.assertTrue((run_dir / "report.html").is_file())  # salvaged


if __name__ == "__main__":
    unittest.main()
