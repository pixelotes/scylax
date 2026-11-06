"""Orchestrator resilience: a phase crash or Ctrl-C must never lose the report.

Covers the "never lose the report" guarantees wired into recon.cli.main:
- a phase whose own code raises is contained; the remaining phases and the
  report still run, and the crash is recorded as a tool failure (so triage marks
  its findings "not re-checked", never "resolved");
- Ctrl-C during a phase stops the run cleanly, salvages a report from the
  evidence so far, and exits 130;
- recovery hints are printed for an incomplete run.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import recon.cli as cli
from recon.runner import Logger, load_tool_failures


_SCOPE_TOML = """\
[engagement]
engagement = "Resilience Test"
authorised_by = "Tester"
authorisation_ref = "REF1"
runs_dir = "{runs}"
alert_webhook = "{webhook}"

[targets]
domains = ["test.example.com"]
"""


class _ResilienceCase(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_phase_map = cli.PHASE_MAP
        self._orig_preflight = cli.preflight
        # Skip dependency checks / prompts / egress lookup: isolate the phase loop.
        cli.preflight = lambda *a, **k: None  # type: ignore[assignment]

    def tearDown(self) -> None:
        cli.PHASE_MAP = self._orig_phase_map
        cli.preflight = self._orig_preflight  # type: ignore[assignment]

    def _scope_file(self, root: Path, webhook: str = "") -> Path:
        runs = root / "runs"
        p = root / "restest.toml"
        p.write_text(_SCOPE_TOML.format(runs=runs.as_posix(), webhook=webhook), encoding="utf-8")
        return p

    def _patch_phases(self, sixth) -> None:
        patched = dict(self._orig_phase_map)
        patched["6"] = sixth
        cli.PHASE_MAP = patched  # type: ignore[assignment]

    def test_phase_crash_is_contained_and_report_still_built(self) -> None:
        def boom(ctx, dm, log):
            raise RuntimeError("kaboom")

        self._patch_phases(boom)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = self._scope_file(root)
            rc = cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "6 T", "-y", "--no-venv"])

            self.assertEqual(rc, 2)  # finished despite the crash -> partial exit code
            run_dir = root / "runs" / "restest" / "2026-11-06"
            self.assertTrue((run_dir / "report.html").is_file())  # triage still ran
            # the crash was recorded so triage won't treat phase 6 as resolved
            fails = load_tool_failures(run_dir)
            self.assertTrue(any(ph == "6" and "crash" in why.lower() for ph, _tool, why in fails),
                            f"expected a recorded crash for phase 6, got {fails}")

    def test_keyboard_interrupt_salvages_report_and_exits_130(self) -> None:
        def stop(ctx, dm, log):
            raise KeyboardInterrupt

        self._patch_phases(stop)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = self._scope_file(root)
            rc = cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "6 T", "-y", "--no-venv"])

            self.assertEqual(rc, 130)  # interrupted
            run_dir = root / "runs" / "restest" / "2026-11-06"
            self.assertTrue((run_dir / "report.html").is_file())  # salvaged a report

    def test_clean_run_exits_zero(self) -> None:
        self._patch_phases(lambda ctx, dm, log: None)  # phase 6 does nothing, no crash
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = self._scope_file(root)
            rc = cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "6 T", "-y", "--no-venv"])
            self.assertEqual(rc, 0)
            self.assertTrue((root / "runs" / "restest" / "2026-11-06" / "report.html").is_file())

    def test_crash_sends_failure_alert(self) -> None:
        def boom(ctx, dm, log):
            raise RuntimeError("kaboom")

        calls: list[dict] = []
        orig = cli.notify.post_run_failure
        cli.notify.post_run_failure = lambda *a, **k: (calls.append(k) or (True, "alert sent"))  # type: ignore[assignment]
        try:
            self._patch_phases(boom)
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                scope = self._scope_file(root, webhook="https://hook.example/x")
                cli.main(["-s", str(scope), "-d", "2026-11-06", "-p", "6 T", "-y", "--no-venv"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["crashed"], ["6"])
            self.assertFalse(calls[0]["interrupted"])
        finally:
            cli.notify.post_run_failure = orig  # type: ignore[assignment]

    def test_recovery_hints_mention_resume_and_report_only(self) -> None:
        from recon.config import RunContext, ScopeConfig

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = ScopeConfig(
                path=root / "s.toml", name="restest", engagement="E",
                authorised_by="T", authorisation_ref="R", domains=["test.example.com"],
            )
            ctx = RunContext(root=root, scope=scope, run_date="2026-11-06",
                             phases=["6", "T"], skip_active=True, skip_cloud=True, yes=True)
            ctx.ensure_dirs()

            lines: list[str] = []
            log = Logger()
            log._c = lambda code, msg: lines.append(msg)  # type: ignore[assignment]

            cli._print_recovery_hints(ctx, log, interrupted=True, crashed=["6"])
            blob = "\n".join(lines)
            self.assertIn("--resume", blob)
            self.assertIn("--report-only", blob)
            self.assertIn("6", blob)  # names the crashed phase

    def test_record_phase_crash_writes_failure_and_traceback(self) -> None:
        from recon.config import RunContext, ScopeConfig

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = ScopeConfig(
                path=root / "s.toml", name="restest", engagement="E",
                authorised_by="T", authorisation_ref="R", domains=["test.example.com"],
            )
            ctx = RunContext(root=root, scope=scope, run_date="2026-11-06",
                             phases=["6"], skip_active=True, skip_cloud=True, yes=True)
            ctx.ensure_dirs()
            log = Logger()

            try:
                raise ValueError("boom-detail")
            except ValueError as exc:
                cli._record_phase_crash(ctx, "6", exc, log)

            fails = load_tool_failures(ctx.run_dir)
            self.assertTrue(any(ph == "6" and "ValueError" in why for ph, _t, why in fails))
            self.assertIn("crashed", (ctx.console_dir / "6.log").read_text(encoding="utf-8"))


class TestRunFailureAlert(unittest.TestCase):
    """notify.post_run_failure (point 5): alert a webhook on a failed/aborted run."""

    def _scope(self, webhook: str = ""):
        from recon.config import ScopeConfig
        return ScopeConfig(path=Path("s.toml"), name="s", engagement="s", alert_webhook=webhook)

    def test_no_webhook_not_attempted(self) -> None:
        from recon import notify
        attempted, _ = notify.post_run_failure(self._scope(), "s", "2026-11-06", crashed=["6"])
        self.assertFalse(attempted)

    def test_clean_run_not_attempted(self) -> None:
        from recon import notify
        attempted, msg = notify.post_run_failure(self._scope("https://hook"), "s", "2026-11-06")
        self.assertFalse(attempted)
        self.assertIn("cleanly", msg)

    def _post_and_capture(self, **kw) -> str:
        from unittest import mock
        from recon import notify

        captured: dict = {}

        class _R:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            captured["body"] = req.data.decode("utf-8")
            return _R()

        with mock.patch.object(notify.urllib.request, "urlopen", fake_urlopen):
            attempted, _ = notify.post_run_failure(
                self._scope("https://hook.example/x"), "acme", "2026-11-06", **kw)
        self.assertTrue(attempted)
        return captured["body"]

    def test_interrupted_card(self) -> None:
        body = self._post_and_capture(interrupted=True)
        self.assertIn("INTERRUPTED", body)
        self.assertIn("acme", body)

    def test_crashed_card_names_phases(self) -> None:
        body = self._post_and_capture(crashed=["6", "8"], run_dir="/runs/acme/2026-11-06")
        self.assertIn("failed phase", body)
        self.assertIn("6, 8", body)
        self.assertIn("/runs/acme/2026-11-06", body)


if __name__ == "__main__":
    unittest.main()
