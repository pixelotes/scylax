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

    def _scope_file(self, root: Path) -> Path:
        runs = root / "runs"
        p = root / "restest.toml"
        p.write_text(_SCOPE_TOML.format(runs=runs.as_posix()), encoding="utf-8")
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

            self.assertEqual(rc, 0)  # the run completed despite the crash
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


if __name__ == "__main__":
    unittest.main()
