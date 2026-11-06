"""Tests for the --doctor health check (recon.cli._doctor)."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

import recon.cli as cli
from recon.runner import Logger


_SCOPE_TOML = """\
[engagement]
engagement = "Doctor Test"
authorised_by = "Tester"
authorisation_ref = "REF1"

[targets]
domains = ["test.example.com"]
"""


class _FakeDM:
    """Stand-in DependencyManager so doctor tests don't depend on host tooling."""

    required_ok = True

    def __init__(self, *a, **k) -> None:
        pass

    def check_all(self, *a, **k):
        return []

    def print_report(self, *a, **k) -> bool:
        return _FakeDM.required_ok


class TestDoctor(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_dm = cli.DependencyManager
        self._orig_egress = cli._get_egress_ip
        cli.DependencyManager = _FakeDM  # type: ignore[assignment]
        cli._get_egress_ip = lambda: "203.0.113.5"  # type: ignore[assignment]
        _FakeDM.required_ok = True

    def tearDown(self) -> None:
        cli.DependencyManager = self._orig_dm  # type: ignore[assignment]
        cli._get_egress_ip = self._orig_egress  # type: ignore[assignment]

    def _run(self, scope_path: Path) -> tuple[int, str]:
        lines: list[str] = []
        log = Logger()
        log._c = lambda code, msg: lines.append(msg)  # type: ignore[assignment]
        args = argparse.Namespace(doctor=True, docker=False, scope=str(scope_path))
        rc = cli._doctor(args, log)
        return rc, "\n".join(lines)

    def test_healthy_scope_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scope = Path(td) / "ok.toml"
            scope.write_text(_SCOPE_TOML, encoding="utf-8")
            rc, out = self._run(scope)
            self.assertEqual(rc, 0)
            self.assertIn("1 domain(s)", out)
            self.assertIn("Next:", out)
            self.assertIn("--profile light", out)

    def test_missing_scope_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rc, out = self._run(Path(td) / "nope.toml")
            self.assertEqual(rc, 1)
            self.assertIn("not found", out)
            self.assertIn("cp scopes/example.toml", out)

    def test_missing_required_dependency_blocks(self) -> None:
        _FakeDM.required_ok = False
        with tempfile.TemporaryDirectory() as td:
            scope = Path(td) / "ok.toml"
            scope.write_text(_SCOPE_TOML, encoding="utf-8")
            rc, out = self._run(scope)
            self.assertEqual(rc, 1)
            self.assertIn("blocking issue", out)

    def test_integrations_report(self) -> None:
        from recon.config import ScopeConfig

        lines: list[str] = []
        log = Logger()
        log._c = lambda code, msg: lines.append(msg)  # type: ignore[assignment]
        scope = ScopeConfig(
            path=Path("s.toml"), name="s", engagement="s",
            shodan_api_key="abc123def", alert_webhook="https://hook.example/x",
        )
        cli._doctor_integrations(scope, log)
        out = "\n".join(lines)
        self.assertIn("Shodan: configured", out)
        self.assertIn("Alert webhook: configured", out)
        self.assertIn("HaveIBeenPwned: not set", out)


if __name__ == "__main__":
    unittest.main()
