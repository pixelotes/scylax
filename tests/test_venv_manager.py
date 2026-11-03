"""Unit tests for virtual environment detection, auto-creation, and bypass."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon.venv_manager import ensure_venv, get_venv_python, in_venv


class TestVenvManager(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.tmp.name)
        (self.repo_root / "scylax.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_in_venv_detection(self) -> None:
        """Verify in_venv() returns a bool."""
        res = in_venv()
        self.assertIsInstance(res, bool)

    def test_get_venv_python_path(self) -> None:
        """Verify python executable path format inside a venv directory."""
        venv_dir = self.repo_root / ".venv"
        py_bin = get_venv_python(venv_dir)
        if sys.platform == "win32":
            self.assertIn("Scripts", str(py_bin))
        else:
            self.assertIn("bin", str(py_bin))

    @patch("recon.venv_manager.in_venv", return_value=True)
    def test_already_in_venv_skips_check(self, mock_in_venv: MagicMock) -> None:
        """When already running inside a venv, ensure_venv returns True immediately without action."""
        res = ensure_venv(self.repo_root, argv=["-s", "scopes/example.toml"])
        self.assertTrue(res)

    @patch("recon.venv_manager.in_venv", return_value=False)
    def test_no_venv_flag_bypasses(self, mock_in_venv: MagicMock) -> None:
        """Passing --no-venv must bypass venv enforcement."""
        res = ensure_venv(self.repo_root, argv=["--no-venv", "-s", "scopes/example.toml"])
        self.assertFalse(res)

    @patch("recon.venv_manager.in_venv", return_value=False)
    def test_no_venv_env_var_bypasses(self, mock_in_venv: MagicMock) -> None:
        """Setting NO_VENV=1 must bypass venv enforcement."""
        with patch.dict("os.environ", {"NO_VENV": "1"}):
            res = ensure_venv(self.repo_root, argv=["-s", "scopes/example.toml"])
            self.assertFalse(res)

    @patch("recon.venv_manager.in_venv", return_value=False)
    def test_help_flag_bypasses(self, mock_in_venv: MagicMock) -> None:
        """Requesting --help or -h must bypass venv prompt to allow viewing options."""
        res = ensure_venv(self.repo_root, argv=["--help"])
        self.assertFalse(res)

        res_short = ensure_venv(self.repo_root, argv=["-h"])
        self.assertFalse(res_short)

    @patch("recon.venv_manager.in_venv", return_value=False)
    @patch("os.execv")
    def test_re_exec_into_existing_venv(self, mock_execv: MagicMock, mock_in_venv: MagicMock) -> None:
        """When .venv already exists, ensure_venv must re-exec using .venv's python."""
        venv_dir = self.repo_root / ".venv"
        py_path = get_venv_python(venv_dir)
        py_path.parent.mkdir(parents=True, exist_ok=True)
        py_path.write_text("#!/bin/sh\n", encoding="utf-8")

        ensure_venv(self.repo_root, argv=["-s", "scopes/test.toml"])
        self.assertTrue(mock_execv.called)
        args_called = mock_execv.call_args[0]
        self.assertEqual(args_called[0], str(py_path))

    @patch("recon.venv_manager.in_venv", return_value=False)
    @patch("os.execv")
    @patch("venv.create")
    def test_auto_create_with_yes_flag(
        self, mock_venv_create: MagicMock, mock_execv: MagicMock, mock_in_venv: MagicMock
    ) -> None:
        """When -y / --yes is supplied, .venv is automatically created and re-execed into."""
        ensure_venv(self.repo_root, argv=["-s", "scopes/test.toml", "-y"])
        self.assertTrue(mock_venv_create.called)
        self.assertTrue(mock_execv.called)

    @patch("recon.venv_manager.in_venv", return_value=False)
    def test_prompt_declined_continues_system_python(self, mock_in_venv: MagicMock) -> None:
        """When user declines the prompt ('n'), ensure_venv returns False and continues."""
        with patch("sys.stdin.readline", return_value="n\n"):
            res = ensure_venv(self.repo_root, argv=["-s", "scopes/test.toml"], interactive_prompt=True)
            self.assertFalse(res)


if __name__ == "__main__":
    unittest.main()

