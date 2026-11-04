"""Tests for phase C content discovery (recon.phases.content)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from recon.config import RunContext, ScopeConfig
from recon.phases import content
from recon.phases.content import _category, _load_words, _traversal_probe, phaseC
from recon.runner import Logger


class _Resp:
    def __init__(self, status: int = 200, body: str = "") -> None:
        self.status = status
        self.body = body
        self.headers = {}


class TestContentDiscovery(unittest.TestCase):
    def test_category_buckets(self) -> None:
        self.assertEqual(_category(".git/config"), "high")
        self.assertEqual(_category("backup.sql"), "high")
        self.assertEqual(_category("admin/login"), "medium")
        self.assertEqual(_category("actuator"), "medium")
        self.assertEqual(_category("assets/logo.png"), "low")

    def test_bundled_wordlist_loads(self) -> None:
        scope = ScopeConfig(path=Path("s.toml"), name="s", engagement="s")
        words = _load_words(scope)
        self.assertGreater(len(words), 100)
        self.assertNotIn("", words)
        self.assertTrue(all(not w.startswith("/") for w in words))

    def test_traversal_signature_gated(self) -> None:
        def passwd(url, **k):
            return _Resp(200, "root:x:0:0:root:/root:/bin/bash\n")

        def html(url, **k):
            return _Resp(200, "<html>home</html>")

        with mock.patch.object(content, "http_get", passwd):
            hits = _traversal_probe(["https://h"], 0.0)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][1], "etc/passwd")

        with mock.patch.object(content, "http_get", html):
            self.assertEqual(_traversal_probe(["https://h"], 0.0), [])

    def test_phase_c_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scope = ScopeConfig(path=Path(td) / "s.toml", name="s", engagement="s",
                                domains=["example.com"])
            ctx = RunContext(root=Path(td), scope=scope, run_date="2026-11-04",
                             phases=["C"], explicit_phases=True)
            ctx.ensure_dirs()
            # named explicitly with -p C => runs
            self.assertEqual(ctx.phase_skip_reason("C"), "")
            scope2 = ScopeConfig(path=Path(td) / "s.toml", name="s", engagement="s",
                                 domains=["example.com"])
            ctx2 = RunContext(root=Path(td), scope=scope2, run_date="2026-11-04",
                              phases=["1", "C"], explicit_phases=False)
            self.assertEqual(ctx2.phase_skip_reason("C"), "content discovery disabled")

    def test_phase_c_writes_outputs_with_native_probe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scope = ScopeConfig(path=Path(td) / "s.toml", name="s", engagement="s",
                                domains=["example.com"], hvt_ips=["203.0.113.5"],
                                content_discovery=True)
            ctx = RunContext(root=Path(td), scope=scope, run_date="2026-11-04", phases=["C"])
            ctx.ensure_dirs()
            dm = mock.Mock()
            dm.is_available.return_value = False  # force native probe

            def fake_get(url, **k):
                if url.endswith("/admin"):
                    return _Resp(200, "login")
                if "etc/passwd" in url:
                    return _Resp(200, "root:x:0:0:root:/root:/bin/bash")
                return _Resp(404, "")

            with mock.patch.object(content, "http_get", fake_get):
                phaseC(ctx, dm, Logger(ctx.run_dir / "log.txt"))

            cd = (ctx.web_dir / "content_discovery.tsv").read_text()
            trav = (ctx.web_dir / "path_traversal.tsv").read_text()
            self.assertIn("/admin", cd)
            self.assertIn("etc/passwd", trav)


if __name__ == "__main__":
    unittest.main()
