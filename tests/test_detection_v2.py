"""Tests for the second detection wave: subdomain takeover, the native sensitive-path
probe, scope validation, tool-failure recording and webhook alerting."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from recon import notify
from recon.config import ScopeConfig, validate_scope
from recon.runner import (
    CmdResult,
    infra_failure,
    load_tool_failures,
    record_tool_failure,
    tool_name,
)
from recon.sensitive_paths import SENSITIVE_PATHS, SensitivePath, probe_sensitive_paths
from recon.takeover import check_takeover


class _Resp:
    def __init__(self, status: int = 200, body: str = "", headers: dict | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}


class TestTakeover(unittest.TestCase):
    def test_azure_nxdomain_is_high(self) -> None:
        c = check_takeover("old.example.com", "gone.azurewebsites.net.", cname_resolves=False)
        self.assertIsNotNone(c)
        assert c is not None
        self.assertEqual((c.service, c.severity), ("Azure", "high"))

    def test_resolving_service_without_fingerprint_is_clean(self) -> None:
        self.assertIsNone(check_takeover("x.example.com", "foo.s3.amazonaws.com", cname_resolves=True))

    def test_s3_unclaimed_fingerprint(self) -> None:
        got = check_takeover(
            "x.example.com", "foo.s3.amazonaws.com", cname_resolves=True,
            http_get=lambda *a, **k: _Resp(404, "<Error><Code>NoSuchBucket</Code>"),
        )
        self.assertIsNotNone(got)
        assert got is not None
        self.assertEqual(got.service, "AWS S3")

    def test_internal_dangling_cname(self) -> None:
        c = check_takeover(
            "a.example.io", "k8s-ing.example.io", cname_resolves=False,
            internal_suffixes=("example.io",),
        )
        self.assertIsNotNone(c)
        assert c is not None
        self.assertEqual(c.service, "internal")

    def test_unknown_cname_is_ignored(self) -> None:
        self.assertIsNone(check_takeover("a.example.com", "b.example.net", cname_resolves=True))


class TestSensitivePaths(unittest.TestCase):
    def test_signature_gated(self) -> None:
        paths = (SensitivePath("/metrics", "telemetry", "medium", r"^# (HELP|TYPE) \w+", "Prometheus metrics exposed"),)

        def ok(url, **k):
            return _Resp(200, "# HELP go_gc_duration_seconds A summary\n# TYPE x gauge")

        def wrong_body(url, **k):
            return _Resp(200, "<html>welcome</html>")

        self.assertEqual(len(probe_sensitive_paths(["https://h"], ok, paths=paths, delay=0)), 1)
        self.assertEqual(len(probe_sensitive_paths(["https://h"], wrong_body, paths=paths, delay=0)), 0)

    def test_status_must_match(self) -> None:
        paths = (SensitivePath("/x", "c", "low", r"found", "t", statuses=(200,)),)
        self.assertEqual(
            len(probe_sensitive_paths(["https://h"], lambda u, **k: _Resp(404, "found"), paths=paths, delay=0)), 0)

    def test_catalogue_is_well_formed(self) -> None:
        for p in SENSITIVE_PATHS:
            self.assertTrue(p.path.startswith("/"))
            self.assertIn(p.severity, ("critical", "high", "medium", "low", "info"))


class TestToolFailures(unittest.TestCase):
    def test_infra_failure_classification(self) -> None:
        docker_down = CmdResult(["x"], 1, "", "Cannot connect to the Docker daemon at unix:///x")
        self.assertTrue(infra_failure(docker_down))
        timed = CmdResult(["x"], 124, "", "", timed_out=True)
        self.assertEqual(infra_failure(timed), "timed out")
        ran_found_nothing = CmdResult(["x"], 0, "no results", "")
        self.assertEqual(infra_failure(ran_found_nothing), "")
        ran_nonzero_normal = CmdResult(["x"], 2, "", "some scan error")
        self.assertEqual(ran_nonzero_normal, ran_nonzero_normal)
        self.assertEqual(infra_failure(ran_nonzero_normal), "")

    def test_tool_name_from_docker(self) -> None:
        self.assertEqual(tool_name(["docker", "run", "--rm", "projectdiscovery/nuclei:latest", "-l", "x"]), "nuclei")
        self.assertEqual(tool_name(["nuclei", "-l", "x"]), "nuclei")

    def test_record_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td)
            record_tool_failure(run_dir, "8", "nuclei", "timed out")
            record_tool_failure(run_dir, "8", "nuclei", "timed out")  # deduped
            self.assertEqual(load_tool_failures(run_dir), [("8", "nuclei", "timed out")])


class TestValidateScope(unittest.TestCase):
    def _write(self, body: str) -> Path:
        d = Path(tempfile.mkdtemp())
        p = d / "s.toml"
        p.write_text(body, encoding="utf-8")
        return p

    def test_clean_scope(self) -> None:
        p = self._write('domains = ["example.com"]\nauthorised_by = "me"\nowned_ranges = ["203.0.113.0/24"]\n')
        errors, warnings = validate_scope(p)
        self.assertEqual(errors, [])

    def test_unknown_key_and_section(self) -> None:
        p = self._write('domains = ["x.com"]\n[intelligence]\nshodan_apikey = "x"\n[bogus]\nfoo = 1\n')
        _, warnings = validate_scope(p)
        self.assertTrue(any("shodan_apikey" in w for w in warnings))
        self.assertTrue(any("bogus" in w for w in warnings))

    def test_missing_file_is_error(self) -> None:
        p = self._write('domains = ["x.com"]\nowned_ips_file = "nope.txt"\n')
        errors, _ = validate_scope(p)
        self.assertTrue(any("owned_ips_file not found" in e for e in errors))

    def test_missing_domains_is_error(self) -> None:
        p = self._write('authorised_by = "me"\n')
        errors, _ = validate_scope(p)
        self.assertTrue(errors)


class TestNotify(unittest.TestCase):
    def _scope(self, webhook: str = "") -> ScopeConfig:
        return ScopeConfig(path=Path("s.toml"), name="s", engagement="s", alert_webhook=webhook)

    def test_no_webhook(self) -> None:
        attempted, _ = notify.post_new_findings(self._scope(), "s", "2026-11-04",
                                                [("high", "k", "t", "e")])
        self.assertFalse(attempted)

    def test_no_findings(self) -> None:
        attempted, _ = notify.post_new_findings(self._scope("https://hook"), "s", "2026-11-04", [])
        self.assertFalse(attempted)

    def test_posts_card(self) -> None:
        captured = {}

        class _R:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            captured["url"] = req.full_url
            captured["body"] = req.data.decode("utf-8")
            return _R()

        with mock.patch.object(notify.urllib.request, "urlopen", fake_urlopen):
            attempted, msg = notify.post_new_findings(
                self._scope("https://hook.example/x"), "acme", "2026-11-04",
                [("critical", "k", "Exposed API", "https://h/export.csv")])
        self.assertTrue(attempted)
        self.assertIn("acme", captured["body"])
        self.assertIn("Exposed API", captured["body"])


if __name__ == "__main__":
    unittest.main()
