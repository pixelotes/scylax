"""Redaction, resilience, checkpoints, dry-run, JSONL export."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from recon import checkpoint, redact, runner
from recon.export import write_assets_jsonl, write_findings_jsonl
from recon.resilience import AdaptiveLimiter, CircuitBreaker, http_get_retry


def resp(status, body="", headers=None):
    return SimpleNamespace(status=status, body=body, headers=headers or {})


class RedactTests(unittest.TestCase):
    def setUp(self):
        redact.clear()

    def tearDown(self):
        redact.clear()

    def test_registered_values_and_url_params_are_masked(self):
        redact.register("topsecretvalue", "abc")  # too short is ignored
        out = redact.redact('curl "https://x/y?key=AAA111&q=1" topsecretvalue abc')
        self.assertNotIn("topsecretvalue", out)
        self.assertNotIn("AAA111", out)
        self.assertIn("abc", out)
        self.assertIn("q=1", out)

    def test_bearer_header_masked_and_record_virtual_cmd_redacts(self):
        redact.register("s3cr3t-token")
        with tempfile.TemporaryDirectory() as d:
            console = Path(d)
            runner.record_virtual_cmd(console, "1", "curl -H 'Authorization: Bearer abc.def' s3cr3t-token", "got s3cr3t-token")
            text = (console / "1.log").read_text() + (console / "commands.jsonl").read_text()
        self.assertNotIn("s3cr3t-token", text)
        self.assertNotIn("abc.def", text)


class ResilienceTests(unittest.TestCase):
    def test_breaker_opens_after_threshold_and_resets_on_success(self):
        b = CircuitBreaker(threshold=2)
        self.assertTrue(b.allow("w"))
        self.assertFalse(b.failure("w"))
        self.assertTrue(b.failure("w"))  # this one opened it
        self.assertFalse(b.allow("w"))
        b.reset()
        b.failure("w")
        b.success("w")
        self.assertTrue(b.allow("w"))

    def test_retry_gives_up_on_final_4xx_and_retries_5xx_with_retry_after(self):
        sleeps, calls = [], iter([resp(503, headers={"retry-after": "7"}), resp(200, "ok")])
        r = http_get_retry("u", fetch=lambda url, **k: next(calls), sleep=sleeps.append, delays=(0, 1, 2))
        self.assertEqual(r.status, 200)
        self.assertEqual(sleeps, [7.0])  # waited the larger of backoff (1) and Retry-After (7)
        r = http_get_retry("u", fetch=lambda url, **k: resp(404), sleep=sleeps.append, delays=(0, 1, 2))
        self.assertEqual(r.status, 404)

    def test_retry_feeds_breaker(self):
        b = CircuitBreaker(threshold=1)
        http_get_retry("u", source="s", breaker=b, fetch=lambda u, **k: resp(0), sleep=lambda s: None, delays=(0, 1))
        self.assertFalse(b.allow("s"))

    def test_limiter_backs_off_then_gives_up_on_throttling_host_only(self):
        sleeps = []
        lim = AdaptiveLimiter(give_up_after=3, sleep=sleeps.append)
        get = lim.wrap(lambda url, **k: resp(429 if "slow" in url else 200))
        for _ in range(3):
            get("https://slow.example/x")
        self.assertEqual(sleeps, [0.25, 0.5])  # 1st call free, then doubling
        self.assertEqual(get("https://slow.example/x").status, 0)  # abandoned, no request made
        self.assertEqual(get("https://fine.example/x").status, 200)


class SensitiveProbeTests(unittest.TestCase):
    def test_dead_host_is_abandoned_after_three_failures_and_others_still_probed(self):
        from collections import Counter
        from recon.sensitive_paths import SensitivePath, probe_sensitive_paths

        paths = [SensitivePath(f"/p{i}", "x", "low", r"HIT", "t") for i in range(10)]
        calls = Counter()

        def get(url, **k):
            host = url.split("/")[2]
            calls[host] += 1
            if host == "dead":
                return resp(0)
            return resp(200, "HIT") if url.endswith("/p3") else resp(404)

        seen = []
        hits = probe_sensitive_paths(["https://dead", "https://ok1", "https://ok2"], get, paths=paths, delay=0,
                                     progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(calls["dead"], 3)
        self.assertEqual((calls["ok1"], calls["ok2"]), (10, 10))
        self.assertEqual([h.url for h in hits], ["https://ok1/p3", "https://ok2/p3"])  # input order kept
        self.assertEqual(seen[-1], (3, 3))

    def test_limiter_stops_calling_a_host_that_never_answers(self):
        lim = AdaptiveLimiter(sleep=lambda s: None)
        calls = []
        get = lim.wrap(lambda url, **k: (calls.append(url), resp(0))[1])
        for _ in range(6):
            get("https://down.example/x")
        self.assertEqual(len(calls), 3)


class CheckpointTests(unittest.TestCase):
    def test_done_only_for_same_scope_signature(self):
        with tempfile.TemporaryDirectory() as d:
            rd = Path(d)
            self.assertFalse(checkpoint.is_done(rd, "4", "sig1"))
            checkpoint.mark_done(rd, "4", "sig1")
            self.assertTrue(checkpoint.is_done(rd, "4", "sig1"))
            self.assertFalse(checkpoint.is_done(rd, "4", "sig2"))  # scope edited
            checkpoint.clear(rd, "4")
            self.assertFalse(checkpoint.is_done(rd, "4", "sig1"))


class DryRunTests(unittest.TestCase):
    def test_nothing_runs_and_plan_lists_commands_and_hosts(self):
        runner.DRY_RUN.reset()
        runner.DRY_RUN.active = True
        runner.DRY_RUN.phase = "4"
        try:
            res = runner.run_cmd(["nmap", "-sT", "10.0.0.1"])
            r = runner.http_get("https://example.org/a?key=SECRETKEYVALUE")
            plan = runner.dry_run_report()
        finally:
            runner.DRY_RUN.reset()
        self.assertEqual((res.returncode, res.stdout, r.status), (0, "", 0))
        self.assertIn("$ nmap -sT 10.0.0.1", plan)
        self.assertIn("HTTP example.org: 1 request(s)", plan)


class ExportTests(unittest.TestCase):
    def test_findings_and_assets_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            rd = Path(d)
            (rd / "osint").mkdir(); (rd / "web").mkdir(); (rd / "scan").mkdir()
            (rd / "osint" / "subdomains.txt").write_text("a.example.com\n")
            (rd / "web" / "httpx_all.json").write_text(json.dumps({"url": "https://a.example.com", "status_code": 200, "title": "t"}) + "\n")
            (rd / "scan" / "full_1.2.3.4.nmap").write_text("443/tcp open  https\n")
            n = write_findings_jsonl(rd, [("high", "k:1", "T", "ev")], engagement="e", run_date="2026-11-04",
                                     target_of=lambda k: "tgt", phase_of=lambda k: "4", tools_of=lambda k: ("nmap",))
            m = write_assets_jsonl(rd)
            f = json.loads((rd / "findings.jsonl").read_text().splitlines()[0])
            assets = [json.loads(l) for l in (rd / "assets.jsonl").read_text().splitlines()]
        self.assertEqual((n, m), (1, 3))
        self.assertEqual((f["status"], f["severity"], f["tools"]), ("candidate", "high", ["nmap"]))
        self.assertEqual({a["type"] for a in assets}, {"hostname", "url", "port"})


if __name__ == "__main__":
    unittest.main()
