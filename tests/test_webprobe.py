"""Web probes that find data exposed behind 404s, at the web root, via OpenAPI or hashed hostnames."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from recon import webprobe
from recon.config import RunContext, ScopeConfig
from recon.deps import DependencyManager
from recon.phases import active, osint
from recon.phases.triage import phaseT
from recon.runner import HttpResponse, Logger

HASH_A = "0123456789abcdef0123456789abcdef"
HASH_B = "fedcba9876543210fedcba9876543210"
HASH_C = "00112233445566778899aabbccddeeff"


def resp(status=200, body="", ctype="", **headers):
    h = {"content-type": ctype} if ctype else {}
    h.update({k.replace("_", "-"): v for k, v in headers.items()})
    return HttpResponse(status=status, body=body, headers=h, final_url="")


class TestClassifiers(unittest.TestCase):
    def test_ingress_default_404_vs_app_404(self) -> None:
        self.assertTrue(webprobe.is_ingress_default_404(404, "text/html", "404 Not Found", "nginx"))
        self.assertTrue(webprobe.is_ingress_default_404(404, "", "", ""))
        self.assertFalse(webprobe.is_ingress_default_404(404, "application/json", "", ""))
        self.assertFalse(webprobe.is_ingress_default_404(404, "text/html", "Page missing - Acme portal", "Apache"))

    def test_sniff_csv_with_personal_fields(self) -> None:
        r = resp(206, "id,displayName,mail,manager,terminationDate\n1,A,a@example.com,,\n",
                 "text/csv; charset=utf-8", content_range="bytes 0-4095/1666615")
        data = webprobe.sniff_root_data("https://x.example.com/export.csv", r)
        self.assertEqual(data.size, "1666615")
        self.assertEqual(data.sensitive, ["displayName", "mail", "manager", "terminationDate"])

    def test_sniff_plain_inventory_without_personal_fields(self) -> None:
        r = resp(200, "uid,name,project,request issue,cluster\n1,argocd,,,c1\n", "text/plain; charset=utf-8",
                 content_length="1566")
        data = webprobe.sniff_root_data("https://x.example.com/", r)
        self.assertEqual(data.columns[:2], ["uid", "name"])
        self.assertEqual(data.sensitive, [])

    def test_sniff_ignores_html_and_prose(self) -> None:
        self.assertIsNone(webprobe.sniff_root_data("u", resp(200, "<html><body>hi</body></html>", "text/html")))
        self.assertIsNone(webprobe.sniff_root_data("u", resp(200, "OK", "text/plain")))
        self.assertIsNone(webprobe.sniff_root_data("u", resp(404, "a,b\n", "text/csv")))

    def test_openapi_and_discovery(self) -> None:
        schema = json.dumps({"openapi": "3.1.0", "paths": {"/export.csv": {"get": {}}, "/items/{id}": {"get": {}},
                                                            "/upload": {"post": {}}}})

        def fake_get(url, **kw):
            if url.endswith("/openapi.json"):
                return resp(200, schema, "application/json")
            if url.endswith("/export.csv"):
                return resp(200, "id;mail;jobTitle\n", "text/csv", content_length="2444730")
            return resp(404, '{"detail":"Not Found"}', "application/json")

        schema_url, eps = webprobe.discover_api("https://h.example.com", fake_get)
        self.assertEqual(schema_url, "https://h.example.com/openapi.json")
        self.assertEqual([(e.url, e.status, e.size, e.sensitive) for e in eps],
                         [("https://h.example.com/export.csv", 200, "2444730", ["mail", "jobTitle"])])

    def test_hash_label(self) -> None:
        self.assertTrue(webprobe.is_hash_label(f"{HASH_A}.example.com"))
        self.assertTrue(webprobe.is_hash_label("123e4567-e89b-12d3-a456-426614174000.example.com"))
        self.assertFalse(webprobe.is_hash_label("cafe.example.com"))
        self.assertFalse(webprobe.is_hash_label("www.example.com"))


class TestPipeline(unittest.TestCase):
    def _ctx(self, root: Path, run_date: str = "2026-11-03", phases=("3", "T")) -> RunContext:
        scope = ScopeConfig(path=root / "scopes" / "acme.toml", name="acme", engagement="Acme", domains=["example.com"])
        ctx = RunContext(root=root, scope=scope, run_date=run_date, phases=list(phases))
        ctx.ensure_dirs()
        return ctx

    def test_phase3_finds_exports_behind_404_and_at_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            hosts = {f"{HASH_A}.example.com": "93.184.216.34", f"{HASH_B}.example.com": "93.184.216.34",
                     "www.example.com": "93.184.216.34"}
            (ctx.osint_dir / "ip_host.tsv").write_text("".join(f"{ip}\t{h}\n" for h, ip in hosts.items()))
            (ctx.osint_dir / "resolved.txt").write_text("".join(f"{h}\n" for h in hosts))
            (ctx.web_dir / "httpx_all.json").write_text("\n".join(json.dumps(x) for x in [
                {"url": f"https://{HASH_A}.example.com", "status_code": 404, "content_type": "application/json"},
                {"url": f"https://{HASH_B}.example.com", "status_code": 200, "content_type": "text/plain"},
                {"url": "https://www.example.com", "status_code": 404, "content_type": "text/html",
                 "title": "404 Not Found", "webserver": "nginx"},
            ]) + "\n")
            schema = json.dumps({"openapi": "3.0.0", "paths": {"/export.csv": {"get": {}}}})
            calls = []

            def fake_get(url, **kw):
                calls.append(url)
                if url == f"https://{HASH_A}.example.com/openapi.json":
                    return resp(200, schema, "application/json")
                if url == f"https://{HASH_A}.example.com/export.csv":
                    return resp(206, "id,userPrincipalName,mail\n", "text/csv", content_range="bytes 0-4095/900000")
                if url == f"https://{HASH_B}.example.com/":
                    return resp(200, "uid,name,cluster\n", "text/plain", content_length="1566")
                return resp(404, "", "")

            dm = mock.Mock(run_dir=None)
            dm.is_available.return_value = True
            dm.build_cmd.side_effect = lambda n, a: [n, *a]
            with mock.patch.object(active, "ev"), mock.patch.object(active, "http_get", side_effect=fake_get), \
                    mock.patch.object(active.time, "sleep"):
                active.phase3(ctx, dm, Logger())

            self.assertFalse(any(u.startswith("https://www.example.com/") for u in calls), "ingress 404 probed")
            api = (ctx.web_dir / "api_endpoints.tsv").read_text()
            self.assertIn(f"https://{HASH_A}.example.com/export.csv\t206\ttext/csv\t900000\tuserPrincipalName,mail", api)
            root = (ctx.web_dir / "root_data.tsv").read_text()
            self.assertIn(f"https://{HASH_B}.example.com/\ttext/plain\t1566\tuid,name,cluster\t", root)

            phaseT(ctx, DependencyManager(use_docker=False, run_dir=ctx.run_dir), Logger())
            rows = [l.split("\t") for l in (ctx.run_dir / "findings_auto.tsv").read_text().splitlines()]
            keys = {r[1]: r[0] for r in rows}
            self.assertEqual(keys[f"api-data:{HASH_A}.example.com"], "critical")
            self.assertEqual(keys[f"data-export:{HASH_B}.example.com"], "high")
            self.assertEqual(keys[f"hash-host:{HASH_A}.example.com"], "medium")
            self.assertEqual(keys[f"hash-host:{HASH_B}.example.com"], "medium")

    def test_failed_httpx_falls_back_and_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            host = f"{HASH_B}.example.com"
            (ctx.osint_dir / "ip_host.tsv").write_text(f"93.184.216.34\t{host}\n")
            (ctx.osint_dir / "resolved.txt").write_text(f"{host}\n")
            failed = mock.Mock(returncode=125, stdout="", stderr="Cannot connect to the Docker daemon")

            def fake_get(url, **kw):
                if url == f"https://{host}/":
                    return resp(200, "uid,name,cluster\n", "text/plain", content_length="1566")
                return resp(404, "", "")

            dm = mock.Mock(run_dir=None)
            dm.is_available.return_value = True
            dm.build_cmd.side_effect = lambda n, a: [n, *a]
            gaps = ctx.run_dir / "gaps.txt"
            with mock.patch.object(active, "ev", return_value=failed), \
                    mock.patch.object(active, "http_get", side_effect=fake_get), mock.patch.object(active.time, "sleep"):
                active.phase3(ctx, dm, Logger(gaps))

            self.assertIn("httpx produced no results (exit 125: Cannot connect to the Docker daemon)", gaps.read_text())
            self.assertIn(f"https://{host} [200]", (ctx.web_dir / "httpx_all.txt").read_text())
            self.assertIn(f"https://{host}/\ttext/plain\t1566", (ctx.web_dir / "root_data.tsv").read_text())
            meta = json.loads((ctx.web_dir / "httpx_all.json").read_text().splitlines()[0])
            self.assertEqual(meta["content_type"], "text/plain")

    def test_certspotter_fallback_records_first_seen(self) -> None:
        pages = [
            [{"id": "1", "dns_names": [f"{HASH_C}.example.com"], "not_before": "2026-04-15T00:00:00Z"},
             {"id": "2", "dns_names": [f"{HASH_C}.example.com", "*.example.com"], "not_before": "2026-02-14T00:00:00Z"}],
            [],
        ]
        seen = {}

        def note(n, d):
            seen[n] = min(seen.get(n, d[:10]), d[:10])

        with mock.patch.object(osint, "http_get_json", side_effect=[(200, p) for p in pages]):
            names = osint._certspotter_names("example.com", note)
        self.assertIn(f"{HASH_C}.example.com", names)
        self.assertEqual(seen[f"{HASH_C}.example.com"], "2026-02-14")


class TestRunDiff(unittest.TestCase):
    def _run(self, root: Path, date: str, phases: str, findings: list[str], extra=None) -> None:
        scope = ScopeConfig(path=root / "scopes" / "acme.toml", name="acme", engagement="Acme", domains=["example.com"])
        ctx = RunContext(root=root, scope=scope, run_date=date, phases=["T"], skip_active=True)
        ctx.ensure_dirs()
        (ctx.run_dir / "run.meta").write_text(f"date={date}\nphases={phases}\n")
        for f, content in (extra or {}).items():
            (ctx.run_dir / f).parent.mkdir(parents=True, exist_ok=True)
            (ctx.run_dir / f).write_text(content)
        (ctx.osint_dir / "dns_example.com.txt").write_text(
            "$ dig +short TXT example.com\n" + ('"v=spf1 -all"\n' if "spf" not in findings else "") + "\n"
            "$ dig +short TXT _dmarc.example.com\n\"v=DMARC1; p=reject\"\n\n"
            "$ dig +short CAA example.com\n0 issue \"letsencrypt.org\"\n\n"
            "$ dig +short DNSKEY example.com\n257 3 13 AAAA\n\n"
        )
        phaseT(ctx, DependencyManager(use_docker=False, run_dir=ctx.run_dir), Logger())

    def test_skipped_phase_is_not_resolved_and_history_ages(self) -> None:
        nmap = "Nmap scan report for 93.184.216.34\n22/tcp open ssh OpenSSH 9.6\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._run(root, "2026-09-01", "2 4 T", ["spf"], {"scan/svc_1.nmap": nmap})
            self._run(root, "2026-10-01", "2 4 T", [], {"scan/svc_1.nmap": nmap})
            # November: phase 4 not run, SPF broken again
            self._run(root, "2026-11-01", "2 T", ["spf"])
            diff = (root / "runs" / "acme" / "2026-11-01" / "diff.md").read_text()
            self.assertIn("## Not re-checked (1)", diff)
            self.assertIn("## Resolved (0)", diff)
            self.assertIn("## Reappeared (1)", diff)
            history = json.loads((root / "runs" / "acme" / "findings_history.json").read_text())
            self.assertEqual(history["ssh:93.184.216.34"]["seen"], ["2026-09-01", "2026-10-01"])
            self.assertEqual(history["spf:example.com"]["seen"], ["2026-09-01", "2026-11-01"])


if __name__ == "__main__":
    unittest.main()
