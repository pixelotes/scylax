"""Detection improvements: NVD fallback helpers, triage rules, report KPIs, re-run hygiene."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from recon import nvd
from recon.config import RunContext, ScopeConfig
from recon.deps import DependencyManager
from recon.phases.triage import phaseT
from recon.report import RunData
from recon.runner import Logger, record_virtual_cmd, reset_phase_console


class TestNvdHelpers(unittest.TestCase):
    def test_cpe_to_23(self) -> None:
        self.assertEqual(
            nvd.cpe_to_23("cpe:/a:apache:http_server:2.4.52"),
            "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
        )
        # Unversioned CPEs would match every CVE of the product: skipped
        self.assertIsNone(nvd.cpe_to_23("cpe:/a:igor_sysoev:nginx"))
        self.assertIsNone(nvd.cpe_to_23("cpe:/o:linux:linux_kernel"))

    def test_nvd_parsing_drops_v2_only(self) -> None:
        payload = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2007-4723", "metrics": {"cvssMetricV2": [
                    {"type": "Primary", "cvssData": {"baseScore": 7.5}}]},
                    "descriptions": [{"lang": "en", "value": "old"}]}},
                {"cve": {"id": "CVE-2022-31813", "metrics": {"cvssMetricV31": [
                    {"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
                    "descriptions": [{"lang": "en", "value": "mod_proxy X-Forwarded-For"}]}},
            ]
        }
        with mock.patch.object(nvd, "http_get_json", return_value=(200, payload)), \
                mock.patch.object(nvd.time, "sleep"):
            st, items = nvd.nvd_cves_for_cpe("cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*", api_key="k")
        self.assertEqual(st, 200)
        self.assertEqual([i["cve_id"] for i in items], ["CVE-2022-31813"])
        self.assertEqual(items[0]["cvss"], "9.8")


class TestTriageRules(unittest.TestCase):
    def _run(self, setup) -> list[list[str]]:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = ScopeConfig(
                path=root / "scopes" / "synthetic.toml",
                name="synthetic",
                engagement="Synthetic",
                domains=["example.com"],
            )
            ctx = RunContext(root=root, scope=scope, run_date="2026-11-03", phases=["T"], skip_active=True)
            ctx.ensure_dirs()
            setup(ctx)
            phaseT(ctx, DependencyManager(use_docker=False, run_dir=ctx.run_dir), Logger())
            rows = (ctx.run_dir / "findings_auto.tsv").read_text().splitlines()
            return [r.split("\t") for r in rows]

    def test_target_column(self) -> None:
        def setup(ctx):
            ctx.azure_dir.mkdir(parents=True, exist_ok=True)
            (ctx.azure_dir / "public_ips.tsv").write_text(
                "93.184.216.34\tvm-runner-ip\trg-ci\tnetworkInterfaces/vm-runner-nic\n", encoding="utf-8")
            (ctx.azure_dir / "nsg_internet_rules.tsv").write_text(
                "runner-nsg\trg-ci\tallow-ssh\t22\t1\tVM-RUNNER-NIC\t/subscriptions/x/nsg/runner-nsg\n"
                "other-nsg\trg-ci\tallow-rdp\t3389\t0\t\t/subscriptions/x/nsg/other-nsg\n",
                encoding="utf-8")
            (ctx.osint_dir / "hibp_account_breaches.tsv").write_text(
                "email\tname\ttitle\tbreach_date\tpwn_count\tdata_classes\tis_verified\tis_sensitive\n"
                "jdoe@example.com\tPeopleDataLabs\tPeopleDataLabs\t\t0\t\tFalse\tFalse\n",
                encoding="utf-8")
        rows = {r[1]: r for r in self._run(setup)}
        self.assertEqual(rows["nsg:runner-nsg:allow-ssh"][4], "93.184.216.34")
        self.assertEqual(rows["nsg:other-nsg:allow-rdp"][4],
                         "https://portal.azure.com/#@/resource/subscriptions/x/nsg/other-nsg")
        breach = rows["hibp-account:jdoe@example.com:PeopleDataLabs"]
        self.assertEqual(breach[4], "https://api.xposedornot.com/v1/check-email/jdoe%40example.com")
        self.assertIn("date unknown", breach[2])
        self.assertIn("unknown", breach[3])

    def test_mgmt_ui_and_dedupe(self) -> None:
        def setup(ctx):
            (ctx.scan_dir / "svc_203.0.113.5.nmap").write_text(
                "Nmap scan report for 203.0.113.5\n"
                "22/tcp   open  ssh        OpenSSH 10.3 (protocol 2.0)\n"
                "443/tcp  open  ssl/https  OPNsense\n"
                "|     <html><head><title>CSRF check failed</title>\n",
                encoding="utf-8",
            )
            (ctx.scan_dir / "svc_203.0.113.6.nmap").write_text(
                "Nmap scan report for 203.0.113.6\n"
                "80/tcp  open  http      Apache httpd 2.4.52 ((Ubuntu))\n"
                "443/tcp open  ssl/http  Apache httpd 2.4.52 ((Ubuntu))\n",
                encoding="utf-8",
            )

        rows = self._run(setup)
        mgmt = [r for r in rows if r[1] == "fw-admin:203.0.113.5"]
        self.assertEqual(len(mgmt), 1)
        self.assertIn("203.0.113.5:443", mgmt[0][3])
        apache = [r for r in rows if r[1] == "apache:203.0.113.6"]
        self.assertEqual(len(apache), 1)
        self.assertEqual(apache[0][3], "203.0.113.6:80; 203.0.113.6:443")

    def test_redirect_tenant_leak(self) -> None:
        tenant = "00000000-1111-4222-8333-444444444444"

        def setup(ctx):
            (ctx.web_dir / "httpx_all.txt").write_text(
                f"https://erp.example.com [302] [] [Apache] [https://account.activedirectory.windowsazure.com/applications/signin/x?tenantId={tenant}]\n"
                "https://fpa.example.com [301] [] [Apache] [https://sso.vendor.example/acme]\n"
                "https://app.example.com [302] [] [] [https://login.example.com/]\n",
                encoding="utf-8",
            )

        rows = self._run(setup)
        leak = [r for r in rows if r[1] == "redirect-tenant-leak"]
        self.assertEqual(len(leak), 1)
        self.assertIn(tenant, leak[0][3])
        self.assertNotIn("login.example.com", leak[0][3])

    def test_report_ignores_cve_header(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td)
            (run_dir / "osint").mkdir()
            (run_dir / "osint" / "service_cves.tsv").write_text(
                "ip\tport\tservice\tversion\tcve\tcvss\tis_kev\tsummary\n", encoding="utf-8"
            )
            data = RunData.__new__(RunData)
            data.run_dir = run_dir
            self.assertEqual(data._load_service_cves(), [])


class TestRerunHygiene(unittest.TestCase):
    def test_reset_phase_console(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cdir = Path(td)
            record_virtual_cmd(cdir, "1", "subfinder -d a", "x")
            record_virtual_cmd(cdir, "2", "dnsx -l s", "y")
            record_virtual_cmd(cdir, "1", "subfinder -d a", "x")
            reset_phase_console(cdir, "1")
            phases = [json.loads(l)["phase"] for l in (cdir / "commands.jsonl").read_text().splitlines()]
            self.assertEqual(phases, ["2"])
            self.assertFalse((cdir / "1.log").exists())

    def test_gaps_not_duplicated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            gaps = Path(td) / "gaps.txt"
            log = Logger(gaps)
            log.warn("nmap missing")
            log.warn("nmap missing")
            self.assertEqual(gaps.read_text().splitlines(), ["nmap missing"])


if __name__ == "__main__":
    unittest.main()
