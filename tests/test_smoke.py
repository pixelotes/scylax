"""Smoke test suite for Recon Pipeline.

Pure Python 3 standard library unittest implementation with zero external dependencies.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon.config import RunContext, ScopeConfig
from recon.deps import DependencyManager
from recon.phases.triage import phaseT
from recon.runner import Logger


class TestSmokePipeline(unittest.TestCase):
    """End-to-end smoke tests for the recon pipeline."""

    def test_1_scope_config_load(self) -> None:
        """Test ScopeConfig properly parses scopes/example.toml and sets all required fields."""
        example_path = REPO_ROOT / "scopes" / "example.toml"
        self.assertTrue(example_path.is_file(), f"Missing scope template: {example_path}")

        config = ScopeConfig.load(example_path)
        self.assertIsInstance(config, ScopeConfig)
        self.assertTrue(config.auto_discover_targets)
        self.assertIsInstance(config.gcp_projects, list)
        self.assertIsInstance(config.azure_subscriptions, list)
        self.assertEqual(config.edge_ports, "21,22,23,53,80,443,8291")
        self.assertTrue(len(config.skip_portscan_orgs_regex) > 0)
        self.assertIn("Cloudflare", config.skip_portscan_orgs_regex)
        self.assertIn("Fastly", config.skip_portscan_orgs_regex)

    def test_2_cli_check_deps(self) -> None:
        """Test ./scylax.py --check-deps and --docker output the dependency table cleanly."""
        cli_script = REPO_ROOT / "scylax.py"
        self.assertTrue(cli_script.is_file(), f"CLI entrypoint not found: {cli_script}")

        # Native check-deps
        res_native = subprocess.run(
            [sys.executable, str(cli_script), "--check-deps"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
        )
        self.assertEqual(res_native.returncode, 0, f"check-deps failed: {res_native.stderr}")
        out_native = res_native.stdout + res_native.stderr
        self.assertTrue("Plugin" in out_native or "Tool" in out_native)
        self.assertIn("Phases", out_native)
        self.assertTrue("Status" in out_native or "Required" in out_native)
        self.assertIn("Provider", out_native)
        self.assertIn("Detail", out_native)
        self.assertIn("nmap", out_native)

        # Docker check-deps
        res_docker = subprocess.run(
            [sys.executable, str(cli_script), "--check-deps", "--docker"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
        )
        self.assertEqual(res_docker.returncode, 0, f"check-deps --docker failed: {res_docker.stderr}")
        out_docker = res_docker.stdout + res_docker.stderr
        self.assertIn("docker", out_docker)
        self.assertTrue("Plugin" in out_docker or "Tool" in out_docker)

    def test_3_dependency_manager_build_cmd(self) -> None:
        """Test DependencyManager command builder and volume mount / path rewriting logic."""
        # 1. Native command building
        dm_native = DependencyManager(use_docker=False)
        cmd_native = dm_native.build_cmd("nmap", ["-sV", "-Pn", "203.0.113.10"])
        self.assertEqual(cmd_native, ["nmap", "-sV", "-Pn", "203.0.113.10"])

        # 2. Docker command building with volume mount and path rewriting
        mock_run_dir = Path("/tmp/mock_recon_run")
        dm_docker = DependencyManager(use_docker=True, run_dir=mock_run_dir)
        target_file = mock_run_dir / "targets.txt"
        output_prefix = mock_run_dir / "scan" / "pass1"

        cmd_docker = dm_docker.build_cmd(
            "nmap",
            ["-sT", "-iL", str(target_file), "-oA", str(output_prefix)],
        )

        self.assertEqual(cmd_docker[:3], ["docker", "run", "--rm"])
        self.assertIn("-v", cmd_docker)
        # Volume mount should map resolved run_dir to /data
        mount_arg = f"{mock_run_dir.resolve()}:/data"
        self.assertIn(mount_arg, cmd_docker)
        self.assertIn("instrumentisto/nmap:latest", cmd_docker)
        # Path rewriting checks
        self.assertIn("-iL", cmd_docker)
        self.assertIn("/data/targets.txt", cmd_docker)
        self.assertIn("/data/scan/pass1", cmd_docker)

    def test_4_phase_t_synthetic_run(self) -> None:
        """Full synthetic run of phaseT and generate_reports inside a TemporaryDirectory."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = ScopeConfig(
                path=root / "scopes" / "synthetic.toml",
                name="synthetic",
                engagement="Synthetic Attack Surface Assessment",
                domains=["example.com"],
                www_url="https://www.example.com/",
                min_apache="2.4.65",
                min_nginx="1.26.0",
                min_routeros="7.15",
            )
            ctx = RunContext(
                root=root,
                scope=scope,
                run_date="2026-11-03",
                phases=["T"],
                skip_active=True,
            )
            ctx.ensure_dirs()

            # 1. DNS logs with SPF, DMARC, AXFR
            (ctx.osint_dir / "dns_example.com.txt").write_text(
                "$ dig +short TXT example.com\n"
                '"v=spf1 include:_spf.google.com ~all"\n\n'
                "$ dig +short TXT _dmarc.example.com\n"
                '"v=DMARC1; p=none;"\n\n'
                "$ dig +short CAA example.com\n\n"
                "$ dig +short DNSKEY example.com\n\n"
                "$ dig AXFR example.com @ns1.example.com\n"
                "AXFR ALLOWED\n",
                encoding="utf-8",
            )

            # 2. Apex domain pointing to untracked external infrastructure
            (ctx.osint_dir / "apex.txt").write_text(
                "example.com apex 198.51.100.99\n"
                "  ptr: legacy.untracked-cloud.net\n"
                "  org-name: Rogue Hosting LLC\n",
                encoding="utf-8",
            )

            # 3. Nmap scan with outdated Apache 2.4.50 and weak SSH algorithms
            (ctx.scan_dir / "svc_198.51.100.10.nmap").write_text(
                "Nmap scan report for 198.51.100.10\n"
                "Host is up (0.012s latency).\n"
                "PORT   STATE SERVICE VERSION\n"
                "22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)\n"
                "|_ssh-dss: legacy key type\n"
                "| ssh2-enum-algos:\n"
                "|   kex_algorithms:\n"
                "|     diffie-hellman-group1-sha1\n"
                "80/tcp open  http    Apache httpd 2.4.50 ((Unix))\n"
                "|_http-server-header: Apache/2.4.50\n"
                "Nmap done\n",
                encoding="utf-8",
            )

            # 4. Fragile edge nmap scan with EOL MikroTik RouterOS 6.48
            (ctx.scan_dir / "edge_203.0.113.5.nmap").write_text(
                "Nmap scan report for 203.0.113.5\n"
                "Host is up (0.025s latency).\n"
                "PORT     STATE SERVICE VERSION\n"
                "8291/tcp open  winbox  MikroTik RouterOS 6.48\n"
                "Nmap done\n",
                encoding="utf-8",
            )

            # 5. Service CVEs with CISA KEV
            (ctx.osint_dir / "service_cves.tsv").write_text(
                "ip\tport\tservice\tversion\tcve\tcvss\tis_kev\tsummary\n"
                "198.51.100.10\t80\tapache\t2.4.50\tCVE-2021-41773\t9.8\ttrue\tPath traversal and RCE in Apache HTTP Server 2.4.49 and 2.4.50\n",
                encoding="utf-8",
            )

            # 6. Exposed paths & APIs
            (ctx.web_dir / "exposed_paths.tsv").write_text(
                "https://api.example.com/v2/api-docs\tapi-schema\tSwagger 2.0 API documentation\n"
                "https://dev.example.com/.env\tdotenv\tDATABASE_URL=postgres://root:secret@db/prod\n",
                encoding="utf-8",
            )

            # 7. Azure NSG internet rules
            (ctx.azure_dir / "nsg_internet_rules.tsv").write_text(
                "nsg-corp-prod\trg-network\tallow-rdp-internet\t3389\t1\n",
                encoding="utf-8",
            )

            # 8. GCP VPC firewall internet rules
            (ctx.gcp_dir / "firewall_internet_rules.tsv").write_text(
                "allow-ssh-internet\tcorp-analytics-prod\tvpc-default\ttcp:22\ttag-bastion\n",
                encoding="utf-8",
            )

            # 9. Azure security posture findings
            (ctx.azure_dir / "posture_findings.tsv").write_text(
                "high\taz-storage-public:stsyncexports\tStorage\tstsyncexports\tAzure Storage Account stsyncexports allows public blob access\trg-sync/stsyncexports allowBlobPublicAccess=true\n",
                encoding="utf-8",
            )

            # 10. AWS Security Group internet rules
            (ctx.aws_dir / "sg_internet_rules.tsv").write_text(
                "sg-0123456789abcdef0\tsg-synthetic-bastion\tus-east-1\t22\t0.0.0.0/0\n",
                encoding="utf-8",
            )

            # 10b. SaaS security posture findings
            (ctx.saas_dir / "posture_findings.tsv").write_text(
                "high\tm365-ca-no-mfa-all\tConditionalAccess\ttenant\tConditional Access without a policy requiring MFA for all users\tNo active CA policy enforces MFA for all users\n",
                encoding="utf-8",
            )

            # 11. Console commands for CLI Explorer
            (ctx.console_dir / "commands.jsonl").write_text(
                '{"phase": "1", "title": "subfinder", "cmd": "subfinder -d example.com -silent", "output": "api.example.com\\ndev.example.com", "returncode": 0, "duration_ms": 320, "timestamp": "2026-11-03T10:00:00Z"}\n'
                '{"phase": "4", "title": "nmap", "cmd": "nmap -sT -sV 198.51.100.10", "output": "PORT 80/tcp open http Apache httpd 2.4.50", "returncode": 0, "duration_ms": 1400, "timestamp": "2026-11-03T10:05:00Z"}\n',
                encoding="utf-8",
            )

            dm = DependencyManager(use_docker=False, run_dir=ctx.run_dir)
            log = Logger()
            phaseT(ctx, dm, log)

            findings_tsv = ctx.run_dir / "findings_auto.tsv"
            findings_md = ctx.run_dir / "findings_auto.md"
            report_md = ctx.run_dir / "report.md"
            report_html = ctx.run_dir / "report.html"

            self.assertTrue(findings_tsv.is_file(), "findings_auto.tsv not generated")
            self.assertTrue(findings_md.is_file(), "findings_auto.md not generated")
            self.assertTrue(report_md.is_file(), "report.md not generated")
            self.assertTrue(report_html.is_file(), "report.html not generated")

            tsv_text = findings_tsv.read_text(encoding="utf-8")
            html_text = report_html.read_text(encoding="utf-8")
            md_text = report_md.read_text(encoding="utf-8")

            # Check expected triage finding keys
            self.assertIn("cve-kev:", tsv_text, "Missing cve-kev finding")
            self.assertIn("routeros:", tsv_text, "Missing routeros finding")
            self.assertIn("apache:", tsv_text, "Missing apache finding")
            self.assertIn("nsg:", tsv_text, "Missing nsg finding")
            self.assertIn("gcp-fw:", tsv_text, "Missing gcp-fw finding")
            self.assertIn("aws-sg:sg-0123456789abcdef0", tsv_text, "Missing aws-sg finding in findings_auto.tsv")
            self.assertIn("az-storage-public:stsyncexports", tsv_text, "Missing azure posture finding in findings_auto.tsv")
            self.assertIn("m365-ca-no-mfa-all", tsv_text, "Missing saas posture finding in findings_auto.tsv")
            self.assertTrue(
                "exposed-api:" in tsv_text or "exposed-path:" in tsv_text,
                "Missing exposed-api or exposed-path finding",
            )

            # Check AWS and Posture findings in report.md and report.html
            self.assertIn("aws-sg:sg-0123456789abcdef0", md_text, "Missing aws-sg finding in report.md")
            self.assertIn("az-storage-public:stsyncexports", md_text, "Missing azure posture finding in report.md")
            self.assertIn("stsyncexports", md_text, "Missing posture resource in report.md")
            self.assertIn("m365-ca-no-mfa-all", md_text, "Missing saas posture finding in report.md")

            self.assertIn("aws-sg:sg-0123456789abcdef0", html_text, "Missing aws-sg finding in report.html")
            self.assertIn("az-storage-public:stsyncexports", html_text, "Missing azure posture finding in report.html")
            self.assertIn("stsyncexports", html_text, "Missing posture resource in report.html")
            self.assertIn("m365-ca-no-mfa-all", html_text, "Missing saas posture finding in report.html")

            # Check CLI terminal windows rendered in output
            self.assertIn("subfinder -d example.com -silent", html_text)
            self.assertTrue(
                "terminal" in html_text.lower() or "cli" in html_text.lower() or "code" in html_text.lower(),
                "CLI terminal windows not rendered in HTML report",
            )
            self.assertIn("subfinder", md_text)

    def test_5_contoso_samples_and_no_legacy_brand(self) -> None:
        """Verify sample Contoso reports exist, are non-empty, and repository is free of references to the former brand."""
        contoso_md = REPO_ROOT / "samples" / "contoso_report.md"
        contoso_html = REPO_ROOT / "samples" / "contoso_report.html"

        self.assertTrue(contoso_md.is_file(), f"Sample Markdown report missing: {contoso_md}")
        self.assertGreater(contoso_md.stat().st_size, 1000, "Sample Markdown report is too small or empty")

        self.assertTrue(contoso_html.is_file(), f"Sample HTML report missing: {contoso_html}")
        self.assertGreater(contoso_html.stat().st_size, 5000, "Sample HTML report is too small or empty")

        # Scan repository for any case-insensitive reference to the forbidden brand name
        forbidden = "".join(["m", "i", "m", "a", "c", "o", "m"])
        violations: list[str] = []

        ignore_dirs = {".git", ".system_generated", "__pycache__", ".pytest_cache", ".venv", "venv"}

        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    if forbidden in content.lower():
                        violations.append(str(fpath.relative_to(REPO_ROOT)))
                except Exception:
                    pass

        self.assertEqual(
            violations,
            [],
            f"Found forbidden brand references to '{forbidden}' in: {violations}",
        )

    def test_6_phase_s_posture(self) -> None:
        """Test phaseS when disabled vs enabled with missing credentials."""
        from unittest.mock import patch
        from recon.phases.saas import phaseS

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scope = ScopeConfig(
                path=root / "scopes" / "synthetic.toml",
                name="synthetic",
                engagement="Synthetic Attack Surface Assessment",
                domains=["example.com"],
                saas_posture=False,
            )
            ctx = RunContext(
                root=root,
                scope=scope,
                run_date="2026-11-03",
                phases=["S"],
                saas_posture=False,
            )
            ctx.ensure_dirs()
            dm = DependencyManager(use_docker=False, run_dir=ctx.run_dir)
            log = Logger()

            # 1. When posture is disabled, it returns immediately without network calls
            with patch("urllib.request.urlopen") as mock_url:
                phaseS(ctx, dm, log)
                mock_url.assert_not_called()
            posture_tsv = ctx.saas_dir / "posture_findings.tsv"
            self.assertFalse(posture_tsv.is_file(), "posture_findings.tsv should not exist when SaaS posture is disabled")

            # 2. When posture is enabled but all provider credentials/tools are missing,
            # it writes an empty posture file or none and does not raise
            ctx_enabled = RunContext(
                root=root,
                scope=scope,
                run_date="2026-11-03",
                phases=["S"],
                saas_posture=True,
            )
            ctx_enabled.ensure_dirs()
            clean_env = {
                k: v for k, v in os.environ.items()
                if not any(k.startswith(p) for p in ("M365_", "GITHUB_", "GAM_"))
            }
            clean_env.pop("GITHUB_ORG", None)
            clean_env.pop("GAM_PATH", None)

            with patch.dict(os.environ, clean_env, clear=True):
                phaseS(ctx_enabled, dm, log)

            posture_tsv_enabled = ctx_enabled.saas_dir / "posture_findings.tsv"
            if posture_tsv_enabled.is_file():
                self.assertEqual(posture_tsv_enabled.read_text(encoding="utf-8").strip(), "")


if __name__ == "__main__":
    unittest.main()
