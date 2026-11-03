"""Unit tests for HaveIBeenPwned and threat intelligence breach auditing."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon.config import RunContext, ScopeConfig
from recon.deps import DependencyManager
from recon.phases.osint import (
    check_pwned_password,
    run_email_enumeration,
    run_hibp_breaches,
)
from recon.phases.triage import phaseT
from recon.runner import Logger


class TestOsintBreaches(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.scope_file = self.root / "test.toml"
        self.scope_file.write_text(
            """
[engagement]
engagement = "Test Engagement"
[targets]
domains = ["contoso.com"]
""",
            encoding="utf-8",
        )
        self.scope = ScopeConfig.load(self.scope_file)
        self.ctx = RunContext(
            root=self.root,
            scope=self.scope,
            run_date="2026-11-03",
            phases=["9", "T"],
            hibp_api_key="test_dummy_key",
        )
        self.ctx.ensure_dirs()
        self.log = Logger()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @patch("recon.phases.osint.time.sleep")
    @patch("recon.phases.osint.http_get_json")
    def test_no_api_key_uses_public_catalogue_and_xposedornot(
        self, mock_http: MagicMock, _sleep: MagicMock
    ) -> None:
        self.ctx.hibp_api_key = ""

        def fake(url, headers=None, timeout=0):
            self.assertNotIn("hibp-api-key", headers or {})
            if "breaches?domain=" in url:
                return 200, [{"Name": "ContosoLeak", "Title": "Contoso Leak", "BreachDate": "2023-04-18",
                              "PwnCount": 10, "DataClasses": ["Email addresses"]}]
            if "xposedornot" in url:
                return 200, {"breaches": [["ContosoLeak"]]}
            if url.endswith("/breach/ContosoLeak"):
                return 200, {"Title": "Contoso Leak", "BreachDate": "2023-04-18", "PwnCount": 10,
                             "DataClasses": ["Email addresses", "Passwords"]}
            return 404, None

        mock_http.side_effect = fake
        with patch.dict("os.environ", {}, clear=True):
            dom_b, acc_b = run_hibp_breaches(self.ctx, self.log, emails=["jdoe@contoso.com"])
        self.assertEqual(len(dom_b), 1)
        self.assertEqual(len(acc_b), 1)
        self.assertIn("Passwords", acc_b[0]["data_classes"])
        self.assertFalse(any("breachedaccount" in c.args[0] for c in mock_http.call_args_list))

    @patch("recon.phases.osint.http_get_json")
    def test_hibp_successful_breaches_found(self, mock_http: MagicMock) -> None:
        mock_http.return_value = (
            200,
            [
                {
                    "Name": "ContosoDataIncident",
                    "Title": "Contoso Incident 2024",
                    "BreachDate": "2024-05-12",
                    "PwnCount": 54200,
                    "DataClasses": ["Email addresses", "Passwords", "Job titles"],
                    "IsVerified": True,
                    "IsSensitive": False,
                }
            ],
        )

        dom_b, acc_b = run_hibp_breaches(self.ctx, self.log, emails=["admin@contoso.com"])
        self.assertEqual(len(dom_b), 1)
        self.assertEqual(dom_b[0]["name"], "ContosoDataIncident")
        self.assertEqual(dom_b[0]["domain"], "contoso.com")

        self.assertEqual(len(acc_b), 1)
        self.assertEqual(acc_b[0]["email"], "admin@contoso.com")
        self.assertEqual(acc_b[0]["name"], "ContosoDataIncident")

        # Verify raw json and tsv files
        tsv_path = self.ctx.osint_dir / "hibp_breaches.tsv"
        self.assertTrue(tsv_path.is_file())
        tsv_content = tsv_path.read_text(encoding="utf-8")
        self.assertIn("ContosoDataIncident", tsv_content)
        self.assertIn("Passwords", tsv_content)

        acc_tsv = self.ctx.osint_dir / "hibp_account_breaches.tsv"
        self.assertTrue(acc_tsv.is_file())
        acc_content = acc_tsv.read_text(encoding="utf-8")
        self.assertIn("admin@contoso.com", acc_content)

        # Verify triage imports findings with high severity due to passwords
        dm = DependencyManager()
        phaseT(self.ctx, dm, self.log)

        findings_auto = self.ctx.run_dir / "findings_auto.tsv"
        self.assertTrue(findings_auto.is_file())
        fa_text = findings_auto.read_text(encoding="utf-8")
        self.assertIn("hibp:contoso.com:ContosoDataIncident", fa_text)
        self.assertIn("hibp-account:admin@contoso.com:ContosoDataIncident", fa_text)
        self.assertIn("high", fa_text)

    @patch("recon.phases.osint.http_get_json")
    def test_hibp_404_no_breaches(self, mock_http: MagicMock) -> None:
        mock_http.return_value = (404, None)
        dom_b, acc_b = run_hibp_breaches(self.ctx, self.log, emails=["clean@contoso.com"])
        self.assertEqual(len(dom_b), 0)
        self.assertEqual(len(acc_b), 0)
        tsv_path = self.ctx.osint_dir / "hibp_breaches.tsv"
        self.assertTrue(tsv_path.is_file())
        self.assertEqual(len(tsv_path.read_text().splitlines()), 1)  # only header

    @patch("recon.phases.osint.http_get")
    def test_check_pwned_password_k_anonymity(self, mock_http: MagicMock) -> None:
        # Mocking sha1("testpass") -> 200DEB8F6174...
        # prefix: 200DE, suffix: B8F6174...
        import hashlib
        h = hashlib.sha1(b"testpass").hexdigest().upper()
        suffix = h[5:]
        mock_http.return_value = MagicMock(
            status=200,
            body=f"0018A45C4D1DEF81644B54AB7F969B88D65:1\n{suffix}:42\n",
        )
        count = check_pwned_password("testpass")
        self.assertEqual(count, 42)

    @patch("recon.phases.osint.http_get")
    def test_email_enumeration_passive_sources(self, mock_http: MagicMock) -> None:
        mock_http.return_value = MagicMock(
            status=200,
            body="pub 4096R/12345678 2024-01-01 John Doe <john.doe@contoso.com>\n",
        )
        # Write mock WHOIS text
        (self.ctx.raw_dir / "whois_contoso.com.txt").write_text(
            "Registrant Name: Jane Admin\nRegistrant Email: security-admin@contoso.com\n",
            encoding="utf-8",
        )
        dm = DependencyManager()
        emails = run_email_enumeration(self.ctx, dm, self.log)
        self.assertIn("john.doe@contoso.com", emails)
        self.assertIn("security-admin@contoso.com", emails)
        self.assertTrue((self.ctx.osint_dir / "emails.txt").is_file())
        self.assertTrue((self.ctx.osint_dir / "emails.tsv").is_file())


if __name__ == "__main__":
    unittest.main()
