"""Unit tests for Google Workspace posture module (recon.saas.google).

Pure Python 3 standard library unittest implementation with zero external dependencies.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from recon.config import RunContext, ScopeConfig
from recon.runner import CmdResult, Logger
import recon.saas.google as google_posture


class TestSaasGooglePosture(unittest.TestCase):
    """Test suite for Google Workspace posture checks."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.scope = ScopeConfig(
            path=self.root / "scope.toml",
            name="test-org",
            engagement="audit",
            domains=["example.com"],
        )
        self.ctx = RunContext(
            root=self.root,
            scope=self.scope,
            run_date="2026-11-03",
            phases=["S"],
        )
        self.ctx.ensure_dirs()
        self.out_dir = self.ctx.run_dir / "saas" / "google"
        self.log = Logger()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("recon.saas.google.have", return_value=False)
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_gam_returns_empty(self, mock_have: MagicMock) -> None:
        """When GAM binary is not found, posture run logs warning and returns []."""
        with patch.object(self.log, "warn") as mock_warn:
            findings = google_posture.run(self.ctx, self.log, self.out_dir)

        self.assertEqual(findings, [])
        mock_warn.assert_called_once_with(
            "Google Workspace posture skipped: GAM not found or not authenticated (set GAM_PATH, super admin required)"
        )

    @patch("recon.saas.google.have", return_value=True)
    @patch("recon.saas.google.run_cmd")
    def test_unauthenticated_gam_returns_empty(
        self, mock_run_cmd: MagicMock, mock_have: MagicMock
    ) -> None:
        """When GAM auth check fails (non-zero exit code), posture run logs warning and returns []."""
        mock_run_cmd.return_value = CmdResult(
            args=["gam", "info", "domain"],
            returncode=1,
            stdout="",
            stderr="ERROR: 401 Unauthorized - Admin SDK not authorized",
        )

        with patch.object(self.log, "warn") as mock_warn:
            findings = google_posture.run(self.ctx, self.log, self.out_dir)

        self.assertEqual(findings, [])
        mock_warn.assert_called_once_with(
            "Google Workspace posture skipped: GAM not found or not authenticated (set GAM_PATH, super admin required)"
        )

    @patch("recon.saas.google.have", return_value=True)
    @patch("recon.saas.google.run_cmd")
    def test_full_posture_audit(
        self, mock_run_cmd: MagicMock, mock_have: MagicMock
    ) -> None:
        """Test full audit flow evaluating users, admins, groups, devices, and OAuth tokens."""
        canned_users = (
            "Getting all Users in domain...\r\n"
            "Got 8 Users...\r\n"
            "primaryEmail,isAdmin,isDelegatedAdmin,isEnforcedIn2Sv,isEnrolledIn2Sv,suspended,orgUnitPath,lastLoginTime,creationTime\r\n"
            "superadmin1@example.com,True,False,True,True,False,/,2026-11-01T10:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
            "superadmin2@example.com,True,False,True,True,False,/,2026-11-01T10:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
            "admin_no_2fa@example.com,True,False,False,False,False,/,2026-11-01T10:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
            "suspended_admin@example.com,True,True,False,False,True,/suspended,2025-01-01T00:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
            "grace_user@example.com,False,False,True,False,False,/,2026-11-02T10:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
            "never_user@example.com,False,False,False,True,False,/sales,Never,2024-01-01T00:00:00.000Z\r\n"
            "inactive_user@example.com,False,False,False,True,False,/sales,2025-01-01T00:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
            "archived_active@example.com,False,False,False,True,False,/archived/users,2026-11-01T10:00:00.000Z,2024-01-01T00:00:00.000Z\r\n"
        )

        canned_admins = (
            "roleAssignmentId,roleId,role,assignedTo,user,group,serviceAccount\r\n"
            "1,1001,_SEED_ADMIN_ROLE,superadmin1@example.com,superadmin1@example.com,,\r\n"
            "2,1001,_SEED_ADMIN_ROLE,superadmin2@example.com,superadmin2@example.com,,\r\n"
            "3,1001,_SEED_ADMIN_ROLE,admin_no_2fa@example.com,admin_no_2fa@example.com,,\r\n"
            "4,1001,_SEED_ADMIN_ROLE,suspended_admin@example.com,suspended_admin@example.com,,\r\n"
            "5,1001,_SEED_ADMIN_ROLE,sa_breakglass@example.com,sa_breakglass@example.com,,\r\n"
            "6,1002,User Management Admin,suspended_admin@example.com,suspended_admin@example.com,,\r\n"
        )

        canned_domains = (
            "domainName,isPrimary,verified\r\n"
            "example.com,True,True\r\n"
            "example.org,False,True\r\n"
        )

        canned_groups = (
            "email,name,whocanjoin,whocanviewmembership,whocanviewgroup,allowexternalmembers,whocanpostmessage\r\n"
            "all-staff@example.com,All Staff,ALL_IN_DOMAIN_CAN_JOIN,ALL_IN_DOMAIN_CAN_VIEW,ALL_IN_DOMAIN_CAN_VIEW,True,ANYONE_CAN_POST\r\n"
            "security@example.com,Security,INVITED_CAN_JOIN,ALL_MANAGERS_CAN_VIEW,ALL_MANAGERS_CAN_VIEW,False,ALL_IN_DOMAIN_CAN_POST\r\n"
        )

        canned_group_members = (
            "group,type,role,id,status,email\r\n"
            "all-staff@example.com,USER,MEMBER,1,ACTIVE,alice@example.com\r\n"
            "all-staff@example.com,USER,MEMBER,2,ACTIVE,external_vendor@external.net\r\n"
            "security@example.com,USER,MEMBER,3,ACTIVE,bob@example.com\r\n"
        )

        canned_mobile = (
            "email,model,os,type,status,deviceCompromisedStatus\r\n"
            "compromised@example.com,Pixel 7,Android 14,ANDROID,APPROVED,Compromised (Rooted)\r\n"
            "wiped@example.com,iPhone 13,iOS 17,IOS,ACCOUNT_WIPED,No compromise detected\r\n"
            "pending@example.com,Galaxy S22,Android 13,ANDROID,PENDING,No compromise detected\r\n"
            "normal@example.com,iPhone 15,iOS 17,IOS,APPROVED,No compromise detected\r\n"
        )

        canned_cros = (
            "serialNumber,osVersion,lastSync,orgUnitPath,status\r\n"
            "CROS-STALE-1,120.0,2025-01-01T12:00:00.000Z,/kiosks,ACTIVE\r\n"
            "CROS-OK-2,128.0,2026-11-01T12:00:00.000Z,/workstations,ACTIVE\r\n"
        )

        canned_tokens = (
            "User,clientId,displayText,scopes\r\n"
            "alice@example.com,client-1,Legacy Backup Tool,https://mail.google.com/ https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/drive\r\n"
            "bob@example.com,client-2,Calendar Sync,https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/contacts\r\n"
        )

        canned_asps = (
            "User,name,clientId,creationTime\r\n"
            "alice@example.com,Legacy Mail Client,101,2025-01-01T00:00:00.000Z\r\n"
        )

        def mock_cmd_side_effect(args: list[str], **kwargs: object) -> CmdResult:
            cmd = " ".join(args)
            if "info domain" in cmd:
                return CmdResult(args=args, returncode=0, stdout="Domain: example.com\nStatus: Verified", stderr="")
            if "print users" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_users, stderr="")
            if "print admins" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_admins, stderr="")
            if "print domains" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_domains, stderr="")
            if "print groups" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_groups, stderr="")
            if "print group-members" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_group_members, stderr="")
            if "print mobile" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_mobile, stderr="")
            if "print cros" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_cros, stderr="")
            if "print tokens" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_tokens, stderr="")
            if "all users print asps" in cmd:
                return CmdResult(args=args, returncode=0, stdout=canned_asps, stderr="")
            return CmdResult(args=args, returncode=0, stdout="", stderr="")

        mock_run_cmd.side_effect = mock_cmd_side_effect

        findings = google_posture.run(self.ctx, self.log, self.out_dir)

        # Build index of findings by key
        by_key: dict[str, list[google_posture.Finding]] = {}
        for f in findings:
            by_key.setdefault(f.key, []).append(f)

        # 1. Admin without 2FA (CRITICAL)
        self.assertIn("gws-admin-no-2fa", by_key)
        admin_no_2fa_f = [f for f in by_key["gws-admin-no-2fa"] if f.resource == "admin_no_2fa@example.com"]
        self.assertEqual(len(admin_no_2fa_f), 1)
        self.assertEqual(admin_no_2fa_f[0].severity, "critical")
        self.assertEqual(admin_no_2fa_f[0].iso, "A.8.2, A.8.5")

        # 2. Super admin count (>4 super admins = HIGH)
        self.assertIn("gws-super-admin-count", by_key)
        sa_f = by_key["gws-super-admin-count"][0]
        self.assertEqual(sa_f.severity, "high")
        self.assertIn("Excessive super admin accounts (5)", sa_f.title)
        self.assertEqual(sa_f.iso, "A.5.15, A.8.2")

        # 3. Suspended admin checks (HIGH)
        self.assertIn("gws-admin-suspended-super", by_key)
        susp_super = by_key["gws-admin-suspended-super"][0]
        self.assertEqual(susp_super.resource, "suspended_admin@example.com")
        self.assertEqual(susp_super.severity, "high")
        self.assertEqual(susp_super.iso, "A.8.2, A.5.15")

        self.assertIn("gws-admin-suspended-delegated", by_key)
        susp_del = by_key["gws-admin-suspended-delegated"][0]
        self.assertEqual(susp_del.resource, "suspended_admin@example.com")
        self.assertEqual(susp_del.severity, "high")

        # 4. Grace period (HIGH)
        self.assertIn("gws-2fa-grace-period", by_key)
        grace_f = by_key["gws-2fa-grace-period"][0]
        self.assertEqual(grace_f.resource, "grace_user@example.com")
        self.assertEqual(grace_f.severity, "high")
        self.assertEqual(grace_f.iso, "A.8.5")

        # 5. Stale accounts: Never logged in & Inactive >90 days (MEDIUM)
        self.assertIn("gws-account-never-logged-in", by_key)
        never_f = by_key["gws-account-never-logged-in"][0]
        self.assertEqual(never_f.resource, "never_user@example.com")
        self.assertEqual(never_f.severity, "medium")
        self.assertEqual(never_f.iso, "A.5.18")

        self.assertIn("gws-account-inactive-90d", by_key)
        inactive_f = by_key["gws-account-inactive-90d"][0]
        self.assertEqual(inactive_f.resource, "inactive_user@example.com")
        self.assertEqual(inactive_f.severity, "medium")

        # 6. Active accounts in /archived OU (HIGH)
        self.assertIn("gws-archived-ou-active-account", by_key)
        arch_f = by_key["gws-archived-ou-active-account"][0]
        self.assertEqual(arch_f.resource, "archived_active@example.com")
        self.assertEqual(arch_f.severity, "high")
        self.assertEqual(arch_f.iso, "A.5.11, A.5.18")

        # 7. 2FA compliance summary (INFO)
        self.assertIn("gws-2fa-compliance", by_key)
        comp_f = by_key["gws-2fa-compliance"][0]
        self.assertEqual(comp_f.severity, "info")
        self.assertEqual(comp_f.iso, "A.8.5")

        # 8. Groups security checks
        self.assertIn("gws-group-unrestricted-join", by_key)
        self.assertEqual(by_key["gws-group-unrestricted-join"][0].severity, "high")
        self.assertEqual(by_key["gws-group-unrestricted-join"][0].iso, "A.5.15")

        self.assertIn("gws-group-broad-visibility", by_key)
        self.assertEqual(by_key["gws-group-broad-visibility"][0].severity, "medium")

        self.assertIn("gws-group-allow-external", by_key)
        self.assertEqual(by_key["gws-group-allow-external"][0].severity, "medium")

        self.assertIn("gws-group-anyone-can-post", by_key)
        self.assertEqual(by_key["gws-group-anyone-can-post"][0].severity, "medium")
        self.assertEqual(by_key["gws-group-anyone-can-post"][0].iso, "A.5.14, A.5.19")

        # 9. External group members (MEDIUM)
        self.assertIn("gws-group-external-members", by_key)
        ext_f = by_key["gws-group-external-members"][0]
        self.assertEqual(ext_f.severity, "medium")
        self.assertIn("external_vendor@external.net", ext_f.detail)

        # 10. Mobile devices: Compromised (HIGH), Wiped (MEDIUM), Pending (LOW), Summary (INFO)
        self.assertIn("gws-device-mobile-compromised", by_key)
        self.assertEqual(by_key["gws-device-mobile-compromised"][0].severity, "high")
        self.assertEqual(by_key["gws-device-mobile-compromised"][0].iso, "A.8.1")

        self.assertIn("gws-device-mobile-wiped", by_key)
        self.assertEqual(by_key["gws-device-mobile-wiped"][0].severity, "medium")

        self.assertIn("gws-device-mobile-pending", by_key)
        self.assertEqual(by_key["gws-device-mobile-pending"][0].severity, "low")

        self.assertIn("gws-device-mobile-summary", by_key)
        self.assertEqual(by_key["gws-device-mobile-summary"][0].severity, "info")

        # 11. Chrome OS devices: Stale (LOW) and Summary (INFO)
        self.assertIn("gws-device-cros-stale-90d", by_key)
        self.assertEqual(by_key["gws-device-cros-stale-90d"][0].severity, "low")
        self.assertEqual(by_key["gws-device-cros-stale-90d"][0].iso, "A.8.1")

        self.assertIn("gws-device-cros-summary", by_key)
        self.assertEqual(by_key["gws-device-cros-summary"][0].severity, "info")

        # 12. OAuth apps: Admin SDK (HIGH), Gmail (LOW), Drive (LOW), Calendar (LOW), Contacts (LOW)
        self.assertIn("gws-oauth-admin-sdk", by_key)
        self.assertEqual(by_key["gws-oauth-admin-sdk"][0].severity, "high")
        self.assertEqual(by_key["gws-oauth-admin-sdk"][0].iso, "A.5.23, A.8.2")

        self.assertIn("gws-oauth-gmail-full", by_key)
        self.assertEqual(by_key["gws-oauth-gmail-full"][0].severity, "low")

        self.assertIn("gws-oauth-drive-full", by_key)
        self.assertEqual(by_key["gws-oauth-drive-full"][0].severity, "low")

        self.assertIn("gws-oauth-calendar-full", by_key)
        self.assertEqual(by_key["gws-oauth-calendar-full"][0].severity, "low")

        self.assertIn("gws-oauth-contacts", by_key)
        self.assertEqual(by_key["gws-oauth-contacts"][0].severity, "low")

        # 13. App-specific passwords in use (MEDIUM)
        self.assertIn("gws-asp-in-use", by_key)
        self.assertEqual(by_key["gws-asp-in-use"][0].severity, "medium")
        self.assertEqual(by_key["gws-asp-in-use"][0].iso, "A.8.5")

        # Verify evidence files saved under out_dir / raw
        raw_dir = self.out_dir / "raw"
        self.assertTrue((raw_dir / "users.csv").is_file())
        self.assertTrue((raw_dir / "admins.csv").is_file())
        self.assertTrue((raw_dir / "domains.csv").is_file())
        self.assertTrue((raw_dir / "groups.csv").is_file())
        self.assertTrue((raw_dir / "group_members.csv").is_file())
        self.assertTrue((raw_dir / "mobile_devices.csv").is_file())
        self.assertTrue((raw_dir / "chrome_devices.csv").is_file())
        self.assertTrue((raw_dir / "oauth_tokens.csv").is_file())
        self.assertTrue((raw_dir / "app_specific_passwords.csv").is_file())

        # Verify virtual command log evidence recorded under console_dir
        self.assertTrue((self.ctx.console_dir / "S.log").is_file())
        self.assertTrue((self.ctx.console_dir / "commands.jsonl").is_file())

    @patch("recon.saas.google.have", return_value=True)
    @patch("recon.saas.google.run_cmd")
    def test_partial_command_failure_continues(
        self, mock_run_cmd: MagicMock, mock_have: MagicMock
    ) -> None:
        """When an individual export fails, audit warns and continues without crashing."""
        def mock_cmd_side_effect(args: list[str], **kwargs: object) -> CmdResult:
            cmd = " ".join(args)
            if "info domain" in cmd:
                return CmdResult(args=args, returncode=0, stdout="Domain info", stderr="")
            if "print users" in cmd:
                return CmdResult(args=args, returncode=1, stdout="", stderr="API quota exceeded")
            if "print admins" in cmd:
                return CmdResult(
                    args=args,
                    returncode=0,
                    stdout=(
                        "role,user\n"
                        "_SEED_ADMIN_ROLE,admin@example.com\n"
                    ),
                    stderr="",
                )
            return CmdResult(args=args, returncode=0, stdout="", stderr="")

        mock_run_cmd.side_effect = mock_cmd_side_effect

        with patch.object(self.log, "warn") as mock_warn:
            findings = google_posture.run(self.ctx, self.log, self.out_dir)

        # Check warning logged for failed users command
        failed_warnings = [
            call.args[0] for call in mock_warn.call_args_list
            if "checks depending on it skipped" in call.args[0]
        ]
        self.assertEqual(len(failed_warnings), 1)
        self.assertIn("print users", failed_warnings[0])

        # Admin count check should still have executed
        admin_findings = [f for f in findings if f.key == "gws-super-admin-count"]
        self.assertEqual(len(admin_findings), 1)
        self.assertEqual(admin_findings[0].severity, "medium")  # 1 super admin

    @patch("recon.saas.google.run_cmd")
    def test_custom_gam_path_env(self, mock_run_cmd: MagicMock) -> None:
        """GAM_PATH env variable takes precedence over PATH."""
        mock_run_cmd.return_value = CmdResult(
            args=["/custom/bin/gam", "info", "domain"],
            returncode=1,
            stdout="",
            stderr="Auth failed",
        )

        with patch.dict(os.environ, {"GAM_PATH": "/custom/bin/gam"}):
            with patch.object(self.log, "warn") as mock_warn:
                findings = google_posture.run(self.ctx, self.log, self.out_dir)

        self.assertEqual(findings, [])
        mock_warn.assert_called_once_with(
            "Google Workspace posture skipped: GAM not found or not authenticated (set GAM_PATH, super admin required)"
        )
        self.assertEqual(mock_run_cmd.call_args[0][0][0], "/custom/bin/gam")

    @patch("recon.saas.google.have", return_value=True)
    @patch("recon.saas.google.run_cmd")
    def test_healthy_tenant_clean_findings(
        self, mock_run_cmd: MagicMock, mock_have: MagicMock
    ) -> None:
        """Tenant with good posture (2 super admins, no ext members, all groups restricted)."""
        def mock_cmd_side_effect(args: list[str], **kwargs: object) -> CmdResult:
            cmd = " ".join(args)
            if "info domain" in cmd:
                return CmdResult(args=args, returncode=0, stdout="Domain info", stderr="")
            if "print users" in cmd:
                return CmdResult(
                    args=args,
                    returncode=0,
                    stdout=(
                        "primaryEmail,isAdmin,isDelegatedAdmin,isEnforcedIn2Sv,isEnrolledIn2Sv,suspended,orgUnitPath,lastLoginTime,creationTime\n"
                        "sa1@example.com,True,False,True,True,False,/,2026-11-01T10:00:00Z,2024-01-01T00:00:00Z\n"
                        "sa2@example.com,True,False,True,True,False,/,2026-11-01T10:00:00Z,2024-01-01T00:00:00Z\n"
                    ),
                    stderr="",
                )
            if "print admins" in cmd:
                return CmdResult(
                    args=args,
                    returncode=0,
                    stdout=(
                        "role,user\n"
                        "_SEED_ADMIN_ROLE,sa1@example.com\n"
                        "_SEED_ADMIN_ROLE,sa2@example.com\n"
                    ),
                    stderr="",
                )
            if "print domains" in cmd:
                return CmdResult(args=args, returncode=0, stdout="domainName\nexample.com\n", stderr="")
            if "print groups" in cmd:
                return CmdResult(
                    args=args,
                    returncode=0,
                    stdout=(
                        "email,name,whocanjoin,whocanviewmembership,whocanviewgroup,allowexternalmembers,whocanpostmessage\n"
                        "team@example.com,Team,INVITED_CAN_JOIN,ALL_MEMBERS_CAN_VIEW,ALL_MEMBERS_CAN_VIEW,False,ALL_IN_DOMAIN_CAN_POST\n"
                    ),
                    stderr="",
                )
            if "print group-members" in cmd:
                return CmdResult(
                    args=args,
                    returncode=0,
                    stdout=(
                        "group,type,role,id,status,email\n"
                        "team@example.com,USER,MEMBER,1,ACTIVE,sa1@example.com\n"
                    ),
                    stderr="",
                )
            return CmdResult(args=args, returncode=0, stdout="", stderr="")

        mock_run_cmd.side_effect = mock_cmd_side_effect

        findings = google_posture.run(self.ctx, self.log, self.out_dir)

        # 2 super admins -> info severity
        sa_f = [f for f in findings if f.key == "gws-super-admin-count"]
        self.assertEqual(len(sa_f), 1)
        self.assertEqual(sa_f[0].severity, "info")

        # 0 unrestricted self-join groups -> info finding
        sj_f = [f for f in findings if f.key == "gws-group-unrestricted-join"]
        self.assertEqual(len(sj_f), 1)
        self.assertEqual(sj_f[0].severity, "info")

        # 0 external members -> info finding
        em_f = [f for f in findings if f.key == "gws-group-external-members"]
        self.assertEqual(len(em_f), 1)
        self.assertEqual(em_f[0].severity, "info")

        # 100% 2FA compliance -> info finding
        comp_f = [f for f in findings if f.key == "gws-2fa-compliance"]
        self.assertEqual(len(comp_f), 1)
        self.assertIn("100%", comp_f[0].title)

        # Ensure all findings produce valid TSV rows
        for f in findings:
            row = f.row()
            self.assertEqual(len(row), 6)
            self.assertIn(row[0], ("critical", "high", "medium", "low", "info"))
            self.assertTrue(row[1].startswith("gws-"))
            self.assertEqual(row[2], "Workspace")


if __name__ == "__main__":
    unittest.main()
