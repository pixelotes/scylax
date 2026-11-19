"""Unit tests for Microsoft 365 / Entra ID SaaS posture audit module (recon.saas.m365)."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from recon.config import RunContext, ScopeConfig
from recon.runner import Logger
from recon.saas.m365 import run


class TestSaasM365Posture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)
        self.scope = ScopeConfig(
            path=self.root_path / "scope.toml",
            name="test-m365-scope",
            engagement="audit",
        )
        self.ctx = RunContext(
            root=self.root_path,
            scope=self.scope,
            run_date="2026-11-03",
            phases=["S"],
        )
        self.ctx.ensure_dirs()
        self.out_dir = self.ctx.run_dir / "saas" / "m365"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.gaps_file = self.ctx.run_dir / "gaps.txt"
        self.log = Logger(gaps_file=self.gaps_file)

        self.mock_env = {
            "M365_TENANT_ID": "11111111-2222-3333-4444-555555555555",
            "M365_CLIENT_ID": "66666666-7777-8888-9999-000000000000",
            "M365_CLIENT_SECRET": "SuperSecretClientKey123!",
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_missing_env_vars_returns_empty_without_network(self) -> None:
        """When credentials are not in environment, run() must log a warning and return [] immediately."""
        for missing_var in ("M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"):
            env = {k: v for k, v in self.mock_env.items() if k != missing_var}
            with patch.dict(os.environ, env, clear=True):
                with patch("recon.saas.m365.http_json") as mock_http:
                    with patch.object(self.log, "warn") as mock_warn:
                        findings = run(self.ctx, self.log, self.out_dir)
                        self.assertEqual(findings, [])
                        mock_http.assert_not_called()
                        mock_warn.assert_called_with(
                            "M365 posture skipped: set M365_TENANT_ID, M365_CLIENT_ID and M365_CLIENT_SECRET"
                        )

    @patch("recon.saas.m365.http_json")
    def test_auth_failure_returns_empty_without_secret_leak(self, mock_http: MagicMock) -> None:
        """When client credentials authentication fails, run() must log a warning without secrets and return []."""
        mock_http.return_value = (
            401,
            {"error": "invalid_client", "error_description": "Invalid client secret provided."},
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            with patch.object(self.log, "warn") as mock_warn:
                findings = run(self.ctx, self.log, self.out_dir)

        self.assertEqual(findings, [])
        mock_warn.assert_called_once()
        warn_msg = mock_warn.call_args[0][0]
        self.assertIn("M365 authentication failed: HTTP 401", warn_msg)
        self.assertNotIn(self.mock_env["M365_CLIENT_SECRET"], warn_msg)

    def _setup_canned_graph(
        self,
        *,
        sec_defaults_enabled: bool = False,
        ca_policies: list[dict] | None = None,
        users: list[dict] | None = None,
        mfa_reg: list[dict] | None = None,
        directory_roles: list[dict] | None = None,
        applications: list[dict] | None = None,
        oauth2_grants: list[dict] | None = None,
        risky_users: list[dict] | None = None,
        risk_detections: list[dict] | None = None,
        domains: list[dict] | None = None,
        endpoint_failures: dict[str, int] | None = None,
    ):
        """Build a mock handler dispatching predefined canned Graph API responses."""
        if endpoint_failures is None:
            endpoint_failures = {}

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        thirty_days_ago = (now_utc - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

        if ca_policies is None:
            ca_policies = []

        if users is None:
            users = [
                {
                    "id": "u1",
                    "displayName": "Global Admin User",
                    "userPrincipalName": "ga@example.com",
                    "accountEnabled": True,
                    "userType": "Member",
                    "signInActivity": {"lastSignInDateTime": thirty_days_ago},
                },
                {
                    "id": "u2",
                    "displayName": "Regular Member",
                    "userPrincipalName": "member@example.com",
                    "accountEnabled": True,
                    "userType": "Member",
                    "signInActivity": {"lastSignInDateTime": thirty_days_ago},
                },
            ]

        if mfa_reg is None:
            mfa_reg = [
                {
                    "userPrincipalName": "ga@example.com",
                    "isMfaRegistered": True,
                    "isSsprRegistered": True,
                },
                {
                    "userPrincipalName": "member@example.com",
                    "isMfaRegistered": True,
                    "isSsprRegistered": True,
                },
            ]

        if directory_roles is None:
            directory_roles = [
                {
                    "id": "r1",
                    "displayName": "Global Administrator",
                    "members": [{"id": "u1", "userPrincipalName": "ga@example.com"}],
                }
            ]

        if applications is None:
            applications = []

        if oauth2_grants is None:
            oauth2_grants = []

        if risky_users is None:
            risky_users = []

        if risk_detections is None:
            risk_detections = []

        if domains is None:
            domains = [{"id": "example.com", "isVerified": True}]

        def _handler(method: str, url: str, **kwargs) -> tuple[int, object]:
            if method == "POST" and "oauth2/v2.0/token" in url:
                return (200, {"access_token": "mock-token-xyz-12345", "expires_in": 3600})

            for failed_path, status in endpoint_failures.items():
                if failed_path in url:
                    return (status, {"error": {"code": "Error", "message": f"{failed_path} unavailable"}})

            if "/organization" in url:
                return (200, {"value": [{"id": "tenant-1", "displayName": "Example Org"}]})
            if "/domains" in url:
                return (200, {"value": domains})
            if "identitySecurityDefaultsEnforcementPolicy" in url:
                return (200, {"id": "sec-defaults", "isEnabled": sec_defaults_enabled})
            if "conditionalAccess/policies" in url:
                return (200, {"value": ca_policies})
            if "/users" in url:
                return (200, {"value": users})
            if "authenticationMethods/userRegistrationDetails" in url:
                return (200, {"value": mfa_reg})
            if "/directoryRoles" in url:
                return (200, {"value": directory_roles})
            if "/applications" in url:
                return (200, {"value": applications})
            if "/oauth2PermissionGrants" in url:
                return (200, {"value": oauth2_grants})
            if "identityProtection/riskyUsers" in url:
                return (200, {"value": risky_users})
            if "identityProtection/riskDetections" in url:
                return (200, {"value": risk_detections})

            return (404, {"error": {"message": "Not found"}})

        return _handler

    @patch("recon.saas.m365.http_json")
    def test_critical_secdefaults_off_no_ca(self, mock_http: MagicMock) -> None:
        """When security defaults is OFF and there are NO Conditional Access policies, flag CRITICAL."""
        mock_http.side_effect = self._setup_canned_graph(
            sec_defaults_enabled=False,
            ca_policies=[],
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-secdefaults-off-noca", keys)
        f = keys["m365-secdefaults-off-noca"]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.service, "ConditionalAccess")
        self.assertEqual(f.iso, "A.8.5, A.5.16")
        self.assertIn("passwords", f.detail)

    @patch("recon.saas.m365.http_json")
    def test_secdefaults_enabled(self, mock_http: MagicMock) -> None:
        """When security defaults is ON, flag INFO finding."""
        mock_http.side_effect = self._setup_canned_graph(
            sec_defaults_enabled=True,
            ca_policies=[],
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-secdefaults-enabled", keys)
        self.assertEqual(keys["m365-secdefaults-enabled"].severity, "info")

    @patch("recon.saas.m365.http_json")
    def test_secdefaults_off_with_ca_policies(self, mock_http: MagicMock) -> None:
        """When security defaults is OFF but CA policies exist, flag INFO finding."""
        mock_http.side_effect = self._setup_canned_graph(
            sec_defaults_enabled=False,
            ca_policies=[
                {
                    "id": "ca1",
                    "displayName": "Enforce MFA",
                    "state": "enabled",
                    "conditions": {"users": {"includeUsers": ["All"]}},
                    "grantControls": {"builtInControls": ["mfa"]},
                }
            ],
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-secdefaults-disabled-ca", keys)
        self.assertEqual(keys["m365-secdefaults-disabled-ca"].severity, "info")

    @patch("recon.saas.m365.http_json")
    def test_global_admin_counts(self, mock_http: MagicMock) -> None:
        """Test excessive (>5), single (=1), and normal (2-4) Global Admin counts."""
        # Case 1: Single Global Admin -> MEDIUM
        mock_http.side_effect = self._setup_canned_graph(
            directory_roles=[
                {
                    "displayName": "Global Administrator",
                    "members": [{"id": "u1", "userPrincipalName": "solo_admin@example.com"}],
                }
            ]
        )
        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)
        keys = {f.key: f for f in findings}
        self.assertIn("m365-ga-count", keys)
        self.assertEqual(keys["m365-ga-count"].severity, "medium")
        self.assertIn("single point of failure", keys["m365-ga-count"].title)

        # Case 2: Excessive (>5) Global Admins -> HIGH
        many_members = [
            {"id": f"u{i}", "userPrincipalName": f"admin{i}@example.com"}
            for i in range(1, 8)
        ]
        mock_http.side_effect = self._setup_canned_graph(
            directory_roles=[
                {
                    "displayName": "Global Administrator",
                    "members": many_members,
                }
            ]
        )
        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)
        keys = {f.key: f for f in findings}
        self.assertIn("m365-ga-count", keys)
        self.assertEqual(keys["m365-ga-count"].severity, "high")
        self.assertIn("Excessive Global Administrators (7)", keys["m365-ga-count"].title)

    @patch("recon.saas.m365.http_json")
    def test_admins_without_mfa(self, mock_http: MagicMock) -> None:
        """Test Global Administrator and Privileged role holders without MFA registration."""
        directory_roles = [
            {
                "displayName": "Global Administrator",
                "members": [
                    {"id": "u1", "userPrincipalName": "ga_with_mfa@example.com"},
                    {"id": "u2", "userPrincipalName": "ga_no_mfa@example.com"},
                ],
            },
            {
                "displayName": "User Administrator",
                "members": [
                    {"id": "u3", "userPrincipalName": "user_admin_no_mfa@example.com"},
                ],
            },
        ]
        mfa_reg = [
            {"userPrincipalName": "ga_with_mfa@example.com", "isMfaRegistered": True},
            {"userPrincipalName": "ga_no_mfa@example.com", "isMfaRegistered": False},
            {"userPrincipalName": "user_admin_no_mfa@example.com", "isMfaRegistered": False},
        ]

        mock_http.side_effect = self._setup_canned_graph(
            directory_roles=directory_roles,
            mfa_reg=mfa_reg,
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-ga-nomfa", keys)
        self.assertEqual(keys["m365-ga-nomfa"].severity, "critical")
        self.assertIn("ga_no_mfa@example.com", keys["m365-ga-nomfa"].detail)

        self.assertIn("m365-priv-nomfa", keys)
        self.assertEqual(keys["m365-priv-nomfa"].severity, "high")
        self.assertIn("user_admin_no_mfa@example.com", keys["m365-priv-nomfa"].detail)

    @patch("recon.saas.m365.http_json")
    def test_mfa_compliance_and_sspr(self, mock_http: MagicMock) -> None:
        """Test active user MFA compliance percentage and missing SSPR registration."""
        users = [
            {"id": "u1", "accountEnabled": True, "userPrincipalName": "u1@example.com", "userType": "Member"},
            {"id": "u2", "accountEnabled": True, "userPrincipalName": "u2@example.com", "userType": "Member"},
        ]
        mfa_reg = [
            {"userPrincipalName": "u1@example.com", "isMfaRegistered": True, "isSsprRegistered": True},
            {"userPrincipalName": "u2@example.com", "isMfaRegistered": False, "isSsprRegistered": False},
        ]

        mock_http.side_effect = self._setup_canned_graph(users=users, mfa_reg=mfa_reg)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-mfa-compliance", keys)
        self.assertEqual(keys["m365-mfa-compliance"].severity, "medium")
        self.assertIn("50% compliance", keys["m365-mfa-compliance"].title)

        self.assertIn("m365-sspr-not-registered", keys)
        self.assertEqual(keys["m365-sspr-not-registered"].severity, "low")

    @patch("recon.saas.m365.http_json")
    def test_guests_and_stale_accounts(self, mock_http: MagicMock) -> None:
        """Test guest user detection and accounts with no sign-in in >90 days."""
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        hundred_days_ago = (now_utc - datetime.timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%SZ")

        users = [
            {
                "id": "u1",
                "userPrincipalName": "guest1@external.com",
                "userType": "Guest",
                "accountEnabled": True,
            },
            {
                "id": "u2",
                "userPrincipalName": "stale_member@example.com",
                "userType": "Member",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": hundred_days_ago},
            },
            {
                "id": "u3",
                "userPrincipalName": "never_signed@example.com",
                "userType": "Member",
                "accountEnabled": True,
                "signInActivity": None,
            },
        ]

        mock_http.side_effect = self._setup_canned_graph(users=users)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-guests", keys)
        self.assertEqual(keys["m365-guests"].severity, "medium")
        self.assertIn("guest1@external.com", keys["m365-guests"].detail)

        self.assertIn("m365-stale-accounts", keys)
        self.assertEqual(keys["m365-stale-accounts"].severity, "medium")
        self.assertIn("2 account(s) (1 never signed in)", keys["m365-stale-accounts"].detail)

    @patch("recon.saas.m365.http_json")
    def test_conditional_access_policies_analysis(self, mock_http: MagicMock) -> None:
        """Test CA policy report-only mode, missing MFA for all users, exclusions, and legacy auth blocking."""
        ca_policies = [
            {
                "id": "ca1",
                "displayName": "Audit Policy",
                "state": "enabledForReportingButNotEnforced",
                "conditions": {"users": {"includeUsers": ["All"]}},
            },
            {
                "id": "ca2",
                "displayName": "MFA for Groups",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["Group1"],
                        "excludeUsers": ["ExcludedUser1", "ExcludedUser2"],
                    },
                    "clientAppTypes": ["browser"],
                },
                "grantControls": {"builtInControls": ["mfa"]},
            },
        ]

        mock_http.side_effect = self._setup_canned_graph(ca_policies=ca_policies)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-ca-summary", keys)
        self.assertEqual(keys["m365-ca-summary"].severity, "info")

        self.assertIn("m365-ca-reportonly", keys)
        self.assertEqual(keys["m365-ca-reportonly"].severity, "low")
        self.assertIn("Audit Policy", keys["m365-ca-reportonly"].detail)

        self.assertIn("m365-ca-no-mfa-all", keys)
        self.assertEqual(keys["m365-ca-no-mfa-all"].severity, "high")

        self.assertIn("m365-ca-exclusions", keys)
        self.assertEqual(keys["m365-ca-exclusions"].severity, "medium")
        self.assertIn("MFA for Groups: 2 excluded", keys["m365-ca-exclusions"].detail)

        self.assertIn("m365-ca-legacy-auth", keys)
        self.assertEqual(keys["m365-ca-legacy-auth"].severity, "high")

    @patch("recon.saas.m365.http_json")
    def test_legacy_auth_blocked_info(self, mock_http: MagicMock) -> None:
        """When legacy auth is blocked by a CA policy, flag INFO finding."""
        ca_policies = [
            {
                "id": "ca1",
                "displayName": "Block Legacy Auth",
                "state": "enabled",
                "conditions": {
                    "users": {"includeUsers": ["All"]},
                    "clientAppTypes": ["exchangeActiveSync", "other"],
                },
                "grantControls": {"builtInControls": ["block"]},
            }
        ]

        mock_http.side_effect = self._setup_canned_graph(ca_policies=ca_policies)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-ca-legacy-auth", keys)
        self.assertEqual(keys["m365-ca-legacy-auth"].severity, "info")

    @patch("recon.saas.m365.http_json")
    def test_oauth2_sensitive_grants(self, mock_http: MagicMock) -> None:
        """Test OAuth2 grants with AllPrincipals consent, Mail.ReadWrite/Send, and Files.ReadWrite."""
        oauth2_grants = [
            {
                "id": "g1",
                "consentType": "AllPrincipals",
                "scope": "User.Read Mail.ReadWrite",
            },
            {
                "id": "g2",
                "consentType": "Principal",
                "scope": "Files.ReadWrite Calendars.Read",
            },
        ]

        mock_http.side_effect = self._setup_canned_graph(oauth2_grants=oauth2_grants)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-oauth-allprincipals", keys)
        self.assertEqual(keys["m365-oauth-allprincipals"].severity, "info")

        self.assertIn("m365-oauth-sensitive-mail", keys)
        self.assertEqual(keys["m365-oauth-sensitive-mail"].severity, "medium")

        self.assertIn("m365-oauth-sensitive-files", keys)
        self.assertEqual(keys["m365-oauth-sensitive-files"].severity, "low")

    @patch("recon.saas.m365.http_json")
    def test_app_credentials_expiration(self, mock_http: MagicMock) -> None:
        """Test expired and soon-to-expire app password credentials."""
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        past_dt = (now_utc - datetime.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        soon_dt = (now_utc + datetime.timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_far = (now_utc + datetime.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

        applications = [
            {
                "id": "app1",
                "displayName": "Abandoned App",
                "passwordCredentials": [{"endDateTime": past_dt}],
            },
            {
                "id": "app2",
                "displayName": "Expiring App",
                "passwordCredentials": [{"endDateTime": soon_dt}],
            },
            {
                "id": "app3",
                "displayName": "Healthy App",
                "passwordCredentials": [{"endDateTime": future_far}],
            },
        ]

        mock_http.side_effect = self._setup_canned_graph(applications=applications)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-app-creds-expired", keys)
        self.assertEqual(keys["m365-app-creds-expired"].severity, "medium")
        self.assertIn("Abandoned App", keys["m365-app-creds-expired"].detail)

        self.assertIn("m365-app-creds-expiring", keys)
        self.assertEqual(keys["m365-app-creds-expiring"].severity, "low")
        self.assertIn("Expiring App", keys["m365-app-creds-expiring"].detail)

    @patch("recon.saas.m365.http_json")
    def test_risky_users_and_detections(self, mock_http: MagicMock) -> None:
        """Test risky user and risk detection alerting."""
        risky_users = [
            {"userPrincipalName": "compromised@example.com", "riskLevel": "high"},
            {"userPrincipalName": "suspicious@example.com", "riskLevel": "medium"},
        ]
        risk_detections = [
            {"riskEventType": "unfamiliarFeatures", "riskLevel": "high"},
            {"riskEventType": "unfamiliarFeatures", "riskLevel": "medium"},
            {"riskEventType": "anonymousIPAddress", "riskLevel": "medium"},
        ]

        mock_http.side_effect = self._setup_canned_graph(
            risky_users=risky_users,
            risk_detections=risk_detections,
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-risky-users", keys)
        self.assertEqual(keys["m365-risky-users"].severity, "high")
        self.assertIn("compromised@example.com", keys["m365-risky-users"].detail)

        self.assertIn("m365-risk-detections", keys)
        self.assertEqual(keys["m365-risk-detections"].severity, "medium")
        self.assertIn("unfamiliarFeatures (x2)", keys["m365-risk-detections"].detail)

    @patch("recon.saas.m365.http_json")
    def test_domains_and_unverified(self, mock_http: MagicMock) -> None:
        """Test registered domains summary and unverified domain detection."""
        domains = [
            {"id": "example.com", "isVerified": True},
            {"id": "staging.example.com", "isVerified": False},
        ]

        mock_http.side_effect = self._setup_canned_graph(domains=domains)

        with patch.dict(os.environ, self.mock_env, clear=True):
            findings = run(self.ctx, self.log, self.out_dir)

        keys = {f.key: f for f in findings}
        self.assertIn("m365-domains", keys)
        self.assertEqual(keys["m365-domains"].severity, "info")

        self.assertIn("m365-unverified-domains", keys)
        self.assertEqual(keys["m365-unverified-domains"].severity, "medium")
        self.assertIn("staging.example.com", keys["m365-unverified-domains"].detail)

    @patch("recon.saas.m365.http_json")
    def test_endpoint_unavailable_does_not_abort(self, mock_http: MagicMock) -> None:
        """When an endpoint returns 403 or 404, it must not abort the audit, but log warning."""
        mock_http.side_effect = self._setup_canned_graph(
            endpoint_failures={"riskyUsers": 403, "riskDetections": 404}
        )

        with patch.dict(os.environ, self.mock_env, clear=True):
            with patch.object(self.log, "warn") as mock_warn:
                findings = run(self.ctx, self.log, self.out_dir)

        # Audit finished and returned findings for available endpoints
        self.assertTrue(len(findings) > 0)
        keys = {f.key for f in findings}
        self.assertNotIn("m365-risky-users", keys)
        self.assertNotIn("m365-risk-detections", keys)

        # Verify warning was logged for unavailable endpoints
        warn_messages = [c[0][0] for c in mock_warn.call_args_list]
        self.assertTrue(
            any("M365: /identityProtection/riskyUsers unavailable (403)" in m for m in warn_messages)
        )
        self.assertTrue(
            any("M365: /identityProtection/riskDetections unavailable (404)" in m for m in warn_messages)
        )

    @patch("recon.saas.m365.http_json")
    def test_pagination_and_evidence_raw_saved(self, mock_http: MagicMock) -> None:
        """Test pagination via @odata.nextLink and verify raw JSON evidence files are written."""
        page1_users = [
            {"id": "u1", "userPrincipalName": "p1@example.com", "accountEnabled": True, "userType": "Member"}
        ]
        page2_users = [
            {"id": "u2", "userPrincipalName": "p2@example.com", "accountEnabled": True, "userType": "Member"}
        ]

        def _paged_handler(method: str, url: str, **kwargs):
            if method == "POST":
                return (200, {"access_token": "token-abc"})
            if "/users" in url and "page2" not in url:
                return (200, {"value": page1_users, "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page2"})
            if "page2" in url:
                return (200, {"value": page2_users})
            if "/organization" in url:
                return (200, {"value": [{"displayName": "Test Org"}]})
            if "identitySecurityDefaultsEnforcementPolicy" in url:
                return (200, {"isEnabled": True})
            return (200, {"value": []})

        mock_http.side_effect = _paged_handler

        with patch.dict(os.environ, self.mock_env, clear=True):
            run(self.ctx, self.log, self.out_dir)

        raw_users_path = self.out_dir / "raw" / "users.json"
        self.assertTrue(raw_users_path.is_file())
        raw_users_data = json.loads(raw_users_path.read_text(encoding="utf-8"))
        self.assertEqual(len(raw_users_data), 2)
        self.assertEqual(raw_users_data[0]["userPrincipalName"], "p1@example.com")
        self.assertEqual(raw_users_data[1]["userPrincipalName"], "p2@example.com")

        # Verify console log recorded command
        console_log = self.ctx.console_dir / "S.log"
        self.assertTrue(console_log.is_file())
        log_content = console_log.read_text(encoding="utf-8")
        self.assertIn("GET https://graph.microsoft.com/v1.0/users", log_content)
        self.assertNotIn("SuperSecretClientKey123!", log_content)
        self.assertNotIn("token-abc", log_content)


if __name__ == "__main__":
    unittest.main()
