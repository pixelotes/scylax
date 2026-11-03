"""Unit tests for GitHub SaaS posture audit module (recon.saas.github)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from recon.config import RunContext, ScopeConfig
from recon.runner import CmdResult, Logger
from recon.saas.github import _parse_json_stream, run


class TestSaasGitHubPosture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)
        self.scope = ScopeConfig(
            path=self.root_path / "scope.toml",
            name="test-org-scope",
            engagement="audit",
        )
        self.ctx = RunContext(
            root=self.root_path,
            scope=self.scope,
            run_date="2026-03-03",
            phases=["S"],
        )
        self.ctx.ensure_dirs()
        self.out_dir = self.ctx.run_dir / "saas" / "github"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.log = Logger(gaps_file=self.ctx.run_dir / "gaps.txt")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_missing_github_org_returns_empty_without_calling_gh(self) -> None:
        """When GITHUB_ORG is unset, run() must log a warning and return [] immediately."""
        env_without_org = {k: v for k, v in os.environ.items() if k != "GITHUB_ORG"}
        with patch.dict(os.environ, env_without_org, clear=True):
            with patch("recon.saas.github.have") as mock_have:
                with patch("recon.saas.github.run_cmd") as mock_run_cmd:
                    findings = run(self.ctx, self.log, self.out_dir)
                    self.assertEqual(findings, [])
                    mock_have.assert_not_called()
                    mock_run_cmd.assert_not_called()

    def test_missing_gh_binary_returns_empty(self) -> None:
        """When gh is not on PATH, run() must log a warning and return []."""
        with patch.dict(os.environ, {"GITHUB_ORG": "test-org"}):
            with patch("recon.saas.github.have", return_value=False):
                with patch("recon.saas.github.run_cmd") as mock_run_cmd:
                    findings = run(self.ctx, self.log, self.out_dir)
                    self.assertEqual(findings, [])
                    mock_run_cmd.assert_not_called()

    def test_unauthenticated_gh_returns_empty(self) -> None:
        """When gh auth status fails, run() must log a warning and return []."""
        with patch.dict(os.environ, {"GITHUB_ORG": "test-org"}):
            with patch("recon.saas.github.have", return_value=True):
                with patch(
                    "recon.saas.github.run_cmd",
                    return_value=CmdResult(
                        args=["gh", "auth", "status"],
                        returncode=1,
                        stdout="",
                        stderr="You are not logged into any GitHub hosts.",
                    ),
                ):
                    findings = run(self.ctx, self.log, self.out_dir)
                    self.assertEqual(findings, [])

    def test_parse_json_stream(self) -> None:
        """Verify _parse_json_stream handles objects, lists, and paginated concatenated streams."""
        # Single object
        self.assertEqual(_parse_json_stream('{"key": "val"}'), {"key": "val"})
        # Single list
        self.assertEqual(_parse_json_stream('[{"a": 1}]'), [{"a": 1}])
        # Concatenated lists (gh api --paginate output)
        paginated_raw = '[{"id": 1}, {"id": 2}]\n[{"id": 3}]'
        self.assertEqual(
            _parse_json_stream(paginated_raw),
            [{"id": 1}, {"id": 2}, {"id": 3}],
        )
        # Empty or invalid
        self.assertIsNone(_parse_json_stream(""))
        self.assertIsNone(_parse_json_stream("   "))
        self.assertIsNone(_parse_json_stream("not json at all"))

    def test_full_audit_with_findings(self) -> None:
        """Test full audit flow detecting security issues across all categories."""
        org_settings = {
            "two_factor_requirement_enabled": False,
            "default_repository_permission": "admin",
            "members_can_create_public_repositories": True,
            "members_can_delete_repositories": True,
            "members_can_change_repo_visibility": True,
            "members_can_invite_outside_collaborators": True,
            "members_can_fork_private_repositories": True,
            "web_commit_signoff_required": False,
            "advanced_security_enabled_for_new_repositories": False,
            "secret_scanning_enabled_for_new_repositories": False,
            "secret_scanning_push_protection_enabled_for_new_repositories": False,
            "dependency_graph_enabled_for_new_repositories": False,
            "dependabot_alerts_enabled_for_new_repositories": False,
            "dependabot_security_updates_enabled_for_new_repositories": False,
        }

        repos = [
            {
                "name": "public-repo",
                "visibility": "public",
                "archived": False,
                "default_branch": "main",
                "pushed_at": "2026-03-01T12:00:00Z",
                "has_pages": True,
                "security_and_analysis": {
                    "secret_scanning": {"status": "disabled"},
                    "secret_scanning_push_protection": {"status": "disabled"},
                },
            },
            {
                "name": "stale-repo",
                "visibility": "private",
                "archived": False,
                "default_branch": "main",
                "pushed_at": "2024-01-01T00:00:00Z",
                "has_pages": False,
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            },
        ]

        branch_prot = {
            "required_pull_request_reviews": None,
            "required_status_checks": None,
            "enforce_admins": {"enabled": False},
            "allow_force_pushes": {"enabled": True},
            "allow_deletions": {"enabled": True},
            "required_signatures": {"enabled": False},
        }

        def mock_cmd_handler(cmd: list[str], **kwargs: object) -> CmdResult:
            cmd_s = " ".join(cmd)
            if cmd == ["gh", "auth", "status"]:
                return CmdResult(cmd, 0, "Logged in to github.com as test-user", "")

            # Org settings
            if "/orgs/test-org/members?role=admin" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "admin1"}]), "")
            if "/orgs/test-org/members?filter=2fa_disabled" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "dev_no_2fa"}]), "")
            if "/orgs/test-org/members" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "admin1"}, {"login": "dev_no_2fa"}]), "")
            if "/orgs/test-org/outside_collaborators" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "collab1"}]), "")
            if "/orgs/test-org/invitations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "pending_bob"}]), "")
            if "/orgs/test-org/failed_invitations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"email": "failed@domain.test"}]), "")
            if "/orgs/test-org/credential-authorizations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "dev_no_2fa", "authorized_credential_id": None}]), "")
            if "/orgs/test-org/actions/permissions" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"allowed_actions": "all", "enabled_repositories": "all"}), "")
            if "/orgs/test-org/installations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"installations": [{"app_slug": "ci-tool"}]}), "")
            if "/orgs/test-org/repos" in cmd_s:
                return CmdResult(cmd, 0, json.dumps(repos), "")
            if "/orgs/test-org/actions/secrets" in cmd_s:
                return CmdResult(
                    cmd,
                    0,
                    json.dumps({
                        "total_count": 1,
                        "secrets": [{"name": "GLOBAL_AWS_KEY", "visibility": "all"}],
                    }),
                    "",
                )
            if "/orgs/test-org/actions/variables" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"total_count": 0, "variables": []}), "")
            if "/orgs/test-org/secret-scanning/alerts" in cmd_s:
                return CmdResult(
                    cmd,
                    0,
                    json.dumps([{
                        "repository": {"name": "public-repo"},
                        "secret_type_display_name": "Slack Webhook",
                    }]),
                    "",
                )
            if "/orgs/test-org/dependabot/alerts" in cmd_s:
                return CmdResult(
                    cmd,
                    0,
                    json.dumps([{
                        "repository": {"name": "public-repo"},
                        "security_advisory": {"severity": "critical"},
                    }]),
                    "",
                )
            if "/orgs/test-org/code-scanning/alerts" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"rule": {"id": "sql-injection"}}]), "")
            if "phrase=action:org.update_member" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"action": "org.update_member"}]), "")
            if "phrase=action:repo.access" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"action": "repo.access"}]), "")
            if "phrase=action:org.add_member" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org" in cmd_s:
                return CmdResult(cmd, 0, json.dumps(org_settings), "")

            # Per-repo calls
            if "/branches/main/protection" in cmd_s:
                if "public-repo" in cmd_s:
                    return CmdResult(cmd, 0, json.dumps(branch_prot), "")
                # stale-repo is unprotected
                return CmdResult(cmd, 1, "", "HTTP 404: Branch not protected")
            if "/keys" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"id": 1, "title": "Deploy Key", "read_only": False}]), "")
            if "/hooks" in cmd_s:
                return CmdResult(
                    cmd,
                    0,
                    json.dumps([{
                        "id": 10,
                        "config": {"url": "http://insecure.test/hook", "insecure_ssl": "1"},
                        "last_response": {"status": "error", "code": None},
                    }]),
                    "",
                )

            return CmdResult(cmd, 0, "{}", "")

        with patch.dict(os.environ, {"GITHUB_ORG": "test-org"}):
            with patch("recon.saas.github.have", return_value=True):
                with patch("recon.saas.github.run_cmd", side_effect=mock_cmd_handler):
                    findings = run(self.ctx, self.log, self.out_dir)

        finding_map = {f.key: f for f in findings}

        # Assert key high / critical findings
        self.assertIn("gh-org-2fa-not-enforced", finding_map)
        self.assertEqual(finding_map["gh-org-2fa-not-enforced"].severity, "medium")

        self.assertIn("gh-org-default-repo-permission-admin", finding_map)
        self.assertEqual(finding_map["gh-org-default-repo-permission-admin"].severity, "critical")

        self.assertIn("gh-org-members-delete-repos", finding_map)
        self.assertEqual(finding_map["gh-org-members-delete-repos"].severity, "high")

        self.assertIn("gh-org-members-change-visibility", finding_map)
        self.assertEqual(finding_map["gh-org-members-change-visibility"].severity, "high")

        self.assertIn("gh-members-no-2fa", finding_map)
        self.assertEqual(finding_map["gh-members-no-2fa"].severity, "high")

        self.assertIn("gh-public-repos", finding_map)
        self.assertEqual(finding_map["gh-public-repos"].severity, "high")

        self.assertIn("gh-branch-protection-missing", finding_map)
        self.assertIn("gh-branch-protection-force-push-allowed", finding_map)
        self.assertEqual(finding_map["gh-branch-protection-force-push-allowed"].severity, "high")
        self.assertIn("gh-branch-protection-deletion-allowed", finding_map)
        self.assertEqual(finding_map["gh-branch-protection-deletion-allowed"].severity, "high")

        self.assertIn("gh-webhook-ssl-verification-disabled", finding_map)
        self.assertEqual(finding_map["gh-webhook-ssl-verification-disabled"].severity, "high")
        self.assertIn("gh-webhook-unencrypted-http", finding_map)
        self.assertEqual(finding_map["gh-webhook-unencrypted-http"].severity, "high")

        self.assertIn("gh-alerts-dependabot-critical-high", finding_map)
        self.assertEqual(finding_map["gh-alerts-dependabot-critical-high"].severity, "critical")

        self.assertIn("gh-alerts-secret-scanning", finding_map)
        self.assertEqual(finding_map["gh-alerts-secret-scanning"].severity, "high")

        self.assertIn("gh-alerts-code-scanning", finding_map)
        self.assertEqual(finding_map["gh-alerts-code-scanning"].severity, "high")

        self.assertIn("gh-org-secrets-visible-to-all", finding_map)
        self.assertEqual(finding_map["gh-org-secrets-visible-to-all"].severity, "medium")

        self.assertIn("gh-tokens-not-sso-authorized", finding_map)
        self.assertEqual(finding_map["gh-tokens-not-sso-authorized"].severity, "medium")

        self.assertIn("gh-actions-allow-all", finding_map)
        self.assertEqual(finding_map["gh-actions-allow-all"].severity, "medium")

        self.assertIn("gh-stale-repos", finding_map)
        self.assertEqual(finding_map["gh-stale-repos"].severity, "low")

        self.assertIn("gh-pages-enabled", finding_map)
        self.assertEqual(finding_map["gh-pages-enabled"].severity, "low")

        # Verify raw files were written
        raw_dir = self.out_dir / "raw"
        self.assertTrue((raw_dir / "org_settings.json").is_file())
        self.assertTrue((raw_dir / "repos.json").is_file())
        self.assertTrue((raw_dir / "branch_protection.json").is_file())
        self.assertTrue((raw_dir / "repo_webhooks.json").is_file())

        # Verify console log was written
        console_log = self.ctx.console_dir / "S.log"
        self.assertTrue(console_log.is_file())
        self.assertIn("gh api /orgs/test-org", console_log.read_text())

    def test_compliant_org_generates_info_findings(self) -> None:
        """Test a fully compliant and hardened organization generates info findings."""
        org_settings = {
            "two_factor_requirement_enabled": True,
            "default_repository_permission": "none",
            "members_can_create_public_repositories": False,
            "members_can_delete_repositories": False,
            "members_can_change_repo_visibility": False,
            "members_can_invite_outside_collaborators": False,
            "members_can_fork_private_repositories": False,
            "web_commit_signoff_required": True,
            "advanced_security_enabled_for_new_repositories": True,
            "secret_scanning_enabled_for_new_repositories": True,
            "secret_scanning_push_protection_enabled_for_new_repositories": True,
            "dependency_graph_enabled_for_new_repositories": True,
            "dependabot_alerts_enabled_for_new_repositories": True,
            "dependabot_security_updates_enabled_for_new_repositories": True,
        }

        repos = [
            {
                "name": "private-secure",
                "visibility": "private",
                "archived": False,
                "default_branch": "main",
                "pushed_at": "2026-03-01T12:00:00Z",
                "has_pages": False,
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            }
        ]

        branch_prot = {
            "required_pull_request_reviews": {"dismiss_stale_reviews": True},
            "required_status_checks": {"contexts": ["ci/tests"]},
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "required_signatures": {"enabled": True},
        }

        def mock_cmd_handler(cmd: list[str], **kwargs: object) -> CmdResult:
            cmd_s = " ".join(cmd)
            if cmd == ["gh", "auth", "status"]:
                return CmdResult(cmd, 0, "Logged in", "")
            if "/orgs/test-org/members?role=admin" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "admin1"}, {"login": "admin2"}]), "")
            if "/orgs/test-org/members?filter=2fa_disabled" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org/members" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "admin1"}, {"login": "admin2"}]), "")
            if "/orgs/test-org/outside_collaborators" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org/invitations" in cmd_s or "/orgs/test-org/failed_invitations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org/credential-authorizations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "admin1", "authorized_credential_id": 123}]), "")
            if "/orgs/test-org/actions/permissions" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"allowed_actions": "selected", "enabled_repositories": "selected"}), "")
            if "/orgs/test-org/installations" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org/repos" in cmd_s:
                return CmdResult(cmd, 0, json.dumps(repos), "")
            if "/orgs/test-org/actions/secrets" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"total_count": 0, "secrets": []}), "")
            if "/orgs/test-org/actions/variables" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"total_count": 0, "variables": []}), "")
            if "/alerts" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/audit-log" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org" in cmd_s:
                return CmdResult(cmd, 0, json.dumps(org_settings), "")
            if "/branches/main/protection" in cmd_s:
                return CmdResult(cmd, 0, json.dumps(branch_prot), "")
            if "/keys" in cmd_s or "/hooks" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            return CmdResult(cmd, 0, "{}", "")

        with patch.dict(os.environ, {"GITHUB_ORG": "test-org"}):
            with patch("recon.saas.github.have", return_value=True):
                with patch("recon.saas.github.run_cmd", side_effect=mock_cmd_handler):
                    findings = run(self.ctx, self.log, self.out_dir)

        finding_map = {f.key: f for f in findings}
        self.assertIn("gh-org-2fa-enforced", finding_map)
        self.assertEqual(finding_map["gh-org-2fa-enforced"].severity, "info")
        self.assertIn("gh-org-default-repo-permission-none", finding_map)
        self.assertEqual(finding_map["gh-org-default-repo-permission-none"].severity, "info")
        self.assertIn("gh-members-2fa-compliant", finding_map)
        self.assertIn("gh-no-public-repos", finding_map)
        self.assertIn("gh-branch-protection-all", finding_map)
        self.assertIn("gh-no-outside-collaborators", finding_map)

    def test_403_404_graceful_handling(self) -> None:
        """When an endpoint returns 403 or 404 (e.g. audit-log unlicensed), run() continues."""
        def mock_cmd_handler(cmd: list[str], **kwargs: object) -> CmdResult:
            cmd_s = " ".join(cmd)
            if cmd == ["gh", "auth", "status"]:
                return CmdResult(cmd, 0, "Logged in", "")
            if "/audit-log" in cmd_s:
                return CmdResult(cmd, 1, "", "HTTP 403: Must have an enterprise license to use audit log API")
            if "/orgs/test-org/members?role=admin" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([{"login": "admin1"}, {"login": "admin2"}]), "")
            if "/orgs/test-org/members" in cmd_s:
                return CmdResult(cmd, 0, json.dumps([]), "")
            if "/orgs/test-org" in cmd_s:
                return CmdResult(cmd, 0, json.dumps({"two_factor_requirement_enabled": True}), "")
            return CmdResult(cmd, 0, "[]", "")

        with patch.dict(os.environ, {"GITHUB_ORG": "test-org"}):
            with patch("recon.saas.github.have", return_value=True):
                with patch("recon.saas.github.run_cmd", side_effect=mock_cmd_handler):
                    findings = run(self.ctx, self.log, self.out_dir)
                    self.assertTrue(len(findings) > 0)
                    # Audit log findings should be skipped without raising exceptions
                    audit_findings = [f for f in findings if f.key.startswith("gh-audit-log")]
                    self.assertEqual(len(audit_findings), 0)

    def test_repo_capping(self) -> None:
        """When active repos exceed 200, an info finding is emitted and audit is capped."""
        repos = [
            {
                "name": f"repo-{i}",
                "visibility": "private",
                "archived": False,
                "default_branch": "main",
                "pushed_at": f"2026-01-01T{i%24:02d}:00:00Z",
            }
            for i in range(250)
        ]

        per_repo_calls: list[str] = []

        def mock_cmd_handler(cmd: list[str], **kwargs: object) -> CmdResult:
            cmd_s = " ".join(cmd)
            if cmd == ["gh", "auth", "status"]:
                return CmdResult(cmd, 0, "Logged in", "")
            if "/orgs/test-org/repos" in cmd_s:
                return CmdResult(cmd, 0, json.dumps(repos), "")
            if "/branches/main/protection" in cmd_s:
                per_repo_calls.append(cmd_s)
                return CmdResult(cmd, 1, "", "404")
            if "/orgs/test-org" in cmd_s:
                return CmdResult(cmd, 0, "{}", "")
            return CmdResult(cmd, 0, "[]", "")

        with patch.dict(os.environ, {"GITHUB_ORG": "test-org"}):
            with patch("recon.saas.github.have", return_value=True):
                with patch("recon.saas.github.run_cmd", side_effect=mock_cmd_handler):
                    findings = run(self.ctx, self.log, self.out_dir)

        finding_map = {f.key: f for f in findings}
        self.assertIn("gh-repo-cap-reached", finding_map)
        self.assertEqual(finding_map["gh-repo-cap-reached"].severity, "info")
        self.assertIn("Audited 200 of 250", finding_map["gh-repo-cap-reached"].detail)
        # Verify exactly 200 repos were queried for branch protection
        self.assertEqual(len(per_repo_calls), 200)


if __name__ == "__main__":
    unittest.main()
