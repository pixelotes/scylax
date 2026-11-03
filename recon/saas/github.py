"""GitHub organization security posture audit module.

Audits organization settings, identity & access, repository branch protections,
secrets policies, and security alerts via the GitHub CLI (gh api).
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import time
from typing import Any

from recon.config import RunContext
from recon.runner import Logger, have, record_virtual_cmd, run_cmd
from recon.saas.common import Finding, cap_list, redact, save_raw


def _parse_json_stream(raw: str) -> Any:
    """Parse JSON output from gh api, including concatenated pages from --paginate."""
    raw = raw.strip()
    if not raw:
        return None
    decoder = json.JSONDecoder()
    pos = 0
    results: list[Any] = []
    while pos < len(raw):
        while pos < len(raw) and raw[pos].isspace():
            pos += 1
        if pos >= len(raw):
            break
        try:
            obj, idx = decoder.raw_decode(raw, pos)
            results.append(obj)
            pos = idx
        except json.JSONDecodeError:
            break
    if not results:
        return None
    if len(results) == 1:
        return results[0]
    if all(isinstance(x, list) for x in results):
        flattened: list[Any] = []
        for page in results:
            flattened.extend(page)
        return flattened
    return results


def _gh_api(
    ctx: RunContext,
    log: Logger,
    endpoint: str,
    *,
    paginate: bool = False,
    out_dir: Path | None = None,
    raw_name: str | None = None,
    warn_on_error: bool = True,
) -> Any:
    """Execute a read-only gh api GET call with evidence capture and robust JSON parsing."""
    cmd = ["gh", "api"]
    if paginate:
        cmd.append("--paginate")
    cmd.append(endpoint)

    cmd_str = f"gh api {endpoint}"
    t0 = time.perf_counter()
    res = run_cmd(cmd)
    duration_ms = int((time.perf_counter() - t0) * 1000)

    if res.returncode != 0:
        err_msg = res.stderr.strip() or res.stdout.strip()
        record_virtual_cmd(
            ctx.console_dir,
            "S",
            cmd_str,
            redact(err_msg),
            title=f"GitHub API {endpoint}",
            returncode=res.returncode,
            duration_ms=duration_ms,
        )
        if warn_on_error:
            log.warn(f"GitHub: {endpoint} unavailable - checks depending on it skipped")
        return None

    data = _parse_json_stream(res.stdout)
    if data is None:
        summary = "empty response"
    elif isinstance(data, list):
        summary = f"[{len(data)} items]"
    elif isinstance(data, dict):
        summary = f"JSON object ({len(data)} keys)"
    else:
        summary = str(data)[:100]

    record_virtual_cmd(
        ctx.console_dir,
        "S",
        cmd_str,
        summary,
        title=f"GitHub API {endpoint}",
        returncode=0,
        duration_ms=duration_ms,
    )

    if out_dir is not None and raw_name is not None and data is not None:
        save_raw(out_dir, raw_name, data)

    return data


def _parse_iso(ts: str | None) -> datetime.datetime:
    """Parse ISO-8601 timestamp string into timezone-aware UTC datetime."""
    if not ts:
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
    try:
        clean = ts.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


def run(ctx: RunContext, log: Logger, out_dir: Path) -> list[Finding]:
    """Execute GitHub organization security posture audit."""
    org = os.environ.get("GITHUB_ORG", "").strip()
    if not org:
        log.warn("GitHub posture skipped: set GITHUB_ORG and run gh auth login (scopes admin:org, audit_log)")
        return []

    if not have("gh"):
        log.warn("GitHub posture skipped: set GITHUB_ORG and run gh auth login (scopes admin:org, audit_log)")
        return []

    auth_res = run_cmd(["gh", "auth", "status"])
    if auth_res.returncode != 0:
        log.warn("GitHub posture skipped: set GITHUB_ORG and run gh auth login (scopes admin:org, audit_log)")
        return []

    findings: list[Finding] = []
    now = datetime.datetime.now(datetime.timezone.utc)
    thirty_days_ago_iso = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    one_year_ago = now - datetime.timedelta(days=365)

    # ── 1. Organization Settings ──────────────────────────────────────────────
    org_settings = _gh_api(ctx, log, f"/orgs/{org}", out_dir=out_dir, raw_name="org_settings.json")
    if isinstance(org_settings, dict):
        # 2FA enforcement
        if org_settings.get("two_factor_requirement_enabled") is True:
            findings.append(Finding(
                severity="info",
                key="gh-org-2fa-enforced",
                service="GitHub",
                resource=org,
                title="2FA enforcement active at org level",
                detail="two_factor_requirement_enabled = true",
                iso="A.8.5, A.5.16",
            ))
        else:
            findings.append(Finding(
                severity="medium",
                key="gh-org-2fa-not-enforced",
                service="GitHub",
                resource=org,
                title="2FA not enforced at organization level",
                detail="two_factor_requirement_enabled = false",
                iso="A.8.5, A.5.16",
            ))

        # Default repository permission
        default_perm = str(org_settings.get("default_repository_permission") or "read").lower()
        if default_perm == "admin":
            findings.append(Finding(
                severity="critical",
                key="gh-org-default-repo-permission-admin",
                service="GitHub",
                resource=org,
                title="Default repository permission is ADMIN",
                detail="default_repository_permission = admin — all members get admin on every repo",
                iso="A.5.15, A.8.2",
            ))
        elif default_perm == "write":
            findings.append(Finding(
                severity="high",
                key="gh-org-default-repo-permission-write",
                service="GitHub",
                resource=org,
                title="Default repository permission is WRITE",
                detail="default_repository_permission = write — all members can push to every repo",
                iso="A.5.15, A.8.2",
            ))
        elif default_perm == "read":
            findings.append(Finding(
                severity="low",
                key="gh-org-default-repo-permission-read",
                service="GitHub",
                resource=org,
                title="Default repository permission is READ",
                detail="default_repository_permission = read — all members can read every repo. Consider 'none' for least privilege",
                iso="A.5.15",
            ))
        elif default_perm == "none":
            findings.append(Finding(
                severity="info",
                key="gh-org-default-repo-permission-none",
                service="GitHub",
                resource=org,
                title="Default repository permission is NONE (least privilege)",
                detail="default_repository_permission = none — members only access repos through team assignments",
                iso="A.5.15",
            ))

        # Members can create public repos
        can_create_public = org_settings.get("members_can_create_public_repositories", True)
        if can_create_public:
            findings.append(Finding(
                severity="medium",
                key="gh-org-members-create-public-repos",
                service="GitHub",
                resource=org,
                title="Members can create public repositories",
                detail="members_can_create_public_repositories = true — any member can make a repo public",
                iso="A.5.15, A.8.3",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-members-cannot-create-public-repos",
                service="GitHub",
                resource=org,
                title="Members cannot create public repositories",
                detail="members_can_create_public_repositories = false",
                iso="A.5.15, A.8.3",
            ))

        # Members can delete repositories
        can_delete = org_settings.get("members_can_delete_repositories", True)
        if can_delete:
            findings.append(Finding(
                severity="high",
                key="gh-org-members-delete-repos",
                service="GitHub",
                resource=org,
                title="Members can delete repositories",
                detail="members_can_delete_repositories = true — any member can permanently destroy a repo",
                iso="A.8.3, A.8.13",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-members-cannot-delete-repos",
                service="GitHub",
                resource=org,
                title="Members cannot delete repositories",
                detail="members_can_delete_repositories = false",
                iso="A.8.3, A.8.13",
            ))

        # Members can change repo visibility
        can_change_vis = org_settings.get("members_can_change_repo_visibility", True)
        if can_change_vis:
            findings.append(Finding(
                severity="high",
                key="gh-org-members-change-visibility",
                service="GitHub",
                resource=org,
                title="Members can change repository visibility",
                detail="members_can_change_repo_visibility = true — any member can make private repos public",
                iso="A.5.15, A.8.3",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-members-cannot-change-visibility",
                service="GitHub",
                resource=org,
                title="Members cannot change repository visibility",
                detail="members_can_change_repo_visibility = false",
                iso="A.5.15, A.8.3",
            ))

        # Outside collaborator invites
        can_invite = org_settings.get("members_can_invite_outside_collaborators", True)
        if can_invite:
            findings.append(Finding(
                severity="medium",
                key="gh-org-members-invite-collaborators",
                service="GitHub",
                resource=org,
                title="Members can invite outside collaborators",
                detail="members_can_invite_outside_collaborators = true — any member can grant external access",
                iso="A.5.19",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-owners-only-invite-collaborators",
                service="GitHub",
                resource=org,
                title="Only owners can invite outside collaborators",
                detail="members_can_invite_outside_collaborators = false",
                iso="A.5.19",
            ))

        # Private repository forking
        can_fork = org_settings.get("members_can_fork_private_repositories", True)
        if can_fork:
            findings.append(Finding(
                severity="low",
                key="gh-org-members-fork-private-repos",
                service="GitHub",
                resource=org,
                title="Members can fork private repositories",
                detail="members_can_fork_private_repositories = true",
                iso="A.8.3",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-private-repo-forking-disabled",
                service="GitHub",
                resource=org,
                title="Forking of private repositories is disabled",
                detail="members_can_fork_private_repositories = false",
                iso="A.8.3",
            ))

        # Web commit signoff
        web_signoff = org_settings.get("web_commit_signoff_required", False)
        if not web_signoff:
            findings.append(Finding(
                severity="low",
                key="gh-org-web-commit-signoff-disabled",
                service="GitHub",
                resource=org,
                title="Web commit signoff not required",
                detail="web_commit_signoff_required = false — commits via GitHub UI are unsigned",
                iso="A.8.9",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-web-commit-signoff-required",
                service="GitHub",
                resource=org,
                title="Web commit signoff required",
                detail="web_commit_signoff_required = true",
                iso="A.8.9",
            ))

        # Advanced Security auto-enable
        adv_sec = org_settings.get("advanced_security_enabled_for_new_repositories", False)
        if not adv_sec:
            findings.append(Finding(
                severity="medium",
                key="gh-org-adv-sec-not-auto-enabled",
                service="GitHub",
                resource=org,
                title="Advanced Security not auto-enabled for new repos",
                detail="advanced_security_enabled_for_new_repositories = false",
                iso="A.8.8, A.8.25",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-adv-sec-auto-enabled",
                service="GitHub",
                resource=org,
                title="Advanced Security auto-enabled for new repositories",
                detail="advanced_security_enabled_for_new_repositories = true",
                iso="A.8.8, A.8.25",
            ))

        # Secret scanning auto-enable
        sec_scan = org_settings.get("secret_scanning_enabled_for_new_repositories", False)
        if not sec_scan:
            findings.append(Finding(
                severity="medium",
                key="gh-org-secret-scan-not-auto-enabled",
                service="GitHub",
                resource=org,
                title="Secret scanning not auto-enabled for new repos",
                detail="secret_scanning_enabled_for_new_repositories = false",
                iso="A.8.8",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-secret-scan-auto-enabled",
                service="GitHub",
                resource=org,
                title="Secret scanning auto-enabled for new repos",
                detail="secret_scanning_enabled_for_new_repositories = true",
                iso="A.8.8",
            ))

        # Secret scanning push protection auto-enable
        push_prot = org_settings.get("secret_scanning_push_protection_enabled_for_new_repositories", False)
        if not push_prot:
            findings.append(Finding(
                severity="medium",
                key="gh-org-secret-push-not-auto-enabled",
                service="GitHub",
                resource=org,
                title="Secret scanning push protection not auto-enabled for new repos",
                detail="secret_scanning_push_protection_enabled_for_new_repositories = false",
                iso="A.8.8",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-secret-push-auto-enabled",
                service="GitHub",
                resource=org,
                title="Secret scanning push protection auto-enabled for new repos",
                detail="secret_scanning_push_protection_enabled_for_new_repositories = true",
                iso="A.8.8",
            ))

        # Dependency graph auto-enable
        dep_graph = org_settings.get("dependency_graph_enabled_for_new_repositories", False)
        if not dep_graph:
            findings.append(Finding(
                severity="low",
                key="gh-org-dep-graph-not-auto-enabled",
                service="GitHub",
                resource=org,
                title="Dependency graph not auto-enabled for new repos",
                detail="dependency_graph_enabled_for_new_repositories = false — supply chain visibility gap",
                iso="A.8.8",
            ))

        # Dependabot alerts auto-enable
        dep_alerts = org_settings.get("dependabot_alerts_enabled_for_new_repositories", False)
        if not dep_alerts:
            findings.append(Finding(
                severity="low",
                key="gh-org-dependabot-not-auto-enabled",
                service="GitHub",
                resource=org,
                title="Dependabot alerts not auto-enabled for new repos",
                detail="dependabot_alerts_enabled_for_new_repositories = false",
                iso="A.8.8",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-org-dependabot-auto-enabled",
                service="GitHub",
                resource=org,
                title="Dependabot alerts auto-enabled for new repos",
                detail="dependabot_alerts_enabled_for_new_repositories = true",
                iso="A.8.8",
            ))

        # Dependabot security updates auto-enable
        dep_updates = org_settings.get("dependabot_security_updates_enabled_for_new_repositories", False)
        if not dep_updates:
            findings.append(Finding(
                severity="low",
                key="gh-org-dependabot-updates-not-auto-enabled",
                service="GitHub",
                resource=org,
                title="Dependabot security updates (auto-fix PRs) not auto-enabled",
                detail="dependabot_security_updates_enabled_for_new_repositories = false",
                iso="A.8.8",
            ))

    # ── 2. Identity & Access ──────────────────────────────────────────────────
    members_data = _gh_api(ctx, log, f"/orgs/{org}/members", paginate=True, out_dir=out_dir, raw_name="members.json")
    members = members_data if isinstance(members_data, list) else []
    total_members = len(members)

    no_2fa_data = _gh_api(
        ctx, log, f"/orgs/{org}/members?filter=2fa_disabled", paginate=True, out_dir=out_dir, raw_name="members_no_2fa.json"
    )
    no_2fa_members = no_2fa_data if isinstance(no_2fa_data, list) else []
    no_2fa_count = len(no_2fa_members)
    no_2fa_logins = [m.get("login", "unknown") for m in no_2fa_members if isinstance(m, dict)]

    if no_2fa_data is not None:
        if no_2fa_count > 0:
            findings.append(Finding(
                severity="high",
                key="gh-members-no-2fa",
                service="GitHub",
                resource=org,
                title="Members without 2FA enabled",
                detail=f"{no_2fa_count}/{total_members} member(s) non-compliant: {cap_list(no_2fa_logins)}",
                iso="A.8.5",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-members-2fa-compliant",
                service="GitHub",
                resource=org,
                title="2FA compliance: 100%",
                detail=f"All {total_members} members have 2FA enabled",
                iso="A.8.5",
            ))

    # Owners
    owners_data = _gh_api(
        ctx, log, f"/orgs/{org}/members?role=admin", paginate=True, out_dir=out_dir, raw_name="owners.json"
    )
    owners = owners_data if isinstance(owners_data, list) else []
    owner_count = len(owners)
    owner_logins = [o.get("login", "unknown") for o in owners if isinstance(o, dict)]

    if owners_data is not None:
        if owner_count > 5:
            findings.append(Finding(
                severity="medium",
                key="gh-owners-excessive",
                service="GitHub",
                resource=org,
                title=f"Excessive organization owners ({owner_count})",
                detail=f"Best practice: 2-5. Current: {cap_list(owner_logins)}",
                iso="A.5.15, A.8.2",
            ))
        elif owner_count == 1:
            findings.append(Finding(
                severity="medium",
                key="gh-owners-single",
                service="GitHub",
                resource=org,
                title="Only 1 organization owner (single point of failure)",
                detail=cap_list(owner_logins),
                iso="A.5.15, A.8.2",
            ))
        elif 2 <= owner_count <= 5:
            findings.append(Finding(
                severity="info",
                key="gh-owners-count-ok",
                service="GitHub",
                resource=org,
                title=f"Organization owner count: {owner_count}",
                detail=cap_list(owner_logins),
                iso="A.5.15, A.8.2",
            ))

    # Outside collaborators
    collabs_data = _gh_api(
        ctx, log, f"/orgs/{org}/outside_collaborators", paginate=True, out_dir=out_dir, raw_name="outside_collaborators.json"
    )
    collabs = collabs_data if isinstance(collabs_data, list) else []
    collab_count = len(collabs)
    collab_logins = [c.get("login", "unknown") for c in collabs if isinstance(c, dict)]

    if collabs_data is not None:
        if collab_count > 0:
            findings.append(Finding(
                severity="medium",
                key="gh-outside-collaborators",
                service="GitHub",
                resource=org,
                title="Outside collaborators with repository access",
                detail=f"{collab_count} collaborator(s): {cap_list(collab_logins)} — verify each is still required",
                iso="A.5.18, A.5.19",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-no-outside-collaborators",
                service="GitHub",
                resource=org,
                title="No outside collaborators",
                detail="All repository access is through org membership",
                iso="A.5.18",
            ))

    # Invitations
    invitations_data = _gh_api(
        ctx, log, f"/orgs/{org}/invitations", paginate=True, out_dir=out_dir, raw_name="pending_invitations.json"
    )
    if isinstance(invitations_data, list) and invitations_data:
        pending_names = [str(inv.get("login") or inv.get("email") or "unknown") for inv in invitations_data]
        findings.append(Finding(
            severity="low",
            key="gh-pending-invitations",
            service="GitHub",
            resource=org,
            title="Pending organization invitations",
            detail=f"{len(invitations_data)} invitation(s) not yet accepted: {cap_list(pending_names)}",
            iso="A.5.18",
        ))

    failed_inv_data = _gh_api(
        ctx, log, f"/orgs/{org}/failed_invitations", paginate=True, out_dir=out_dir, raw_name="failed_invitations.json"
    )
    if isinstance(failed_inv_data, list) and failed_inv_data:
        failed_names = [str(inv.get("login") or inv.get("email") or "unknown") for inv in failed_inv_data]
        findings.append(Finding(
            severity="low",
            key="gh-failed-invitations",
            service="GitHub",
            resource=org,
            title="Failed organization invitations",
            detail=f"{len(failed_inv_data)} invitation(s) failed: {cap_list(failed_names)}",
            iso="A.5.18",
        ))

    # ── 3. SSO / SAML Credential Authorizations ───────────────────────────────
    sso_data = _gh_api(
        ctx, log, f"/orgs/{org}/credential-authorizations", out_dir=out_dir, raw_name="sso_config.json"
    )
    if isinstance(sso_data, list) and sso_data:
        unauth = [
            c.get("login", "unknown")
            for c in sso_data
            if isinstance(c, dict) and c.get("authorized_credential_id") is None
        ]
        if unauth:
            findings.append(Finding(
                severity="medium",
                key="gh-tokens-not-sso-authorized",
                service="GitHub",
                resource=org,
                title="Active tokens not authorized via SAML SSO",
                detail=f"{len(unauth)} credential(s) without SSO authorization: {cap_list(unauth)}",
                iso="A.5.16, A.8.2",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-tokens-all-sso-authorized",
                service="GitHub",
                resource=org,
                title=f"All {len(sso_data)} active credentials are SSO-authorized",
                detail="No tokens bypassing SAML SSO detected",
                iso="A.5.16",
            ))

    # ── 4. GitHub Actions Permissions ─────────────────────────────────────────
    act_perms = _gh_api(
        ctx, log, f"/orgs/{org}/actions/permissions", out_dir=out_dir, raw_name="actions_permissions.json"
    )
    if isinstance(act_perms, dict):
        allowed_act = act_perms.get("allowed_actions", "unknown")
        enabled_repos = act_perms.get("enabled_repositories", "unknown")
        if allowed_act == "all":
            findings.append(Finding(
                severity="medium",
                key="gh-actions-allow-all",
                service="GitHub",
                resource=org,
                title="GitHub Actions allows ALL actions (including third-party)",
                detail="allowed_actions = all — consider restricting to verified or selected actions",
                iso="A.8.25, A.5.23",
            ))
        elif allowed_act in ("local_only", "selected"):
            findings.append(Finding(
                severity="info",
                key="gh-actions-restricted",
                service="GitHub",
                resource=org,
                title="GitHub Actions restricted to safe action set",
                detail=f"allowed_actions = {allowed_act}, enabled_repositories = {enabled_repos}",
                iso="A.8.25, A.5.23",
            ))

    # ── 5. Installed GitHub Apps ──────────────────────────────────────────────
    apps_data = _gh_api(
        ctx, log, f"/orgs/{org}/installations", out_dir=out_dir, raw_name="github_apps.json"
    )
    apps_list: list[Any] = []
    if isinstance(apps_data, dict):
        apps_list = apps_data.get("installations", [])
    elif isinstance(apps_data, list):
        apps_list = apps_data
    if apps_list:
        app_names = [
            str(a.get("app_slug") or a.get("id") or "app")
            for a in apps_list
            if isinstance(a, dict)
        ]
        findings.append(Finding(
            severity="info",
            key="gh-apps-installed",
            service="GitHub",
            resource=org,
            title="GitHub Apps installed in organization",
            detail=f"{len(apps_list)} app(s): {cap_list(app_names)} — review each for necessity and scope",
            iso="A.5.23",
        ))

    # ── 6. Repositories & Branch Protection ───────────────────────────────────
    repos_data = _gh_api(
        ctx, log, f"/orgs/{org}/repos?type=all&per_page=100", paginate=True, out_dir=out_dir, raw_name="repos.json"
    )
    repos = repos_data if isinstance(repos_data, list) else []

    if repos_data is not None:
        total_repos = len(repos)
        public_repos = [r for r in repos if isinstance(r, dict) and r.get("visibility") == "public"]
        private_repos = [r for r in repos if isinstance(r, dict) and r.get("visibility") == "private"]
        internal_repos = [r for r in repos if isinstance(r, dict) and r.get("visibility") == "internal"]
        active_repos = [r for r in repos if isinstance(r, dict) and not r.get("archived", False)]
        archived_repos = [r for r in repos if isinstance(r, dict) and r.get("archived", False)]

        # Public repos check
        if public_repos:
            pub_names = [r.get("name", "unknown") for r in public_repos]
            findings.append(Finding(
                severity="high",
                key="gh-public-repos",
                service="GitHub",
                resource=org,
                title="Public repositories detected",
                detail=f"{len(public_repos)} public repo(s): {cap_list(pub_names)}",
                iso="A.5.15, A.8.3",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-no-public-repos",
                service="GitHub",
                resource=org,
                title="No public repositories",
                detail=f"All {total_repos} repos are private or internal (private: {len(private_repos)}, internal: {len(internal_repos)})",
                iso="A.5.15, A.8.3",
            ))

        findings.append(Finding(
            severity="info",
            key="gh-repo-inventory",
            service="GitHub",
            resource=org,
            title="Repository inventory",
            detail=f"{total_repos} total — {len(active_repos)} active, {len(archived_repos)} archived",
            iso="A.8.3",
        ))

        # Per-repo security features from repos.json
        no_sec_scan = [
            r.get("name", "unknown")
            for r in active_repos
            if (r.get("security_and_analysis") or {}).get("secret_scanning", {}).get("status") != "enabled"
        ]
        if no_sec_scan:
            findings.append(Finding(
                severity="medium",
                key="gh-repo-no-secret-scanning",
                service="GitHub",
                resource=org,
                title="Active repos without secret scanning enabled",
                detail=f"{len(no_sec_scan)}/{len(active_repos)} active repo(s) — secrets committed may go undetected: {cap_list(no_sec_scan)}",
                iso="A.8.8",
            ))

        no_push_prot = [
            r.get("name", "unknown")
            for r in active_repos
            if (r.get("security_and_analysis") or {}).get("secret_scanning_push_protection", {}).get("status") != "enabled"
        ]
        if no_push_prot:
            findings.append(Finding(
                severity="medium",
                key="gh-repo-no-push-protection",
                service="GitHub",
                resource=org,
                title="Active repos without secret scanning push protection",
                detail=f"{len(no_push_prot)}/{len(active_repos)} active repo(s) — secrets can be pushed without blocking: {cap_list(no_push_prot)}",
                iso="A.8.8",
            ))

        # Stale repos (active repos with no push in >1 year)
        stale_repos = [
            r.get("name", "unknown")
            for r in active_repos
            if _parse_iso(r.get("pushed_at")) < one_year_ago
        ]
        if stale_repos:
            findings.append(Finding(
                severity="low",
                key="gh-stale-repos",
                service="GitHub",
                resource=org,
                title="Non-archived repos with no push in >1 year",
                detail=f"{len(stale_repos)}/{len(active_repos)} active repo(s) — consider archiving: {cap_list(stale_repos)}",
                iso="A.8.3, A.5.18",
            ))

        # GitHub Pages
        pages_repos = [r.get("name", "unknown") for r in repos if isinstance(r, dict) and r.get("has_pages") is True]
        if pages_repos:
            findings.append(Finding(
                severity="low",
                key="gh-pages-enabled",
                service="GitHub",
                resource=org,
                title="Repos with GitHub Pages enabled",
                detail=f"{len(pages_repos)} repo(s) — pages may expose content publicly: {cap_list(pages_repos)}",
                iso="A.8.3",
            ))

        # Cap per-repo calls at 200 most recently pushed non-archived repos
        active_sorted = sorted(active_repos, key=lambda r: _parse_iso(r.get("pushed_at")), reverse=True)
        if len(active_sorted) > 200:
            findings.append(Finding(
                severity="info",
                key="gh-repo-cap-reached",
                service="GitHub",
                resource=org,
                title="Repository audit cap reached",
                detail=f"Audited 200 of {len(active_sorted)} active repositories (capped at the 200 most recently pushed)",
                iso="A.8.3",
            ))
            audited_repos = active_sorted[:200]
        else:
            audited_repos = active_sorted

        # Per-repo API checks (branch protection, deploy keys, webhooks)
        all_branch_protections: list[dict[str, Any]] = []
        all_deploy_keys: list[dict[str, Any]] = []
        all_webhooks: list[dict[str, Any]] = []

        unprotected_repos: list[str] = []
        no_pr_reviews: list[str] = []
        no_status_checks: list[str] = []
        no_dismiss_stale: list[str] = []
        no_admin_enforce: list[str] = []
        force_push_repos: list[str] = []
        allow_delete_repos: list[str] = []
        no_signed_repos: list[str] = []

        for repo_obj in audited_repos:
            repo_name = repo_obj.get("name")
            if not repo_name:
                continue
            default_branch = repo_obj.get("default_branch") or "main"

            # Branch protection (warn_on_error=False because 404 means unprotected)
            bp = _gh_api(
                ctx,
                log,
                f"/repos/{org}/{repo_name}/branches/{default_branch}/protection",
                warn_on_error=False,
            )
            if isinstance(bp, dict):
                bp_tagged = dict(bp)
                bp_tagged["_repo"] = repo_name
                bp_tagged["_branch"] = default_branch
                all_branch_protections.append(bp_tagged)

                # PR reviews
                if bp.get("required_pull_request_reviews") is None:
                    no_pr_reviews.append(repo_name)
                elif bp.get("required_pull_request_reviews", {}).get("dismiss_stale_reviews") is False:
                    no_dismiss_stale.append(repo_name)

                # Status checks
                rsc = bp.get("required_status_checks")
                if rsc is None or not rsc.get("contexts"):
                    no_status_checks.append(repo_name)

                # Admin enforcement
                if bp.get("enforce_admins", {}).get("enabled") is False:
                    no_admin_enforce.append(repo_name)

                # Force push
                if bp.get("allow_force_pushes", {}).get("enabled") is True:
                    force_push_repos.append(repo_name)

                # Deletions
                if bp.get("allow_deletions", {}).get("enabled") is True:
                    allow_delete_repos.append(repo_name)

                # Signed commits
                req_sig = bp.get("required_signatures")
                if req_sig is None or req_sig.get("enabled") is False:
                    no_signed_repos.append(repo_name)
            else:
                unprotected_repos.append(repo_name)

            # Deploy keys per repo
            keys_data = _gh_api(ctx, log, f"/repos/{org}/{repo_name}/keys", warn_on_error=False)
            if isinstance(keys_data, list):
                for k in keys_data:
                    if isinstance(k, dict):
                        kt = dict(k)
                        kt["_repo"] = repo_name
                        all_deploy_keys.append(kt)

            # Webhooks per repo
            hooks_data = _gh_api(ctx, log, f"/repos/{org}/{repo_name}/hooks", warn_on_error=False)
            if isinstance(hooks_data, list):
                for h in hooks_data:
                    if isinstance(h, dict):
                        ht = dict(h)
                        ht["_repo"] = repo_name
                        all_webhooks.append(ht)

        # Save aggregated per-repo raw data
        save_raw(out_dir, "branch_protection.json", all_branch_protections)
        save_raw(out_dir, "deploy_keys.json", all_deploy_keys)
        save_raw(out_dir, "repo_webhooks.json", all_webhooks)

        # Branch protection findings
        if unprotected_repos:
            findings.append(Finding(
                severity="medium",
                key="gh-branch-protection-missing",
                service="GitHub",
                resource=org,
                title="Repositories with no branch protection on default branch",
                detail=f"{len(unprotected_repos)}/{len(audited_repos)} repo(s) unprotected: {cap_list(unprotected_repos)}",
                iso="A.8.9, A.8.32",
            ))
        elif audited_repos:
            findings.append(Finding(
                severity="info",
                key="gh-branch-protection-all",
                service="GitHub",
                resource=org,
                title="All repositories have branch protection",
                detail=f"{len(audited_repos)}/{len(audited_repos)} repos protected",
                iso="A.8.9, A.8.32",
            ))

        if no_pr_reviews:
            findings.append(Finding(
                severity="medium",
                key="gh-branch-protection-no-pr-reviews",
                service="GitHub",
                resource=org,
                title="Branch protection without required PR reviews",
                detail=f"{len(no_pr_reviews)} protected branch(es) missing PR review requirement: {cap_list(no_pr_reviews)}",
                iso="A.8.9",
            ))

        if no_status_checks:
            findings.append(Finding(
                severity="low",
                key="gh-branch-protection-no-status-checks",
                service="GitHub",
                resource=org,
                title="Branch protection without required status checks (CI)",
                detail=f"{len(no_status_checks)} branch(es) — merges possible without passing CI: {cap_list(no_status_checks)}",
                iso="A.8.9, A.8.25",
            ))

        if no_dismiss_stale:
            findings.append(Finding(
                severity="low",
                key="gh-branch-protection-no-dismiss-stale",
                service="GitHub",
                resource=org,
                title="Stale PR approvals not dismissed on new commits",
                detail=f"{len(no_dismiss_stale)} branch(es) — approvals persist after new pushes: {cap_list(no_dismiss_stale)}",
                iso="A.8.9",
            ))

        if no_admin_enforce:
            findings.append(Finding(
                severity="low",
                key="gh-branch-protection-admin-enforcement-disabled",
                service="GitHub",
                resource=org,
                title="Branch protection not enforced for admins",
                detail=f"{len(no_admin_enforce)} branch(es) — admins can bypass: {cap_list(no_admin_enforce)}",
                iso="A.8.9",
            ))

        if force_push_repos:
            findings.append(Finding(
                severity="high",
                key="gh-branch-protection-force-push-allowed",
                service="GitHub",
                resource=org,
                title="Force pushes allowed on protected branches",
                detail=f"{len(force_push_repos)} branch(es) — history can be rewritten: {cap_list(force_push_repos)}",
                iso="A.8.9, A.8.32",
            ))

        if allow_delete_repos:
            findings.append(Finding(
                severity="high",
                key="gh-branch-protection-deletion-allowed",
                service="GitHub",
                resource=org,
                title="Protected branches allow deletion",
                detail=f"{len(allow_delete_repos)} branch(es) — default branch can be deleted: {cap_list(allow_delete_repos)}",
                iso="A.8.9, A.8.13",
            ))

        if no_signed_repos and all_branch_protections:
            findings.append(Finding(
                severity="low",
                key="gh-branch-protection-signed-commits-disabled",
                service="GitHub",
                resource=org,
                title="Signed commits not required on protected branches",
                detail=f"{len(no_signed_repos)}/{len(all_branch_protections)} protected branch(es) do not require commit signing",
                iso="A.8.9",
            ))

        # Deploy keys findings
        rw_keys = [
            f"{k.get('_repo')}: {k.get('title')}"
            for k in all_deploy_keys
            if k.get("read_only") is False
        ]
        if rw_keys:
            findings.append(Finding(
                severity="medium",
                key="gh-deploy-keys-write-access",
                service="GitHub",
                resource=org,
                title="Deploy keys with WRITE access",
                detail=f"{len(rw_keys)} read-write key(s): {cap_list(rw_keys)}",
                iso="A.8.9, A.5.15",
            ))

        # Webhook findings
        if all_webhooks:
            insecure_ssl = [
                f"{h.get('_repo')} -> {(h.get('config') or {}).get('url', 'unknown')}"
                for h in all_webhooks
                if str((h.get("config") or {}).get("insecure_ssl")) in ("1", "true", "True")
            ]
            if insecure_ssl:
                findings.append(Finding(
                    severity="high",
                    key="gh-webhook-ssl-verification-disabled",
                    service="GitHub",
                    resource=org,
                    title="Webhooks with SSL verification disabled",
                    detail=f"{len(insecure_ssl)} webhook(s) vulnerable to MITM: {cap_list(insecure_ssl)}",
                    iso="A.8.24, A.5.14",
                ))

            http_hooks = [
                f"{h.get('_repo')} -> {(h.get('config') or {}).get('url', '')}"
                for h in all_webhooks
                if str((h.get("config") or {}).get("url", "")).lower().startswith("http://")
            ]
            if http_hooks:
                findings.append(Finding(
                    severity="high",
                    key="gh-webhook-unencrypted-http",
                    service="GitHub",
                    resource=org,
                    title="Webhooks sending data over unencrypted HTTP",
                    detail=f"{len(http_hooks)} webhook(s): {cap_list(http_hooks)}",
                    iso="A.8.24, A.5.14",
                ))

            dead_hooks = [
                h for h in all_webhooks
                if (h.get("last_response") or {}).get("status") in ("error", "unused")
                or (h.get("last_response") or {}).get("code") is None
            ]
            if dead_hooks:
                findings.append(Finding(
                    severity="low",
                    key="gh-webhook-dead-or-unused",
                    service="GitHub",
                    resource=org,
                    title="Dead or unused webhooks",
                    detail=f"{len(dead_hooks)}/{len(all_webhooks)} webhook(s) with no successful delivery",
                    iso="A.5.23",
                ))

            findings.append(Finding(
                severity="info",
                key="gh-webhook-inventory",
                service="GitHub",
                resource=org,
                title="Webhook inventory",
                detail=f"{len(all_webhooks)} total webhook(s) across repositories",
                iso="A.5.23",
            ))

    # ── 7. Secrets & Variables ────────────────────────────────────────────────
    secrets_data = _gh_api(
        ctx, log, f"/orgs/{org}/actions/secrets", out_dir=out_dir, raw_name="org_secrets.json"
    )
    if isinstance(secrets_data, dict):
        total_sec = secrets_data.get("total_count", 0)
        sec_list = secrets_data.get("secrets", [])
        if sec_list:
            all_repos_sec = [
                s.get("name", "unknown")
                for s in sec_list
                if isinstance(s, dict) and s.get("visibility") == "all"
            ]
            if all_repos_sec:
                findings.append(Finding(
                    severity="medium",
                    key="gh-org-secrets-visible-to-all",
                    service="GitHub",
                    resource=org,
                    title="Org secrets visible to ALL repositories",
                    detail=f"Secrets exposed to every repo (incl. forks): {cap_list(all_repos_sec)}",
                    iso="A.8.3, A.5.15",
                ))

            names = [s.get("name", "unknown") for s in sec_list if isinstance(s, dict)]
            findings.append(Finding(
                severity="info",
                key="gh-org-secrets-inventory",
                service="GitHub",
                resource=org,
                title="Organization Actions secrets",
                detail=f"{total_sec} secret(s): {cap_list(names)}",
                iso="A.8.3",
            ))

    _gh_api(ctx, log, f"/orgs/{org}/actions/variables", out_dir=out_dir, raw_name="org_variables.json")

    # ── 8. Security Alerts ────────────────────────────────────────────────────
    # Secret scanning alerts
    sec_alerts_data = _gh_api(
        ctx, log, f"/orgs/{org}/secret-scanning/alerts?state=open", out_dir=out_dir, raw_name="secret_scanning_alerts.json"
    )
    if isinstance(sec_alerts_data, list):
        if sec_alerts_data:
            sec_alert_summaries = [
                f"{(a.get('repository') or {}).get('name', 'repo')}: {a.get('secret_type_display_name', a.get('secret_type', 'secret'))}"
                for a in sec_alerts_data
                if isinstance(a, dict)
            ]
            findings.append(Finding(
                severity="high",
                key="gh-alerts-secret-scanning",
                service="GitHub",
                resource=org,
                title="Open secret scanning alerts",
                detail=f"{len(sec_alerts_data)} active alert(s): {cap_list(sec_alert_summaries)}",
                iso="A.8.8, A.8.3",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-alerts-secret-scanning-clean",
                service="GitHub",
                resource=org,
                title="No open secret scanning alerts",
                detail="Secret scanning clean",
                iso="A.8.8",
            ))

    # Dependabot alerts
    dep_alerts_data = _gh_api(
        ctx,
        log,
        f"/orgs/{org}/dependabot/alerts?state=open&severity=critical,high",
        out_dir=out_dir,
        raw_name="dependabot_alerts.json",
    )
    if isinstance(dep_alerts_data, list):
        if dep_alerts_data:
            crit = [
                a for a in dep_alerts_data
                if isinstance(a, dict) and (a.get("security_advisory") or {}).get("severity") == "critical"
            ]
            high = [
                a for a in dep_alerts_data
                if isinstance(a, dict) and (a.get("security_advisory") or {}).get("severity") == "high"
            ]
            repo_counts: dict[str, int] = {}
            for a in dep_alerts_data:
                if isinstance(a, dict):
                    r_name = (a.get("repository") or {}).get("name", "unknown")
                    repo_counts[r_name] = repo_counts.get(r_name, 0) + 1
            top_repos = [f"{r} ({c})" for r, c in sorted(repo_counts.items(), key=lambda x: -x[1])[:5]]
            sev = "critical" if crit else "high"
            findings.append(Finding(
                severity=sev,
                key="gh-alerts-dependabot-critical-high",
                service="GitHub",
                resource=org,
                title="Open Dependabot CRITICAL/HIGH alerts",
                detail=f"{len(dep_alerts_data)} total ({len(crit)} critical, {len(high)} high) — top repos: {cap_list(top_repos)}",
                iso="A.8.8",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-alerts-dependabot-clean",
                service="GitHub",
                resource=org,
                title="No open Dependabot critical/high alerts",
                detail="Dependency vulnerability status: clean",
                iso="A.8.8",
            ))

    # Code scanning alerts
    code_alerts_data = _gh_api(
        ctx, log, f"/orgs/{org}/code-scanning/alerts?state=open", out_dir=out_dir, raw_name="code_scanning_alerts.json"
    )
    if isinstance(code_alerts_data, list):
        if code_alerts_data:
            findings.append(Finding(
                severity="high",
                key="gh-alerts-code-scanning",
                service="GitHub",
                resource=org,
                title="Open code scanning alerts",
                detail=f"{len(code_alerts_data)} active alert(s)",
                iso="A.8.8, A.8.25",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="gh-alerts-code-scanning-clean",
                service="GitHub",
                resource=org,
                title="No open code scanning alerts",
                detail="Code scanning clean",
                iso="A.8.8",
            ))

    # ── 9. Audit Log (Last 30 Days) ───────────────────────────────────────────
    audit_roles = _gh_api(
        ctx,
        log,
        f"/orgs/{org}/audit-log?phrase=action:org.update_member+created:>={thirty_days_ago_iso}&per_page=100",
        out_dir=out_dir,
        raw_name="audit_log_roles.json",
    )
    if isinstance(audit_roles, list) and audit_roles:
        findings.append(Finding(
            severity="info",
            key="gh-audit-log-role-changes",
            service="GitHub",
            resource=org,
            title="Member role changes in last 30 days",
            detail=f"{len(audit_roles)} event(s) — review for unauthorized privilege escalation",
            iso="A.8.15",
        ))

    audit_vis = _gh_api(
        ctx,
        log,
        f"/orgs/{org}/audit-log?phrase=action:repo.access+created:>={thirty_days_ago_iso}&per_page=100",
        out_dir=out_dir,
        raw_name="audit_log_visibility.json",
    )
    if isinstance(audit_vis, list) and audit_vis:
        findings.append(Finding(
            severity="medium",
            key="gh-audit-log-visibility-changes",
            service="GitHub",
            resource=org,
            title="Repository visibility changes in last 30 days",
            detail=f"{len(audit_vis)} event(s) — review for unintended public exposure",
            iso="A.8.15, A.8.3",
        ))

    _gh_api(
        ctx,
        log,
        f"/orgs/{org}/audit-log?phrase=action:org.add_member+action:org.remove_member+created:>={thirty_days_ago_iso}&per_page=100",
        out_dir=out_dir,
        raw_name="audit_log_members.json",
    )

    return findings
