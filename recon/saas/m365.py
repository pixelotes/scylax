"""Microsoft 365 / Entra ID posture audit module.

Performs read-only configuration checks via Microsoft Graph API for tenant security posture,
identity governance, Conditional Access, application permissions, and external access.
"""

from __future__ import annotations

from collections import Counter
import datetime
import os
import re
from pathlib import Path
from typing import Any

from recon.config import RunContext
from recon.runner import Logger, record_virtual_cmd
from recon.saas.common import Finding, cap_list, http_json, redact, save_raw

GRAPH_V1 = "https://graph.microsoft.com/v1.0"


def _parse_utc(dt_str: str | None) -> datetime.datetime | None:
    """Parse ISO 8601 timestamp to timezone-aware UTC datetime."""
    if not dt_str:
        return None
    try:
        dt = datetime.datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def _fetch_graph(
    path_or_url: str,
    token: str,
    client_secret: str,
    ctx: RunContext,
    log: Logger,
    out_dir: Path,
    raw_name: str,
    endpoint_label: str,
    *,
    is_single: bool = False,
) -> Any | None:
    """Fetch Graph API endpoint with @odata.nextLink pagination, recording virtual cmds and raw evidence.

    Returns the parsed data (list for collections, dict for single objects), or None if unavailable.
    """
    url = path_or_url if path_or_url.startswith("http") else f"{GRAPH_V1}/{path_or_url.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {token}",
        "ConsistencyLevel": "eventual",
    }

    current_url: str | None = url
    all_items: list[Any] = []
    first = True

    while current_url:
        status, resp = http_json("GET", current_url, headers=headers)
        cmd_str = f"GET {current_url}"

        if status != 200:
            err_summary = str(resp)[:200] if resp else "error"
            out_summary = f"status: {status} Error: {err_summary}"
            record_virtual_cmd(
                ctx.console_dir,
                "S",
                redact(cmd_str, token, client_secret),
                redact(out_summary, token, client_secret),
                title=f"M365: {endpoint_label}",
                returncode=status if status != 0 else 1,
            )
            if first:
                log.warn(f"M365: {endpoint_label} unavailable ({status}) - checks depending on it skipped")
                return None
            break

        first = False

        if is_single or not (isinstance(resp, dict) and "value" in resp and isinstance(resp["value"], list)):
            out_summary = "status: 200 OK"
            record_virtual_cmd(
                ctx.console_dir,
                "S",
                redact(cmd_str, token, client_secret),
                redact(out_summary, token, client_secret),
                title=f"M365: {endpoint_label}",
                returncode=0,
            )
            save_raw(out_dir, raw_name, resp)
            return resp

        page_items = resp.get("value", [])
        all_items.extend(page_items)
        out_summary = f"status: 200 OK ({len(page_items)} items)"
        record_virtual_cmd(
            ctx.console_dir,
            "S",
            redact(cmd_str, token, client_secret),
            redact(out_summary, token, client_secret),
            title=f"M365: {endpoint_label}",
            returncode=0,
        )
        current_url = resp.get("@odata.nextLink")

    save_raw(out_dir, raw_name, all_items)
    return all_items


def run(ctx: RunContext, log: Logger, out_dir: Path) -> list[Finding]:
    """Execute Microsoft 365 / Entra ID posture audit.

    Returns a list of posture findings mapped to ISO 27001 controls.
    """
    tenant_id = os.environ.get("M365_TENANT_ID", "").strip()
    client_id = os.environ.get("M365_CLIENT_ID", "").strip()
    client_secret = os.environ.get("M365_CLIENT_SECRET", "").strip()

    if not (tenant_id and client_id and client_secret):
        log.warn("M365 posture skipped: set M365_TENANT_ID, M365_CLIENT_ID and M365_CLIENT_SECRET")
        return []

    # Authenticate via OAuth2 client credentials
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_cmd = f"POST {token_url}"
    token_status, token_resp = http_json(
        "POST",
        token_url,
        form={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
    )

    token = token_resp.get("access_token") if isinstance(token_resp, dict) else None
    if token_status != 200 or not token:
        err_msg = ""
        if isinstance(token_resp, dict):
            err_msg = token_resp.get("error_description") or token_resp.get("error") or ""
        elif isinstance(token_resp, str):
            err_msg = token_resp[:200]
        out_summary = f"status: {token_status} (authentication failed: {err_msg})"
        record_virtual_cmd(
            ctx.console_dir,
            "S",
            redact(token_cmd, client_secret),
            redact(out_summary, client_secret),
            title="M365: Auth",
            returncode=token_status if token_status != 0 else 1,
        )
        safe_err = redact(err_msg, client_secret)
        log.warn(f"M365 authentication failed: HTTP {token_status} ({safe_err})".strip())
        return []

    record_virtual_cmd(
        ctx.console_dir,
        "S",
        redact(token_cmd, client_secret),
        "status: 200 OK (access token acquired)",
        title="M365: Auth",
        returncode=0,
    )

    # Fetch tenant organization details
    org_data = _fetch_graph(
        "organization",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "organization.json",
        "/organization",
    )
    tenant_resource = tenant_id
    if org_data:
        org_first = org_data[0] if isinstance(org_data, list) else org_data
        if isinstance(org_first, dict):
            tenant_resource = org_first.get("displayName") or org_first.get("id") or tenant_id

    # Fetch endpoints
    domains = _fetch_graph(
        "domains",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "domains.json",
        "/domains",
    )

    sec_defaults = _fetch_graph(
        "policies/identitySecurityDefaultsEnforcementPolicy",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "security_defaults.json",
        "/policies/identitySecurityDefaultsEnforcementPolicy",
        is_single=True,
    )

    ca_policies = _fetch_graph(
        "identity/conditionalAccess/policies",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "conditional_access.json",
        "/identity/conditionalAccess/policies",
    )

    users = _fetch_graph(
        "users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=999",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "users.json",
        "/users",
    )

    mfa_reg = _fetch_graph(
        "reports/authenticationMethods/userRegistrationDetails",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "mfa_registration.json",
        "/reports/authenticationMethods/userRegistrationDetails",
    )

    directory_roles = _fetch_graph(
        "directoryRoles?$expand=members",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "directory_roles.json",
        "/directoryRoles",
    )

    applications = _fetch_graph(
        "applications?$select=id,displayName,appId,createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess&$top=999",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "applications.json",
        "/applications",
    )

    oauth2_grants = _fetch_graph(
        "oauth2PermissionGrants?$top=999",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "oauth2_grants.json",
        "/oauth2PermissionGrants",
    )

    risky_users = _fetch_graph(
        "identityProtection/riskyUsers?$filter=riskState eq 'atRisk'",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "risky_users.json",
        "/identityProtection/riskyUsers",
    )

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    seven_days_ago = (now_utc - datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    risk_detections = _fetch_graph(
        f"identityProtection/riskDetections?$filter=activityDateTime ge {seven_days_ago}&$top=500",
        token,
        client_secret,
        ctx,
        log,
        out_dir,
        "risk_detections.json",
        "/identityProtection/riskDetections",
    )

    findings: list[Finding] = []

    # 1. Security Defaults & CA Interaction
    if sec_defaults is not None:
        sec_enabled = bool(sec_defaults.get("isEnabled", False))
        ca_count = len(ca_policies) if ca_policies is not None else 0

        if sec_enabled:
            findings.append(Finding(
                severity="info",
                key="m365-secdefaults-enabled",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="Security Defaults enabled",
                detail="Baseline MFA enforcement is active for all users",
                iso="A.8.5, A.5.16",
            ))
        elif ca_count > 0:
            findings.append(Finding(
                severity="info",
                key="m365-secdefaults-disabled-ca",
                service="ConditionalAccess",
                resource=tenant_resource,
                title=f"Security Defaults disabled — Conditional Access in use ({ca_count} policies)",
                detail="Verify CA policies cover all users and enforce MFA",
                iso="A.8.5, A.5.16",
            ))
        elif ca_policies is not None:
            findings.append(Finding(
                severity="critical",
                key="m365-secdefaults-off-noca",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="Security Defaults disabled with NO Conditional Access policies",
                detail="No baseline MFA enforcement — accounts are protected only by passwords",
                iso="A.8.5, A.5.16",
            ))

    # 2. Global Administrator count
    ga_members: list[str] = []
    ga_upns: list[str] = []
    if directory_roles is not None:
        ga_role = next(
            (r for r in directory_roles if r.get("displayName") == "Global Administrator"),
            None,
        )
        if ga_role:
            for m in ga_role.get("members", []):
                upn = m.get("userPrincipalName") or m.get("displayName") or m.get("id") or "unknown"
                ga_members.append(upn)
                if m.get("userPrincipalName"):
                    ga_upns.append(m["userPrincipalName"])

        ga_count = len(ga_members)
        if ga_count > 5:
            findings.append(Finding(
                severity="high",
                key="m365-ga-count",
                service="EntraID",
                resource=tenant_resource,
                title=f"Excessive Global Administrators ({ga_count})",
                detail=f"Best practice: 2-4. Current: {cap_list(ga_members)}",
                iso="A.5.15, A.8.2",
            ))
        elif ga_count == 1:
            findings.append(Finding(
                severity="medium",
                key="m365-ga-count",
                service="EntraID",
                resource=ga_members[0],
                title="Only 1 Global Administrator (single point of failure)",
                detail=cap_list(ga_members),
                iso="A.5.15, A.8.2",
            ))
        elif ga_count > 1:
            findings.append(Finding(
                severity="info",
                key="m365-ga-count",
                service="EntraID",
                resource=tenant_resource,
                title=f"Global Administrator count: {ga_count}",
                detail=cap_list(ga_members),
                iso="A.5.15, A.8.2",
            ))

    # 3. Admins without MFA registered
    if directory_roles is not None and mfa_reg is not None:
        mfa_map = {
            item.get("userPrincipalName", "").lower(): bool(item.get("isMfaRegistered", False))
            for item in mfa_reg
            if item.get("userPrincipalName")
        }

        ga_no_mfa = [u for u in ga_upns if not mfa_map.get(u.lower(), False)]
        if ga_no_mfa:
            findings.append(Finding(
                severity="critical",
                key="m365-ga-nomfa",
                service="EntraID",
                resource=tenant_resource,
                title="Global Administrator(s) without MFA registered",
                detail=f"{len(ga_no_mfa)} admin(s): {cap_list(ga_no_mfa)}",
                iso="A.8.2, A.8.5",
            ))

        priv_upns_set: set[str] = set()
        for r in directory_roles:
            for m in r.get("members", []):
                u = m.get("userPrincipalName")
                if u:
                    priv_upns_set.add(u)

        priv_no_mfa = sorted(u for u in priv_upns_set if not mfa_map.get(u.lower(), False))
        if priv_no_mfa:
            findings.append(Finding(
                severity="high",
                key="m365-priv-nomfa",
                service="EntraID",
                resource=tenant_resource,
                title="Privileged role holders without MFA registered",
                detail=f"{len(priv_no_mfa)} user(s): {cap_list(priv_no_mfa)}",
                iso="A.8.2, A.8.5",
            ))

    # 4. MFA compliance (all users) & SSPR
    if mfa_reg is not None:
        total_active = sum(1 for u in users if u.get("accountEnabled") is True) if users is not None else len(mfa_reg)
        total_mfa = sum(1 for item in mfa_reg if item.get("isMfaRegistered") is True)
        no_mfa_users = [
            item.get("userPrincipalName", "")
            for item in mfa_reg
            if not item.get("isMfaRegistered") and item.get("userPrincipalName")
        ]
        pct = (total_mfa * 100 // total_active) if total_active > 0 else 0
        pct = min(100, pct)

        if no_mfa_users:
            findings.append(Finding(
                severity="medium",
                key="m365-mfa-compliance",
                service="EntraID",
                resource=tenant_resource,
                title=f"Users without MFA registered ({pct}% compliance)",
                detail=f"{len(no_mfa_users)} user(s): {cap_list(no_mfa_users, 20)}",
                iso="A.8.5",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="m365-mfa-compliance",
                service="EntraID",
                resource=tenant_resource,
                title=f"MFA compliance: {pct}%",
                detail=f"{total_mfa}/{total_active} active users have MFA registered",
                iso="A.8.5",
            ))

        no_sspr = sum(1 for item in mfa_reg if not item.get("isSsprRegistered"))
        if no_sspr > 0:
            findings.append(Finding(
                severity="low",
                key="m365-sspr-not-registered",
                service="EntraID",
                resource=tenant_resource,
                title="Users not registered for Self-Service Password Reset",
                detail=f"{no_sspr} user(s)",
                iso="A.8.5",
            ))

    # 5. Guest users
    if users is not None:
        guests = [u for u in users if u.get("userType") == "Guest"]
        active_guests = [u for u in guests if u.get("accountEnabled") is True]
        guest_upns = [
            u.get("userPrincipalName") or u.get("displayName") or u.get("id") or "unknown"
            for u in active_guests
        ]

        if guests:
            findings.append(Finding(
                severity="medium",
                key="m365-guests",
                service="EntraID",
                resource=tenant_resource,
                title="Active guest (external) users",
                detail=f"{len(active_guests)} active guest(s) out of {len(guests)} total — review for necessity: {cap_list(guest_upns, 15)}",
                iso="A.5.18, A.5.19",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="m365-guests",
                service="EntraID",
                resource=tenant_resource,
                title="No guest users in tenant",
                detail="",
                iso="A.5.19",
            ))

    # 6. Stale accounts (no sign-in in >90 days)
    if users is not None:
        cutoff_90d = now_utc - datetime.timedelta(days=90)
        stale_users: list[str] = []
        never_signed_count = 0

        for u in users:
            if u.get("accountEnabled") is True and u.get("userType") == "Member":
                sign_in_act = u.get("signInActivity") or {}
                last_dt_str = sign_in_act.get("lastSignInDateTime")
                last_dt = _parse_utc(last_dt_str)
                upn = u.get("userPrincipalName") or u.get("displayName") or u.get("id") or "unknown"

                if last_dt is None:
                    never_signed_count += 1
                    stale_users.append(upn)
                elif last_dt < cutoff_90d:
                    stale_users.append(upn)

        if stale_users:
            findings.append(Finding(
                severity="medium",
                key="m365-stale-accounts",
                service="EntraID",
                resource=tenant_resource,
                title="Active accounts with no sign-in in >90 days",
                detail=f"{len(stale_users)} account(s) ({never_signed_count} never signed in): {cap_list(stale_users, 10)}",
                iso="A.5.18",
            ))

    # 7. Conditional Access analysis
    if ca_policies is not None:
        ca_total = len(ca_policies)
        ca_enabled = sum(1 for p in ca_policies if p.get("state") == "enabled")
        ca_report = sum(1 for p in ca_policies if p.get("state") == "enabledForReportingButNotEnforced")
        ca_disabled = sum(1 for p in ca_policies if p.get("state") == "disabled")

        findings.append(Finding(
            severity="info",
            key="m365-ca-summary",
            service="ConditionalAccess",
            resource=tenant_resource,
            title="Conditional Access policy summary",
            detail=f"{ca_total} total — {ca_enabled} enabled, {ca_report} report-only, {ca_disabled} disabled",
            iso="A.5.16, A.8.5",
        ))

        if ca_report > 0:
            ca_report_names = [
                p.get("displayName", "Unnamed")
                for p in ca_policies
                if p.get("state") == "enabledForReportingButNotEnforced"
            ]
            findings.append(Finding(
                severity="low",
                key="m365-ca-reportonly",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="CA policies in report-only mode (not enforcing)",
                detail=f"{ca_report} policy(ies): {cap_list(ca_report_names)}",
                iso="A.5.16",
            ))

        # Check if any enabled policy enforces MFA for ALL users
        has_mfa_all = False
        legacy_block_count = 0
        excluded_policies: list[str] = []

        for p in ca_policies:
            if p.get("state") != "enabled":
                continue

            cond = p.get("conditions") or {}
            cond_users = cond.get("users") or {}
            incl = cond_users.get("includeUsers") or []
            excl = cond_users.get("excludeUsers") or []

            # Check MFA for all
            incl_all = ("All" in incl or "all" in incl) if isinstance(incl, list) else str(incl).lower() == "all"
            grant = p.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []
            if isinstance(built_in, str):
                built_in = [built_in]
            built_in_lower = [c.lower() for c in built_in]

            if incl_all and "mfa" in built_in_lower:
                has_mfa_all = True

            # Check excluded users
            if excl and isinstance(excl, list) and len(excl) > 0:
                p_name = p.get("displayName", "Unnamed")
                excluded_policies.append(f"{p_name}: {len(excl)} excluded")

            # Check legacy auth blocking
            client_apps = cond.get("clientAppTypes") or []
            if isinstance(client_apps, str):
                client_apps = [client_apps]
            client_apps_lower = [a.lower() for a in client_apps]
            if ("exchangeactivesync" in client_apps_lower or "other" in client_apps_lower) and "block" in built_in_lower:
                legacy_block_count += 1

        if not has_mfa_all and ca_enabled > 0:
            findings.append(Finding(
                severity="high",
                key="m365-ca-no-mfa-all",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="No CA policy enforces MFA for ALL users",
                detail="Verify MFA coverage via group-targeted policies — no single policy covers all users with MFA grant",
                iso="A.8.5",
            ))

        if excluded_policies:
            findings.append(Finding(
                severity="medium",
                key="m365-ca-exclusions",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="CA policies with user exclusions",
                detail=f"{len(excluded_policies)} policy(ies) have excluded users — review for gaps: {cap_list(excluded_policies)}",
                iso="A.5.16",
            ))

        if legacy_block_count == 0:
            findings.append(Finding(
                severity="high",
                key="m365-ca-legacy-auth",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="No CA policy blocks legacy authentication",
                detail="Legacy auth protocols (IMAP, POP3, SMTP, ActiveSync) bypass MFA — create a blocking policy",
                iso="A.8.5, A.5.16",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="m365-ca-legacy-auth",
                service="ConditionalAccess",
                resource=tenant_resource,
                title="Legacy authentication is blocked by CA policy",
                detail=f"{legacy_block_count} policy(ies) block legacy auth protocols",
                iso="A.8.5",
            ))

    # 8. OAuth2 delegated permission grants
    if oauth2_grants is not None:
        grant_count = len(oauth2_grants)
        all_principals = sum(1 for g in oauth2_grants if g.get("consentType") == "AllPrincipals")
        mail_rw = sum(
            1 for g in oauth2_grants
            if re.search(r"\b(Mail\.ReadWrite|Mail\.Send)\b", g.get("scope") or "", re.IGNORECASE)
        )
        files_rw = sum(
            1 for g in oauth2_grants
            if re.search(r"\bFiles\.ReadWrite\b", g.get("scope") or "", re.IGNORECASE)
        )

        findings.append(Finding(
            severity="info",
            key="m365-oauth-allprincipals",
            service="EntraID",
            resource=tenant_resource,
            title="OAuth2 delegated permission grants",
            detail=f"{grant_count} total grant(s), {all_principals} with admin consent (AllPrincipals)",
            iso="A.5.23",
        ))

        if mail_rw > 0:
            findings.append(Finding(
                severity="medium",
                key="m365-oauth-sensitive-mail",
                service="EntraID",
                resource=tenant_resource,
                title="Apps with Mail.ReadWrite or Mail.Send delegated consent",
                detail=f"{mail_rw} grant(s) — review for data exfiltration risk",
                iso="A.5.23, A.8.3",
            ))

        if files_rw > 0:
            findings.append(Finding(
                severity="low",
                key="m365-oauth-sensitive-files",
                service="EntraID",
                resource=tenant_resource,
                title="Apps with Files.ReadWrite delegated consent",
                detail=f"{files_rw} grant(s)",
                iso="A.5.23, A.8.3",
            ))

    # 9. App registrations credentials
    if applications is not None:
        soon_30d = now_utc + datetime.timedelta(days=30)
        expired_apps: list[str] = []
        expiring_apps: list[str] = []

        for app in applications:
            name = app.get("displayName") or app.get("appId") or app.get("id") or "Unnamed App"
            creds = app.get("passwordCredentials") or []
            has_expired = False
            has_expiring = False
            for cred in creds:
                end_dt = _parse_utc(cred.get("endDateTime"))
                if end_dt:
                    if end_dt < now_utc:
                        has_expired = True
                    elif now_utc <= end_dt < soon_30d:
                        has_expiring = True
            if has_expired:
                expired_apps.append(name)
            if has_expiring:
                expiring_apps.append(name)

        expired_apps = sorted(set(expired_apps))
        expiring_apps = sorted(set(expiring_apps))

        if expired_apps:
            findings.append(Finding(
                severity="medium",
                key="m365-app-creds-expired",
                service="EntraID",
                resource=tenant_resource,
                title="App registrations with expired credentials",
                detail=f"{len(expired_apps)} app(s) — may indicate abandoned apps: {cap_list(expired_apps)}",
                iso="A.5.23, A.5.18",
            ))

        if expiring_apps:
            findings.append(Finding(
                severity="low",
                key="m365-app-creds-expiring",
                service="EntraID",
                resource=tenant_resource,
                title="App credentials expiring within 30 days",
                detail=f"{len(expiring_apps)} app(s): {cap_list(expiring_apps)}",
                iso="A.5.23",
            ))

    # 10. Risky users
    if risky_users is not None:
        if risky_users:
            risky_high = sum(1 for u in risky_users if (u.get("riskLevel") or "").lower() == "high")
            risky_med = sum(1 for u in risky_users if (u.get("riskLevel") or "").lower() == "medium")
            risky_list = [
                u.get("userPrincipalName") or u.get("id") or "unknown"
                for u in risky_users
            ]
            sev = "high" if risky_high > 0 else "medium"
            findings.append(Finding(
                severity=sev,
                key="m365-risky-users",
                service="EntraID",
                resource=tenant_resource,
                title="Users flagged as at-risk",
                detail=f"{len(risky_users)} user(s) ({risky_high} high, {risky_med} medium): {cap_list(risky_list, 10)}",
                iso="A.8.16",
            ))
        else:
            findings.append(Finding(
                severity="info",
                key="m365-risky-users",
                service="EntraID",
                resource=tenant_resource,
                title="No users currently flagged as at-risk",
                detail="",
                iso="A.8.16",
            ))

    # 11. Risk detections (last 7 days)
    if risk_detections is not None and len(risk_detections) > 0:
        det_high = sum(1 for d in risk_detections if (d.get("riskLevel") or "").lower() == "high")
        type_counts = Counter(d.get("riskEventType") or "unknown" for d in risk_detections)
        det_types_summary = ", ".join(f"{t} (x{cnt})" for t, cnt in type_counts.items())
        findings.append(Finding(
            severity="medium",
            key="m365-risk-detections",
            service="EntraID",
            resource=tenant_resource,
            title="Risk detections in last 7 days",
            detail=f"{len(risk_detections)} detection(s) ({det_high} high): {det_types_summary}",
            iso="A.8.16",
        ))

    # 12. Domains
    if domains is not None:
        domain_names = [d.get("id") or "unknown" for d in domains if d.get("id")]
        findings.append(Finding(
            severity="info",
            key="m365-domains",
            service="EntraID",
            resource=tenant_resource,
            title="Registered domains",
            detail=f"{len(domains)} domain(s): {cap_list(domain_names)}",
            iso="A.5.23",
        ))

        unverified = [d.get("id") or "unknown" for d in domains if d.get("isVerified") is False]
        if unverified:
            findings.append(Finding(
                severity="medium",
                key="m365-unverified-domains",
                service="EntraID",
                resource=tenant_resource,
                title="Unverified domains",
                detail=f"{len(unverified)} domain(s) not verified: {cap_list(unverified)}",
                iso="A.5.23",
            ))

    return findings
