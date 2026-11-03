"""Google Workspace posture assessment module driven by GAM CLI.

Exports and evaluates identity, authentication, group, device, and OAuth
configurations against security baselines and ISO 27001 controls.
"""

from __future__ import annotations

import csv
import datetime
import io
import os
import re
import shlex
import shutil
import time
from collections import defaultdict
from pathlib import Path

from recon.config import RunContext
from recon.runner import Logger, have, record_virtual_cmd, run_cmd
from recon.saas.common import Finding, cap_list, save_raw


def _clean_gam_csv(raw_text: str) -> str:
    """Strip carriage returns, blank lines, and GAM progress prefixes."""
    cleaned_lines = []
    for line in raw_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in ("Getting ", "Got ", "Retrieving ", "Printing ")):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _parse_csv_rows(csv_text: str) -> list[dict[str, str]]:
    """Parse cleaned CSV into a list of row dictionaries."""
    if not csv_text.strip():
        return []
    reader = csv.reader(io.StringIO(csv_text))
    try:
        header = next(reader)
    except StopIteration:
        return []
    headers = [h.strip() for h in header]
    rows: list[dict[str, str]] = []
    for raw_row in reader:
        if not raw_row or not any(raw_row):
            continue
        row_dict: dict[str, str] = {}
        for idx, h in enumerate(headers):
            val = raw_row[idx].strip() if idx < len(raw_row) else ""
            row_dict[h] = val
        rows.append(row_dict)
    return rows


def _get_field(row: dict[str, str], *field_names: str, default: str = "") -> str:
    """Retrieve field value case-insensitively from a row dict."""
    for f in field_names:
        if f in row and row[f] != "":
            return row[f]
    lower_map = {k.lower(): v for k, v in row.items()}
    for f in field_names:
        if f.lower() in lower_map and lower_map[f.lower()] != "":
            return lower_map[f.lower()]
    return default


def _parse_utc_iso(date_str: str) -> datetime.datetime | None:
    """Parse an ISO date string into a UTC timezone-aware datetime."""
    if not date_str or date_str in ("Never", "None", "-"):
        return None
    s = date_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except (ValueError, TypeError):
        pass
    try:
        return datetime.datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None


def _find_gam(log: Logger) -> str | None:
    """Resolve GAM binary path from GAM_PATH or system PATH."""
    gam_env = os.environ.get("GAM_PATH")
    if gam_env:
        return gam_env
    if have("gam"):
        return "gam"
    log.warn("Google Workspace posture skipped: GAM not found or not authenticated (set GAM_PATH, super admin required)")
    return None


def _run_export(
    gam_bin: str,
    args: list[str],
    name: str,
    ctx: RunContext,
    log: Logger,
    out_dir: Path,
) -> list[dict[str, str]] | None:
    """Execute a GAM command, record evidence, save raw CSV, and return parsed rows."""
    cmd_list = [gam_bin] + args
    cmd_str = shlex.join(cmd_list)
    t0 = time.perf_counter()
    res = run_cmd(cmd_list, timeout=120)
    duration_ms = int((time.perf_counter() - t0) * 1000)

    if res.returncode != 0:
        err_msg = (res.stderr or res.stdout or "Command failed").strip()
        record_virtual_cmd(
            ctx.console_dir,
            "S",
            cmd_str,
            err_msg[:300],
            title=f"gam {' '.join(args[:2])}",
            returncode=res.returncode,
            duration_ms=duration_ms,
        )
        log.warn(f"Google Workspace: '{cmd_str}' failed - checks depending on it skipped")
        return None

    cleaned = _clean_gam_csv(res.stdout)
    save_raw(out_dir, f"{name}.csv", cleaned)

    rows = _parse_csv_rows(cleaned)
    lines = cleaned.splitlines()
    header = lines[0] if lines else ""
    summary = f"{len(rows)} rows\n{header}" if header else f"{len(rows)} rows"

    record_virtual_cmd(
        ctx.console_dir,
        "S",
        cmd_str,
        summary,
        title=f"gam {' '.join(args[:2])}",
        returncode=res.returncode,
        duration_ms=duration_ms,
    )
    return rows


def run(ctx: RunContext, log: Logger, out_dir: Path) -> list[Finding]:
    """Execute Google Workspace posture assessment and return list of findings."""
    gam_bin = _find_gam(log)
    if not gam_bin:
        return []

    # Verify authentication and super admin access via read-only command
    t0 = time.perf_counter()
    auth_cmd = [gam_bin, "info", "domain"]
    auth_str = shlex.join(auth_cmd)
    auth_res = run_cmd(auth_cmd, timeout=30)
    duration_ms = int((time.perf_counter() - t0) * 1000)

    record_virtual_cmd(
        ctx.console_dir,
        "S",
        auth_str,
        (auth_res.combined[:300] if auth_res.returncode == 0 else auth_res.stderr or auth_res.stdout or "Auth check failed").strip(),
        title="gam info domain",
        returncode=auth_res.returncode,
        duration_ms=duration_ms,
    )

    if auth_res.returncode != 0:
        log.warn("Google Workspace posture skipped: GAM not found or not authenticated (set GAM_PATH, super admin required)")
        return []

    findings: list[Finding] = []
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    cutoff_90d = now_utc - datetime.timedelta(days=90)

    # ── 1. Data Exports ──────────────────────────────────────────────────────────
    users_rows = _run_export(
        gam_bin,
        [
            "print",
            "users",
            "fields",
            "primaryEmail,isAdmin,isDelegatedAdmin,isEnforcedIn2Sv,isEnrolledIn2Sv,suspended,orgUnitPath,lastLoginTime,creationTime",
        ],
        "users",
        ctx,
        log,
        out_dir,
    )

    admins_rows = _run_export(
        gam_bin,
        ["print", "admins"],
        "admins",
        ctx,
        log,
        out_dir,
    )

    domains_rows = _run_export(
        gam_bin,
        ["print", "domains"],
        "domains",
        ctx,
        log,
        out_dir,
    )

    groups_rows = _run_export(
        gam_bin,
        [
            "print",
            "groups",
            "fields",
            "email,name,whocanjoin,whocanviewmembership,whocanviewgroup,allowexternalmembers,whocanpostmessage",
        ],
        "groups",
        ctx,
        log,
        out_dir,
    )

    group_members_rows = _run_export(
        gam_bin,
        ["print", "group-members"],
        "group_members",
        ctx,
        log,
        out_dir,
    )

    mobile_rows = _run_export(
        gam_bin,
        ["print", "mobile", "fields", "email,model,os,type,status,deviceCompromisedStatus"],
        "mobile_devices",
        ctx,
        log,
        out_dir,
    )

    chrome_rows = _run_export(
        gam_bin,
        ["print", "cros", "fields", "serialNumber,osVersion,lastSync,orgUnitPath,status"],
        "chrome_devices",
        ctx,
        log,
        out_dir,
    )

    tokens_rows = _run_export(
        gam_bin,
        ["print", "tokens"],
        "oauth_tokens",
        ctx,
        log,
        out_dir,
    )

    asps_rows = _run_export(
        gam_bin,
        ["all", "users", "print", "asps", "oneitemperrow"],
        "app_specific_passwords",
        ctx,
        log,
        out_dir,
    )

    # ── 2. Admin & Domain Indexes ────────────────────────────────────────────────
    org_domains: set[str] = set()
    if domains_rows is not None:
        for r in domains_rows:
            d = _get_field(r, "domainName", "domain")
            if not d and r:
                d = next(iter(r.values()))
            d_clean = d.strip().lower()
            if d_clean and d_clean not in ("domain", "domainname"):
                org_domains.add(d_clean)

    admin_roles_by_user: dict[str, list[str]] = defaultdict(list)
    super_admins: list[str] = []
    if admins_rows is not None:
        for r in admins_rows:
            role = _get_field(r, "role", "roleName")
            user = _get_field(r, "user", "userEmail", "assignedTo")
            svcacct = _get_field(r, "serviceAccount", "svcacct")
            if role.lower() in ("role", "rolename"):
                continue

            target = user or svcacct
            if target and role:
                admin_roles_by_user[target].append(role)

            if role in ("_SEED_ADMIN_ROLE", "Super Admin"):
                if target and target not in super_admins:
                    super_admins.append(target)

    # ── 3. Super Admin Count Check ───────────────────────────────────────────────
    if admins_rows is not None:
        sa_count = len(super_admins)
        sa_list_str = cap_list(super_admins)
        if sa_count > 4:
            findings.append(
                Finding(
                    severity="high",
                    key="gws-super-admin-count",
                    service="Workspace",
                    resource="tenant",
                    title=f"Excessive super admin accounts ({sa_count})",
                    detail=f"Best practice: 2-3. Current: {sa_list_str}",
                    iso="A.5.15, A.8.2",
                )
            )
        elif sa_count == 1:
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-super-admin-count",
                    service="Workspace",
                    resource="tenant",
                    title="Only 1 super admin (single point of failure)",
                    detail=f"Current: {sa_list_str}",
                    iso="A.5.15, A.8.2",
                )
            )
        else:
            findings.append(
                Finding(
                    severity="info",
                    key="gws-super-admin-count",
                    service="Workspace",
                    resource="tenant",
                    title=f"Super admin count: {sa_count}",
                    detail=f"Current: {sa_list_str}",
                    iso="A.5.15, A.8.2",
                )
            )

    # ── 4. User Checks (Suspended Admins, 2FA, Stale, Archived OU) ───────────────
    if users_rows is not None:
        total_active = 0
        enrolled_2fa_count = 0

        for r in users_rows:
            email = _get_field(r, "primaryEmail", "email")
            if not email or email.lower() in ("primaryemail", "email"):
                continue

            is_admin = _get_field(r, "isAdmin").lower() in ("true", "1")
            is_delegated = _get_field(r, "isDelegatedAdmin").lower() in ("true", "1")
            is_enforced = _get_field(r, "isEnforcedIn2Sv").lower() in ("true", "1")
            is_enrolled = _get_field(r, "isEnrolledIn2Sv").lower() in ("true", "1")
            suspended = _get_field(r, "suspended").lower() in ("true", "1")
            ou = _get_field(r, "orgUnitPath")
            last_login = _get_field(r, "lastLoginTime")

            # Admin roles on suspended accounts
            if suspended:
                if is_admin:
                    findings.append(
                        Finding(
                            severity="high",
                            key="gws-admin-suspended-super",
                            service="Workspace",
                            resource=email,
                            title="Super Admin role active on suspended account",
                            detail=f"{email} (OU: {ou})",
                            iso="A.8.2, A.5.15",
                        )
                    )
                if is_delegated:
                    role_count = len(admin_roles_by_user.get(email, []))
                    findings.append(
                        Finding(
                            severity="high",
                            key="gws-admin-suspended-delegated",
                            service="Workspace",
                            resource=email,
                            title="Delegated admin roles active on suspended account",
                            detail=f"{email} — {role_count} role(s) (OU: {ou})",
                            iso="A.8.2, A.5.15",
                        )
                    )
                continue

            # Active account checks
            total_active += 1
            if is_enrolled:
                enrolled_2fa_count += 1
            else:
                findings.append(
                    Finding(
                        severity="medium",
                        key="gws-user-no-2fa",
                        service="Workspace",
                        resource=email,
                        title="2FA not enrolled",
                        detail=email,
                        iso="A.8.5",
                    )
                )

            # Admin accounts without 2FA
            is_admin_account = is_admin or (email in admin_roles_by_user)
            if is_admin_account and not is_enrolled:
                roles = admin_roles_by_user.get(email) or (["Super Admin"] if is_admin else ["Admin"])
                findings.append(
                    Finding(
                        severity="critical",
                        key="gws-admin-no-2fa",
                        service="Workspace",
                        resource=email,
                        title="Admin account without 2FA enrolled",
                        detail=f"{email} — roles: {', '.join(roles)}",
                        iso="A.8.2, A.8.5",
                    )
                )

            # 2FA enforced but not enrolled (grace period)
            if is_enforced and not is_enrolled:
                findings.append(
                    Finding(
                        severity="high",
                        key="gws-2fa-grace-period",
                        service="Workspace",
                        resource=email,
                        title="2FA enforced but not enrolled (grace period)",
                        detail=f"{email} — account can still log in without 2FA",
                        iso="A.8.5",
                    )
                )

            # Stale accounts (never logged in or inactive >90 days)
            if not last_login or last_login in ("Never", "None", "-"):
                findings.append(
                    Finding(
                        severity="medium",
                        key="gws-account-never-logged-in",
                        service="Workspace",
                        resource=email,
                        title="Active account has never logged in",
                        detail=f"{email} (OU: {ou})",
                        iso="A.5.18",
                    )
                )
            else:
                dt_login = _parse_utc_iso(last_login)
                if dt_login and dt_login < cutoff_90d:
                    findings.append(
                        Finding(
                            severity="medium",
                            key="gws-account-inactive-90d",
                            service="Workspace",
                            resource=email,
                            title="Active account inactive for >90 days",
                            detail=f"{email} — last login: {last_login} (OU: {ou})",
                            iso="A.5.18",
                        )
                    )

            # Active accounts in /archived OU
            if ou.lower().startswith("/archived"):
                findings.append(
                    Finding(
                        severity="high",
                        key="gws-archived-ou-active-account",
                        service="Workspace",
                        resource=email,
                        title="Active (unsuspended) account in /archived OU",
                        detail=f"{email} (OU: {ou}) — should be suspended or moved",
                        iso="A.5.11, A.5.18",
                    )
                )

        # 2FA compliance summary
        pct = (enrolled_2fa_count * 100 // total_active) if total_active > 0 else 0
        findings.append(
            Finding(
                severity="info",
                key="gws-2fa-compliance",
                service="Workspace",
                resource="tenant",
                title=f"2FA compliance: {pct}%",
                detail=f"{enrolled_2fa_count}/{total_active} active accounts enrolled",
                iso="A.8.5",
            )
        )

    # ── 5. Groups Security Checks ────────────────────────────────────────────────
    if groups_rows is not None:
        self_join_groups: list[str] = []
        broad_view_groups: list[str] = []
        ext_allowed_groups: list[str] = []
        anyone_post_groups: list[str] = []

        for r in groups_rows:
            grp_email = _get_field(r, "email", "name")
            if not grp_email or grp_email.lower() in ("email", "name"):
                continue

            whocanjoin = _get_field(r, "whocanjoin")
            whocanviewmembership = _get_field(r, "whocanviewmembership")
            whocanviewgroup = _get_field(r, "whocanviewgroup")
            allowexternal = _get_field(r, "allowexternalmembers").lower() in ("true", "1")
            whocanpost = _get_field(r, "whocanpostmessage")

            if whocanjoin == "ALL_IN_DOMAIN_CAN_JOIN":
                self_join_groups.append(grp_email)
            if "ALL_IN_DOMAIN_CAN_VIEW" in (whocanviewmembership, whocanviewgroup):
                broad_view_groups.append(grp_email)
            if allowexternal:
                ext_allowed_groups.append(grp_email)
            if whocanpost == "ANYONE_CAN_POST":
                anyone_post_groups.append(grp_email)

        if self_join_groups:
            findings.append(
                Finding(
                    severity="high",
                    key="gws-group-unrestricted-join",
                    service="Workspace",
                    resource="groups",
                    title="Groups allowing unrestricted self-join",
                    detail=f"{len(self_join_groups)} group(s) with ALL_IN_DOMAIN_CAN_JOIN: {cap_list(self_join_groups)}",
                    iso="A.5.15",
                )
            )
        else:
            findings.append(
                Finding(
                    severity="info",
                    key="gws-group-unrestricted-join",
                    service="Workspace",
                    resource="groups",
                    title="No groups with unrestricted self-join",
                    detail="All groups require invitation or approval",
                    iso="A.5.15",
                )
            )

        if broad_view_groups:
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-group-broad-visibility",
                    service="Workspace",
                    resource="groups",
                    title="Groups with broad conversation visibility",
                    detail=f"{len(broad_view_groups)} group(s) with ALL_IN_DOMAIN_CAN_VIEW: {cap_list(broad_view_groups)}",
                    iso="A.5.15",
                )
            )

        if ext_allowed_groups:
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-group-allow-external",
                    service="Workspace",
                    resource="groups",
                    title="Groups allowing external members",
                    detail=f"{len(ext_allowed_groups)} group(s): {cap_list(ext_allowed_groups)}",
                    iso="A.5.19",
                )
            )

        if anyone_post_groups:
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-group-anyone-can-post",
                    service="Workspace",
                    resource="groups",
                    title="Groups accepting posts from anyone (inc. external)",
                    detail=f"{len(anyone_post_groups)} group(s): {cap_list(anyone_post_groups)}",
                    iso="A.5.14, A.5.19",
                )
            )

    # ── 6. External Group Members ────────────────────────────────────────────────
    if group_members_rows is not None and org_domains:
        ext_member_groups: dict[str, list[str]] = defaultdict(list)
        total_ext_members = 0

        for r in group_members_rows:
            grp = _get_field(r, "group", "groupEmail")
            m_type = _get_field(r, "type").upper()
            email = _get_field(r, "email", "memberEmail")

            if not email or m_type == "GROUP" or email.lower() in ("email", "memberemail"):
                continue

            domain = email.split("@")[-1].lower() if "@" in email else ""
            if domain and domain not in org_domains:
                total_ext_members += 1
                ext_member_groups[grp].append(email)

        if total_ext_members > 0:
            details = [f"{g} -> {cap_list(m, 5)}" for g, m in ext_member_groups.items()]
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-group-external-members",
                    service="Workspace",
                    resource="groups",
                    title=f"External members found in {len(ext_member_groups)} group(s)",
                    detail=f"{total_ext_members} external member(s): {cap_list(details, 10)}",
                    iso="A.5.19",
                )
            )
        else:
            findings.append(
                Finding(
                    severity="info",
                    key="gws-group-external-members",
                    service="Workspace",
                    resource="groups",
                    title="No external group members detected",
                    detail="All members belong to org domains",
                    iso="A.5.19",
                )
            )

    # ── 7. Mobile Devices ────────────────────────────────────────────────────────
    if mobile_rows is not None:
        total_mobile = 0
        approved_mobile = 0
        pending_items: list[str] = []
        wiped_items: list[str] = []
        compromised_items: list[str] = []

        for r in mobile_rows:
            email = _get_field(r, "email")
            if not email or email.lower() == "email":
                continue

            total_mobile += 1
            model = _get_field(r, "model")
            status = _get_field(r, "status").upper()
            comp_status = _get_field(r, "deviceCompromisedStatus", "compStatus")

            item_desc = f"{email} ({model})" if model else email

            if status == "APPROVED":
                approved_mobile += 1
            elif status == "PENDING":
                pending_items.append(item_desc)
            elif status == "ACCOUNT_WIPED":
                wiped_items.append(item_desc)

            if comp_status and comp_status not in ("No compromise detected", "Undetected"):
                compromised_items.append(f"{item_desc}: {comp_status}")

        if compromised_items:
            findings.append(
                Finding(
                    severity="high",
                    key="gws-device-mobile-compromised",
                    service="Workspace",
                    resource="devices",
                    title="Compromised mobile devices detected",
                    detail=f"{len(compromised_items)} device(s) — {cap_list(compromised_items)}",
                    iso="A.8.1",
                )
            )

        if wiped_items:
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-device-mobile-wiped",
                    service="Workspace",
                    resource="devices",
                    title="Devices with ACCOUNT_WIPED status (possible incomplete offboarding)",
                    detail=f"{len(wiped_items)} device(s) — {cap_list(wiped_items)}",
                    iso="A.8.1, A.5.11",
                )
            )

        if pending_items:
            findings.append(
                Finding(
                    severity="low",
                    key="gws-device-mobile-pending",
                    service="Workspace",
                    resource="devices",
                    title="Mobile devices pending approval",
                    detail=f"{len(pending_items)} device(s) — {cap_list(pending_items)}",
                    iso="A.8.1",
                )
            )

        if total_mobile > 0:
            findings.append(
                Finding(
                    severity="info",
                    key="gws-device-mobile-summary",
                    service="Workspace",
                    resource="devices",
                    title="Mobile device fleet summary",
                    detail=f"{total_mobile} total, {approved_mobile} approved, {len(pending_items)} pending, {len(wiped_items)} wiped, {len(compromised_items)} compromised",
                    iso="A.8.1",
                )
            )

    # ── 8. Chrome OS Devices ─────────────────────────────────────────────────────
    if chrome_rows is not None:
        total_cros = 0
        stale_cros_items: list[str] = []

        for r in chrome_rows:
            serial = _get_field(r, "serialNumber", "serial")
            if not serial or serial.lower() in ("serialnumber", "serial"):
                continue

            total_cros += 1
            last_sync = _get_field(r, "lastSync")
            ou = _get_field(r, "orgUnitPath")

            dt_sync = _parse_utc_iso(last_sync)
            if dt_sync and dt_sync < cutoff_90d:
                stale_cros_items.append(f"{serial} ({ou}, last sync: {last_sync})")

        if stale_cros_items:
            findings.append(
                Finding(
                    severity="low",
                    key="gws-device-cros-stale-90d",
                    service="Workspace",
                    resource="devices",
                    title="Chrome OS devices not synced in >90 days",
                    detail=f"{len(stale_cros_items)}/{total_cros} device(s) — {cap_list(stale_cros_items)}",
                    iso="A.8.1",
                )
            )

        if total_cros > 0:
            findings.append(
                Finding(
                    severity="info",
                    key="gws-device-cros-summary",
                    service="Workspace",
                    resource="devices",
                    title="Chrome OS fleet summary",
                    detail=f"{total_cros} device(s)",
                    iso="A.8.1",
                )
            )

    # ── 9. OAuth Tokens Analysis ─────────────────────────────────────────────────
    if tokens_rows is not None:
        total_tokens = len(tokens_rows)
        unique_users: set[str] = set()
        unique_apps: set[str] = set()

        mail_apps: list[str] = []
        drive_apps: list[str] = []
        admin_sdk_apps: list[str] = []
        calendar_apps: list[str] = []
        contacts_apps: list[str] = []

        for r in tokens_rows:
            user = _get_field(r, "user", "User", "primaryEmail")
            app = _get_field(r, "displayText", "appName", "clientName", "app")
            scopes = _get_field(r, "scopes", "scope")
            row_full = " ".join(r.values())

            if not user and r:
                user = next(iter(r.values()))
            if not app and len(r) >= 3:
                app = list(r.values())[2]

            if user:
                unique_users.add(user)
            if app:
                unique_apps.add(app)

            app_label = app or user or "Unknown App"
            scope_tokens = [s.strip() for s in re.split(r"[\s,]+", scopes) if s.strip()]

            # Mail grants
            if "mail.google.com" in row_full:
                mail_apps.append(app_label)

            # Drive full grant
            has_drive_full = any(s == "https://www.googleapis.com/auth/drive" or s.endswith("/auth/drive") for s in scope_tokens)
            if has_drive_full or "googleapis.com/auth/drive " in row_full:
                drive_apps.append(app_label)

            # Admin SDK
            has_admin_sdk = any(
                any(adm in s for adm in ("admin.directory", "admin.reports", "admin.datatransfer"))
                for s in scope_tokens
            ) or any(adm in row_full for adm in ("admin.directory", "admin.reports", "admin.datatransfer"))
            if has_admin_sdk:
                admin_sdk_apps.append(app_label)

            # Calendar full grant
            has_cal_full = any(s == "https://www.googleapis.com/auth/calendar" or s.endswith("/auth/calendar") for s in scope_tokens)
            if has_cal_full or "googleapis.com/auth/calendar " in row_full:
                calendar_apps.append(app_label)

            # Contacts grant
            has_contacts = any(s == "https://www.googleapis.com/auth/contacts" or s.endswith("/auth/contacts") for s in scope_tokens)
            if has_contacts or "googleapis.com/auth/contacts " in row_full:
                contacts_apps.append(app_label)

        findings.append(
            Finding(
                severity="info",
                key="gws-oauth-token-summary",
                service="Workspace",
                resource="oauth",
                title="OAuth token summary",
                detail=f"{total_tokens} grants across {len(unique_users)} users and {len(unique_apps)} apps",
                iso="A.5.23",
            )
        )

        if admin_sdk_apps:
            findings.append(
                Finding(
                    severity="high",
                    key="gws-oauth-admin-sdk",
                    service="Workspace",
                    resource="oauth",
                    title="Apps with Admin SDK access",
                    detail=f"{len(admin_sdk_apps)} grant(s) across apps: {cap_list(sorted(set(admin_sdk_apps)))} — high privilege, review urgently",
                    iso="A.5.23, A.8.2",
                )
            )

        if mail_apps:
            findings.append(
                Finding(
                    severity="low",
                    key="gws-oauth-gmail-full",
                    service="Workspace",
                    resource="oauth",
                    title="Apps with full Gmail access (mail.google.com)",
                    detail=f"{len(mail_apps)} grant(s) across apps: {cap_list(sorted(set(mail_apps)))} — review for legitimacy",
                    iso="A.5.23, A.8.3",
                )
            )

        if drive_apps:
            findings.append(
                Finding(
                    severity="low",
                    key="gws-oauth-drive-full",
                    service="Workspace",
                    resource="oauth",
                    title="Apps with full Drive access (auth/drive)",
                    detail=f"{len(drive_apps)} grant(s) across apps: {cap_list(sorted(set(drive_apps)))} — review for legitimacy",
                    iso="A.5.23, A.8.3",
                )
            )

        if calendar_apps:
            findings.append(
                Finding(
                    severity="low",
                    key="gws-oauth-calendar-full",
                    service="Workspace",
                    resource="oauth",
                    title="Apps with full Calendar access",
                    detail=f"{len(calendar_apps)} grant(s) across apps: {cap_list(sorted(set(calendar_apps)))}",
                    iso="A.5.23",
                )
            )

        if contacts_apps:
            findings.append(
                Finding(
                    severity="low",
                    key="gws-oauth-contacts",
                    service="Workspace",
                    resource="oauth",
                    title="Apps with Contacts access",
                    detail=f"{len(contacts_apps)} grant(s) across apps: {cap_list(sorted(set(contacts_apps)))}",
                    iso="A.5.23",
                )
            )

    # ── 10. App-Specific Passwords ───────────────────────────────────────────────
    if asps_rows is not None:
        asp_users: set[str] = set()
        for r in asps_rows:
            user = _get_field(r, "User", "user", "primaryEmail")
            if not user and r:
                user = next(iter(r.values()))
            if user and user.lower() not in ("user", "primaryemail"):
                asp_users.add(user)

        asp_count = len(asps_rows)
        if asp_count > 0:
            findings.append(
                Finding(
                    severity="medium",
                    key="gws-asp-in-use",
                    service="Workspace",
                    resource="users",
                    title="App-specific passwords in use (bypasses 2FA)",
                    detail=f"{asp_count} ASP(s) found — users: {cap_list(sorted(asp_users))}",
                    iso="A.8.5",
                )
            )

    return findings
