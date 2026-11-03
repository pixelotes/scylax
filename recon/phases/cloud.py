"""Annex A (Azure), Annex G (Google Cloud), and Annex W (AWS) asset-informed exposure and posture phases."""

from __future__ import annotations

import base64
import csv
import json
from pathlib import Path
import re
import shutil
import socket
from typing import Any, List, Set, Tuple

from recon.config import RunContext
from recon.deps import DependencyManager
from recon.runner import Logger, ev, record_virtual_cmd, run_cmd

__all__ = [
    "phaseA",
    "phaseG",
    "phaseW",
    "_scan_cloud_ips",
    "_run_azure_posture",
    "_run_gcp_posture",
    "_run_aws_posture",
    "_run_prowler",
]


def _is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address belongs to standard private/internal ranges."""
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            octet = int(parts[1])
            if 16 <= octet <= 31:
                return True
    return False


def _write_posture_findings(
    cloud_dir: Path,
    findings: list[tuple[str, str, str, str, str, str]],
) -> None:
    """Write posture findings to <cloud_dir>/posture_findings.tsv.

    Columns: severity \t key \t service \t resource \t title \t detail
    """
    cloud_dir.mkdir(parents=True, exist_ok=True)
    posture_tsv = cloud_dir / "posture_findings.tsv"
    seen: set[str] = set()
    with posture_tsv.open("w", encoding="utf-8") as f:
        for sev, key, service, resource, title, detail in findings:
            sev_clean = str(sev).lower().strip()
            key_clean = str(key).strip()
            service_clean = str(service).strip()
            resource_clean = str(resource).strip()
            title_clean = str(title).strip()
            detail_clean = (
                str(detail)
                .strip()
                .replace("\t", " ")
                .replace("\r", " ")
                .replace("\n", " ")
            )
            line_key = f"{sev_clean}\t{key_clean}"
            if line_key not in seen:
                seen.add(line_key)
                f.write(
                    f"{sev_clean}\t{key_clean}\t{service_clean}\t{resource_clean}\t{title_clean}\t{detail_clean}\n"
                )


def _run_prowler(
    ctx: RunContext,
    dm: DependencyManager,
    log: Logger,
    provider: str,
    output_dir: Path,
    phase_id: str,
) -> list[tuple[str, str, str, str, str, str]]:
    """Execute Prowler assessment for provider and extract failed findings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    findings: list[tuple[str, str, str, str, str, str]] = []

    if not dm.is_available("prowler"):
        log.warn(f"prowler CLI missing - Prowler {provider} assessment skipped")
        return findings

    log.info(f"Running Prowler CSPM assessment for {provider.upper()}")
    cmd = dm.build_cmd(
        "prowler",
        [
            provider,
            "-M",
            "json",
            "-o",
            str(output_dir),
            "-F",
            f"prowler_{provider}",
        ],
    )
    ev(
        ctx.console_dir,
        phase_id,
        cmd,
        timeout=1800,
        title=f"Prowler {provider.upper()} assessment",
    )

    json_candidates = list(output_dir.glob(f"prowler_{provider}*.json"))
    if not json_candidates and (output_dir / f"prowler_{provider}.json").is_file():
        json_candidates = [output_dir / f"prowler_{provider}.json"]

    if json_candidates:
        target_json = sorted(json_candidates, key=lambda p: p.stat().st_mtime)[-1]
        try:
            content = target_json.read_text(encoding="utf-8", errors="replace")
            items: list[dict[str, Any]] = []
            if content.strip().startswith("["):
                items = json.loads(content)
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            items.append(json.loads(line))
                        except Exception:
                            pass

            for item in items:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("Status") or item.get("status") or "").upper()
                if status and status != "FAIL":
                    continue
                sev_raw = str(item.get("Severity") or item.get("severity") or "medium").lower()
                if sev_raw not in ("critical", "high", "medium", "low"):
                    sev_raw = "medium"
                check_id = str(item.get("CheckID") or item.get("check_id") or "").strip()
                svc = str(item.get("ServiceName") or item.get("service_name") or provider).strip()
                resource = str(
                    item.get("ResourceId")
                    or item.get("resource_id")
                    or item.get("ResourceArn")
                    or ""
                ).strip()
                title = str(item.get("CheckTitle") or item.get("check_title") or check_id).strip()
                detail = str(item.get("StatusExtended") or item.get("status_extended") or "").strip()

                key = f"prowler-{provider}:{check_id}:{resource}" if resource else f"prowler-{provider}:{check_id}"
                findings.append((sev_raw, key, svc, resource or provider, title, detail))
        except Exception as exc:
            log.warn(f"Failed to parse Prowler {provider} output: {exc}")

    return findings


def _run_azure_posture(
    ctx: RunContext,
    dm: DependencyManager,
    log: Logger,
) -> list[tuple[str, str, str, str, str, str]]:
    """Run Azure Security Posture checks via Azure Resource Graph queries and optional Prowler."""
    findings: list[tuple[str, str, str, str, str, str]] = []
    if not dm.is_available("az"):
        log.warn("az CLI missing - Azure posture checks skipped")
        return findings

    log.info("Running Azure Security Posture checks")
    sub_args: list[str] = []
    for s in getattr(ctx.scope, "azure_subscriptions", []):
        sub_args.extend(["--subscriptions", s])

    # 1. Storage Accounts
    query_storage = (
        "Resources "
        "| where type =~ 'microsoft.storage/storageaccounts' "
        "| project name, resourceGroup, "
        "allowBlobPublicAccess=properties.allowBlobPublicAccess, "
        "supportsHttpsTrafficOnly=properties.supportsHttpsTrafficOnly, "
        "minimumTlsVersion=properties.minimumTlsVersion"
    )
    cmd_storage = dm.build_cmd(
        "az",
        ["graph", "query", "--first", "1000", *sub_args, "-o", "json", "-q", query_storage],
    )
    res_storage = ev(
        ctx.console_dir,
        "A",
        cmd_storage,
        timeout=120,
        title="Azure Posture: Storage Accounts",
    )
    if res_storage.returncode == 0:
        try:
            data = json.loads(res_storage.stdout)
            rows = (
                data.get("data", [])
                if isinstance(data, dict)
                else (data if isinstance(data, list) else [])
            )
            for item in rows:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                rg = str(item.get("resourceGroup") or "").strip()
                allow_public = item.get("allowBlobPublicAccess")
                if allow_public is True or str(allow_public).lower() == "true":
                    findings.append((
                        "high",
                        f"az-storage-public:{name}",
                        "Storage",
                        name,
                        f"Azure Storage Account {name} allows public blob access",
                        f"{rg}/{name} allowBlobPublicAccess=true",
                    ))
                https_traffic = item.get("supportsHttpsTrafficOnly")
                if https_traffic is False or str(https_traffic).lower() == "false":
                    findings.append((
                        "medium",
                        f"az-storage-http:{name}",
                        "Storage",
                        name,
                        f"Azure Storage Account {name} allows unencrypted HTTP traffic",
                        f"{rg}/{name} supportsHttpsTrafficOnly=false",
                    ))
                tls = str(item.get("minimumTlsVersion") or "TLS1_0").strip()
                if tls != "TLS1_2":
                    findings.append((
                        "low",
                        f"az-storage-tls:{name}",
                        "Storage",
                        name,
                        f"Azure Storage Account {name} uses legacy TLS ({tls})",
                        f"{rg}/{name}",
                    ))
        except Exception:
            pass

    # 2. Key Vaults
    query_kv = (
        "Resources "
        "| where type =~ 'microsoft.keyvault/vaults' "
        "| project name, resourceGroup, "
        "enablePurgeProtection=properties.enablePurgeProtection"
    )
    cmd_kv = dm.build_cmd(
        "az",
        ["graph", "query", "--first", "1000", *sub_args, "-o", "json", "-q", query_kv],
    )
    res_kv = ev(
        ctx.console_dir,
        "A",
        cmd_kv,
        timeout=120,
        title="Azure Posture: Key Vaults",
    )
    if res_kv.returncode == 0:
        try:
            data = json.loads(res_kv.stdout)
            rows = (
                data.get("data", [])
                if isinstance(data, dict)
                else (data if isinstance(data, list) else [])
            )
            for item in rows:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                rg = str(item.get("resourceGroup") or "").strip()
                purge = item.get("enablePurgeProtection")
                if purge is not True and str(purge).lower() != "true":
                    findings.append((
                        "medium",
                        f"az-kv-purge:{name}",
                        "KeyVault",
                        name,
                        f"Key Vault {name} has purge protection disabled",
                        f"{rg}/{name}",
                    ))
        except Exception:
            pass

    # 3. SQL Servers
    query_sql = (
        "Resources "
        "| where type =~ 'microsoft.sql/servers' "
        "| project name, resourceGroup, "
        "publicNetworkAccess=properties.publicNetworkAccess"
    )
    cmd_sql = dm.build_cmd(
        "az",
        ["graph", "query", "--first", "1000", *sub_args, "-o", "json", "-q", query_sql],
    )
    res_sql = ev(
        ctx.console_dir,
        "A",
        cmd_sql,
        timeout=120,
        title="Azure Posture: SQL Servers",
    )
    if res_sql.returncode == 0:
        try:
            data = json.loads(res_sql.stdout)
            rows = (
                data.get("data", [])
                if isinstance(data, dict)
                else (data if isinstance(data, list) else [])
            )
            for item in rows:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                rg = str(item.get("resourceGroup") or "").strip()
                pna = str(item.get("publicNetworkAccess") or "").strip()
                if pna.lower() == "enabled":
                    findings.append((
                        "medium",
                        f"az-sql-public:{name}",
                        "Database",
                        name,
                        f"Azure SQL Server {name} has public network access enabled",
                        f"{rg}/{name}",
                    ))
        except Exception:
            pass

    # 4. Defender for Cloud
    query_defender = (
        "Resources "
        "| where type =~ 'microsoft.security/pricings' "
        "| project name, "
        "pricingTier=properties.pricingTier"
    )
    cmd_defender = dm.build_cmd(
        "az",
        ["graph", "query", "--first", "1000", *sub_args, "-o", "json", "-q", query_defender],
    )
    res_defender = ev(
        ctx.console_dir,
        "A",
        cmd_defender,
        timeout=120,
        title="Azure Posture: Defender for Cloud",
    )
    if res_defender.returncode == 0:
        try:
            data = json.loads(res_defender.stdout)
            rows = (
                data.get("data", [])
                if isinstance(data, dict)
                else (data if isinstance(data, list) else [])
            )
            for item in rows:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                pricing_tier = str(item.get("pricingTier") or "").strip()
                if (
                    name in ("VirtualMachines", "StorageAccounts", "SqlServers")
                    and pricing_tier.lower() == "free"
                ):
                    findings.append((
                        "medium",
                        f"az-defender-free:{name}",
                        "SecurityCenter",
                        name,
                        f"Microsoft Defender for Cloud disabled (Free tier) for {name}",
                        "pricingTier=Free",
                    ))
        except Exception:
            pass

    # 5. Prowler (optional)
    if (
        bool(getattr(ctx, "use_prowler", False) or getattr(ctx.scope, "use_prowler", False))
        and dm.is_available("prowler")
    ):
        prowler_findings = _run_prowler(ctx, dm, log, "azure", ctx.azure_dir, "A")
        findings.extend(prowler_findings)

    _write_posture_findings(ctx.azure_dir, findings)
    log.ok(f"Azure posture checks completed: {len(findings)} findings recorded")
    return findings


def _run_gcp_posture(
    ctx: RunContext,
    dm: DependencyManager,
    log: Logger,
    projects: list[str],
) -> list[tuple[str, str, str, str, str, str]]:
    """Run GCP Security Posture checks across projects and optional Prowler."""
    findings: list[tuple[str, str, str, str, str, str]] = []
    if not dm.is_available("gcloud"):
        log.warn("gcloud CLI missing - GCP posture checks skipped")
        return findings

    log.info(f"Running GCP Security Posture checks for {len(projects)} projects")
    cloud_sql_public_ips: list[tuple[str, str, str, str]] = []

    for proj in projects:
        # 1. Cloud Storage Buckets
        cmd_b = dm.build_cmd(
            "gcloud",
            ["storage", "buckets", "list", "--project", proj, "--format=json"],
        )
        res_b = ev(
            ctx.console_dir,
            "G",
            cmd_b,
            timeout=60,
            title=f"GCP Posture ({proj}): GCS buckets",
        )
        if res_b.returncode == 0:
            try:
                buckets = json.loads(res_b.stdout)
                if isinstance(buckets, list):
                    for b in buckets:
                        if not isinstance(b, dict):
                            continue
                        bname = str(b.get("name") or b.get("id") or "").strip()
                        if not bname:
                            continue
                        iam_conf = (
                            b.get("iamConfiguration")
                            or b.get("iam_configuration")
                            or {}
                        )
                        ubla = (
                            iam_conf.get("uniformBucketLevelAccess")
                            or iam_conf.get("uniform_bucket_level_access")
                            or {}
                        )
                        ubla_enabled = ubla.get("enabled", False)
                        if not ubla_enabled:
                            findings.append((
                                "low",
                                f"gcp-gcs-ubla:{bname}",
                                "GCS",
                                bname,
                                f"GCS bucket {bname} has uniform bucket-level access disabled",
                                f"project={proj}",
                            ))

                        # Bucket IAM policy
                        cmd_iam = dm.build_cmd(
                            "gcloud",
                            [
                                "storage",
                                "buckets",
                                "get-iam-policy",
                                f"gs://{bname}",
                                "--project",
                                proj,
                                "--format=json",
                            ],
                        )
                        res_iam = ev(
                            ctx.console_dir,
                            "G",
                            cmd_iam,
                            timeout=30,
                            title=f"GCP Posture ({proj}): GCS bucket {bname} IAM policy",
                        )
                        if res_iam.returncode == 0:
                            try:
                                iam_data = json.loads(res_iam.stdout)
                                bindings = iam_data.get("bindings") or []
                                for binding in bindings:
                                    if not isinstance(binding, dict):
                                        continue
                                    role = str(binding.get("role") or "").strip()
                                    members = binding.get("members") or []
                                    for member in members:
                                        if member in ("allUsers", "allAuthenticatedUsers"):
                                            findings.append((
                                                "critical",
                                                f"gcp-gcs-public:{bname}",
                                                "GCS",
                                                bname,
                                                f"GCS bucket {bname} is publicly accessible ({member})",
                                                f"project={proj} role={role}",
                                            ))
                            except Exception:
                                pass
            except Exception:
                pass

        # 2. Cloud SQL Instances
        cmd_sql = dm.build_cmd(
            "gcloud",
            ["sql", "instances", "list", "--project", proj, "--format=json"],
        )
        res_sql = ev(
            ctx.console_dir,
            "G",
            cmd_sql,
            timeout=60,
            title=f"GCP Posture ({proj}): Cloud SQL instances",
        )
        if res_sql.returncode == 0:
            try:
                sql_data = json.loads(res_sql.stdout)
                if isinstance(sql_data, list):
                    for item in sql_data:
                        if not isinstance(item, dict):
                            continue
                        iname = str(item.get("name") or "").strip()
                        ip_addresses = item.get("ipAddresses") or []
                        public_sql_ips: list[str] = []
                        for ip_info in ip_addresses:
                            if not isinstance(ip_info, dict):
                                continue
                            if str(ip_info.get("type") or "").upper() == "PRIMARY":
                                ip_val = str(ip_info.get("ipAddress") or "").strip()
                                if ip_val and not _is_private_ip(ip_val):
                                    public_sql_ips.append(ip_val)

                        if public_sql_ips:
                            for pip in public_sql_ips:
                                cloud_sql_public_ips.append((pip, iname, proj, "cloud_sql"))

                            settings = item.get("settings") or {}
                            ip_conf = settings.get("ipConfiguration") or {}
                            auth_nets = ip_conf.get("authorizedNetworks") or []
                            open_to_all = False
                            for an in auth_nets:
                                val = an.get("value") if isinstance(an, dict) else str(an)
                                if val in ("0.0.0.0/0", "*"):
                                    open_to_all = True
                                    break
                            if open_to_all:
                                findings.append((
                                    "critical",
                                    f"gcp-sql-open:{iname}",
                                    "CloudSQL",
                                    iname,
                                    f"Cloud SQL instance {iname} allows connections from 0.0.0.0/0",
                                    f"project={proj}",
                                ))
                            require_ssl = ip_conf.get("requireSsl")
                            ssl_mode = str(ip_conf.get("sslMode") or "")
                            if not require_ssl and ssl_mode not in (
                                "ENCRYPTED_ONLY",
                                "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
                            ):
                                findings.append((
                                    "high",
                                    f"gcp-sql-nossl:{iname}",
                                    "CloudSQL",
                                    iname,
                                    f"Cloud SQL instance {iname} does not enforce SSL/TLS",
                                    f"project={proj}",
                                ))
            except Exception:
                pass

        # 3. IAM & Service Accounts
        cmd_iam = dm.build_cmd(
            "gcloud",
            ["projects", "get-iam-policy", proj, "--format=json"],
        )
        res_iam = ev(
            ctx.console_dir,
            "G",
            cmd_iam,
            timeout=60,
            title=f"GCP Posture ({proj}): project IAM policy",
        )
        if res_iam.returncode == 0:
            try:
                iam_data = json.loads(res_iam.stdout)
                bindings = iam_data.get("bindings") or []
                for binding in bindings:
                    if not isinstance(binding, dict):
                        continue
                    role = str(binding.get("role") or "").strip()
                    if role in ("roles/editor", "roles/owner"):
                        members = binding.get("members") or []
                        for member in members:
                            if "-compute@developer.gserviceaccount.com" in member:
                                findings.append((
                                    "medium",
                                    f"gcp-iam-default-sa:{proj}",
                                    "IAM",
                                    proj,
                                    f"Default Compute Engine SA has overly permissive role ({role})",
                                    f"{member} in {proj}",
                                ))
            except Exception:
                pass

    # Ensure public Cloud SQL IPs get added to gcp/public_ips.tsv
    if cloud_sql_public_ips:
        pub_tsv = ctx.gcp_dir / "public_ips.tsv"
        existing_ips: set[str] = set()
        if pub_tsv.is_file():
            for line in pub_tsv.read_text(encoding="utf-8", errors="replace").splitlines():
                p = line.strip().split("\t")
                if p and p[0].strip():
                    existing_ips.add(p[0].strip())
        with pub_tsv.open("a", encoding="utf-8") as f:
            for ip, name, proj, rtype in cloud_sql_public_ips:
                if ip not in existing_ips:
                    existing_ips.add(ip)
                    f.write(f"{ip}\t{name}\t{proj}\t{rtype}\n")

    # 4. Prowler (optional)
    if (
        bool(getattr(ctx, "use_prowler", False) or getattr(ctx.scope, "use_prowler", False))
        and dm.is_available("prowler")
    ):
        prowler_findings = _run_prowler(ctx, dm, log, "gcp", ctx.gcp_dir, "G")
        findings.extend(prowler_findings)

    _write_posture_findings(ctx.gcp_dir, findings)
    log.ok(f"GCP posture checks completed: {len(findings)} findings recorded")
    return findings


def _build_aws_cmd(
    dm: DependencyManager,
    args: list[str],
    profile: str = "",
    region: str = "",
) -> list[str]:
    """Helper to build AWS command with optional profile and region."""
    cmd_args: list[str] = list(args)
    if profile:
        cmd_args.extend(["--profile", profile])
    if region:
        cmd_args.extend(["--region", region])
    return dm.build_cmd("aws", cmd_args)


def _run_aws_posture(
    ctx: RunContext,
    dm: DependencyManager,
    log: Logger,
    profiles: list[str],
    regions: list[str],
) -> list[tuple[str, str, str, str, str, str]]:
    """Run AWS Security Posture checks across profiles and regions."""
    findings: list[tuple[str, str, str, str, str, str]] = []
    if not dm.is_available("aws"):
        log.warn("aws CLI missing - AWS posture checks skipped")
        return findings

    aws_dir = getattr(ctx, "aws_dir", ctx.run_dir / "aws")
    aws_dir.mkdir(parents=True, exist_ok=True)
    log.info(
        f"Running AWS Security Posture checks across {len(profiles)} profile(s) and {len(regions)} region(s)"
    )

    for prof in profiles:
        prof_label = prof if prof else "default"

        # 1. IAM Account Summary & MFA
        cmd_summary = _build_aws_cmd(dm, ["iam", "get-account-summary", "--output", "json"], prof)
        res_summary = ev(
            ctx.console_dir,
            "W",
            cmd_summary,
            timeout=30,
            title=f"AWS Posture ({prof_label}): IAM account summary",
        )
        if res_summary.returncode == 0:
            try:
                summary_map = json.loads(res_summary.stdout).get("SummaryMap", {})
                if summary_map.get("AccountMFAEnabled") == 0:
                    findings.append((
                        "critical",
                        "aws-iam-root-nomfa",
                        "IAM",
                        "root",
                        "AWS Root account does not have MFA enabled",
                        "AccountMFAEnabled=0",
                    ))
            except Exception:
                pass

        # IAM Credential Report
        cmd_gen = _build_aws_cmd(dm, ["iam", "generate-credential-report", "--output", "json"], prof)
        ev(
            ctx.console_dir,
            "W",
            cmd_gen,
            timeout=30,
            title=f"AWS Posture ({prof_label}): generate credential report",
        )
        cmd_rep = _build_aws_cmd(dm, ["iam", "get-credential-report", "--output", "json"], prof)
        res_rep = ev(
            ctx.console_dir,
            "W",
            cmd_rep,
            timeout=30,
            title=f"AWS Posture ({prof_label}): get credential report",
        )
        if res_rep.returncode == 0:
            try:
                rep_data = json.loads(res_rep.stdout)
                content_b64 = rep_data.get("Content", "")
                if content_b64:
                    csv_text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                    reader = csv.DictReader(csv_text.splitlines())
                    for row in reader:
                        user = str(row.get("user") or "").strip()
                        pwd_enabled = str(row.get("password_enabled") or "").strip().lower()
                        mfa_active = str(row.get("mfa_active") or "").strip().lower()
                        if pwd_enabled == "true" and mfa_active == "false":
                            findings.append((
                                "high",
                                f"aws-iam-user-nomfa:{user}",
                                "IAM",
                                user,
                                f"IAM console user '{user}' does not have MFA enabled",
                                "password_enabled=true, mfa_active=false",
                            ))
            except Exception:
                pass

        # 2. S3 Buckets
        cmd_s3 = _build_aws_cmd(dm, ["s3api", "list-buckets", "--output", "json"], prof)
        res_s3 = ev(
            ctx.console_dir,
            "W",
            cmd_s3,
            timeout=60,
            title=f"AWS Posture ({prof_label}): list S3 buckets",
        )
        if res_s3.returncode == 0:
            try:
                buckets = json.loads(res_s3.stdout).get("Buckets", [])
                for b_obj in buckets:
                    if not isinstance(b_obj, dict):
                        continue
                    b = str(b_obj.get("Name") or "").strip()
                    if not b:
                        continue

                    # Public Access Block
                    cmd_pab = _build_aws_cmd(
                        dm,
                        ["s3api", "get-public-access-block", "--bucket", b, "--output", "json"],
                        prof,
                    )
                    res_pab = ev(
                        ctx.console_dir,
                        "W",
                        cmd_pab,
                        timeout=30,
                        title=f"AWS Posture ({prof_label}): S3 PAB {b}",
                    )
                    pab_ok = False
                    if res_pab.returncode == 0:
                        try:
                            pab_conf = json.loads(res_pab.stdout).get(
                                "PublicAccessBlockConfiguration", {}
                            )
                            if (
                                pab_conf.get("BlockPublicAcls") is True
                                and pab_conf.get("IgnorePublicAcls") is True
                                and pab_conf.get("BlockPublicPolicy") is True
                                and pab_conf.get("RestrictPublicBuckets") is True
                            ):
                                pab_ok = True
                        except Exception:
                            pass

                    if not pab_ok:
                        cmd_ps = _build_aws_cmd(
                            dm,
                            ["s3api", "get-bucket-policy-status", "--bucket", b, "--output", "json"],
                            prof,
                        )
                        res_ps = ev(
                            ctx.console_dir,
                            "W",
                            cmd_ps,
                            timeout=30,
                            title=f"AWS Posture ({prof_label}): S3 policy status {b}",
                        )
                        is_public = False
                        if res_ps.returncode == 0:
                            try:
                                is_public = (
                                    json.loads(res_ps.stdout)
                                    .get("PolicyStatus", {})
                                    .get("IsPublic")
                                    is True
                                )
                            except Exception:
                                pass

                        if is_public:
                            findings.append((
                                "critical",
                                f"aws-s3-public:{b}",
                                "S3",
                                b,
                                f"S3 bucket '{b}' is publicly accessible",
                                "Bucket policy or ACL allows public access",
                            ))
                        else:
                            findings.append((
                                "medium",
                                f"aws-s3-pab:{b}",
                                "S3",
                                b,
                                f"S3 bucket '{b}' does not have full S3 Block Public Access enabled",
                                "PublicAccessBlock incomplete or missing",
                            ))

                    # Bucket Encryption
                    cmd_enc = _build_aws_cmd(
                        dm,
                        ["s3api", "get-bucket-encryption", "--bucket", b, "--output", "json"],
                        prof,
                    )
                    res_enc = ev(
                        ctx.console_dir,
                        "W",
                        cmd_enc,
                        timeout=30,
                        title=f"AWS Posture ({prof_label}): S3 encryption {b}",
                    )
                    has_enc = False
                    if res_enc.returncode == 0:
                        try:
                            enc_rules = (
                                json.loads(res_enc.stdout)
                                .get("ServerSideEncryptionConfiguration", {})
                                .get("Rules", [])
                            )
                            if enc_rules:
                                has_enc = True
                        except Exception:
                            pass

                    if not has_enc:
                        findings.append((
                            "medium",
                            f"aws-s3-unencrypted:{b}",
                            "S3",
                            b,
                            f"S3 bucket '{b}' has no default encryption",
                            "No SSE configuration",
                        ))
            except Exception:
                pass

        # Per-region checks
        for reg in regions:
            # 3. CloudTrail
            cmd_ct = _build_aws_cmd(
                dm, ["cloudtrail", "describe-trails", "--output", "json"], prof, reg
            )
            res_ct = ev(
                ctx.console_dir,
                "W",
                cmd_ct,
                timeout=30,
                title=f"AWS Posture ({prof_label}/{reg}): describe trails",
            )
            if res_ct.returncode == 0:
                try:
                    trails = json.loads(res_ct.stdout).get("trailList", [])
                    if not trails:
                        findings.append((
                            "high",
                            f"aws-cloudtrail-none:{reg}",
                            "CloudTrail",
                            reg,
                            "No AWS CloudTrail trail configured",
                            f"region={reg}",
                        ))
                    else:
                        has_multi_region = any(
                            t.get("IsMultiRegionTrail") is True for t in trails
                        )
                        if not has_multi_region:
                            findings.append((
                                "medium",
                                "aws-cloudtrail-single-region",
                                "CloudTrail",
                                "account",
                                "No multi-region CloudTrail trail configured",
                                "IsMultiRegionTrail=false on all trails",
                            ))
                        for t in trails:
                            tname = str(t.get("Name") or "").strip()
                            if t.get("LogFileValidationEnabled") is False:
                                findings.append((
                                    "low",
                                    f"aws-cloudtrail-novalidation:{tname}",
                                    "CloudTrail",
                                    tname,
                                    f"CloudTrail '{tname}' has log file integrity validation disabled",
                                    "LogFileValidationEnabled=false",
                                ))
                except Exception:
                    pass

            # 4. SecurityHub
            cmd_sh = _build_aws_cmd(
                dm, ["securityhub", "describe-hub", "--output", "json"], prof, reg
            )
            res_sh = ev(
                ctx.console_dir,
                "W",
                cmd_sh,
                timeout=30,
                title=f"AWS Posture ({prof_label}/{reg}): describe hub",
            )
            if (
                res_sh.returncode != 0
                or "InvalidAccessException" in res_sh.stderr
                or "not subscribed" in res_sh.stderr.lower()
            ):
                findings.append((
                    "medium",
                    f"aws-securityhub-disabled:{reg}",
                    "SecurityHub",
                    reg,
                    f"AWS SecurityHub is not enabled in {reg}",
                    "InvalidAccessException / not subscribed",
                ))

            # 5. GuardDuty
            cmd_gd = _build_aws_cmd(
                dm, ["guardduty", "list-detectors", "--output", "json"], prof, reg
            )
            res_gd = ev(
                ctx.console_dir,
                "W",
                cmd_gd,
                timeout=30,
                title=f"AWS Posture ({prof_label}/{reg}): list detectors",
            )
            gd_enabled = False
            if res_gd.returncode == 0:
                try:
                    detectors = json.loads(res_gd.stdout).get("DetectorIds", [])
                    if detectors:
                        gd_enabled = True
                except Exception:
                    pass
            if not gd_enabled:
                findings.append((
                    "medium",
                    f"aws-guardduty-disabled:{reg}",
                    "GuardDuty",
                    reg,
                    f"Amazon GuardDuty is not enabled in {reg}",
                    "DetectorIds=[]",
                ))

            # 6. RDS Public & Unencrypted
            cmd_rds = _build_aws_cmd(
                dm, ["rds", "describe-db-instances", "--output", "json"], prof, reg
            )
            res_rds = ev(
                ctx.console_dir,
                "W",
                cmd_rds,
                timeout=60,
                title=f"AWS Posture ({prof_label}/{reg}): describe db instances",
            )
            if res_rds.returncode == 0:
                try:
                    db_instances = json.loads(res_rds.stdout).get("DBInstances", [])
                    for db in db_instances:
                        if not isinstance(db, dict):
                            continue
                        dbid = str(db.get("DBInstanceIdentifier") or "").strip()
                        engine = str(db.get("Engine") or "database").strip()
                        endpoint_obj = db.get("Endpoint") or {}
                        endpoint_addr = str(endpoint_obj.get("Address") or "").strip()
                        endpoint_port = str(endpoint_obj.get("Port") or "").strip()
                        if db.get("PubliclyAccessible") is True:
                            findings.append((
                                "high",
                                f"aws-rds-public:{dbid}",
                                "RDS",
                                dbid,
                                f"RDS database '{dbid}' ({engine}) is publicly accessible",
                                f"{endpoint_addr}:{endpoint_port}",
                            ))
                        if db.get("StorageEncrypted") is False:
                            findings.append((
                                "medium",
                                f"aws-rds-unencrypted:{dbid}",
                                "RDS",
                                dbid,
                                f"RDS database '{dbid}' storage is not encrypted at rest",
                                "StorageEncrypted=false",
                            ))
                except Exception:
                    pass

            # 7. EC2 EBS Default Encryption
            cmd_ebs = _build_aws_cmd(
                dm, ["ec2", "get-ebs-encryption-by-default", "--output", "json"], prof, reg
            )
            res_ebs = ev(
                ctx.console_dir,
                "W",
                cmd_ebs,
                timeout=30,
                title=f"AWS Posture ({prof_label}/{reg}): get ebs encryption default",
            )
            if res_ebs.returncode == 0:
                try:
                    ebs_default = json.loads(res_ebs.stdout).get("EbsEncryptionByDefault")
                    if ebs_default is False:
                        findings.append((
                            "low",
                            f"aws-ebs-default-unenc:{reg}",
                            "EC2",
                            reg,
                            f"EBS default encryption is disabled in {reg}",
                            "EbsEncryptionByDefault=false",
                        ))
                except Exception:
                    pass

    # 8. Prowler (optional)
    if (
        bool(getattr(ctx, "use_prowler", False) or getattr(ctx.scope, "use_prowler", False))
        and dm.is_available("prowler")
    ):
        prowler_findings = _run_prowler(ctx, dm, log, "aws", aws_dir, "W")
        findings.extend(prowler_findings)

    _write_posture_findings(aws_dir, findings)
    log.ok(f"AWS posture checks completed: {len(findings)} findings recorded")
    return findings


def _scan_cloud_ips(
    ctx: RunContext,
    dm: DependencyManager,
    log: Logger,
    cloud_dir: Path,
    phase_id: str,
    label: str,
) -> None:
    """Scan cloud public IPs: pass 1 fast discovery and pass 2 service detection."""
    cloud_dir.mkdir(parents=True, exist_ok=True)
    pub_tsv = cloud_dir / "public_ips.tsv"
    raw_ips: list[str] = []
    if pub_tsv.is_file():
        with pub_tsv.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                cols = line.split("\t")
                ip = cols[0].strip()
                if ip:
                    raw_ips.append(ip)

    n = len(raw_ips)

    exclude_set: set[str] = set(ctx.scope.exclude_ips) | set(ctx.scope.edge_ips)
    target_ips: list[str] = []
    seen_targets: set[str] = set()
    for ip in raw_ips:
        if ip not in exclude_set and ip not in seen_targets:
            seen_targets.add(ip)
            target_ips.append(ip)

    targets_path = cloud_dir / "targets.txt"
    with targets_path.open("w", encoding="utf-8") as f:
        for ip in target_ips:
            f.write(f"{ip}\n")

    log.info(f"{n} {label} public IPs; pass 1 (fast discovery)")

    open_ports_path = cloud_dir / "open_ports.tsv"
    open_ports: list[tuple[str, str]] = []

    if target_ips and dm.is_available("nmap"):
        pass1_cmd = dm.build_cmd(
            "nmap",
            [
                "-sT",
                "-Pn",
                "--top-ports",
                "1000",
                "--max-rate",
                str(ctx.scope.nmap_max_rate),
                "--host-timeout",
                "90s",
                "--open",
                "-iL",
                str(targets_path),
                "-oA",
                str(cloud_dir / "pass1"),
            ],
        )
        ev(
            ctx.console_dir,
            phase_id,
            pass1_cmd,
            timeout=1800,
            title=f"{label} nmap pass 1",
        )

        gnmap_path = cloud_dir / "pass1.gnmap"
        if gnmap_path.is_file():
            with gnmap_path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "Ports: " not in line:
                        continue
                    m_host = re.search(r"Host:\s+(\S+)", line)
                    if not m_host:
                        continue
                    host_ip = m_host.group(1)
                    port_matches = re.findall(r"(\d+)/open/tcp", line)
                    if port_matches:
                        ports_str = ",".join(port_matches)
                        open_ports.append((host_ip, ports_str))

        with open_ports_path.open("w", encoding="utf-8") as f:
            for host_ip, ports in open_ports:
                f.write(f"{host_ip}\t{ports}\n")

        log.info("pass 2 (service detection on open ports)")

        for host_ip, ports in open_ports:
            pass2_cmd = dm.build_cmd(
                "nmap",
                [
                    "-sT",
                    "-Pn",
                    "-p",
                    ports,
                    "--max-rate",
                    str(ctx.scope.nmap_max_rate),
                    "-sV",
                    "--version-all",
                    "--script",
                    "banner,http-title,http-headers,ssl-cert,ssh2-enum-algos,http-methods",
                    "-oA",
                    str(cloud_dir / f"svc_{host_ip}"),
                    host_ip,
                ],
            )
            ev(
                ctx.console_dir,
                phase_id,
                pass2_cmd,
                timeout=600,
                title=f"{label} nmap svc ({host_ip})",
            )
    else:
        if not open_ports_path.exists():
            open_ports_path.write_text("", encoding="utf-8")

    up = 0
    gnmap_path = cloud_dir / "pass1.gnmap"
    if gnmap_path.is_file():
        with gnmap_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "Status: Up" in line:
                    up += 1

    open_count = len(open_ports)
    no_exposure = n - open_count
    coverage_path = cloud_dir / "coverage.txt"
    coverage_path.write_text(
        f"public_ips={n} responded={up} open_ports={open_count} no_exposure={no_exposure}\n",
        encoding="utf-8",
    )


def phaseA(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Annex A - asset-informed exposure (Azure public IPs + NSG rules)."""
    log.info("Annex A - asset-informed exposure (Azure public IPs + NSG rules)")
    ctx.azure_dir.mkdir(parents=True, exist_ok=True)

    if ctx.scope.azure_inventory_file:
        inv_path = Path(ctx.scope.azure_inventory_file)
        if inv_path.is_file():
            shutil.copyfile(inv_path, ctx.azure_dir / "public_ips.tsv")
        else:
            log.warn(f"azure_inventory_file not found: {inv_path}")
            return
    elif dm.is_available("az"):
        sub_args: list[str] = []
        for s in ctx.scope.azure_subscriptions:
            sub_args.extend(["--subscriptions", s])

        query_ips = (
            "Resources "
            "| where type =~ 'microsoft.network/publicipaddresses' "
            "| project ip=tostring(properties.ipAddress), name, resourceGroup, subscriptionId, "
            "attachedTo=tostring(properties.ipConfiguration.id)"
        )
        cmd_ips = dm.build_cmd(
            "az",
            ["graph", "query", "--first", "1000", *sub_args, "-o", "json", "-q", query_ips],
        )
        res_ips = ev(
            ctx.console_dir,
            "A",
            cmd_ips,
            timeout=120,
            title="Azure Resource Graph: Public IPs",
        )

        if res_ips.returncode != 0:
            log.warn("az graph query failed (az login? resource-graph extension?)")
            return

        try:
            data = json.loads(res_ips.stdout)
            if isinstance(data, dict):
                rows = data.get("data", [])
            elif isinstance(data, list):
                rows = data
            else:
                log.warn("az graph query failed (az login? resource-graph extension?)")
                return
        except Exception:
            log.warn("az graph query failed (az login? resource-graph extension?)")
            return

        # Save raw JSON
        (ctx.azure_dir / "public_ips.json").write_text(res_ips.stdout, encoding="utf-8")

        all_lines: list[str] = []
        valid_lines: list[str] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            ip = str(item.get("ip") or "").strip()
            name = str(item.get("name") or "").strip()
            rg = str(item.get("resourceGroup") or "").strip()
            raw_att = str(item.get("attachedTo") or "").strip()
            if not raw_att:
                attached_to = "unattached"
            else:
                parts = raw_att.split("/")
                if len(parts) >= 9:
                    attached_to = "/".join(parts[7:9])
                else:
                    attached_to = raw_att
            line = f"{ip}\t{name}\t{rg}\t{attached_to}"
            all_lines.append(line)
            if ip:
                valid_lines.append(line)

        with (ctx.azure_dir / "public_ips_all.tsv").open("w", encoding="utf-8") as f:
            for l in all_lines:
                f.write(f"{l}\n")

        with (ctx.azure_dir / "public_ips.tsv").open("w", encoding="utf-8") as f:
            for l in valid_lines:
                f.write(f"{l}\n")

        # NSG rules query
        query_nsg = (
            "Resources "
            "| where type =~ 'microsoft.network/networksecuritygroups' "
            "| mv-expand r = properties.securityRules "
            "| where r.properties.direction == 'Inbound' and r.properties.access == 'Allow' "
            "| extend src = tostring(r.properties.sourceAddressPrefix) "
            "| where src in ('*', 'Internet', '0.0.0.0/0', 'Any') "
            "| project nsg=name, resourceGroup, rule=tostring(r.name), "
            "ports=strcat(tostring(r.properties.destinationPortRange), tostring(r.properties.destinationPortRanges)), "
            "attachedNics=array_length(properties.networkInterfaces)"
        )
        cmd_nsg = dm.build_cmd(
            "az",
            ["graph", "query", "--first", "1000", *sub_args, "-o", "json", "-q", query_nsg],
        )
        res_nsg = ev(
            ctx.console_dir,
            "A",
            cmd_nsg,
            timeout=120,
            title="Azure Resource Graph: NSG Rules",
        )

        nsg_rows: list[dict[str, Any]] = []
        if res_nsg.returncode == 0:
            try:
                nsg_data = json.loads(res_nsg.stdout)
                if isinstance(nsg_data, dict):
                    nsg_rows = nsg_data.get("data", [])
                elif isinstance(nsg_data, list):
                    nsg_rows = nsg_data
            except Exception:
                nsg_rows = []

        with (ctx.azure_dir / "nsg_internet_rules.tsv").open("w", encoding="utf-8") as f:
            for item in nsg_rows:
                if not isinstance(item, dict):
                    continue
                nsg = str(item.get("nsg") or "").strip()
                rg = str(item.get("resourceGroup") or "").strip()
                rule = str(item.get("rule") or "").strip()
                ports = str(item.get("ports") or "").strip()
                attached_nics = item.get("attachedNics")
                if attached_nics is None:
                    attached_nics = 0
                f.write(f"{nsg}\t{rg}\t{rule}\t{ports}\t{attached_nics}\n")
    else:
        log.warn("az CLI missing and no azure_inventory_file - Annex A skipped")
        return

    # Posture check when requested
    if bool(getattr(ctx, "cloud_posture", False) or getattr(ctx.scope, "cloud_posture", False)):
        _run_azure_posture(ctx, dm, log)

    _scan_cloud_ips(ctx, dm, log, ctx.azure_dir, "A", "Azure")


def phaseG(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Annex G - asset-informed exposure (Google Cloud public IPs + VPC firewall rules)."""
    log.info("Annex G - asset-informed exposure (Google Cloud public IPs + VPC firewall rules)")
    ctx.gcp_dir.mkdir(parents=True, exist_ok=True)

    projects: list[str] = []
    if ctx.scope.gcp_inventory_file:
        inv_path = Path(ctx.scope.gcp_inventory_file)
        if inv_path.is_file():
            shutil.copyfile(inv_path, ctx.gcp_dir / "public_ips.tsv")
        else:
            log.warn(f"gcp_inventory_file not found: {inv_path}")
            return
    elif dm.is_available("gcloud"):
        projects = list(ctx.scope.gcp_projects)
        if not projects:
            cmd = dm.build_cmd("gcloud", ["projects", "list", "--format=json"])
            res = ev(ctx.console_dir, "G", cmd, timeout=60, title="GCP: list projects")
            if res.returncode != 0:
                log.warn("gcloud projects list failed or returned no projects (gcloud auth login?)")
                return
            try:
                proj_data = json.loads(res.stdout)
                if isinstance(proj_data, list):
                    projects = [
                        p.get("projectId")
                        for p in proj_data
                        if isinstance(p, dict) and p.get("projectId")
                    ]
            except Exception:
                projects = []

            if not projects:
                log.warn("gcloud projects list failed or returned no projects (gcloud auth login?)")
                return

        public_ips: list[tuple[str, str, str, str]] = []  # (ip, name, project, resource_type)
        firewall_rules: list[tuple[str, str, str, str, str]] = []  # (name, project, network, ports, targetTags)

        for proj in projects:
            # 1. Static addresses
            cmd_addr = dm.build_cmd(
                "gcloud",
                ["compute", "addresses", "list", "--project", proj, "--format=json"],
            )
            res_addr = ev(
                ctx.console_dir,
                "G",
                cmd_addr,
                timeout=60,
                title=f"GCP ({proj}): compute addresses",
            )
            if res_addr.returncode == 0:
                try:
                    addr_data = json.loads(res_addr.stdout)
                    if isinstance(addr_data, list):
                        for item in addr_data:
                            if not isinstance(item, dict):
                                continue
                            addr_type = str(item.get("addressType") or "EXTERNAL").upper()
                            ip = str(item.get("address") or "").strip()
                            name = str(item.get("name") or "").strip()
                            if addr_type != "INTERNAL" and ip and not _is_private_ip(ip):
                                public_ips.append((ip, name, proj, "address"))
                except Exception:
                    pass

            # 2. VM instances
            cmd_inst = dm.build_cmd(
                "gcloud",
                ["compute", "instances", "list", "--project", proj, "--format=json"],
            )
            res_inst = ev(
                ctx.console_dir,
                "G",
                cmd_inst,
                timeout=90,
                title=f"GCP ({proj}): compute instances",
            )
            if res_inst.returncode == 0:
                try:
                    inst_data = json.loads(res_inst.stdout)
                    if isinstance(inst_data, list):
                        for item in inst_data:
                            if not isinstance(item, dict):
                                continue
                            inst_name = str(item.get("name") or "").strip()
                            interfaces = item.get("networkInterfaces") or []
                            for iface in interfaces:
                                if not isinstance(iface, dict):
                                    continue
                                configs = iface.get("accessConfigs") or []
                                for ac in configs:
                                    if not isinstance(ac, dict):
                                        continue
                                    nat_ip = str(ac.get("natIP") or "").strip()
                                    if nat_ip and not _is_private_ip(nat_ip):
                                        public_ips.append((nat_ip, inst_name, proj, "instance"))
                except Exception:
                    pass

            # 3. Load Balancer forwarding rules
            cmd_fr = dm.build_cmd(
                "gcloud",
                ["compute", "forwarding-rules", "list", "--project", proj, "--format=json"],
            )
            res_fr = ev(
                ctx.console_dir,
                "G",
                cmd_fr,
                timeout=60,
                title=f"GCP ({proj}): forwarding rules",
            )
            if res_fr.returncode == 0:
                try:
                    fr_data = json.loads(res_fr.stdout)
                    if isinstance(fr_data, list):
                        for item in fr_data:
                            if not isinstance(item, dict):
                                continue
                            scheme = str(item.get("loadBalancingScheme") or "").upper()
                            if "INTERNAL" in scheme:
                                continue
                            ip = str(item.get("IPAddress") or "").strip()
                            fr_name = str(item.get("name") or "").strip()
                            if ip and not _is_private_ip(ip):
                                public_ips.append((ip, fr_name, proj, "forwarding_rule"))
                except Exception:
                    pass

            # 4. VPC Firewall rules
            cmd_fw = dm.build_cmd(
                "gcloud",
                ["compute", "firewall-rules", "list", "--project", proj, "--format=json"],
            )
            res_fw = ev(
                ctx.console_dir,
                "G",
                cmd_fw,
                timeout=60,
                title=f"GCP ({proj}): firewall rules",
            )
            if res_fw.returncode == 0:
                try:
                    fw_data = json.loads(res_fw.stdout)
                    if isinstance(fw_data, list):
                        for item in fw_data:
                            if not isinstance(item, dict):
                                continue
                            direction = str(item.get("direction") or "INGRESS").upper()
                            if direction != "INGRESS":
                                continue
                            if item.get("disabled", False):
                                continue
                            src_ranges = set(item.get("sourceRanges") or [])
                            if not (src_ranges & {"0.0.0.0/0", "*"}):
                                continue
                            allowed = item.get("allowed") or []
                            if not allowed:
                                continue

                            port_specs: list[str] = []
                            has_all = False
                            for allow in allowed:
                                if not isinstance(allow, dict):
                                    continue
                                proto = str(allow.get("IPProtocol") or "").lower()
                                ports = allow.get("ports") or []
                                if proto == "all":
                                    has_all = True
                                    break
                                elif ports:
                                    for p in ports:
                                        port_specs.append(f"{proto}:{p}")
                                else:
                                    port_specs.append(proto)

                            ports_str = "all" if has_all else (",".join(port_specs) if port_specs else "all")

                            fw_name = str(item.get("name") or "").strip()
                            net = str(item.get("network") or "").strip()
                            if "/" in net:
                                net = net.split("/")[-1]
                            target_tags = item.get("targetTags") or []
                            target_tags_str = ",".join(str(t) for t in target_tags)

                            firewall_rules.append((fw_name, proj, net, ports_str, target_tags_str))
                except Exception:
                    pass

        # Write firewall_internet_rules.tsv
        with (ctx.gcp_dir / "firewall_internet_rules.tsv").open("w", encoding="utf-8") as f:
            for fw_name, proj, net, ports_str, target_tags_str in firewall_rules:
                f.write(f"{fw_name}\t{proj}\t{net}\t{ports_str}\t{target_tags_str}\n")

        # Deduplicate public IPs and write public_ips.tsv
        seen_ips: set[str] = set()
        deduped_ips: list[tuple[str, str, str, str]] = []
        for ip, name, proj, rtype in public_ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                deduped_ips.append((ip, name, proj, rtype))

        with (ctx.gcp_dir / "public_ips.tsv").open("w", encoding="utf-8") as f:
            for ip, name, proj, rtype in deduped_ips:
                f.write(f"{ip}\t{name}\t{proj}\t{rtype}\n")
    else:
        log.warn("gcloud CLI missing and no gcp_inventory_file - Annex G skipped")
        return

    # Posture check when requested
    if bool(getattr(ctx, "cloud_posture", False) or getattr(ctx.scope, "cloud_posture", False)):
        _run_gcp_posture(ctx, dm, log, projects)

    _scan_cloud_ips(ctx, dm, log, ctx.gcp_dir, "G", "GCP")


def phaseW(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Annex W - asset-informed exposure & posture (AWS public IPs, ALB/RDS/CloudFront, SGs & posture)."""
    log.info("Annex W - asset-informed exposure & posture (AWS public IPs, ALB/RDS/CloudFront, SGs & posture)")
    aws_dir = getattr(ctx, "aws_dir", ctx.run_dir / "aws")
    aws_dir.mkdir(parents=True, exist_ok=True)

    profiles: list[str] = list(getattr(ctx.scope, "aws_profiles", []))
    if not profiles:
        profiles = [""]

    regions: list[str] = list(getattr(ctx.scope, "aws_regions", []))

    # 1. Scannable AWS Assets Enumeration
    aws_inv_file = getattr(ctx.scope, "aws_inventory_file", "")
    if aws_inv_file:
        inv_path = Path(aws_inv_file)
        if inv_path.is_file():
            shutil.copyfile(inv_path, aws_dir / "public_ips.tsv")
        else:
            log.warn(f"aws_inventory_file not found: {inv_path}")
            return
    elif dm.is_available("aws"):
        # Auto-discover regions if not specified
        if not regions:
            cmd_reg = dm.build_cmd(
                "aws",
                ["ec2", "describe-regions", "--query", "Regions[].RegionName", "--output", "json"],
            )
            res_reg = ev(
                ctx.console_dir,
                "W",
                cmd_reg,
                timeout=30,
                title="AWS: describe regions",
            )
            if res_reg.returncode == 0:
                try:
                    reg_list = json.loads(res_reg.stdout)
                    if isinstance(reg_list, list) and reg_list:
                        regions = [str(r) for r in reg_list]
                except Exception:
                    pass
            if not regions:
                regions = ["us-east-1"]

        # Verify identity
        cmd_id = _build_aws_cmd(dm, ["sts", "get-caller-identity", "--output", "json"], profiles[0])
        res_id = ev(
            ctx.console_dir,
            "W",
            cmd_id,
            timeout=30,
            title="AWS: sts get-caller-identity",
        )
        if res_id.returncode != 0:
            log.warn("aws sts get-caller-identity failed (configure AWS credentials) - Annex W skipped")
            return

        public_ips: list[tuple[str, str, str, str]] = []  # (ip, name, account_or_region, resource_type)
        public_endpoints: list[tuple[str, str, str, str]] = []  # (hostname, resource_type, region, detail)
        sg_rules: list[tuple[str, str, str, str, str]] = []  # (group_id, group_name, region, ports, cidr)

        # Global assets (CloudFront)
        for prof in profiles:
            cmd_cf = _build_aws_cmd(dm, ["cloudfront", "list-distributions", "--output", "json"], prof)
            res_cf = ev(
                ctx.console_dir,
                "W",
                cmd_cf,
                timeout=60,
                title="AWS: list cloudfront distributions",
            )
            if res_cf.returncode == 0:
                try:
                    cf_data = json.loads(res_cf.stdout)
                    items = cf_data.get("DistributionList", {}).get("Items", [])
                    for dist in items:
                        if not isinstance(dist, dict):
                            continue
                        domain_name = str(dist.get("DomainName") or "").strip()
                        dist_id = str(dist.get("Id") or "").strip()
                        aliases = dist.get("Aliases", {}).get("Items", []) or []
                        aliases_str = ",".join(str(a) for a in aliases)
                        if domain_name:
                            public_endpoints.append(
                                (domain_name, "cloudfront", "global", f"id={dist_id} aliases={aliases_str}")
                            )
                except Exception:
                    pass

        # Per-profile and per-region assets
        for prof in profiles:
            for reg in regions:
                # 1. Elastic IPs
                cmd_eip = _build_aws_cmd(dm, ["ec2", "describe-addresses", "--output", "json"], prof, reg)
                res_eip = ev(
                    ctx.console_dir,
                    "W",
                    cmd_eip,
                    timeout=60,
                    title=f"AWS ({reg}): describe addresses",
                )
                if res_eip.returncode == 0:
                    try:
                        eip_data = json.loads(res_eip.stdout)
                        for addr in eip_data.get("Addresses", []):
                            if not isinstance(addr, dict):
                                continue
                            ip = str(addr.get("PublicIp") or "").strip()
                            alloc_id = str(addr.get("AllocationId") or "").strip()
                            assoc_id = str(addr.get("AssociationId") or "").strip()
                            name = alloc_id or assoc_id or ip
                            if ip and not _is_private_ip(ip):
                                public_ips.append((ip, name, reg, "elastic_ip"))
                    except Exception:
                        pass

                # 2. EC2 Instances with Public IP
                cmd_ec2 = _build_aws_cmd(dm, ["ec2", "describe-instances", "--output", "json"], prof, reg)
                res_ec2 = ev(
                    ctx.console_dir,
                    "W",
                    cmd_ec2,
                    timeout=90,
                    title=f"AWS ({reg}): describe instances",
                )
                if res_ec2.returncode == 0:
                    try:
                        ec2_data = json.loads(res_ec2.stdout)
                        for resv in ec2_data.get("Reservations", []):
                            if not isinstance(resv, dict):
                                continue
                            for inst in resv.get("Instances", []):
                                if not isinstance(inst, dict):
                                    continue
                                ip = str(inst.get("PublicIpAddress") or "").strip()
                                iid = str(inst.get("InstanceId") or "").strip()
                                inst_name = ""
                                for tag in inst.get("Tags", []):
                                    if isinstance(tag, dict) and tag.get("Key") == "Name":
                                        inst_name = str(tag.get("Value") or "").strip()
                                name = inst_name or iid
                                if ip and not _is_private_ip(ip):
                                    public_ips.append((ip, name, reg, "ec2_instance"))
                    except Exception:
                        pass

                # 3. Load Balancers (ALB/NLB)
                cmd_lb = _build_aws_cmd(dm, ["elbv2", "describe-load-balancers", "--output", "json"], prof, reg)
                res_lb = ev(
                    ctx.console_dir,
                    "W",
                    cmd_lb,
                    timeout=60,
                    title=f"AWS ({reg}): describe load balancers",
                )
                if res_lb.returncode == 0:
                    try:
                        lb_data = json.loads(res_lb.stdout)
                        for lb in lb_data.get("LoadBalancers", []):
                            if not isinstance(lb, dict):
                                continue
                            scheme = str(lb.get("Scheme") or "").lower()
                            if scheme == "internet-facing":
                                dns_name = str(lb.get("DNSName") or "").strip()
                                lb_name = str(lb.get("LoadBalancerName") or "").strip()
                                lb_type = str(lb.get("Type") or "alb").strip()
                                if dns_name:
                                    public_endpoints.append((dns_name, f"lb_{lb_type}", reg, lb_name))
                                    try:
                                        _, _, resolved_ips = socket.gethostbyname_ex(dns_name)
                                        for rip in resolved_ips:
                                            if rip and not _is_private_ip(rip):
                                                public_ips.append((rip, lb_name or dns_name, reg, f"lb_{lb_type}"))
                                    except Exception:
                                        pass
                    except Exception:
                        pass

                # 4. Public RDS Databases
                cmd_rds = _build_aws_cmd(dm, ["rds", "describe-db-instances", "--output", "json"], prof, reg)
                res_rds = ev(
                    ctx.console_dir,
                    "W",
                    cmd_rds,
                    timeout=60,
                    title=f"AWS ({reg}): describe rds instances",
                )
                if res_rds.returncode == 0:
                    try:
                        rds_data = json.loads(res_rds.stdout)
                        for db in rds_data.get("DBInstances", []):
                            if not isinstance(db, dict):
                                continue
                            if db.get("PubliclyAccessible") is True:
                                dbid = str(db.get("DBInstanceIdentifier") or "").strip()
                                endpoint = db.get("Endpoint") or {}
                                addr = str(endpoint.get("Address") or "").strip()
                                port = str(endpoint.get("Port") or "").strip()
                                endpoint_str = f"{addr}:{port}" if port else addr
                                if addr:
                                    public_endpoints.append((endpoint_str, "rds", reg, dbid))
                                    try:
                                        _, _, resolved_ips = socket.gethostbyname_ex(addr)
                                        for rip in resolved_ips:
                                            if rip and not _is_private_ip(rip):
                                                public_ips.append((rip, dbid or addr, reg, "rds"))
                                    except Exception:
                                        pass
                    except Exception:
                        pass

                # 5. Security Groups open to Internet
                cmd_sg = _build_aws_cmd(dm, ["ec2", "describe-security-groups", "--output", "json"], prof, reg)
                res_sg = ev(
                    ctx.console_dir,
                    "W",
                    cmd_sg,
                    timeout=60,
                    title=f"AWS ({reg}): describe security groups",
                )
                if res_sg.returncode == 0:
                    try:
                        sg_data = json.loads(res_sg.stdout)
                        for sg in sg_data.get("SecurityGroups", []):
                            if not isinstance(sg, dict):
                                continue
                            gid = str(sg.get("GroupId") or "").strip()
                            gname = str(sg.get("GroupName") or "").strip()
                            for perm in sg.get("IpPermissions", []):
                                if not isinstance(perm, dict):
                                    continue
                                ip_proto = str(perm.get("IpProtocol") or "all").lower()
                                from_p = perm.get("FromPort")
                                to_p = perm.get("ToPort")
                                if ip_proto in ("-1", "all"):
                                    ports_str = "all"
                                elif from_p is not None and to_p is not None:
                                    ports_str = str(from_p) if from_p == to_p else f"{from_p}-{to_p}"
                                else:
                                    ports_str = ip_proto

                                for ipr in perm.get("IpRanges", []):
                                    if isinstance(ipr, dict):
                                        cidr = str(ipr.get("CidrIp") or "").strip()
                                        if cidr in ("0.0.0.0/0", "*"):
                                            sg_rules.append((gid, gname, reg, ports_str, cidr))

                                for ipr6 in perm.get("Ipv6Ranges", []):
                                    if isinstance(ipr6, dict):
                                        cidr6 = str(ipr6.get("CidrIpv6") or "").strip()
                                        if cidr6 in ("::/0", "*"):
                                            sg_rules.append((gid, gname, reg, ports_str, cidr6))
                    except Exception:
                        pass

        # Write sg_internet_rules.tsv
        with (aws_dir / "sg_internet_rules.tsv").open("w", encoding="utf-8") as f:
            for gid, gname, reg, ports_str, cidr in sg_rules:
                f.write(f"{gid}\t{gname}\t{reg}\t{ports_str}\t{cidr}\n")

        # Write public_endpoints.tsv
        with (aws_dir / "public_endpoints.tsv").open("w", encoding="utf-8") as f:
            for hostname, rtype, reg, detail in public_endpoints:
                f.write(f"{hostname}\t{rtype}\t{reg}\t{detail}\n")

        # Deduplicate and write public_ips.tsv
        seen_ips: set[str] = set()
        deduped_ips: list[tuple[str, str, str, str]] = []
        for ip, name, acct_reg, rtype in public_ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                deduped_ips.append((ip, name, acct_reg, rtype))

        with (aws_dir / "public_ips.tsv").open("w", encoding="utf-8") as f:
            for ip, name, acct_reg, rtype in deduped_ips:
                f.write(f"{ip}\t{name}\t{acct_reg}\t{rtype}\n")
    else:
        log.warn("aws CLI missing and no aws_inventory_file - Annex W skipped")
        return

    # 2. AWS Security Posture checks
    if bool(getattr(ctx, "cloud_posture", False) or getattr(ctx.scope, "cloud_posture", False)):
        if not regions:
            regions = ["us-east-1"]
        _run_aws_posture(ctx, dm, log, profiles, regions)

    # 3. Port & Service scanning
    _scan_cloud_ips(ctx, dm, log, aws_dir, "W", "AWS")
