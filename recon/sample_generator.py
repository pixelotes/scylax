"""Generate realistic synthetic assessment data and compile sample reports.

Builds a comprehensive synthetic run directory for:
'Contoso Ltd. & Northwind Traders — H2 External Attack Surface Assessment'
across contoso.com, northwindtraders.com, and fabrikam.io.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure package root is in sys.path
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from recon.report import generate_reports


def build_sample_run(run_dir: Path) -> None:
    """Populate run_dir with rich, realistic assessment artifacts across all phases."""
    raw_dir = run_dir / "raw"
    web_dir = run_dir / "web"
    scan_dir = run_dir / "scan"
    osint_dir = run_dir / "osint"
    azure_dir = run_dir / "azure"
    gcp_dir = run_dir / "gcp"
    saas_dir = run_dir / "saas"
    console_dir = run_dir / "console"

    for d in (raw_dir, web_dir, scan_dir, osint_dir, azure_dir, gcp_dir, saas_dir, console_dir):
        d.mkdir(parents=True, exist_ok=True)

    # 1. run.meta
    meta_content = (
        "engagement=Contoso & Northwind Traders Semi-Annual EASM\n"
        "scope=contoso_northwind\n"
        "date=2026-11-03\n"
        "authorised_by=Sarah Jenkins, VP of Information Security (Contoso Ltd.)\n"
        "authorisation_ref=SEC-2026-8841\n"
        "phases=1 2 3 4 4b 5 6 7 8 9 A G S T\n"
        "skip_active=0\n"
        "use_docker=0\n"
        "egress_ip=198.51.100.24\n"
    )
    (run_dir / "run.meta").write_text(meta_content, encoding="utf-8")

    # 2. tool_versions.txt
    tool_versions_content = (
        "dig native: DiG 9.10.6\n"
        "whois native: system whois\n"
        "subfinder native: subfinder v2.6.6\n"
        "dnsx native: dnsx 1.1.6\n"
        "httpx native: httpx v1.6.8\n"
        "nmap native: Nmap 7.95 ( https://nmap.org )\n"
        "nuclei native: nuclei v3.3.5\n"
        "amass docker: docker (caffix/amass:latest)\n"
        "whatweb docker: docker (bberastegui/whatweb:latest)\n"
        "trufflehog docker: docker (trufflesecurity/trufflehog:latest)\n"
        "az native: azure-cli 2.65.0\n"
        "gcloud native: Google Cloud SDK 500.0.0\n"
    )
    (run_dir / "tool_versions.txt").write_text(tool_versions_content, encoding="utf-8")

    # 3. gaps.txt
    gaps_content = (
        "amass execution timed out after 10m on contoso.com - crt.sh and subfinder results retained\n"
        "whatweb ruby gems missing on native host - container provider used\n"
    )
    (run_dir / "gaps.txt").write_text(gaps_content, encoding="utf-8")

    # 4. findings_auto.tsv
    findings = [
        ("CRITICAL", "routeros:203.0.113.45", "End-of-life RouterOS 6.48.6 on branch office edge gateway", "203.0.113.45:8291 MikroTik RouterOS 6.48.6 (RouterOS winbox)"),
        ("CRITICAL", "cve:198.51.100.52:CVE-2024-38077", "Remote Desktop Services RCE CVE-2024-38077 (CISA KEV)", "198.51.100.52:3389 Microsoft Remote Desktop Services (CVSS 9.8)"),
        ("CRITICAL", "mgmt:198.51.100.52:3389", "Management / legacy service ms-wbt-server exposed", "198.51.100.52:3389 Microsoft Terminal Services"),
        ("HIGH", "cve:203.0.113.19:CVE-2021-41773", "Apache 2.4.49 Path Traversal & RCE CVE-2021-41773 (CISA KEV)", "203.0.113.19:80 Apache/2.4.49 (Unix) mod_ssl/2.4.49"),
        ("HIGH", "dirlist:https://files.northwindtraders.com/exports/", "Unauthenticated directory listing", "https://files.northwindtraders.com/exports/ (Index of /exports)"),
        ("HIGH", "path:dev-portal.fabrikam.io/.env", "Exposed environment configuration (.env)", "https://dev-portal.fabrikam.io/.env contains APP_KEY and DB_PASSWORD"),
        ("HIGH", "path:api-staging.northwindtraders.com/v2/api-docs", "Exposed OpenAPI / Swagger specification", "https://api-staging.northwindtraders.com/v2/api-docs (Swagger 2.0 API spec)"),
        ("HIGH", "hibp:contoso.com:ContosoMarketing2023", "Domain breach history: Contoso Marketing Portal Leak (2023-04-18)", "18400 accounts, exposed: Email addresses;Passwords;Job titles"),
        ("HIGH", "fw-admin:198.51.100.90", "Firewall / router admin GUI on the internet", "Login | OPNsense at https://198.51.100.90/ (port 443)"),
        ("HIGH", "wayback-critical", "Sensitive files in Wayback history", "18 URLs with config/sql/backup extensions"),
        ("HIGH", "az-storage-public:stcontosoexports", "Azure Storage Account stcontosoexports allows public blob access", "rg-contoso-storage/stcontosoexports allowBlobPublicAccess=true"),
        ("MEDIUM", "hibp:northwindtraders.com:NorthwindSupport2022", "Domain breach history: Northwind Customer Support Leak (2022-11-05)", "9350 accounts, exposed: Email addresses;Names;Phone numbers"),
        ("MEDIUM", "az-storage-http:stnorthwindlogs", "Azure Storage Account stnorthwindlogs allows unencrypted HTTP traffic", "rg-northwind-data/stnorthwindlogs supportsHttpsTrafficOnly=false"),
        ("MEDIUM", "az-kv-purge:kv-contoso-prod", "Key Vault kv-contoso-prod has purge protection disabled", "rg-contoso-security/kv-contoso-prod enablePurgeProtection=false"),
        ("MEDIUM", "az-sql-public:sql-contoso-erp", "Azure SQL Server sql-contoso-erp has public network access enabled", "rg-contoso-erp-prod/sql-contoso-erp publicNetworkAccess=Enabled"),
        ("MEDIUM", "az-defender-free:VirtualMachines", "Microsoft Defender for Cloud disabled (Free tier) for VirtualMachines", "pricingTier=Free"),
        ("MEDIUM", "az-defender-free:StorageAccounts", "Microsoft Defender for Cloud disabled (Free tier) for StorageAccounts", "pricingTier=Free"),
        ("MEDIUM", "az-defender-free:SqlServers", "Microsoft Defender for Cloud disabled (Free tier) for SqlServers", "pricingTier=Free"),
        ("MEDIUM", "az-kv-purge:kv-northwind-dev", "Key Vault kv-northwind-dev has purge protection disabled", "rg-northwind-security/kv-northwind-dev enablePurgeProtection=false"),
        ("MEDIUM", "nsg:nsg-contoso-erp-prod:Allow-RDP-Internet", "NSG allows 3389 from Internet", "rg-contoso-erp-prod/nsg-contoso-erp-prod rule Allow-RDP-Internet (nics: nic-contoso-erp-01)"),
        ("MEDIUM", "gcp-fw:allow-ssh-legacy", "GCP firewall allows tcp:22 from Internet", "contoso-analytics-prod/allow-ssh-legacy (source: 0.0.0.0/0)"),
        ("MEDIUM", "dmarc:fabrikam.io", "fabrikam.io has no DMARC p=reject", "v=DMARC1; p=none; rua=mailto:dmarc@fabrikam.io"),
        ("MEDIUM", "apex:fabrikam.io", "fabrikam.io apex resolves to infrastructure not in our inventory", "192.0.2.77 (DigitalOcean, LLC)"),
        ("MEDIUM", "internal-name:vpn-internal.contoso.com", "Internal-named host publicly resolvable", "vpn-internal.contoso.com -> 198.51.100.15"),
        ("MEDIUM", "cert-expired:203.0.113.88", "Expired TLS certificate", "203.0.113.88 expired 2026-08-14"),
        ("LOW", "az-storage-tls:stnorthwindlogs", "Azure Storage Account stnorthwindlogs uses legacy TLS (TLS1_0)", "rg-northwind-data/stnorthwindlogs minimumTlsVersion=TLS1_0"),
        ("LOW", "az-storage-tls:stcontosobackups", "Azure Storage Account stcontosobackups uses legacy TLS (TLS1_1)", "rg-contoso-storage/stcontosobackups minimumTlsVersion=TLS1_1"),
        ("LOW", "headers:www", "Public website missing security headers", "https://www.contoso.com: permissions-policy x-content-type-options"),
        ("LOW", "caa:fabrikam.io", "No CAA on fabrikam.io", "dig CAA fabrikam.io"),
        ("LOW", "dnssec:fabrikam.io", "DNSSEC unsigned on fabrikam.io", "dig DNSKEY fabrikam.io"),
        ("INFO", "perimeter:mapping", "Multi-cloud attack surface perimeter mapped", "85 subdomains identified across 3 domains in AWS, Azure, GCP, and DigitalOcean"),
        # SaaS Posture Findings
        ("CRITICAL", "m365-admin-no-mfa", "2 Global Administrators without MFA registered", "Accounts admin-backup@contoso.com, breakglass-svc@contoso.com have Global Admin role without MFA registered"),
        ("HIGH", "m365-ca-no-mfa-all", "Conditional Access without a policy requiring MFA for all users", "No active Conditional Access policy enforces MFA for all users across all cloud apps"),
        ("HIGH", "m365-oauth-allprincipals-mail", "OAuth grant with Mail.ReadWrite to AllPrincipals", "Delegated permission Mail.ReadWrite consented for AllPrincipals scope on ContosoMailSyncApp"),
        ("HIGH", "gh-org-2fa-disabled", "Organization does not require 2FA for 3 members", "3 members without 2FA registered in contoso-org; two_factor_requirement_enabled=false"),
        ("HIGH", "gh-secret-scanning-alerts", "Open secret scanning alerts in organization repositories", "2 unresolved secret scanning alerts in contoso-org/contoso-api"),
        ("MEDIUM", "m365-guest-users-active", "14 active guest users with access to tenant resources", "14 external guest user accounts active; 4 have not signed in for over 180 days"),
        ("MEDIUM", "m365-stale-accounts", "Stale user accounts inactive for >90 days", "8 enabled user accounts with lastSignInDateTime older than 90 days"),
        ("MEDIUM", "m365-app-secret-expired", "App registration secret expired", "Client secret for app contoso-crm-connector expired on 2026-10-15"),
        ("MEDIUM", "gh-repo-no-branch-protection", "6 repos without branch protection", "Repositories contoso-api, northwind-web, fabrikam-core, data-pipeline, devops-tools, staging-env lack default branch protection"),
        ("MEDIUM", "gh-webhook-ssl-insecure", "Webhook without SSL verification", "Webhook URL https://ci.contoso.com/gh-hook in contoso-org/northwind-web has SSL verification disabled"),
        ("LOW", "m365-ca-report-only", "Conditional Access policies in report-only mode", "Policy CA003-LegacyAuthBlock configured in report-only mode (not enforced)"),
        ("INFO", "m365-mfa-compliance", "MFA compliance at 91%", "242 of 266 total licensed users in contoso.com tenant have registered MFA authentication methods"),
    ]
    def _sample_target(key: str, evidence: str) -> str:
        # Derive a finding target (IP, then hostname) from the key/evidence so the
        # sample exercises asset grouping just like a real run's Target column.
        for text in (key, evidence):
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
            if m:
                return m.group(1)
        m = re.search(r"\bhttps?://([a-z0-9.-]+)", evidence.lower())
        if m:
            return m.group(1)
        m = re.search(r"\b([a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,})\b", (key + " " + evidence).lower())
        return m.group(1) if m else ""

    tsv_content = "".join(
        f"{s}\t{k}\t{t}\t{e}\t{_sample_target(k, e)}\n" for s, k, t, e in findings
    )
    (run_dir / "findings_auto.tsv").write_text(tsv_content, encoding="utf-8")

    # 5. findings_auto.md
    md_lines = [
        "# Automatic finding candidates - 2026-11-03\n\n",
        "Validate every line by hand before it goes into the report.\n\n",
        "| Severity | Finding | Evidence | Key |\n",
        "|---|---|---|---|\n",
    ]
    for s, k, t, e in findings:
        md_lines.append(f"| {s} | {t} | {e} | `{k}` |\n")
    md_lines.append("\n## Gaps / tool failures\n\n")
    md_lines.append("- amass execution timed out after 10m on contoso.com - crt.sh and subfinder results retained\n")
    md_lines.append("- whatweb ruby gems missing on native host - container provider used\n")
    (run_dir / "findings_auto.md").write_text("".join(md_lines), encoding="utf-8")

    # 6. diff.md
    diff_content = (
        "# Changes 2026-05-12 -> 2026-11-03\n\n"
        "## New (4)\n\n"
        "- **CRITICAL** End-of-life RouterOS 6.48.6 on branch office edge gateway - 203.0.113.45:8291\n"
        "- **HIGH** Exposed environment configuration (.env) - dev-portal.fabrikam.io/.env\n"
        "- **HIGH** Unauthenticated directory listing - https://files.northwindtraders.com/exports/\n"
        "- **MEDIUM** GCP firewall allows tcp:22 from Internet - contoso-analytics-prod/allow-ssh-legacy\n\n"
        "## Resolved (3)\n\n"
        "- **HIGH** Apache 2.4.49 Path Traversal & RCE CVE-2021-41773 - 203.0.113.19:80\n"
        "- **MEDIUM** Public website missing security headers - https://www.contoso.com\n"
        "- **LOW** No CAA on northwindtraders.com - dig CAA northwindtraders.com\n\n"
        "## Persisting (9)\n\n"
        "- **CRITICAL** Management / legacy service ms-wbt-server exposed - 198.51.100.52:3389\n"
        "- **CRITICAL** Remote Desktop Services RCE CVE-2024-38077 (CISA KEV) - 198.51.100.52:3389\n"
        "- **HIGH** Firewall / router admin GUI on the internet - 198.51.100.90 (Login | OPNsense)\n"
        "- **HIGH** Sensitive files in Wayback history - 18 URLs\n"
        "- **HIGH** Exposed OpenAPI / Swagger specification - api-staging.northwindtraders.com/v2/api-docs\n"
        "- **MEDIUM** NSG allows 3389 from Internet - rg-contoso-erp-prod/nsg-contoso-erp-prod rule Allow-RDP-Internet\n"
        "- **MEDIUM** fabrikam.io has no DMARC p=reject - dig TXT _dmarc.fabrikam.io\n"
        "- **MEDIUM** fabrikam.io apex resolves to infrastructure not in our inventory - 192.0.2.77 (DigitalOcean)\n"
        "- **LOW** DNSSEC unsigned on fabrikam.io - dig DNSKEY fabrikam.io\n"
    )
    (run_dir / "diff.md").write_text(diff_content, encoding="utf-8")

    # 7. OSINT Subdomains
    subdomains = [
        "contoso.com", "www.contoso.com", "mail.contoso.com", "autodiscover.contoso.com",
        "vpn.contoso.com", "vpn-internal.contoso.com", "portal.contoso.com", "erp.contoso.com",
        "staging.contoso.com", "dev.contoso.com", "api.contoso.com", "auth.contoso.com",
        "sso.contoso.com", "mfa.contoso.com", "remote.contoso.com", "ns1.contoso.com",
        "ns2.contoso.com", "app.contoso.com", "status.contoso.com", "edge-gw.contoso.com",
        "gateway.contoso.com", "connect.contoso.com", "analytics.contoso.com", "crm.contoso.com",
        "northwindtraders.com", "www.northwindtraders.com", "shop.northwindtraders.com",
        "api.northwindtraders.com", "api-staging.northwindtraders.com", "files.northwindtraders.com",
        "cdn.northwindtraders.com", "orders.northwindtraders.com", "tracking.northwindtraders.com",
        "partner.northwindtraders.com", "supplier.northwindtraders.com", "payments.northwindtraders.com",
        "b2b.northwindtraders.com", "wholesale.northwindtraders.com",
        "fabrikam.io", "www.fabrikam.io", "dev-portal.fabrikam.io", "api.fabrikam.io",
        "docs.fabrikam.io", "sandbox.fabrikam.io", "auth.fabrikam.io", "console.fabrikam.io",
        "telemetry.fabrikam.io", "iot-hub.fabrikam.io", "firmware.fabrikam.io"
    ]
    (osint_dir / "subdomains.txt").write_text("\n".join(subdomains) + "\n", encoding="utf-8")
    (osint_dir / "subdomain_counts.txt").write_text("contoso.com: 24\nnorthwindtraders.com: 14\nfabrikam.io: 11\n", encoding="utf-8")
    (osint_dir / "new_subdomains.txt").write_text("api-staging.northwindtraders.com\ndev-portal.fabrikam.io\nfiles.northwindtraders.com\nedge-gw.contoso.com\n", encoding="utf-8")
    (osint_dir / "gone_subdomains.txt").write_text("legacy-test.contoso.com\nold-checkout.northwindtraders.com\n", encoding="utf-8")
    (osint_dir / "resolved.txt").write_text("\n".join(subdomains) + "\n", encoding="utf-8")

    discovered_ips = [
        "198.51.100.10", "198.51.100.12", "198.51.100.15", "198.51.100.52", "198.51.100.90",
        "203.0.113.19", "203.0.113.45", "203.0.113.88", "192.0.2.77"
    ]
    (osint_dir / "discovered_targets.txt").write_text("\n".join(discovered_ips) + "\n", encoding="utf-8")

    # 8. IP Organizations
    ip_orgs_data = [
        ("198.51.100.10", "Microsoft Azure (East US)", "erp-lb.contoso.com", "erp.contoso.com, portal.contoso.com"),
        ("198.51.100.12", "Microsoft Azure (East US)", "mail-relay.contoso.com", "mail.contoso.com, autodiscover.contoso.com"),
        ("198.51.100.15", "Microsoft Azure (East US)", "vpn-gw.contoso.com", "vpn.contoso.com, vpn-internal.contoso.com"),
        ("198.51.100.52", "Microsoft Azure (West Europe)", "vm-erp-legacy.contoso.com", "remote.contoso.com"),
        ("198.51.100.90", "Cogent Communications", "edge-fw01.contoso.com", "fw01.contoso.com"),
        ("203.0.113.19", "Amazon Web Services (us-east-1)", "ec2-legacy-app.aws.com", "api-staging.northwindtraders.com"),
        ("203.0.113.45", "Lumen Technologies (Tier 1)", "branch-gw45.northwind.net", "edge-gw.contoso.com"),
        ("203.0.113.88", "Google Cloud Platform (us-central1)", "gcp-lb-ingress.google.com", "shop.northwindtraders.com"),
        ("192.0.2.77", "DigitalOcean, LLC", "droplet-untracked-77.do.net", "fabrikam.io, dev-portal.fabrikam.io"),
    ]
    ip_orgs_tsv = "".join(f"{ip}\t{org}\t{ptr}\t{hosts}\n" for ip, org, ptr, hosts in ip_orgs_data)
    (osint_dir / "ip_orgs.tsv").write_text(ip_orgs_tsv, encoding="utf-8")

    # 9. DNS Posture files
    dns_contoso = (
        ";; Domain: contoso.com\n"
        "$ dig +short SOA contoso.com\n"
        "ns1-09.azure-dns.com. msnhst.microsoft.com. 1 3600 300 2419200 300\n\n"
        "$ dig +short TXT contoso.com\n"
        '"v=spf1 include:spf.protection.outlook.com -all"\n\n"MS=ms98124019"\n\n'
        "$ dig +short TXT _dmarc.contoso.com\n"
        '"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@contoso.com; ruf=mailto:dmarc@contoso.com; sp=reject; aspf=r;"\n\n'
        "$ dig +short CAA contoso.com\n"
        '0 issue "digicert.com"\n0 issue "letsencrypt.org"\n0 iodef "mailto:security@contoso.com"\n\n'
        "$ dig +short DNSKEY contoso.com\n"
        "257 3 13 4iM8aWq...==\n"
    )
    (osint_dir / "dns_contoso.com.txt").write_text(dns_contoso, encoding="utf-8")

    dns_northwind = (
        ";; Domain: northwindtraders.com\n"
        "$ dig +short SOA northwindtraders.com\n"
        "dns1.p04.nsone.net. hostmaster.nsone.net. 17290182 43200 7200 1209600 3600\n\n"
        "$ dig +short TXT northwindtraders.com\n"
        '"v=spf1 include:_spf.google.com ~all"\n\n'
        "$ dig +short TXT _dmarc.northwindtraders.com\n"
        '"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@northwindtraders.com;"\n\n'
        "$ dig +short CAA northwindtraders.com\n"
        '0 issue "letsencrypt.org"\n\n'
        "$ dig +short DNSKEY northwindtraders.com\n"
        "257 3 8 AwEAAc9...\n"
    )
    (osint_dir / "dns_northwindtraders.com.txt").write_text(dns_northwind, encoding="utf-8")

    dns_fabrikam = (
        ";; Domain: fabrikam.io\n"
        "$ dig +short SOA fabrikam.io\n"
        "ns1.digitalocean.com. hostmaster.fabrikam.io. 17290182 10800 3600 604800 1800\n\n"
        "$ dig +short TXT fabrikam.io\n"
        '"v=spf1 include:mailgun.org ~all"\n\n'
        "$ dig +short TXT _dmarc.fabrikam.io\n"
        '"v=DMARC1; p=none; rua=mailto:dmarc@fabrikam.io;"\n\n'
        "$ dig +short CAA fabrikam.io\n\n"
        "$ dig +short DNSKEY fabrikam.io\n\n"
    )
    (osint_dir / "dns_fabrikam.io.txt").write_text(dns_fabrikam, encoding="utf-8")

    # 10. Apex
    apex_content = (
        "contoso.com apex 13.107.246.10\n"
        "  ptr: contoso.com\n"
        "  org-name: Microsoft Corporation\n"
        "northwindtraders.com apex 104.21.65.122\n"
        "  ptr: northwindtraders.com\n"
        "  org-name: Cloudflare, Inc.\n"
        "fabrikam.io apex 192.0.2.77\n"
        "  ptr: untracked-vps.digitalocean.com\n"
        "  org-name: DigitalOcean, LLC\n"
    )
    (osint_dir / "apex.txt").write_text(apex_content, encoding="utf-8")

    # 10b. HaveIBeenPwned Domain Breaches
    hibp_content = (
        "domain\tname\ttitle\tbreach_date\tpwn_count\tdata_classes\tis_verified\tis_sensitive\n"
        "contoso.com\tContosoMarketing2023\tContoso Marketing Portal Leak\t2023-04-18\t18400\tEmail addresses;Passwords;Job titles\tTrue\tFalse\n"
        "northwindtraders.com\tNorthwindSupport2022\tNorthwind Customer Support Leak\t2022-11-05\t9350\tEmail addresses;Names;Phone numbers\tTrue\tFalse\n"
    )
    (osint_dir / "hibp_breaches.tsv").write_text(hibp_content, encoding="utf-8")

    # 10c. Discovered Corporate Emails & Account Breaches
    emails_list = [
        "sarah.jenkins@contoso.com",
        "admin-backup@contoso.com",
        "security@contoso.com",
        "support@northwindtraders.com",
        "dev-lead@fabrikam.io",
    ]
    (osint_dir / "emails.txt").write_text("\n".join(emails_list) + "\n", encoding="utf-8")
    emails_tsv = (
        "email\tdomain\tsource\n"
        "sarah.jenkins@contoso.com\tcontoso.com\ttheHarvester\n"
        "admin-backup@contoso.com\tcontoso.com\tspiderfoot\n"
        "security@contoso.com\tcontoso.com\twhois\n"
        "support@northwindtraders.com\tnorthwindtraders.com\ttheHarvester\n"
        "dev-lead@fabrikam.io\tfabrikam.io\tpgp_keyserver\n"
    )
    (osint_dir / "emails.tsv").write_text(emails_tsv, encoding="utf-8")

    hibp_account_content = (
        "email\tname\ttitle\tbreach_date\tpwn_count\tdata_classes\tis_verified\tis_sensitive\n"
        "sarah.jenkins@contoso.com\tContosoMarketing2023\tContoso Marketing Portal Leak\t2023-04-18\t18400\tEmail addresses;Passwords;Job titles\tTrue\tFalse\n"
        "dev-lead@fabrikam.io\tNorthwindSupport2022\tNorthwind Customer Support Leak\t2022-11-05\t9350\tEmail addresses;Names;Phone numbers\tTrue\tFalse\n"
    )
    (osint_dir / "hibp_account_breaches.tsv").write_text(hibp_account_content, encoding="utf-8")

    # 11. Service CVEs
    service_cves = [
        ("198.51.100.52", "3389", "ms-wbt-server", "Microsoft Terminal Services", "CVE-2024-38077", "9.8", "TRUE", "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability"),
        ("203.0.113.19", "80", "http", "Apache httpd 2.4.49", "CVE-2021-41773", "7.5", "TRUE", "Path traversal and file disclosure flaw in Apache HTTP Server 2.4.49"),
        ("203.0.113.45", "8291", "winbox", "MikroTik RouterOS 6.48.6", "CVE-2023-32154", "7.8", "FALSE", "MikroTik RouterOS IPv6 route advertisement buffer overflow vulnerability"),
        ("198.51.100.10", "443", "http", "OpenSSL 1.1.1k", "CVE-2022-0778", "7.5", "FALSE", "BN_mod_sqrt() infinite loop vulnerability in OpenSSL parsing invalid certificates"),
        ("198.51.100.90", "443", "http", "OPNsense 23.7.1", "CVE-2023-43261", "8.8", "FALSE", "Improper authentication bypass in administrative management console"),
        ("203.0.113.88", "443", "http", "nginx 1.20.1", "CVE-2021-23017", "7.7", "FALSE", "1-byte memory overwrite in resolver component leading to DoS or worker crash"),
    ]
    cves_tsv = "".join(f"{ip}\t{p}\t{svc}\t{ver}\t{cve}\t{cvss}\t{kev}\t{sum_}\n" for ip, p, svc, ver, cve, cvss, kev, sum_ in service_cves)
    (osint_dir / "service_cves.tsv").write_text(cves_tsv, encoding="utf-8")

    # 12. Entry Points
    entry_points = [
        ("IDOR / Object Reference", "id, account_id, user_id", "https://api.northwindtraders.com/v1/customers?account_id=9821"),
        ("SQL Injection / Filter", "filter, sort, query, q", "https://shop.northwindtraders.com/catalog/search?sort=price_desc&filter=active"),
        ("SSRF / Webhook", "url, callback, target, webhook", "https://dev-portal.fabrikam.io/webhooks/test?url=https://internal.fabrikam.io/"),
        ("Open Redirect", "redirect, next, return_to", "https://portal.contoso.com/login?return_to=https://portal.contoso.com/dashboard"),
        ("Debug / Admin", "debug, test, verbose, trace", "https://api-staging.northwindtraders.com/health?debug=1&trace=true"),
        ("File Inclusion / Path", "file, path, template, view", "https://files.northwindtraders.com/download?file=reports/2026-Q3.pdf"),
    ]
    entry_tsv = "".join(f"{cat}\t{param}\t{url}\n" for cat, param, url in entry_points)
    (osint_dir / "entry_points.tsv").write_text(entry_tsv, encoding="utf-8")

    # 13. Wayback Critical
    wayback_urls = [
        "https://api-staging.northwindtraders.com/.env",
        "https://files.northwindtraders.com/exports/payroll_2026.csv",
        "https://shop.northwindtraders.com/backup/database_dump.sql.gz",
        "https://portal.contoso.com/config/web.config.bak",
        "https://dev-portal.fabrikam.io/id_rsa.pub",
        "https://files.northwindtraders.com/exports/partners_export.json",
        "https://api.northwindtraders.com/v1/debug.log",
        "https://shop.northwindtraders.com/phpinfo.php",
    ]
    (osint_dir / "wayback_critical.txt").write_text("\n".join(wayback_urls) + "\n", encoding="utf-8")

    # 14. Web HTTP Probes
    httpx_lines = [
        "https://www.contoso.com [200] [Contoso Enterprise Global] [Microsoft-IIS/10.0] []",
        "https://portal.contoso.com [200] [Contoso Identity & Cloud Portal] [nginx/1.24.0] [https://auth.contoso.com/oauth2]",
        "https://erp.contoso.com [200] [Contoso ERP Enterprise Suite] [Microsoft-IIS/10.0] []",
        "https://remote.contoso.com [200] [Contoso RDS Web Gateway] [Microsoft-HTTPAPI/2.0] []",
        "https://shop.northwindtraders.com [200] [Northwind Global B2B Marketplace] [Cloudflare] []",
        "https://api.northwindtraders.com [200] [Northwind Core Commerce API v1] [envoy/1.28.0] []",
        "https://api-staging.northwindtraders.com [200] [Swagger UI - Staging API] [Apache/2.4.49] []",
        "https://files.northwindtraders.com [200] [Index of /] [Apache/2.4.52] []",
        "https://dev-portal.fabrikam.io [200] [Fabrikam Developer Sandbox] [nginx/1.22.1] []",
        "https://www.fabrikam.io [200] [Fabrikam Smart Manufacturing] [nginx/1.26.1] []",
        "https://198.51.100.90:443 [200] [Login | OPNsense] [lighttpd/1.4.69] []",
        "https://203.0.113.88:443 [502] [502 Bad Gateway] [nginx/1.20.1] []",
    ]
    (web_dir / "httpx_all.txt").write_text("\n".join(httpx_lines) + "\n", encoding="utf-8")

    # 15. Web Exposed Paths
    exposed_paths = [
        ("https://api-staging.northwindtraders.com/v2/api-docs", "OpenAPI Spec", '{"swagger":"2.0","info":{"title":"Northwind Staging Core API","version":"2.4.0"}}'),
        ("https://dev-portal.fabrikam.io/.env", "Config Leak", "APP_ENV=staging\\nAPP_KEY=base64:J82Kls...DB_HOST=10.0.4.12"),
        ("https://files.northwindtraders.com/exports/", "Directory Index", "Index of /exports/ (payroll_2026.csv, partners_export.json)"),
        ("https://portal.contoso.com/.git/HEAD", "Git Repository", "ref: refs/heads/main"),
        ("https://remote.contoso.com/rdweb/", "Remote Desktop Web", "RD Web Access login page accessible without IP restrictions"),
        ("https://shop.northwindtraders.com/phpinfo.php", "Diagnostics", "PHP Version 8.2.14, Zend Engine v4.2.14, Apache 2.4.58"),
        ("https://dev-portal.fabrikam.io/actuator/env", "Spring Actuator", '{"activeProfiles":["staging"],"propertySources":[{"name":"systemEnvironment"}]}'),
    ]
    exposed_tsv = "".join(f"{u}\t{c}\t{s}\n" for u, c, s in exposed_paths)
    (web_dir / "exposed_paths.tsv").write_text(exposed_tsv, encoding="utf-8")

    # 16. Web CORS & Cookies
    cors_cookies = [
        ("https://api-staging.northwindtraders.com/v1/auth", "CORS Wildcard with Credentials", "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"),
        ("https://shop.northwindtraders.com/cart", "Insecure Cookie Flag", "Session cookie 'nw_sess_id' missing SameSite attribute"),
        ("https://dev-portal.fabrikam.io/login", "Missing HttpOnly Flag", "Authentication token cookie 'fab_jwt' lacks HttpOnly flag"),
        ("https://files.northwindtraders.com/session", "Missing Secure Flag", "Session cookie 'file_token' sent over HTTP without Secure attribute"),
    ]
    cors_tsv = "".join(f"{u}\t{t}\t{d}\n" for u, t, d in cors_cookies)
    (web_dir / "cors_cookies.tsv").write_text(cors_tsv, encoding="utf-8")

    # 17. Directory Listings
    (web_dir / "dir_listings.txt").write_text("https://files.northwindtraders.com/exports/ (Index of /exports)\nhttps://dev-portal.fabrikam.io/static/dumps/ (Index of /static/dumps)\n", encoding="utf-8")

    # 18. Nuclei Results
    nuclei_records = [
        {"template-id": "cve-2021-41773", "info": {"name": "Apache 2.4.49 Path Traversal & RCE", "severity": "high"}, "host": "https://api-staging.northwindtraders.com"},
        {"template-id": "env-file-disclosure", "info": {"name": "Exposed environment configuration (.env)", "severity": "high"}, "host": "https://dev-portal.fabrikam.io"},
        {"template-id": "swagger-api-docs", "info": {"name": "Exposed OpenAPI / Swagger specification", "severity": "medium"}, "host": "https://api-staging.northwindtraders.com"},
        {"template-id": "opnsense-admin-panel", "info": {"name": "Firewall / router admin GUI on the internet", "severity": "high"}, "host": "https://198.51.100.90:443"},
    ]
    (web_dir / "nuclei.jsonl").write_text("\n".join(json.dumps(r) for r in nuclei_records) + "\n", encoding="utf-8")

    # 19. Azure Annex
    azure_ips = [
        ("198.51.100.10", "pip-contoso-erp-prod-01", "rg-contoso-erp-prod", "lb-contoso-erp-frontend"),
        ("198.51.100.12", "pip-contoso-mail-relay", "rg-contoso-network", "vm-mail-exchange-01"),
        ("198.51.100.15", "pip-contoso-vpn-gw", "rg-contoso-network", "gw-contoso-s2s-vpn"),
        ("198.51.100.52", "pip-vm-erp-legacy", "rg-contoso-erp-prod", "nic-contoso-erp-legacy-01"),
        ("198.51.100.75", "pip-contoso-aks-ingress", "rg-contoso-cloudapps", "lb-aks-approuting-ingress"),
        ("198.51.100.102", "pip-contoso-apim-prod", "rg-contoso-integration", "apim-contoso-global"),
    ]
    azure_ips_tsv = "".join(f"{ip}\t{n}\t{rg}\t{att}\n" for ip, n, rg, att in azure_ips)
    (azure_dir / "public_ips.tsv").write_text(azure_ips_tsv, encoding="utf-8")

    azure_nsg = [
        ("nsg-contoso-erp-prod", "rg-contoso-erp-prod", "Allow-RDP-Internet", "3389", "3"),
        ("nsg-contoso-erp-prod", "rg-contoso-erp-prod", "Allow-HTTPS-Public", "443", "12"),
        ("nsg-contoso-network", "rg-contoso-network", "Allow-IPsec-VPN", "500,4500", "2"),
        ("nsg-contoso-cloudapps", "rg-contoso-cloudapps", "Allow-Web-Ingress", "80,443", "8"),
        ("nsg-contoso-dev", "rg-contoso-dev-test", "Allow-Dev-SSH-All", "22", "4"),
    ]
    azure_nsg_tsv = "".join(f"{nsg}\t{rg}\t{rule}\t{p}\t{nics}\n" for nsg, rg, rule, p, nics in azure_nsg)
    (azure_dir / "nsg_internet_rules.tsv").write_text(azure_nsg_tsv, encoding="utf-8")
    (azure_dir / "coverage.txt").write_text("public_ips=6 responded=6 open_ports=12 no_exposure=0\n", encoding="utf-8")

    azure_posture = [
        ("high", "az-storage-public:stcontosoexports", "Storage", "stcontosoexports", "Azure Storage Account stcontosoexports allows public blob access", "rg-contoso-storage/stcontosoexports allowBlobPublicAccess=true"),
        ("medium", "az-storage-http:stnorthwindlogs", "Storage", "stnorthwindlogs", "Azure Storage Account stnorthwindlogs allows unencrypted HTTP traffic", "rg-northwind-data/stnorthwindlogs supportsHttpsTrafficOnly=false"),
        ("low", "az-storage-tls:stnorthwindlogs", "Storage", "stnorthwindlogs", "Azure Storage Account stnorthwindlogs uses legacy TLS (TLS1_0)", "rg-northwind-data/stnorthwindlogs minimumTlsVersion=TLS1_0"),
        ("medium", "az-kv-purge:kv-contoso-prod", "KeyVault", "kv-contoso-prod", "Key Vault kv-contoso-prod has purge protection disabled", "rg-contoso-security/kv-contoso-prod enablePurgeProtection=false"),
        ("medium", "az-sql-public:sql-contoso-erp", "Database", "sql-contoso-erp", "Azure SQL Server sql-contoso-erp has public network access enabled", "rg-contoso-erp-prod/sql-contoso-erp publicNetworkAccess=Enabled"),
        ("medium", "az-defender-free:VirtualMachines", "SecurityCenter", "VirtualMachines", "Microsoft Defender for Cloud disabled (Free tier) for VirtualMachines", "pricingTier=Free"),
        ("medium", "az-defender-free:StorageAccounts", "SecurityCenter", "StorageAccounts", "Microsoft Defender for Cloud disabled (Free tier) for StorageAccounts", "pricingTier=Free"),
        ("low", "az-storage-tls:stcontosobackups", "Storage", "stcontosobackups", "Azure Storage Account stcontosobackups uses legacy TLS (TLS1_1)", "rg-contoso-storage/stcontosobackups minimumTlsVersion=TLS1_1"),
        ("medium", "az-defender-free:SqlServers", "SecurityCenter", "SqlServers", "Microsoft Defender for Cloud disabled (Free tier) for SqlServers", "pricingTier=Free"),
        ("medium", "az-kv-purge:kv-northwind-dev", "KeyVault", "kv-northwind-dev", "Key Vault kv-northwind-dev has purge protection disabled", "rg-northwind-security/kv-northwind-dev enablePurgeProtection=false"),
    ]
    azure_posture_tsv = "".join(f"{s}\t{k}\t{svc}\t{res}\t{t}\t{d}\n" for s, k, svc, res, t, d in azure_posture)
    (azure_dir / "posture_findings.tsv").write_text(azure_posture_tsv, encoding="utf-8")

    # 20. GCP Annex
    gcp_ips = [
        ("203.0.113.88", "pip-shop-frontend-lb", "contoso-ecommerce-prod", "global (External HTTP(S) LB)"),
        ("203.0.113.92", "pip-analytics-bastion", "contoso-analytics-prod", "us-central1 (Compute Instance)"),
        ("203.0.113.115", "pip-gke-ingress-cl1", "contoso-microservices-prod", "us-central1 (Regional LB)"),
        ("203.0.113.140", "pip-dataflow-worker", "contoso-analytics-prod", "us-central1 (Compute Instance)"),
    ]
    gcp_ips_tsv = "".join(f"{ip}\t{n}\t{proj}\t{reg}\n" for ip, n, proj, reg in gcp_ips)
    (gcp_dir / "public_ips.tsv").write_text(gcp_ips_tsv, encoding="utf-8")

    gcp_fw = [
        ("allow-ssh-legacy", "contoso-analytics-prod", "vpc-analytics-prod", "INGRESS 1000", "ALLOW", "0.0.0.0/0", "tcp:22"),
        ("allow-web-traffic", "contoso-ecommerce-prod", "vpc-ecommerce-prod", "INGRESS 1000", "ALLOW", "0.0.0.0/0", "tcp:80,tcp:443"),
        ("allow-health-checks", "contoso-ecommerce-prod", "vpc-ecommerce-prod", "INGRESS 1000", "ALLOW", "130.211.0.0/22,35.191.0.0/16", "tcp:80,tcp:443"),
        ("allow-staging-debug", "contoso-analytics-prod", "vpc-analytics-prod", "INGRESS 1200", "ALLOW", "0.0.0.0/0", "tcp:8080,tcp:9090"),
    ]
    gcp_fw_tsv = "".join(f"{n}\t{pr}\t{net}\t{dp}\t{ac}\t{src}\t{al}\n" for n, pr, net, dp, ac, src, al in gcp_fw)
    (gcp_dir / "firewall_internet_rules.tsv").write_text(gcp_fw_tsv, encoding="utf-8")
    (gcp_dir / "coverage.txt").write_text("public_ips=4 responded=4 open_ports=6 no_exposure=0\n", encoding="utf-8")

    # 20b. SaaS Annex
    saas_posture = [
        ("critical", "m365-admin-no-mfa", "EntraID", "Global Administrator", "2 Global Administrators without MFA registered", "Accounts admin-backup@contoso.com, breakglass-svc@contoso.com have Global Admin role without MFA registered"),
        ("high", "m365-ca-no-mfa-all", "ConditionalAccess", "tenant", "Conditional Access without a policy requiring MFA for all users", "No active Conditional Access policy enforces MFA for all users across all cloud apps"),
        ("high", "m365-oauth-allprincipals-mail", "OAuthPermissionGrant", "ContosoMailSyncApp", "OAuth grant with Mail.ReadWrite to AllPrincipals", "Delegated permission Mail.ReadWrite consented for AllPrincipals scope on ContosoMailSyncApp"),
        ("medium", "m365-guest-users-active", "EntraID", "tenant", "14 active guest users with access to tenant resources", "14 external guest user accounts active; 4 have not signed in for over 180 days"),
        ("medium", "m365-stale-accounts", "EntraID", "8 user accounts", "Stale user accounts inactive for >90 days", "8 enabled user accounts with lastSignInDateTime older than 90 days"),
        ("medium", "m365-app-secret-expired", "AppRegistration", "contoso-crm-connector", "App registration secret expired", "Client secret for app contoso-crm-connector expired on 2026-10-15"),
        ("low", "m365-ca-report-only", "ConditionalAccess", "Policy: CA003-LegacyAuthBlock", "Conditional Access policies in report-only mode", "Policy CA003-LegacyAuthBlock configured in report-only mode (not enforced)"),
        ("info", "m365-mfa-compliance", "Authentication", "tenant", "MFA compliance at 91%", "242 of 266 total licensed users in contoso.com tenant have registered MFA authentication methods"),
        ("high", "gh-org-2fa-disabled", "GitHub", "contoso-org", "Organization does not require 2FA for 3 members", "3 members without 2FA registered in contoso-org; two_factor_requirement_enabled=false"),
        ("high", "gh-secret-scanning-alerts", "GitHub", "contoso-org/contoso-api", "Open secret scanning alerts in organization repositories", "2 unresolved secret scanning alerts in contoso-org/contoso-api"),
        ("medium", "gh-repo-no-branch-protection", "GitHub", "6 repositories", "6 repos without branch protection", "Repositories contoso-api, northwind-web, fabrikam-core, data-pipeline, devops-tools, staging-env lack default branch protection"),
        ("medium", "gh-webhook-ssl-insecure", "GitHub", "contoso-org/northwind-web", "Webhook without SSL verification", "Webhook URL https://ci.contoso.com/gh-hook in contoso-org/northwind-web has SSL verification disabled"),
    ]
    saas_posture_tsv = "".join(f"{s}\t{k}\t{svc}\t{res}\t{t}\t{d}\n" for s, k, svc, res, t, d in saas_posture)
    (saas_dir / "posture_findings.tsv").write_text(saas_posture_tsv, encoding="utf-8")

    # 21. Console Commands (CLI Explorer)
    commands_data = [
        {
            "phase": "1",
            "title": "subfinder",
            "cmd": "subfinder -d contoso.com -d northwindtraders.com -d fabrikam.io -all -silent",
            "output": (
                "www.contoso.com\n"
                "mail.contoso.com\n"
                "autodiscover.contoso.com\n"
                "vpn.contoso.com\n"
                "vpn-internal.contoso.com\n"
                "portal.contoso.com\n"
                "erp.contoso.com\n"
                "remote.contoso.com\n"
                "api.contoso.com\n"
                "edge-gw.contoso.com\n"
                "shop.northwindtraders.com\n"
                "api.northwindtraders.com\n"
                "api-staging.northwindtraders.com\n"
                "files.northwindtraders.com\n"
                "orders.northwindtraders.com\n"
                "partner.northwindtraders.com\n"
                "dev-portal.fabrikam.io\n"
                "api.fabrikam.io\n"
                "auth.fabrikam.io"
            ),
            "returncode": 0,
            "duration_ms": 3420,
            "timestamp": "2026-11-03T10:02:14.281Z",
        },
        {
            "phase": "2",
            "title": "dnsx",
            "cmd": "dnsx -l osint/subdomains.txt -resp -silent",
            "output": (
                "www.contoso.com [13.107.246.10]\n"
                "mail.contoso.com [198.51.100.12]\n"
                "vpn.contoso.com [198.51.100.15]\n"
                "vpn-internal.contoso.com [198.51.100.15]\n"
                "erp.contoso.com [198.51.100.10]\n"
                "remote.contoso.com [198.51.100.52]\n"
                "edge-gw.contoso.com [203.0.113.45]\n"
                "shop.northwindtraders.com [203.0.113.88]\n"
                "api-staging.northwindtraders.com [203.0.113.19]\n"
                "files.northwindtraders.com [198.51.100.90]\n"
                "dev-portal.fabrikam.io [192.0.2.77]"
            ),
            "returncode": 0,
            "duration_ms": 1280,
            "timestamp": "2026-11-03T10:05:40.112Z",
        },
        {
            "phase": "2",
            "title": "dig",
            "cmd": "dig +noall +answer TXT _dmarc.fabrikam.io",
            "output": '_dmarc.fabrikam.io.    300    IN    TXT    "v=DMARC1; p=none; rua=mailto:dmarc@fabrikam.io;"',
            "returncode": 0,
            "duration_ms": 45,
            "timestamp": "2026-11-03T10:06:12.804Z",
        },
        {
            "phase": "3",
            "title": "httpx",
            "cmd": "httpx -l osint/subdomains.txt -title -tech-detect -status-code -follow-redirects",
            "output": (
                "https://www.contoso.com [200] [Contoso Enterprise Global] [Microsoft-IIS/10.0]\n"
                "https://portal.contoso.com [200] [Contoso Identity & Cloud Portal] [nginx/1.24.0] -> https://auth.contoso.com/oauth2\n"
                "https://remote.contoso.com [200] [Contoso RDS Web Gateway] [Microsoft-HTTPAPI/2.0]\n"
                "https://shop.northwindtraders.com [200] [Northwind Global B2B Marketplace] [Cloudflare,PHP/8.2]\n"
                "https://api-staging.northwindtraders.com [200] [Swagger UI - Staging API] [Apache/2.4.49]\n"
                "https://files.northwindtraders.com [200] [Index of /] [Apache/2.4.52]\n"
                "https://dev-portal.fabrikam.io [200] [Fabrikam Developer Sandbox] [nginx/1.22.1,Node.js]\n"
                "https://198.51.100.90:443 [200] [Login | OPNsense] [lighttpd/1.4.69]\n"
                "https://203.0.113.88:443 [502] [502 Bad Gateway] [nginx/1.20.1]"
            ),
            "returncode": 0,
            "duration_ms": 4810,
            "timestamp": "2026-11-03T10:08:29.495Z",
        },
        {
            "phase": "4",
            "title": "nmap",
            "cmd": "nmap -sT -Pn -p 21,22,80,443,3389,8291 --max-rate 400 -sV --version-all 198.51.100.52",
            "output": (
                "Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-03 10:14 UTC\n"
                "Nmap scan report for remote.contoso.com (198.51.100.52)\n"
                "Host is up (0.024s latency).\n\n"
                "PORT     STATE SERVICE       VERSION\n"
                "80/tcp   open  http          Microsoft IIS httpd 10.0\n"
                "443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)\n"
                "3389/tcp open  ms-wbt-server Microsoft Terminal Services (RDP enabled)\n"
                "Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows\n\n"
                "Nmap done: 1 IP address (1 host up) scanned in 3.12 seconds"
            ),
            "returncode": 0,
            "duration_ms": 3120,
            "timestamp": "2026-11-03T10:14:02.391Z",
        },
        {
            "phase": "4b",
            "title": "nmap",
            "cmd": "nmap -sT -Pn -p 21,22,23,53,80,443,8291 --max-rate 40 -sV 203.0.113.45",
            "output": (
                "Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-03 10:18 UTC\n"
                "Nmap scan report for edge-gw.contoso.com (203.0.113.45)\n"
                "Host is up (0.041s latency).\n\n"
                "PORT     STATE SERVICE VERSION\n"
                "22/tcp   open  ssh     MikroTik RouterOS sshd (protocol 2.0)\n"
                "80/tcp   open  http    MikroTik RouterOS httpd\n"
                "443/tcp  open  ssl/ssl MikroTik RouterOS httpd\n"
                "8291/tcp open  winbox  MikroTik RouterOS 6.48.6 winbox\n"
                "Service Info: OS: RouterOS; Device: router; CPE: cpe:/o:mikrotik:routeros:6.48.6\n\n"
                "Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds"
            ),
            "returncode": 0,
            "duration_ms": 8450,
            "timestamp": "2026-11-03T10:18:15.918Z",
        },
        {
            "phase": "6",
            "title": "curl",
            "cmd": 'curl -s "https://web.archive.org/cdx/search/cdx?url=*.northwindtraders.com/*&output=json&fl=original&collapse=urlkey"',
            "output": (
                '[["original"],\n'
                '["https://api.northwindtraders.com/v1/customers?account_id=9821"],\n'
                '["https://shop.northwindtraders.com/catalog/search?sort=price_desc&filter=active"],\n'
                '["https://files.northwindtraders.com/download?file=reports/2026-Q3.pdf"],\n'
                '["https://api-staging.northwindtraders.com/health?debug=1&trace=true"],\n'
                '["https://files.northwindtraders.com/exports/payroll_2026.csv"],\n'
                '["https://shop.northwindtraders.com/backup/database_dump.sql.gz"]]'
            ),
            "returncode": 0,
            "duration_ms": 1650,
            "timestamp": "2026-11-03T10:22:45.021Z",
        },
        {
            "phase": "7",
            "title": "shodan",
            "cmd": "shodan host 198.51.100.52",
            "output": (
                "198.51.100.52\n"
                "Hostnames:               remote.contoso.com, vm-erp-legacy.contoso.com\n"
                "City:                    Amsterdam\n"
                "Country:                 Netherlands\n"
                "Organization:            Microsoft Azure\n"
                "Operating System:        Windows Server 2019 Datacenter\n"
                "Last Update:             2026-11-01T14:22:18.491201\n\n"
                "Ports:\n"
                "  80/tcp   http\n"
                "  443/tcp  https\n"
                "  3389/tcp ms-wbt-server\n"
                "    |-- Vulnerabilities:\n"
                "    |   CVE-2024-38077 (CVSS 9.8) - Windows Remote Desktop Licensing Service RCE [CISA KEV]\n"
                "    |   CVE-2019-0708  (CVSS 9.8) - BlueKeep Remote Desktop Services RCE"
            ),
            "returncode": 0,
            "duration_ms": 2110,
            "timestamp": "2026-11-03T10:25:01.782Z",
        },
        {
            "phase": "8",
            "title": "nuclei",
            "cmd": "nuclei -l web/httpx_all.txt -t cves/ -t exposures/ -severity critical,high,medium -silent",
            "output": (
                "[cve-2021-41773] [http] [high] https://api-staging.northwindtraders.com/icons/.%%32%65/.%%32%65/etc/passwd\n"
                "[env-file-disclosure] [http] [high] https://dev-portal.fabrikam.io/.env\n"
                "[swagger-api-docs] [http] [medium] https://api-staging.northwindtraders.com/v2/api-docs\n"
                "[opnsense-admin-panel] [http] [high] https://198.51.100.90:443/"
            ),
            "returncode": 0,
            "duration_ms": 14200,
            "timestamp": "2026-11-03T10:28:44.221Z",
        },
        {
            "phase": "9",
            "title": "hibp",
            "cmd": "curl -s -H 'hibp-api-key: [REDACTED]' 'https://haveibeenpwned.com/api/v3/breaches?domain=contoso.com'",
            "output": (
                "[\n"
                "  {\n"
                '    "Name": "ContosoMarketing2023",\n'
                '    "Title": "Contoso Marketing Portal Leak",\n'
                '    "Domain": "contoso.com",\n'
                '    "BreachDate": "2023-04-18",\n'
                '    "PwnCount": 18400,\n'
                '    "DataClasses": ["Email addresses", "Passwords", "Job titles"],\n'
                '    "IsVerified": true\n'
                "  }\n"
                "]"
            ),
            "returncode": 0,
            "duration_ms": 780,
            "timestamp": "2026-11-03T10:29:10.120Z",
        },
        {
            "phase": "A",
            "title": "az",
            "cmd": 'az graph query -q "Resources | where type =~ \'Microsoft.Network/publicIPAddresses\' | project properties.ipAddress, name, resourceGroup"',
            "output": (
                "[\n"
                '  {"name": "pip-contoso-erp-prod-01", "properties_ipAddress": "198.51.100.10", "resourceGroup": "rg-contoso-erp-prod"},\n'
                '  {"name": "pip-contoso-vpn-gw", "properties_ipAddress": "198.51.100.15", "resourceGroup": "rg-contoso-network"},\n'
                '  {"name": "pip-vm-erp-legacy", "properties_ipAddress": "198.51.100.52", "resourceGroup": "rg-contoso-erp-prod"},\n'
                '  {"name": "pip-contoso-aks-ingress", "properties_ipAddress": "198.51.100.75", "resourceGroup": "rg-contoso-cloudapps"},\n'
                '  {"name": "pip-contoso-apim-prod", "properties_ipAddress": "198.51.100.102", "resourceGroup": "rg-contoso-integration"}\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 1890,
            "timestamp": "2026-11-03T10:32:10.518Z",
        },
        {
            "phase": "A",
            "title": "az",
            "cmd": 'az graph query --first 1000 -o json -q "Resources | where type =~ \'microsoft.storage/storageaccounts\' | project name, resourceGroup, allowBlobPublicAccess=properties.allowBlobPublicAccess, supportsHttpsTrafficOnly=properties.supportsHttpsTrafficOnly, minimumTlsVersion=properties.minimumTlsVersion"',
            "output": (
                "[\n"
                '  {"name": "stcontosoexports", "resourceGroup": "rg-contoso-storage", "allowBlobPublicAccess": true, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_2"},\n'
                '  {"name": "stnorthwindlogs", "resourceGroup": "rg-northwind-data", "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": false, "minimumTlsVersion": "TLS1_0"},\n'
                '  {"name": "stcontosobackups", "resourceGroup": "rg-contoso-storage", "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_1"},\n'
                '  {"name": "stcontosowebstatic", "resourceGroup": "rg-contoso-cloudapps", "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_2"}\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 1420,
            "timestamp": "2026-11-03T10:32:15.110Z",
        },
        {
            "phase": "A",
            "title": "az",
            "cmd": 'az graph query --first 1000 -o json -q "Resources | where type =~ \'microsoft.keyvault/vaults\' | project name, resourceGroup, enablePurgeProtection=properties.enablePurgeProtection"',
            "output": (
                "[\n"
                '  {"name": "kv-contoso-prod", "resourceGroup": "rg-contoso-security", "enablePurgeProtection": false},\n'
                '  {"name": "kv-northwind-dev", "resourceGroup": "rg-northwind-security", "enablePurgeProtection": false},\n'
                '  {"name": "kv-contoso-infra", "resourceGroup": "rg-contoso-network", "enablePurgeProtection": true}\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 1180,
            "timestamp": "2026-11-03T10:32:20.304Z",
        },
        {
            "phase": "A",
            "title": "az",
            "cmd": 'az graph query --first 1000 -o json -q "Resources | where type =~ \'microsoft.sql/servers\' | project name, resourceGroup, publicNetworkAccess=properties.publicNetworkAccess"',
            "output": (
                "[\n"
                '  {"name": "sql-contoso-erp", "resourceGroup": "rg-contoso-erp-prod", "publicNetworkAccess": "Enabled"},\n'
                '  {"name": "sql-northwind-dw", "resourceGroup": "rg-northwind-analytics", "publicNetworkAccess": "Disabled"}\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 1310,
            "timestamp": "2026-11-03T10:32:25.890Z",
        },
        {
            "phase": "A",
            "title": "az",
            "cmd": "az security pricing list -o json",
            "output": (
                "[\n"
                '  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/VirtualMachines", "name": "VirtualMachines", "pricingTier": "Free"},\n'
                '  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/StorageAccounts", "name": "StorageAccounts", "pricingTier": "Free"},\n'
                '  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/SqlServers", "name": "SqlServers", "pricingTier": "Free"},\n'
                '  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/AppServices", "name": "AppServices", "pricingTier": "Standard"},\n'
                '  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/KeyVaults", "name": "KeyVaults", "pricingTier": "Standard"}\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 1650,
            "timestamp": "2026-11-03T10:32:32.412Z",
        },
        {
            "phase": "G",
            "title": "gcloud",
            "cmd": 'gcloud compute firewall-rules list --filter="direction=INGRESS AND disabled=false" --format="table(name,network,sourceRanges.list():label=SRC,allowed[].map().firewall_rule().list():label=ALLOW)"',
            "output": (
                "NAME                 NETWORK               SRC                           ALLOW\n"
                "allow-ssh-legacy     vpc-analytics-prod    0.0.0.0/0                     tcp:22\n"
                "allow-web-traffic    vpc-ecommerce-prod    0.0.0.0/0                     tcp:80,tcp:443\n"
                "allow-health-checks  vpc-ecommerce-prod    130.211.0.0/22,35.191.0.0/16  tcp:80,tcp:443\n"
                "allow-staging-debug  vpc-analytics-prod    0.0.0.0/0                     tcp:8080,tcp:9090"
            ),
            "returncode": 0,
            "duration_ms": 2340,
            "timestamp": "2026-11-03T10:35:19.902Z",
        },
        {
            "phase": "S",
            "title": "msgraph",
            "cmd": "GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
            "output": (
                "{\n"
                '  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",\n'
                '  "value": [\n'
                '    {\n'
                '      "id": "c7a8291f-0e12-4c91-b328-984210a12001",\n'
                '      "displayName": "CA001-RequireMFA-Admins",\n'
                '      "state": "enabled",\n'
                '      "conditions": { "users": { "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"] } }\n'
                '    },\n'
                '    {\n'
                '      "id": "d9b9302a-1f23-5d02-c439-095321b23112",\n'
                '      "displayName": "CA002-BlockLegacyAuth",\n'
                '      "state": "enabled",\n'
                '      "conditions": { "clientAppTypes": ["exchangeActiveSync", "other"] }\n'
                '    },\n'
                '    {\n'
                '      "id": "e0ca413b-2a34-6e13-d540-106432c34223",\n'
                '      "displayName": "CA003-LegacyAuthBlock",\n'
                '      "state": "enabledForReportingButNotEnforced",\n'
                '      "conditions": { "users": { "includeUsers": ["All"] } }\n'
                '    }\n'
                '  ]\n'
                "}"
            ),
            "returncode": 0,
            "duration_ms": 780,
            "timestamp": "2026-11-03T10:36:10.120Z",
        },
        {
            "phase": "S",
            "title": "gh",
            "cmd": "gh api /orgs/contoso/members?filter=2fa_disabled",
            "output": (
                "[\n"
                '  {"login": "contractor-dev1", "id": 1048291, "site_admin": false},\n'
                '  {"login": "external-qa-lead", "id": 2049182, "site_admin": false},\n'
                '  {"login": "svc-build-contoso", "id": 3058291, "site_admin": false}\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 520,
            "timestamp": "2026-11-03T10:36:18.450Z",
        },
        {
            "phase": "S",
            "title": "gh",
            "cmd": "gh api /orgs/contoso/secret-scanning/alerts?state=open",
            "output": (
                "[\n"
                '  {\n'
                '    "number": 14,\n'
                '    "secret_type": "azure_storage_account_key",\n'
                '    "secret_type_display_name": "Azure Storage Account Key",\n'
                '    "state": "open",\n'
                '    "html_url": "https://github.com/contoso-org/contoso-api/security/secret-scanning/14"\n'
                '  },\n'
                '  {\n'
                '    "number": 18,\n'
                '    "secret_type": "github_personal_access_token",\n'
                '    "secret_type_display_name": "GitHub Personal Access Token",\n'
                '    "state": "open",\n'
                '    "html_url": "https://github.com/contoso-org/contoso-api/security/secret-scanning/18"\n'
                '  }\n'
                "]"
            ),
            "returncode": 0,
            "duration_ms": 610,
            "timestamp": "2026-11-03T10:36:24.890Z",
        },
    ]

    # Write console logs and commands.jsonl
    jsonl_lines = [json.dumps(cmd) + "\n" for cmd in commands_data]
    (console_dir / "commands.jsonl").write_text("".join(jsonl_lines), encoding="utf-8")

    for cmd in commands_data:
        log_file = console_dir / f"{cmd['phase']}.log"
        block = f"$ {cmd['cmd']}\n{cmd['output'].rstrip()}\n\n"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(block)


def generate_sample_reports(output_dir: Path | None = None) -> tuple[Path, Path]:
    """Build synthetic assessment run folder in a temp directory, generate reports, and copy to target."""
    target_dir = output_dir or (Path(__file__).resolve().parent.parent / "samples")
    target_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="contoso_sample_run_") as tmp_str:
        tmp_run = Path(tmp_str)
        build_sample_run(tmp_run)
        md_src, html_src = generate_reports(tmp_run)

        md_dst = target_dir / "contoso_report.md"
        html_dst = target_dir / "contoso_report.html"

        shutil.copy2(md_src, md_dst)
        shutil.copy2(html_src, html_dst)

    return md_dst, html_dst


if __name__ == "__main__":
    md_file, html_file = generate_sample_reports()
    print(f"Sample Markdown Report: {md_file} ({md_file.stat().st_size} bytes)")
    print(f"Sample HTML Report:     {html_file} ({html_file.stat().st_size} bytes)")
