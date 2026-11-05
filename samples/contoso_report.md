# External Attack Surface Assessment Report: Contoso & Northwind Traders Semi-Annual EASM

## Executive Metadata

| Parameter | Detail |
|---|---|
| **Engagement** | Contoso & Northwind Traders Semi-Annual EASM |
| **Date** | 2026-11-03 |
| **Scope** | `contoso_northwind` |
| **Authorised By** | Sarah Jenkins, VP of Information Security (Contoso Ltd.) (SEC-2026-8841) |
| **Egress IP** | `198.51.100.24` |
| **Phases Run** | `1 2 3 4 4b 5 6 7 8 9 A G S T` (Skip Active: 0, Docker: 0) |

## 1. Executive Summary & KPIs

This report presents the findings and asset inventory resulting from automated external attack surface reconnaissance. All passive discovery and active scanning procedures adhered strictly to the engagement scope and authorization terms.

### Finding Candidates Counts

| Severity | Count | Primary Impact |
|---|---|---|
| `CRITICAL` | **4** | Remote code execution, credential exposure, or open management interfaces |
| `HIGH` | **12** | Directory listings, unauthenticated APIs, DNS zone transfers, end-of-life daemons |
| `MEDIUM` | **19** | Email security omissions (SPF/DMARC), public SSH, weak TLS/SSH ciphers, cloud NSG rules |
| `LOW` | **6** | Missing defensive HTTP security headers, public WHOIS registrant disclosures |
| `INFO` | **2** | Service banners, technology version footprints, informational reconnaissance data |
| **TOTAL** | **43** | **Total candidate findings identified** |

### Perimeter Attack Surface KPIs

| Perimeter Metric | Count | Operational Notes |
|---|---|---|
| **Subdomains Discovered** | **49** | 49 total (+4 new, -2 decommissioned) |
| **Resolving Hosts** | **49** | Public DNS A/AAAA records verified |
| **Live Web Hosts** | **12** | Responsive HTTP/HTTPS endpoints detected via httpx probe |
| **Target IPs Scanned** | **14** | External infrastructure endpoints scanned |
| **CVEs Identified** | **6** | 6 unique CVEs (**2 CISA Known Exploited [KEV]**) |
| **Cloud Public IPs** | **10** | 6 Azure + 4 GCP + 0 AWS |

## 2. Finding Candidates (Prioritised)

*All findings are automated candidates to validate through manual review, not definitive penetration test conclusions.*

| Severity | Asset | Finding Title | Target | Evidence | Rule Key |
|---|---|---|---|---|---|
| `CRITICAL` | `CLOUD-002` | Management / legacy service ms-wbt-server exposed | 198.51.100.52 | `198.51.100.52:3389 Microsoft Terminal Services` | `mgmt:198.51.100.52:3389` |
| `CRITICAL` | `CLOUD-002` | Remote Desktop Services RCE CVE-2024-38077 (CISA KEV) | 198.51.100.52 | `198.51.100.52:3389 Microsoft Remote Desktop Services (CVSS 9.8)` | `cve:198.51.100.52:CVE-2024-38077` |
| `CRITICAL` | `ROUTER-001` | End-of-life RouterOS 6.48.6 on branch office edge gateway | 203.0.113.45 | `203.0.113.45:8291 MikroTik RouterOS 6.48.6 (RouterOS winbox)` | `routeros:203.0.113.45` |
| `CRITICAL` | - | 2 Global Administrators without MFA registered | - | `Accounts admin-backup@contoso.com, breakglass-svc@contoso.com have Global Admin role without MFA registered` | `m365-admin-no-mfa` |
| `HIGH` | `FW-001` | Firewall / router admin GUI on the internet | 198.51.100.90 | `Login \| OPNsense at https://198.51.100.90/ (port 443)` | `fw-admin:198.51.100.90` |
| `HIGH` | `WEB-001` | Apache 2.4.49 Path Traversal & RCE CVE-2021-41773 (CISA KEV) | 203.0.113.19 | `203.0.113.19:80 Apache/2.4.49 (Unix) mod_ssl/2.4.49` | `cve:203.0.113.19:CVE-2021-41773` |
| `HIGH` | `WEB-002` | Exposed OpenAPI / Swagger specification | api-staging.northwindtraders.com | `https://api-staging.northwindtraders.com/v2/api-docs (Swagger 2.0 API spec)` | `path:api-staging.northwindtraders.com/v2/api-docs` |
| `HIGH` | `WEB-004` | Exposed environment configuration (.env) | dev-portal.fabrikam.io | `https://dev-portal.fabrikam.io/.env contains APP_KEY and DB_PASSWORD` | `path:dev-portal.fabrikam.io/.env` |
| `HIGH` | `WEB-006` | Unauthenticated directory listing | files.northwindtraders.com | `https://files.northwindtraders.com/exports/ (Index of /exports)` | `dirlist:https://files.northwindtraders.com/exports/` |
| `HIGH` | - | Azure Storage Account stcontosoexports allows public blob access | - | `rg-contoso-storage/stcontosoexports allowBlobPublicAccess=true` | `az-storage-public:stcontosoexports` |
| `HIGH` | - | Organization does not require 2FA for 3 members | - | `3 members without 2FA registered in contoso-org; two_factor_requirement_enabled=false` | `gh-org-2fa-disabled` |
| `HIGH` | - | Open secret scanning alerts in organization repositories | - | `2 unresolved secret scanning alerts in contoso-org/contoso-api` | `gh-secret-scanning-alerts` |
| `HIGH` | - | Domain breach history: Contoso Marketing Portal Leak (2023-04-18) | - | `18400 accounts, exposed: Email addresses;Passwords;Job titles` | `hibp:contoso.com:ContosoMarketing2023` |
| `HIGH` | - | Conditional Access without a policy requiring MFA for all users | - | `No active Conditional Access policy enforces MFA for all users across all cloud apps` | `m365-ca-no-mfa-all` |
| `HIGH` | - | OAuth grant with Mail.ReadWrite to AllPrincipals | - | `Delegated permission Mail.ReadWrite consented for AllPrincipals scope on ContosoMailSyncApp` | `m365-oauth-allprincipals-mail` |
| `HIGH` | - | Sensitive files in Wayback history | - | `18 URLs with config/sql/backup extensions` | `wayback-critical` |
| `MEDIUM` | `ASSET-001` | fabrikam.io apex resolves to infrastructure not in our inventory | 192.0.2.77 | `192.0.2.77 (DigitalOcean, LLC)` | `apex:fabrikam.io` |
| `MEDIUM` | `ASSET-002` | GCP firewall allows tcp:22 from Internet | 0.0.0.0 | `contoso-analytics-prod/allow-ssh-legacy (source: 0.0.0.0/0)` | `gcp-fw:allow-ssh-legacy` |
| `MEDIUM` | `DOMAIN-001` | Webhook without SSL verification | ci.contoso.com | `Webhook URL https://ci.contoso.com/gh-hook in contoso-org/northwind-web has SSL verification disabled` | `gh-webhook-ssl-insecure` |
| `MEDIUM` | `K8S-003` | Expired TLS certificate | 203.0.113.88 | `203.0.113.88 expired 2026-08-14` | `cert-expired:203.0.113.88` |
| `MEDIUM` | `VPN-001` | Internal-named host publicly resolvable | 198.51.100.15 | `vpn-internal.contoso.com -> 198.51.100.15` | `internal-name:vpn-internal.contoso.com` |
| `MEDIUM` | - | Microsoft Defender for Cloud disabled (Free tier) for SqlServers | - | `pricingTier=Free` | `az-defender-free:SqlServers` |
| `MEDIUM` | - | Microsoft Defender for Cloud disabled (Free tier) for StorageAccounts | - | `pricingTier=Free` | `az-defender-free:StorageAccounts` |
| `MEDIUM` | - | Microsoft Defender for Cloud disabled (Free tier) for VirtualMachines | - | `pricingTier=Free` | `az-defender-free:VirtualMachines` |
| `MEDIUM` | - | Key Vault kv-contoso-prod has purge protection disabled | - | `rg-contoso-security/kv-contoso-prod enablePurgeProtection=false` | `az-kv-purge:kv-contoso-prod` |
| `MEDIUM` | - | Key Vault kv-northwind-dev has purge protection disabled | - | `rg-northwind-security/kv-northwind-dev enablePurgeProtection=false` | `az-kv-purge:kv-northwind-dev` |
| `MEDIUM` | - | Azure SQL Server sql-contoso-erp has public network access enabled | - | `rg-contoso-erp-prod/sql-contoso-erp publicNetworkAccess=Enabled` | `az-sql-public:sql-contoso-erp` |
| `MEDIUM` | - | Azure Storage Account stnorthwindlogs allows unencrypted HTTP traffic | - | `rg-northwind-data/stnorthwindlogs supportsHttpsTrafficOnly=false` | `az-storage-http:stnorthwindlogs` |
| `MEDIUM` | - | fabrikam.io has no DMARC p=reject | - | `v=DMARC1; p=none; rua=mailto:dmarc@fabrikam.io` | `dmarc:fabrikam.io` |
| `MEDIUM` | - | 6 repos without branch protection | - | `Repositories contoso-api, northwind-web, fabrikam-core, data-pipeline, devops-tools, staging-env lack default branch protection` | `gh-repo-no-branch-protection` |
| `MEDIUM` | - | Domain breach history: Northwind Customer Support Leak (2022-11-05) | - | `9350 accounts, exposed: Email addresses;Names;Phone numbers` | `hibp:northwindtraders.com:NorthwindSupport2022` |
| `MEDIUM` | - | App registration secret expired | - | `Client secret for app contoso-crm-connector expired on 2026-10-15` | `m365-app-secret-expired` |
| `MEDIUM` | - | 14 active guest users with access to tenant resources | - | `14 external guest user accounts active; 4 have not signed in for over 180 days` | `m365-guest-users-active` |
| `MEDIUM` | - | Stale user accounts inactive for >90 days | - | `8 enabled user accounts with lastSignInDateTime older than 90 days` | `m365-stale-accounts` |
| `MEDIUM` | - | NSG allows 3389 from Internet | - | `rg-contoso-erp-prod/nsg-contoso-erp-prod rule Allow-RDP-Internet (nics: nic-contoso-erp-01)` | `nsg:nsg-contoso-erp-prod:Allow-RDP-Internet` |
| `LOW` | `WEB-010` | Public website missing security headers | www.contoso.com | `https://www.contoso.com: permissions-policy x-content-type-options` | `headers:www` |
| `LOW` | - | Azure Storage Account stcontosobackups uses legacy TLS (TLS1_1) | - | `rg-contoso-storage/stcontosobackups minimumTlsVersion=TLS1_1` | `az-storage-tls:stcontosobackups` |
| `LOW` | - | Azure Storage Account stnorthwindlogs uses legacy TLS (TLS1_0) | - | `rg-northwind-data/stnorthwindlogs minimumTlsVersion=TLS1_0` | `az-storage-tls:stnorthwindlogs` |
| `LOW` | - | No CAA on fabrikam.io | - | `dig CAA fabrikam.io` | `caa:fabrikam.io` |
| `LOW` | - | DNSSEC unsigned on fabrikam.io | - | `dig DNSKEY fabrikam.io` | `dnssec:fabrikam.io` |
| `LOW` | - | Conditional Access policies in report-only mode | - | `Policy CA003-LegacyAuthBlock configured in report-only mode (not enforced)` | `m365-ca-report-only` |
| `INFO` | - | MFA compliance at 91% | - | `242 of 266 total licensed users in contoso.com tenant have registered MFA authentication methods` | `m365-mfa-compliance` |
| `INFO` | - | Multi-cloud attack surface perimeter mapped | - | `85 subdomains identified across 3 domains in AWS, Azure, GCP, and DigitalOcean` | `perimeter:mapping` |

## 2b. Asset Inventory

*Stable identifiers (persisted per scope) group tests, findings and CVEs by asset for risk review and forensics.*

| ID | Type | Asset | Product / Version | Open Ports | Findings | CVEs |
|---|---|---|---|---|---|---|
| `CLOUD-002` | Cloud host | pip-vm-erp-legacy (`198.51.100.52`) | ms-wbt-server Microsoft Terminal Services | 3389/ms-wbt-server | 2 — Management / legacy service ms-wbt-server exposed; Remote Desktop Services RCE CVE-2024-38077 (CISA KEV) | CVE-2024-38077 |
| `ROUTER-001` | Router | branch-gw45.northwind.net (`203.0.113.45`) | winbox MikroTik RouterOS 6.48.6 | 8291/winbox | 1 — End-of-life RouterOS 6.48.6 on branch office edge gateway | CVE-2023-32154 |
| `FW-001` | Firewall | edge-fw01.contoso.com (`198.51.100.90`) | http OPNsense 23.7.1, lighttpd/1.4.69 | 443/http | 1 — Firewall / router admin GUI on the internet | CVE-2023-43261 |
| `WEB-001` | Web service | ec2-legacy-app.aws.com (`203.0.113.19`) | http Apache httpd 2.4.49 | 80/http | 1 — Apache 2.4.49 Path Traversal & RCE CVE-2021-41773 (CISA KEV) | CVE-2021-41773 |
| `WEB-002` | Web service | api-staging.northwindtraders.com (`api-staging.northwindtraders.com`) | Apache/2.4.49 | - | 1 — Exposed OpenAPI / Swagger specification | - |
| `WEB-004` | Web service | dev-portal.fabrikam.io (`dev-portal.fabrikam.io`) | nginx/1.22.1 | - | 1 — Exposed environment configuration (.env) | - |
| `WEB-006` | Web service | files.northwindtraders.com (`files.northwindtraders.com`) | Apache/2.4.52 | - | 1 — Unauthenticated directory listing | - |
| `ASSET-001` | Asset | droplet-untracked-77.do.net (`192.0.2.77`) | - | - | 1 — fabrikam.io apex resolves to infrastructure not in our inventory | - |
| `ASSET-002` | Asset | 0.0.0.0 (`0.0.0.0`) | - | - | 1 — GCP firewall allows tcp:22 from Internet | - |
| `DOMAIN-001` | Domain / name | ci.contoso.com (`ci.contoso.com`) | - | - | 1 — Webhook without SSL verification | - |
| `K8S-003` | Kubernetes ingress | pip-shop-frontend-lb (`203.0.113.88`) | http nginx 1.20.1, nginx/1.20.1 | 443/http | 1 — Expired TLS certificate | CVE-2021-23017 |
| `VPN-001` | VPN gateway | pip-contoso-vpn-gw (`198.51.100.15`) | - | - | 1 — Internal-named host publicly resolvable | - |
| `WEB-010` | Web service | www.contoso.com (`www.contoso.com`) | Microsoft-IIS/10.0 | - | 1 — Public website missing security headers | - |
| `CLOUD-001` | Cloud host | pip-contoso-apim-prod (`198.51.100.102`) | - | - | - | - |
| `CLOUD-003` | Cloud host | pip-dataflow-worker (`203.0.113.140`) | - | - | - | - |
| `CLOUD-004` | Cloud host | pip-analytics-bastion (`203.0.113.92`) | - | - | - | - |
| `K8S-001` | Kubernetes ingress | pip-contoso-aks-ingress (`198.51.100.75`) | - | - | - | - |
| `K8S-002` | Kubernetes ingress | pip-gke-ingress-cl1 (`203.0.113.115`) | - | - | - | - |
| `LB-001` | Load balancer | pip-contoso-erp-prod-01 (`198.51.100.10`) | http OpenSSL 1.1.1k | 443/http | - | CVE-2022-0778 |
| `MAIL-001` | Mail server | pip-contoso-mail-relay (`198.51.100.12`) | - | - | - | - |
| `WEB-003` | Web service | api.northwindtraders.com (`api.northwindtraders.com`) | envoy/1.28.0 | - | - | - |
| `WEB-005` | Web service | erp.contoso.com (`erp.contoso.com`) | Microsoft-IIS/10.0 | - | - | - |
| `WEB-007` | Web service | portal.contoso.com (`portal.contoso.com`) | nginx/1.24.0 | - | - | - |
| `WEB-008` | Web service | remote.contoso.com (`remote.contoso.com`) | Microsoft-HTTPAPI/2.0 | - | - | - |
| `WEB-009` | Web service | shop.northwindtraders.com (`shop.northwindtraders.com`) | Cloudflare | - | - | - |
| `WEB-011` | Web service | www.fabrikam.io (`www.fabrikam.io`) | nginx/1.26.1 | - | - | - |

## 3. Service Inventory & CVE / CISA KEV Correlation

| IP:Port | Service & Version | CVEs | Summary |
|---|---|---|---|
| `198.51.100.52:3389` | `ms-wbt-server Microsoft Terminal Services` | `CVE-2024-38077` (9.8) **[KEV]** | Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability |
| `203.0.113.19:80` | `http Apache httpd 2.4.49` | `CVE-2021-41773` (7.5) **[KEV]** | Path traversal and file disclosure flaw in Apache HTTP Server 2.4.49 |
| `198.51.100.90:443` | `http OPNsense 23.7.1` | `CVE-2023-43261` (8.8) | Improper authentication bypass in administrative management console |
| `203.0.113.45:8291` | `winbox MikroTik RouterOS 6.48.6` | `CVE-2023-32154` (7.8) | MikroTik RouterOS IPv6 route advertisement buffer overflow vulnerability |
| `203.0.113.88:443` | `http nginx 1.20.1` | `CVE-2021-23017` (7.7) | 1-byte memory overwrite in resolver component leading to DoS or worker crash |
| `198.51.100.10:443` | `http OpenSSL 1.1.1k` | `CVE-2022-0778` (7.5) | BN_mod_sqrt() infinite loop vulnerability in OpenSSL parsing invalid certificates |

## 4. Web Surface & Potential Entry Points

### 4.1 Exposed Well-Known Paths / API Schemas

| Target URL | Category | Evidence Snippet |
|---|---|---|
| `https://api-staging.northwindtraders.com/v2/api-docs` | **OpenAPI Spec** | `{"swagger":"2.0","info":{"title":"Northwind Staging Core API","version":"2.4.0"}}` |
| `https://dev-portal.fabrikam.io/.env` | **Config Leak** | `APP_ENV=staging\nAPP_KEY=base64:J82Kls...DB_HOST=10.0.4.12` |
| `https://files.northwindtraders.com/exports/` | **Directory Index** | `Index of /exports/ (payroll_2026.csv, partners_export.json)` |
| `https://portal.contoso.com/.git/HEAD` | **Git Repository** | `ref: refs/heads/main` |
| `https://remote.contoso.com/rdweb/` | **Remote Desktop Web** | `RD Web Access login page accessible without IP restrictions` |
| `https://shop.northwindtraders.com/phpinfo.php` | **Diagnostics** | `PHP Version 8.2.14, Zend Engine v4.2.14, Apache 2.4.58` |
| `https://dev-portal.fabrikam.io/actuator/env` | **Spring Actuator** | `{"activeProfiles":["staging"],"propertySources":[{"name":"systemEnvironment"}]}` |

### 4.2 CORS & Cookie Weaknesses

| Target URL | Issue Type | Detail |
|---|---|---|
| `https://api-staging.northwindtraders.com/v1/auth` | **CORS Wildcard with Credentials** | Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true |
| `https://shop.northwindtraders.com/cart` | **Insecure Cookie Flag** | Session cookie 'nw_sess_id' missing SameSite attribute |
| `https://dev-portal.fabrikam.io/login` | **Missing HttpOnly Flag** | Authentication token cookie 'fab_jwt' lacks HttpOnly flag |
| `https://files.northwindtraders.com/session` | **Missing Secure Flag** | Session cookie 'file_token' sent over HTTP without Secure attribute |

### 4.3 Potential Parameter Entry Points

| Category | Parameter or Pattern | Sample URL |
|---|---|---|
| **IDOR / Object Reference** | `id, account_id, user_id` | `https://api.northwindtraders.com/v1/customers?account_id=9821` |
| **SQL Injection / Filter** | `filter, sort, query, q` | `https://shop.northwindtraders.com/catalog/search?sort=price_desc&filter=active` |
| **SSRF / Webhook** | `url, callback, target, webhook` | `https://dev-portal.fabrikam.io/webhooks/test?url=https://internal.fabrikam.io/` |
| **Open Redirect** | `redirect, next, return_to` | `https://portal.contoso.com/login?return_to=https://portal.contoso.com/dashboard` |
| **Debug / Admin** | `debug, test, verbose, trace` | `https://api-staging.northwindtraders.com/health?debug=1&trace=true` |
| **File Inclusion / Path** | `file, path, template, view` | `https://files.northwindtraders.com/download?file=reports/2026-Q3.pdf` |

### 4.4 Directory Listings

- `https://files.northwindtraders.com/exports/ (Index of /exports)`
- `https://dev-portal.fabrikam.io/static/dumps/ (Index of /static/dumps)`

## 5. Cloud Perimeter (Grey-Box)

### 5.1 Microsoft Azure Public IPs & Internet NSG Rules

| Public IP | Name | Resource Group | Attached Resource |
|---|---|---|---|
| `198.51.100.10` | pip-contoso-erp-prod-01 | rg-contoso-erp-prod | lb-contoso-erp-frontend |
| `198.51.100.12` | pip-contoso-mail-relay | rg-contoso-network | vm-mail-exchange-01 |
| `198.51.100.15` | pip-contoso-vpn-gw | rg-contoso-network | gw-contoso-s2s-vpn |
| `198.51.100.52` | pip-vm-erp-legacy | rg-contoso-erp-prod | nic-contoso-erp-legacy-01 |
| `198.51.100.75` | pip-contoso-aks-ingress | rg-contoso-cloudapps | lb-aks-approuting-ingress |
| `198.51.100.102` | pip-contoso-apim-prod | rg-contoso-integration | apim-contoso-global |

#### Azure Internet NSG Rules

| NSG Name | Resource Group | Rule | Inbound Ports | Attached NICs |
|---|---|---|---|---|
| `nsg-contoso-erp-prod` | rg-contoso-erp-prod | Allow-RDP-Internet | `3389` | 3 |
| `nsg-contoso-erp-prod` | rg-contoso-erp-prod | Allow-HTTPS-Public | `443` | 12 |
| `nsg-contoso-network` | rg-contoso-network | Allow-IPsec-VPN | `500,4500` | 2 |
| `nsg-contoso-cloudapps` | rg-contoso-cloudapps | Allow-Web-Ingress | `80,443` | 8 |
| `nsg-contoso-dev` | rg-contoso-dev-test | Allow-Dev-SSH-All | `22` | 4 |

**Azure Coverage**: `public_ips=6 responded=6 open_ports=12 no_exposure=0`

### 5.2 Google Cloud (GCP) Public IPs & VPC Firewall Rules

| Public IP | Name | Project | Region / Type |
|---|---|---|---|
| `203.0.113.88` | pip-shop-frontend-lb | contoso-ecommerce-prod | global (External HTTP(S) LB) |
| `203.0.113.92` | pip-analytics-bastion | contoso-analytics-prod | us-central1 (Compute Instance) |
| `203.0.113.115` | pip-gke-ingress-cl1 | contoso-microservices-prod | us-central1 (Regional LB) |
| `203.0.113.140` | pip-dataflow-worker | contoso-analytics-prod | us-central1 (Compute Instance) |

#### GCP Firewall Internet Rules

| Rule Name | Project | Network | Direction / Priority | Action | Source Ranges | Allowed Ports |
|---|---|---|---|---|---|---|
| `allow-ssh-legacy` | contoso-analytics-prod | vpc-analytics-prod | INGRESS 1000 | ALLOW | `0.0.0.0/0` | `tcp:22` |
| `allow-web-traffic` | contoso-ecommerce-prod | vpc-ecommerce-prod | INGRESS 1000 | ALLOW | `0.0.0.0/0` | `tcp:80,tcp:443` |
| `allow-health-checks` | contoso-ecommerce-prod | vpc-ecommerce-prod | INGRESS 1000 | ALLOW | `130.211.0.0/22,35.191.0.0/16` | `tcp:80,tcp:443` |
| `allow-staging-debug` | contoso-analytics-prod | vpc-analytics-prod | INGRESS 1200 | ALLOW | `0.0.0.0/0` | `tcp:8080,tcp:9090` |

**GCP Coverage**: `public_ips=4 responded=4 open_ports=6 no_exposure=0`

### 5.3 Amazon Web Services (AWS) Public IPs, Endpoints & Security Groups

*No AWS public IP assets discovered or AWS Annex skipped.*

## 6. Cloud Security Posture

*Automated cloud security configuration checks (candidates to validate, not definitive penetration test conclusions).*

### 6.1 Azure Security Posture

| Severity | Service | Resource | Title | Detail |
|---|---|---|---|---|
| `HIGH` | Storage | stcontosoexports | Azure Storage Account stcontosoexports allows public blob access | rg-contoso-storage/stcontosoexports allowBlobPublicAccess=true |
| `MEDIUM` | Storage | stnorthwindlogs | Azure Storage Account stnorthwindlogs allows unencrypted HTTP traffic | rg-northwind-data/stnorthwindlogs supportsHttpsTrafficOnly=false |
| `LOW` | Storage | stnorthwindlogs | Azure Storage Account stnorthwindlogs uses legacy TLS (TLS1_0) | rg-northwind-data/stnorthwindlogs minimumTlsVersion=TLS1_0 |
| `MEDIUM` | KeyVault | kv-contoso-prod | Key Vault kv-contoso-prod has purge protection disabled | rg-contoso-security/kv-contoso-prod enablePurgeProtection=false |
| `MEDIUM` | Database | sql-contoso-erp | Azure SQL Server sql-contoso-erp has public network access enabled | rg-contoso-erp-prod/sql-contoso-erp publicNetworkAccess=Enabled |
| `MEDIUM` | SecurityCenter | VirtualMachines | Microsoft Defender for Cloud disabled (Free tier) for VirtualMachines | pricingTier=Free |
| `MEDIUM` | SecurityCenter | StorageAccounts | Microsoft Defender for Cloud disabled (Free tier) for StorageAccounts | pricingTier=Free |
| `LOW` | Storage | stcontosobackups | Azure Storage Account stcontosobackups uses legacy TLS (TLS1_1) | rg-contoso-storage/stcontosobackups minimumTlsVersion=TLS1_1 |
| `MEDIUM` | SecurityCenter | SqlServers | Microsoft Defender for Cloud disabled (Free tier) for SqlServers | pricingTier=Free |
| `MEDIUM` | KeyVault | kv-northwind-dev | Key Vault kv-northwind-dev has purge protection disabled | rg-northwind-security/kv-northwind-dev enablePurgeProtection=false |

### 6.2 GCP Security Posture

*No GCP security posture findings recorded.*

### 6.3 AWS Security Posture

*No AWS security posture findings recorded.*

## 7. SaaS Security Posture

*Automated SaaS security configuration checks (candidates to validate, not definitive penetration test conclusions).*

### 7.1 Microsoft 365 Posture

| Severity | Service | Resource | Title | Detail |
|---|---|---|---|---|
| `CRITICAL` | EntraID | Global Administrator | 2 Global Administrators without MFA registered | Accounts admin-backup@contoso.com, breakglass-svc@contoso.com have Global Admin role without MFA registered |
| `HIGH` | ConditionalAccess | tenant | Conditional Access without a policy requiring MFA for all users | No active Conditional Access policy enforces MFA for all users across all cloud apps |
| `HIGH` | OAuthPermissionGrant | ContosoMailSyncApp | OAuth grant with Mail.ReadWrite to AllPrincipals | Delegated permission Mail.ReadWrite consented for AllPrincipals scope on ContosoMailSyncApp |
| `MEDIUM` | EntraID | tenant | 14 active guest users with access to tenant resources | 14 external guest user accounts active; 4 have not signed in for over 180 days |
| `MEDIUM` | EntraID | 8 user accounts | Stale user accounts inactive for >90 days | 8 enabled user accounts with lastSignInDateTime older than 90 days |
| `MEDIUM` | AppRegistration | contoso-crm-connector | App registration secret expired | Client secret for app contoso-crm-connector expired on 2026-10-15 |
| `LOW` | ConditionalAccess | Policy: CA003-LegacyAuthBlock | Conditional Access policies in report-only mode | Policy CA003-LegacyAuthBlock configured in report-only mode (not enforced) |
| `INFO` | Authentication | tenant | MFA compliance at 91% | 242 of 266 total licensed users in contoso.com tenant have registered MFA authentication methods |

### 7.2 GitHub Posture

| Severity | Service | Resource | Title | Detail |
|---|---|---|---|---|
| `HIGH` | GitHub | contoso-org | Organization does not require 2FA for 3 members | 3 members without 2FA registered in contoso-org; two_factor_requirement_enabled=false |
| `HIGH` | GitHub | contoso-org/contoso-api | Open secret scanning alerts in organization repositories | 2 unresolved secret scanning alerts in contoso-org/contoso-api |
| `MEDIUM` | GitHub | 6 repositories | 6 repos without branch protection | Repositories contoso-api, northwind-web, fabrikam-core, data-pipeline, devops-tools, staging-env lack default branch protection |
| `MEDIUM` | GitHub | contoso-org/northwind-web | Webhook without SSL verification | Webhook URL https://ci.contoso.com/gh-hook in contoso-org/northwind-web has SSL verification disabled |

### 7.3 Google Workspace Posture

*No Google Workspace security posture findings recorded.*

## 8. Changes vs Previous Run (`Diff`)

# Changes 2026-05-12 -> 2026-11-03

## New (4)

- **CRITICAL** End-of-life RouterOS 6.48.6 on branch office edge gateway - 203.0.113.45:8291
- **HIGH** Exposed environment configuration (.env) - dev-portal.fabrikam.io/.env
- **HIGH** Unauthenticated directory listing - https://files.northwindtraders.com/exports/
- **MEDIUM** GCP firewall allows tcp:22 from Internet - contoso-analytics-prod/allow-ssh-legacy

## Resolved (3)

- **HIGH** Apache 2.4.49 Path Traversal & RCE CVE-2021-41773 - 203.0.113.19:80
- **MEDIUM** Public website missing security headers - https://www.contoso.com
- **LOW** No CAA on northwindtraders.com - dig CAA northwindtraders.com

## Persisting (9)

- **CRITICAL** Management / legacy service ms-wbt-server exposed - 198.51.100.52:3389
- **CRITICAL** Remote Desktop Services RCE CVE-2024-38077 (CISA KEV) - 198.51.100.52:3389
- **HIGH** Firewall / router admin GUI on the internet - 198.51.100.90 (Login | OPNsense)
- **HIGH** Sensitive files in Wayback history - 18 URLs
- **HIGH** Exposed OpenAPI / Swagger specification - api-staging.northwindtraders.com/v2/api-docs
- **MEDIUM** NSG allows 3389 from Internet - rg-contoso-erp-prod/nsg-contoso-erp-prod rule Allow-RDP-Internet
- **MEDIUM** fabrikam.io has no DMARC p=reject - dig TXT _dmarc.fabrikam.io
- **MEDIUM** fabrikam.io apex resolves to infrastructure not in our inventory - 192.0.2.77 (DigitalOcean)
- **LOW** DNSSEC unsigned on fabrikam.io - dig DNSKEY fabrikam.io

## 9. CLI Evidence & Tool Outputs

<details><summary>Phase 1: Subdomains — subfinder (<code>$ subfinder -d contoso.com -d northwindtraders.com -d fabrikam.io -all -silent</code>)</summary>

```console
$ subfinder -d contoso.com -d northwindtraders.com -d fabrikam.io -all -silent
www.contoso.com
mail.contoso.com
autodiscover.contoso.com
vpn.contoso.com
vpn-internal.contoso.com
portal.contoso.com
erp.contoso.com
remote.contoso.com
api.contoso.com
edge-gw.contoso.com
shop.northwindtraders.com
api.northwindtraders.com
api-staging.northwindtraders.com
files.northwindtraders.com
orders.northwindtraders.com
partner.northwindtraders.com
dev-portal.fabrikam.io
api.fabrikam.io
auth.fabrikam.io
```
</details>

<details><summary>Phase 2: DNS — dnsx (<code>$ dnsx -l osint/subdomains.txt -resp -silent</code>)</summary>

```console
$ dnsx -l osint/subdomains.txt -resp -silent
www.contoso.com [13.107.246.10]
mail.contoso.com [198.51.100.12]
vpn.contoso.com [198.51.100.15]
vpn-internal.contoso.com [198.51.100.15]
erp.contoso.com [198.51.100.10]
remote.contoso.com [198.51.100.52]
edge-gw.contoso.com [203.0.113.45]
shop.northwindtraders.com [203.0.113.88]
api-staging.northwindtraders.com [203.0.113.19]
files.northwindtraders.com [198.51.100.90]
dev-portal.fabrikam.io [192.0.2.77]
```
</details>

<details><summary>Phase 2: DNS — dig (<code>$ dig +noall +answer TXT _dmarc.fabrikam.io</code>)</summary>

```console
$ dig +noall +answer TXT _dmarc.fabrikam.io
_dmarc.fabrikam.io.    300    IN    TXT    "v=DMARC1; p=none; rua=mailto:dmarc@fabrikam.io;"
```
</details>

<details><summary>Phase 3: Web — httpx (<code>$ httpx -l osint/subdomains.txt -title -tech-detect -status-code -follow-redirects</code>)</summary>

```console
$ httpx -l osint/subdomains.txt -title -tech-detect -status-code -follow-redirects
https://www.contoso.com [200] [Contoso Enterprise Global] [Microsoft-IIS/10.0]
https://portal.contoso.com [200] [Contoso Identity & Cloud Portal] [nginx/1.24.0] -> https://auth.contoso.com/oauth2
https://remote.contoso.com [200] [Contoso RDS Web Gateway] [Microsoft-HTTPAPI/2.0]
https://shop.northwindtraders.com [200] [Northwind Global B2B Marketplace] [Cloudflare,PHP/8.2]
https://api-staging.northwindtraders.com [200] [Swagger UI - Staging API] [Apache/2.4.49]
https://files.northwindtraders.com [200] [Index of /] [Apache/2.4.52]
https://dev-portal.fabrikam.io [200] [Fabrikam Developer Sandbox] [nginx/1.22.1,Node.js]
https://198.51.100.90:443 [200] [Login | OPNsense] [lighttpd/1.4.69]
https://203.0.113.88:443 [502] [502 Bad Gateway] [nginx/1.20.1]
```
</details>

<details><summary>Phase 4: HVT Scan — nmap (<code>$ nmap -sT -Pn -p 21,22,80,443,3389,8291 --max-rate 400 -sV --version-all 198.51.100.52</code>)</summary>

```console
$ nmap -sT -Pn -p 21,22,80,443,3389,8291 --max-rate 400 -sV --version-all 198.51.100.52
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-03 10:14 UTC
Nmap scan report for remote.contoso.com (198.51.100.52)
Host is up (0.024s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services (RDP enabled)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 3.12 seconds
```
</details>

<details><summary>Phase 4b: Edge — nmap (<code>$ nmap -sT -Pn -p 21,22,23,53,80,443,8291 --max-rate 40 -sV 203.0.113.45</code>)</summary>

```console
$ nmap -sT -Pn -p 21,22,23,53,80,443,8291 --max-rate 40 -sV 203.0.113.45
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-03 10:18 UTC
Nmap scan report for edge-gw.contoso.com (203.0.113.45)
Host is up (0.041s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     MikroTik RouterOS sshd (protocol 2.0)
80/tcp   open  http    MikroTik RouterOS httpd
443/tcp  open  ssl/ssl MikroTik RouterOS httpd
8291/tcp open  winbox  MikroTik RouterOS 6.48.6 winbox
Service Info: OS: RouterOS; Device: router; CPE: cpe:/o:mikrotik:routeros:6.48.6

Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
```
</details>

<details><summary>Phase 6: Wayback — curl (<code>$ curl -s "https://web.archive.org/cdx/search/cdx?url=*.northwindtraders.com/*&output=json&fl=original&collapse=urlkey"</code>)</summary>

```console
$ curl -s "https://web.archive.org/cdx/search/cdx?url=*.northwindtraders.com/*&output=json&fl=original&collapse=urlkey"
[["original"],
["https://api.northwindtraders.com/v1/customers?account_id=9821"],
["https://shop.northwindtraders.com/catalog/search?sort=price_desc&filter=active"],
["https://files.northwindtraders.com/download?file=reports/2026-Q3.pdf"],
["https://api-staging.northwindtraders.com/health?debug=1&trace=true"],
["https://files.northwindtraders.com/exports/payroll_2026.csv"],
["https://shop.northwindtraders.com/backup/database_dump.sql.gz"]]
```
</details>

<details><summary>Phase 7: Shodan & CVEs — shodan (<code>$ shodan host 198.51.100.52</code>)</summary>

```console
$ shodan host 198.51.100.52
198.51.100.52
Hostnames:               remote.contoso.com, vm-erp-legacy.contoso.com
City:                    Amsterdam
Country:                 Netherlands
Organization:            Microsoft Azure
Operating System:        Windows Server 2019 Datacenter
Last Update:             2026-11-01T14:22:18.491201

Ports:
  80/tcp   http
  443/tcp  https
  3389/tcp ms-wbt-server
    |-- Vulnerabilities:
    |   CVE-2024-38077 (CVSS 9.8) - Windows Remote Desktop Licensing Service RCE [CISA KEV]
    |   CVE-2019-0708  (CVSS 9.8) - BlueKeep Remote Desktop Services RCE
```
</details>

<details><summary>Phase 8: Nuclei — nuclei (<code>$ nuclei -l web/httpx_all.txt -t cves/ -t exposures/ -severity critical,high,medium -silent</code>)</summary>

```console
$ nuclei -l web/httpx_all.txt -t cves/ -t exposures/ -severity critical,high,medium -silent
[cve-2021-41773] [http] [high] https://api-staging.northwindtraders.com/icons/.%%32%65/.%%32%65/etc/passwd
[env-file-disclosure] [http] [high] https://dev-portal.fabrikam.io/.env
[swagger-api-docs] [http] [medium] https://api-staging.northwindtraders.com/v2/api-docs
[opnsense-admin-panel] [http] [high] https://198.51.100.90:443/
```
</details>

<details><summary>Phase 9: Secrets — hibp (<code>$ curl -s -H 'hibp-api-key: [REDACTED]' 'https://haveibeenpwned.com/api/v3/breaches?domain=contoso.com'</code>)</summary>

```console
$ curl -s -H 'hibp-api-key: [REDACTED]' 'https://haveibeenpwned.com/api/v3/breaches?domain=contoso.com'
[
  {
    "Name": "ContosoMarketing2023",
    "Title": "Contoso Marketing Portal Leak",
    "Domain": "contoso.com",
    "BreachDate": "2023-04-18",
    "PwnCount": 18400,
    "DataClasses": ["Email addresses", "Passwords", "Job titles"],
    "IsVerified": true
  }
]
```
</details>

<details><summary>Annex A: Azure — az (<code>$ az graph query -q "Resources \| where type =~ 'Microsoft.Network/publicIPAddresses' \| project properties.ipAddress, name, resourceGroup"</code>)</summary>

```console
$ az graph query -q "Resources | where type =~ 'Microsoft.Network/publicIPAddresses' | project properties.ipAddress, name, resourceGroup"
[
  {"name": "pip-contoso-erp-prod-01", "properties_ipAddress": "198.51.100.10", "resourceGroup": "rg-contoso-erp-prod"},
  {"name": "pip-contoso-vpn-gw", "properties_ipAddress": "198.51.100.15", "resourceGroup": "rg-contoso-network"},
  {"name": "pip-vm-erp-legacy", "properties_ipAddress": "198.51.100.52", "resourceGroup": "rg-contoso-erp-prod"},
  {"name": "pip-contoso-aks-ingress", "properties_ipAddress": "198.51.100.75", "resourceGroup": "rg-contoso-cloudapps"},
  {"name": "pip-contoso-apim-prod", "properties_ipAddress": "198.51.100.102", "resourceGroup": "rg-contoso-integration"}
]
```
</details>

<details><summary>Annex A: Azure — az (<code>$ az graph query --first 1000 -o json -q "Resources \| where type =~ 'microsoft.storage/storageaccounts' \| project name, resourceGroup, allowBlobPublicAccess=properties.allowBlobPublicAccess, supportsHttpsTrafficOnly=properties.supportsHttpsTrafficOnly, minimumTlsVersion=properties.minimumTlsVersion"</code>)</summary>

```console
$ az graph query --first 1000 -o json -q "Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, resourceGroup, allowBlobPublicAccess=properties.allowBlobPublicAccess, supportsHttpsTrafficOnly=properties.supportsHttpsTrafficOnly, minimumTlsVersion=properties.minimumTlsVersion"
[
  {"name": "stcontosoexports", "resourceGroup": "rg-contoso-storage", "allowBlobPublicAccess": true, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_2"},
  {"name": "stnorthwindlogs", "resourceGroup": "rg-northwind-data", "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": false, "minimumTlsVersion": "TLS1_0"},
  {"name": "stcontosobackups", "resourceGroup": "rg-contoso-storage", "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_1"},
  {"name": "stcontosowebstatic", "resourceGroup": "rg-contoso-cloudapps", "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_2"}
]
```
</details>

<details><summary>Annex A: Azure — az (<code>$ az graph query --first 1000 -o json -q "Resources \| where type =~ 'microsoft.keyvault/vaults' \| project name, resourceGroup, enablePurgeProtection=properties.enablePurgeProtection"</code>)</summary>

```console
$ az graph query --first 1000 -o json -q "Resources | where type =~ 'microsoft.keyvault/vaults' | project name, resourceGroup, enablePurgeProtection=properties.enablePurgeProtection"
[
  {"name": "kv-contoso-prod", "resourceGroup": "rg-contoso-security", "enablePurgeProtection": false},
  {"name": "kv-northwind-dev", "resourceGroup": "rg-northwind-security", "enablePurgeProtection": false},
  {"name": "kv-contoso-infra", "resourceGroup": "rg-contoso-network", "enablePurgeProtection": true}
]
```
</details>

<details><summary>Annex A: Azure — az (<code>$ az graph query --first 1000 -o json -q "Resources \| where type =~ 'microsoft.sql/servers' \| project name, resourceGroup, publicNetworkAccess=properties.publicNetworkAccess"</code>)</summary>

```console
$ az graph query --first 1000 -o json -q "Resources | where type =~ 'microsoft.sql/servers' | project name, resourceGroup, publicNetworkAccess=properties.publicNetworkAccess"
[
  {"name": "sql-contoso-erp", "resourceGroup": "rg-contoso-erp-prod", "publicNetworkAccess": "Enabled"},
  {"name": "sql-northwind-dw", "resourceGroup": "rg-northwind-analytics", "publicNetworkAccess": "Disabled"}
]
```
</details>

<details><summary>Annex A: Azure — az (<code>$ az security pricing list -o json</code>)</summary>

```console
$ az security pricing list -o json
[
  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/VirtualMachines", "name": "VirtualMachines", "pricingTier": "Free"},
  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/StorageAccounts", "name": "StorageAccounts", "pricingTier": "Free"},
  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/SqlServers", "name": "SqlServers", "pricingTier": "Free"},
  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/AppServices", "name": "AppServices", "pricingTier": "Standard"},
  {"id": "/subscriptions/sub-contoso-prod/providers/Microsoft.Security/pricings/KeyVaults", "name": "KeyVaults", "pricingTier": "Standard"}
]
```
</details>

<details><summary>Annex G: GCP — gcloud (<code>$ gcloud compute firewall-rules list --filter="direction=INGRESS AND disabled=false" --format="table(name,network,sourceRanges.list():label=SRC,allowed[].map().firewall_rule().list():label=ALLOW)"</code>)</summary>

```console
$ gcloud compute firewall-rules list --filter="direction=INGRESS AND disabled=false" --format="table(name,network,sourceRanges.list():label=SRC,allowed[].map().firewall_rule().list():label=ALLOW)"
NAME                 NETWORK               SRC                           ALLOW
allow-ssh-legacy     vpc-analytics-prod    0.0.0.0/0                     tcp:22
allow-web-traffic    vpc-ecommerce-prod    0.0.0.0/0                     tcp:80,tcp:443
allow-health-checks  vpc-ecommerce-prod    130.211.0.0/22,35.191.0.0/16  tcp:80,tcp:443
allow-staging-debug  vpc-analytics-prod    0.0.0.0/0                     tcp:8080,tcp:9090
```
</details>

<details><summary>S — msgraph (<code>$ GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies</code>)</summary>

```console
$ GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
  "value": [
    {
      "id": "c7a8291f-0e12-4c91-b328-984210a12001",
      "displayName": "CA001-RequireMFA-Admins",
      "state": "enabled",
      "conditions": { "users": { "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"] } }
    },
    {
      "id": "d9b9302a-1f23-5d02-c439-095321b23112",
      "displayName": "CA002-BlockLegacyAuth",
      "state": "enabled",
      "conditions": { "clientAppTypes": ["exchangeActiveSync", "other"] }
    },
    {
      "id": "e0ca413b-2a34-6e13-d540-106432c34223",
      "displayName": "CA003-LegacyAuthBlock",
      "state": "enabledForReportingButNotEnforced",
      "conditions": { "users": { "includeUsers": ["All"] } }
    }
  ]
}
```
</details>

<details><summary>S — gh (<code>$ gh api /orgs/contoso/members?filter=2fa_disabled</code>)</summary>

```console
$ gh api /orgs/contoso/members?filter=2fa_disabled
[
  {"login": "contractor-dev1", "id": 1048291, "site_admin": false},
  {"login": "external-qa-lead", "id": 2049182, "site_admin": false},
  {"login": "svc-build-contoso", "id": 3058291, "site_admin": false}
]
```
</details>

<details><summary>S — gh (<code>$ gh api /orgs/contoso/secret-scanning/alerts?state=open</code>)</summary>

```console
$ gh api /orgs/contoso/secret-scanning/alerts?state=open
[
  {
    "number": 14,
    "secret_type": "azure_storage_account_key",
    "secret_type_display_name": "Azure Storage Account Key",
    "state": "open",
    "html_url": "https://github.com/contoso-org/contoso-api/security/secret-scanning/14"
  },
  {
    "number": 18,
    "secret_type": "github_personal_access_token",
    "secret_type_display_name": "GitHub Personal Access Token",
    "state": "open",
    "html_url": "https://github.com/contoso-org/contoso-api/security/secret-scanning/18"
  }
]
```
</details>


## 10. Gaps & Tool Versions

### 10.1 Tool Failures and Environmental Gaps

- amass execution timed out after 10m on contoso.com - crt.sh and subfinder results retained
- whatweb ruby gems missing on native host - container provider used

### 10.2 Tool Versions & Runtime Dependencies

| Tool / Utility | Discovered Version |
|---|---|
| **dig** | `native: DiG 9.10.6` |
| **whois** | `native: system whois` |
| **subfinder** | `native: subfinder v2.6.6` |
| **dnsx** | `native: dnsx 1.1.6` |
| **httpx** | `native: httpx v1.6.8` |
| **nmap** | `native: Nmap 7.95 ( https://nmap.org )` |
| **nuclei** | `native: nuclei v3.3.5` |
| **amass** | `docker: docker (caffix/amass:latest)` |
| **whatweb** | `docker: docker (bberastegui/whatweb:latest)` |
| **trufflehog** | `docker: docker (trufflesecurity/trufflehog:latest)` |
| **az** | `native: azure-cli 2.65.0` |
| **gcloud** | `native: Google Cloud SDK 500.0.0` |
