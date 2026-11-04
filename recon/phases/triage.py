"""Phase T: Automated finding candidate triage, deduplication, and report generation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import re
import urllib.parse

from recon.config import RunContext
from recon.deps import DependencyManager
from recon.report import generate_reports, nsg_ports
from recon.webprobe import is_hash_label, is_ingress_default_404
from recon import notify
from recon.runner import (
    Logger,
    http_get,
    load_tool_failures,
    record_virtual_cmd,
    ver_lt,
)


def _extract_dig_section(
    dns_text: str, qtype: str, target: str, filter_cname: bool = True
) -> list[str]:
    """Extract lines from a dig section in dns_<domain>.txt.

    Matches headers formatted as: '$ dig +short <TYPE> <TARGET>'
    Drops CNAME lines (ending in '.') if filter_cname is True.
    """
    header = f"$ dig +short {qtype} {target}".strip()
    in_sect = False
    lines: list[str] = []
    for line in dns_text.splitlines():
        line_s = line.strip()
        if line_s == header:
            in_sect = True
            continue
        elif line_s.startswith("$ "):
            in_sect = False
            continue
        if in_sect and line_s:
            if filter_cname and line_s.endswith("."):
                continue
            lines.append(line_s)
    return lines


def phaseT(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase T: Triage - automatic finding candidates and report generation."""
    log.info("Triage - automatic finding candidates (validate by hand)")
    ctx.ensure_dirs()

    candidates: list[tuple[str, str, str, str]] = []
    key_index: dict[str, int] = {}
    targets: dict[str, str] = {}

    def add(severity: str, key: str, title: str, evidence: str, target: str = "") -> None:
        """One candidate per rule key; extra evidence (e.g. other ports) is merged.

        target is the IP / URL to look at; when empty it is derived from the key."""
        key = key.strip()
        evidence = evidence.strip()
        if target and key not in targets:
            targets[key] = target.strip()
        if key in key_index:
            i = key_index[key]
            sev0, _, title0, ev0 = candidates[i]
            if evidence and evidence not in ev0.split("; "):
                candidates[i] = (sev0, key, title0, f"{ev0}; {evidence}" if ev0 else evidence)
            return
        key_index[key] = len(candidates)
        candidates.append((severity.lower().strip(), key, title.strip(), evidence))

    # ------------------------------------------------------------------
    # 2. DNS & Mail Posture per domain
    # ------------------------------------------------------------------
    for d in ctx.scope.domains:
        dns_file = ctx.osint_dir / f"dns_{d}.txt"
        if dns_file.is_file():
            dns_text = dns_file.read_text(encoding="utf-8", errors="replace")

            # SPF: No v=spf1 in TXT {d}
            spf_lines = _extract_dig_section(dns_text, "TXT", d, filter_cname=True)
            if not any("v=spf1" in line for line in spf_lines):
                add("medium", f"spf:{d}", f"{d} has no SPF record", f"dig TXT {d}")

            # DMARC: No p=reject in TXT _dmarc.{d}
            dmarc_lines = _extract_dig_section(dns_text, "TXT", f"_dmarc.{d}", filter_cname=True)
            if not any("p=reject" in line for line in dmarc_lines):
                dmarc_val = dmarc_lines[0].strip() if dmarc_lines else ""
                add("medium", f"dmarc:{d}", f"{d} has no DMARC p=reject", dmarc_val or f"dig TXT _dmarc.{d}")

            # CAA: Empty CAA {d}
            caa_lines = _extract_dig_section(dns_text, "CAA", d, filter_cname=True)
            if not caa_lines:
                add("low", f"caa:{d}", f"No CAA on {d}", f"dig CAA {d}")

            # DNSSEC: Empty DNSKEY {d}
            dnskey_lines = _extract_dig_section(dns_text, "DNSKEY", d, filter_cname=True)
            if not dnskey_lines:
                add("low", f"dnssec:{d}", f"DNSSEC unsigned on {d}", f"dig DNSKEY {d}")

            # Zone transfer allowed
            if "AXFR ALLOWED" in dns_text:
                add("high", f"axfr:{d}", f"Zone transfer allowed on {d}", "dig AXFR")

            # Wildcard DNS: Non-empty output in $ dig +short zzz...
            in_zzz = False
            zzz_lines: list[str] = []
            for line in dns_text.splitlines():
                line_s = line.strip()
                if re.match(r"^\$\s+dig\s+\+short\s+zzz", line_s):
                    in_zzz = True
                    continue
                elif line_s.startswith("$ "):
                    in_zzz = False
                    continue
                if in_zzz and line_s:
                    zzz_lines.append(line_s)
            if zzz_lines:
                add("low", f"wildcard:{d}", f"Wildcard DNS on {d}", "random label resolves")

        # WHOIS domain: check for unredacted Registrant (Name|Email)
        whois_file = ctx.raw_dir / f"whois_{d}.txt"
        if whois_file.is_file():
            whois_text = whois_file.read_text(encoding="utf-8", errors="replace")
            domain_pattern = r"@(?:" + "|".join(re.escape(dom) for dom in ctx.scope.domains) + r")"
            w_matches: list[str] = []
            for line in whois_text.splitlines():
                line_clean = line.strip()
                if not re.search(r"^\s*Registrant (Name|Email):", line, re.IGNORECASE):
                    continue
                if re.search(
                    r"redact|privacy|not disclosed|withheld|rdds|data protected|contact the registrar|:\s*$",
                    line_clean,
                    re.IGNORECASE,
                ):
                    continue
                if re.search(r"Registrant Name", line_clean, re.IGNORECASE) or re.search(
                    domain_pattern, line_clean, re.IGNORECASE
                ):
                    w_matches.append(line_clean)
                    if len(w_matches) >= 2:
                        break
            if w_matches:
                whois_match = ";".join(w_matches)
                add("low", f"whois:{d}", f"Registrant data public on {d}", whois_match)

    # ------------------------------------------------------------------
    # 3. Apex Ownership
    # ------------------------------------------------------------------
    apex_file = ctx.osint_dir / "apex.txt"
    if apex_file.is_file():
        known_ips: set[str] = set(ctx.scope.hvt_ips)
        for cloud_tsv in (
            ctx.azure_dir / "public_ips.tsv",
            ctx.gcp_dir / "public_ips.tsv",
            ctx.aws_dir / "public_ips.tsv",
        ):
            if cloud_tsv.is_file():
                for l in cloud_tsv.read_text(encoding="utf-8", errors="replace").splitlines():
                    parts = l.strip().split("\t")
                    if parts and parts[0].strip():
                        known_ips.add(parts[0].strip())

        ip_org_map: dict[str, str] = {}
        ip_orgs_file = ctx.osint_dir / "ip_orgs.tsv"
        if ip_orgs_file.is_file():
            for l in ip_orgs_file.read_text(encoding="utf-8", errors="replace").splitlines():
                cols = l.split("\t")
                if len(cols) >= 2 and cols[1].strip():
                    ip_org_map[cols[0].strip()] = cols[1].strip()

        apex_text = apex_file.read_text(encoding="utf-8", errors="replace")
        blocks: list[tuple[str, str, list[str]]] = []
        cur_d = ""
        cur_ip = ""
        cur_lines: list[str] = []
        for line in apex_text.splitlines():
            m_apex = re.match(r"^(\S+)\s+apex\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line.strip())
            if m_apex:
                if cur_d and cur_ip:
                    blocks.append((cur_d, cur_ip, cur_lines))
                cur_d = m_apex.group(1)
                cur_ip = m_apex.group(2)
                cur_lines = []
            else:
                cur_lines.append(line)
        if cur_d and cur_ip:
            blocks.append((cur_d, cur_ip, cur_lines))

        for d, ip, blk_lines in blocks:
            if ip in known_ips:
                continue

            org = ""
            for bl in blk_lines:
                m_org = re.search(r"(?i)\borg-?name\b\s*:\s*(.*)", bl)
                if m_org:
                    org = m_org.group(1).strip()
                    break
            if not org:
                for bl in blk_lines:
                    m_net = re.search(r"(?i)\bnetname\b\s*:\s*(.*)", bl)
                    if m_net:
                        org = m_net.group(1).strip()
                        break

            if not org:
                org = ip_org_map.get(ip, "")
            trusted_re = ctx.scope.apex_trusted_orgs_regex
            is_trusted = False
            if ctx.scope.apex_trusted_orgs and org and trusted_re:
                is_trusted = bool(re.search(trusted_re, org, re.IGNORECASE))

            if not is_trusted:
                add(
                    "medium",
                    f"apex:{d}",
                    f"{d} apex resolves to infrastructure not in our inventory",
                    f"{ip} ({org})",
                )

    # ------------------------------------------------------------------
    # 4. Internal Hostnames & Directory Listings
    # ------------------------------------------------------------------
    resolved_file = ctx.osint_dir / "resolved.txt"
    if resolved_file.is_file():
        for line in resolved_file.read_text(encoding="utf-8", errors="replace").splitlines():
            h = line.strip()
            if h and re.search(r"^[^.]*internal", h, re.IGNORECASE):
                add("medium", f"internal-name:{h}", "Internal-named host publicly resolvable", h)

    traversal_file = ctx.web_dir / "path_traversal.tsv"
    if traversal_file.is_file():
        for line in traversal_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                url, target = parts[0].strip(), parts[1].strip()
                snippet = parts[2].strip() if len(parts) > 2 else ""
                add("high", f"traversal:{url}", "Path traversal / local file inclusion confirmed",
                    f"{url} -> {target} ({snippet})", target=url)

    content_file = ctx.web_dir / "content_discovery.tsv"
    if content_file.is_file():
        for line in content_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                url, status, size, cat = (x.strip() for x in parts[:4])
                add(cat, f"content-disc:{url}",
                    f"Exposed path reachable (HTTP {status})", f"{url} [{status}, {size} bytes]", target=url)

    secret_leaks_file = ctx.osint_dir / "secret_leaks.tsv"
    if secret_leaks_file.is_file():
        for line in secret_leaks_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                repo, loc, detector, verified = (x.strip() for x in parts[:4])
                sev = "high" if verified == "verified" else "medium"
                add(sev, f"secret-leak:{repo}:{loc}:{detector}",
                    f"Secret leaked in public repo ({detector}" + (", verified)" if verified == "verified" else ")"),
                    f"{repo} {loc}")

    takeover_file = ctx.osint_dir / "takeover_candidates.tsv"
    if takeover_file.is_file():
        for line in takeover_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 5:
                host, cname, service, sev, reason = (x.strip() for x in parts[:5])
                evidence = parts[5].strip() if len(parts) > 5 else ""
                detail = f"{host} -> {cname} ({service}); {reason}"
                if evidence:
                    detail += f"; fingerprint: {evidence}"
                add(sev, f"takeover:{host}", f"Possible subdomain takeover ({service})", detail, target=host)

    dirlist_file = ctx.web_dir / "dir_listings.txt"
    if dirlist_file.is_file():
        for line in dirlist_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split()
            if parts:
                url = parts[0]
                add("high", f"dirlist:{url}", "Unauthenticated directory listing", url)

    # ------------------------------------------------------------------
    # 5. Exposed Paths, CORS/Cookies, Entry Points
    # ------------------------------------------------------------------
    sensitive_file = ctx.web_dir / "sensitive_paths.tsv"
    if sensitive_file.is_file():
        for line in sensitive_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                url, category, sev, title = (x.strip() for x in parts[:4])
                snippet = parts[4].strip() if len(parts) > 4 else ""
                add(sev, f"sensitive-path:{url}", title, f"{url} ({category}: {snippet})", target=url)

    exposed_file = ctx.web_dir / "exposed_paths.tsv"
    if exposed_file.is_file():
        for line in exposed_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                url = parts[0].strip()
                category = parts[1].strip()
                snippet = parts[2].strip() if len(parts) > 2 else ""
                if category in ("dotenv", "git-repo", "actuator-env"):
                    add(
                        "high",
                        f"exposed-path:{url}",
                        f"Sensitive configuration/source exposed ({category})",
                        f"{url} ({snippet})",
                    )
                elif category in ("api-schema", "api-docs", "graphql", "apache-status", "wp-users", "actuator"):
                    add(
                        "medium",
                        f"exposed-api:{url}",
                        f"Publicly accessible API schema or telemetry endpoint ({category})",
                        f"{url} ({snippet})",
                    )
                elif category == "robots-disallow":
                    add(
                        "low",
                        f"robots:{url}",
                        "Sensitive paths disclosed in robots.txt",
                        f"{url} ({snippet})",
                    )

    # Data files served without authentication: at the web root, inside a
    # directory listing, or behind an OpenAPI-described endpoint.
    def _kb(size: str) -> str:
        return f"{int(size) // 1024} KB" if size.isdigit() else "size unknown"

    root_file = ctx.web_dir / "root_data.tsv"
    if root_file.is_file():
        for line in root_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            url, ctype, size = parts[0], parts[1], parts[2]
            cols = parts[3] if len(parts) > 3 else ""
            sensitive = parts[4] if len(parts) > 4 else ""
            host = urllib.parse.urlparse(url).hostname or url
            if sensitive:
                add("critical", f"data-export:{host}", "Unauthenticated data export with personal or secret fields",
                    f"{url} ({ctype}, {_kb(size)}; fields: {sensitive})")
            else:
                add("high", f"data-export:{host}", "Unauthenticated data file served",
                    f"{url} ({ctype}, {_kb(size)}; columns: {cols[:120]})")

    api_file = ctx.web_dir / "api_endpoints.tsv"
    if api_file.is_file():
        for line in api_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 4 or parts[1] not in ("200", "206"):
                continue
            url, _, ctype, size = parts[:4]
            sensitive = parts[4] if len(parts) > 4 else ""
            host = urllib.parse.urlparse(url).hostname or url
            bulky = size.isdigit() and int(size) >= 10 * 1024
            if sensitive:
                add("critical", f"api-data:{host}", "Unauthenticated API endpoint returns personal or secret data",
                    f"{url} ({ctype}, {_kb(size)}; fields: {sensitive})")
            elif bulky or any(t in ctype for t in ("csv", "octet-stream", "spreadsheet")):
                add("high", f"api-data:{host}", "Unauthenticated API endpoint returns bulk data",
                    f"{url} ({ctype}, {_kb(size)})")

    # Hostnames that only rely on being unguessable. TLS certificates publish
    # every hostname in Certificate Transparency logs, so a hashed name is not
    # a secret: flag the ones that answer without authentication.
    ct_seen: dict[str, str] = {}
    ct_file = ctx.osint_dir / "ct_first_seen.tsv"
    if ct_file.is_file():
        for line in ct_file.read_text(encoding="utf-8", errors="replace").splitlines():
            cols = line.split("\t")
            if len(cols) == 2:
                ct_seen[cols[0]] = cols[1]
    httpx_meta: dict[str, tuple[str, str, str]] = {}
    httpx_json_file = ctx.web_dir / "httpx_all.json"
    if httpx_json_file.is_file():
        for line in httpx_json_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            h = urllib.parse.urlparse(str(item.get("url") or "")).hostname or ""
            httpx_meta[h] = (
                str(item.get("content_type") or ""),
                str(item.get("title") or ""),
                str(item.get("webserver") or ""),
            )
    httpx_all_file = ctx.web_dir / "httpx_all.txt"
    if httpx_all_file.is_file():
        for line in httpx_all_file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^(\S+)\s+\[(\d{3})\]", line)
            if not m:
                continue
            host = urllib.parse.urlparse(m.group(1)).hostname or ""
            code = int(m.group(2))
            if not is_hash_label(host) or code in (401, 403, 407):
                continue
            ct, title, server = httpx_meta.get(host, ("", "", ""))
            if code >= 500 or is_ingress_default_404(code, ct, title, server):
                continue
            first = ct_seen.get(host, "")
            add(
                "medium",
                f"hash-host:{host}",
                "Service protected only by an unguessable hostname (public in CT logs)",
                f"{host} [{code}]" + (f", first certificate {first}" if first else ""),
            )

    new_subs_file = ctx.osint_dir / "new_subdomains.txt"
    if new_subs_file.is_file():
        new_subs = [l.strip() for l in new_subs_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        if new_subs:
            hashed = [h for h in new_subs if is_hash_label(h)]
            add(
                "info",
                "new-hostnames",
                f"{len(new_subs)} new hostnames since the previous run ({len(hashed)} hash-like)",
                ", ".join((hashed + [h for h in new_subs if h not in hashed])[:12]),
            )

    cors_file = ctx.web_dir / "cors_cookies.tsv"
    if cors_file.is_file():
        for line in cors_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                url = parts[0].strip()
                issue_type = parts[1].strip()
                detail = parts[2].strip() if len(parts) > 2 else ""
                if "cors" in issue_type.lower():
                    add("medium", f"cors:{url}", "Permissive CORS policy detected", f"{url}: {detail}")
                else:
                    add("low", f"cookie:{url}", "Session cookie missing security flags", f"{url}: {detail}")

    # Vanity redirects that disclose the Entra tenant / app IDs and the SaaS map
    httpx_txt = ctx.web_dir / "httpx_all.txt"
    if httpx_txt.is_file():
        tenants: set[str] = set()
        saas_hosts: set[str] = set()
        sources: list[str] = []
        own_suffixes = tuple(f".{d}" for d in ctx.scope.domains) + tuple(ctx.scope.domains)
        for line in httpx_txt.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^(\S+)\s+\[(30[1278])\].*\[([^\]]*)\]\s*$", line.strip())
            if not m or not m.group(3).startswith("http"):
                continue
            loc = m.group(3)
            loc_host = (urllib.parse.urlparse(loc).hostname or "").lower()
            if not loc_host or loc_host.endswith(own_suffixes):
                continue
            tid = re.search(
                r"(?i)(?:tenantId=|login\.microsoftonline\.com/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                loc,
            )
            if tid:
                tenants.add(tid.group(1).lower())
            saas_hosts.add(loc_host)
            sources.append(urllib.parse.urlparse(m.group(1)).hostname or m.group(1))
        if tenants:
            add(
                "medium",
                "redirect-tenant-leak",
                "Vanity redirects disclose Entra tenant / app IDs and SaaS map",
                f"tenant {', '.join(sorted(tenants))}; {len(set(sources))} hosts -> "
                f"{', '.join(sorted(saas_hosts)[:8])}",
            )
        elif len(saas_hosts) >= 3:
            add(
                "low",
                "redirect-saas-map",
                "Vanity redirects disclose the SaaS map",
                f"{len(set(sources))} hosts -> {', '.join(sorted(saas_hosts)[:8])}",
            )

    entry_file = ctx.osint_dir / "entry_points.tsv"
    if entry_file.is_file():
        cat_groups: dict[str, list[str]] = {}
        for line in entry_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 3:
                category = parts[0].strip()
                if category.lower() == "category":
                    continue
                sample_url = parts[2].strip()
                cat_groups.setdefault(category, []).append(sample_url)
        for category, sample_urls in cat_groups.items():
            count = len(sample_urls)
            first_sample_url = sample_urls[0] if sample_urls else ""
            key_suffix = category.split()[0].lower() if category.split() else category.lower()
            add(
                "info",
                f"entrypoint:{key_suffix}",
                f"Potential {category} parameter surface identified ({count} endpoints)",
                f"Sample: {first_sample_url}",
            )

    # ------------------------------------------------------------------
    # 6. Nmap Service Scans
    # ------------------------------------------------------------------
    MGMT_UI_RE = re.compile(
        r"\b(?:OPNsense|pfSense|FortiGate|FortiOS|Fortinet|Sophos|SonicWALL|WatchGuard|"
        r"WebFig|RouterOS|MikroTik|Ubiquiti|UniFi|Webmin|Proxmox|VMware ESXi|vCenter|"
        r"iDRAC|Integrated Lights-Out|iLO|Supermicro|Synology|QNAP|cPanel|Plesk|"
        r"phpMyAdmin|Jenkins|Grafana|Kibana|Portainer|RabbitMQ Management|Tomcat Manager)\b",
        re.IGNORECASE,
    )

    MGMT_PORTS = {
        21,
        23,
        2000,
        8291,
        8728,
        3389,
        445,
        5900,
        5985,
        1723,
        3306,
        1433,
        5432,
        6379,
        9200,
        27017,
    }

    nmap_files: list[Path] = []
    for s_dir, glob_pat in (
        (ctx.scan_dir, "svc_*.nmap"),
        (ctx.scan_dir, "edge_*.nmap"),
        (ctx.azure_dir, "svc_*.nmap"),
        (ctx.gcp_dir, "svc_*.nmap"),
        (ctx.aws_dir, "svc_*.nmap"),
    ):
        if s_dir.is_dir():
            nmap_files.extend(s_dir.glob(glob_pat))
    nmap_files = sorted(set(nmap_files))

    for nmap_path in nmap_files:
        content = nmap_path.read_text(encoding="utf-8", errors="replace")
        host_blocks = re.split(r"(?=Nmap scan report for )", content)
        for block in host_blocks:
            m_ip = re.search(r"Nmap scan report for .*?([0-9]+(?:\.[0-9]+){3})", block)
            if not m_ip:
                continue
            ip = m_ip.group(1)

            # Open TCP ports
            for line in block.splitlines():
                m_port = re.match(r"^([0-9]+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
                if not m_port:
                    continue
                p = int(m_port.group(1))
                svc = m_port.group(2)
                rest = m_port.group(3).strip()

                if p in MGMT_PORTS:
                    add(
                        "critical",
                        f"mgmt:{ip}:{p}",
                        f"Management / legacy / database service {svc} exposed",
                        f"{ip}:{p} {rest}".strip(),
                    )
                elif p == 22:
                    add(
                        "medium",
                        f"ssh:{ip}",
                        "SSH reachable from the internet",
                        f"{ip}:22 {rest}".strip(),
                    )

                m_ap = re.search(r"Apache httpd ([0-9.]+)", rest)
                if m_ap:
                    v = m_ap.group(1).rstrip(".")
                    if ver_lt(v, ctx.scope.min_apache):
                        add("high", f"apache:{ip}", f"Outdated Apache {v}", f"{ip}:{p}")

                m_ng = re.search(r"nginx ([0-9.]+)", rest)
                if m_ng:
                    v = m_ng.group(1).rstrip(".")
                    if ver_lt(v, ctx.scope.min_nginx):
                        add("medium", f"nginx:{ip}", f"Outdated nginx {v}", f"{ip}:{p}")

                m_ros = re.search(r"MikroTik[^0-9]*([0-9]+\.[0-9]+)", rest)
                if m_ros:
                    v = m_ros.group(1).rstrip(".")
                    if ver_lt(v, ctx.scope.min_routeros):
                        add("critical", f"routeros:{ip}", f"End-of-life RouterOS {v}", f"{ip}:{p}")

            # Weak SSH algorithms
            weak_algos = sorted(
                set(
                    re.findall(
                        r"ssh-dss|diffie-hellman-group14-sha1|diffie-hellman-group1-sha1",
                        block,
                    )
                )
            )
            if weak_algos:
                add(
                    "medium",
                    f"ssh-weak:{ip}",
                    "SSH offers legacy algorithms",
                    ",".join(weak_algos),
                )

            # Default Kubernetes fake certificate
            if "Kubernetes Ingress Controller Fake Certificate" in block:
                add("low", f"fakecert:{ip}", "Default Kubernetes ingress certificate", ip)

            # Firewall admin GUI
            mgmt_lines = [
                l for l in block.splitlines()
                if re.match(r"^\d+/tcp\s+open\b", l.strip()) or "http-title" in l
            ]
            m_fw = MGMT_UI_RE.search("\n".join(mgmt_lines))
            if m_fw:
                port_m = re.search(r"^(\d+)/tcp\s+open\b.*" + re.escape(m_fw.group(0)), block, re.M)
                where = f"{ip}:{port_m.group(1)}" if port_m else ip
                add(
                    "high",
                    f"fw-admin:{ip}",
                    "Firewall / router / server management interface on the internet",
                    f"{where} {m_fw.group(0)}",
                )

            # Expired TLS cert
            expired_seen: set[str] = set()
            for m_exp in re.finditer(r"Not valid after:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", block):
                exp = m_exp.group(1)
                if exp < ctx.today and exp not in expired_seen:
                    expired_seen.add(exp)
                    add(
                        "medium",
                        f"cert-expired:{ip}",
                        "Expired TLS certificate",
                        f"{ip} expired {exp}",
                    )

            # 502 Bad Gateway
            if "502 Bad Gateway" in block:
                add("low", f"502:{ip}", "Broken / abandoned gateway (502)", ip)

    # ------------------------------------------------------------------
    # 7. Service CVE & CISA KEV Correlation
    # ------------------------------------------------------------------
    cve_file = ctx.osint_dir / "service_cves.tsv"
    if cve_file.is_file():
        cve_groups: dict[tuple[str, str, str, str], list[dict[str, object]]] = {}
        for line in cve_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 6:
                ip_cve, port_cve, svc_cve, ver_cve, cve_id, cvss_str = [p.strip() for p in parts[:6]]
                if ip_cve.lower() == "ip":
                    continue
                is_kev_val = parts[6].strip() if len(parts) > 6 else ""
                try:
                    cvss_val = float(cvss_str)
                except (ValueError, TypeError):
                    cvss_val = 0.0
                grp_key = (ip_cve, port_cve, svc_cve, ver_cve)
                cve_groups.setdefault(grp_key, []).append({
                    "cve": cve_id,
                    "cvss": cvss_val,
                    "is_kev": is_kev_val.lower() in ("true", "1", "yes"),
                })

        for (ip_cve, port_cve, svc_cve, ver_cve), items in cve_groups.items():
            kev_cves: list[str] = []
            seen_kev: set[str] = set()
            for it in items:
                cve_code = str(it["cve"])
                if it["is_kev"] and cve_code not in seen_kev:
                    seen_kev.add(cve_code)
                    kev_cves.append(cve_code)

            service_ver = f"{svc_cve} {ver_cve}".strip()

            if kev_cves:
                add(
                    "critical",
                    f"cve-kev:{ip_cve}:{port_cve}",
                    f"Actively exploited CVE (CISA KEV) on {service_ver}".strip(),
                    f"{ip_cve}:{port_cve} -> {', '.join(kev_cves[:5])}",
                )
            else:
                max_cvss = max((float(it["cvss"]) for it in items), default=0.0)
                if max_cvss >= 7.0:
                    sorted_items = sorted(items, key=lambda x: -float(x["cvss"]))
                    top_cves: list[str] = []
                    seen_top: set[str] = set()
                    for it in sorted_items:
                        cve_code = str(it["cve"])
                        if cve_code not in seen_top:
                            seen_top.add(cve_code)
                            top_cves.append(cve_code)
                    # Distro packages (Ubuntu/Debian/RHEL...) backport fixes without
                    # changing the upstream version: version-matched CVEs need checking.
                    distro = re.search(r"(?i)ubuntu|debian|deb\d|\.el\d|rhel|centos|suse|alpine", service_ver)
                    add(
                        "medium" if distro else "high",
                        f"cve-high:{ip_cve}:{port_cve}",
                        f"High-severity CVEs (max CVSS {max_cvss}) on {service_ver}".strip()
                        + (" - distro build, verify backports" if distro else ""),
                        f"{ip_cve}:{port_cve} -> {', '.join(top_cves[:5])}",
                    )

    # ------------------------------------------------------------------
    # 8. Cloud Firewall Rules Open to the Internet
    # ------------------------------------------------------------------
    SENSITIVE_PORTS_RE = re.compile(
        r"(^|[^0-9])(22|3389|445|1433|3306|5432|5985|5986|6379|27017|\*|all)([^0-9]|$)",
        re.IGNORECASE,
    )

    # Public IP per NIC ("networkInterfaces/<nic>" in public_ips.tsv), to point NSG findings at an address.
    # Azure resource names are case-insensitive and both APIs spell them differently.
    azure_nic_ips: dict[str, str] = {}
    azure_ips_file = ctx.azure_dir / "public_ips.tsv"
    if azure_ips_file.is_file():
        for line in azure_ips_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4 and parts[3].startswith("networkInterfaces/"):
                azure_nic_ips.setdefault(parts[3].split("/", 1)[1].lower(), parts[0].strip())

    azure_nsg_file = ctx.azure_dir / "nsg_internet_rules.tsv"
    if azure_nsg_file.is_file():
        for line in azure_nsg_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                nsg = parts[0].strip()
                rg = parts[1].strip()
                rule = parts[2].strip()
                ports = nsg_ports(parts[3])
                nics = parts[4].strip() if len(parts) > 4 else "0"
                nic_names = [n for n in (parts[5].split(",") if len(parts) > 5 else []) if n]
                nsg_id = parts[6].strip() if len(parts) > 6 else ""
                if SENSITIVE_PORTS_RE.search(ports):
                    ips = list(dict.fromkeys(azure_nic_ips[n.lower()] for n in nic_names if n.lower() in azure_nic_ips))
                    add(
                        "medium",
                        f"nsg:{nsg}:{rule}",
                        f"Azure NSG allows {ports} from Internet",
                        f"{rg}/{nsg} rule {rule} (nics: {nics})",
                        target=", ".join(ips) or (f"https://portal.azure.com/#@/resource{nsg_id}" if nsg_id else ""),
                    )

    gcp_fw_file = ctx.gcp_dir / "firewall_internet_rules.tsv"
    if gcp_fw_file.is_file():
        for line in gcp_fw_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                name = parts[0].strip()
                project = parts[1].strip()
                network = parts[2].strip()
                ports = parts[3].strip()
                tags = parts[4].strip() if len(parts) > 4 else ""
                if SENSITIVE_PORTS_RE.search(ports):
                    add(
                        "medium",
                        f"gcp-fw:{project}:{name}",
                        f"GCP VPC firewall allows {ports} from Internet",
                        f"{project}/{network} rule {name} (tags: {tags})",
                        target=f"https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/details/{name}?project={project}",
                    )

    aws_sg_file = ctx.aws_dir / "sg_internet_rules.tsv"
    if aws_sg_file.is_file():
        for line in aws_sg_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                gid = parts[0].strip()
                gname = parts[1].strip()
                reg = parts[2].strip()
                ports = parts[3].strip()
                cidr = parts[4].strip() if len(parts) > 4 else ""
                if SENSITIVE_PORTS_RE.search(ports):
                    add(
                        "medium",
                        f"aws-sg:{gid}",
                        f"AWS Security Group allows {ports} from Internet",
                        f"{gname} ({gid}) in {reg} (cidr: {cidr})",
                        target=f"https://console.aws.amazon.com/ec2/home?region={reg}#SecurityGroup:groupId={gid}",
                    )

    # ------------------------------------------------------------------
    # 8b. Cloud Security Posture Findings
    # ------------------------------------------------------------------
    for cloud_dir in (ctx.azure_dir, ctx.gcp_dir, ctx.aws_dir):
        posture_tsv = cloud_dir / "posture_findings.tsv"
        if posture_tsv.is_file():
            for line in posture_tsv.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 5:
                    sev = parts[0].strip()
                    key = parts[1].strip()
                    # parts[2] is service, parts[3] is resource
                    title = parts[4].strip()
                    detail = parts[5].strip() if len(parts) >= 6 else ""
                    if sev and key and title:
                        add(sev, key, title, detail)

    # ------------------------------------------------------------------
    # 8c. SaaS Security Posture Findings
    # ------------------------------------------------------------------
    saas_posture_tsv = ctx.saas_dir / "posture_findings.tsv"
    if saas_posture_tsv.is_file():
        for line in saas_posture_tsv.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 5:
                sev = parts[0].strip()
                key = parts[1].strip()
                # parts[2] is service, parts[3] is resource
                title = parts[4].strip()
                detail = parts[5].strip() if len(parts) >= 6 else ""
                if sev and key and title:
                    add(sev, key, title, detail)

    # ------------------------------------------------------------------
    # 9. Nuclei, Wayback Critical & Website Security Headers
    # ------------------------------------------------------------------
    nuclei_file = ctx.web_dir / "nuclei.jsonl"
    if nuclei_file.is_file():
        for line in nuclei_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                n_obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = n_obj.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            template_id = str(n_obj.get("template-id") or n_obj.get("templateID") or "")
            host = str(n_obj.get("host") or "")
            name = str(info.get("name") or template_id or "")
            add(severity, f"nuclei:{template_id}:{host}", name, host)

    wb_file = ctx.osint_dir / "wayback_critical.txt"
    if wb_file.is_file():
        wb_lines = [l.strip() for l in wb_file.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        if wb_lines:
            add("high", "wayback-critical", "Sensitive files in Wayback history", f"{len(wb_lines)} URLs")

    if ctx.scope.www_url and not ctx.skip_active:
        try:
            resp = http_get(
                ctx.scope.www_url,
                timeout=10.0,
                verify_ssl=False,
                follow_redirects=True,
                method="HEAD",
            )
            if resp.status == 0:
                resp = http_get(
                    ctx.scope.www_url,
                    timeout=10.0,
                    verify_ssl=False,
                    follow_redirects=True,
                    method="GET",
                )
            if resp.status > 0:
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                missing: list[str] = []
                for h_name in ("x-frame-options", "x-content-type-options", "permissions-policy"):
                    if h_name not in headers_lower:
                        missing.append(h_name)
                if missing:
                    add(
                        "low",
                        "headers:www",
                        "Public website missing security headers",
                        f"{ctx.scope.www_url}: {' '.join(missing)}",
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 9b. HaveIBeenPwned Domain Breaches
    # ------------------------------------------------------------------
    hibp_file = ctx.osint_dir / "hibp_breaches.tsv"
    if hibp_file.is_file():
        for line in hibp_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("domain\t"):
                continue
            parts = line.split("\t")
            if len(parts) >= 5:
                b_domain = parts[0].strip()
                b_name = parts[1].strip()
                b_title = parts[2].strip() or b_name
                b_date = parts[3].strip()
                b_pwn_cnt = parts[4].strip()
                b_classes = parts[5].strip() if len(parts) > 5 else ""
                is_sensitive = parts[7].strip().lower() in ("true", "1") if len(parts) > 7 else False

                sev = "medium"
                if "passwords" in b_classes.lower() or "password hints" in b_classes.lower() or is_sensitive:
                    sev = "high"
                add(
                    sev,
                    f"hibp:{b_domain}:{b_name}",
                    f"Domain breach history: {b_title} ({b_date})",
                    f"{b_pwn_cnt} accounts, exposed: {b_classes}",
                )

    # ------------------------------------------------------------------
    # 9c. HaveIBeenPwned Compromised Corporate Accounts
    # ------------------------------------------------------------------
    hibp_acc_file = ctx.osint_dir / "hibp_account_breaches.tsv"
    if hibp_acc_file.is_file():
        for line in hibp_acc_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("email\t"):
                continue
            parts = line.split("\t")
            if len(parts) >= 5:
                b_email = parts[0].strip()
                b_name = parts[1].strip()
                b_title = parts[2].strip() or b_name
                b_date = parts[3].strip()
                b_pwn_cnt = parts[4].strip()
                b_classes = parts[5].strip() if len(parts) > 5 else ""
                is_sensitive = parts[7].strip().lower() in ("true", "1") if len(parts) > 7 else False

                sev = "medium"
                if "passwords" in b_classes.lower() or "password hints" in b_classes.lower() or is_sensitive:
                    sev = "high"
                add(
                    sev,
                    f"hibp-account:{b_email}:{b_name}",
                    f"Compromised corporate email: {b_email} in {b_title} ({b_date or 'date unknown'})",
                    f"Exposed data: {b_classes.replace(';', '; ') or 'unknown (not published for this breach)'}",
                )

    # ------------------------------------------------------------------
    # 10. Write Outputs (findings_auto.tsv, findings_auto.md, diff.md, report.md, report.html)
    # ------------------------------------------------------------------
    SEVERITY_ORDER: dict[str, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    candidates[:] = _fold_per_host(candidates, SEVERITY_ORDER)

    seen_candidates: set[tuple[str, str, str, str]] = set()
    deduped: list[tuple[str, str, str, str]] = []
    for sev, key, title, ev in candidates:
        item = (
            sev.lower().strip(),
            key.strip(),
            title.strip(),
            ev.strip().replace("\t", " ").replace("\r", " ").replace("\n", " "),
        )
        if item not in seen_candidates:
            seen_candidates.add(item)
            deduped.append(item)

    # Sort deduplicated findings by severity order ("critical", "high", "medium", "low", "info") then by key
    deduped.sort(key=lambda x: (SEVERITY_ORDER.get(x[0], 99), x[1], x[2]))

    # Write findings_auto.tsv
    def target_of(key: str) -> str:
        return targets.get(key) or finding_target(key)

    tsv_lines = [f"{sev}\t{key}\t{title}\t{ev}\t{target_of(key)}\n" for sev, key, title, ev in deduped]
    (ctx.run_dir / "findings_auto.tsv").write_text("".join(tsv_lines), encoding="utf-8")

    # Write findings_auto.md
    md_lines: list[str] = [
        f"# Automatic finding candidates - {ctx.run_date}",
        "",
        "Validate every line by hand before it goes into the report.",
        "",
        "| Severity | Finding | Target | Evidence | Key |",
        "|---|---|---|---|---|",
    ]
    for sev, key, title, ev in deduped:
        esc_title = title.replace("|", "\\|")
        esc_ev = ev.replace("|", "\\|")
        esc_target = target_of(key).replace("|", "\\|")
        md_lines.append(f"| {sev} | {esc_title} | {esc_target} | {esc_ev} | `{key}` |")

    gaps_file = ctx.run_dir / "gaps.txt"
    if gaps_file.is_file():
        raw_gaps = [
            line.strip()
            for line in gaps_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        if raw_gaps:
            unique_gaps = sorted(set(raw_gaps))
            md_lines.append("")
            md_lines.append("## Gaps / tool failures")
            md_lines.append("")
            for g in unique_gaps:
                md_lines.append(f"- {g}")

    (ctx.run_dir / "findings_auto.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    # Diff against the previous run and the scope-wide finding history
    curr_map: dict[str, tuple[str, str, str, str]] = {}
    for item in deduped:
        curr_map.setdefault(item[1], item)
    history_path = ctx.runs_root / ctx.scope.name / "findings_history.json"
    had_history = history_path.is_file()
    history = _update_history(ctx, curr_map)

    if ctx.prev_run_dir is None and had_history:
        log.warn(
            f"no previous run directory under {ctx.runs_root / ctx.scope.name} but a finding "
            f"history exists - the diff is skipped; is runs_dir / the working directory correct?"
        )

    if ctx.prev_run_dir is not None and (ctx.prev_run_dir / "findings_auto.tsv").is_file():
        prev_tsv = ctx.prev_run_dir / "findings_auto.tsv"
        prev_map: dict[str, tuple[str, str, str, str]] = {}
        for line in prev_tsv.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                prev_map.setdefault(parts[1].strip(), (parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()))

        curr_phases = _run_phases(ctx.run_dir)
        prev_phases = _run_phases(ctx.prev_run_dir)
        prev_keys = set(prev_map)
        curr_keys = set(curr_map)

        failed_tools = {tool for _, tool, _ in load_tool_failures(ctx.run_dir)}

        def _checked_in_both(key: str) -> bool:
            # The tool that reports it failed this time: absence proves nothing
            if any(t in failed_tools for t in finding_tools(key)):
                return False
            ph = finding_phase(key)
            # Unknown origin, or run.meta missing: assume it was checked
            return ph is None or not curr_phases or not prev_phases or (ph in curr_phases and ph in prev_phases)

        gone = prev_keys - curr_keys
        resolved_keys = sorted(k for k in gone if _checked_in_both(k))
        unchecked_keys = sorted(k for k in gone if not _checked_in_both(k))
        new_all = curr_keys - prev_keys
        reappeared_keys = sorted(k for k in new_all if len(history.get(k, {}).get("seen", [])) > 1)
        new_keys = sorted(k for k in new_all if k not in reappeared_keys)
        persisting_keys = sorted(curr_keys & prev_keys)

        def _age(key: str) -> str:
            h = history.get(key, {})
            seen = h.get("seen", [])
            return f" _(open since {h.get('first_seen', '?')}, {len(seen)} runs)_" if seen else ""

        diff_lines: list[str] = [f"# Changes {ctx.prev_run_dir.name} -> {ctx.run_date}"]
        for section_name, keys, src, with_age in (
            ("New", new_keys, curr_map, False),
            ("Reappeared", reappeared_keys, curr_map, True),
            ("Resolved", resolved_keys, prev_map, False),
            ("Not re-checked", unchecked_keys, prev_map, False),
            ("Persisting", persisting_keys, curr_map, True),
        ):
            diff_lines.append("")
            diff_lines.append(f"## {section_name} ({len(keys)})")
            diff_lines.append("")
            if section_name == "Not re-checked" and keys:
                diff_lines.append("_The phase or tool that produces these did not run (or failed) this time; status unknown._")
                diff_lines.append("")
            for k in sorted(keys, key=lambda x: (SEVERITY_ORDER.get(src[x][0], 99), x)):
                f_item = src[k]
                diff_lines.append(f"- **{f_item[0]}** {f_item[2]} - {f_item[3]}" + (_age(k) if with_age else ""))

        (ctx.run_dir / "diff.md").write_text("\n".join(diff_lines) + "\n", encoding="utf-8")
        log.ok(f"diff vs {ctx.prev_run_dir.name} in diff.md")

        # Alert on new / reappeared high and critical findings
        alert_keys = [k for k in (new_keys + reappeared_keys)
                      if curr_map[k][0] in ("critical", "high")]
        if alert_keys and notify.webhook_url(ctx.scope):
            alert_findings = [curr_map[k] for k in sorted(
                alert_keys, key=lambda x: (SEVERITY_ORDER.get(curr_map[x][0], 99), x))]
            _, msg = notify.post_new_findings(
                ctx.scope, ctx.scope.name, ctx.run_date, alert_findings)
            log.info(f"Alert: {msg}")

    record_virtual_cmd(
        console_dir=ctx.console_dir,
        phase="T",
        cmd_str=f"triage --run-dir {ctx.run_dir.name}",
        output=f"{len(deduped)} candidates -> findings_auto.md, report.md, report.html",
        title="Triage Finding Candidates",
    )

    md_path, html_path = generate_reports(ctx.run_dir)
    log.ok(f"{len(deduped)} candidates -> findings_auto.md, report.md, report.html")


# Which phase produces each finding key (by prefix). Used so that a run that
# skipped a phase does not report that phase's findings as "resolved".
_PHASE_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("new-hostnames", "1"),
    ("spf:", "2"), ("dmarc:", "2"), ("caa:", "2"), ("dnssec:", "2"), ("axfr:", "2"),
    ("wildcard:", "2"), ("whois:", "2"), ("apex:", "2"), ("internal-name:", "2"),
    ("dirlist:", "3"), ("exposed-path:", "3"), ("exposed-api:", "3"), ("robots:", "3"),
    ("cors:", "3"), ("cookie:", "3"), ("headers:", "3"), ("data-export:", "3"),
    ("api-data:", "3"), ("hash-host:", "3"), ("redirect-", "3"),
    ("mgmt:", "4"), ("ssh:", "4"), ("ssh-weak:", "4"), ("apache:", "4"), ("nginx:", "4"),
    ("routeros:", "4"), ("fakecert:", "4"), ("fw-admin:", "4"), ("cert-expired:", "4"), ("502:", "4"),
    ("entrypoint:", "6"), ("wayback-", "6"),
    ("cve-", "7"),
    ("nuclei:", "8"), ("sensitive-path:", "8"),
    ("takeover:", "2"),
    ("secret-leak:", "9"),
    ("content-disc:", "C"), ("traversal:", "C"),
)


# Which external tools produce each finding key. If one of them failed in the
# current run (tool_failures.tsv), a missing finding is "not re-checked".
_TOOLS_BY_PREFIX: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("nuclei:", ("nuclei",)),
    ("secret-leak:", ("gitleaks", "trufflehog", "git")),
    ("content-disc:", ("gobuster",)),
    ("traversal:", ("gobuster",)),
    ("takeover:", ("dig",)),
    ("mgmt:", ("nmap",)), ("ssh:", ("nmap",)), ("ssh-weak:", ("nmap",)), ("apache:", ("nmap",)),
    ("nginx:", ("nmap",)), ("routeros:", ("nmap",)), ("fakecert:", ("nmap",)), ("fw-admin:", ("nmap",)),
    ("cert-expired:", ("nmap",)), ("cve-", ("nmap",)),
)


def finding_tools(key: str) -> tuple[str, ...]:
    for prefix, tools in _TOOLS_BY_PREFIX:
        if key.startswith(prefix):
            return tools
    return ()


def finding_phase(key: str) -> str | None:
    for prefix, phase in _PHASE_BY_PREFIX:
        if key.startswith(prefix):
            return phase
    return None


def _run_phases(run_dir: Path) -> set[str]:
    meta = run_dir / "run.meta"
    if not meta.is_file():
        return set()
    for line in meta.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("phases="):
            phases = set(line[len("phases="):].split())
            # Phase 4b (edge devices) produces the same finding types as 4
            if "4b" in phases:
                phases.add("4")
            return phases
    return set()


def _update_history(ctx: RunContext, curr_map: dict[str, tuple[str, str, str, str]]) -> dict[str, dict]:
    """Record in runs/<scope>/findings_history.json the run dates each finding
    key was seen on, so persisting and reappearing findings can be aged."""
    path = ctx.runs_root / ctx.scope.name / "findings_history.json"
    try:
        history = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (json.JSONDecodeError, OSError):
        history = {}
    for key, (sev, _, title, _) in curr_map.items():
        h = history.setdefault(key, {"first_seen": ctx.run_date, "seen": []})
        if ctx.run_date not in h["seen"]:
            h["seen"].append(ctx.run_date)
            h["seen"].sort()
        h["first_seen"] = min(h["first_seen"], ctx.run_date)
        h["severity"], h["title"] = sev, title
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(history, indent=1, sort_keys=True), encoding="utf-8")
    except OSError:
        pass
    return history


# Web findings about the same host are folded into its most severe one, so a
# single exposed service shows up once (with the rest as supporting evidence)
# instead of as a directory listing + data file + API docs + hashed name.
_IP_KEY_PREFIXES = ("502:", "apache:", "cert-expired:", "fakecert:", "fw-admin:", "nginx:",
                    "routeros:", "ssh:", "ssh-weak:")
_URL_KEY_PREFIXES = ("cookie:", "cors:", "dirlist:", "exposed-api:", "exposed-path:", "robots:", "sensitive-path:", "content-disc:", "traversal:")
_HOST_KEY_PREFIXES = ("api-data:", "data-export:", "hash-host:")
_DOMAIN_KEY_PREFIXES = ("apex:", "axfr:", "caa:", "dmarc:", "dnssec:", "spf:", "whois:", "wildcard:",
                        "internal-name:")


def finding_target(key: str) -> str:
    """The IP, host:port or URL a finding is about, derived from its rule key.

    Breach findings point at a public lookup: the account's XposedOrNot query
    or the breach's HIBP catalogue entry. '' when the key names no resource."""
    prefix, _, rest = key.partition(":")
    prefix += ":"
    if prefix in _IP_KEY_PREFIXES or prefix in _DOMAIN_KEY_PREFIXES:
        return rest
    if prefix in _URL_KEY_PREFIXES:
        return rest
    if prefix in _HOST_KEY_PREFIXES:
        return f"https://{rest}/"
    if prefix in ("mgmt:", "cve-kev:", "cve-high:"):
        return rest  # ip:port
    if prefix == "nuclei:":
        return rest.split(":", 1)[1] if ":" in rest else rest
    if prefix == "hibp-account:":
        email = rest.rsplit(":", 1)[0]
        return f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(email)}"
    if prefix == "hibp:":
        breach = rest.rsplit(":", 1)[-1]
        return f"https://haveibeenpwned.com/PwnedWebsites#{urllib.parse.quote(breach)}"
    return ""


_HOST_FOLD_PREFIXES = ("api-data:", "data-export:", "exposed-path:", "dirlist:", "exposed-api:", "hash-host:", "sensitive-path:", "content-disc:", "traversal:")


def _fold_host(key: str) -> str | None:
    for prefix in _HOST_FOLD_PREFIXES:
        if key.startswith(prefix):
            rest = key[len(prefix):]
            return (urllib.parse.urlparse(rest).hostname or "") if "://" in rest else rest.split("/")[0]
    return None


def _fold_per_host(
    candidates: list[tuple[str, str, str, str]], severity_order: dict[str, int]
) -> list[tuple[str, str, str, str]]:
    groups: dict[str, list[int]] = {}
    for i, (_, key, _, _) in enumerate(candidates):
        host = _fold_host(key)
        if host:
            groups.setdefault(host, []).append(i)
    drop: set[int] = set()
    out = list(candidates)
    for idxs in groups.values():
        if len(idxs) < 2:
            continue
        rank = lambda i: (severity_order.get(candidates[i][0], 99),
                          [k for k in range(len(_HOST_FOLD_PREFIXES)) if candidates[i][1].startswith(_HOST_FOLD_PREFIXES[k])][0])
        main, *rest = sorted(idxs, key=rank)
        sev, key, title, evidence = candidates[main]
        extra = "; ".join(f"{candidates[i][2]}: {candidates[i][3]}" for i in rest)
        out[main] = (sev, key, title, f"{evidence} | also: {extra}")
        drop.update(rest)
    return [c for i, c in enumerate(out) if i not in drop]
