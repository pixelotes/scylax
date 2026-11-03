"""Active reconnaissance phases: web probing, port/service scanning, fingerprinting, and vulnerability detection."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from pathlib import Path

from recon.config import RunContext
from recon.deps import DependencyManager
from recon.runner import Logger, ev, http_get, record_virtual_cmd, run_cmd


WELL_KNOWN_PATHS: list[tuple[str, str, str]] = [
    ("/swagger.json", "api-schema", r'"swagger"\s*:|"openapi"\s*:'),
    ("/openapi.json", "api-schema", r'"openapi"\s*:|"swagger"\s*:'),
    ("/v2/api-docs", "api-schema", r'"swagger"\s*:|"paths"\s*:'),
    ("/v3/api-docs", "api-schema", r'"openapi"\s*:|"paths"\s*:'),
    ("/graphql", "graphql", r'"data"|"errors"|GraphQL'),
    ("/actuator/health", "actuator", r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"'),
    ("/actuator/env", "actuator-env", r'"activeProfiles"|"propertySources"'),
    ("/.env", "dotenv", r"^[A-Z0-9_]+=.+"),
    ("/.git/HEAD", "git-repo", r"^ref:\s+refs/heads/"),
    ("/server-status", "apache-status", r"Apache Server Status for"),
    ("/wp-json/wp/v2/users", "wp-users", r'"slug"\s*:.*"name"\s*:'),
    ("/robots.txt", "robots-disallow", r"(?i)Disallow:\s*/(admin|api|backup|private|internal|config|db|v1|v2)"),
]


def phase3(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 3: Live web host discovery, exposed paths/APIs, and CORS/cookie hygiene."""
    log.info("Phase 3 - live web host discovery, well-known paths & header/cookie hygiene")
    ctx.ensure_dirs()
    if dm.run_dir is None:
        dm.run_dir = ctx.run_dir

    resolved_file = ctx.osint_dir / "resolved.txt"
    hosts: list[str] = []
    if resolved_file.is_file():
        hosts = [
            line.strip()
            for line in resolved_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    httpx_all_txt = ctx.web_dir / "httpx_all.txt"
    httpx_lines: list[str] = []

    if dm.is_available("httpx"):
        httpx_json = ctx.web_dir / "httpx_all.json"
        ev(
            ctx.console_dir,
            "3",
            dm.build_cmd(
                "httpx",
                [
                    "-l",
                    str(resolved_file),
                    "-sc",
                    "-title",
                    "-server",
                    "-tech-detect",
                    "-location",
                    "-ip",
                    "-json",
                    "-silent",
                    "-rate-limit",
                    str(ctx.scope.httpx_rate),
                    "-timeout",
                    "10",
                    "-retries",
                    "1",
                    "-o",
                    str(httpx_json),
                ],
            ),
            timeout=900,
            title="httpx live host probe",
        )
        if httpx_json.is_file():
            with httpx_json.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    url = str(item.get("url") or "")
                    status_code = str(item.get("status_code") or item.get("status-code") or "")
                    title = str(item.get("title") or "").replace("\r", " ").replace("\n", " ")
                    webserver = str(item.get("webserver") or "")
                    location = str(item.get("location") or "")
                    httpx_lines.append(f"{url} [{status_code}] [{title}] [{webserver}] [{location}]")
    else:
        log.warn("httpx missing - using native Python HTTPS/HTTP probe (slower, no tech-detect)")
        for h in hosts:
            for scheme in ("https", "http"):
                probe_url = f"{scheme}://{h}/"
                resp = http_get(probe_url, timeout=8.0, verify_ssl=False, follow_redirects=False)
                if resp.status == 0:
                    continue
                m = re.search(r"<title[^>]*>(.*?)</title>", resp.body, re.IGNORECASE | re.DOTALL)
                title = ""
                if m:
                    title = re.sub(r"<[^>]*>", "", m.group(1)).strip().replace("\r", " ").replace("\n", " ")
                server = resp.headers.get("server", "")
                location = resp.redirect_url or resp.headers.get("location", "")
                httpx_lines.append(f"{scheme}://{h} [{resp.status}] [{title}] [{server}] [{location}]")
                break
            time.sleep(0.05)

    httpx_lines.sort()
    httpx_all_txt.write_text(
        "\n".join(httpx_lines) + ("\n" if httpx_lines else ""), encoding="utf-8"
    )

    # Record HTTP status code distribution in console phase "3" via record_virtual_cmd
    code_counts: dict[str, int] = {}
    for line in httpx_lines:
        m = re.search(r"\[(\d{3})\]", line)
        if m:
            code = m.group(1)
            code_counts[code] = code_counts.get(code, 0) + 1
    sorted_codes = sorted(code_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    dist_output = "\n".join(f"{count:>7} [{code}]" for code, count in sorted_codes)
    record_virtual_cmd(
        console_dir=ctx.console_dir,
        phase="3",
        cmd_str="grep -oE '\\[[0-9]{3}\\]' web/httpx_all.txt | sort | uniq -c | sort -rn",
        output=dist_output,
        title="HTTP status code distribution",
    )

    # Directory listings (ctx.web_dir / "dir_listings.txt" & ctx.web_dir / "dir_listings_files.txt")
    dir_listing_lines = [
        line
        for line in httpx_lines
        if re.search(r"Directory listing for|Index of /", line, re.IGNORECASE)
    ]
    (ctx.web_dir / "dir_listings.txt").write_text(
        "\n".join(dir_listing_lines) + ("\n" if dir_listing_lines else ""), encoding="utf-8"
    )

    dir_files_output: list[str] = []
    for line in dir_listing_lines:
        parts = line.split()
        if not parts:
            continue
        url = parts[0]
        url_fetch = url if url.endswith("/") else f"{url}/"
        dir_files_output.append(f"$ curl -s {url_fetch} | grep -oE <a href>")
        resp = http_get(url_fetch, timeout=10.0, verify_ssl=False)
        matches = re.findall(r'<a\s+href="[^"]*">[^<]*</a>', resp.body, re.IGNORECASE)
        for tag in matches[:50]:
            dir_files_output.append(tag)
        dir_files_output.append("# contents NOT downloaded")

    (ctx.web_dir / "dir_listings_files.txt").write_text(
        "\n".join(dir_files_output) + ("\n" if dir_files_output else ""), encoding="utf-8"
    )

    # Non-intrusive Well-Known Paths & API Surface Check (ctx.web_dir / "exposed_paths.tsv")
    live_base_urls: list[str] = []
    seen_bases: set[str] = set()
    exclude_set = set(ctx.scope.edge_ips) | set(ctx.scope.exclude_ips)

    for line in httpx_lines:
        parts = line.split()
        if not parts:
            continue
        u = parts[0]
        m = re.search(r"\[(\d{3})\]", line)
        if not m:
            continue
        code = int(m.group(1))
        if code not in (200, 301, 302, 401, 403):
            continue
        parsed = urllib.parse.urlparse(u)
        host = parsed.hostname or ""
        if host in exclude_set or any(ex in host for ex in exclude_set if ex):
            continue
        scheme = parsed.scheme or "http"
        base = f"{scheme}://{parsed.netloc}".rstrip("/")
        if base and base not in seen_bases:
            seen_bases.add(base)
            live_base_urls.append(base)
            if len(live_base_urls) >= 40:
                break

    exposed_rows: list[str] = []
    for base_url in live_base_urls:
        for path, category, regex in WELL_KNOWN_PATHS:
            target_url = f"{base_url}{path}"
            resp = http_get(target_url, timeout=8.0, verify_ssl=False, follow_redirects=False)
            if resp.status == 200:
                m = re.search(regex, resp.body, re.MULTILINE)
                if m:
                    snippet = m.group(0).strip().replace("\t", " ").replace("\r", " ").replace("\n", " ")[:120]
                    exposed_rows.append(f"{target_url}\t{category}\t{snippet}")
            time.sleep(0.05)

    (ctx.web_dir / "exposed_paths.tsv").write_text(
        "\n".join(exposed_rows) + ("\n" if exposed_rows else ""), encoding="utf-8"
    )

    # CORS & Cookie Hygiene (ctx.web_dir / "cors_cookies.tsv")
    cors_cookie_rows: list[str] = []
    for base_url in live_base_urls:
        root_resp = http_get(f"{base_url}/", timeout=8.0, verify_ssl=False, follow_redirects=False)
        headers = root_resp.headers

        # Check access-control-allow-origin header
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        if acao == "*" and acac == "true":
            cors_cookie_rows.append(
                f"{base_url}\tcors-wildcard-credentials\tAccess-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
            )

        # Check set-cookie header
        set_cookie = headers.get("set-cookie", "").strip()
        if set_cookie:
            cookie_chunks = [
                c.strip()
                for c in re.split(r",\s*(?=[a-zA-Z0-9_\-]+=[^;]+)", set_cookie)
                if c.strip()
            ]
            for chunk in cookie_chunks:
                parts = [p.strip() for p in chunk.split(";") if p.strip()]
                if not parts:
                    continue
                first = parts[0]
                if "=" not in first:
                    continue
                cookie_name = first.split("=", 1)[0].strip()
                if re.search(r"(?i)(sess|token|auth|jwt|id|login|user|sid|csrf|xsrf)", cookie_name):
                    attrs = [p.lower() for p in parts[1:]]
                    if "secure" not in attrs:
                        cors_cookie_rows.append(
                            f"{base_url}\tcookie-missing-secure\tSession cookie '{cookie_name}' missing Secure flag"
                        )
                    if "httponly" not in attrs:
                        cors_cookie_rows.append(
                            f"{base_url}\tcookie-missing-httponly\tSession cookie '{cookie_name}' missing HttpOnly flag"
                        )
        time.sleep(0.05)

    (ctx.web_dir / "cors_cookies.tsv").write_text(
        "\n".join(cors_cookie_rows) + ("\n" if cors_cookie_rows else ""), encoding="utf-8"
    )

    summary_lines = [
        f"Exposed paths checked across {len(live_base_urls)} live hosts: {len(exposed_rows)} findings",
        *(f"  {r}" for r in exposed_rows[:10]),
        f"CORS & Cookie hygiene checks across {len(live_base_urls)} live hosts: {len(cors_cookie_rows)} findings",
        *(f"  {r}" for r in cors_cookie_rows[:10]),
    ]
    record_virtual_cmd(
        console_dir=ctx.console_dir,
        phase="3",
        cmd_str="probe-well-known-paths & cors-cookies",
        output="\n".join(summary_lines),
        title="Well-Known Paths & CORS/Cookie Audit",
    )

    log.ok(
        f"{len(httpx_lines)} live web hosts, {len(dir_listing_lines)} directory listings, "
        f"{len(exposed_rows)} exposed paths, {len(cors_cookie_rows)} CORS/cookie findings"
    )


def phase4(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 4: Port and service scan of high-value & auto-discovered targets (two-pass)."""
    log.info("Phase 4 - port and service scan of high-value & auto-discovered targets (two-pass)")
    ctx.ensure_dirs()
    if dm.run_dir is None:
        dm.run_dir = ctx.run_dir

    raw_ips: list[str] = list(ctx.scope.hvt_ips)
    if ctx.scope.auto_discover_targets:
        disc_file = ctx.osint_dir / "discovered_targets.txt"
        if disc_file.is_file():
            for line in disc_file.read_text(encoding="utf-8", errors="replace").splitlines():
                ip_str = line.strip()
                if ip_str and not ip_str.startswith("#"):
                    raw_ips.append(ip_str)

    exclude_ips = set(ctx.scope.exclude_ips) | set(ctx.scope.edge_ips)
    target_ips: list[str] = []
    seen_ips: set[str] = set()
    for ip in raw_ips:
        if (
            ip not in seen_ips
            and ip not in exclude_ips
            and not ip.startswith("127.")
            and ip != "::1"
            and ip != "0.0.0.0"
        ):
            seen_ips.add(ip)
            target_ips.append(ip)

    if not dm.is_available("nmap"):
        log.warn("nmap not available - phase 4 skipped")
        return

    if not target_ips:
        log.info("No target IPs to scan in phase 4")
        return

    total = len(target_ips)
    log.info(f"Phase 4: Scanning {total} targets (rate: {ctx.scope.nmap_max_rate} pkts/s, max-retries: 1, host-timeout: 5m)")

    for idx, ip in enumerate(target_ips, 1):
        full_prefix = ctx.scan_dir / f"full_{ip}"
        nmap_file = ctx.scan_dir / f"full_{ip}.nmap"

        # Check if already scanned in an earlier or interrupted run
        if nmap_file.is_file() and nmap_file.stat().st_size > 0:
            log.info(f"[{idx}/{total}] Reusing existing scan for {ip}")
        else:
            log.info(f"[{idx}/{total}] Scanning full TCP ports on {ip}...")
            ev(
                ctx.console_dir,
                "4",
                dm.build_cmd(
                    "nmap",
                    [
                        "-sT",
                        "-Pn",
                        "-p-",
                        "--max-rate",
                        str(ctx.scope.nmap_max_rate),
                        "--max-retries",
                        "1",
                        "--host-timeout",
                        "5m",
                        "--open",
                        "-oA",
                        str(full_prefix),
                        ip,
                    ],
                ),
                timeout=360,
                title=f"nmap full TCP ({ip})",
            )

        open_ports: list[str] = []
        if nmap_file.is_file():
            for line in nmap_file.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^([0-9]+)/tcp\s+open", line)
                if m:
                    open_ports.append(m.group(1))

        if not open_ports:
            log.warn(f"[{idx}/{total}] {ip}: no open TCP ports")
            continue

        ports_csv = ",".join(open_ports)
        svc_prefix = ctx.scan_dir / f"svc_{ip}"
        svc_file = ctx.scan_dir / f"svc_{ip}.nmap"

        if svc_file.is_file() and svc_file.stat().st_size > 0:
            log.ok(f"[{idx}/{total}] {ip}: {ports_csv} (reused service scan)")
        else:
            log.info(f"[{idx}/{total}] Service fingerprinting on {ip}:{ports_csv}...")
            ev(
                ctx.console_dir,
                "4",
                dm.build_cmd(
                    "nmap",
                    [
                        "-sT",
                        "-Pn",
                        "-p",
                        ports_csv,
                        "--max-rate",
                        str(ctx.scope.nmap_max_rate),
                        "--host-timeout",
                        "5m",
                        "-sV",
                        "--script",
                        "banner,ssl-cert,ssh2-enum-algos,http-title,http-headers,http-server-header",
                        "-oA",
                        str(svc_prefix),
                        ip,
                    ],
                ),
                timeout=360,
                title=f"nmap service scan ({ip})",
            )
            log.ok(f"[{idx}/{total}] {ip}: {ports_csv}")

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        for idx, ip in enumerate(target_ips, 1):
            udp_prefix = ctx.scan_dir / f"udp_{ip}"
            log.info(f"[{idx}/{total}] Scanning UDP VPN ports on {ip}...")
            ev(
                ctx.console_dir,
                "4",
                dm.build_cmd(
                    "nmap",
                    [
                        "-sU",
                        "-Pn",
                        "-p",
                        "500,4500,443",
                        "--max-rate",
                        "100",
                        "--host-timeout",
                        "3m",
                        "-oA",
                        str(udp_prefix),
                        ip,
                    ],
                ),
                timeout=240,
                title=f"nmap UDP ({ip})",
            )
    else:
        log.warn("UDP scan of VPN ports not performed (requires root; re-run with sudo for IKE/IPsec 500/4500)")


def phase4b(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 4b: Safe edge device fingerprint."""
    log.info("Phase 4b - edge fingerprint (safe, slow, no auth)")
    ctx.ensure_dirs()
    if dm.run_dir is None:
        dm.run_dir = ctx.run_dir

    if not dm.is_available("nmap"):
        log.warn("nmap not available - phase 4b skipped")
        return

    total_edges = len(ctx.scope.edge_ips)
    for idx, ip in enumerate(ctx.scope.edge_ips, 1):
        edge_prefix = ctx.scan_dir / f"edge_{ip}"
        edge_file = ctx.scan_dir / f"edge_{ip}.nmap"
        if edge_file.is_file() and edge_file.stat().st_size > 0:
            log.info(f"[{idx}/{total_edges}] Reusing existing edge scan for {ip}")
            continue
        log.info(f"[{idx}/{total_edges}] Fingerprinting edge device {ip} (ports: {ctx.scope.edge_ports})...")
        ev(
            ctx.console_dir,
            "4b",
            dm.build_cmd(
                "nmap",
                [
                    "-sT",
                    "-Pn",
                    "-T2",
                    "--max-rate",
                    str(ctx.scope.edge_max_rate),
                    "--host-timeout",
                    "5m",
                    "-p",
                    ctx.scope.edge_ports,
                    "-sV",
                    "--script",
                    "banner",
                    "-oA",
                    str(edge_prefix),
                    ip,
                ],
            ),
            timeout=360,
            title=f"nmap edge fingerprint ({ip})",
        )
    log.ok(f"Phase 4b complete for {len(ctx.scope.edge_ips)} edge devices")


def phase5(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 5: Technology fingerprint."""
    log.info("Phase 5 - technology fingerprint (httpx tech-detect / whatweb)")
    ctx.ensure_dirs()
    if dm.run_dir is None:
        dm.run_dir = ctx.run_dir

    httpx_json = ctx.web_dir / "httpx_all.json"
    tech_tsv = ctx.web_dir / "tech.tsv"
    if httpx_json.is_file():
        tech_rows: list[str] = []
        with httpx_json.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tech = item.get("tech")
                url = str(item.get("url") or "")
                if tech and url:
                    if isinstance(tech, list):
                        tech_str = ",".join(str(t) for t in tech if str(t).strip())
                    else:
                        tech_str = str(tech).strip()
                    if tech_str:
                        tech_rows.append(f"{url}\t{tech_str}")
        tech_tsv.write_text("\n".join(tech_rows) + ("\n" if tech_rows else ""), encoding="utf-8")

    httpx_txt = ctx.web_dir / "httpx_all.txt"
    whatweb_targets = ctx.web_dir / "whatweb_targets.txt"
    urls: list[str] = []
    seen_urls: set[str] = set()
    if httpx_txt.is_file():
        for line in httpx_txt.read_text(encoding="utf-8", errors="replace").splitlines():
            if re.search(r"\[(200|301|302|401|403)\]", line):
                parts = line.split()
                if parts:
                    u = parts[0]
                    if u not in seen_urls:
                        seen_urls.add(u)
                        urls.append(u)

    whatweb_targets.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")

    if dm.is_available("whatweb") and whatweb_targets.is_file() and whatweb_targets.stat().st_size > 0:
        ev(
            ctx.console_dir,
            "5",
            dm.build_cmd(
                "whatweb",
                [
                    "-a",
                    "1",
                    "--no-errors",
                    "-i",
                    str(whatweb_targets),
                    f"--log-brief={ctx.web_dir / 'whatweb.txt'}",
                ],
            ),
            timeout=600,
            title="whatweb fingerprint",
        )
    log.ok(f"Phase 5 complete: extracted tech for {len(urls)} live targets")


def phase8(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 8: Non-intrusive vulnerability detection (nuclei)."""
    log.info("Phase 8 - vulnerability detection (nuclei, non-intrusive templates)")
    ctx.ensure_dirs()
    if dm.run_dir is None:
        dm.run_dir = ctx.run_dir

    if not dm.is_available("nuclei"):
        log.warn("nuclei not available - phase 8 skipped")
        return

    targets: list[str] = []
    for ip in ctx.scope.hvt_ips:
        targets.append(f"https://{ip}")

    if ctx.scope.auto_discover_targets:
        disc_file = ctx.osint_dir / "discovered_targets.txt"
        if disc_file.is_file():
            for line in disc_file.read_text(encoding="utf-8", errors="replace").splitlines():
                item = line.strip()
                if item and not item.startswith("#"):
                    targets.append(f"https://{item}" if not item.startswith("http") else item)

    httpx_txt = ctx.web_dir / "httpx_all.txt"
    if httpx_txt.is_file():
        for line in httpx_txt.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"^(\S+)\s+\[(\d{3})\]", line)
            if m:
                url_str, code = m.group(1), int(m.group(2))
                if code in (200, 301, 302, 307, 308, 401, 403):
                    targets.append(url_str)

    forbidden_ips = set(ctx.scope.edge_ips) | set(ctx.scope.exclude_ips)
    filtered_targets: list[str] = []
    seen: set[str] = set()
    for t in targets:
        if any(bad_ip in t for bad_ip in forbidden_ips if bad_ip):
            continue
        if t not in seen:
            seen.add(t)
            filtered_targets.append(t)

    filtered_targets.sort()
    nuclei_targets_file = ctx.web_dir / "nuclei_targets.txt"
    nuclei_targets_file.write_text(
        "\n".join(filtered_targets) + ("\n" if filtered_targets else ""), encoding="utf-8"
    )

    nuclei_jsonl = ctx.web_dir / "nuclei.jsonl"
    ev(
        ctx.console_dir,
        "8",
        dm.build_cmd(
            "nuclei",
            [
                "-l",
                str(nuclei_targets_file),
                "-exclude-tags",
                "intrusive,dos,fuzz,brute,default-login,xss,sqli,rce,lfi",
                "-severity",
                "medium,high,critical",
                "-rate-limit",
                str(ctx.scope.nuclei_rate),
                "-silent",
                "-jsonl",
                "-o",
                str(nuclei_jsonl),
            ],
        ),
        timeout=1800,
        title="nuclei scan",
    )

    findings_count = 0
    if nuclei_jsonl.is_file():
        findings_count = sum(
            1 for line in nuclei_jsonl.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()
        )
    log.ok(f"nuclei: {findings_count} findings")
