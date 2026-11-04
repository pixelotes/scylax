"""OSINT and passive reconnaissance phase implementations.

Phases implemented:
- phase1: Passive subdomain enumeration (subfinder, amass, crt.sh)
- phase2: DNS resolution, posture, and target IP auto-discovery
- phase6: Historical URLs (Wayback CDX) & potential entry points
- phase7: Exposure DB lookup (Shodan) & automated service/CPE CVE correlation
- phase9: Secret scanning (Trufflehog instructions & GitHub code search)
"""

from __future__ import annotations

import collections
import csv
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import socket
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Set, Tuple

from recon.config import RunContext
from recon.deps import DependencyManager
from recon.runner import (
    Logger,
    ev,
    http_get,
    http_get_json,
    record_tool_failure,
    record_virtual_cmd,
    run_cmd,
)
from recon.osint_keys import collect_keys, write_configs
from recon.nvd import cpe_to_23, load_kev_ids, nvd_cves_for_cpe
from recon.scope import ScopeGuard
from recon.takeover import check_takeover
from recon.webprobe import is_hash_label


def _prepare_key_args(
    ctx: RunContext, dm: DependencyManager, log: Logger, keys_dir: Path
) -> tuple[list[str], list[str]]:
    """Write subfinder/amass provider configs from the scope's API keys.

    Returns extra CLI args for (subfinder, amass); both empty when no key applies."""
    keys = collect_keys(ctx.scope, ctx.shodan_api_key)
    if not keys:
        return [], []

    def tool_path(tool: str) -> Callable[[Path], str]:
        # In docker mode the run dir is mounted at /data inside the container.
        if dm.get_provider(tool) == "docker":
            return lambda p: f"/data/{p.relative_to(ctx.run_dir).as_posix()}"
        return lambda p: str(p.resolve())

    sf_path, _, sources = write_configs(keys, keys_dir, tool_path("subfinder"))
    _, am_path, _ = write_configs(keys, keys_dir, tool_path("amass"))
    if sources:
        log.info(f"API keys loaded for subfinder/amass: {', '.join(sources)}")
    return (["-pc", sf_path] if sf_path else []), (["-config", am_path] if am_path else [])


def phase1(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 1 - passive subdomain enumeration (subfinder, amass -passive, crt.sh)."""
    ctx.ensure_dirs()
    keys_dir = ctx.run_dir / ".keys"
    try:
        sf_args, am_args = _prepare_key_args(ctx, dm, log, keys_dir)
        _phase1(ctx, dm, log, sf_args, am_args)
    finally:
        shutil.rmtree(keys_dir, ignore_errors=True)  # never leave keys in the evidence folder


def _phase1(ctx: RunContext, dm: DependencyManager, log: Logger, sf_args: list[str], am_args: list[str]) -> None:
    log.info("Phase 1 - passive subdomain enumeration (subfinder, amass -passive, crt.sh)")
    ctx.ensure_dirs()

    all_raw_lines: list[str] = []
    # Certificate Transparency: first certificate date per hostname
    ct_first_seen: dict[str, str] = {}

    def _ct_note(name: str, not_before: str) -> None:
        name = name.strip().lower()
        if name.startswith("*."):
            name = name[2:]
        day = str(not_before or "")[:10]
        if name and day and (name not in ct_first_seen or day < ct_first_seen[name]):
            ct_first_seen[name] = day

    for d in ctx.scope.domains:
        # 1. subfinder
        if dm.is_available("subfinder"):
            cmd = dm.build_cmd("subfinder", ["-d", d, "-all", "-silent", *sf_args])
            res = ev(ctx.console_dir, "1", cmd, timeout=300, title=f"subfinder ({d})")
            for line in res.stdout.splitlines():
                s = line.strip()
                if s:
                    all_raw_lines.append(s)

        # 2. amass (passive)
        if ctx.scope.use_amass and dm.is_available("amass"):
            amass_timeout = ctx.scope.amass_timeout_min * 60 + 120
            cmd = dm.build_cmd(
                "amass",
                ["enum", "-passive", "-timeout", str(ctx.scope.amass_timeout_min), *am_args, "-d", d],
            )
            res = ev(ctx.console_dir, "1", cmd, timeout=amass_timeout, title=f"amass ({d})")
            amass_re = re.compile(rf"([a-zA-Z0-9_-]+\.)+{re.escape(d)}", re.IGNORECASE)
            for m in amass_re.finditer(res.stdout):
                all_raw_lines.append(m.group(0))
            # amass v5 stores results in its asset DB (enum stdout is mostly a
            # progress bar), so harvest whatever it found - even after a timeout.
            subs = ev(
                ctx.console_dir, "1",
                dm.build_cmd("amass", ["subs", "-names", "-nocolor", "-d", d]),
                timeout=60, title=f"amass subs ({d})",
            )
            harvested = 0
            if subs.returncode == 0:
                for m in amass_re.finditer(subs.stdout):
                    all_raw_lines.append(m.group(0))
                    harvested += 1
            if res.timed_out:
                log.warn(
                    f"amass timed out for {d} after {amass_timeout}s "
                    f"(-timeout is minutes *without progress*, a stalled/busy amass engine "
                    f"can hold it open; try `pkill -f 'amass engine'`); "
                    f"recovered {harvested} names from its DB"
                )
            elif res.returncode != 0:
                log.warn(f"amass failed for {d} (rc={res.returncode}): {res.stderr.strip()[-200:]}")

        # 3. crt.sh
        url = f"https://crt.sh/?q=%25.{d}&output=json"
        status, data = http_get_json(url, timeout=120)
        found_crt: list[str] = []
        if status == 200 and data is not None:
            crt_file = ctx.raw_dir / f"crtsh_{d}.json"
            crt_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "name_value" in item:
                        nv_raw = str(item["name_value"])
                        for name_line in nv_raw.splitlines():
                            _ct_note(name_line, item.get("not_before", ""))
                            nl = name_line.strip().lower()
                            if nl.startswith("*."):
                                nl = nl[2:]
                            if nl:
                                found_crt.append(nl)
                                all_raw_lines.append(nl)

        record_virtual_cmd(
            ctx.console_dir,
            "1",
            f"curl -s 'https://crt.sh/?q=%.{d}&output=json' | jq -r '.[].name_value'",
            f"HTTP {status} ({len(found_crt)} names)",
            title=f"crt.sh ({d})",
        )
        if status != 200:
            # crt.sh is often overloaded: fall back to SSLMate certspotter (keyless, rate limited)
            cs_names = _certspotter_names(d, _ct_note)
            all_raw_lines.extend(cs_names)
            record_virtual_cmd(
                ctx.console_dir,
                "1",
                f"curl -s 'https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names'",
                f"{len(cs_names)} names",
                title=f"certspotter ({d})",
            )
            if not cs_names:
                log.warn(f"crt.sh returned HTTP {status} and certspotter returned nothing for {d} (CT coverage relies on subfinder + amass)")

        # Always include d itself
        all_raw_lines.append(d)

    # Normalize to lowercase and filter strictly to names matching (^|\.)(domain1|domain2|...)$
    escaped_domains = [re.escape(dom.lower()) for dom in ctx.scope.domains]
    pattern = re.compile(rf"(^|\.)({'|'.join(escaped_domains)})$", re.IGNORECASE)

    subdomains = sorted(
        {
            line.strip().lower()
            for line in all_raw_lines
            if line.strip() and pattern.search(line.strip().lower())
        }
    )

    out_file = ctx.osint_dir / "subdomains.txt"
    out_file.write_text("".join(f"{s}\n" for s in subdomains), encoding="utf-8")

    subs_all_file = ctx.raw_dir / "subs_all.txt"
    subs_all_file.write_text("".join(f"{s}\n" for s in subdomains), encoding="utf-8")

    # Per-domain counts
    counts_lines: list[str] = []
    for d in ctx.scope.domains:
        d_re = re.compile(rf"(^|\.){re.escape(d.lower())}$", re.IGNORECASE)
        c = sum(1 for s in subdomains if d_re.search(s))
        counts_lines.append(f"{d} {c}\n")

    (ctx.osint_dir / "subdomain_counts.txt").write_text("".join(counts_lines), encoding="utf-8")
    # Wildcard CT queries are truncated on large domains; look up hash-like
    # hostnames (the "unguessable URL" pattern) one by one so they get a date.
    missing = [h for h in subdomains if is_hash_label(h) and h not in ct_first_seen][:60]
    for h in missing:
        st, data = http_get_json(f"https://crt.sh/?q={urllib.parse.quote(h)}&output=json", timeout=60)
        if st == 200 and isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for name_line in str(item.get("name_value", "")).splitlines():
                        _ct_note(name_line, item.get("not_before", ""))
        time.sleep(1.0)
    if missing:
        record_virtual_cmd(
            ctx.console_dir, "1", f"crt.sh exact lookups for {len(missing)} hash-like hostnames",
            f"{sum(1 for h in missing if h in ct_first_seen)} dated", title="crt.sh (hash-like hosts)",
        )
    (ctx.osint_dir / "ct_first_seen.tsv").write_text(
        "".join(f"{h}\t{ct_first_seen[h]}\n" for h in sorted(ct_first_seen) if pattern.search(h)),
        encoding="utf-8",
    )
    log.ok(f"{len(subdomains)} subdomains")

    # Diff against previous run
    if ctx.prev_run_dir is not None:
        prev_subs_file = ctx.prev_run_dir / "osint" / "subdomains.txt"
        if prev_subs_file.is_file():
            prev_subs = set(
                line.strip().lower()
                for line in prev_subs_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
            curr_subs = set(subdomains)
            new_subs = sorted(curr_subs - prev_subs)
            gone_subs = sorted(prev_subs - curr_subs)
            (ctx.osint_dir / "new_subdomains.txt").write_text(
                "".join(f"{s}\n" for s in new_subs), encoding="utf-8"
            )
            (ctx.osint_dir / "gone_subdomains.txt").write_text(
                "".join(f"{s}\n" for s in gone_subs), encoding="utf-8"
            )
            log.ok(f"vs {ctx.prev_run_dir.name}: {len(new_subs)} new, {len(gone_subs)} gone")


def _certspotter_names(domain: str, note, max_pages: int = 20) -> list[str]:
    """Hostnames for ``domain`` from SSLMate certspotter, recording first-seen dates."""
    names: list[str] = []
    after = ""
    for _ in range(max_pages):
        url = (
            f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
            f"&include_subdomains=true&expand=dns_names" + (f"&after={after}" if after else "")
        )
        st, data = http_get_json(url, timeout=60)
        if st != 200 or not isinstance(data, list) or not data:
            break
        for item in data:
            for n in item.get("dns_names") or []:
                n = str(n).strip().lower()
                if n.startswith("*."):
                    n = n[2:]
                if n:
                    names.append(n)
                    note(n, item.get("not_before", ""))
        after = str(data[-1].get("id", ""))
        if not after:
            break
    return names


def phase2(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 2 - DNS resolution, mail posture & target IP auto-discovery."""
    log.info("Phase 2 - DNS resolution, mail posture & target IP auto-discovery")
    ctx.ensure_dirs()

    subs_file = ctx.osint_dir / "subdomains.txt"
    if not subs_file.exists():
        subs_file.write_text("", encoding="utf-8")

    subdomains = [
        line.strip()
        for line in subs_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    re_ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    ip_host_pairs: list[tuple[str, str]] = []
    resolved_hosts: set[str] = set()
    cname_map: dict[str, list[str]] = {}

    if dm.is_available("dnsx"):
        cmd = dm.build_cmd(
            "dnsx",
            ["-l", str(subs_file), "-a", "-cname", "-resp", "-json", "-silent"],
        )
        res = ev(ctx.console_dir, "2", cmd, timeout=600, title="dnsx resolution")
        (ctx.raw_dir / "dnsx.json").write_text(res.stdout, encoding="utf-8")
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            host = obj.get("host", "")
            a_list = obj.get("a", [])
            cname_list = obj.get("cname") or []
            if host and cname_list:
                cname_map[host] = [str(c).strip() for c in cname_list if c]
            if host and a_list:
                for ip in a_list:
                    ip_str = str(ip).strip()
                    if re_ipv4.match(ip_str):
                        ip_host_pairs.append((ip_str, host))
                        resolved_hosts.add(host)
    else:
        for h in subdomains:
            cmd = dm.build_cmd("dig", ["+short", "A", h])
            res = run_cmd(cmd, timeout=10)
            for line in res.stdout.splitlines():
                ip_str = line.strip()
                if re_ipv4.match(ip_str):
                    ip_host_pairs.append((ip_str, h))
                    resolved_hosts.add(h)

    ip_host_pairs = sorted(set(ip_host_pairs))

    # Write ip_host.tsv
    with (ctx.osint_dir / "ip_host.tsv").open("w", encoding="utf-8") as f:
        for ip, host in ip_host_pairs:
            f.write(f"{ip}\t{host}\n")

    # Write resolved.txt
    sorted_resolved = sorted(resolved_hosts)
    with (ctx.osint_dir / "resolved.txt").open("w", encoding="utf-8") as f:
        for host in sorted_resolved:
            f.write(f"{host}\n")

    # Write ip_counts.txt
    ip_counts = collections.Counter(ip for ip, _ in ip_host_pairs)
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    with (ctx.osint_dir / "ip_counts.txt").open("w", encoding="utf-8") as f:
        for ip, count in sorted_ip_counts:
            f.write(f"{count:7d} {ip}\n")

    log.ok(f"{len(sorted_resolved)} resolving names on {len(sorted_ip_counts)} IPs")

    # Subdomain takeover: dangling CNAMEs pointing to unclaimed services or to
    # internal names that no longer resolve.
    def _resolves(name: str) -> bool:
        try:
            socket.getaddrinfo(name, None)
            return True
        except (socket.gaierror, UnicodeError, OSError):
            return False

    internal_suffixes = tuple(ctx.scope.domains)
    takeover_rows: list[str] = []
    for host, cnames in sorted(cname_map.items()):
        for cname in cnames:
            cand = check_takeover(
                host, cname,
                cname_resolves=_resolves(cname.rstrip(".")),
                http_get=http_get,
                internal_suffixes=internal_suffixes,
            )
            if cand is not None:
                takeover_rows.append(
                    f"{cand.host}\t{cand.cname}\t{cand.service}\t{cand.severity}\t{cand.reason}\t{cand.evidence}"
                )
                break  # one finding per host is enough
    (ctx.osint_dir / "takeover_candidates.tsv").write_text(
        "".join(f"{r}\n" for r in takeover_rows), encoding="utf-8"
    )
    if takeover_rows:
        log.warn(f"{len(takeover_rows)} possible subdomain takeover(s) in osint/takeover_candidates.tsv")

    # Clear apex.txt
    (ctx.osint_dir / "apex.txt").write_text("", encoding="utf-8")

    # Per domain checks
    for d in ctx.scope.domains:
        dns_sections: list[str] = []

        # 1. dig +short NS {d}
        cmd = dm.build_cmd("dig", ["+short", "NS", d])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short NS {d}", title=f"dig NS ({d})")
        dns_sections.append(f"$ dig +short NS {d}\n{res.stdout.rstrip()}")
        ns_list = [line.strip().rstrip(".") for line in res.stdout.splitlines() if line.strip()]

        # 2. dig +short MX {d}
        cmd = dm.build_cmd("dig", ["+short", "MX", d])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short MX {d}", title=f"dig MX ({d})")
        dns_sections.append(f"$ dig +short MX {d}\n{res.stdout.rstrip()}")

        # 3. dig +short TXT {d}
        cmd = dm.build_cmd("dig", ["+short", "TXT", d])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short TXT {d}", title=f"dig TXT ({d})")
        dns_sections.append(f"$ dig +short TXT {d}\n{res.stdout.rstrip()}")

        # 4. dig +short TXT _dmarc.{d}
        cmd = dm.build_cmd("dig", ["+short", "TXT", f"_dmarc.{d}"])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short TXT _dmarc.{d}", title=f"dig TXT _dmarc ({d})")
        dns_sections.append(f"$ dig +short TXT _dmarc.{d}\n{res.stdout.rstrip()}")

        # 5. dig +short CAA {d}
        cmd = dm.build_cmd("dig", ["+short", "CAA", d])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short CAA {d}", title=f"dig CAA ({d})")
        dns_sections.append(f"$ dig +short CAA {d}\n{res.stdout.rstrip()}")

        # 6. dig +short DNSKEY {d}
        cmd = dm.build_cmd("dig", ["+short", "DNSKEY", d])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short DNSKEY {d}", title=f"dig DNSKEY ({d})")
        dns_sections.append(f"$ dig +short DNSKEY {d}\n{res.stdout.rstrip()}")

        # 7. dig +short A {d}
        cmd = dm.build_cmd("dig", ["+short", "A", d])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short A {d}", title=f"dig A ({d})")
        dns_sections.append(f"$ dig +short A {d}\n{res.stdout.rstrip()}")
        apex_ips = sorted({line.strip() for line in res.stdout.splitlines() if re_ipv4.match(line.strip())})

        # 8. dig +short zzz<random>.{d}
        rand_sub = f"zzz{random.randint(10000, 999999)}.{d}"
        cmd = dm.build_cmd("dig", ["+short", rand_sub])
        res = ev(ctx.console_dir, "2", cmd, display_cmd=f"dig +short {rand_sub}", title=f"dig wildcard ({d})")
        dns_sections.append(f"$ dig +short {rand_sub}\n{res.stdout.rstrip()}")

        # AXFR per NS
        for ns in ns_list:
            cmd = dm.build_cmd("dig", ["AXFR", d, f"@{ns}", "+time=5", "+tries=1"])
            axfr_res = run_cmd(cmd, timeout=10)
            axfr_out = "AXFR ALLOWED" if "XFR size" in axfr_res.combined else "AXFR refused"
            record_virtual_cmd(
                ctx.console_dir,
                "2",
                f"dig AXFR {d} @{ns} +time=5 +tries=1",
                axfr_out,
                title=f"AXFR ({d} @{ns})",
            )
            dns_sections.append(f"$ dig AXFR {d} @{ns}\n{axfr_out}")

        # Write dns_{d}.txt
        dns_txt = "\n\n".join(dns_sections) + "\n"
        (ctx.osint_dir / f"dns_{d}.txt").write_text(dns_txt, encoding="utf-8")

        # Whois domain
        whois_cmd = dm.build_cmd("whois", [d])
        whois_res = ev(ctx.console_dir, "2", whois_cmd, title=f"whois ({d})")
        (ctx.raw_dir / f"whois_{d}.txt").write_text(whois_res.combined, encoding="utf-8")

        whois_re = re.compile(r"^(registrant|registrar:|name server|dnssec)", re.IGNORECASE)
        filtered_whois = [
            line for line in whois_res.combined.splitlines() if whois_re.search(line)
        ]
        (ctx.osint_dir / f"whois_{d}.txt").write_text(
            "\n".join(filtered_whois) + ("\n" if filtered_whois else ""), encoding="utf-8"
        )

        # Apex ownership
        with (ctx.osint_dir / "apex.txt").open("a", encoding="utf-8") as f:
            for ip in apex_ips:
                ptr_res = run_cmd(dm.build_cmd("dig", ["+short", "-x", ip]), timeout=10)
                ptr = ptr_res.stdout.splitlines()[0].strip() if ptr_res.stdout.splitlines() else ""
                whois_ip_res = run_cmd(dm.build_cmd("whois", [ip]), timeout=15)
                whois_ip_re = re.compile(r"^(netname|org-name|orgname|country):", re.IGNORECASE)
                whois_ip_lines = [
                    f"  {line.strip()}"
                    for line in whois_ip_res.combined.splitlines()
                    if whois_ip_re.search(line)
                ][:4]

                f.write(f"{d} apex {ip}\n")
                f.write(f"  ptr: {ptr}\n")
                for wl in whois_ip_lines:
                    f.write(f"{wl}\n")

    log.ok("DNS posture in osint/dns_*.txt, apex ownership in osint/apex.txt")

    # Target IP auto-discovery
    ip_to_hosts: dict[str, list[str]] = collections.defaultdict(list)
    for ip, host in ip_host_pairs:
        if host not in ip_to_hosts[ip]:
            ip_to_hosts[ip].append(host)

    discovered_targets: list[str] = []
    ip_orgs_lines: list[str] = []

    skip_re = None
    if ctx.scope.skip_portscan_orgs_regex and ctx.scope.skip_portscan_orgs_regex != r"^$":
        skip_re = re.compile(ctx.scope.skip_portscan_orgs_regex, re.IGNORECASE)
    guard = ScopeGuard(
        list(ctx.scope.exclude_ips) + list(ctx.scope.edge_ips),
        {},
        ctx.scope.owned_entries() if ctx.scope.ownership_enforced else None,
    )
    skipped_lines: list[str] = []

    for ip in sorted(ip_to_hosts.keys()):
        hosts = ip_to_hosts[ip]
        ptr_res = run_cmd(dm.build_cmd("dig", ["+short", "-x", ip]), timeout=10)
        ptr = ptr_res.stdout.splitlines()[0].strip() if ptr_res.stdout.splitlines() else ""

        # Collect every org/netname/descr line: ARIN lists NetName before OrgName,
        # so the first match alone misses providers such as Fastly or CloudFront.
        orgs: list[str] = []
        if dm.is_available("whois"):
            whois_res = run_cmd(dm.build_cmd("whois", [ip]), timeout=15)
            for line in whois_res.combined.splitlines():
                m = re.match(r"(?i)^(?:org-name|orgname|org|netname|descr|owner):\s*(.+)$", line.strip())
                if m and m.group(1).strip() not in orgs:
                    orgs.append(m.group(1).strip())
        org = "; ".join(orgs)

        hosts_sample = ",".join(hosts[:5])
        ip_orgs_lines.append(f"{ip}\t{org}\t{ptr}\t{hosts_sample}\n")

        if ctx.scope.auto_discover_targets:
            reason = ""
            if not guard.ip_allowed(ip):
                reason = "excluded/edge/non-public"
            elif skip_re is not None and (
                any(skip_re.search(o) for o in orgs) or (ptr and skip_re.search(ptr))
            ):
                reason = "cdn/saas org"
            elif not guard.is_owned(ip):
                reason = "not in owned_ranges (third-party hosting)"
            if reason:
                skipped_lines.append(f"{ip}\t{reason}\t{org}\t{ptr}\t{hosts_sample}\n")
                continue
            discovered_targets.append(ip)

    discovered_targets = sorted(set(discovered_targets))
    (ctx.osint_dir / "ip_orgs.tsv").write_text("".join(ip_orgs_lines), encoding="utf-8")
    (ctx.osint_dir / "skipped_targets.tsv").write_text("".join(skipped_lines), encoding="utf-8")
    (ctx.osint_dir / "discovered_targets.txt").write_text(
        "".join(f"{ip}\n" for ip in discovered_targets), encoding="utf-8"
    )

    summary_msg = (
        f"Auto-discovered {len(discovered_targets)} targets from {len(ip_to_hosts)} IPs "
        f"({len(ip_to_hosts) - len(discovered_targets)} skipped/excluded)"
    )
    record_virtual_cmd(
        ctx.console_dir,
        "2",
        "auto-discover-targets osint/ip_orgs.tsv",
        summary_msg,
        title="Target IP Auto-Discovery",
    )
    log.ok(f"Auto-discovered {len(discovered_targets)} targets in osint/discovered_targets.txt")


def phase6(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 6 - historical URLs (Wayback CDX) & potential entry points."""
    log.info("Phase 6 - historical URLs (Wayback CDX) & potential entry points")
    ctx.ensure_dirs()

    # TLDs that can never exist on the public internet (so never in the archive).
    non_public_tlds = {"local", "localhost", "internal", "lan", "home", "corp", "intranet", "test", "invalid", "example"}
    retry_delays = (0, 5, 15, 30)  # Wayback CDX returns transient 503s under load

    for d in ctx.scope.domains:
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in non_public_tlds:
            log.info(f"Wayback CDX for {d} skipped (non-public TLD, never archived)")
            continue

        url = f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=txt&fl=original&collapse=urlkey"
        resp = None
        for attempt, delay in enumerate(retry_delays, start=1):
            if delay:
                time.sleep(delay)
            resp = http_get(url, timeout=180)
            if resp.status == 200:
                break
            # 4xx (except 429) won't improve on retry
            if 400 <= resp.status < 500 and resp.status != 429:
                break
            log.warn(
                f"Wayback CDX for {d}: HTTP {resp.status or 'timeout/connection error'} "
                f"(attempt {attempt}/{len(retry_delays)})"
            )
        assert resp is not None
        (ctx.osint_dir / f"wayback_{d}.txt").write_text(resp.body if resp.status == 200 else "", encoding="utf-8")
        if resp.status != 200:
            log.warn(f"Wayback CDX for {d} failed (last status: {resp.status or 'timeout/connection error'})")
        elif not resp.body.strip():
            log.info(f"Wayback CDX for {d}: no archived URLs")

    all_urls: list[str] = []
    for d in ctx.scope.domains:
        p = ctx.osint_dir / f"wayback_{d}.txt"
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                u = line.strip()
                if u:
                    all_urls.append(u)

    unique_urls = sorted(set(all_urls))
    (ctx.osint_dir / "wayback_all.txt").write_text(
        "".join(f"{u}\n" for u in unique_urls), encoding="utf-8"
    )

    re_sensitive = re.compile(
        r"\.(env|sql|bak|old|key|pem|p12|pfx|json|config|conf|cfg|ya?ml|log|zip|tar|gz|7z|rar|csv|xlsx?|db|sqlite|git|svn|ps1|sh)(\?|$)",
        re.IGNORECASE,
    )
    sensitive_urls = [u for u in unique_urls if re_sensitive.search(u)]
    (ctx.osint_dir / "wayback_sensitive.txt").write_text(
        "".join(f"{u}\n" for u in sensitive_urls), encoding="utf-8"
    )

    re_critical = re.compile(
        r"\.(env|sql|bak|key|pem|p12|pfx|db|sqlite)(\?|$)|/\.git/",
        re.IGNORECASE,
    )
    critical_urls = [u for u in sensitive_urls if re_critical.search(u)]
    (ctx.osint_dir / "wayback_critical.txt").write_text(
        "".join(f"{u}\n" for u in critical_urls), encoding="utf-8"
    )

    # Identify Potential Entry Points
    idor_param_re = re.compile(
        r"(?:^|[?&])(id|user_id|userid|account|account_id|order|order_id|doc|invoice|profile|uid|uuid)=",
        re.IGNORECASE,
    )
    idor_path_re = re.compile(r"/api/v\d+/[a-z]+/\d+", re.IGNORECASE)
    lfi_re = re.compile(
        r"(?:^|[?&])(file|path|folder|dir|template|page|include|doc|load)=",
        re.IGNORECASE,
    )
    ssrf_re = re.compile(
        r"(?:^|[?&])(redirect|redirect_uri|next|url|return|return_to|dest|continue|callback|webhook)=",
        re.IGNORECASE,
    )
    sqli_re = re.compile(
        r"(?:^|[?&])(sort|order_by|filter|search|query|q|cat|category|where|table)=",
        re.IGNORECASE,
    )

    entry_points: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    # Static assets carry cache-busters (?id=, ?v=) that are not entry points
    static_re = re.compile(
        r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3)$",
        re.IGNORECASE,
    )

    for u in unique_urls:
        if len(entry_points) >= 200:
            break
        try:
            parsed = urllib.parse.urlsplit(u)
        except Exception:
            continue
        if static_re.search(parsed.path):
            continue

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        q_params = sorted(
            k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        )
        base_plus_params = f"{base_url}?{'&'.join(q_params)}" if q_params else base_url

        # Check IDOR/BOLA
        m_idor = idor_param_re.search(u)
        if m_idor:
            k = ("IDOR/BOLA candidate", base_plus_params)
            if k not in seen:
                seen.add(k)
                entry_points.append(("IDOR/BOLA candidate", m_idor.group(1), u))
                if len(entry_points) >= 200:
                    break
        else:
            m_path = idor_path_re.search(parsed.path)
            if m_path:
                rest_base = re.sub(r"/\d+", "/{id}", parsed.path)
                k = ("IDOR/BOLA candidate", f"{parsed.scheme}://{parsed.netloc}{rest_base}")
                if k not in seen:
                    seen.add(k)
                    entry_points.append(("IDOR/BOLA candidate", m_path.group(0), u))
                    if len(entry_points) >= 200:
                        break

        # Check LFI/Path
        m_lfi = lfi_re.search(u)
        if m_lfi:
            k = ("LFI/Path candidate", base_plus_params)
            if k not in seen:
                seen.add(k)
                entry_points.append(("LFI/Path candidate", m_lfi.group(1), u))
                if len(entry_points) >= 200:
                    break

        # Check Open Redirect/SSRF
        m_ssrf = ssrf_re.search(u)
        if m_ssrf:
            k = ("Open Redirect/SSRF candidate", base_plus_params)
            if k not in seen:
                seen.add(k)
                entry_points.append(("Open Redirect/SSRF candidate", m_ssrf.group(1), u))
                if len(entry_points) >= 200:
                    break

        # Check SQLi/Query
        m_sqli = sqli_re.search(u)
        if m_sqli:
            k = ("SQLi/Query candidate", base_plus_params)
            if k not in seen:
                seen.add(k)
                entry_points.append(("SQLi/Query candidate", m_sqli.group(1), u))
                if len(entry_points) >= 200:
                    break

    with (ctx.osint_dir / "entry_points.tsv").open("w", encoding="utf-8") as f:
        for cat, pat, sample in entry_points:
            f.write(f"{cat}\t{pat}\t{sample}\n")

    summary_text = (
        f"{len(unique_urls)} URLs, {len(sensitive_urls)} sensitive-extension, "
        f"{len(critical_urls)} critical, {len(entry_points)} potential entry points"
    )
    record_virtual_cmd(
        ctx.console_dir,
        "6",
        "wayback-cdx + entry-points",
        summary_text,
        title="Wayback CDX & Entry Points",
    )
    log.ok(f"Wayback: {summary_text}")


def phase7(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 7 - exposure DB lookup (Shodan) & CVE correlation."""
    log.info("Phase 7 - exposure DB lookup (Shodan) & CVE correlation")
    ctx.ensure_dirs()

    # Gather target IPs
    re_ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    candidate_ips: set[str] = set()

    for ip in ctx.scope.hvt_ips:
        if re_ipv4.match(ip.strip()):
            candidate_ips.add(ip.strip())
    for ip in ctx.scope.edge_ips:
        if re_ipv4.match(ip.strip()):
            candidate_ips.add(ip.strip())

    discovered_file = ctx.osint_dir / "discovered_targets.txt"
    if discovered_file.is_file():
        for line in discovered_file.read_text(encoding="utf-8").splitlines():
            ip = line.strip()
            if re_ipv4.match(ip):
                candidate_ips.add(ip)

    for pub_tsv in (ctx.azure_dir / "public_ips.tsv", ctx.gcp_dir / "public_ips.tsv"):
        if pub_tsv.is_file():
            for line in pub_tsv.read_text(encoding="utf-8").splitlines():
                parts = line.split("\t")
                if parts and re_ipv4.match(parts[0].strip()):
                    candidate_ips.add(parts[0].strip())

    apex_file = ctx.osint_dir / "apex.txt"
    if apex_file.is_file():
        for line in apex_file.read_text(encoding="utf-8").splitlines():
            m = re.search(r"apex\s+([0-9.]+)", line)
            if m and re_ipv4.match(m.group(1)):
                candidate_ips.add(m.group(1))

    target_ips = sorted(candidate_ips)

    # Part A: Shodan Host API (if ctx.shodan_api_key is set)
    shodan_file = ctx.osint_dir / "shodan_full.jsonl"
    if not shodan_file.exists():
        shodan_file.write_text("", encoding="utf-8")

    shodan_records: list[dict[str, Any]] = []
    if ctx.shodan_api_key:
        for ip in target_ips:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={ctx.shodan_api_key}"
            status, data = http_get_json(url, timeout=30)
            if status == 200 and isinstance(data, dict):
                data["_ip"] = ip
                shodan_records.append(data)
                with shodan_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(data) + "\n")
            time.sleep(1)

        masked_lines: list[str] = []
        for rec in shodan_records:
            masked_lines.append(
                json.dumps(
                    {
                        "ip": rec.get("_ip", ""),
                        "org": rec.get("org", ""),
                        "hostnames": rec.get("hostnames", []),
                        "ports": rec.get("ports", []),
                        "vulns": len(rec.get("vulns", [])),
                        "last_update": rec.get("last_update", ""),
                    }
                )
            )
        record_virtual_cmd(
            ctx.console_dir,
            "7",
            'curl -s "https://api.shodan.io/shodan/host/<ip>?key=***" | jq \'{ports, vulns:(.vulns|length)}\'',
            "\n".join(masked_lines),
            title="Shodan Host Lookups",
        )

    # Part B: Automated Nmap XML + Shodan CVE & CISA KEV Correlation
    services_found: list[dict[str, Any]] = []
    xml_candidates: list[Path] = []
    for d_path in (ctx.scan_dir, ctx.azure_dir, ctx.gcp_dir):
        if d_path.is_dir():
            xml_candidates.extend(sorted(d_path.glob("*.xml")))

    for xml_path in xml_candidates:
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception:
            continue

        for host in root.findall("host"):
            ip_found = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip_found = addr.get("addr", "")
                    break
            if not ip_found or not re_ipv4.match(ip_found):
                continue

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_id = port.get("portid", "")
                    srv = port.find("service")
                    if srv is not None:
                        s_name = srv.get("name", "")
                        prod = srv.get("product", "")
                        ver = srv.get("version", "")
                        cpes = [
                            c.text.strip()
                            for c in (srv.findall("cpe") + port.findall("cpe"))
                            if c.text and c.text.strip()
                        ]
                        services_found.append(
                            {
                                "ip": ip_found,
                                "port": port_id,
                                "service": s_name,
                                "version": f"{prod} {ver}".strip(),
                                "cpes": cpes,
                            }
                        )

    # Cache for CVEDB queries
    cpe_cache: dict[str, list[dict[str, Any]]] = {}
    cve_cache: dict[str, dict[str, Any]] = {}
    # CVEDB (*.shodan.io) is often blocked by egress firewalls; fall back to NVD.
    cve_source = {"name": "cvedb", "down": False}

    def fetch_cve(cve_id: str) -> dict[str, Any]:
        if cve_id in cve_cache:
            return cve_cache[cve_id]
        cve_url = f"https://cvedb.shodan.io/cve/{cve_id}"
        st, data = http_get_json(cve_url, timeout=15)
        res_info = {
            "cvss": "",
            "is_kev": False,
            "summary": "",
        }
        if st == 200 and isinstance(data, dict):
            cvss_val = data.get("cvss") if data.get("cvss") is not None else data.get("cvss_v3")
            res_info["cvss"] = str(cvss_val) if cvss_val is not None else ""
            res_info["is_kev"] = bool(data.get("kev") or False)
            res_info["summary"] = str(data.get("summary") or "").strip()
        cve_cache[cve_id] = res_info
        return res_info

    def fetch_cpe_cves(cpe: str) -> list[dict[str, Any]]:
        cpe_full = cpe_to_23(cpe)
        if cpe_full is None:
            return []
        cpe_clean = cpe.strip()
        if cpe_clean.startswith("cpe:/"):
            parts = cpe_clean[len("cpe:/") :].split(":")
            if len(parts) >= 3:
                cpe23 = f"cpe:2.3:{':'.join(parts)}"
            else:
                cpe23 = cpe_clean
        else:
            cpe23 = cpe_clean

        if cpe23 in cpe_cache:
            return cpe_cache[cpe23]

        items: list[dict[str, Any]] = []
        st, data = 0, None
        if not cve_source["down"]:
            url = f"https://cvedb.shodan.io/cves?cpe23={urllib.parse.quote(cpe23)}"
            st, data = http_get_json(url, timeout=15)
            if st == 0 or st == 403 or st >= 500:
                cve_source.update(name="nvd", down=True)
                log.warn("Shodan CVEDB unreachable - falling back to NVD API (set NVD_API_KEY to speed it up)")
        if cve_source["down"]:
            nvd_st, items = nvd_cves_for_cpe(cpe_full)
            if nvd_st != 200:
                log.warn(f"NVD lookup failed for {cpe_full} (HTTP {nvd_st})")
            cpe_cache[cpe23] = items
            return items
        if st == 200 and data is not None:
            raw_cves = (
                data.get("cves")
                if isinstance(data, dict)
                else (data if isinstance(data, list) else [])
            )
            if isinstance(raw_cves, list):
                for item in raw_cves:
                    if isinstance(item, dict):
                        cid = item.get("cve_id") or item.get("cve") or item.get("id") or ""
                        cvss_val = (
                            item.get("cvss")
                            if item.get("cvss") is not None
                            else item.get("cvss_v3")
                        )
                        is_kev = bool(item.get("kev") or item.get("is_kev") or False)
                        summ = str(item.get("summary") or item.get("description") or "").strip()
                        if cid:
                            items.append(
                                {
                                    "cve_id": str(cid),
                                    "cvss": str(cvss_val) if cvss_val is not None else "",
                                    "is_kev": is_kev,
                                    "summary": summ,
                                }
                            )
                    elif isinstance(item, str) and item.strip():
                        cid = item.strip()
                        c_info = fetch_cve(cid)
                        items.append(
                            {
                                "cve_id": cid,
                                "cvss": c_info["cvss"],
                                "is_kev": c_info["is_kev"],
                                "summary": c_info["summary"],
                            }
                        )

        cpe_cache[cpe23] = items
        return items

    # Collect CVE findings
    findings: list[dict[str, Any]] = []

    for srv in services_found:
        for cpe in srv["cpes"]:
            cve_items = fetch_cpe_cves(cpe)
            for c_item in cve_items:
                findings.append(
                    {
                        "ip": srv["ip"],
                        "port": srv["port"],
                        "service": srv["service"],
                        "version": srv["version"],
                        "cve": c_item["cve_id"],
                        "cvss": c_item["cvss"],
                        "is_kev": c_item["is_kev"],
                        "summary": c_item["summary"],
                    }
                )

    # Merge CVEs from shodan_full.jsonl
    if shodan_file.is_file():
        for line in shodan_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ip_val = rec.get("_ip") or rec.get("ip_str") or ""
            vulns = rec.get("vulns", [])
            if not ip_val:
                continue
            if isinstance(vulns, list):
                for cve_id in vulns:
                    cve_id_str = str(cve_id).strip()
                    if not cve_id_str:
                        continue
                    c_info = fetch_cve(cve_id_str)
                    findings.append(
                        {
                            "ip": ip_val,
                            "port": "shodan",
                            "service": "shodan",
                            "version": "",
                            "cve": cve_id_str,
                            "cvss": c_info["cvss"],
                            "is_kev": c_info["is_kev"],
                            "summary": c_info["summary"],
                        }
                    )
            elif isinstance(vulns, dict):
                for cve_id, vdata in vulns.items():
                    cve_id_str = str(cve_id).strip()
                    if not cve_id_str:
                        continue
                    if isinstance(vdata, dict) and ("cvss" in vdata or "summary" in vdata):
                        cvss_val = (
                            vdata.get("cvss")
                            if vdata.get("cvss") is not None
                            else vdata.get("cvss_v3")
                        )
                        findings.append(
                            {
                                "ip": ip_val,
                                "port": "shodan",
                                "service": "shodan",
                                "version": "",
                                "cve": cve_id_str,
                                "cvss": str(cvss_val) if cvss_val is not None else "",
                                "is_kev": bool(vdata.get("kev") or False),
                                "summary": str(vdata.get("summary") or ""),
                            }
                        )
                    else:
                        c_info = fetch_cve(cve_id_str)
                        findings.append(
                            {
                                "ip": ip_val,
                                "port": "shodan",
                                "service": "shodan",
                                "version": "",
                                "cve": cve_id_str,
                                "cvss": c_info["cvss"],
                                "is_kev": c_info["is_kev"],
                                "summary": c_info["summary"],
                            }
                        )

    kev_ids = load_kev_ids()
    if kev_ids:
        for f in findings:
            if f["cve"] in kev_ids:
                f["is_kev"] = True
    else:
        log.warn("CISA KEV catalogue unreachable - KEV flags rely on CVEDB data only")

    # Deduplicate findings by (ip, port, cve)
    seen_f: set[tuple[str, str, str]] = set()
    unique_findings: list[dict[str, Any]] = []
    for f in findings:
        k = (f["ip"], str(f["port"]), f["cve"])
        if k not in seen_f:
            seen_f.add(k)
            unique_findings.append(f)

    # Write osint/service_cves.tsv
    header = "ip\tport\tservice\tversion\tcve\tcvss\tis_kev\tsummary\n"
    tsv_lines = [header]
    for f in unique_findings:
        clean_sum = (
            f["summary"].replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()
        )
        tsv_lines.append(
            f"{f['ip']}\t{f['port']}\t{f['service']}\t{f['version']}\t{f['cve']}\t{f['cvss']}\t{f['is_kev']}\t{clean_sum}\n"
        )
    (ctx.osint_dir / "service_cves.tsv").write_text("".join(tsv_lines), encoding="utf-8")

    # Write azure/cve_cvss.csv and azure/cve_summary.txt
    seen_ip_cve: set[tuple[str, str]] = set()
    cve_cvss_rows: list[dict[str, str]] = []
    for f in unique_findings:
        k = (f["ip"], f["cve"])
        if k not in seen_ip_cve:
            seen_ip_cve.add(k)
            cve_cvss_rows.append({"ip": f["ip"], "cve": f["cve"], "cvss": str(f["cvss"])})

    csv_lines = ["ip,cve,cvss\n"]
    for r in cve_cvss_rows:
        csv_lines.append(f"{r['ip']},{r['cve']},{r['cvss']}\n")
    (ctx.azure_dir / "cve_cvss.csv").write_text("".join(csv_lines), encoding="utf-8")

    # Replicate original cve_summary.txt logic
    by_ip: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for r in cve_cvss_rows:
        by_ip[r["ip"]].append(r)

    total_unique_cves = len({r["cve"] for r in cve_cvss_rows})
    cves_with_cvss = len({r["cve"] for r in cve_cvss_rows if r.get("cvss")})

    summary_lines = [
        f"{total_unique_cves} unique CVEs, {cves_with_cvss} with CVSS"
    ]

    def _max_score(rs: list[dict[str, str]]) -> float:
        scores: list[float] = []
        for r in rs:
            val = r.get("cvss", "")
            try:
                scores.append(float(val))
            except (ValueError, TypeError):
                pass
        return max(scores) if scores else 0.0

    for ip, rs in sorted(by_ip.items(), key=lambda kv: -_max_score(kv[1])):
        scored: list[dict[str, str]] = []
        for r in rs:
            val = r.get("cvss", "")
            try:
                float(val)
                scored.append(r)
            except (ValueError, TypeError):
                pass
        scored.sort(key=lambda r: -float(r["cvss"]))
        top = ", ".join(f"{r['cve']} ({r['cvss']})" for r in scored[:5])
        max_str = scored[0]["cvss"] if scored else "-"
        summary_lines.append(f"{ip}\t{len(rs)} / {len(scored)}\tmax {max_str}\t{top}")

    summary_text = "\n".join(summary_lines) + "\n"
    (ctx.azure_dir / "cve_summary.txt").write_text(summary_text, encoding="utf-8")

    record_virtual_cmd(
        ctx.console_dir,
        "7",
        f"cve-lookup --from-nmap-xml --source {cve_source['name']} --kev cisa",
        summary_text.strip(),
        title="CVE & CISA KEV Correlation",
    )
    log.ok(
        f"CVE correlation: {total_unique_cves} unique CVEs; summary in azure/cve_summary.txt and osint/service_cves.tsv"
    )


def check_pwned_password(password: str, timeout: float = 10.0) -> int:
    """Check if a password has been compromised in data breaches using HaveIBeenPwned's free API.

    Reference: https://api.pwnedpasswords.com/range/{prefix} (Zero API key required).
    Uses a k-anonymity model: computes SHA-1 and sends only the first 5 hex characters.
    Returns the count of times the password was seen in public data breaches (0 if clean).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = http_get(
        url,
        headers={"User-Agent": "Scylax/1.0", "Add-Padding": "true"},
        timeout=timeout,
    )
    if resp.status == 200 and resp.body:
        for line in resp.body.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 2 and parts[0].upper() == suffix:
                try:
                    return int(parts[1])
                except ValueError:
                    return 1
    return 0


def run_email_enumeration(ctx: RunContext, dm: DependencyManager, log: Logger) -> list[str]:
    """Discover corporate email addresses for in-scope domains using theHarvester, amass, spiderfoot, and passive OSINT."""
    log.info("Phase 9 - corporate email enumeration (theHarvester, amass, spiderfoot, PGP & passive sources)")
    ctx.ensure_dirs()

    discovered_emails: set[str] = set()
    email_sources: list[tuple[str, str, str]] = []

    # 1. theHarvester (if available natively or in Docker)
    if dm.is_available("theharvester"):
        for d in ctx.scope.domains:
            cmd = dm.build_cmd("theharvester", ["-d", d, "-b", "all", "-l", "200"])
            res = ev(ctx.console_dir, "9", cmd, timeout=180, title=f"theHarvester ({d})")
            re_domain_email = re.compile(
                rf"[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)*{re.escape(d)}", re.IGNORECASE
            )
            for m in re_domain_email.finditer(res.stdout):
                em = m.group(0).lower().strip()
                if em and not em.startswith(("abuse@", "noc@", "hostmaster@", "postmaster@")):
                    if em not in discovered_emails:
                        discovered_emails.add(em)
                        email_sources.append((em, d, "theHarvester"))

    # 2. Amass intel / contact enumeration (if available)
    if dm.is_available("amass") and ctx.scope.use_amass:
        for d in ctx.scope.domains:
            # Amass contact/whois intel
            cmd = dm.build_cmd("amass", ["intel", "-whois", "-d", d])
            res = ev(ctx.console_dir, "9", cmd, timeout=120, title=f"amass intel emails ({d})")
            re_amass_email = re.compile(
                rf"[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)*{re.escape(d)}", re.IGNORECASE
            )
            for m in re_amass_email.finditer(res.stdout):
                em = m.group(0).lower().strip()
                if em and not em.startswith(("abuse@", "noc@", "hostmaster@")):
                    if em not in discovered_emails:
                        discovered_emails.add(em)
                        email_sources.append((em, d, "amass"))

    # 3. SpiderFoot CLI (if available)
    if dm.is_available("spiderfoot"):
        for d in ctx.scope.domains:
            cmd = dm.build_cmd("spiderfoot", ["-s", d, "-m", "sfp_hunter,sfp_pgp,sfp_whois,sfp_email", "-u", "cli"])
            res = ev(ctx.console_dir, "9", cmd, timeout=180, title=f"spiderfoot emails ({d})")
            re_sf_email = re.compile(
                rf"[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)*{re.escape(d)}", re.IGNORECASE
            )
            for m in re_sf_email.finditer(res.stdout):
                em = m.group(0).lower().strip()
                if em and em not in discovered_emails:
                    discovered_emails.add(em)
                    email_sources.append((em, d, "spiderfoot"))

    # 4. Passive search from Public PGP Key Server (Ubuntu keyserver HTTP interface)
    for d in ctx.scope.domains:
        url = f"https://keyserver.ubuntu.com/pks/lookup?search={urllib.parse.quote(d)}&op=index"
        resp = http_get(url, timeout=15.0)
        pgp_found: list[str] = []
        if resp.status == 200 and resp.body:
            re_pgp = re.compile(
                rf"[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)*{re.escape(d)}", re.IGNORECASE
            )
            for m in re_pgp.finditer(resp.body):
                em = m.group(0).lower().strip()
                if em and em not in discovered_emails:
                    discovered_emails.add(em)
                    email_sources.append((em, d, "pgp_keyserver"))
                    pgp_found.append(em)
        record_virtual_cmd(
            ctx.console_dir,
            "9",
            f"curl -s '{url}' | grep -iE '@{d}'",
            f"Discovered {len(pgp_found)} email(s) via Ubuntu PGP keyserver",
            title=f"PGP keyserver email lookup ({d})",
        )

    # 5. Passive extraction from WHOIS text files (Phase 2 output)
    for d in ctx.scope.domains:
        whois_file = ctx.raw_dir / f"whois_{d}.txt"
        if whois_file.is_file():
            text = whois_file.read_text(encoding="utf-8", errors="replace")
            re_whois = re.compile(
                rf"[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)*{re.escape(d)}", re.IGNORECASE
            )
            for m in re_whois.finditer(text):
                em = m.group(0).lower().strip()
                if em and not re.search(r"privacy|redact|proxy|domainprotect|whoisguard", em):
                    if em not in discovered_emails:
                        discovered_emails.add(em)
                        email_sources.append((em, d, "whois"))

    # 6. Passive extraction from Wayback CDX URLs (Phase 6 output)
    wb_file = ctx.osint_dir / "wayback_all.txt"
    if wb_file.is_file():
        wb_text = wb_file.read_text(encoding="utf-8", errors="replace")
        for d in ctx.scope.domains:
            re_wb = re.compile(
                rf"[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)*{re.escape(d)}", re.IGNORECASE
            )
            for m in re_wb.finditer(wb_text):
                em = m.group(0).lower().strip()
                if em and em not in discovered_emails:
                    discovered_emails.add(em)
                    email_sources.append((em, d, "wayback"))

    sorted_emails = sorted(discovered_emails)
    (ctx.osint_dir / "emails.txt").write_text(
        "\n".join(sorted_emails) + ("\n" if sorted_emails else ""), encoding="utf-8"
    )

    tsv_lines = ["email\tdomain\tsource\n"]
    for em, dom, src in sorted(email_sources, key=lambda x: (x[1], x[0])):
        tsv_lines.append(f"{em}\t{dom}\t{src}\n")
    (ctx.osint_dir / "emails.tsv").write_text("".join(tsv_lines), encoding="utf-8")

    log.ok(f"Email enumeration: {len(sorted_emails)} corporate email(s) discovered across in-scope domains")
    return sorted_emails


_HIBP_BREACH_CACHE: dict[str, dict[str, Any] | None] = {}


def _hibp_breach_details(name: str) -> dict[str, Any] | None:
    """Fetch public breach metadata (DataClasses, dates) from HIBP's free catalogue."""
    if name in _HIBP_BREACH_CACHE:
        return _HIBP_BREACH_CACHE[name]
    url = f"https://haveibeenpwned.com/api/v3/breach/{urllib.parse.quote(name)}"
    status, data = http_get_json(url, headers={"User-Agent": "Scylax/1.0"}, timeout=20.0)
    details = data if status == 200 and isinstance(data, dict) else None
    _HIBP_BREACH_CACHE[name] = details
    return details


BREACH_RETRY_WAIT = 30.0
BREACH_RETRIES = 2


def _breach_lookup(
    log: Logger,
    service: str,
    em: str,
    url: str,
    headers: dict[str, str],
) -> tuple[int, Any]:
    """GET a per-account breach API, retrying failures (rate limit, 5xx, timeout).

    200 and 404 are answers ("breached" / "not breached"); anything else is
    retried after BREACH_RETRY_WAIT seconds, up to BREACH_RETRIES times.
    """
    status, data = http_get_json(url, headers=headers, timeout=20.0)
    for attempt in range(1, BREACH_RETRIES + 1):
        if status in (200, 404):
            break
        log.info(f"{service} lookup for {em} returned HTTP {status}; retry {attempt}/{BREACH_RETRIES} in {BREACH_RETRY_WAIT:.0f}s")
        time.sleep(BREACH_RETRY_WAIT)
        status, data = http_get_json(url, headers=headers, timeout=20.0)
    return status, data


def _xposedornot_account_breaches(
    ctx: RunContext,
    log: Logger,
    emails: list[str],
) -> list[dict[str, Any]]:
    """Check accounts with the free XposedOrNot API (no key; about 1 request per second).

    XposedOrNot returns breach names only, so each name is enriched with HIBP's public
    breach catalogue when the same breach exists there.
    """
    results: list[dict[str, Any]] = []
    for em in emails:
        time.sleep(1.1)
        url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(em)}"
        status, data = _breach_lookup(log, "XposedOrNot", em, url, {"User-Agent": "Scylax/1.0"})
        display_cmd = f"curl -s '{url}'"
        if status == 404:
            record_virtual_cmd(
                ctx.console_dir, "9", display_cmd,
                f"HTTP 404: No breach records for {em}",
                title=f"XposedOrNot account breaches ({em})",
            )
            continue
        if status != 200 or not isinstance(data, dict):
            log.warn(f"XposedOrNot lookup for {em} returned HTTP {status} after {BREACH_RETRIES} retries")
            record_virtual_cmd(
                ctx.console_dir, "9", display_cmd, f"HTTP {status}",
                title=f"XposedOrNot account breaches ({em})", returncode=1,
            )
            continue
        record_virtual_cmd(
            ctx.console_dir, "9", display_cmd, json.dumps(data, indent=2),
            title=f"XposedOrNot account breaches ({em})",
        )
        raw = data.get("breaches") or []
        # The free API returns [["BreachA", "BreachB"]]; accept a flat list too.
        names: list[str] = []
        for item in raw:
            if isinstance(item, list):
                names.extend(str(x) for x in item if x)
            elif item:
                names.append(str(item))
        for name in dict.fromkeys(names):
            d = _hibp_breach_details(name) or {}
            classes = d.get("DataClasses") or []
            results.append(
                {
                    "email": em,
                    "name": name,
                    "title": str(d.get("Title") or name),
                    "breach_date": str(d.get("BreachDate") or ""),
                    "pwn_count": str(d.get("PwnCount") or "0"),
                    "data_classes": ";".join(str(c) for c in classes) if isinstance(classes, list) else str(classes),
                    "is_verified": str(bool(d.get("IsVerified", False))),
                    "is_sensitive": str(bool(d.get("IsSensitive", False))),
                }
            )
    return results


def run_hibp_breaches(
    ctx: RunContext,
    log: Logger,
    emails: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Query HaveIBeenPwned API for domain breach history and compromised corporate accounts."""
    api_key = (ctx.hibp_api_key or os.environ.get("HIBP_API_KEY", "")).strip()
    log.info("Checking HaveIBeenPwned domain & corporate account breach exposure")
    domain_breaches: list[dict[str, Any]] = []
    account_breaches: list[dict[str, Any]] = []
    # The breach catalogue (/breaches?domain=, /breach/{name}) is public; only per-account lookups need a key.
    headers = {"User-Agent": "Scylax/1.0"}
    if api_key:
        headers["hibp-api-key"] = api_key
    key_hdr = " -H 'hibp-api-key: [REDACTED]'" if api_key else ""

    # 1. Domain breaches
    for i, d in enumerate(ctx.scope.domains):
        if i > 0:
            time.sleep(1.6)  # HIBP enforces 1 request per 1.5s rate limit
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={urllib.parse.quote(d)}"
        status, data = http_get_json(url, headers=headers, timeout=20.0)

        display_cmd = f"curl -s{key_hdr} '{url}'"
        if status == 200 and isinstance(data, list):
            record_virtual_cmd(
                ctx.console_dir,
                "9",
                display_cmd,
                json.dumps(data, indent=2),
                title=f"HIBP domain breaches ({d})",
            )
            raw_path = ctx.osint_dir / f"hibp_{d}.json"
            raw_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            for b in data:
                if isinstance(b, dict):
                    data_classes = b.get("DataClasses") or []
                    dc_str = (
                        ";".join(str(c) for c in data_classes)
                        if isinstance(data_classes, list)
                        else str(data_classes)
                    )
                    domain_breaches.append(
                        {
                            "domain": d,
                            "name": str(b.get("Name") or ""),
                            "title": str(b.get("Title") or b.get("Name") or ""),
                            "breach_date": str(b.get("BreachDate") or ""),
                            "pwn_count": str(b.get("PwnCount") or "0"),
                            "data_classes": dc_str,
                            "is_verified": str(bool(b.get("IsVerified", False))),
                            "is_sensitive": str(bool(b.get("IsSensitive", False))),
                        }
                    )
        elif status == 404:
            record_virtual_cmd(
                ctx.console_dir,
                "9",
                display_cmd,
                "HTTP 404: No breaches found for domain",
                title=f"HIBP domain breaches ({d})",
            )
        else:
            log.warn(f"HIBP domain query for {d} returned HTTP {status}")
            record_virtual_cmd(
                ctx.console_dir,
                "9",
                display_cmd,
                f"HTTP {status}",
                title=f"HIBP domain breaches ({d})",
                returncode=1,
            )

    tsv_path = ctx.osint_dir / "hibp_breaches.tsv"
    tsv_lines = ["domain\tname\ttitle\tbreach_date\tpwn_count\tdata_classes\tis_verified\tis_sensitive\n"]
    for b in domain_breaches:
        tsv_lines.append(
            f"{b['domain']}\t{b['name']}\t{b['title']}\t{b['breach_date']}\t{b['pwn_count']}\t{b['data_classes']}\t{b['is_verified']}\t{b['is_sensitive']}\n"
        )
    tsv_path.write_text("".join(tsv_lines), encoding="utf-8")

    # 2. Account breaches (for discovered corporate emails)
    target_emails = emails
    if target_emails is None:
        emails_file = ctx.osint_dir / "emails.txt"
        target_emails = (
            [l.strip() for l in emails_file.read_text(encoding="utf-8").splitlines() if l.strip()]
            if emails_file.is_file()
            else []
        )

    if api_key:
        log.info(f"Checking {min(len(target_emails), 50)} corporate account(s) against HaveIBeenPwned")
        for em in target_emails[:50]:
            time.sleep(1.6)  # HIBP enforces 1 request per 1.5s rate limit
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(em)}?truncateResponse=false"
            status, data = _breach_lookup(log, "HIBP", em, url, headers)
            display_cmd = f"curl -s{key_hdr} '{url}'"

            if status == 200 and isinstance(data, list):
                record_virtual_cmd(
                    ctx.console_dir,
                    "9",
                    display_cmd,
                    json.dumps(data, indent=2),
                    title=f"HIBP account breaches ({em})",
                )
                raw_acc_path = ctx.osint_dir / f"hibp_account_{re.sub(r'[^a-zA-Z0-9_.-]', '_', em)}.json"
                raw_acc_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                for b in data:
                    if isinstance(b, dict):
                        data_classes = b.get("DataClasses") or []
                        dc_str = (
                            ";".join(str(c) for c in data_classes)
                            if isinstance(data_classes, list)
                            else str(data_classes)
                        )
                        account_breaches.append(
                            {
                                "email": em,
                                "name": str(b.get("Name") or ""),
                                "title": str(b.get("Title") or b.get("Name") or ""),
                                "breach_date": str(b.get("BreachDate") or ""),
                                "pwn_count": str(b.get("PwnCount") or "0"),
                                "data_classes": dc_str,
                                "is_verified": str(bool(b.get("IsVerified", False))),
                                "is_sensitive": str(bool(b.get("IsSensitive", False))),
                            }
                        )
            elif status == 404:
                record_virtual_cmd(
                    ctx.console_dir,
                    "9",
                    display_cmd,
                    f"HTTP 404: No breach records for {em}",
                    title=f"HIBP account breaches ({em})",
                )
            else:
                log.warn(f"HIBP account lookup for {em} returned HTTP {status} after {BREACH_RETRIES} retries")
                record_virtual_cmd(
                    ctx.console_dir,
                    "9",
                    display_cmd,
                    f"HTTP {status}",
                    title=f"HIBP account breaches ({em})",
                    returncode=1,
                )

    elif target_emails:
        log.info(
            "HIBP API key not set - checking corporate accounts against the free XposedOrNot API instead"
        )
        account_breaches.extend(_xposedornot_account_breaches(ctx, log, target_emails[:50]))

    acc_tsv_path = ctx.osint_dir / "hibp_account_breaches.tsv"
    acc_tsv_lines = ["email\tname\ttitle\tbreach_date\tpwn_count\tdata_classes\tis_verified\tis_sensitive\n"]
    for b in account_breaches:
        acc_tsv_lines.append(
            f"{b['email']}\t{b['name']}\t{b['title']}\t{b['breach_date']}\t{b['pwn_count']}\t{b['data_classes']}\t{b['is_verified']}\t{b['is_sensitive']}\n"
        )
    acc_tsv_path.write_text("".join(acc_tsv_lines), encoding="utf-8")

    log.ok(
        f"HIBP audit complete: {len(domain_breaches)} domain breach incident(s), "
        f"{len(account_breaches)} compromised corporate account incident(s)"
    )
    return domain_breaches, account_breaches


MAX_REPOS_TO_SCAN = 30


def _scan_public_repos(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Scan the GitHub organization's public repos for leaked secrets.

    Prefers gitleaks (lighter: a shallow clone's working tree) and falls back to
    TruffleHog (remote git history, verified secrets only). Writes
    osint/secret_leaks.tsv. Skipped silently when no org or no scanner is set."""
    org = os.environ.get("GITHUB_ORG", "").strip()
    if not org or not dm.is_available("gh"):
        return
    use_gitleaks = dm.is_available("gitleaks")
    use_trufflehog = dm.is_available("trufflehog")
    if not (use_gitleaks or use_trufflehog):
        return
    if run_cmd(dm.build_cmd("gh", ["auth", "status"]), timeout=10).returncode != 0:
        return

    repos_res = ev(
        ctx.console_dir, "9",
        dm.build_cmd("gh", ["api", "--paginate",
                            f"/orgs/{org}/repos?type=public&per_page=100"]),
        timeout=120, title=f"list public repos ({org})",
    )
    try:
        data = _parse_json_stream_osint(repos_res.stdout)
    except Exception:
        data = None
    repos = [
        r for r in (data or [])
        if isinstance(r, dict) and not r.get("archived") and not r.get("fork")
        and r.get("clone_url")
    ]
    if not repos:
        return
    repos.sort(key=lambda r: str(r.get("pushed_at") or ""), reverse=True)
    capped = repos[:MAX_REPOS_TO_SCAN]
    scanner = "gitleaks" if use_gitleaks else "trufflehog"
    log.info(f"Secret scan: {scanner} over {len(capped)} public repo(s) of {org}"
             + (f" (capped from {len(repos)})" if len(repos) > MAX_REPOS_TO_SCAN else ""))

    rows: list[str] = []
    import tempfile
    for repo in capped:
        name = str(repo.get("name"))
        clone_url = str(repo.get("clone_url"))
        if use_gitleaks:
            with tempfile.TemporaryDirectory() as td:
                clone = run_cmd(["git", "clone", "--depth", "1", "--quiet", clone_url, td], timeout=180)
                if clone.returncode != 0:
                    record_tool_failure(ctx.run_dir, "9", "git", f"clone {name} failed")
                    continue
                report = Path(td) / "_gitleaks.json"
                res = ev(
                    ctx.console_dir, "9",
                    dm.build_cmd("gitleaks", ["dir", td, "--report-format", "json",
                                              "--report-path", str(report), "--exit-code", "0"]),
                    timeout=300, title=f"gitleaks {name}",
                )
                if report.is_file():
                    try:
                        for item in json.loads(report.read_text(encoding="utf-8", errors="replace")) or []:
                            loc = f"{item.get('File', '?')}:{item.get('StartLine', '?')}"
                            rows.append(f"{name}\t{loc}\t{item.get('RuleID', 'secret')}\tunverified")
                    except Exception:
                        pass
        else:
            res = ev(
                ctx.console_dir, "9",
                dm.build_cmd("trufflehog", ["git", clone_url, "--only-verified", "--json", "--no-update"]),
                timeout=300, title=f"trufflehog {name}",
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                git = ((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {}
                loc = f"{git.get('file', '?')}@{str(git.get('commit', ''))[:10]}"
                rows.append(f"{name}\t{loc}\t{obj.get('DetectorName', 'secret')}\tverified")

    (ctx.osint_dir / "secret_leaks.tsv").write_text("".join(f"{r}\n" for r in rows), encoding="utf-8")
    if rows:
        log.warn(f"{len(rows)} potential secret(s) in public repos - osint/secret_leaks.tsv")
    else:
        log.ok(f"Secret scan: no secrets found in {len(capped)} public repo(s)")


def _parse_json_stream_osint(raw: str) -> Any:
    """Parse one or more concatenated JSON values (gh --paginate), flattening lists."""
    raw = (raw or "").strip()
    if not raw:
        return None
    dec = json.JSONDecoder()
    pos, out = 0, []
    while pos < len(raw):
        while pos < len(raw) and raw[pos].isspace():
            pos += 1
        if pos >= len(raw):
            break
        try:
            obj, pos = dec.raw_decode(raw, pos)
        except json.JSONDecodeError:
            break
        out.append(obj)
    if len(out) == 1:
        return out[0]
    flat: list[Any] = []
    for o in out:
        flat.extend(o if isinstance(o, list) else [o])
    return flat


def phase9(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase 9 - secret scanning, email enumeration & breach intelligence."""
    log.info("Phase 9 - secret scanning, email enumeration & breach intelligence")
    ctx.ensure_dirs()

    domain_searches = "\n".join(
        f"  gh search code '{d}' --limit 100" for d in ctx.scope.domains
    )
    todo_content = f"""Internal Git repositories may not be reachable from the assessment host. Run over a local clone or repository filesystem:

  docker run --rm -v "$PWD:/pwd" trufflesecurity/trufflehog:latest filesystem /pwd --only-verified

Public GitHub code search (after gh auth login):
{domain_searches}
"""
    (ctx.osint_dir / "secrets_TODO.txt").write_text(todo_content, encoding="utf-8")

    if dm.is_available("gh"):
        auth_res = run_cmd(dm.build_cmd("gh", ["auth", "status"]), timeout=10)
        if auth_res.returncode == 0:
            for d in ctx.scope.domains:
                ev(
                    ctx.console_dir,
                    "9",
                    dm.build_cmd("gh", ["search", "code", d, "--limit", "100"]),
                    timeout=60,
                    title=f"gh search code ({d})",
                )
        else:
            log.warn("gh not authenticated - public code-leak search not run")

    # 0b. Scan the organization's public repositories for leaked secrets
    _scan_public_repos(ctx, dm, log)

    # 1. Enumerate corporate emails via theHarvester, amass, spiderfoot, and passive sources
    emails = run_email_enumeration(ctx, dm, log)

    # 2. Check HaveIBeenPwned for domain breaches and compromised corporate emails
    run_hibp_breaches(ctx, log, emails=emails)
