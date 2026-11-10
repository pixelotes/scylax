"""Phase C: content discovery (optional).

Actively checks whether paths that should not be reachable are exposed — control
panels, API documentation, source control, config, backups, telemetry — on the
web assets we own. It is non-intrusive: GET only, no redirects followed, rate
limited, and it runs only against ownership-allowlisted hosts. Uses gobuster when
available, otherwise a native threaded probe. Opt-in via [content_discovery] in
the scope or by naming phase C with -p.
"""

from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from recon import checkpoint
from recon.config import RunContext
from recon.deps import DependencyManager
from recon.resilience import AdaptiveLimiter
from recon.runner import Logger, ev, http_get, infra_failure, record_tool_failure, record_virtual_cmd
from recon.scope import guard_for, ip_in, parse_networks
from recon.webprobe import PROBE_BYTES

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "content_discovery.txt"
INTERESTING_STATUSES = (200, 204, 301, 302, 307, 308, 401, 403, 405)
MAX_REQUESTS = 4000  # safety cap across all hosts, keeps the phase light

# Path-traversal / LFI probes. Each payload is paired with a signature that must
# appear in the response body, so a finding is confirmed by content (reaching
# /etc/passwd or win.ini), never by status alone. GET only, non-intrusive.
_PASSWD_SIG = r"root:.*?:0:0:"
_WININI_SIG = r"(?i)\[(fonts|extensions|mci extensions)\]|for 16-bit app support"
TRAVERSAL_PROBES: tuple[tuple[str, str], ...] = (
    ("/../../../../../../../../etc/passwd", _PASSWD_SIG),
    ("/....//....//....//....//etc/passwd", _PASSWD_SIG),
    ("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", _PASSWD_SIG),
    ("/..%2f..%2f..%2f..%2fetc%2fpasswd", _PASSWD_SIG),
    ("/%252e%252e%252f%252e%252e%252fetc%252fpasswd", _PASSWD_SIG),
    ("/static/../../../../../../etc/passwd", _PASSWD_SIG),
    ("/assets/../../../../../../etc/passwd", _PASSWD_SIG),
    ("/..%c0%af..%c0%af..%c0%afetc/passwd", _PASSWD_SIG),
    ("/..%5c..%5c..%5c..%5cwindows%5cwin.ini", _WININI_SIG),
    ("/%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", _WININI_SIG),
)

_HIGH = ("git", "svn", ".env", "backup", "dump", ".sql", "secret", "credential",
         "id_rsa", ".ssh", ".aws", "htpasswd", "wp-config", "heapdump", "actuator/env")
_MEDIUM = ("admin", "console", "manager", "phpmyadmin", "adminer", "login", "cpanel",
           "panel", "dashboard", "jenkins", "grafana", "kibana", "solr", "jolokia",
           "actuator", "metrics", "pprof", "phpinfo", "wp-admin", "portal")


def _category(path: str) -> str:
    low = path.lower()
    if any(k in low for k in _HIGH):
        return "high"
    if any(k in low for k in _MEDIUM):
        return "medium"
    return "low"


def _load_words(scope) -> list[str]:
    wl = getattr(scope, "content_discovery_wordlist", "")
    path = scope.resolve_file(wl) if wl else None
    path = path or DEFAULT_WORDLIST
    words: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line.lstrip("/"))
    return list(dict.fromkeys(words))


def _owned_bases(ctx: RunContext) -> list[str]:
    guard = guard_for(ctx)
    blocked = parse_networks(list(ctx.scope.exclude_ips) + list(ctx.scope.edge_ips))
    hvt_set = set(ctx.scope.hvt_ips)
    bases: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        p = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = p.hostname or ""
        base = f"{p.scheme or 'https'}://{p.netloc}"
        if not host or base in seen:
            return
        if host in hvt_set:
            if ip_in(host, blocked):
                return
        elif not guard.url_allowed(base, require_owned=True):
            return
        seen.add(base)
        bases.append(base)

    for ip in ctx.scope.hvt_ips:
        add(f"https://{ip}")
    httpx_txt = ctx.web_dir / "httpx_all.txt"
    if httpx_txt.is_file():
        for line in httpx_txt.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^(\S+)\s+\[(\d{3})\]", line)
            if m and int(m.group(2)) in (200, 301, 302, 307, 308, 401, 403):
                add(m.group(1))
    return sorted(bases)


def _native_probe(bases: list[str], words: list[str], delay: float, log: Logger,
                  units: "checkpoint.Units | None" = None) -> list[tuple[str, str, int, int]]:
    words_sig = hashlib.sha256("\n".join(words).encode()).hexdigest()[:12]
    rows: list[tuple[str, str, int, int]] = []
    budget = MAX_REQUESTS
    get = AdaptiveLimiter(base_delay=0.0).wrap(http_get)  # backs off / gives up on hosts that throttle

    def probe(base: str, word: str) -> tuple[str, str, int, int] | None:
        url = f"{base}/{word}"
        resp = get(url, timeout=8.0, verify_ssl=False, follow_redirects=False, max_bytes=PROBE_BYTES)
        if getattr(resp, "status", 0) in INTERESTING_STATUSES:
            return (base, word, resp.status, len(getattr(resp, "body", "") or ""))
        return None

    for base in bases:
        if budget <= 0:
            break
        batch = words[:budget]
        budget -= len(batch)
        key = f"native:{base}:{words_sig}:{len(batch)}"
        if units is not None and units.done(key):
            rows.extend((b, w, int(st), int(sz)) for b, w, st, sz in units.get(key) or [])
            continue
        base_rows: list[tuple[str, str, int, int]] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(probe, base, w) for w in batch]
            for fut in futures:
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r:
                    base_rows.append(r)
        rows.extend(base_rows)
        if units is not None:
            units.mark(key, base_rows)
        if delay:
            time.sleep(delay)
    return rows


def _gobuster(ctx: RunContext, dm: DependencyManager, log: Logger, base: str,
              wordlist: Path, delay: float,
              units: "checkpoint.Units | None" = None) -> list[tuple[str, str, int, int]]:
    try:
        wl_sig = f"{wordlist}:{wordlist.stat().st_size}"
    except OSError:
        wl_sig = str(wordlist)
    key = f"gobuster:{base}:{wl_sig}"
    if units is not None and units.done(key):
        return [(b, w, int(st), int(sz)) for b, w, st, sz in units.get(key) or []]
    out_file = ctx.web_dir / "_gobuster.txt"
    if out_file.is_file():
        out_file.unlink()
    res = ev(
        ctx.console_dir, "C",
        dm.build_cmd("gobuster", [
            "dir", "-u", base, "-w", str(wordlist), "-q", "-k", "-t", "8",
            "--no-error", "--delay", f"{delay}s", "--timeout", "8s",
            "-o", str(out_file),
        ]),
        timeout=600, title=f"gobuster {base}",
    )
    if res.returncode != 0 or infra_failure(res):
        record_tool_failure(ctx.run_dir, "C", "gobuster", infra_failure(res) or f"exit {res.returncode}")
        return []
    rows: list[tuple[str, str, int, int]] = []
    if out_file.is_file():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"^(\S+)\s+\(Status:\s*(\d{3})\)(?:\s*\[Size:\s*(\d+)\])?", line.strip())
            if m:
                path = m.group(1).lstrip("/")
                rows.append((base, path, int(m.group(2)), int(m.group(3) or 0)))
        out_file.unlink()
    if units is not None:
        units.mark(key, rows)
    return rows


def _traversal_probe(bases: list[str], delay: float,
                     units: "checkpoint.Units | None" = None) -> list[tuple[str, str, str]]:
    """Probe each base for path traversal; keep only responses matching the signature.
    Returns (url, payload_category, snippet)."""
    hits: list[tuple[str, str, str]] = []
    get = AdaptiveLimiter().wrap(http_get)
    for base in bases:
        key = f"traversal:{base}:{len(TRAVERSAL_PROBES)}"
        if units is not None and units.done(key):
            hits.extend((u, t, sn) for u, t, sn in units.get(key) or [])
            continue
        base_hits: list[tuple[str, str, str]] = []
        for payload, sig in TRAVERSAL_PROBES:
            url = f"{base}{payload}"
            resp = get(url, timeout=8.0, verify_ssl=False, follow_redirects=False, max_bytes=8192)
            if getattr(resp, "status", 0) in (200, 206):
                m = re.search(sig, getattr(resp, "body", "") or "")
                if m:
                    target = "etc/passwd" if sig == _PASSWD_SIG else "windows/win.ini"
                    snippet = m.group(0).replace("\t", " ").replace("\n", " ")[:80]
                    base_hits.append((url, target, snippet))
                    break  # one confirmed traversal per host is enough
            if delay:
                time.sleep(delay)
        hits.extend(base_hits)
        if units is not None:
            units.mark(key, base_hits)
    return hits


def phaseC(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase C - content discovery of exposed paths (optional, opt-in)."""
    log.info("Phase C - content discovery (exposed panels, docs, config, backups)")
    ctx.ensure_dirs()
    if not (getattr(ctx.scope, "content_discovery", False) or "C" in ctx.phases):
        log.info("content discovery disabled (set [content_discovery] enabled = true or use -p C)")
        return

    bases = _owned_bases(ctx)
    out = ctx.web_dir / "content_discovery.tsv"
    if out.is_file():
        out.unlink()
    if not bases:
        log.warn("content discovery: no owned web bases to probe")
        out.write_text("", encoding="utf-8")
        return

    words = _load_words(ctx.scope)
    delay = max(0.0, 1.0 / float(getattr(ctx.scope, "content_discovery_rate", 20) or 20))
    wordlist_path = ctx.scope.resolve_file(getattr(ctx.scope, "content_discovery_wordlist", "")) or DEFAULT_WORDLIST

    log.info(f"content discovery: {len(words)} paths on {len(bases)} owned host(s)")
    units = checkpoint.Units(ctx, "C")
    if dm.is_available("gobuster"):
        rows: list[tuple[str, str, int, int]] = []
        for base in bases:
            rows.extend(_gobuster(ctx, dm, log, base, wordlist_path, delay, units))
    else:
        log.info("gobuster not available - using the native content-discovery probe")
        rows = _native_probe(bases, words, delay, log, units)

    tsv_rows = []
    for base, path, status, size in rows:
        host = urllib.parse.urlparse(base).netloc
        cat = _category(path)
        tsv_rows.append(f"{base}/{path}\t{status}\t{size}\t{cat}\t{host}")
    out.write_text("".join(f"{r}\n" for r in tsv_rows), encoding="utf-8")
    record_virtual_cmd(
        ctx.console_dir, "C", f"content discovery ({len(words)} paths x {len(bases)} hosts)",
        "\n".join(tsv_rows) or "no exposed paths found",
        title="Content discovery results",
    )
    log.ok(f"content discovery: {len(tsv_rows)} exposed path(s) in web/content_discovery.tsv")

    # Path traversal / LFI (signature-confirmed, GET only)
    trav_file = ctx.web_dir / "path_traversal.tsv"
    if trav_file.is_file():
        trav_file.unlink()
    trav = _traversal_probe(bases, delay, units)
    trav_rows = [f"{url}\t{target}\t{snippet}" for url, target, snippet in trav]
    trav_file.write_text("".join(f"{r}\n" for r in trav_rows), encoding="utf-8")
    if trav:
        log.warn(f"content discovery: {len(trav)} path-traversal hit(s) in web/path_traversal.tsv")
    record_virtual_cmd(
        ctx.console_dir, "C", f"path-traversal probe ({len(TRAVERSAL_PROBES)} payloads x {len(bases)} hosts)",
        "\n".join(trav_rows) or "no path traversal found",
        title="Path traversal probe",
    )
