"""AI analysis bundle: one self-contained, LLM-ingestible file per run.

report.md / report.html embed every tool's console evidence and run to megabytes,
too large for a model's context window. ai_bundle.md is a compact companion that
carries the run metadata, coverage gaps and the structured source files the report
is built from, each embedded verbatim in a path-tagged block. From it alone an LLM
can reason about the run, and `report_from_bundle()` can rebuild report.md /
report.html. Small source files are embedded whole; a few large dumps are capped,
so a report regenerated from the bundle is complete except for those long lists.
"""

from __future__ import annotations

import re
from pathlib import Path

TOTAL_BUDGET = 500_000
PER_LINE = 1000
CAP_ROWS = 300

# Source files embedded verbatim (small, and what the report's sections are built
# from). Order is reading order for a human/LLM. Missing files are skipped.
CORE_FILES: tuple[str, ...] = (
    "run.meta", "tool_versions.txt", "gaps.txt", "tool_failures.tsv",
    "findings_auto.tsv", "suppressed.tsv", "diff.md",
    "osint/apex.txt", "osint/subdomain_counts.txt",
    "osint/new_subdomains.txt", "osint/gone_subdomains.txt", "osint/discovered_targets.txt",
    "osint/ip_orgs.tsv", "osint/emails.tsv",
    "osint/hibp_breaches.tsv", "osint/hibp_account_breaches.tsv",
    "osint/takeover_candidates.tsv", "osint/secret_leaks.tsv", "osint/skipped_targets.tsv",
    "web/exposed_paths.tsv", "web/entry_points.tsv", "web/cors_cookies.tsv",
    "web/dir_listings.txt", "web/root_data.tsv", "web/api_endpoints.tsv", "web/sensitive_paths.tsv",
    "azure/public_ips.tsv", "azure/public_endpoints.tsv", "azure/nsg_internet_rules.tsv",
    "azure/coverage.txt", "azure/posture_findings.tsv",
    "gcp/public_ips.tsv", "gcp/firewall_internet_rules.tsv", "gcp/coverage.txt", "gcp/posture_findings.tsv",
    "aws/public_ips.tsv", "aws/public_endpoints.tsv", "aws/sg_internet_rules.tsv",
    "aws/coverage.txt", "aws/posture_findings.tsv",
)

# Large files feeding secondary sections: embedded but row-capped.
CAPPED_FILES: tuple[str, ...] = (
    "osint/service_cves.tsv", "osint/subdomains.txt", "osint/resolved.txt",
    "osint/ip_host.tsv", "osint/ct_first_seen.tsv", "web/httpx_all.txt", "web/tech.tsv",
)

# Glob patterns for files whose exact names vary (one per SaaS provider).
GLOB_FILES: tuple[str, ...] = ("saas/*/posture_findings.tsv",)

_FILE_MARKER = "<!-- scylax-file: {path} ({meta}) -->"
_MARKER_RE = re.compile(r"<!-- scylax-file: (?P<path>[^ ]+) \((?P<meta>[^)]*)\) -->\n```[a-z]*\n(?P<body>.*?)\n```", re.DOTALL)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip()]


def _meta(run_dir: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in _lines(_read(run_dir / "run.meta")):
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _fence_for(rel: str) -> str:
    if rel.endswith(".tsv"):
        return "tsv"
    if rel.endswith(".md"):
        return "markdown"
    return "text"


def build_ai_bundle(run_dir: Path | str) -> Path:
    """Write ai_bundle.md in run_dir and return its path."""
    run_dir = Path(run_dir).resolve()
    meta = _meta(run_dir)
    scope = meta.get("scope", run_dir.parent.name)
    date = meta.get("date", run_dir.name)

    parts: list[str] = []
    budget = TOTAL_BUDGET

    def emit(s: str) -> None:
        nonlocal budget
        parts.append(s)
        budget -= len(s)

    emit(f"# Scylax AI analysis bundle — {scope} — {date}\n\n")
    emit(
        "> CONFIDENTIAL: contains real target data. For analysis only.\n>\n"
        "> Self-contained companion to report.md / report.html, sized for an LLM "
        "context window. You are reviewing an external attack-surface run: prioritise "
        "`findings_auto.tsv` and `diff.md` below, treat each finding as a candidate to "
        "validate (not a confirmed vulnerability), and note that a coverage gap means a "
        "check could not run, so a missing finding there is not proof of safety.\n>\n"
        "> Each section embeds a source file in a `scylax-file:` block; a report can be "
        "rebuilt from this bundle with `scylax.py --report-from-bundle ai_bundle.md`.\n\n"
    )

    # Quick orientation
    gaps = _lines(_read(run_dir / "gaps.txt"))
    failures = _lines(_read(run_dir / "tool_failures.tsv"))
    n_findings = len(_lines(_read(run_dir / "findings_auto.tsv")))
    emit("## At a glance\n\n")
    emit(f"- Findings: **{n_findings}**\n")
    emit(f"- Coverage gaps: {len(gaps)} · tool failures: {len(failures)}\n")
    if failures:
        emit("- Failed tools (their findings are NOT re-checked): "
             + ", ".join(sorted({f.split(chr(9))[1] for f in failures if chr(9) in f})) + "\n")
    emit("\n")

    seen: set[str] = set()

    def embed(rel: str, *, cap: int | None) -> None:
        nonlocal budget
        if rel in seen:
            return
        text = _read(run_dir / rel)
        if not text.strip():
            return
        seen.add(rel)
        all_lines = text.splitlines()
        total = len(all_lines)
        if cap is not None and total > cap:
            body = "\n".join(ln[:PER_LINE] for ln in all_lines[:cap])
            meta_note = f"{total} rows, first {cap} shown"
        else:
            body = "\n".join(ln[:PER_LINE] for ln in all_lines)
            meta_note = f"{total} rows"
        block = f"{_FILE_MARKER.format(path=rel, meta=meta_note)}\n```{_fence_for(rel)}\n{body}\n```\n\n"
        if budget - len(block) <= 0 and rel not in ("run.meta", "findings_auto.tsv", "diff.md"):
            return  # keep the essentials; drop later large blocks when out of budget
        emit(block)

    emit("## Source files\n\n")
    for rel in CORE_FILES:
        embed(rel, cap=None)
    for pattern in GLOB_FILES:
        for p in sorted(run_dir.glob(pattern)):
            embed(str(p.relative_to(run_dir)), cap=None)
    for rel in CAPPED_FILES:
        embed(rel, cap=CAP_ROWS)

    if budget <= 0:
        emit("_Size budget reached; some large lists were truncated or omitted (full files are in the run folder)._\n\n")
    emit(
        "## Not included\n\nRaw per-tool console output (`console/`) is omitted to keep "
        "the bundle within an LLM context window; it is in the run folder if needed.\n"
    )

    out = run_dir / "ai_bundle.md"
    out.write_text("".join(parts), encoding="utf-8")
    return out


def extract_files(bundle_text: str) -> dict[str, str]:
    """Return {relative_path: file_body} for every scylax-file block in a bundle."""
    return {m.group("path"): m.group("body") for m in _MARKER_RE.finditer(bundle_text)}


def report_from_bundle(bundle_path: Path | str, out_dir: Path | str | None = None) -> tuple[Path, Path]:
    """Reconstruct the run's source files from a bundle and regenerate the reports.

    Writes the embedded files into out_dir (default: a sibling '<bundle>_report'
    folder) and calls generate_reports. Large lists that were capped in the bundle
    come back truncated; everything embedded whole is faithful."""
    from recon.report import generate_reports

    bundle_path = Path(bundle_path).resolve()
    text = _read(bundle_path)
    files = extract_files(text)
    if "run.meta" not in files and "findings_auto.tsv" not in files:
        raise ValueError(f"{bundle_path} has no scylax-file blocks: not a Scylax AI bundle")

    dest = Path(out_dir).resolve() if out_dir else bundle_path.parent / f"{bundle_path.stem}_report"
    for rel, body in files.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body + ("\n" if not body.endswith("\n") else ""), encoding="utf-8")
    return generate_reports(dest)
