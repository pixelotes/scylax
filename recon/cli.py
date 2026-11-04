"""Command line interface and workflow orchestrator for the Reconnaissance Pipeline."""

from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from pathlib import Path
from typing import Sequence

from recon.config import ACTIVE_PHASES, DEFAULT_PHASES, RunContext, ScopeConfig, validate_scope
from recon.deps import DependencyManager
from recon.phases import PHASE_MAP, active, cloud, osint, saas, triage
from recon.ai_bundle import report_from_bundle
from recon.report import generate_reports
from recon.runner import TOOL_FAILURES_FILE, Logger, have, http_get, load_tool_failures, reset_phase_console
from recon.venv_manager import ensure_venv


BANNER = """\
   ███████╗ ██████╗██╗   ██╗██╗      █████╗ ██╗  ██╗
   ██╔════╝██╔════╝╚██╗ ██╔╝██║     ██╔══██╗╚██╗██╔╝
   ███████╗██║      ╚████╔╝ ██║     ███████║ ╚███╔╝
   ╚════██║██║       ╚██╔╝  ██║     ██╔══██║ ██╔██╗
   ███████║╚██████╗   ██║   ███████╗██║  ██║██╔╝ ██╗
   ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

   Discover. Map. Understand.
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   [ EASM ] [ CSPM ] [ SSPM ] [ OSINT ] [ RECON ]

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""


BANNER = """\
   ███████╗ ██████╗██╗   ██╗██╗      █████╗ ██╗  ██╗
   ██╔════╝██╔════╝╚██╗ ██╔╝██║     ██╔══██╗╚██╗██╔╝
   ███████╗██║      ╚████╔╝ ██║     ███████║ ╚███╔╝
   ╚════██║██║       ╚██╔╝  ██║     ██╔══██║ ██╔██╗
   ███████║╚██████╗   ██║   ███████╗██║  ██║██╔╝ ██╗
   ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

   Discover. Map. Understand.
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   [ EASM ] [ CSPM ] [ SSPM ] [ OSINT ] [ RECON ]

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""


def _get_egress_ip() -> str:
    """Attempt to detect the external egress IP address, falling back to 'unknown'."""
    try:
        resp = http_get("https://ifconfig.me", timeout=5.0)
        if resp.status == 200 and resp.body.strip():
            ip_candidate = resp.body.strip().splitlines()[0].strip()
            if re.match(r"^[0-9a-fA-F:.]+$", ip_candidate):
                return ip_candidate
    except Exception:
        pass
    return "unknown"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with flags, environment variable defaults, and help text."""
    parser = argparse.ArgumentParser(
        prog="scylax.py",
        description=f"{BANNER}\n\nDigital Attack Surface Cartography & Reconnaissance Pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-s",
        "--scope",
        default=os.environ.get("SCOPE", "scopes/default.toml"),
        help="scope TOML file (default: $SCOPE or scopes/default.toml)",
    )
    parser.add_argument(
        "-p",
        "--phases",
        default=os.environ.get("PHASES", " ".join(DEFAULT_PHASES)),
        help='space-separated phases string (default: $PHASES or "%(default)s")',
    )
    parser.add_argument(
        "-d",
        "--date",
        default=os.environ.get("RUN_DATE", datetime.date.today().isoformat()),
        help="run folder date name (default: $RUN_DATE or today)",
    )
    parser.add_argument(
        "-P",
        "--passive-only",
        action="store_true",
        default=(os.environ.get("SKIP_ACTIVE") == "1"),
        help="skip active phases (3, 4, 4b, 5, 8, A, G, W) (or SKIP_ACTIVE=1)",
    )
    parser.add_argument(
        "-n",
        "--no-cloud",
        "--no-azure",
        dest="no_cloud",
        action="store_true",
        default=(os.environ.get("SKIP_CLOUD") == "1" or os.environ.get("SKIP_AZURE") == "1"),
        help="skip cloud annexes A, G, and W (or SKIP_CLOUD=1 / SKIP_AZURE=1)",
    )
    parser.add_argument(
        "--cloud-posture",
        action="store_true",
        default=(os.environ.get("CLOUD_POSTURE") == "1"),
        help="enable cloud security posture checks across Azure, GCP, and AWS (or CLOUD_POSTURE=1)",
    )
    parser.add_argument(
        "--saas-posture",
        action="store_true",
        default=(os.environ.get("SAAS_POSTURE") == "1"),
        help="enable SaaS security posture checks across M365, GitHub, and Google Workspace (or SAAS_POSTURE=1)",
    )
    parser.add_argument(
        "--prowler",
        dest="use_prowler",
        action="store_true",
        default=(os.environ.get("USE_PROWLER") == "1"),
        help="enable deep Prowler CSPM assessment during cloud posture checks (or USE_PROWLER=1)",
    )
    parser.add_argument(
        "-q",
        "--quick",
        action="count",
        default=(int(os.environ["QUICK"]) if os.environ.get("QUICK", "").isdigit() else 0),
        help="quick port scan in phase 4: -q scans the top 1000 ports, -qq the top 100, instead of all 65535 (or QUICK=1 / QUICK=2)",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=(int(os.environ["TOP_PORTS"]) if os.environ.get("TOP_PORTS") else None),
        help="number of top ports to scan with nmap (e.g. 1000 or 100; default: all 65535 or 1000 with -q)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        default=(os.environ.get("YES") == "1"),
        help="do not ask for confirmation before active phases (or YES=1)",
    )
    parser.add_argument(
        "--authorised-by",
        default=os.environ.get("AUTHORISED_BY", "").strip(),
        help="override authorised_by written authorisation string for active phases",
    )
    parser.add_argument(
        "--authorisation-ref",
        default=os.environ.get("AUTHORISATION_REF", "").strip(),
        help="override authorisation_ref ticket/reference string for active phases",
    )
    parser.add_argument(
        "-D",
        "--docker",
        action="store_true",
        default=(os.environ.get("USE_DOCKER") == "1"),
        help="use Docker containers for supported tools instead of native binaries (or USE_DOCKER=1)",
    )
    parser.add_argument(
        "--shodan-key",
        default=os.environ.get("SHODAN_API_KEY", "").strip(),
        help="Shodan API key for phase 7 host lookups (or set SHODAN_API_KEY)",
    )
    parser.add_argument(
        "--hibp-key",
        default=os.environ.get("HIBP_API_KEY", "").strip(),
        help="HaveIBeenPwned API key for domain/account breach audit (or set HIBP_API_KEY)",
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="check and display all tool dependencies (native vs Docker) and exit",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate the scope file (unknown keys, missing files, empty sections) and exit",
    )
    parser.add_argument(
        "--report-only",
        metavar="DIR",
        help="regenerate report.md and report.html for an existing run directory and exit",
    )
    parser.add_argument(
        "--report-from-bundle",
        metavar="FILE",
        help="rebuild report.md and report.html from an ai_bundle.md and exit",
    )
    parser.add_argument(
        "--no-venv",
        action="store_true",
        default=(os.environ.get("NO_VENV") == "1"),
        help="do not prompt for or use a virtual environment (or set NO_VENV=1)",
    )
    return parser


def _clear_tool_failures(run_dir: Path, phase: str) -> None:
    """A phase that runs again starts with a clean failure record."""
    path = run_dir / TOOL_FAILURES_FILE
    if path.is_file():
        keep = [l for l in path.read_text(encoding="utf-8").splitlines() if l.split("\t", 1)[0] != phase]
        path.write_text("".join(f"{l}\n" for l in keep), encoding="utf-8")


def preflight(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Validate dependencies, permissions, and prerequisites before executing phases."""
    log.info(f"Scope: {ctx.scope.path}  Run folder: {ctx.run_dir}  (previous: {ctx.prev_run_dir or 'none'})")

    # Determine active phases that will actually run
    effective_phases = [p for p in ctx.phases if not ctx.phase_skip_reason(p)]

    statuses = dm.check_all(effective_phases)
    ok_req = dm.print_report(statuses)

    for st in statuses:
        if not st.available and not st.is_required_for_active and st.needed_for_phases:
            used_by = [p for p in st.plugin.phases if p in effective_phases]
            log.warn(f"{st.plugin.name} not available ({st.plugin.install_macos}) - phase {'/'.join(used_by)} degraded")

    if not ok_req:
        log.error("Missing required dependencies for requested phases. Install them or try --docker.")
        sys.exit(1)

    if "7" in effective_phases and not ctx.shodan_api_key:
        log.warn("SHODAN_API_KEY not set - Shodan host lookup in phase 7 skipped (Nmap CPE -> CVEDB correlation will still run)")

    # Check SaaS posture credentials / CLIs if phase S is requested and enabled
    if "S" in effective_phases and (ctx.saas_posture or getattr(ctx.scope, "saas_posture", False)):
        providers = [p.lower().strip() for p in getattr(ctx.scope, "saas_providers", ["m365", "github", "google"])]
        if "m365" in providers:
            m365_vars = ["M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"]
            missing_m365 = [v for v in m365_vars if not os.environ.get(v, "").strip()]
            if missing_m365:
                log.warn(f"M365 posture credentials missing ({', '.join(missing_m365)})")
        if "github" in providers:
            missing_gh = []
            if not os.environ.get("GITHUB_ORG", "").strip():
                missing_gh.append("GITHUB_ORG")
            if not have("gh"):
                missing_gh.append("gh CLI")
            if missing_gh:
                log.warn(f"GitHub posture requirements missing ({', '.join(missing_gh)})")
        if "google" in providers or "gws" in providers:
            has_gam = have("gam") or bool(os.environ.get("GAM_PATH", "").strip())
            if not has_gam:
                log.warn("Google Workspace posture requirements missing (gam CLI / GAM_PATH)")

    # Check authorization for active phases
    has_active = any(p in ACTIVE_PHASES for p in effective_phases) and not ctx.skip_active
    if has_active:
        if not ctx.scope.authorised_by:
            log.error(f"{ctx.scope.path}: authorised_by is empty. Active phases need written authorisation (or use -P / --passive-only).")
            sys.exit(1)
        if not ctx.yes:
            sys.stderr.write(f"Active scanning authorised by {ctx.scope.authorised_by} ({ctx.scope.authorisation_ref}). Continue? [y/N] ")
            sys.stderr.flush()
            ans = sys.stdin.readline().strip().lower()
            if ans != "y":
                log.error("Aborted by user.")
                sys.exit(1)

    # Write run.meta and tool_versions.txt
    egress_ip = _get_egress_ip()
    # Re-running some phases in an existing run dir keeps the record of the
    # phases that already produced evidence there (the diff relies on it).
    run_phases = list(ctx.phases)
    old_meta = ctx.run_dir / "run.meta"
    if old_meta.is_file():
        for line in old_meta.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("phases="):
                run_phases = list(dict.fromkeys(line[len("phases="):].split() + run_phases))
    meta_content = (
        f"engagement={ctx.scope.engagement}\n"
        f"scope={ctx.scope.path}\n"
        f"date={ctx.run_date}\n"
        f"authorised_by={ctx.scope.authorised_by}\n"
        f"authorisation_ref={ctx.scope.authorisation_ref}\n"
        f"phases={' '.join(run_phases)}\n"
        f"skip_active={'1' if ctx.skip_active else '0'}\n"
        f"use_docker={'1' if ctx.use_docker else '0'}\n"
        f"egress_ip={egress_ip}\n"
    )
    (ctx.run_dir / "run.meta").write_text(meta_content, encoding="utf-8")
    (ctx.run_dir / "tool_versions.txt").write_text(dm.tool_versions() + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI main entry point."""
    _repo_root = Path(__file__).resolve().parent.parent
    ensure_venv(_repo_root, argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    log = Logger()

    # 1. Immediate dependency check
    if args.check_deps:
        dm = DependencyManager(use_docker=args.docker)
        statuses = dm.check_all()
        ok_req = dm.print_report(statuses, file=sys.stdout)
        return 0 if ok_req else 1

    # 1b. Scope validation
    if args.check_config:
        errors, warnings = validate_scope(Path(args.scope))
        for w in warnings:
            log.warn(w)
        for e in errors:
            log.error(e)
        if not errors and not warnings:
            log.ok(f"{args.scope}: no problems found")
        elif not errors:
            log.ok(f"{args.scope}: {len(warnings)} warning(s), no errors")
        return 1 if errors else 0

    # 2. Report only regeneration
    if args.report_only:
        report_dir = Path(args.report_only)
        if not report_dir.is_dir():
            log.error(f"Report directory not found: {report_dir}")
            return 1
        md_path, html_path = generate_reports(report_dir)
        log.ok(f"Reports generated: {md_path} and {html_path}")
        return 0

    # 2b. Rebuild a report from an AI bundle
    if args.report_from_bundle:
        bundle = Path(args.report_from_bundle)
        if not bundle.is_file():
            log.error(f"Bundle file not found: {bundle}")
            return 1
        try:
            md_path, html_path = report_from_bundle(bundle)
        except Exception as exc:
            log.error(f"Could not rebuild report from bundle: {exc}")
            return 1
        log.ok(f"Reports rebuilt from bundle: {md_path} and {html_path}")
        return 0

    print(BANNER)
    print()

    # 3. Load scope config
    scope_path = Path(args.scope)
    if not scope_path.is_file():
        log.error(f"Scope file not found: {scope_path} (copy scopes/example.toml)")
        return 1

    try:
        scope = ScopeConfig.load(scope_path)
    except Exception as exc:
        log.error(f"Failed to load scope configuration: {exc}")
        return 1

    if args.authorised_by:
        scope.authorised_by = args.authorised_by.strip()
    elif not scope.authorised_by and os.environ.get("AUTHORISED_BY"):
        scope.authorised_by = os.environ.get("AUTHORISED_BY", "").strip()

    if args.authorisation_ref:
        scope.authorisation_ref = args.authorisation_ref.strip()
    elif not scope.authorisation_ref and os.environ.get("AUTHORISATION_REF"):
        scope.authorisation_ref = os.environ.get("AUTHORISATION_REF", "").strip()

    phases = [p.strip() for p in re.split(r"[\s,]+", args.phases) if p.strip()]
    # Cloud annexes named explicitly (-p or $PHASES) run even without provider config.
    explicit_phases = args.phases != " ".join(DEFAULT_PHASES)

    ctx = RunContext(
        root=Path.cwd(),
        scope=scope,
        run_date=args.date,
        phases=phases,
        skip_active=args.passive_only,
        skip_cloud=args.no_cloud,
        skip_azure=args.no_cloud,
        use_docker=args.docker,
        yes=args.yes,
        shodan_api_key=(args.shodan_key or scope.shodan_api_key or os.environ.get("SHODAN_API_KEY", "")).strip(),
        hibp_api_key=(args.hibp_key or scope.hibp_api_key or os.environ.get("HIBP_API_KEY", "")).strip(),
        cloud_posture=bool(args.cloud_posture or scope.cloud_posture),
        use_prowler=bool(args.use_prowler or scope.use_prowler),
        saas_posture=bool(args.saas_posture or scope.saas_posture),
        quick_scan=bool(args.quick or scope.quick_scan),
        explicit_phases=explicit_phases,
        top_ports=(
            args.top_ports if args.top_ports is not None
            else scope.top_ports if scope.top_ports is not None
            else (100 if args.quick >= 2 else None)
        ),
    )
    ctx.ensure_dirs()
    log.gaps_file = ctx.run_dir / "gaps.txt"
    # gaps.txt describes this run: a re-run that collects evidence starts it afresh
    # (a triage-only re-run keeps the gaps of the run it reports on).
    if any(p != "T" for p in ctx.phases) and log.gaps_file.is_file():
        log.gaps_file.unlink()

    # API plugins are detected through their environment variables: expose keys
    # that came from the scope file or the command line the same way.
    for var, value in (("SHODAN_API_KEY", ctx.shodan_api_key), ("HIBP_API_KEY", ctx.hibp_api_key)):
        if value and not os.environ.get(var, "").strip():
            os.environ[var] = value

    dm = DependencyManager(use_docker=ctx.use_docker, run_dir=ctx.run_dir)
    preflight(ctx, dm, log)

    # Phase dispatch table
    phase_dispatch = PHASE_MAP

    for p in ctx.phases:
        reason = ctx.phase_skip_reason(p)
        if reason:
            log.info(f"skip phase {p} ({reason})")
            continue
        fn = phase_dispatch.get(p)
        if fn is None:
            log.warn(f"unknown phase {p}")
            continue
        reset_phase_console(ctx.console_dir, p)
        _clear_tool_failures(ctx.run_dir, p)
        fn(ctx, dm, log)
        for ph, tool, reason in load_tool_failures(ctx.run_dir):
            if ph == p:
                log.warn(f"{tool} failed in phase {p} ({reason}) - its results are missing; findings it would report are not re-checked")

    log.ok(f"Done. Evidence: {ctx.run_dir}")
    return 0
