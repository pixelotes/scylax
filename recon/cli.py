"""Command line interface and workflow orchestrator for the Reconnaissance Pipeline."""

from __future__ import annotations

import argparse
import datetime
import os
import re
import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Sequence

from recon.config import (
    ACTIVE_PHASES,
    DEFAULT_PHASES,
    PROFILE_ALIASES,
    PROFILES,
    RunContext,
    ScopeConfig,
    profile_names,
    profile_phases,
    resolve_profile,
    validate_scope,
)
from recon import checkpoint, notify, redact, scheduler
from recon.deps import DependencyManager
from recon.phases import PHASE_MAP, active, cloud, osint, saas, triage
from recon.ai_bundle import report_from_bundle
from recon.export import export_report_data
from recon.report import generate_reports
from recon.runner import (
    DRY_RUN, STOP, TOOL_FAILURES_FILE, TOOL_FAILURES_LOCK, Logger, dry_run_active, dry_run_report, have, http_get,
    load_tool_failures, record_tool_failure, reset_phase_console, set_log_phase,
)
from recon.resilience import BREAKERS
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


def _doctor_integrations(scope: ScopeConfig, log: Logger) -> None:
    """Report which optional integrations are configured for a scope."""
    def mark(name: str, present: bool, how: str) -> None:
        if present:
            log.ok(f"  {name}: configured")
        else:
            log.info(f"  {name}: not set ({how})")

    shodan = (scope.shodan_api_key or os.environ.get("SHODAN_API_KEY", "")).strip()
    hibp = (scope.hibp_api_key or os.environ.get("HIBP_API_KEY", "")).strip()
    nvd = (scope.intel_keys.get("nvd_api_key", "") or os.environ.get("NVD_API_KEY", "")).strip()
    log.info("Integrations / API keys:")
    mark("Shodan", bool(shodan), "phase 7 host lookup; SHODAN_API_KEY or [targets] shodan_api_key")
    mark("HaveIBeenPwned", bool(hibp), "breach audit; HIBP_API_KEY or [targets] hibp_api_key")
    mark("NVD", bool(nvd), "faster CVE lookups; NVD_API_KEY or [intel] nvd_api_key")
    mark("Alert webhook", bool(notify.webhook_url(scope)), "run & finding alerts; alert_webhook or SCYLAX_ALERT_WEBHOOK")


def _doctor(args: argparse.Namespace, log: Logger) -> int:
    """One-shot environment & scope health check. Returns 0 when nothing blocks a
    run, 1 when there is a blocking problem (missing required tool, or a scope that
    is absent or invalid)."""
    log.info("Scylax doctor - environment & scope health check")
    blocking = 0

    log.ok(f"Python {sys.version.split()[0]}")
    if have("docker"):
        log.ok("Docker available (containerised tools usable with --docker)")
    else:
        log.info("Docker not found (optional; install it to run tools with --docker)")

    log.info("Dependencies (all phases):")
    dm = DependencyManager(use_docker=args.docker)
    statuses = dm.check_all()
    if not dm.print_report(statuses):
        blocking += 1

    log.info("Scope:")
    scope_path = Path(args.scope)
    if not scope_path.is_file():
        log.error(f"Scope file not found: {scope_path}")
        log.info("  create one:  cp scopes/example.toml scopes/<name>.toml   (then edit it)")
        blocking += 1
    else:
        errors, warnings = validate_scope(scope_path)
        for w in warnings:
            log.warn(w)
        for e in errors:
            log.error(e)
        if errors:
            blocking += 1
        try:
            scope = ScopeConfig.load(scope_path)
        except Exception as exc:
            log.error(f"Could not load scope: {exc}")
            blocking += 1
        else:
            auth = "authorised" if scope.authorised_by else "NO authorisation set"
            log.ok(f"{scope.path}: {len(scope.domains)} domain(s), {len(scope.hvt_ips)} HVT IP(s), {auth}")
            if not scope.authorised_by:
                log.warn("authorised_by is empty - active phases will be refused (use -P / --passive-only)")
            _doctor_integrations(scope, log)

    log.info(f"Egress IP (what targets will see): {_get_egress_ip()}")

    log.info("Next:")
    if blocking:
        log.warn(f"{blocking} blocking issue(s) above - fix them before a full run.")
    scope_hint = args.scope if scope_path.is_file() else "scopes/<name>.toml"
    log.info(f"  preview a run:  python3 scylax.py -s {scope_hint} --profile light --dry-run")
    log.info(f"  run it:         python3 scylax.py -s {scope_hint} --profile light")
    return 1 if blocking else 0


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer >= 1, got {value!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"expected an integer >= 1, got {n}")
    return n


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
        "--profile",
        default=os.environ.get("PROFILE", "").strip(),
        metavar="NAME",
        help="phase-group preset (e.g. passive, light, external, blueteam, purpleteam, full, "
             "web, cloud, intel, saas; or $PROFILE). Sets phases and posture toggles; "
             "an explicit -p overrides the phases. Use '--profile list' to see them all.",
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
        "--dry-run",
        action="store_true",
        help="print the commands and HTTP requests each phase would issue, run nothing and write no evidence "
             "(commands that depend on earlier phases' discoveries cannot be listed)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip phases already completed (without tool failures) in this run folder; scope edits invalidate them",
    )
    parser.add_argument(
        "--jobs",
        type=_positive_int,
        default=int(os.environ["SCYLAX_JOBS"]) if os.environ.get("SCYLAX_JOBS", "").strip().isdigit() else None,
        metavar="N",
        help="run up to N independent phases at once (default 1 = sequential; or SCYLAX_JOBS, or scope `jobs`). "
             "Phases that send traffic to the targets never overlap, so traffic intensity does not increase",
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
        "--doctor",
        action="store_true",
        help="one-shot health check: Python, tools, scope, API keys, egress IP, and the "
             "command to run next; then exit (0 if nothing blocks a run, 1 otherwise)",
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
        "--export",
        metavar="DIR",
        help="write report_data.json (consolidated assets + findings + relations, "
             "the report-generator contract) for an existing run directory and exit",
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
    with TOOL_FAILURES_LOCK:
        if path.is_file():
            keep = [l for l in path.read_text(encoding="utf-8").splitlines() if l.split("\t", 1)[0] != phase]
            path.write_text("".join(f"{l}\n" for l in keep), encoding="utf-8")


def _record_phase_crash(ctx: RunContext, phase: str, exc: BaseException, log: Logger) -> None:
    """Contain a phase's own crash: record it as a tool failure (so triage treats
    its findings as not re-checked, never resolved) and append the traceback to the
    phase log for debugging. Never raises."""
    summary = f"crashed: {type(exc).__name__}: {exc}"
    try:
        record_tool_failure(ctx.run_dir, phase, f"phase-{phase}", redact.redact(summary))
    except Exception:
        pass
    try:
        ctx.console_dir.mkdir(parents=True, exist_ok=True)
        with (ctx.console_dir / f"{phase}.log").open("a", encoding="utf-8") as fh:
            fh.write(f"\n[scylax] phase {phase} crashed:\n{redact.redact(traceback.format_exc())}\n")
    except Exception:
        pass


def _salvage_report(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Produce a report from whatever evidence exists when triage did not run
    (interrupted, crashed, or stopped before phase T). Best-effort: tries a fresh
    triage first, then a plain report build, and never raises."""
    log.info("Producing a report from the evidence collected so far...")
    try:
        reset_phase_console(ctx.console_dir, "T")
    except Exception:
        pass
    try:
        DRY_RUN.phase = "T"
        PHASE_MAP["T"](ctx, dm, log)
        log.ok(f"Report generated from partial evidence: {ctx.run_dir}")
        return
    except Exception as exc:
        log.error(f"Triage on partial evidence failed ({type(exc).__name__}: {exc}); building a plain report")
    try:
        generate_reports(ctx.run_dir)
        log.ok(f"Report generated: {ctx.run_dir}")
    except Exception as exc:
        log.error(f"Could not generate any report: {exc}")


def _print_recovery_hints(ctx: RunContext, log: Logger, *, interrupted: bool, crashed: Sequence[str]) -> None:
    """Tell the user exactly how to pick up an incomplete run."""
    if crashed:
        log.warn(f"Phases that crashed: {', '.join(crashed)} - their findings are marked not re-checked, not resolved")
    log.info("Recovery:")
    log.info(f"  resume what's left:  python3 scylax.py -s {ctx.scope.path} -d {ctx.run_date} --resume")
    log.info(f"  rebuild the report:  python3 scylax.py --report-only {ctx.run_dir}")


def _alert_run_failure(ctx: RunContext, log: Logger, *, interrupted: bool, crashed: Sequence[str]) -> None:
    """Best-effort webhook alert that the run did not finish cleanly. Never raises."""
    if not notify.webhook_url(ctx.scope):
        return
    try:
        attempted, msg = notify.post_run_failure(
            ctx.scope, ctx.scope.name, ctx.run_date,
            interrupted=interrupted, crashed=list(crashed), run_dir=str(ctx.run_dir),
        )
        if attempted:
            log.info(f"Failure alert: {msg}")
    except Exception as exc:
        log.warn(f"Could not send failure alert: {exc}")


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
        if dry_run_active():
            log.warn("Missing required dependencies (dry-run continues; a real run would stop here)")
        else:
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
    if has_active and dry_run_active():
        if not ctx.scope.authorised_by:
            log.warn("authorised_by is empty: a real run of the active phases would be refused")
        else:
            log.info(f"Active scanning authorised by {ctx.scope.authorised_by} ({ctx.scope.authorisation_ref})")
    elif has_active:
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


def _resolve_jobs(args: argparse.Namespace, scope: ScopeConfig, log: Logger) -> int:
    """--jobs, else scope `jobs`, else 1. A dry run is always sequential: its plan
    attributes each command to the (single) current phase."""
    jobs = args.jobs if args.jobs is not None else (getattr(scope, "jobs", None) or 1)
    jobs = max(1, int(jobs))
    if jobs > 1 and dry_run_active():
        log.info("--dry-run lists phases one at a time: ignoring --jobs")
        return 1
    return jobs


def _phase_runnable(ctx: RunContext, log: Logger, p: str, scope_sig: str, args: argparse.Namespace) -> bool:
    """False (after saying why) for a phase that will not run in this invocation."""
    reason = ctx.phase_skip_reason(p)
    if reason:
        log.info(f"skip phase {p} ({reason})")
        return False
    fn = PHASE_MAP.get(p)
    if fn is None:
        log.warn(f"unknown phase {p}")
        return False
    if args.resume and p != "T" and checkpoint.is_done(ctx.run_dir, p, scope_sig):
        log.info(f"skip phase {p} (already completed in this run folder; --resume)")
        return False
    return True


def _execute_phase(
    ctx: RunContext, dm: DependencyManager, log: Logger, p: str, scope_sig: str, args: argparse.Namespace,
) -> str:
    """Run one phase with its prologue, crash containment, tool-failure check and
    checkpoint; return a scheduler outcome. May run in a worker thread (--jobs)."""
    fn = PHASE_MAP[p]
    DRY_RUN.phase = p
    reset_phase_console(ctx.console_dir, p)
    _clear_tool_failures(ctx.run_dir, p)
    checkpoint.clear(ctx.run_dir, p)
    try:
        fn(ctx, dm, log)
    except KeyboardInterrupt:
        log.warn(f"Interrupted during phase {p} - stopping and salvaging a report from the evidence so far")
        return scheduler.INTERRUPTED
    except Exception as exc:
        # The phase's own code crashed (not an external tool, which run_cmd
        # already contains). Keep the remaining phases and the report alive.
        _record_phase_crash(ctx, p, exc, log)
        log.error(f"Phase {p} crashed ({type(exc).__name__}: {exc}) - continuing with the remaining phases")
        return scheduler.CRASHED
    failed = [(tool, why) for ph, tool, why in load_tool_failures(ctx.run_dir) if ph == p]
    for tool, why in failed:
        log.warn(f"{tool} failed in phase {p} ({why}) - its results are missing; findings it would report are not re-checked")
    if not failed and not dry_run_active() and p != "T":
        checkpoint.mark_done(ctx.run_dir, p, scope_sig)
    return scheduler.FAILED if failed else scheduler.OK


def main(argv: Sequence[str] | None = None) -> int:
    """CLI main entry point."""
    _repo_root = Path(__file__).resolve().parent.parent
    ensure_venv(_repo_root, argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    log = Logger()

    # 0. List available phase-group profiles and exit
    if args.profile.strip().lower() in ("list", "help", "?"):
        print("Available --profile presets (phase T is always appended):\n")
        for name, cfg in PROFILES.items():
            print(f"  {name:11} {' '.join(profile_phases(name))}")
            toggles = [t for t in ("cloud_posture", "saas_posture", "use_prowler") if cfg.get(t)]
            if toggles:
                print(f"              toggles: {', '.join(toggles)}")
            print(f"              {cfg['desc']}")
        if PROFILE_ALIASES:
            print("\nAliases: " + ", ".join(f"{a} -> {t}" for a, t in PROFILE_ALIASES.items()))
        return 0

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

    # 1c. Full environment & scope health check
    if args.doctor:
        return _doctor(args, log)

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

    # 2c. Write the consolidated report_data.json for an existing run
    if args.export:
        export_dir = Path(args.export)
        if not export_dir.is_dir():
            log.error(f"Run directory not found: {export_dir}")
            return 1
        try:
            out_path = export_report_data(export_dir)
        except Exception as exc:
            log.error(f"Could not export report data: {exc}")
            return 1
        log.ok(f"Exported report data: {out_path}")
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

    # A --profile preset selects the phases (unless -p was given explicitly) and
    # enables its posture toggles. Treating the profile as explicit lets its
    # opt-in phases (A/G/W, C, E) run just as naming them with -p would.
    profile_cfg: dict = {}
    if args.profile:
        try:
            profile_cfg = resolve_profile(args.profile)
        except KeyError:
            log.error(
                f"Unknown profile '{args.profile}'. Available: "
                f"{', '.join(profile_names())} (see --profile list)."
            )
            return 1
        if not explicit_phases:
            phases = profile_phases(args.profile)
        explicit_phases = True
        log.info(f"Profile '{args.profile.lower().strip()}': phases {' '.join(phases)}")

    dry_dir: str | None = None
    if args.dry_run:
        # Nothing is executed or written to the real runs folder; triage has nothing to triage.
        phases = [p for p in phases if p != "T"]
        dry_dir = tempfile.mkdtemp(prefix="scylax-dryrun-")
        scope.runs_dir = dry_dir
        DRY_RUN.root = str(Path(dry_dir).resolve())
        DRY_RUN.reset()
        DRY_RUN.active = True
        log.info("DRY RUN: listing what each phase would execute; no command is run and no evidence is written")

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
        cloud_posture=bool(args.cloud_posture or scope.cloud_posture or profile_cfg.get("cloud_posture")),
        use_prowler=bool(args.use_prowler or scope.use_prowler or profile_cfg.get("use_prowler")),
        saas_posture=bool(args.saas_posture or scope.saas_posture or profile_cfg.get("saas_posture")),
        quick_scan=bool(args.quick or scope.quick_scan),
        explicit_phases=explicit_phases,
        resume=args.resume,
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
    if any(p != "T" for p in ctx.phases) and log.gaps_file.is_file() and not args.resume:
        log.gaps_file.unlink()

    # Never let a key reach evidence files or warnings, whatever tool echoes it.
    redact.register(ctx.shodan_api_key, ctx.hibp_api_key)
    redact.register(*(v for k, v in scope.intel_keys.items() if not k.endswith(("_username", "_id"))))
    redact.register(*(os.environ.get(v) for v in ("M365_CLIENT_SECRET", "GITHUB_TOKEN", "GH_TOKEN", "NVD_API_KEY")))
    if scope.has_secrets() and (scope_path.stat().st_mode & 0o077):
        log.warn(f"{scope_path} holds API keys but is readable by other users: chmod 600 {scope_path}")

    # API plugins are detected through their environment variables: expose keys
    # that came from the scope file or the command line the same way.
    for var, value in (
        ("SHODAN_API_KEY", ctx.shodan_api_key),
        ("HIBP_API_KEY", ctx.hibp_api_key),
        ("NVD_API_KEY", scope.intel_keys.get("nvd_api_key", "")),
    ):
        if value and not os.environ.get(var, "").strip():
            os.environ[var] = value

    dm = DependencyManager(use_docker=ctx.use_docker, run_dir=ctx.run_dir)
    preflight(ctx, dm, log)

    BREAKERS.reset()
    scope_sig = checkpoint.scope_signature(scope_path)
    jobs = _resolve_jobs(args, scope, log)
    if jobs > 1:
        log.info(f"Running up to {jobs} independent phases at a time; phases that send traffic "
                 "to the targets still run one at a time")
    interrupted = False
    crashed: list[str] = []
    t_done = False
    try:
        def run_one(p: str) -> str:
            if jobs > 1:
                set_log_phase(p)
            try:
                return _execute_phase(ctx, dm, log, p, scope_sig, args)
            finally:
                if jobs > 1:
                    set_log_phase("")

        def on_interrupt() -> None:
            STOP.set()
            log.warn("Interrupted - no new phase starts; waiting for the running phases to stop, "
                     "then salvaging a report from the evidence so far")

        STOP.clear()
        try:
            outcomes, interrupted = scheduler.run_phases(
                ctx.phases, run_one, jobs=jobs,
                runnable=lambda p: _phase_runnable(ctx, log, p, scope_sig, args),
                on_interrupt=on_interrupt,
            )
        finally:
            STOP.clear()
        crashed = [p for p, outcome in outcomes.items() if outcome == scheduler.CRASHED]
        t_done = outcomes.get("T") in (scheduler.OK, scheduler.FAILED)

        if dry_run_active():
            print()
            print("DRY RUN PLAN (commands and requests that depend on earlier results or on a first response are not listed):")
            print(dry_run_report() or "  (nothing to execute)")
            return 0
    finally:
        if dry_dir:
            shutil.rmtree(dry_dir, ignore_errors=True)

    # Never lose the report: if triage was requested but did not get to run (the run
    # was interrupted, crashed, or stopped before phase T), build one from whatever
    # evidence was collected.
    if not dry_run_active() and "T" in ctx.phases and not t_done:
        _salvage_report(ctx, dm, log)

    if interrupted or crashed:
        _print_recovery_hints(ctx, log, interrupted=interrupted, crashed=crashed)
        _alert_run_failure(ctx, log, interrupted=interrupted, crashed=crashed)

    # Exit codes: 0 clean · 1 config/usage (returned earlier) · 2 a phase crashed
    # but the run finished · 130 interrupted.
    if interrupted:
        return 130
    if crashed:
        log.warn(f"Done with {len(crashed)} failed phase(s). Evidence: {ctx.run_dir}")
        return 2
    log.ok(f"Done. Evidence: {ctx.run_dir}")
    return 0
