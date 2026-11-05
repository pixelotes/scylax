"""Phase E - third-party SaaS exposure (Atlassian Cloud): fixed anonymous read-only checks."""

from __future__ import annotations

from recon import misconfig, saas_exposure
from recon.config import RunContext
from recon.deps import DependencyManager
from recon.phases.osint import NON_PUBLIC_TLDS
from recon.resilience import AdaptiveLimiter
from recon.runner import Logger, ev, http_get, record_virtual_cmd


def phaseE(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    log.info("Phase E - third-party SaaS exposure (anonymous, read-only, fixed endpoints)")
    ctx.ensure_dirs()
    domains = [d for d in ctx.scope.domains if d.rsplit(".", 1)[-1].lower() not in NON_PUBLIC_TLDS]
    slugs = saas_exposure.candidate_slugs(domains, getattr(ctx.scope, "saas_org_names", []))
    if not slugs:
        log.warn("SaaS exposure: no tenant names to try (set [saas_exposure] org_names)")
        return

    def trace(cmd: str, summary: str) -> None:
        record_virtual_cmd(console_dir=ctx.console_dir, phase="E", cmd_str=cmd, output=summary,
                           title="SaaS exposure probe")

    fetch = AdaptiveLimiter(base_delay=0.2).wrap(http_get)
    tenants: list[tuple[str, str, str]] = []
    findings: list[saas_exposure.Finding] = []
    for slug in slugs:
        t, f = saas_exposure.check_atlassian(slug, fetch, trace)
        tenants += t
        findings += f

    if getattr(ctx.scope, "use_misconfig_mapper", False):
        mm_tenants, mm_findings = _misconfig_mapper(ctx, dm, log, slugs)
        tenants += mm_tenants
        findings += mm_findings

    clean = lambda rows: "".join("\t".join(c.replace("\t", " ").replace("\n", " ") for c in r) + "\n" for r in rows)
    (ctx.saas_dir / "exposure_findings.tsv").write_text(clean(findings), encoding="utf-8")
    (ctx.saas_dir / "exposure_tenants.tsv").write_text(clean(tenants), encoding="utf-8")
    log.ok(f"SaaS exposure: {len(slugs)} name(s) tried, {len(tenants)} tenant(s) found, {len(findings)} candidate(s)")


def _misconfig_mapper(ctx: RunContext, dm: DependencyManager, log: Logger, slugs: list[str]):
    """Opt-in misconfig-mapper pass: exact names only, GET templates only, with a delay."""
    if not dm.is_available("misconfig-mapper"):
        log.warn("use_misconfig_mapper is on but misconfig-mapper is not installed "
                 "(go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest)")
        return [], []
    tdir = misconfig.find_templates_dir(getattr(ctx.scope, "misconfig_templates", ""))
    if tdir is None:
        log.warn("misconfig-mapper templates not found: set [saas_exposure] misconfig_templates to a folder with "
                 "services.json (fetch it once with: misconfig-mapper -update-templates -templates DIR)")
        return [], []
    try:
        services, refused = misconfig.select_services(
            misconfig.load_services(tdir), getattr(ctx.scope, "misconfig_services", []))
    except (OSError, ValueError) as exc:
        log.warn(f"misconfig-mapper templates unreadable ({exc})")
        return [], []
    for r in refused:
        log.info(f"misconfig-mapper: {r} not run")
    if not services:
        log.warn("misconfig-mapper: no runnable (plain GET) services selected")
        return [], []
    delay = int(getattr(ctx.scope, "misconfig_delay_ms", 1000) or 1000)
    timeout = min(1800, 60 + misconfig.request_count(services) * (delay // 1000 + 8))
    tenants, findings = [], []
    for slug in slugs:
        args = misconfig.build_args(slug, tdir, [s["id"] for s in services], delay)
        res = ev(ctx.console_dir, "E", dm.build_cmd("misconfig-mapper", args), timeout=timeout,
                 title=f"misconfig-mapper ({slug})")
        f, t = misconfig.parse_results(res.stdout, slug)
        findings += f
        tenants += t
    log.ok(f"misconfig-mapper: {len(services)} service template(s), {len(findings)} possible misconfiguration(s)")
    return tenants, findings
