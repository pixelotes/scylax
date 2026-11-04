"""Phase E - third-party SaaS exposure (Atlassian Cloud): fixed anonymous read-only checks."""

from __future__ import annotations

from recon import saas_exposure
from recon.config import RunContext
from recon.deps import DependencyManager
from recon.phases.osint import NON_PUBLIC_TLDS
from recon.resilience import AdaptiveLimiter
from recon.runner import Logger, http_get, record_virtual_cmd


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

    clean = lambda rows: "".join("\t".join(c.replace("\t", " ").replace("\n", " ") for c in r) + "\n" for r in rows)
    (ctx.saas_dir / "exposure_findings.tsv").write_text(clean(findings), encoding="utf-8")
    (ctx.saas_dir / "exposure_tenants.tsv").write_text(clean(tenants), encoding="utf-8")
    log.ok(f"SaaS exposure: {len(slugs)} name(s) tried, {len(tenants)} tenant(s) found, {len(findings)} candidate(s)")
