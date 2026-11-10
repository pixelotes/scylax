"""Phase S: SaaS Security Posture Checks (Microsoft 365, GitHub, Google Workspace).

Authenticated, read-only configuration posture audit across SaaS tenants.
"""

from __future__ import annotations

import importlib

from recon.config import RunContext
from recon.deps import DependencyManager
from recon.runner import Logger
from recon.saas.common import Finding


def phaseS(ctx: RunContext, dm: DependencyManager, log: Logger) -> None:
    """Phase S: SaaS security posture assessment."""
    if not (getattr(ctx, "saas_posture", False) or getattr(ctx.scope, "saas_posture", False)):
        log.info("SaaS posture disabled (use --saas-posture)")
        return

    ctx.saas_dir.mkdir(parents=True, exist_ok=True)
    providers = getattr(ctx.scope, "saas_providers", None) or ["m365", "github", "google"]

    all_findings: list[Finding] = []

    for prov in providers:
        name = str(prov).strip().lower()
        if not name:
            continue
        mod_name = "google" if name in ("google", "gws") else name
        out_dir = ctx.saas_dir / mod_name

        try:
            mod = importlib.import_module(f"recon.saas.{mod_name}")
            runner_fn = getattr(mod, "run", None)
            if not callable(runner_fn):
                raise AttributeError(f"Module recon.saas.{mod_name} has no callable run() function")

            prov_findings = runner_fn(ctx, log, out_dir) or []
            all_findings.extend(prov_findings)
            log.ok(f"SaaS {mod_name}: {len(prov_findings)} findings")
        except Exception as exc:
            log.warn(f"SaaS provider {mod_name} failed: {exc}")
            continue

    posture_tsv = ctx.saas_dir / "posture_findings.tsv"
    lines: list[str] = []
    seen: set[str] = set()
    for f in all_findings:
        if hasattr(f, "row") and callable(f.row):
            row = f.row()
        elif isinstance(f, (list, tuple)) and len(f) >= 5:
            row = (
                str(f[0]).strip().lower(),
                str(f[1]).strip(),
                str(f[2]).strip(),
                str(f[3]).strip(),
                str(f[4]).strip(),
                str(f[5]).strip() if len(f) > 5 else "",
            )
        else:
            continue

        line_key = f"{row[0]}\t{row[1]}"
        if line_key not in seen:
            seen.add(line_key)
            lines.append("\t".join(row) + "\n")

    posture_tsv.write_text("".join(lines), encoding="utf-8")
