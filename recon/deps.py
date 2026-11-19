"""Plugin manager and dependency resolution for pipeline phases."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from recon.plugins import PLUGINS, Plugin, get_plugin
from recon.plugins.base import PluginStatus
from recon.runner import have


# Phase -> (Required Plugin IDs, Optional Plugin IDs)
PHASE_DEPENDENCIES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "1": ((), ("subfinder", "amass")),
    "2": (("dig", "whois"), ("dnsx", "hibp")),
    "3": ((), ("httpx",)),
    "4": (("nmap",), ()),
    "4b": (("nmap",), ()),
    "5": ((), ("httpx", "whatweb")),
    "6": ((), ("hibp",)),
    "7": ((), ("shodan",)),
    "8": ((), ("nuclei",)),
    "9": ((), ("theharvester", "amass", "spiderfoot", "hibp", "xposedornot", "trufflehog", "gh")),
    "A": ((), ("az", "nmap", "prowler")),
    "G": ((), ("gcloud", "nmap", "prowler")),
    "W": ((), ("aws", "nmap", "prowler")),
    "S": ((), ("m365_graph", "gh", "gam")),
    "C": ((), ("gobuster",)),
    "E": ((), ()),
    "T": ((), ()),
}


class DependencyManager:
    """Manages plugin discovery, availability probing, command wrapping, and phase dependency enforcement."""

    def __init__(self, use_docker: bool = False, run_dir: Path | None = None) -> None:
        self.use_docker = use_docker
        self.run_dir = run_dir
        self._plugins = dict(PLUGINS)

    def docker_available(self) -> bool:
        return have("docker")

    def get_plugin(self, tool_or_plugin_id: str) -> Plugin | None:
        return get_plugin(tool_or_plugin_id)

    def check_all(self, active_phases: Sequence[str] | None = None) -> list[PluginStatus]:
        """Probe all plugins and evaluate requirements for the requested phases."""
        req_set: set[str] = set()
        opt_set: set[str] = set()

        phases = active_phases if active_phases is not None else tuple(PHASE_DEPENDENCIES.keys())
        for p in phases:
            if p in PHASE_DEPENDENCIES:
                r, o = PHASE_DEPENDENCIES[p]
                req_set.update(r)
                opt_set.update(o)

        statuses: list[PluginStatus] = []
        for plugin in self._plugins.values():
            is_avail, provider, detail = plugin.check_availability(use_docker=self.use_docker)
            needed = (plugin.id in req_set) or (plugin.id in opt_set)
            is_req = plugin.id in req_set

            statuses.append(
                PluginStatus(
                    plugin=plugin,
                    available=is_avail,
                    provider=provider,
                    detail=detail,
                    needed_for_phases=needed,
                    is_required_for_active=is_req,
                )
            )
        return statuses

    def is_available(self, plugin_id: str) -> bool:
        p = self.get_plugin(plugin_id)
        if not p:
            return False
        avail, _, _ = p.check_availability(use_docker=self.use_docker)
        return avail

    def get_provider(self, plugin_id: str) -> str:
        p = self.get_plugin(plugin_id)
        if not p:
            return "missing"
        _, provider, _ = p.check_availability(use_docker=self.use_docker)
        return provider

    def build_cmd(
        self,
        tool_name: str,
        args: Sequence[str],
        *,
        mount_dir: Path | None = None,
    ) -> list[str]:
        p = self.get_plugin(tool_name)
        if p:
            m_dir = mount_dir or self.run_dir
            return p.build_cmd(args, use_docker=self.use_docker, mount_dir=m_dir)
        return [tool_name, *(str(a) for a in args)]

    def print_report(
        self,
        statuses: Sequence[PluginStatus] | None = None,
        file: Any = sys.stderr,
    ) -> bool:
        """Display an aligned plugin dependency table."""
        if statuses is None:
            statuses = self.check_all()

        col_w = {"name": 14, "kind": 8, "phases": 12, "status": 10, "provider": 10, "detail": 32}
        header = (
            f"{'Plugin':<{col_w['name']}} "
            f"{'Kind':<{col_w['kind']}} "
            f"{'Phases':<{col_w['phases']}} "
            f"{'Status':<{col_w['status']}} "
            f"{'Provider':<{col_w['provider']}} "
            f"{'Detail'}"
        )
        sep = "-" * 88

        lines = [header, sep]
        missing_required: list[PluginStatus] = []
        missing_optional: list[PluginStatus] = []

        for st in statuses:
            if not st.needed_for_phases:
                continue

            phases_str = ",".join(st.plugin.phases)
            if st.available:
                status_str = "READY"
                prov_str = st.provider
            else:
                if st.is_required_for_active:
                    status_str = "MISSING *"
                    missing_required.append(st)
                else:
                    status_str = "OPTIONAL"
                    missing_optional.append(st)
                prov_str = "-"

            row = (
                f"{st.plugin.id:<{col_w['name']}} "
                f"{st.plugin.kind.value:<{col_w['kind']}} "
                f"{phases_str:<{col_w['phases']}} "
                f"{status_str:<{col_w['status']}} "
                f"{prov_str:<{col_w['provider']}} "
                f"{st.detail[:40]}"
            )
            lines.append(row)

        lines.append(sep)

        # Actionable instructions
        if missing_required or missing_optional:
            lines.append("\nPlugin setup instructions:")
            if self.docker_available() and not self.use_docker:
                lines.append("  💡 Tip: Docker is available. Missing CLI tools can run containerized with --docker\n")

            if missing_required:
                lines.append("🔴 REQUIRED plugins missing (phases cannot run without these):")
                for st in missing_required:
                    lines.append(f"  * {st.plugin.name} [{st.plugin.id}]")
                    if st.plugin.install_macos:
                        lines.append(f"      macOS: {st.plugin.install_macos}")
                    if st.plugin.install_linux:
                        lines.append(f"      Linux: {st.plugin.install_linux}")

            if missing_optional:
                lines.append("\n🟡 OPTIONAL plugins missing (phases will run in degraded mode):")
                for st in missing_optional:
                    lines.append(f"  * {st.plugin.name} [{st.plugin.id}]")
                    if st.plugin.install_macos:
                        lines.append(f"      macOS: {st.plugin.install_macos}")
                    if st.plugin.install_linux:
                        lines.append(f"      Linux: {st.plugin.install_linux}")

        output = "\n".join(lines) + "\n"
        if file is not None:
            file.write(output)
            file.flush()

        return len(missing_required) == 0

    def tool_versions(self) -> str:
        statuses = self.check_all()
        lines: list[str] = []
        for st in statuses:
            if st.available:
                lines.append(f"{st.plugin.id} ({st.provider}): {st.detail}")
        return "\n".join(lines)


# Backwards-compatibility alias for code importing TOOLS or ToolSpec
@dataclass(frozen=True)
class ToolSpec:
    name: str
    required: bool
    phases: tuple[str, ...]
    native_bin: str
    version_args: tuple[str, ...]
    docker_image: str | None
    install_macos: str
    install_linux: str
    description: str
    prefer_docker_when_missing: bool = False
