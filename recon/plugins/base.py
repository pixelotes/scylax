"""Base classes and types for the Recon Plugin & Provider system."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence

from recon.runner import have, run_cmd


class PluginKind(str, Enum):
    BINARY = "binary"      # Native executable (e.g. nmap, dig, whois, subfinder)
    DOCKER = "docker"      # Can run in Docker container as primary or fallback
    API = "api"            # Cloud/Remote HTTP API (e.g. shodan, haveibeenpwned, m365_graph)
    HYBRID = "hybrid"      # Binary or API integration (e.g. gh CLI with GitHub API)


@dataclass
class PluginStatus:
    plugin: "Plugin"
    available: bool
    provider: str          # "native", "docker", "api", "missing"
    detail: str
    needed_for_phases: bool = True
    is_required_for_active: bool = False


@dataclass
class Plugin:
    id: str
    name: str
    kind: PluginKind
    description: str
    phases: tuple[str, ...] = field(default_factory=tuple)
    required_env: tuple[str, ...] = field(default_factory=tuple)
    native_bin: str | None = None
    version_args: tuple[str, ...] = ("--version",)
    docker_image: str | None = None
    prefer_docker_when_missing: bool = False
    install_macos: str = ""
    install_linux: str = ""
    custom_checker: Callable[[bool], tuple[bool, str, str]] | None = None

    def check_availability(self, use_docker: bool = False) -> tuple[bool, str, str]:
        """Return (is_available, provider, detail)."""
        if self.custom_checker:
            return self.custom_checker(use_docker)

        if self.kind == PluginKind.API:
            # Check required env vars
            if not self.required_env:
                return True, "api", "public API"
            missing = [var for var in self.required_env if not os.environ.get(var, "").strip()]
            if missing:
                return False, "missing", f"missing env: {', '.join(missing)}"
            return True, "api", "API key configured"

        # Binary / Docker
        docker_ready = have("docker")
        if use_docker and self.docker_image and docker_ready:
            return True, "docker", f"docker ({self.docker_image})"

        if self.native_bin:
            bin_to_use = self.native_bin
            if not have(bin_to_use) and have(bin_to_use.lower()):
                bin_to_use = bin_to_use.lower()
            if have(bin_to_use):
                detail = self._probe_native_version(bin_name=bin_to_use)
                return True, "native", detail

        if self.prefer_docker_when_missing and self.docker_image and docker_ready:
            return True, "docker", f"docker ({self.docker_image})"

        return False, "missing", "not installed"

    def _probe_native_version(self, bin_name: str | None = None) -> str:
        target_bin = bin_name or self.native_bin
        if not target_bin:
            return "installed"
        try:
            res = run_cmd([target_bin, *self.version_args], timeout=5)
            line = (res.stdout or res.stderr).splitlines()
            if line:
                return line[0].strip()[:80]
            return "installed"
        except Exception:
            return "installed"

    def build_cmd(
        self,
        args: Sequence[str],
        *,
        use_docker: bool = False,
        mount_dir: Path | None = None,
    ) -> list[str]:
        """Construct the executable command (native or docker run)."""
        is_avail, provider, _ = self.check_availability(use_docker)
        if provider == "docker" and self.docker_image:
            cmd = ["docker", "run", "--rm"]
            if mount_dir:
                cmd.extend(["-v", f"{mount_dir.resolve()}:/data"])

            # Cloud credentials mounts and environment pass-through
            if self.id in ("az", "azure") and (Path.home() / ".azure").is_dir():
                cmd.extend(["-v", f"{Path.home() / '.azure'}:/root/.azure"])
            if self.id in ("gcloud", "gcp") and (Path.home() / ".config" / "gcloud").is_dir():
                cmd.extend(["-v", f"{Path.home() / '.config' / 'gcloud'}:/root/.config/gcloud"])
            if self.id in ("aws", "prowler"):
                if (Path.home() / ".aws").is_dir():
                    cmd.extend(["-v", f"{Path.home() / '.aws'}:/root/.aws:ro"])
                for env_var in (
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN",
                    "AWS_DEFAULT_REGION",
                    "AWS_PROFILE",
                ):
                    if env_var in os.environ:
                        cmd.extend(["-e", env_var])

            # Path rewriting for mounted run_dir
            mapped_args = []
            m_res = str(mount_dir.resolve()) if mount_dir else None
            m_str = str(mount_dir) if mount_dir else None
            for a in args:
                s = str(a)
                if m_res and (s == m_res or s.startswith(m_res + "/")):
                    s = "/data" + s[len(m_res):]
                elif m_str and (s == m_str or s.startswith(m_str + "/")):
                    s = "/data" + s[len(m_str):]
                mapped_args.append(s)

            # Container entrypoint handling
            if self.id in ("az", "azure"):
                cmd.extend([self.docker_image, "az", *mapped_args])
            elif self.id in ("gcloud", "gcp"):
                cmd.extend([self.docker_image, "gcloud", *mapped_args])
            else:
                cmd.extend([self.docker_image, *mapped_args])
            return cmd

        # Native binary
        bin_name = self.native_bin or self.id
        if not have(bin_name) and have(bin_name.lower()):
            bin_name = bin_name.lower()
        return [bin_name, *(str(a) for a in args)]
