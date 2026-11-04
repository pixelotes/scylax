"""Plugin registry containing all tools, remote services, and cloud providers."""

from __future__ import annotations

import os
from typing import Sequence

from recon.plugins.base import Plugin, PluginKind
from recon.runner import have, run_cmd


def _check_httpx(use_docker: bool) -> tuple[bool, str, str]:
    docker_ready = have("docker")
    if use_docker and docker_ready:
        return True, "docker", "docker (projectdiscovery/httpx:latest)"

    if have("httpx"):
        res = run_cmd(["httpx", "-version"], timeout=5)
        text = res.stdout + res.stderr
        if "projectdiscovery" in text.lower() or "httpx" in text.lower():
            line = text.splitlines()[0].strip() if text.splitlines() else "installed"
            return True, "native", line[:80]

    if docker_ready:
        return True, "docker", "docker (projectdiscovery/httpx:latest)"

    return False, "missing", "not installed (projectdiscovery httpx required)"


def _check_gh(use_docker: bool) -> tuple[bool, str, str]:
    if not have("gh"):
        return False, "missing", "not installed (brew install gh / apt install gh)"
    res = run_cmd(["gh", "auth", "status"], timeout=10)
    if res.returncode == 0:
        ver = run_cmd(["gh", "--version"], timeout=5)
        line = ver.stdout.splitlines()[0].strip() if ver.stdout.splitlines() else "installed"
        return True, "native", f"{line[:60]} (authenticated)"
    return False, "missing", "installed but not authenticated (run 'gh auth login')"


def _check_gam(use_docker: bool) -> tuple[bool, str, str]:
    gam_bin = os.environ.get("GAM_PATH") or ("gam" if have("gam") else None)
    if not gam_bin:
        return False, "missing", "not installed (set GAM_PATH or install gam)"
    res = run_cmd([gam_bin, "version"], timeout=5)
    line = (res.stdout or res.stderr).splitlines()
    detail = line[0].strip()[:80] if line else "installed"
    return True, "native", detail


PLUGINS: dict[str, Plugin] = {
    # ── Network & Core OSINT Binaries ──
    "dig": Plugin(
        id="dig",
        name="Domain Information Groper (dig)",
        kind=PluginKind.BINARY,
        description="DNS resolution and posture interrogation (NS, MX, SPF, DMARC, CAA, AXFR)",
        phases=("2",),
        native_bin="dig",
        version_args=("-v",),
        docker_image="alpine/bind-tools:latest",
        install_macos="xcode-select --install (or brew install bind)",
        install_linux="sudo apt install dnsutils",
    ),
    "whois": Plugin(
        id="whois",
        name="WHOIS Client",
        kind=PluginKind.BINARY,
        description="Domain and IP ASN / organisation lookup",
        phases=("2",),
        native_bin="whois",
        version_args=("--version",),
        docker_image=None,
        install_macos="Pre-installed on macOS (or brew install whois)",
        install_linux="sudo apt install whois",
    ),
    "nmap": Plugin(
        id="nmap",
        name="Network Mapper (nmap)",
        kind=PluginKind.BINARY,
        description="High-value target port scanning, service detection, and banner fingerprinting",
        phases=("4", "4b", "A", "G", "W"),
        native_bin="nmap",
        version_args=("--version",),
        docker_image="instrumentisto/nmap:latest",
        install_macos="brew install nmap",
        install_linux="sudo apt install nmap",
    ),
    "subfinder": Plugin(
        id="subfinder",
        name="ProjectDiscovery Subfinder",
        kind=PluginKind.BINARY,
        description="Fast passive subdomain enumeration from public CT and OSINT feeds",
        phases=("1",),
        native_bin="subfinder",
        version_args=("-version",),
        docker_image="projectdiscovery/subfinder:latest",
        install_macos="brew install subfinder",
        install_linux="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "amass": Plugin(
        id="amass",
        name="OWASP Amass",
        kind=PluginKind.DOCKER,
        description="In-depth passive subdomain enumeration",
        phases=("1", "9"),
        native_bin="amass",
        version_args=("-version",),
        docker_image="caffix/amass:latest",
        prefer_docker_when_missing=True,
        install_macos="brew install amass (or Docker caffix/amass)",
        install_linux="docker pull caffix/amass:latest",
    ),
    "dnsx": Plugin(
        id="dnsx",
        name="ProjectDiscovery dnsx",
        kind=PluginKind.BINARY,
        description="Fast multi-purpose DNS resolution and classification toolkit",
        phases=("2",),
        native_bin="dnsx",
        version_args=("-version",),
        docker_image="projectdiscovery/dnsx:latest",
        install_macos="brew install dnsx",
        install_linux="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    ),
    "httpx": Plugin(
        id="httpx",
        name="ProjectDiscovery httpx",
        kind=PluginKind.BINARY,
        description="High-throughput HTTP probing, technology detection, and title extraction",
        phases=("3", "5"),
        native_bin="httpx",
        version_args=("-version",),
        docker_image="projectdiscovery/httpx:latest",
        install_macos="brew install httpx",
        install_linux="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        custom_checker=_check_httpx,
    ),
    "whatweb": Plugin(
        id="whatweb",
        name="WhatWeb",
        kind=PluginKind.DOCKER,
        description="Web technology fingerprinting scanner",
        phases=("5",),
        native_bin="whatweb",
        version_args=("--version",),
        docker_image="bberastegui/whatweb:latest",
        prefer_docker_when_missing=True,
        install_macos="docker pull bberastegui/whatweb:latest",
        install_linux="sudo apt install whatweb (or Docker)",
    ),
    "nuclei": Plugin(
        id="nuclei",
        name="ProjectDiscovery Nuclei",
        kind=PluginKind.DOCKER,
        description="Non-intrusive template-based vulnerability and misconfiguration detection",
        phases=("8",),
        native_bin="nuclei",
        version_args=("-version",),
        docker_image="projectdiscovery/nuclei:latest",
        prefer_docker_when_missing=True,
        install_macos="brew install nuclei (or Docker)",
        install_linux="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    "gobuster": Plugin(
        id="gobuster",
        name="Gobuster",
        kind=PluginKind.DOCKER,
        description="Content discovery (directory/file brute-forcing) for exposed paths",
        phases=("C",),
        native_bin="gobuster",
        version_args=("version",),
        docker_image="ghcr.io/oj/gobuster:latest",
        prefer_docker_when_missing=False,
        install_macos="brew install gobuster",
        install_linux="go install github.com/OJ/gobuster/v3@latest (or apt install gobuster)",
    ),
    "gitleaks": Plugin(
        id="gitleaks",
        name="Gitleaks",
        kind=PluginKind.DOCKER,
        description="Lightweight secret scanner for git repositories (alternative to TruffleHog)",
        phases=("9",),
        native_bin="gitleaks",
        version_args=("version",),
        docker_image="zricethezav/gitleaks:latest",
        prefer_docker_when_missing=False,
        install_macos="brew install gitleaks",
        install_linux="go install github.com/gitleaks/gitleaks/v8@latest (or apt install gitleaks)",
    ),
    "trufflehog": Plugin(
        id="trufflehog",
        name="TruffleHog",
        kind=PluginKind.DOCKER,
        description="Secret and credential leak detection in local repositories and filesystems",
        phases=("9",),
        native_bin="trufflehog",
        version_args=("--version",),
        docker_image="trufflesecurity/trufflehog:latest",
        prefer_docker_when_missing=True,
        install_macos="brew install trufflehog (or Docker)",
        install_linux="docker pull trufflesecurity/trufflehog:latest",
    ),
    "theharvester": Plugin(
        id="theharvester",
        name="theHarvester",
        kind=PluginKind.DOCKER,
        description="OSINT tool for gathering domain emails, subdomains, employee names, and public exposures",
        phases=("9",),
        native_bin="theHarvester",
        version_args=("-h",),
        docker_image="theharvester/theharvester:latest",
        prefer_docker_when_missing=True,
        install_macos="brew install theharvester (or Docker theharvester/theharvester)",
        install_linux="sudo apt install -y theharvester (or Docker theharvester/theharvester)",
    ),
    "spiderfoot": Plugin(
        id="spiderfoot",
        name="SpiderFoot",
        kind=PluginKind.DOCKER,
        description="Automated OSINT intelligence gathering, domain email extraction, and asset reconnaissance",
        phases=("9",),
        native_bin="spiderfoot",
        version_args=("-h",),
        docker_image="spiderfoot/spiderfoot:latest",
        prefer_docker_when_missing=True,
        install_macos="brew install spiderfoot (or Docker spiderfoot/spiderfoot)",
        install_linux="pip install spiderfoot (or Docker spiderfoot/spiderfoot)",
    ),

    # ── Intelligence & API Services ──
    "shodan": Plugin(
        id="shodan",
        name="Shodan REST API",
        kind=PluginKind.API,
        description="Host exposure history, historical open ports, and Shodan vulnerability data",
        phases=("7",),
        required_env=("SHODAN_API_KEY",),
        install_macos="export SHODAN_API_KEY=your_key",
        install_linux="export SHODAN_API_KEY=your_key",
    ),
    "hibp": Plugin(
        id="hibp",
        name="HaveIBeenPwned API",
        kind=PluginKind.API,
        description="Public and enterprise domain breach and leaked account exposure audit",
        phases=("2", "6", "9"),
        required_env=("HIBP_API_KEY",),
        install_macos="export HIBP_API_KEY=your_key (https://haveibeenpwned.com/API/Key)",
        install_linux="export HIBP_API_KEY=your_key (https://haveibeenpwned.com/API/Key)",
    ),
    "xposedornot": Plugin(
        id="xposedornot",
        name="XposedOrNot API",
        kind=PluginKind.API,
        description="Free, keyless per-account breach lookup used when no HIBP API key is set",
        phases=("9",),
        install_macos="No setup required (public API, about 1 request per second)",
        install_linux="No setup required (public API, about 1 request per second)",
    ),

    # ── Cloud Infrastructure CLIs ──
    "az": Plugin(
        id="az",
        name="Azure CLI (az)",
        kind=PluginKind.HYBRID,
        description="Azure Resource Graph queries for Public IPs, NSG rules, and cloud posture",
        phases=("A",),
        native_bin="az",
        version_args=("--version",),
        docker_image="mcr.microsoft.com/azure-cli:latest",
        install_macos="brew install azure-cli && az login && az extension add --name resource-graph",
        install_linux="curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash",
    ),
    "gcloud": Plugin(
        id="gcloud",
        name="Google Cloud SDK (gcloud)",
        kind=PluginKind.HYBRID,
        description="GCP compute external addresses, instances, forwarding rules, and VPC firewalls",
        phases=("G",),
        native_bin="gcloud",
        version_args=("--version",),
        docker_image="gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine",
        install_macos="brew install --cask google-cloud-sdk && gcloud auth login",
        install_linux="sudo snap install google-cloud-cli --classic && gcloud auth login",
    ),
    "aws": Plugin(
        id="aws",
        name="AWS CLI (aws)",
        kind=PluginKind.HYBRID,
        description="AWS Elastic IPs, EC2, ALB/NLB, RDS, CloudFront, and Security Groups",
        phases=("W",),
        native_bin="aws",
        version_args=("--version",),
        docker_image="amazon/aws-cli:latest",
        install_macos="brew install awscli && aws configure",
        install_linux="sudo apt install awscli (or official AWS CLI v2 installer)",
    ),
    "prowler": Plugin(
        id="prowler",
        name="Prowler CSPM",
        kind=PluginKind.DOCKER,
        description="Optional in-depth Cloud Security Posture Management scanner across AWS, Azure, GCP",
        phases=("A", "G", "W"),
        native_bin="prowler",
        version_args=("-v",),
        docker_image="toniblyx/prowler:latest",
        prefer_docker_when_missing=True,
        install_macos="pipx install prowler (or Docker toniblyx/prowler)",
        install_linux="pipx install prowler (or Docker toniblyx/prowler)",
    ),

    # ── SaaS & Identity Providers ──
    "gh": Plugin(
        id="gh",
        name="GitHub CLI (gh)",
        kind=PluginKind.HYBRID,
        description="GitHub public leak search (phase 9) and organization posture audit (phase S)",
        phases=("9", "S"),
        native_bin="gh",
        version_args=("--version",),
        install_macos="brew install gh && gh auth login",
        install_linux="sudo apt install gh && gh auth login",
        custom_checker=_check_gh,
    ),
    "m365_graph": Plugin(
        id="m365_graph",
        name="Microsoft Graph API Client",
        kind=PluginKind.API,
        description="Entra ID / M365 authentication, Conditional Access, and identity posture audit",
        phases=("S",),
        required_env=("M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"),
        install_macos="export M365_TENANT_ID=... M365_CLIENT_ID=... M365_CLIENT_SECRET=...",
        install_linux="export M365_TENANT_ID=... M365_CLIENT_ID=... M365_CLIENT_SECRET=...",
    ),
    "gam": Plugin(
        id="gam",
        name="Google Apps Manager (GAM)",
        kind=PluginKind.BINARY,
        description="Google Workspace super admin security configuration and identity audit",
        phases=("S",),
        native_bin="gam",
        version_args=("version",),
        install_macos="bash <(curl -s -S -L https://gam-shortn.appspot.com/gam-install)",
        install_linux="bash <(curl -s -S -L https://gam-shortn.appspot.com/gam-install)",
        custom_checker=_check_gam,
    ),
}


def get_plugin(plugin_id: str) -> Plugin | None:
    return PLUGINS.get(plugin_id.lower())


def list_plugins() -> list[Plugin]:
    return list(PLUGINS.values())

