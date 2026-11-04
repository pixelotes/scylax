"""Scope enforcement helpers shared by the active phases.

Every active probe must pass through these checks so that ``exclude_ips``,
``edge_ips`` and non-public address space are honoured regardless of whether
the target is expressed as an IP, a hostname or a URL.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from pathlib import Path
from typing import Dict, Iterable, List, Set

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(entries: Iterable[str]) -> List[IPNetwork]:
    """Parse IPs and CIDRs from scope entries, ignoring anything unparseable."""
    nets: List[IPNetwork] = []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(str(e).strip(), strict=False))
        except ValueError:
            continue
    return nets


def ip_in(ip: str, nets: Iterable[IPNetwork]) -> bool:
    """True if ``ip`` falls inside any of ``nets`` (CIDR-aware)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def is_public_ip(ip: str) -> bool:
    """True only for valid, globally routable addresses.

    Rejects RFC1918, CGNAT (100.64/10), loopback, link-local (incl. cloud
    metadata 169.254.169.254), multicast and reserved space.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def load_host_ips(osint_dir: Path) -> Dict[str, Set[str]]:
    """Map hostname -> resolved IPs from ``osint/ip_host.tsv`` (written by phase 2)."""
    mapping: Dict[str, Set[str]] = {}
    tsv = osint_dir / "ip_host.tsv"
    if not tsv.is_file():
        return mapping
    for line in tsv.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            mapping.setdefault(parts[1].lower().rstrip("."), set()).add(parts[0])
    return mapping


class ScopeGuard:
    """Decides whether a host, IP or URL may be actively probed."""

    def __init__(
        self,
        blocked: Iterable[str],
        host_ips: Dict[str, Set[str]],
        owned: Iterable[str] | None = None,
    ):
        self.blocked = parse_networks(blocked)
        self.host_ips = host_ips
        # None = no ownership allowlist configured (any public IP is acceptable)
        self.owned = parse_networks(owned) if owned is not None else None

    def is_owned(self, ip: str) -> bool:
        return self.owned is None or ip_in(ip, self.owned)

    def ip_allowed(self, ip: str, require_owned: bool = False) -> bool:
        if not is_public_ip(ip) or ip_in(ip, self.blocked):
            return False
        return self.is_owned(ip) if require_owned else True

    def host_allowed(self, host: str, require_owned: bool = False) -> bool:
        """Hostnames are allowed only if every resolved IP is allowed.

        Unknown hostnames (not resolved in phase 2) are refused: we cannot
        prove they are outside excluded/edge/private space.
        """
        host = host.strip().lower().rstrip(".")
        if not host:
            return False
        try:
            ipaddress.ip_address(host.strip("[]"))
            return self.ip_allowed(host.strip("[]"), require_owned)
        except ValueError:
            pass
        ips = self.host_ips.get(host)
        if not ips:
            return False
        return all(self.ip_allowed(ip, require_owned) for ip in ips)

    def url_allowed(self, url: str, require_owned: bool = False) -> bool:
        if "://" not in url:
            url = f"https://{url}"
        return self.host_allowed(urllib.parse.urlparse(url).hostname or "", require_owned)


def guard_for(ctx) -> ScopeGuard:
    """ScopeGuard that blocks ``exclude_ips`` and ``edge_ips`` for a run."""
    return ScopeGuard(
        list(ctx.scope.exclude_ips) + list(ctx.scope.edge_ips),
        load_host_ips(ctx.osint_dir),
        ctx.scope.owned_entries() if ctx.scope.ownership_enforced else None,
    )
