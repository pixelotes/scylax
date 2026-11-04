"""TLS posture and certificate pivots, read from the nmap service-scan XML.

Nothing is sent that phase 4 does not already send: ``ssl-cert`` and
``ssl-enum-ciphers`` run inside the existing per-IP service scan, and this module
only parses what they recorded. Findings are candidates for the auditor to
validate, in the TSV shape the triage phase ingests:

    severity, key, service, resource, title, detail, target
"""

from __future__ import annotations

import datetime
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

LEGACY_PROTOCOLS = {"SSLv2": "high", "SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "medium"}
_GRADE_SEVERITY = {"F": "medium", "E": "medium", "D": "medium", "C": "low"}
_WEAK_SIG = re.compile(r"(?i)md[245]|sha1")


@dataclass
class TlsService:
    ip: str
    port: str
    protocols: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # proto -> [(cipher, grade)]
    least_strength: str = ""
    cn: str = ""
    issuer_cn: str = ""
    sans: list[str] = field(default_factory=list)
    key_type: str = ""
    key_bits: int = 0
    sig_algo: str = ""
    not_after: str = ""


def _elem(node: ET.Element, key: str) -> str:
    e = node.find(f"./elem[@key='{key}']")
    return (e.text or "").strip() if e is not None and e.text else ""


def _parse_cert(script: ET.Element, svc: TlsService) -> None:
    subject = script.find("./table[@key='subject']")
    issuer = script.find("./table[@key='issuer']")
    pubkey = script.find("./table[@key='pubkey']")
    validity = script.find("./table[@key='validity']")
    svc.cn = _elem(subject, "commonName") if subject is not None else ""
    svc.issuer_cn = _elem(issuer, "commonName") if issuer is not None else ""
    if pubkey is not None:
        svc.key_type = _elem(pubkey, "type")
        bits = _elem(pubkey, "bits")
        svc.key_bits = int(bits) if bits.isdigit() else 0
    svc.sig_algo = _elem(script, "sig_algo")
    if validity is not None:
        svc.not_after = _elem(validity, "notAfter")[:10]
    for ext in script.findall("./table[@key='extensions']/table"):
        if "Subject Alternative Name" in _elem(ext, "name"):
            svc.sans = [s.strip()[4:] for s in _elem(ext, "value").split(",") if s.strip().startswith("DNS:")]


def _parse_ciphers(script: ET.Element, svc: TlsService) -> None:
    for proto in script.findall("./table"):
        key = proto.get("key", "")
        if not key.startswith(("SSL", "TLS")):
            continue
        ciphers = [
            (_elem(c, "name"), _elem(c, "strength"))
            for c in proto.findall("./table[@key='ciphers']/table")
        ]
        svc.protocols[key] = ciphers
    svc.least_strength = _elem(script, "least strength")


def parse_nmap_tls(xml_path: Path) -> list[TlsService]:
    """TLS services found in one nmap XML file (empty when the file is missing or invalid)."""
    try:
        root = ET.parse(xml_path).getroot()
    except (OSError, ET.ParseError):
        return []
    out: list[TlsService] = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")
        ip = addr.get("addr", "") if addr is not None else ""
        for port in host.findall("./ports/port"):
            svc = TlsService(ip=ip, port=port.get("portid", ""))
            seen = False
            for script in port.findall("script"):
                if script.get("id") == "ssl-cert":
                    _parse_cert(script, svc)
                    seen = True
                elif script.get("id") == "ssl-enum-ciphers":
                    _parse_ciphers(script, svc)
                    seen = True
            if seen:
                out.append(svc)
    return out


def tls_findings(
    services: list[TlsService], today: str | None = None
) -> list[tuple[str, str, str, str, str, str, str]]:
    today = today or datetime.date.today().isoformat()
    soon = (datetime.date.fromisoformat(today) + datetime.timedelta(days=30)).isoformat()
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for s in services:
        where = f"{s.ip}:{s.port}"
        legacy = [p for p in s.protocols if p in LEGACY_PROTOCOLS]
        if legacy:
            sev = "high" if any(LEGACY_PROTOCOLS[p] == "high" for p in legacy) else "medium"
            rows.append((sev, f"tls-proto:{where}", "tls", where, "Legacy TLS/SSL protocol versions enabled",
                         f"{where} accepts {', '.join(sorted(legacy))}", where))
        grade = s.least_strength.strip().upper()[:1]
        if grade in _GRADE_SEVERITY:
            weak = sorted({c for ciphers in s.protocols.values() for c, g in ciphers if g.upper() in "CDEF" and g})
            rows.append((_GRADE_SEVERITY[grade], f"tls-cipher:{where}", "tls", where,
                         f"Weak TLS cipher suites (weakest grade {grade})",
                         f"{where}: {', '.join(weak[:5])}{' ...' if len(weak) > 5 else ''}", where))
        if s.key_type.lower() == "rsa" and 0 < s.key_bits < 2048:
            rows.append(("medium", f"tls-cert:{where}:key", "tls", where, "Weak certificate key",
                         f"{where} RSA {s.key_bits} bits", where))
        if s.sig_algo and _WEAK_SIG.search(s.sig_algo):
            rows.append(("medium", f"tls-cert:{where}:sig", "tls", where, "Certificate signed with a weak algorithm",
                         f"{where} {s.sig_algo}", where))
        if s.not_after and today <= s.not_after <= soon:
            rows.append(("low", f"tls-cert:{where}:expiring", "tls", where, "Certificate expires within 30 days",
                         f"{where} expires {s.not_after}", where))
        if s.cn and s.cn == s.issuer_cn:
            rows.append(("low", f"tls-cert:{where}:selfsigned", "tls", where, "Self-signed certificate",
                         f"{where} CN={s.cn}", where))
    return rows


def cert_names(services: list[TlsService]) -> list[tuple[str, str, str]]:
    """(ip:port, hostname) pairs from certificate CN/SAN, lower-cased, wildcards stripped."""
    out: list[tuple[str, str, str]] = []
    for s in services:
        for name in [s.cn, *s.sans]:
            n = name.strip().lower().removeprefix("*.")
            if n and "." in n and not re.fullmatch(r"[\d.]+", n) and (s.ip, s.port, n) not in out:
                out.append((s.ip, s.port, n))
    return out


def in_scope(name: str, domains: list[str]) -> bool:
    return any(name == d.lower() or name.endswith("." + d.lower()) for d in domains)
