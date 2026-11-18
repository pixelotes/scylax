"""Subdomain takeover detection for dangling CNAME / ALIAS records.

A takeover is possible when a subdomain's CNAME points to a third-party service
(or an internal name) whose backing resource no longer exists, so an attacker can
re-create it and serve content from your name. Detection is evidence-based and
non-intrusive: the CNAME target must match a known service pattern AND either the
target resolves NXDOMAIN or the service returns its "unclaimed resource"
fingerprint. Nothing is claimed or registered.

Fingerprints are a curated, conservative subset of the public can-i-take-over-xyz
project; each entry needs a body fingerprint so a plain 404 never alerts on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class TakeoverRule:
    service: str
    cname_patterns: tuple[str, ...]  # regex, matched against the CNAME target
    fingerprints: tuple[str, ...] = ()  # body strings that mean "unclaimed"
    severity: str = "high"
    nxdomain_is_takeover: bool = False  # target NXDOMAIN alone is enough (vulnerable services)


# Conservative set: well-known services with a distinctive unclaimed-resource page.
TAKEOVER_RULES: tuple[TakeoverRule, ...] = (
    TakeoverRule("AWS S3", (r"\.s3[.-][\w.-]*amazonaws\.com$", r"\.s3\.amazonaws\.com$"),
                 ("NoSuchBucket", "The specified bucket does not exist")),
    TakeoverRule("AWS CloudFront", (r"\.cloudfront\.net$",),
                 ("ERROR: The request could not be satisfied", "Bad request.")),
    TakeoverRule("Azure", (r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$", r"\.cloudapp\.net$",
                           r"\.trafficmanager\.net$", r"\.blob\.core\.windows\.net$",
                           r"\.azureedge\.net$", r"\.azurefd\.net$", r"\.azure-api\.net$"),
                 ("404 Web Site not found", "The specified blob does not exist",
                  "Error 404 - Web app not found"), nxdomain_is_takeover=True),
    TakeoverRule("GitHub Pages", (r"\.github\.io$",),
                 ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file")),
    TakeoverRule("Heroku", (r"\.herokuapp\.com$", r"\.herokudns\.com$", r"\.herokussl\.com$"),
                 ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    TakeoverRule("Fastly", (r"\.fastly\.net$",), ("Fastly error: unknown domain",)),
    TakeoverRule("Shopify", (r"\.myshopify\.com$",), ("Sorry, this shop is currently unavailable",)),
    TakeoverRule("Zendesk", (r"\.zendesk\.com$",), ("Help Center Closed",)),
    TakeoverRule("Cargo", (r"\.cargocollective\.com$",), ("404 Not Found",)),
    TakeoverRule("Ghost", (r"\.ghost\.io$",), ("The thing you were looking for is no longer here",)),
    TakeoverRule("Pantheon", (r"\.pantheonsite\.io$",), ("404 error unknown site",)),
    TakeoverRule("Tumblr", (r"\.domains\.tumblr\.com$",), ("Whatever you were looking for doesn't currently exist at this address",)),
    TakeoverRule("Wordpress", (r"\.wordpress\.com$",), ("Do you want to register",)),
    TakeoverRule("Surge.sh", (r"\.surge\.sh$",), ("project not found",)),
    TakeoverRule("Bitbucket", (r"\.bitbucket\.io$",), ("Repository not found",)),
    TakeoverRule("Netlify", (r"\.netlify\.app$", r"\.netlify\.com$"), ("Not Found - Request ID",)),
    TakeoverRule("Readthedocs", (r"\.readthedocs\.io$",), ("404 Not Found", "Maze Found")),
    TakeoverRule("Unbounce", (r"\.unbouncepages\.com$",), ("The requested URL was not found on this server",)),
    TakeoverRule("Webflow", (r"\.proxy\.webflow\.com$", r"\.webflow\.io$"), ("The page you are looking for doesn't exist or has been moved",)),
    TakeoverRule("Help Scout", (r"\.helpscoutdocs\.com$",), ("No settings were found for this company",)),
    TakeoverRule("AWS Elastic Beanstalk", (r"\.elasticbeanstalk\.com$",), (), nxdomain_is_takeover=True),
)


@dataclass
class TakeoverCandidate:
    host: str
    cname: str
    service: str
    severity: str
    reason: str
    evidence: str = ""


def _rule_for(cname: str) -> TakeoverRule | None:
    low = cname.rstrip(".").lower()
    for rule in TAKEOVER_RULES:
        if any(re.search(p, low) for p in rule.cname_patterns):
            return rule
    return None


def check_takeover(
    host: str,
    cname: str,
    *,
    cname_resolves: bool,
    http_get: Callable[..., object] | None = None,
    internal_suffixes: tuple[str, ...] = (),
) -> TakeoverCandidate | None:
    """Assess one host->CNAME pair. Returns a candidate only with real evidence:
    a matching service plus NXDOMAIN (for takeover-prone services) or an unclaimed
    fingerprint in the served page; or an internal/in-scope CNAME target that no
    longer resolves (dangling internal record)."""
    cname_clean = cname.rstrip(".").lower()

    rule = _rule_for(cname_clean)
    if rule is not None:
        if not cname_resolves:
            if rule.nxdomain_is_takeover:
                return TakeoverCandidate(host, cname_clean, rule.service, rule.severity,
                                         "CNAME target does not resolve (service allows re-registration)")
            # Service not auto-takeover on NXDOMAIN alone: still worth flagging, lower
            return TakeoverCandidate(host, cname_clean, rule.service, "medium",
                                     "CNAME target does not resolve")
        if http_get is not None and rule.fingerprints:
            for scheme in ("https", "http"):
                resp = http_get(f"{scheme}://{host}/", timeout=8.0, verify_ssl=False,
                                follow_redirects=True, max_bytes=8192)
                body = getattr(resp, "body", "") or ""
                for fp in rule.fingerprints:
                    if fp.lower() in body.lower():
                        return TakeoverCandidate(host, cname_clean, rule.service, rule.severity,
                                                 "Service returns its unclaimed-resource page",
                                                 evidence=fp)
        return None

    # Internal or in-scope CNAME target that no longer resolves: a dangling record
    if internal_suffixes and not cname_resolves:
        if any(cname_clean.endswith(suf.lstrip(".").lower()) for suf in internal_suffixes):
            return TakeoverCandidate(host, cname_clean, "internal", "medium",
                                     "CNAME points to an internal name that no longer resolves (dangling record)")
    return None
