"""TLS posture, well-known pivots, SaaS exposure."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from recon import saas_exposure, tlsposture, wellknown

XML = """<nmaprun><host><address addr="203.0.113.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><script id="ssl-cert" output="">
<table key="subject"><elem key="commonName">www.acme.com</elem></table>
<table key="issuer"><elem key="commonName">www.acme.com</elem></table>
<table key="pubkey"><elem key="type">rsa</elem><elem key="bits">1024</elem></table>
<table key="extensions"><table><elem key="name">X509v3 Subject Alternative Name</elem>
<elem key="value">DNS:www.acme.com, DNS:vpn.acme.com, DNS:*.other.net</elem></table></table>
<elem key="sig_algo">sha1WithRSAEncryption</elem>
<table key="validity"><elem key="notBefore">2020-01-01T00:00:00</elem><elem key="notAfter">2026-11-20T00:00:00</elem></table>
</script><script id="ssl-enum-ciphers" output="">
<table key="TLSv1.0"><table key="ciphers"><table><elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem><elem key="strength">C</elem></table></table></table>
<table key="TLSv1.2"><table key="ciphers"><table><elem key="name">TLS_RSA_WITH_AES_128_GCM_SHA256</elem><elem key="strength">A</elem></table></table></table>
<elem key="least strength">C</elem></script></port></ports></host></nmaprun>"""


class TlsTests(unittest.TestCase):
    def test_findings_and_pivots_from_nmap_xml(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "svc.xml"
            p.write_text(XML)
            svcs = tlsposture.parse_nmap_tls(p)
        rows = {r[1]: r for r in tlsposture.tls_findings(svcs, "2026-11-04")}
        self.assertEqual(rows["tls-proto:203.0.113.5:443"][0], "medium")
        self.assertEqual(rows["tls-cipher:203.0.113.5:443"][0], "low")
        self.assertIn("tls-cert:203.0.113.5:443:key", rows)
        self.assertIn("tls-cert:203.0.113.5:443:sig", rows)
        self.assertIn("tls-cert:203.0.113.5:443:expiring", rows)
        self.assertIn("tls-cert:203.0.113.5:443:selfsigned", rows)
        names = {n for _, _, n in tlsposture.cert_names(svcs)}
        self.assertEqual(names, {"www.acme.com", "vpn.acme.com", "other.net"})
        self.assertTrue(tlsposture.in_scope("vpn.acme.com", ["acme.com"]))
        self.assertFalse(tlsposture.in_scope("other.net", ["acme.com"]))

    def test_missing_or_broken_xml_is_empty(self):
        self.assertEqual(tlsposture.parse_nmap_tls(Path("/nonexistent.xml")), [])


class WellKnownTests(unittest.TestCase):
    def test_security_txt_problems_and_pivots(self):
        txt = "Contact: mailto:s@acme.com\nExpires: 2025-01-01T00:00:00Z\nPolicy: https://trust.acme.com/p\n"

        def fetch(url, **k):
            if url.endswith("security.txt"):
                return SimpleNamespace(status=200, body=txt)
            if url.endswith("openid-configuration"):
                return SimpleNamespace(status=200, body='{"issuer":"https://sso.acme.com","x":"https://evil.net"}')
            return SimpleNamespace(status=404, body="")

        findings, pivots = wellknown.run(["acme.com"], ["https://app.acme.com"], {"sso.acme.com"}, fetch, "2026-11-04")
        self.assertEqual([f[1] for f in findings], ["wellknown:security-txt:acme.com:expired"])
        got = {(p[2], p[4]) for p in pivots}
        self.assertIn(("trust.acme.com", "no"), got)
        self.assertIn(("sso.acme.com", "yes"), got)
        self.assertNotIn("evil.net", {p[2] for p in pivots})
        self.assertNotIn(("acme.com", "no"), got)  # the apex itself is never "missing"

    def test_missing_security_txt_is_info(self):
        findings, _ = wellknown.run(["acme.com"], [], set(), lambda u, **k: SimpleNamespace(status=404, body=""), "2026-11-04")
        self.assertEqual((findings[0][0], findings[0][1]), ("info", "wellknown:security-txt:acme.com"))


def fake_atlassian(routes):
    def fetch(url, **k):
        for suffix, (status, body) in routes.items():
            if url.endswith(suffix) or suffix in url:
                return SimpleNamespace(status=status, body=body)
        return SimpleNamespace(status=404, body="")
    return fetch


class SaasExposureTests(unittest.TestCase):
    def test_slugs_from_domains_and_extra(self):
        self.assertEqual(saas_exposure.candidate_slugs(["acme.com", "acme.io", "x.y"], ["Acme-Corp"]), ["acme-corp", "acme"])

    def test_exposed_jira_and_confluence_are_reported_with_counts_only(self):
        trace = []
        fetch = fake_atlassian({
            "/serverInfo": (200, '{"deploymentType":"Cloud","baseUrl":"https://acme.atlassian.net"}'),
            "/rest/api/2/search": (200, '{"total":42,"issues":[]}'),
            "/project/search": (200, '{"total":3,"values":[{"key":"SEC"}]}'),
            "/user/picker": (401, ""),
            "/dashboard/search": (401, ""),
            "/wiki/rest/api/space": (200, '{"results":[{"key":"HR"}]}'),
            "/wiki/rest/api/content": (200, '{"results":[{"id":"1"}]}'),
        })
        tenants, findings = saas_exposure.check_atlassian("acme", fetch, lambda c, s: trace.append((c, s)))
        keys = {f[1]: f for f in findings}
        self.assertEqual(set(keys), {"saas-exposure:jira-issues:acme", "saas-exposure:jira-projects:acme",
                                     "saas-exposure:confluence-spaces:acme", "saas-exposure:confluence-pages:acme"})
        self.assertIn("42", keys["saas-exposure:jira-issues:acme"][5])
        self.assertNotIn("SEC", " ".join(str(f) for f in findings))  # no record contents kept
        self.assertEqual({t[1] for t in tenants}, {"jira", "confluence"})
        self.assertTrue(all("curl" in c for c, _ in trace))

    def test_protected_tenant_has_no_findings_and_missing_tenant_is_silent(self):
        protected = fake_atlassian({
            "/serverInfo": (200, '{"deploymentType":"Cloud"}'),
            "/wiki/rest/api/space": (401, ""),
        })
        tenants, findings = saas_exposure.check_atlassian("acme", protected, lambda c, s: None)
        self.assertEqual(findings, [])
        self.assertIn(("acme", "confluence", "exists (anonymous access denied)"), tenants)
        tenants, findings = saas_exposure.check_atlassian("nope", fake_atlassian({}), lambda c, s: None)
        self.assertEqual((tenants, findings), ([], []))

    def test_retired_search_endpoint_falls_back(self):
        fetch = fake_atlassian({
            "/serverInfo": (200, '{"deploymentType":"Cloud"}'),
            "/rest/api/2/search": (410, ""),
            "/rest/api/3/search/jql": (200, '{"issues":[{"id":"1"}]}'),
        })
        _, findings = saas_exposure.check_atlassian("acme", fetch, lambda c, s: None)
        self.assertIn("saas-exposure:jira-issues:acme", {f[1] for f in findings})


if __name__ == "__main__":
    unittest.main()
