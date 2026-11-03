"""Scope enforcement tests: private IPs, exclude/edge on hostname paths, CIDR entries."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from recon.config import RunContext, ScopeConfig
from recon.phases import active
from recon.runner import Logger
from recon.scope import ScopeGuard, is_public_ip, load_host_ips


class TestScopeHelpers(unittest.TestCase):
    def test_non_public_ips_rejected(self) -> None:
        for ip in ("10.0.0.1", "172.16.5.4", "192.168.1.1", "100.64.0.1",
                   "169.254.169.254", "127.0.0.1", "0.0.0.0", "::1", "fe80::1", "not-an-ip"):
            self.assertFalse(is_public_ip(ip), ip)
        self.assertTrue(is_public_ip("8.8.8.8"))

    def test_guard_cidr_and_hostnames(self) -> None:
        guard = ScopeGuard(
            ["203.0.113.0/24", "198.51.100.7"],
            {
                "app.example.com": {"93.184.216.34"},
                "edge.example.com": {"198.51.100.7"},
                "mixed.example.com": {"93.184.216.34", "203.0.113.9"},
                "internal.example.com": {"10.1.2.3"},
            },
        )
        self.assertTrue(guard.host_allowed("app.example.com"))
        self.assertTrue(guard.url_allowed("https://APP.example.com:8443/x"))
        self.assertFalse(guard.host_allowed("edge.example.com"))
        self.assertFalse(guard.host_allowed("mixed.example.com"))
        self.assertFalse(guard.host_allowed("internal.example.com"))
        self.assertFalse(guard.host_allowed("unknown.example.com"))
        self.assertFalse(guard.ip_allowed("203.0.113.200"))
        self.assertFalse(guard.url_allowed("https://169.254.169.254/latest"))


class TestActivePhasesScope(unittest.TestCase):
    def _ctx(self, root: Path) -> RunContext:
        scope = ScopeConfig(
            path=root / "scopes" / "synthetic.toml",
            name="synthetic",
            engagement="Synthetic",
            domains=["example.com"],
            hvt_ips=["93.184.216.34"],
            edge_ips=["198.51.100.7"],
            exclude_ips=["203.0.113.0/24"],
        )
        ctx = RunContext(root=root, scope=scope, run_date="2026-11-03", phases=["3", "8"])
        ctx.ensure_dirs()
        (ctx.osint_dir / "ip_host.tsv").write_text(
            "93.184.216.34\tapp.example.com\n"
            "198.51.100.7\tvpn.example.com\n"
            "203.0.113.9\tlegacy.example.com\n"
            "10.1.2.3\tintranet.example.com\n",
            encoding="utf-8",
        )
        (ctx.osint_dir / "resolved.txt").write_text(
            "app.example.com\nvpn.example.com\nlegacy.example.com\nintranet.example.com\n",
            encoding="utf-8",
        )
        return ctx

    def _dm(self) -> mock.Mock:
        dm = mock.Mock()
        dm.run_dir = None
        dm.is_available.return_value = True
        dm.build_cmd.side_effect = lambda name, args: [name, *args]
        return dm

    def test_phase3_httpx_targets_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            with mock.patch.object(active, "ev"), mock.patch.object(active, "http_get"), \
                    mock.patch.object(active, "_native_http_probe", return_value=[]):
                active.phase3(ctx, self._dm(), Logger(ctx.run_dir / "log.txt"))
            targets = (ctx.web_dir / "httpx_targets.txt").read_text().split()
            self.assertEqual(targets, ["app.example.com"])

    def test_phase8_nuclei_targets_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            (ctx.osint_dir / "discovered_targets.txt").write_text(
                "93.184.216.34\n10.1.2.3\n169.254.169.254\n", encoding="utf-8"
            )
            (ctx.web_dir / "httpx_all.txt").write_text(
                "https://app.example.com [200] [App] [nginx] []\n"
                "https://vpn.example.com [200] [VPN] [] []\n"
                "https://legacy.example.com [403] [] [] []\n"
                "https://intranet.example.com [200] [] [] []\n",
                encoding="utf-8",
            )
            with mock.patch.object(active, "ev"):
                active.phase8(ctx, self._dm(), Logger(ctx.run_dir / "log.txt"))
            targets = (ctx.web_dir / "nuclei_targets.txt").read_text().split()
            self.assertEqual(sorted(targets), ["https://93.184.216.34", "https://app.example.com"])

    def test_load_host_ips_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(load_host_ips(Path(td)), {})



class TestOwnership(unittest.TestCase):
    def test_owned_allowlist(self) -> None:
        # Owned/allowlist checks need globally routable IPs (TEST-NET ranges are rejected)
        guard = ScopeGuard([], {"cdn.example.com": {"1.1.1.1"}, "app.example.com": {"93.184.216.34"}},
                           owned=["93.184.216.0/24"])
        self.assertTrue(guard.ip_allowed("1.1.1.1"))  # light probing still allowed
        self.assertFalse(guard.ip_allowed("1.1.1.1", require_owned=True))
        self.assertTrue(guard.url_allowed("https://app.example.com", require_owned=True))
        self.assertFalse(guard.url_allowed("https://cdn.example.com", require_owned=True))

    def test_owned_entries_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "owned.txt").write_text("# azure\n198.51.100.198\tvm-lb\n203.0.113.0/25\n", encoding="utf-8")
            scope = ScopeConfig(path=root / "s.toml", name="s", engagement="s",
                                hvt_ips=["203.0.113.110"], owned_ips_file="owned.txt")
            self.assertTrue(scope.ownership_enforced)
            self.assertEqual(sorted(scope.owned_entries()), ["198.51.100.198", "203.0.113.0/25", "203.0.113.110"])



if __name__ == "__main__":
    unittest.main()
