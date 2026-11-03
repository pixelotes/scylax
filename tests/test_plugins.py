"""Unit tests for the Plugin & Provider architecture."""

import unittest
from pathlib import Path

from recon.deps import DependencyManager, PHASE_DEPENDENCIES
from recon.plugins import PLUGINS, get_plugin, list_plugins
from recon.plugins.base import PluginKind


class TestPluginsSystem(unittest.TestCase):
    def test_plugins_registry(self) -> None:
        """Verify all expected core plugins are registered with correct types."""
        self.assertGreaterEqual(len(list_plugins()), 18)

        # Network binaries
        nmap = get_plugin("nmap")
        self.assertIsNotNone(nmap)
        self.assertEqual(nmap.kind, PluginKind.BINARY)

        # Remote APIs
        shodan = get_plugin("shodan")
        self.assertIsNotNone(shodan)
        self.assertEqual(shodan.kind, PluginKind.API)
        self.assertIn("SHODAN_API_KEY", shodan.required_env)

        hibp = get_plugin("hibp")
        self.assertIsNotNone(hibp)
        self.assertEqual(hibp.kind, PluginKind.API)
        self.assertIn("HIBP_API_KEY", hibp.required_env)

        # SaaS & Cloud
        m365 = get_plugin("m365_graph")
        self.assertIsNotNone(m365)
        self.assertEqual(m365.kind, PluginKind.API)

        gh = get_plugin("gh")
        self.assertIsNotNone(gh)
        self.assertEqual(gh.kind, PluginKind.HYBRID)

        # OSINT Email gathering plugins
        th = get_plugin("theharvester")
        self.assertIsNotNone(th)
        self.assertEqual(th.kind, PluginKind.DOCKER)

        sf = get_plugin("spiderfoot")
        self.assertIsNotNone(sf)
        self.assertEqual(sf.kind, PluginKind.DOCKER)

    def test_phase_dependencies_declared(self) -> None:
        """Verify phases have declared required and optional dependencies."""
        self.assertIn("1", PHASE_DEPENDENCIES)
        self.assertIn("4", PHASE_DEPENDENCIES)
        self.assertIn("7", PHASE_DEPENDENCIES)
        self.assertIn("S", PHASE_DEPENDENCIES)

        # Phase 4 requires nmap
        req_4, opt_4 = PHASE_DEPENDENCIES["4"]
        self.assertIn("nmap", req_4)

        # Phase 7 has optional shodan
        req_7, opt_7 = PHASE_DEPENDENCIES["7"]
        self.assertIn("shodan", opt_7)

        # Phase S has SaaS plugins
        req_s, opt_s = PHASE_DEPENDENCIES["S"]
        self.assertIn("m365_graph", opt_s)
        self.assertIn("gh", opt_s)

    def test_dependency_manager_check_all(self) -> None:
        """Verify DependencyManager checks all registered plugins."""
        dm = DependencyManager(use_docker=False)
        statuses = dm.check_all(active_phases=["2", "4", "7"])
        self.assertTrue(len(statuses) >= 18)

        status_map = {st.plugin.id: st for st in statuses}
        self.assertTrue(status_map["nmap"].is_required_for_active)
        self.assertFalse(status_map["shodan"].is_required_for_active)

    def test_docker_command_rewriting(self) -> None:
        """Verify path rewriting when running a plugin through Docker."""
        dm = DependencyManager(use_docker=True)
        mount_dir = Path("/tmp/test_recon_mount")
        cmd = dm.build_cmd(
            "nmap",
            ["-sT", "-iL", "/tmp/test_recon_mount/targets.txt", "-oA", "/tmp/test_recon_mount/scan/pass1"],
            mount_dir=mount_dir,
        )
        self.assertEqual(cmd[0], "docker")
        self.assertEqual(cmd[1], "run")
        self.assertIn("/data/targets.txt", cmd)
        self.assertIn("/data/scan/pass1", cmd)


if __name__ == "__main__":
    unittest.main()

