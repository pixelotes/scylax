import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from recon.osint_keys import collect_keys, write_configs


class OsintKeysTests(unittest.TestCase):
    def test_collect_prefers_scope_then_env_and_includes_shodan(self):
        scope = SimpleNamespace(intel_keys={"virustotal_api_key": "vt"}, shodan_api_key="sh")
        os.environ["CHAOS_API_KEY"] = "ch"
        try:
            keys = collect_keys(scope, "")
        finally:
            del os.environ["CHAOS_API_KEY"]
        self.assertEqual(keys, {"virustotal_api_key": "vt", "chaos_api_key": "ch", "shodan_api_key": "sh"})

    def test_write_configs_private_and_partial_creds_skipped(self):
        keys = {"shodan_api_key": "S", "passivetotal_username": "u", "censys_api_id": "i", "censys_api_secret": "s"}
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / ".keys"
            sf, am, sources = write_configs(keys, dest, lambda p: f"/data/{p.name}")
            self.assertEqual(sf, "/data/subfinder-provider.yaml")
            self.assertEqual(am, "/data/amass-config.yaml")
            # passivetotal lacks its api key -> skipped; censys is subfinder-only
            self.assertEqual(sources, ["shodan", "censys"])
            sf_text = (dest / "subfinder-provider.yaml").read_text()
            self.assertIn('censys: ["i:s"]', sf_text)
            self.assertNotIn("passivetotal", sf_text)
            am_text = (dest / "amass-datasources.yaml").read_text()
            self.assertIn("name: Shodan", am_text)
            self.assertNotIn("PassiveTotal", am_text)
            self.assertEqual(os.stat(dest / "subfinder-provider.yaml").st_mode & 0o777, 0o600)

    def test_no_keys_writes_nothing_useful(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(write_configs({}, Path(d) / "k"), (None, None, []))


if __name__ == "__main__":
    unittest.main()
