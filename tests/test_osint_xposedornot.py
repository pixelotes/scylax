"""XposedOrNot fallback for per-account breach checks (no network)."""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.phases import osint  # noqa: E402


class TestXposedOrNotFallback(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ctx = SimpleNamespace(console_dir=Path(self.tmp.name), run_dir=Path(self.tmp.name), scope=None, resume=False)
        self.log = mock.Mock()
        osint._HIBP_BREACH_CACHE.clear()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _fake_get(self, url, headers=None, timeout=0):
        if "xposedornot" in url and "found%40" in url:
            return 200, {"breaches": [["Adobe", "Unknown2024"]]}
        if "xposedornot" in url:
            return 404, None
        if url.endswith("/breach/Adobe"):
            return 200, {"Title": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 152445165,
                         "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}
        return 404, None

    def test_names_are_enriched_and_not_found_is_empty(self) -> None:
        with mock.patch.object(osint, "http_get_json", side_effect=self._fake_get), \
             mock.patch.object(osint.time, "sleep"):
            res = osint._xposedornot_account_breaches(
                self.ctx, self.log, ["found@example.com", "clean@example.com"]
            )
        self.assertEqual([r["name"] for r in res], ["Adobe", "Unknown2024"])
        adobe = res[0]
        self.assertEqual(adobe["email"], "found@example.com")
        self.assertIn("Passwords", adobe["data_classes"])
        self.assertEqual(adobe["breach_date"], "2013-10-04")
        self.assertEqual(res[1]["data_classes"], "")
        self.assertTrue((Path(self.tmp.name) / "commands.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
