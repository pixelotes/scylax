"""Tests for phase-group profiles (recon.config PROFILES / --profile)."""

from __future__ import annotations

import unittest

from recon.config import (
    DEFAULT_PHASES,
    PROFILE_ALIASES,
    PROFILES,
    profile_names,
    profile_phases,
    resolve_profile,
)

_VALID_PHASES = set(DEFAULT_PHASES)


class TestProfiles(unittest.TestCase):
    def test_names_present(self) -> None:
        names = profile_names()
        for expected in ("passive", "light", "external", "blueteam", "purpleteam", "full"):
            self.assertIn(expected, names)

    def test_every_profile_uses_valid_phases(self) -> None:
        for name, cfg in PROFILES.items():
            for p in cfg["phases"]:
                self.assertIn(p, _VALID_PHASES, f"{name} references unknown phase {p!r}")
            self.assertTrue(cfg.get("desc"), f"{name} has no description")

    def test_phases_canonical_order_and_triage_last(self) -> None:
        for name in profile_names():
            ph = profile_phases(name)
            self.assertEqual(ph[-1], "T", f"{name} must end with triage phase T")
            order = {p: i for i, p in enumerate(DEFAULT_PHASES)}
            idx = [order[p] for p in ph]
            self.assertEqual(idx, sorted(idx), f"{name} phases not in canonical order")
            self.assertEqual(len(ph), len(set(ph)), f"{name} has duplicate phases")

    def test_passive_is_zero_touch(self) -> None:
        self.assertEqual(profile_phases("passive"), ["1", "2", "6", "7", "9", "T"])

    def test_light_has_no_nmap_phases(self) -> None:
        ph = set(profile_phases("light"))
        self.assertFalse(ph & {"4", "4b"}, "light must not include nmap port-scan phases")

    def test_aliases_resolve(self) -> None:
        self.assertEqual(resolve_profile("redteam"), PROFILES["external"])
        self.assertEqual(resolve_profile("osint"), PROFILES["passive"])
        self.assertEqual(resolve_profile("leaks"), PROFILES["intel"])
        for alias, target in PROFILE_ALIASES.items():
            self.assertIn(target, PROFILES, f"alias {alias} points at unknown {target}")

    def test_case_insensitive(self) -> None:
        self.assertEqual(profile_phases("BlueTeam"), profile_phases("blueteam"))

    def test_unknown_raises(self) -> None:
        with self.assertRaises(KeyError):
            resolve_profile("does-not-exist")

    def test_posture_toggles(self) -> None:
        for name in ("blueteam", "purpleteam", "full"):
            self.assertTrue(PROFILES[name].get("cloud_posture"), f"{name} should enable cloud_posture")
            self.assertTrue(PROFILES[name].get("saas_posture"), f"{name} should enable saas_posture")
        self.assertTrue(PROFILES["full"].get("use_prowler"), "full should enable Prowler")
        self.assertTrue(PROFILES["cloud"].get("cloud_posture"))
        self.assertTrue(PROFILES["saas"].get("saas_posture"))

    def test_full_covers_all_scan_phases(self) -> None:
        full = set(profile_phases("full"))
        # full should be the maximal profile: every phase except none missing
        self.assertEqual(full, _VALID_PHASES)


if __name__ == "__main__":
    unittest.main()
