"""Offline checks that keep the baseline stock and the objective honest."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BaselineTests(unittest.TestCase):
    def test_compose_has_no_config_override(self):
        compose = (ROOT / "lab" / "docker-compose.yml").read_text()
        for marker in ("php.ini", "php -d", "0.0.0.0:", "privileged: true",
                       "network_mode: host", "seccomp=unconfined"):
            self.assertNotIn(marker, compose, marker)

    def test_setup_writes_no_php_ini(self):
        setup = (ROOT / "lab" / "setup.sh").read_text()
        self.assertNotIn('cat > "$ROOT/php.ini"', setup)
        self.assertFalse((ROOT / "lab" / "php.ini").exists())

    def test_goal_is_rce_and_unmet(self):
        goal = (ROOT / "GOAL.md").read_text()
        self.assertIn("RCE", goal)
        self.assertIn("NOT ACHIEVED", goal)
        self.assertIn("stock", goal.lower())
        self.assertIn("G2", goal)

    def test_scope_is_stock_first(self):
        scope = (ROOT / "docs" / "TARGET_SCOPE.md").read_text().lower()
        self.assertIn("stock default", scope)
        self.assertIn("no php.ini", scope)
        self.assertNotIn("all bundled extensions", scope)

    def test_blind_spots_are_deferred(self):
        for name in ("extensions", "bundled_libs", "non_memory",
                     "build_matrix", "fuzz_targets", "patch_history"):
            data = json.loads((ROOT / "research" / f"{name}.json").read_text())
            self.assertTrue(data["status"].startswith("deferred"),
                            f"{name}: {data['status']}")


if __name__ == "__main__":
    unittest.main()
