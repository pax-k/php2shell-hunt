"""Offline inventory invariants for the imported verifier set.

These do not prove a vulnerability. They keep the published PoC tree inside the
scope the repository claims: loopback defaults, no remote-target packaging, and
no arbitrary command shell-out.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POC = ROOT / "poc"

LOOPBACK_MARKERS = ("loopback", "127.0.0.1", "127.0.0.0", "localhost", "::1")
FORBIDDEN_LITERALS = ("0.0.0.0",)


class PocInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.files = sorted(POC.glob("*.py"))
        self.assertTrue(self.files, "poc/ has no Python files")

    def test_all_pocs_parse(self) -> None:
        for path in self.files:
            source = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=path.name):
                ast.parse(source)

    def test_targeted_pocs_default_to_loopback(self) -> None:
        targeted = [p for p in self.files if "--target" in p.read_text(
            encoding="utf-8", errors="replace")]
        self.assertTrue(targeted, "no verifier exposes --target")
        for path in targeted:
            source = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=path.name):
                self.assertTrue(
                    any(marker in source for marker in LOOPBACK_MARKERS),
                    f"{path.name} exposes --target without a loopback default")

    def test_no_wildcard_bind_literals(self) -> None:
        for path in self.files:
            source = path.read_text(encoding="utf-8", errors="replace")
            for literal in FORBIDDEN_LITERALS:
                with self.subTest(path=path.name, literal=literal):
                    self.assertNotIn(literal, source,
                                     f"{path.name} binds or targets {literal}")

    def test_no_shell_true(self) -> None:
        for path in self.files:
            source = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=path.name):
                self.assertNotIn("shell=True", source,
                                 f"{path.name} shells out with shell=True")


if __name__ == "__main__":
    unittest.main()
