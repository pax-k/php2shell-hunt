"""Contract tests for POC scope and command handling. No network is used."""

import subprocess
import sys
import unittest
from pathlib import Path

from poc import lib

ROOT = Path(__file__).resolve().parents[1]


class AllowlistTests(unittest.TestCase):
    def test_allowlisted_commands(self):
        for command in ("id", "uname", "whoami"):
            self.assertEqual(lib.require_command(command), command)

    def test_rejects_arbitrary_commands(self):
        for command in ("sh", "bash -c id", "system", "curl", ""):
            with self.assertRaises(lib.ScopeError):
                lib.require_command(command)


class ScopeTests(unittest.TestCase):
    def test_accepts_loopback(self):
        for target in ("http://127.0.0.1:18091",
                       "http://localhost:18091",
                       "http://[::1]:18091"):
            parsed = lib.parse_target(target)
            self.assertTrue(lib.is_loopback(parsed["host"]))

    def test_rejects_remote(self):
        for target in ("http://192.0.2.1:80", "http://example.com",
                       "https://10.0.0.1"):
            with self.assertRaises(lib.ScopeError):
                lib.parse_target(target)


class VerifierTests(unittest.TestCase):
    def test_help_and_remote_rejection(self):
        script = ROOT / "poc" / "verify_session_injection.py"
        help_run = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(help_run.returncode, 0, help_run.stderr)
        self.assertNotIn("--command", help_run.stdout)
        remote = subprocess.run(
            [sys.executable, str(script), "--target", "http://192.0.2.1"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(remote.returncode, 2, remote.stderr)
        self.assertIn("refusing non-loopback", remote.stderr)


if __name__ == "__main__":
    unittest.main()
