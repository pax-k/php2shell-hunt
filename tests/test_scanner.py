"""Offline scanner tests. No socket may be opened; scan() is mocked."""

import io
import itertools
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from scanner import check


class ScopeTests(unittest.TestCase):
    def test_loopback_accepts_lab_targets(self):
        for host in ("localhost", "127.0.0.1", "127.9.9.9", "::1"):
            self.assertTrue(check.is_loopback(host), host)
            check.ensure_loopback(host)

    def test_loopback_rejects_remote_and_names(self):
        for host in ("192.0.2.1", "10.0.0.1", "example.com", "0.0.0.0"):
            self.assertFalse(check.is_loopback(host), host)
            with self.assertRaises(check.ScopeError):
                check.ensure_loopback(host)

    def test_parse_target_rejects_remote(self):
        with self.assertRaises(check.ScopeError):
            check.parse_target("http://192.0.2.1:8080")

    def test_parse_target_accepts_ipv6(self):
        target = check.parse_target("http://[::1]:8080/x")
        self.assertEqual(target["host"], "::1")
        self.assertEqual(target["port"], 8080)
        self.assertEqual(target["path"], "/x")


class VersionTests(unittest.TestCase):
    def test_boundaries(self):
        cases = {
            "8.2.34": True,
            "8.2.35": False,
            "8.3.35": True,
            "8.3.36": False,
            "8.4.26": True,
            "8.4.27": False,
            "8.5.11": True,
            "8.5.12": False,
            "5.3.29": False,
            "5.4.0": True,
        }
        for version, expected in cases.items():
            self.assertEqual(
                check.is_vulnerable(check.parse_version(version)),
                expected, version)

    def test_unknown_version(self):
        self.assertIsNone(check.is_vulnerable(None))


class CliTests(unittest.TestCase):
    def setUp(self):
        network_patch = patch.object(
            check.socket, "create_connection",
            side_effect=AssertionError("network access is forbidden"))
        self.network = network_patch.start()
        self.addCleanup(network_patch.stop)

    def run_cli(self, verdicts, *options):
        targets = [f"http://127.0.0.1:{18000 + i}"
                   for i in range(len(verdicts))]
        results = {
            target: {
                "target": target,
                "verdict": verdict,
                "confidence": "LOW",
                "version": None,
                "sapi": None,
                "checks": {},
                "chains": [],
                "recommendation": "",
                "error": None,
            }
            for target, verdict in zip(targets, verdicts)
        }
        argv = []
        if len(targets) == 1:
            argv.append(targets[0])
        else:
            argv.extend(["--targets", "-", "--threads", "2"])
        argv.extend(options)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(check.sys, "stdin", io.StringIO("\n".join(targets))), \
                patch.object(check, "scan",
                             side_effect=lambda url, *a, **k: results[url]), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = check.main(argv)
        self.network.assert_not_called()
        return code, stdout.getvalue()

    def test_single_target_exit_codes(self):
        for verdict, expected in (
            ("VULNERABLE", 0), ("LIKELY_VULNERABLE", 0),
            ("PATCHED", 1), ("UNKNOWN", 2), ("ERROR", 2),
        ):
            with self.subTest(verdict=verdict):
                code, output = self.run_cli([verdict], "--json")
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(output)["verdict"], verdict)

    def test_only_all_patched_returns_one(self):
        code, _ = self.run_cli(["PATCHED", "PATCHED"], "--json")
        self.assertEqual(code, 1)

    def test_inconclusive_batch_returns_two(self):
        for verdicts in (
            ("PATCHED", "UNKNOWN"), ("PATCHED", "ERROR"),
            ("UNKNOWN", "ERROR"), ("UNKNOWN", "UNKNOWN"), ("ERROR", "ERROR"),
        ):
            for order in set(itertools.permutations(verdicts)):
                with self.subTest(verdicts=order):
                    code, _ = self.run_cli(order, "--json")
                    self.assertEqual(code, 2)

    def test_vulnerable_precedence(self):
        for vulnerable in ("VULNERABLE", "LIKELY_VULNERABLE"):
            for other in ("PATCHED", "UNKNOWN", "ERROR"):
                for order in ((vulnerable, other), (other, vulnerable)):
                    with self.subTest(verdicts=order):
                        code, _ = self.run_cli(order, "--json")
                        self.assertEqual(code, 0)

    def test_quiet_preserves_exit_code_and_filters(self):
        code, output = self.run_cli(["PATCHED", "UNKNOWN"], "--quiet")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        code, output = self.run_cli(["PATCHED", "VULNERABLE"], "--quiet")
        self.assertEqual(code, 0)
        self.assertIn("Verdict: VULNERABLE", output)
        self.assertNotIn("Verdict: PATCHED", output)


if __name__ == "__main__":
    unittest.main()
