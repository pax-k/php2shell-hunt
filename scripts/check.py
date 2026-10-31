#!/usr/bin/env python3
"""Offline consistency gate for php2shell-hunt.

This does not prove a vulnerability. It proves the repository is internally
consistent: required files exist, manifests parse, no row claims coverage
without a receipt, the lab remains unprivileged, and the Python surfaces
compile.
"""

from __future__ import annotations

import compileall
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "GOAL.md",
    "README.md",
    "AGENTS.md",
    "PROGRESS.md",
    "opencode.json",
    "scanner/check.py",
    "poc/lib.py",
    "poc/verify_session_injection.py",
    "tests/test_scanner.py",
    "tests/test_pocs.py",
    "tests/test_baseline.py",
    "lab/setup.sh",
    "lab/docker-compose.yml",
    "scripts/scan.sh",
    "scripts/lab_matrix.sh",
    "docs/PIPELINE.md",
    "docs/RCE_PATH.md",
    "docs/TARGET_SCOPE.md",
    "docs/BLIND_SPOTS.md",
    "docs/SCANNER.md",
    "docs/TESTING.md",
    "docs/LAB_MATRIX.md",
    "docs/STATUS.md",
    "detection/README.md",
    "detection/suricata.rules",
    "detection/sigma/php2shell_upload_progress.yml",
    "detection/modsecurity.conf",
    "detection/openresty.lua",
    "research/extensions.json",
    "research/bundled_libs.json",
    "research/non_memory.json",
    "research/build_matrix.json",
    "research/fuzz_targets.json",
    "research/patch_history.json",
]

forbidden_compose = (
    "privileged: true",
    "privileged: True",
    "seccomp=unconfined",
    "network_mode: host",
    "0.0.0.0:",
)


class Gate:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checks = 0

    def check(self, condition: bool, message: str) -> None:
        self.checks += 1
        if not condition:
            self.errors.append(message)

    def fail(self, message: str) -> None:
        self.check(False, message)


def validate_rows(path: Path, rows_key: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get(rows_key)
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path.name}: missing non-empty {rows_key!r}")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path.name}: {rows_key}[{index}] is not an object")
        status = row.get("status")
        if not isinstance(status, str) or not status.strip():
            raise ValueError(f"{path.name}: {rows_key}[{index}] has no status")
        if status.strip().lower() == "covered" and not row.get("receipt"):
            raise ValueError(
                f"{path.name}: {rows_key}[{index}] claims covered without receipt")


def main() -> int:
    gate = Gate()
    for relative in REQUIRED:
        gate.check((ROOT / relative).is_file(), f"missing required file: {relative}")

    for relative in ("research/extensions.json",
                     "research/bundled_libs.json",
                     "research/non_memory.json",
                     "research/build_matrix.json",
                     "research/fuzz_targets.json",
                     "research/patch_history.json"):
        path = ROOT / relative
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            gate.check(bool(data.get("scope")), f"{relative}: missing scope")
            gate.check(bool(data.get("status")), f"{relative}: missing status")
        except (OSError, ValueError) as exc:
            gate.fail(f"{relative}: {exc}")

    for relative, key in (
        ("research/extensions.json", "extensions"),
        ("research/bundled_libs.json", "libraries"),
        ("research/non_memory.json", "classes"),
        ("research/build_matrix.json", "rows"),
        ("research/fuzz_targets.json", "targets"),
        ("research/patch_history.json", "targets"),
    ):
        try:
            validate_rows(ROOT / relative, key)
        except (OSError, ValueError) as exc:
            gate.fail(str(exc))

    compose = (ROOT / "lab/docker-compose.yml").read_text(encoding="utf-8")
    for marker in forbidden_compose:
        gate.check(marker not in compose,
                   f"lab/docker-compose.yml contains forbidden {marker!r}")
    gate.check("php.ini" not in compose,
               "lab/docker-compose.yml mounts or references php.ini")
    gate.check(not (ROOT / "lab/php.ini").exists(),
               "lab/php.ini exists; the baseline must use image defaults")
    setup = (ROOT / "lab/setup.sh").read_text(encoding="utf-8")
    gate.check('cat > "$ROOT/php.ini"' not in setup,
               "lab/setup.sh writes a php.ini override")
    goal = (ROOT / "GOAL.md").read_text(encoding="utf-8")
    gate.check("NOT ACHIEVED" in goal, "GOAL.md does not state current status")
    gate.check("RCE" in goal, "GOAL.md does not name the RCE objective")

    for relative in ("scanner/check.py", "poc/lib.py"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        gate.check("is_loopback" in source, f"{relative}: no loopback guard")
        gate.check("refusing non-loopback" in source,
                   f"{relative}: no scope rejection message")

    for directory in ("scanner", "poc", "scripts", "tests"):
        ok = compileall.compile_dir(str(ROOT / directory), quiet=1,
                                    force=True)
        gate.check(bool(ok), f"{directory}: compile failed")

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/inventory_extensions.py"),
         "--self-test"],
        capture_output=True, text=True, timeout=30)
    gate.check(result.returncode == 0,
               f"inventory self-test failed: {result.stderr.strip()}")

    gate.check("no license" in (ROOT / "README.md").read_text(
        encoding="utf-8").lower(), "README does not state the license decision")

    if gate.errors:
        for error in gate.errors:
            print(f"[fail] {error}")
        print(f"[gate] {len(gate.errors)} failure(s) across {gate.checks} checks")
        return 1
    print(f"[gate] {gate.checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
