#!/usr/bin/env python3
"""Inventory loaded PHP extensions against research/extensions.json."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research" / "extensions.json"


def parse_modules(text: str) -> set[str]:
    modules = set()
    for line in text.splitlines():
        name = line.strip()
        if not name or name.startswith("[") or name.startswith("PHP "):
            continue
        modules.add(name.lower())
    return modules


def inventory(php: str) -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    proc = subprocess.run([php, "-m"], capture_output=True, text=True,
                          timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "php -m failed")
    loaded = parse_modules(proc.stdout)
    rows = []
    for extension in manifest["extensions"]:
        name = extension["name"].lower()
        rows.append({**extension, "loaded": name in loaded})
    return {
        "scope": manifest["scope"],
        "php": subprocess.run([php, "-r", "echo PHP_VERSION;"],
                              capture_output=True, text=True,
                              timeout=30).stdout.strip(),
        "loaded": sorted(loaded),
        "rows": rows,
        "loaded_count": sum(row["loaded"] for row in rows),
        "total": len(rows),
    }


def render(result: dict) -> str:
    lines = [f"# Extension inventory — PHP {result['php']}", "",
             f"Scope: {result['scope']}", "",
             f"Loaded: {result['loaded_count']}/{result['total']} "
             "manifest extensions.", "",
             "| Extension | Loaded | Surface | Status |",
             "|---|---|---|---|"]
    for row in result["rows"]:
        lines.append(f"| {row['name']} | {'yes' if row['loaded'] else 'no'} "
                     f"| {row['surface']} | {row['status']} |")
    lines += ["", "A loaded extension is not an audited extension. The "
              "status column stays `deferred-not-inventoried` until a "
              "function/parser map and a lab or fuzz receipt exist.", ""]
    return "\n".join(lines)


def self_test() -> None:
    modules = parse_modules("PHP 8.5.12\n[PHP Modules]\nCore\nigbinary\n\n"
                            "[Zend Modules]\nZend OPcache\n")
    assert modules == {"core", "igbinary", "zend opcache"}, modules
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["extensions"], "empty extension manifest"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "reports"))
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        print("[ok] extension inventory self-test")
        return 0
    result = inventory(args.php)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "extensions.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "extensions.md").write_text(render(result), encoding="utf-8")
    print(f"[ok] {result['php']}: {result['loaded_count']}/{result['total']} "
          f"manifest extensions loaded -> {out / 'extensions.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
