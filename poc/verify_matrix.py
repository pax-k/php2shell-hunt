#!/usr/bin/env python3
"""Version x arch matrix — the "general default installations" proof.

Runs the full triad per row: fire + command output (pos), patched build blocks
(neg), `+0x1000` bias prevents the fire (bias). A row is only "proven" when
all three legs hold.

Usage:
  # offline: validate the matrix table against the profile registry
  python3 poc/verify_matrix.py --dry-run

  # one row against the lab-matrix compose (:18164 / :18165)
  python3 poc/verify_matrix.py --rows 8.4 --proof lab-matrix/out/p1

  # every row (needs the lab-matrix services up)
  python3 poc/verify_matrix.py --proof lab-matrix/out/p1 \
      --json /tmp/php2shell-matrix.json

Lab-only; `id | uname | whoami` only.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import matrix, profiles
from php2shell.guard import ALLOWED_CMDS, check_cmd

ROOT = Path(__file__).resolve().parent.parent


def _matches(row, token):
    return (row["key"] == token or row["version"] == token
            or row["key"].startswith(token + ".")
            or row["version"].startswith(token + "."))


def select_rows(rows_arg):
    if not rows_arg:
        return matrix.ROWS
    wanted = [r.strip() for r in rows_arg.split(",") if r.strip()]
    rows = [r for r in matrix.ROWS if any(_matches(r, t) for t in wanted)]
    missing = [t for t in wanted
               if not any(_matches(r, t) for r in matrix.ROWS)]
    if missing:
        sys.exit(f"unknown row(s): {', '.join(missing)}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", default=None,
                    help="comma-separated row keys or versions (default: all)")
    ap.add_argument("--arch", default=None, choices=["x86_64", "aarch64"])
    ap.add_argument("--cmd", default="id", choices=ALLOWED_CMDS)
    ap.add_argument("--proof", default=str(ROOT / "lab-matrix" / "out" / "p1"))
    ap.add_argument("--json", default=None, help="write the result JSON here")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate the matrix/profile registry offline")
    ap.add_argument("--self-test", action="store_true",
                    help="offline triad/profile invariants")
    args = ap.parse_args()

    if args.dry_run or args.self_test:
        rows = matrix.validate_config(select_rows(args.rows), args.arch)
        print(f"[ok] matrix config valid: {len(rows)} row(s)")
        for r in rows:
            prof = profiles.find(php_version=r["version"], arch=r["arch"])
            geom = "calibrated" if prof.get("geometry_calibrated") else "default"
            print(f"     {r['version']:8} {r['arch']:8} "
                  f"zif={prof['zif_system']:#x} "
                  f"s_off={prof['s_off']:#x} (geometry={geom}) "
                  f"buckets={prof['main_bucket_count']} "
                  f"ports={r['port']}/{r['patched_port']}")
        return 0

    cmd = check_cmd(args.cmd)
    rows = select_rows(args.rows)
    results = []
    for row in rows:
        print(f"\n### {row['version']} ({row['arch']})  "
              f"port {row['port']} / patched {row['patched_port']}")
        results.append(matrix.run_row(
            row, cmd=cmd, proof=args.proof,
            report=lambda m: print(f"    {m}")))

    print()
    print(matrix.markdown(results))
    proven = sum(1 for r in results if r.proven)
    print(f"\nproven: {proven}/{len(results)}")

    if args.json:
        Path(args.json).write_text(matrix.dump(results) + "\n",
                                   encoding="utf-8")
        print(f"wrote {args.json}")
    return 0 if proven == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
