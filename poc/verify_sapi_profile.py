#!/usr/bin/env python3
"""Print the scanner-style SAPI/limit profile for a lab target.

This is the precondition layer the public scanners use before firing:
version (and fixed-release gating), SAPI, `memory_limit` (exact, via the
lab's OOM probe), `post_max_size`, `max_input_vars`, and the worker count.

Usage:
  python3 poc/verify_sapi_profile.py --target http://127.0.0.1:18110
  python3 poc/verify_sapi_profile.py --target http://127.0.0.1:18097
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import probe, sapi


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18110")
    ap.add_argument("--banner", default="/probe.php")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    print(f"[*] SAPI/limit profile: {host}:{port}{args.banner}")
    info = sapi.profile(host, port, args.banner)
    if info.get("error"):
        print(f"[!] {info['error']}")
        return 1

    order = [
        "php_version", "sapi", "upload_progress", "memory_limit",
        "memory_limit_bytes", "memory_limit_probe_bytes", "post_max_size",
        "post_max_size_bytes", "max_input_vars", "display_errors",
        "version_status", "worker_count", "worker_pids",
    ]
    for k in order:
        if k in info and info[k] not in (None, "", []):
            print(f"    {k:24} {info[k]}")

    print()
    vs = info.get("version_status")
    if vs == "fixed":
        print("[*] version >= the fixed release for its branch: core chain")
        print("    should be blocked (still test application-level chains).")
    elif vs == "vulnerable":
        print("[*] version < the fixed release: core-chain preconditions hold.")
    else:
        print("[*] version unknown/unmapped: do NOT infer patch status from")
        print("    the string alone (distro backports keep the version).")

    if info.get("memory_limit_probe_bytes"):
        mem = info["memory_limit_probe_bytes"]
        print(f"[*] exact memory_limit from OOM probe: {mem} bytes")
        print(f"    amplification target: a ~{max(1, mem // (32 * 1024 * 1024))} MB")
        print("    duplicate-header body reaches this limit (see")
        print("    poc/verify_amplification.py).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
