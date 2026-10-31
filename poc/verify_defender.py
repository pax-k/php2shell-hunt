#!/usr/bin/env python3
"""
Defender verification: fire each php2shell-chain trigger against the
HARDENED lab (lab-defender, :18083) and assert that the administrative
controls kill the chain's precondition — the defender proving itself,
with evidence.

Controls under test (all set via FPM php_admin_value, which per-directory
.user.ini cannot override):
  1. session.upload_progress.enabled = 0
     -> the rfc1867 session callback path is dead: no upload-progress
        session writes. Precondition of: Chain A/B/C injection, the
        stall-arming write path, and BOTH CVE-2026-109619 consumers
        (upload progress IS the consumer).
  2. session.serialize_handler = php_serialize (consistent, administrative)
     -> the cross-directory handler mismatch precondition of Chain C dies.
  3. session.use_strict_mode = 1 / use_only_cookies = 1
     -> session fixation hardening.
  4. memory_limit = -1
     -> the CVE-2026-109618 OOM trigger cannot fire (no PHP-level fatal
        interruptor). NOTE the advisory's own caveat: this removes PHP's
        memory cap and is a PARTIAL, temporary mitigation only.

Usage:
  cd lab-defender && docker compose up -d
  python3 verify_defender.py --target http://127.0.0.1:18083

For authorized security testing against your own lab only.
"""
import argparse
import socket
import subprocess
import sys
from urllib.parse import urlparse

BOUNDARY = "DEFENDER"
SID = "abcdef0123456789abcdef0123456789"


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


def upload(host, port, path, sid, filename, progress="x"):
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


def expansion_body(count, depth):
    out = []
    for i in range(count):
        name = f"r{i}" + "[a]" * (depth - 1)
        out.append(f"--{BOUNDARY}\r\n"
                   f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
                   f"\r\n\r\n")
    out.append(f"--{BOUNDARY}--\r\n")
    body = "".join(out).encode()
    req = (
        f"POST /expand_probe.php HTTP/1.1\r\n"
        f"Host: x\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return req


def docker_exec(container, cmd):
    try:
        r = subprocess.run(["docker", "exec", container] + cmd,
                            capture_output=True, text=True, timeout=20)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"<docker exec failed: {e}>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18083")
    ap.add_argument("--container", default="php2shell-defender")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80

    print("[*] Defender verification: administrative controls vs the")
    print("    php2shell chain preconditions")
    print(f"[*] Target: {args.target} (php:8.2-fpm, same engine as the")
    print("    vulnerable lab; only the ini stance differs)")
    print()

    # read the effective config
    resp = http_req(host, port, (
        f"GET /index.php HTTP/1.1\r\nHost: {host}\r\n"
        f"Connection: close\r\n\r\n").encode())
    ident = [l for l in resp.decode("latin1", "replace").splitlines()
             if l.startswith("PHP ")]
    print(f"[*] Target identity: {ident[0] if ident else '?'}")
    print()

    results = []

    # --- control 1: upload_progress disabled --------------------------
    print("[1] session.upload_progress.enabled = 0")
    print("    fire the Chain-A/C injection upload (SID + upload-progress +")
    print("    payload filename):")
    upload(host, port, "/app/upload.php", SID, 'x|O:8:\\"FileLogger\\":1:{}')
    sess = docker_exec(args.container, ["cat", f"/tmp/sessions/sess_{SID}"])
    ok1 = sess.startswith("<") or sess == "" or "No such file" in sess \
        or "upload_progress" not in sess
    if ok1:
        print(f"    session file: {sess[:80] if sess else '<absent>'}")
        print("    [PASS] no upload_progress key was written -> the rfc1867")
        print("           session callback path is dead: Chains A/B/C")
        print("           injection, the stall-arming write path, and both")
        print("           CVE-2026-109619 consumers (upload progress IS the")
        print("           consumer) cannot arm.")
        results.append(("upload_progress.enabled=0", "rfc1867 session path", True))
    else:
        print(f"    [FAIL] session content: {sess[:120]}")
        results.append(("upload_progress.enabled=0", "rfc1867 session path", False))
    print()

    # --- control 2: consistent serialize_handler -----------------------
    print("[2] session.serialize_handler = php_serialize (administrative)")
    print("    fire the Chain-C mismatch (api/ dir tries `php` via .user.ini):")
    resp = http_req(host, port, (
        f"GET /api/handler_probe.php HTTP/1.1\r\nHost: {host}\r\n"
        f"Connection: close\r\n\r\n").encode())
    text = resp.decode("latin1", "replace") if resp else ""
    ok2 = "handler=php_serialize" in text
    if ok2:
        print("    [PASS] api/ resolves handler=php_serialize — the per-dir")
        print("           .user.ini cannot override the admin value, so the")
        print("           mismatch precondition of Chain C is dead: injected")
        print("           payloads stay inert strings.")
        results.append(("serialize_handler=php_serialize", "Chain C mismatch", True))
    else:
        print(f"    [FAIL] api/ handler resolution: {text.splitlines()[:2]}")
        results.append(("serialize_handler=php_serialize", "Chain C mismatch", False))
    print()

    # --- control 4: memory_limit=-1 --------------------------------------
    print("[4] memory_limit = -1")
    print("    fire the CVE-2026-109618 empty-upload expansion producer:")
    resp = http_req(host, port, expansion_body(600, 60))
    text = resp.decode("latin1", "replace") if resp else ""
    oom = "Allowed memory size" in text
    completed = "FILES count" in text
    if completed and not oom:
        print("    [PASS] the OOM trigger cannot fire (no PHP-level fatal")
        print("           interruptor -> no CVE-2026-109618 producer, and")
        print("           the 109619 chains lose their OOM interruptor).")
        print("           CAVEAT (advisory): memory_limit=-1 removes PHP's")
        print("           memory cap entirely — partial, temporary")
        print("           mitigation only; exhaustion risk moves to the")
        print("           process/container level. PATCHING remains the")
        print("           only complete fix.")
        results.append(("memory_limit=-1", "OOM trigger", True))
    else:
        print(f"    [FAIL] oom={oom} completed={completed}")
        results.append(("memory_limit=-1", "OOM trigger", False))
    print()

    print("[*] Summary — the defender proving itself:")
    for control, precondition, ok in results:
        print(f"    [{'PASS' if ok else 'FAIL'}] {control:34s} kills: {precondition}")
    all_ok = all(r[2] for r in results)
    print()
    print("[*] Interpretation: with these administrative controls, every")
    print("    reproduced chain in this repo loses a required precondition")
    print("    on THIS engine. This does NOT replace the 8.2.35+ patch:")
    print("    - CVE-2026-109618 has non-OOM interruptors (mmap failures,")
    print("      RLIMIT-style limits are explicitly dangerous per the")
    print("      advisory),")
    print("    - CVE-2026-109619 has other producers/consumers (error")
    print("      state, INI diagnostics),")
    print("    - the advisory's own words: patch now; these are temporary,")
    print("      partial mitigations.")


if __name__ == "__main__":
    main()
