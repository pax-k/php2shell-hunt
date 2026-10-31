"""Shared loopback-only transport and command allowlist for POCs."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from urllib.parse import urlparse

ALLOWED_COMMANDS = frozenset({"id", "uname", "whoami"})


class ScopeError(ValueError):
    """Target or command is outside the lab contract."""


def is_loopback(host: str) -> bool:
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_target(value: str) -> dict:
    parsed = urlparse(value if "://" in value else f"http://{value}")
    host = parsed.hostname or "127.0.0.1"
    if not is_loopback(host):
        raise ScopeError(
            f"refusing non-loopback target {host!r}; lab targets are "
            "localhost, 127.0.0.0/8, and ::1")
    tls = parsed.scheme == "https"
    return {
        "host": host,
        "port": parsed.port or (443 if tls else 80),
        "tls": tls,
        "path": parsed.path or "/",
    }


def require_command(command: str) -> str:
    if command not in ALLOWED_COMMANDS:
        raise ScopeError(
            f"command {command!r} is not in the allowlist "
            f"{sorted(ALLOWED_COMMANDS)}")
    return command


def request(target: dict, method: str, path: str | None = None,
            headers: dict | None = None, body: bytes | None = None,
            timeout: int = 10) -> tuple[int, dict, bytes]:
    if not is_loopback(target["host"]):
        raise ScopeError(f"refusing non-loopback host {target['host']!r}")
    path = path or target["path"]
    fields = {"Host": target["host"], "Connection": "close"}
    if headers:
        fields.update(headers)
    if body:
        fields["Content-Length"] = str(len(body))
    raw = f"{method} {path} HTTP/1.1\r\n"
    raw += "".join(f"{key}: {value}\r\n" for key, value in fields.items())
    raw += "\r\n"
    payload = raw.encode("latin-1") + (body or b"")
    sock = socket.create_connection((target["host"], target["port"]),
                                    timeout=timeout)
    try:
        if target["tls"]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target["host"])
        sock.sendall(payload)
        response = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, ConnectionResetError, ssl.SSLError):
                break
            if not chunk:
                break
            response += chunk
    finally:
        sock.close()
    if b"\r\n\r\n" not in response:
        return 0, {}, response
    head, response_body = response.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = 0
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    response_headers = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", "replace")
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            response_headers[key.strip().lower()] = value.strip()
    return status, response_headers, response_body
