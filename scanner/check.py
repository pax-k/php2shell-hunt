#!/usr/bin/env python3
"""Loopback-only PHP session scanner (CVE-2026-109618 / CVE-2026-109619 shape).

Four tiers, increasing risk:

  1. passive version fingerprint;
  2. upload_progress reachability + session fixation probe;
  3. session-write marker check;
  4. destructive OOM differential, only with --active.

No third-party dependencies. Non-loopback targets are rejected before a socket
is opened. This is a lab tool, not a remote scanner.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

PATCHED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
FLOOR = (5, 4, 0)


class ScopeError(ValueError):
    """Raised when a target is outside the loopback lab scope."""


def is_loopback(host: str) -> bool:
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ensure_loopback(host: str) -> None:
    if not is_loopback(host):
        raise ScopeError(
            f"refusing non-loopback target {host!r}; lab targets are "
            "localhost, 127.0.0.0/8, and ::1")


def parse_target(target: str) -> dict:
    raw = target if "://" in target else f"http://{target}"
    parsed = urlparse(raw)
    host = parsed.hostname or "127.0.0.1"
    ensure_loopback(host)
    tls = parsed.scheme == "https"
    return {
        "target": target,
        "host": host,
        "port": parsed.port or (443 if tls else 80),
        "tls": tls,
        "path": parsed.path or "/",
    }


def _connect(host: str, port: int, tls: bool, timeout: int):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(raw, server_hostname=host)
    return raw


def _recv_all(sock, timeout: int) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(65536)
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def _parse_response(raw: bytes) -> tuple[int, dict, bytes]:
    if not raw:
        return 0, {}, b""
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    else:
        head, body = raw, b""
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    match = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
    status = int(match.group(1)) if match else 0
    headers = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", "replace")
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers, body


def http_request(host: str, port: int, method: str, path: str,
                 headers: dict | None = None, body: bytes | None = None,
                 tls: bool = False, timeout: int = 10) -> tuple[int, dict, bytes]:
    ensure_loopback(host)
    request_headers = {"Host": host, "Connection": "close"}
    if headers:
        request_headers.update(headers)
    if body:
        request_headers["Content-Length"] = str(len(body))
    request = f"{method} {path} HTTP/1.1\r\n"
    request += "".join(f"{k}: {v}\r\n" for k, v in request_headers.items())
    request += "\r\n"
    payload = request.encode("latin-1")
    if body:
        payload += body
    try:
        sock = _connect(host, port, tls, timeout)
        sock.sendall(payload)
        raw = _recv_all(sock, timeout)
        sock.close()
        return _parse_response(raw)
    except (socket.error, ssl.SSLError, OSError) as exc:
        return 0, {}, str(exc).encode()


def parse_version(value: str | None) -> tuple | None:
    if not value:
        return None
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def is_vulnerable(version: tuple | None) -> bool | None:
    if version is None:
        return None
    if version < FLOOR:
        return False
    patched = PATCHED.get(version[:2])
    if patched is None:
        return True
    return version < patched


def recommendation(version: tuple | None) -> str:
    if version is None:
        return "version unknown; verify manually before testing the active tier"
    patched = PATCHED.get(version[:2])
    if patched is None:
        return "EOL branch; no upstream fix"
    if version < patched:
        return f"upgrade to {'.'.join(map(str, patched))}+"
    return "version is patched"



def check_version(target: dict, timeout: int = 10) -> dict:
    result = {"version": None, "sapi": None, "vulnerable": None,
              "source": None}
    status, headers, body = http_request(
        target["host"], target["port"], "GET", target["path"],
        tls=target["tls"], timeout=timeout)
    if status == 0:
        result["source"] = "connection_failed"
        return result
    for source, value in (("x-powered-by", headers.get("x-powered-by", "")),
                          ("server-header", headers.get("server", ""))):
        match = re.search(r"PHP/(\d+\.\d+\.\d+)", value)
        if match:
            result["version"] = match.group(1)
            result["source"] = source
            break
    if result["version"] is None and body:
        match = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        if match:
            result["version"] = match.group(1).decode()
            result["source"] = "body"
    server = headers.get("server", "").lower()
    if "apache" in server:
        result["sapi"] = "mod_php"
    elif "nginx" in server:
        result["sapi"] = "fpm"
    if result["version"]:
        result["vulnerable"] = is_vulnerable(parse_version(result["version"]))
    return result


def _multipart(fields: list[tuple[str, str]], file_marker: str) -> tuple[str, bytes]:
    boundary = "SCANBOUND" + uuid.uuid4().hex[:8]
    chunks = []
    for name, value in fields:
        chunks.append(f"--{boundary}\r\n")
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n')
        chunks.append(f"{value}\r\n")
    chunks.append(f"--{boundary}\r\n")
    chunks.append('Content-Disposition: form-data; name="f"; '
                  f'filename="{file_marker}"\r\n\r\n')
    chunks.append("X\r\n")
    chunks.append(f"--{boundary}--\r\n")
    return boundary, "".join(chunks).encode("latin-1")


def check_upload_progress(target: dict, timeout: int = 10) -> dict:
    result = {"reachable": False, "session_fixation": False, "details": ""}
    boundary, body = _multipart(
        [("PHP_SESSION_UPLOAD_PROGRESS", "scancheck")], "test.txt")
    status, headers, _ = http_request(
        target["host"], target["port"], "POST", target["path"],
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        body=body, tls=target["tls"], timeout=timeout)
    if status == 0:
        result["details"] = "connection failed"
        return result
    cookie = headers.get("set-cookie", "")
    if "PHPSESSID" in cookie:
        result["reachable"] = True
        result["details"] = "upload_progress accepted; session cookie returned"
    elif status in (200, 301, 302):
        result["details"] = f"HTTP {status}; no session cookie"
    else:
        result["details"] = f"HTTP {status}"

    sid = "fixcheck" + uuid.uuid4().hex[:16]
    boundary2, body2 = _multipart(
        [("PHPSESSID", sid), ("PHP_SESSION_UPLOAD_PROGRESS", "scancheck")],
        "test.txt")
    status2, headers2, _ = http_request(
        target["host"], target["port"], "POST", target["path"],
        headers={"Content-Type": f"multipart/form-data; boundary={boundary2}"},
        body=body2, tls=target["tls"], timeout=timeout)
    cookie2 = headers2.get("set-cookie", "")
    if status2 and sid in cookie2:
        result["reachable"] = True
        result["session_fixation"] = True
        result["details"] = "session fixation via POST body confirmed"
    elif status2 and "PHPSESSID" in cookie2 and result["reachable"]:
        result["details"] += "; fixation blocked or server chose its own SID"
    return result


def check_session_write(target: dict, timeout: int = 10) -> dict:
    result = {"injectable": False, "details": ""}
    marker = "___PHP2SHELL_PROBE_" + uuid.uuid4().hex[:8] + "___"
    sid = "writecheck" + uuid.uuid4().hex[:16]
    boundary, body = _multipart(
        [("PHP_SESSION_UPLOAD_PROGRESS", "x")], marker)
    status, _, _ = http_request(
        target["host"], target["port"], "POST", target["path"],
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={sid}",
        }, body=body, tls=target["tls"], timeout=timeout)
    if status == 0:
        result["details"] = "injection request failed"
        return result
    status2, _, response_body = http_request(
        target["host"], target["port"], "GET", target["path"],
        headers={"Cookie": f"PHPSESSID={sid}"}, tls=target["tls"],
        timeout=timeout)
    if status2 and marker.encode() in response_body:
        result["injectable"] = True
        result["details"] = "filename marker reflected through the session"
    else:
        result["details"] = "marker not reflected (expected unless the endpoint dumps session state)"
    return result


def check_oom(target: dict, timeout: int = 20) -> dict:
    """Destructive local probe: a large multipart body against a lab worker."""
    boundary = "OOMBOUND" + uuid.uuid4().hex[:8]
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        "x\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
    ).encode("latin-1") + b"A" * (4 * 1024 * 1024) + (
        f"\r\n--{boundary}--\r\n").encode("latin-1")
    status, _, _ = http_request(
        target["host"], target["port"], "POST", target["path"],
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        body=body, tls=target["tls"], timeout=timeout)
    if status == 0:
        return {"vulnerable": False, "behavior": "connection failed/reset"}
    if status in (500, 502, 503):
        return {"vulnerable": True, "behavior": f"HTTP {status}"}
    return {"vulnerable": False, "behavior": f"HTTP {status}"}


def scan(url: str, active: bool = False, path: str | None = None,
         timeout: int = 10) -> dict:
    target = parse_target(url)
    if path:
        target["path"] = path
    result = {
        "target": target["target"],
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "version": None,
        "sapi": None,
        "checks": {},
        "chains": [],
        "recommendation": "",
        "error": None,
    }
    for name, check in (
        ("version", check_version),
        ("upload_progress", check_upload_progress),
    ):
        try:
            result["checks"][name] = check(target, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - report per-tier failures
            result["checks"][name] = {"error": str(exc)}
    version = result["checks"]["version"]
    result["version"] = version.get("version")
    result["sapi"] = version.get("sapi")
    upload = result["checks"]["upload_progress"]
    if upload.get("reachable"):
        try:
            result["checks"]["session_write"] = check_session_write(
                target, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            result["checks"]["session_write"] = {"error": str(exc)}
    if active:
        try:
            result["checks"]["oom"] = check_oom(target, timeout=max(timeout, 20))
        except Exception as exc:  # noqa: BLE001
            result["checks"]["oom"] = {"error": str(exc)}

    version_vuln = version.get("vulnerable")
    upload_reachable = upload.get("reachable", False)
    oom_vuln = result["checks"].get("oom", {}).get("vulnerable")
    if oom_vuln is True:
        result["verdict"], result["confidence"] = "VULNERABLE", "HIGH"
    elif version_vuln is True and upload_reachable:
        result["verdict"], result["confidence"] = "VULNERABLE", "HIGH"
    elif version_vuln is True:
        result["verdict"], result["confidence"] = "VULNERABLE", "MEDIUM"
    elif version_vuln is False and not oom_vuln:
        result["verdict"] = "PATCHED"
        result["confidence"] = "HIGH" if upload_reachable else "MEDIUM"
    elif upload_reachable and version_vuln is None:
        result["verdict"], result["confidence"] = "LIKELY_VULNERABLE", "MEDIUM"
    elif version.get("source") == "connection_failed":
        result["verdict"], result["error"] = "ERROR", "connection failed"
    result["recommendation"] = recommendation(parse_version(result["version"]))

    if result["verdict"] in ("VULNERABLE", "LIKELY_VULNERABLE"):
        result["chains"] = ["A", "B"]
        if result["sapi"] == "fpm":
            result["chains"] += ["C", "E"]
        elif result["sapi"] == "mod_php":
            result["chains"].append("D")
        elif result["sapi"] is None:
            result["chains"] += ["C", "D", "E"]
    return result


def format_text(result: dict) -> str:
    lines = [f"[*] {result['target']}",
             f"    PHP {result['version'] or 'unknown'} | "
             f"SAPI {result['sapi'] or 'unknown'}"]
    upload = result["checks"].get("upload_progress", {})
    if upload:
        state = "reachable" if upload.get("reachable") else "not reachable"
        extra = " | fixation" if upload.get("session_fixation") else ""
        lines.append(f"    upload_progress: {state}{extra}")
    write = result["checks"].get("session_write", {})
    if write:
        detail = write.get("details", "")
        if detail:
            lines.append(f"    session write: {detail}")
    oom = result["checks"].get("oom", {})
    if oom:
        lines.append(f"    OOM probe: {oom.get('behavior', 'not run')}")
    lines += ["", f"    Verdict: {result['verdict']} ({result['confidence']})"]
    if result["chains"]:
        lines.append(f"    Chains: {', '.join(result['chains'])}")
    if result["recommendation"]:
        lines.append(f"    {result['recommendation']}")
    if result["error"]:
        lines.append(f"    Error: {result['error']}")
    return "\n".join(lines)


def _targets(args) -> list[str]:
    targets = [args.target] if args.target else []
    if args.targets:
        lines = (sys.stdin.read().splitlines() if args.targets == "-"
                 else open(args.targets, encoding="utf-8").read().splitlines())
        targets.extend(line.strip() for line in lines
                       if line.strip() and not line.lstrip().startswith("#"))
    seen, unique = set(), []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
    return unique


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Loopback-only PHP session scanner (lab tool)")
    parser.add_argument("target", nargs="?", help="target URL")
    parser.add_argument("--targets", "-f", metavar="FILE",
                        help="one URL per line; '-' for stdin")
    parser.add_argument("--path", "-p", help="override endpoint path")
    parser.add_argument("--active", action="store_true",
                        help="enable the destructive OOM probe")
    parser.add_argument("--json", "-j", action="store_true")
    parser.add_argument("--threads", "-t", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args(argv)
    targets = _targets(args)
    if not targets:
        parser.error("provide a target or --targets file")
    if args.active:
        print("[!] active mode: OOM probes may kill local workers",
              file=sys.stderr)
    try:
        parsed = [parse_target(target) for target in targets]
    except ScopeError as exc:
        print(f"[scope] {exc}", file=sys.stderr)
        return 2

    results = []
    if len(parsed) == 1:
        results.append(scan(targets[0], args.active, args.path, args.timeout))
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
            futures = [pool.submit(scan, target, args.active, args.path,
                                   args.timeout) for target in targets]
            for future in as_completed(futures):
                results.append(future.result())

    if args.json:
        print(json.dumps(results[0] if len(results) == 1 else results,
                         indent=2, default=str))
    else:
        for result in results:
            if args.quiet and result["verdict"] not in (
                    "VULNERABLE", "LIKELY_VULNERABLE"):
                continue
            print(format_text(result))
            print()
    verdicts = {result["verdict"] for result in results}
    if verdicts & {"VULNERABLE", "LIKELY_VULNERABLE"}:
        return 0
    if verdicts == {"PATCHED"}:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
