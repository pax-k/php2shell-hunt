"""SAPI / limit profiling for a lab target.

Public scanners (Assetnote, devploit, murrez) all gate on the same facts
before sending an exploit: PHP version/SAPI, `memory_limit`,
`post_max_size`, and whether the worker pool is single- or multi-worker.
This module reads them from the target's own banner/probe endpoints and,
when available, from the lab's on-demand OOM probe.

Nothing here is destructive: the OOM probe is a single bounded allocation
on a lab the caller owns.
"""

import re

from . import probe

VERSION_RE = re.compile(r"PHP[/ ]?(\d+\.\d+\.\d+)")
OOM_RE = re.compile(rb"Allowed memory size of (\d+) bytes exhausted")
PID_RE = re.compile(rb"pid=(\d+)")

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}


def human_to_bytes(v):
    v = (v or "").strip()
    if not v or v == "-1":
        return None
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    try:
        return int(v[:-1]) * mult[v[-1:].upper()] if v[-1:].isalpha() else int(v)
    except (ValueError, KeyError):
        return None


def parse_banner(body):
    """Parse the generic lab banner and probe.php keys."""
    out = {}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) else body
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("PHP "):
            out["php_version"] = line[4:].strip()
        elif line.startswith("SAPI "):
            out["sapi"] = line[4:].strip()
        elif line.startswith("upload_progress "):
            out["upload_progress"] = line.split(None, 1)[1].strip().lower() in (
                "1", "on", "true", "yes"
            )
        elif ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if k in ("memory_limit", "post_max_size", "max_input_vars",
                     "display_errors", "max_input_time"):
                out[k] = v
    return out


def version_status(version):
    """Return 'fixed' / 'vulnerable' / 'unknown' for a PHP version string."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        return "unknown"
    major, minor, patch = (int(x) for x in m.groups())
    fixed = FIXED.get((major, minor))
    if fixed is None:
        return "unknown"
    return "fixed" if patch >= fixed else "vulnerable"


def probe_memory_limit(host, port, oom_path="/oom_probe.php", timeout=30):
    """Read the exact memory_limit from the lab's on-demand OOM probe.

    `oom_probe.php` allocates 256 MB with display_errors forced on, so on a
    vulnerable lab it prints `Allowed memory size of N bytes exhausted`.
    Returns (bytes, detail).
    """
    try:
        resp = probe.http_get(host, port, oom_path, timeout=timeout,
                              recv_timeout=timeout)
    except OSError as e:
        return None, f"{oom_path} unreachable: {e}"
    body = probe.body(resp)
    m = OOM_RE.search(body)
    if m:
        return int(m.group(1)), f"{oom_path} OOM line"
    if b"no oom" in body:
        return None, f"{oom_path}: no OOM (memory_limit > 256M or disabled)"
    return None, f"{oom_path}: no OOM signature ({probe.status(resp)})"


def sample_workers(host, port, worker_id_path="/worker_id.php", count=12):
    pids = []
    for _ in range(count):
        try:
            resp = probe.http_get(host, port, worker_id_path, timeout=8,
                                  recv_timeout=6)
        except OSError:
            continue
        m = PID_RE.search(resp)
        if m:
            pids.append(int(m.group(1)))
    return pids


def profile(host, port, banner_path="/probe.php"):
    """Collect the scanner-style profile for a lab target."""
    try:
        resp = probe.http_get(host, port, banner_path, timeout=10,
                              recv_timeout=8)
        info = parse_banner(probe.body(resp))
    except OSError as e:
        return {"error": str(e)}
    info["memory_limit_bytes"] = human_to_bytes(info.get("memory_limit"))
    info["post_max_size_bytes"] = human_to_bytes(info.get("post_max_size"))
    info["version_status"] = version_status(info.get("php_version"))
    mem, detail = probe_memory_limit(host, port)
    if mem is not None:
        info["memory_limit_probe_bytes"] = mem
        info["memory_limit_probe"] = detail
    pids = sample_workers(host, port)
    info["worker_pids"] = sorted(set(pids))
    info["worker_count"] = len(set(pids))
    return info
