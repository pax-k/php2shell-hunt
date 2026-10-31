"""Build-to-build ELF diff for the php2shell matrix.

Compares two stock images' `libphp.so` (or an explicit binary) using the
host-side ELF reader, so no binutils are needed inside the image. Produces a
Markdown report and a machine-readable JSON summary.

    scripts/diff_builds.sh --old php:8.4.26-apache --new php:8.4.27-apache

Optional external engines (`ghidriff`, `abidiff`) are used when installed and
recorded as unavailable otherwise. Nothing here talks to a lab target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from . import elf, offsets, profiles

ROOT = Path(__file__).resolve().parent.parent
LIBPHP_CANDIDATES = (
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/local/lib/libphp.so",
    "/usr/local/lib/libphp.so.8",
)
NOTABLE = (
    "zif_system",
    "zif_passthru",
    "zif_exec",
    "zval_ptr_dtor",
    "php_session_initialize",
    "php_session_rfc1867_cleanup",
    "php_session_flush",
    "php_var_unserialize",
    "var_destroy",
    "zend_objects_store_del",
    "zend_mm_alloc_small",
    "php_request_shutdown",
)


class DockerError(RuntimeError):
    pass


def _run(argv, timeout=300, check=True):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise DockerError(f"{argv[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"{' '.join(argv)} timed out") from exc
    if check and proc.returncode != 0:
        raise DockerError(f"{' '.join(argv)} failed: {proc.stderr.strip()}")
    return proc


def inspect(image: str, platform: str | None = None) -> dict:
    fmt = ("{{.Id}}|{{.Architecture}}|{{.Os}}|"
           "{{join .RepoDigests \",\"}}|{{.Size}}")
    argv = ["docker", "image", "inspect", "--format", fmt]
    out = _run(argv + [image]).stdout.strip().split("|")
    info = {
        "image": image,
        "id": out[0],
        "arch": "aarch64" if out[1] in ("arm64", "aarch64") else out[1],
        "os": out[2],
        "digests": [d for d in out[3].split(",") if d],
        "size": int(out[4]),
    }
    env = _run(["docker", "image", "inspect", "--format",
                "{{json .Config.Env}}", image]).stdout
    for item in json.loads(env):
        if item.startswith("PHP_VERSION="):
            info["php_version"] = item.split("=", 1)[1]
            break
    return info


def _copy_out(image: str, path: str, dest: Path, platform: str | None) -> None:
    argv = ["docker", "create"]
    if platform:
        argv += ["--platform", platform]
    container = _run(argv + [image]).stdout.strip()
    try:
        proc = _run(["docker", "cp", f"{container}:{path}", str(dest)],
                    check=False)
        if proc.returncode != 0:
            raise DockerError(f"{image}:{path}: {proc.stderr.strip()}")
    finally:
        _run(["docker", "rm", "-f", container], check=False)


def extract(image: str, paths, workdir: Path,
            platform: str | None) -> dict[str, Path]:
    """Copy each requested path out of the image; skip paths that don't exist."""
    found: dict[str, Path] = {}
    workdir.mkdir(parents=True, exist_ok=True)
    for index, path in enumerate(paths):
        dest = workdir / f"{index}_{Path(path).name or 'binary'}"
        try:
            _copy_out(image, path, dest, platform)
        except DockerError:
            continue
        found[path] = dest
    if not found:
        raise DockerError(f"{image}: none of {list(paths)} exist")
    return found


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def compare(old: elf.Elf, new: elf.Elf) -> dict:
    sections = []
    for name in sorted({s.name for s in old.sections} |
                       {s.name for s in new.sections}):
        a, b = old.section(name), new.section(name)
        if a is None or b is None:
            sections.append({"name": name, "state": "added" if a is None
                             else "removed", "old_size": a.size if a else None,
                             "new_size": b.size if b else None})
            continue
        changed = a.size != b.size or _sha(a.data) != _sha(b.data)
        if changed:
            sections.append({"name": name, "state": "changed",
                             "old_size": a.size, "new_size": b.size,
                             "old_sha": _sha(a.data),
                             "new_sha": _sha(b.data)})

    fo, fn = old.functions(), new.functions()
    common = sorted(set(fo) & set(fn))
    added = sorted(set(fn) - set(fo))
    removed = sorted(set(fo) - set(fn))
    shifts = {n: fn[n].value - fo[n].value for n in common}
    grew = [n for n in common if fo[n].size != fn[n].size]
    hist = Counter(shifts.values())
    notable = []
    for name in NOTABLE:
        a, b = old.symbol(name), new.symbol(name)
        if a or b:
            notable.append({
                "name": name,
                "old": a.value if a else None,
                "new": b.value if b else None,
                "shift": (b.value - a.value) if a and b else None,
                "old_size": a.size if a else None,
                "new_size": b.size if b else None,
            })
    return {
        "sections_changed": sections,
        "symbols": {
            "common": len(common), "added": len(added),
            "removed": len(removed), "size_changed": len(grew),
            "added_names": added, "removed_names": removed,
            "size_changed_names": sorted(
                grew, key=lambda n: abs(fn[n].size - fo[n].size),
                reverse=True)[:100],
        },
        "notable": notable,
        "shift": {
            "unique": len(hist),
            "median": sorted(shifts.values())[len(shifts) // 2]
            if shifts else None,
            "mode": hist.most_common(1)[0] if hist else None,
            "histogram": [[s, c] for s, c in
                          sorted(hist.items(), key=lambda kv: (-kv[1], kv[0]))[:20]],
            "top": [[n, shifts[n], fn[n].value] for n in
                    sorted(common, key=lambda n: abs(shifts[n]),
                           reverse=True)[:20]],
        },
    }


def _table(rows, headers) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join("" if v is None else str(v)
                                     for v in row) + " |")
    return "\n".join(out)


def _hex(v):
    return f"0x{v:x}" if isinstance(v, int) else v


def try_tool(name: str, argv, timeout: int) -> dict:
    exe = shutil.which(name)
    if not exe:
        return {"status": "unavailable",
                "hint": f"install {name} to enable this section"}
    proc = _run([exe, *argv], timeout=timeout, check=False)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-2000:],
    }


def render(info_old: dict, info_new: dict, targets: list[dict],
           ext: dict) -> str:
    lines = [
        f"# Build diff: `{info_old['image']}` -> `{info_new['image']}`",
        "",
        "Generated by `scripts/diff_builds.sh` (host-side ELF reader; no "
        "binutils in the image).",
        "",
        "## Identity",
        "",
        _table(
            [["image", info_old["image"], info_new["image"]],
             ["id", info_old["id"][:19], info_new["id"][:19]],
             ["digest", (info_old["digests"] or ["-"])[0],
              (info_new["digests"] or ["-"])[0]],
             ["arch", info_old["arch"], info_new["arch"]],
             ["php", info_old.get("php_version", "?"),
              info_new.get("php_version", "?")]],
            ["field", "old", "new"],
        ),
        "",
    ]
    for target in targets:
        a, b, diff = target["old"], target["new"], target["diff"]
        lines += [
            f"## `{target['path']}`",
            "",
            _table(
                [["sha256", a.sha256[:24], b.sha256[:24]],
                 ["build-id", a.build_id[:24] or "-", b.build_id[:24] or "-"],
                 ["sections", len(a.sections), len(b.sections)],
                 ["symbols", len(a.symbols), len(b.symbols)]],
                ["field", "old", "new"],
            ),
            "",
            f"**Changed sections:** {len(diff['sections_changed'])}",
            "",
        ]
        if diff["sections_changed"]:
            lines += [_table(
                [[s["name"], s.get("state"), s.get("old_size"),
                  s.get("new_size")] for s in diff["sections_changed"][:25]],
                ["section", "state", "old size", "new size"]), ""]
        sym = diff["symbols"]
        lines += [
            f"**Functions:** {sym['common']} common, "
            f"{sym['added']} added, {sym['removed']} removed, "
            f"{sym['size_changed']} changed size.",
            "",
            "### Notable symbols",
            "",
            _table(
                [[n["name"], _hex(n["old"]), _hex(n["new"]), _hex(n["shift"]),
                  f"{n['old_size']} -> {n['new_size']}"]
                 for n in diff["notable"]],
                ["symbol", "old", "new", "shift", "size"],
            ),
            "",
            "### Address shift",
            "",
        ]
        sh = diff["shift"]
        if sh["unique"]:
            mode_s, mode_c = sh["mode"]
            lines += [
                f"Median shift `{_hex(sh['median'])}`, mode `{_hex(mode_s)}` "
                f"({mode_c} functions), {sh['unique']} distinct shifts.",
                "",
                _table([[_hex(s), c] for s, c in sh["histogram"]],
                       ["shift", "functions"]),
                "",
                "Top movers:",
                "",
                _table([[_hex(v), _hex(s), n] for n, s, v in sh["top"][:10]],
                       ["new address", "shift", "symbol"]),
                "",
            ]
        if sym["added_names"]:
            lines += ["**Added (first 20):** " +
                      ", ".join(f"`{n}`" for n in sym["added_names"][:20]), ""]
        if sym["removed_names"]:
            lines += ["**Removed (first 20):** " +
                      ", ".join(f"`{n}`" for n in sym["removed_names"][:20]),
                      ""]

    lines += ["## External engines", ""]
    for name, result in ext.items():
        lines.append(f"- **{name}**: {result['status']}"
                     + (f" — {result.get('hint', '')}"
                        if result.get("hint") else ""))
    lines += [
        "",
        "## Reproduce",
        "",
        "```sh",
        f"scripts/diff_builds.sh --old {info_old['image']} "
        f"--new {info_new['image']}",
        "```",
        "",
        "A constant shift across unrelated functions means the image layout "
        "moved; a per-symbol shift means code before it changed size. Either "
        "way, re-extract offsets per build (`scripts/extract_offsets.sh`) "
        "rather than reusing a page-delta.",
        "",
    ]
    return "\n".join(lines)


def profile_row(info: dict, path: str, binary: elf.Elf,
                codename: str) -> dict | None:
    zif = binary.symbol("zif_system")
    dtor = binary.symbol("zval_ptr_dtor")
    if not zif or not dtor or info["arch"] not in profiles.ARCH_DEFAULTS:
        return None
    bias = profiles.ARCH_DEFAULTS[info["arch"]]["leak_bias"]
    return {
        "id": f"php-{info.get('php_version', 'unknown')}-{codename}-"
              f"{info['arch']}",
        "image": info["image"],
        "php_version": info.get("php_version", "unknown"),
        "arch": info["arch"],
        "codename": codename,
        "libphp_path": path,
        "libphp_sha256": binary.sha256,
        "build_id": binary.build_id,
        "zval_ptr_dtor": dtor.value,
        "zif_system": zif.value,
        "zif_passthru": (binary.symbol("zif_passthru").value
                         if binary.symbol("zif_passthru") else None),
        "leak_dtor": dtor.value,
        "leak_dtor_biased": dtor.value + bias,
        "validated": False,
    }


def self_test() -> bool:
    assert elf.self_test()
    a = elf.Elf(sections=[elf.Section(".text", 1, 0, 0, 0, 10, 0, 0, b"abc")],
                symbols=[elf.Symbol("f", 0x100, 4, elf.STT_FUNC,
                                    elf.STB_GLOBAL, 1)])
    b = elf.Elf(sections=[elf.Section(".text", 1, 0, 0, 0, 10, 0, 0, b"abc")],
                symbols=[elf.Symbol("f", 0x200, 8, elf.STT_FUNC,
                                    elf.STB_GLOBAL, 1)])
    diff = compare(a, b)
    assert diff["symbols"]["common"] == 1, diff
    assert diff["shift"]["mode"] == (0x100, 1), diff["shift"]
    assert diff["notable"] == [], diff["notable"]
    md = render({"image": "a", "id": "a" * 20, "digests": [], "arch": "x"},
                {"image": "b", "id": "b" * 20, "digests": [], "arch": "x"},
                [{"path": "libphp.so", "old": a, "new": b, "diff": diff}],
                {"ghidriff": {"status": "unavailable"}})
    assert "Build diff" in md and "0x100" in md, md[:200]
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--old", default="php:8.4.26-apache")
    ap.add_argument("--new", default="php:8.4.27-apache")
    ap.add_argument("--platform", default=None)
    ap.add_argument("--target", action="append", default=[],
                    help="extra binary path inside the image (repeatable)")
    ap.add_argument("--out", default=None, help="Markdown path")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--codename", default="bookworm")
    ap.add_argument("--ghidriff", action="store_true")
    ap.add_argument("--abidiff", action="store_true")
    ap.add_argument("--write-profile", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        print("[ok] build_diff self-test (ELF parse, symbol shift, report)")
        return 0

    paths = args.target or list(LIBPHP_CANDIDATES)
    work = Path(tempfile.mkdtemp(prefix="php2shell-diff-"))
    try:
        info_old = inspect(args.old, args.platform)
        info_new = inspect(args.new, args.platform)
        old_files = extract(args.old, paths, work / "old", args.platform)
        new_files = extract(args.new, paths, work / "new", args.platform)
        common = sorted(set(old_files) & set(new_files))
        if not common:
            raise DockerError(
                f"no common target: old={sorted(old_files)} "
                f"new={sorted(new_files)}")
        targets = []
        for path in common:
            a = elf.load(str(old_files[path]))
            b = elf.load(str(new_files[path]))
            targets.append({"path": path, "old": a, "new": b,
                            "diff": compare(a, b)})

        ext: dict[str, dict] = {}
        first = targets[0]
        if args.ghidriff:
            ext["ghidriff"] = try_tool(
                "ghidriff", [str(first["old"].path), str(first["new"].path),
                             "-o", str(work / "ghidriff")], 1800)
        if args.abidiff:
            ext["abidiff"] = try_tool(
                "abidiff", [str(first["old"].path),
                            str(first["new"].path)], 300)
        ext.setdefault("ghidriff", {
            "status": "unavailable", "hint": "pass --ghidriff to run it"})
        ext.setdefault("abidiff", {
            "status": "unavailable", "hint": "pass --abidiff to run it"})

        md = render(info_old, info_new, targets, ext)
        slug = f"{args.old}--{args.new}".replace(":", "_").replace("/", "_")
        out = Path(args.out) if args.out else ROOT / "docs" / f"DIFF_{slug}.md"
        json_out = (Path(args.json_out) if args.json_out else
                    ROOT / "reports" / "build-diff" / f"{slug}.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        payload = {
            "schema": 1,
            "old": info_old,
            "new": info_new,
            "targets": [{"path": t["path"],
                         "old_sha256": t["old"].sha256,
                         "new_sha256": t["new"].sha256,
                         "old_build_id": t["old"].build_id,
                         "new_build_id": t["new"].build_id,
                         "diff": t["diff"]} for t in targets],
            "external": ext,
        }
        json_out.write_text(json.dumps(payload, indent=2, sort_keys=True)
                            + "\n", encoding="utf-8")
        print(f"[ok] {out}")
        print(f"[ok] {json_out}")
        for t in targets:
            s = t["diff"]["symbols"]
            mode = t["diff"]["shift"]["mode"]
            print(f"     {t['path']}: {s['common']} funcs, "
                  f"+{s['added']}/-{s['removed']}, "
                  f"mode shift {_hex(mode[0]) if mode else '-'}")

        if args.write_profile:
            profile_target = next(
                (t for t in targets if "libphp" in t["path"]), targets[0])
            row = profile_row(info_new, profile_target["path"],
                              profile_target["new"], args.codename)
            if row is None:
                print("[warn] profile not written: zif_system/zval_ptr_dtor "
                      "not both present")
            else:
                path = offsets.merge([row],
                                     profiles.PROFILE_DIR / "offsets.json")
                print(f"[ok] profile row {row['id']} -> {path}")
        return 0
    except DockerError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"[keep] {work}")


if __name__ == "__main__":
    sys.exit(main())
