# Phase 1/2 results — real-app chains for CVE-2026-115560 → var_destroy

**Date:** 2026-10-31  
**Scope:** LAB-ONLY, `127.0.0.1`; fixed benign command `id>/tmp/vd 2>&1`.
Published 2026-10-31; see `docs/RESPONSIBLE_PUBLICATION.md`.

Companion docs: `PLAN_115560.md`, `GADGET_SURVEY_115560.md`,
`PHASE0_115560_FREEZE.md`, `DRUPAL_115560.md`, `ROUNDCUBE_115560.md`,
`DRUPAL_AUTOLOAD_PROBE.md`, `NOVELTY_115560_2026-10-31.md`,
`DEFENSE_115560.md`.

## Gate summary

| Gate | Condition | Result |
|---|---|---|
| G0 | four positives + all controls negative | **PASS** (frozen, `PHASE0_115560_FREEZE.md`) |
| G1 | Drupal P5 UAF + terminal through 115560 | **PASS** on 8.4.27 and 8.5.12; `cleanup=On` race PASS on 8.4.27 |
| G2 | Roundcube plugin path + terminal | **PASS for the plugin-assisted profile**; stock db/redis blocker documented |
| G4 | novelty + embargo decision | **Novelty resolved (composition is public); embargo decision pending user** |

## Phase 1 — Drupal 11.4.11 P5 (G1 PASS)

**Chain:** stock Drupal core
`YamlCacheCollectorDiscovery::__destruct → MenuActiveTrail::destruct →
CacheCollector::updateCache → MemoryBackend::get → prepareItem →
unserialize($prepared->data)`.

**Delivery:** the real 115560 session decoder (`php_serialize` upload-progress
record; app switches to `php`; `session_start()`). No application
`unserialize()` sink.

**Heap shaping:** `cid_len=8102`, `nk=65` string-keyed `keysToPersist` entries,
`npad=4` late 8160-byte strings. The `$cid . ':' . __CLASS__` lock name
(8135 B → 8160 allocation) reclaims the freed `var_entries` chunk; `cid[0:8]`
is the forged `zval *`.

| build | container / port | main | zif | delta | proof |
|---|---|---|---|---|---|
| 8.4.27 | `php2shell-115560-drupal-8427` / `18300` | `0xffff9ee00000` | `0xffffa1401510` | `0x7b019` | `uid=33(www-data)` |
| 8.5.12 | `php2shell-115560-drupal-8512` / `18301` | `0xffff82000000` | `0xffff7ef35490` | `0x7b019` | `uid=33(www-data)` |

**ASAN:** `heap-use-after-free`, READ of size 8 at
`var_unserializer.c:906`, through `var_destroy` → `ps_srlzr_decode_php` →
`php_session_start()`.

**Autoload fidelity:** `vd_nopreload.php` (no `class_exists()` preload) still
reaches `uid=33`, so the stock Composer autoloader resolves the P5 classes
during the normal decode. (`DRUPAL_AUTOLOAD_PROBE.md`.)

**Controls:** `--cid-len 100` (no 8160 spray) → HTTP 200, no proof;
`--bias-zif 0x1000` → no proof. Both keep `nk=65,npad=4`.

**`cleanup=On` race (default profile, 18302):** PASS on 8.4.27. A multi-child
Apache config lets the streaming upload (8×64 KiB, 0.6 s apart) hold one child
while the consumer GET runs in another at `settle=0.7 s`. `vd_seed.php` writes
the persistent first record (`seed_d = "|" + valid a:1018`); the `php` decoder
parses it as record #1 and the streamed progress payload as record #2.
Evidence: `main=0xffff9d000000`, `delta=0x7b875`, `uid=33`; controls
`--settle 6.0`, `--no-seed`, and `--bias-zif 0x1000` are negative.
Independently re-run in this session.

**Caveat:** needs the non-default
`session.storage.options.serialize_handler: php` line. This is a config-gated
profile, not default Drupal.

## Phase 2 — Roundcube 1.6.11 (G2 plugin-assisted PASS)

**Load order:** plugin top-level code runs in `rcmail::startup()` before
`session_init()`; the simple-gadget destructor fires during the decode, before
`plugin-init`.

**Write path:** the upload-progress hook writes
`sess_<sid>` under `php_serialize`; the consumer reads the same file with
`session_storage='php'`.

**Terminal:** plugin `CachePurge` dtor sprays and re-enters `R:1020;`; forged
`zif_system` writes `uid=33`:
- 8.4.27 `:18310`, `delta=0x8d9c1`;
- 8.5.12 `:18311`, `delta=0x9e9c1`.

**Controls:** `--bias-zif 0x1000`, `--noswitch`, `--nogadget` → no proof.

**Structural blocker:** stock Roundcube only runs
`ini_set('session.serialize_handler','php')` in
`rcube_session::register_session_handler()`, called by db/redis/memcache session
drivers. Those read their own store, so the upload-progress **file** record is
never decoded. Reproduced with SQLite: the DB row had no `upload_progress`
bytes. The pass therefore uses a plugin that supplies the same switch before
`session_init()` while `session_storage='php'` reads the file. It is a
plugin/custom-code profile, not a stock chain.

## Phase 4 — novelty (composition is public)

The full four-stage composition is published by `ACD421/PHP`
(`weapons/lab/fa_jammy.sh`, 2026-10-26), and the default `cleanup=On`
slow-upload race by `zero1` (2026-10-21). The prior “nobody published the
composition” sentence is retracted.

Defensible narrow delta:

- patched **8.4.27 / 8.5.12** pre-auth end-to-end;
- **default `cleanup=On` race + var_destroy terminal** (two-record seed);
- **arm64 no-`/proc`** measured full-window result;
- measured raw-session carrier and per-build constants.

Not claimed: default PHP, “first”, a new composition, a new CVE, or a new
`disable_functions`/pinning technique.

## Recommended next steps

1. Decide publication/embargo (see options in
   `NOVELTY_115560_2026-10-31.md` §6).
2. If publishing, credit `ACD421/PHP`, B63, googlesky, mnk-works,
   TheCyberGeek/Qi Deng, dinosn, and Calif.
3. Keep the Drupal/Roundcube profiles framed as **config-gated / plugin-gated**,
   not default-app chains.
4. Optional breadth: Phase 3 public simple-gadget baseline (not required for
   the real-app result).
