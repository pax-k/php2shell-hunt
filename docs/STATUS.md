# PHP2Shell — current status, RCE scenarios, and research backlog

**Snapshot:** 2026-10-31
**Scope:** this repo's own labs only; fixed benign command allowlist
(`id | uname | whoami`); no remote target packaging.
**Primary sources:** the repo's POCs/labs, the official advisories
(2026-10-21), Wiz's exploitation telemetry (2026-10-27), and the public
ecosystem survey in [`ECOSYSTEM.md`](ECOSYSTEM.md). The method that produced
this status is [`PIPELINE.md`](PIPELINE.md).

**2026-10-30 external review:** [`RESEARCH_REVIEW_2026-10-30.md`](RESEARCH_REVIEW_2026-10-30.md)
— public prior art, corrected novelty claims, and the next chain.

**2026-10-31 surface map:** [`ATTACK_SURFACE_MAP.md`](ATTACK_SURFACE_MAP.md)
— the full layer map (core, session, wire, extensions, app gadgets, client,
deployment) and the ranked 0day frontier with per-row falsification tests.

Status legend:

- ✅ **validated** — reproduced in a lab in this repo, command/output proof
- ⚠️ **harness** — implemented and unit-tested; live reproduction not achieved
- 📄 **documented** — recorded for reference/detection; no active primitive
- ❌ **not present** — no lab or code yet

---

## 0. Repository contract

Non-finding rows, kept separate from the exploitation status below.

| Contract | State | Receipt |
|---|---|---|
| Scanner scope guard rejects non-loopback before socket creation | validated | `tests/test_scanner.py` |
| Scanner version boundaries and exit-code matrix | validated | `tests/test_scanner.py` |
| PoC allowlist and loopback transport | validated | `tests/test_pocs.py` |
| Extension inventory vs manifest | validated | `scripts/inventory_extensions.py` |
| Lab binds loopback, unprivileged, image defaults | validated | `lab/docker-compose.yml`, `scripts/check.py` |
| Offline gate: consistency, manifests, compile, tests | validated | `scripts/check.sh` |

The stock baseline receipts (`php --ini` = `(none)`, `upload_progress=1/1`,
`memory_limit=128M`, `post_max_size=8M`) are for `php:8.4.26-apache`; the
8.4.27 image is the patched negative. Scanner verdicts are triage, not RCE.

Tiers used below: `STOCK`, `CONFIG-GATED`, `LAB-ONLY` (see `GOAL.md`). Nothing
in this repository is `STOCK`.

## 1. TL;DR

RCE today comes from **two application-level chains that survive the PHP
patch** (Chain A and Chain C), plus a **core chain now reproduced
un-instrumented** on stock `php:8.4.26-apache` (blocked on patched
8.4.27), plus an older **instrumented FPM proof** (rung 5b).

- **Reliable now (lab):** Chain A / session poisoning + LFI; Chain C
  (handler mismatch + gadget). Both are verified on patched 8.2.35.
- **Un-instrumented core chain:** CVE-2026-109619 (9bie ladder, mod_php)
  — in-band Set-Cookie leak → `zif_system` dispatch, fixed benign command,
  no oracle/gdb. **Verified on amd64 and natively on arm64**, 3/3 across
  three distinct ASLR generations, and across the **8.4 patch series (6
  builds, pos/neg/bias each)**; blocked on patched 8.4.27.
- **Still instrumented:** the 8.2.34 FPM rung-5b proof (uses `[UAFDBG]`).
- **Open:** cross-build portability (per-build offsets), a native-arch
  ASLR cross-check, and CVE-2026-109618's mod_php pre-app escalation.

The core CVEs are now reproduced *un-instrumented* on one build. What
remains is generalization (portability), not feasibility.

---

## 2. RCE scenario matrix

| # | Scenario | Preconditions | SAPI / versions | Status | Evidence | Real-world odds |
|---|---|---|---|---|---|---|
| 1 | **Chain A — session-file injection + LFI** | `session.upload_progress=On` (default) + reachable LFI + session save path includable | Any SAPI, 5.4–8.5.11; **verified on patched 8.2.35 / 8.4.27 / 8.5.12** | ✅ | `poc/verify_chain_a_lfi.py`; `lab-patched :18087/:18088` | **Medium** — legacy apps, plugins, admin panels |
| 2 | **Session poisoning + LFI** (Wiz "branded" category) | `upload_progress=On` + LFI; PHP code in the progress *value* | Any SAPI; verified on 8.2.34, **8.4.27, 8.5.12** | ✅ | `poc/verify_session_poison_lfi.py`; `lab-patched :18087/:18088` | **Medium** — no filename-injection fix needed |
| 3 | **Chain C — handler mismatch + gadget** | `php_serialize` write dir vs `php` read dir + loaded `__destruct` gadget | Any SAPI, 5.4–8.5.11; **verified on patched 8.2.35 / 8.4.27 / 8.5.12** | ✅ | `poc/verify_rce_gadget.py`; `lab-patched :18087/:18088` | **Lower** — config drift + framework gadget |
| 4 | **Chain B — `var_destroy` re-entry UAF → terminal call** | Reachable `unserialize()` of attacker data + a re-entry gadget | **survives patched 8.4.27 / 8.5.12** (patch-gap); `uid=33` on stock ZendMM 8.4.26/8.4.27/8.5.12 with a **lab-assisted** carrier address | ✅ lab-only | `poc/verify_vardestroy_rce.py`, `poc/verify_uaf_asan.php`, `lab-asan-85x/`; `:18130`/`:18131`/`:18133` | **Medium for impacted apps** — PHP-core UAF the CVE patch does not fix; in-band leak still open |
| 4b | **115560 → var_destroy → `zif_system` (no app `unserialize()` sink)** | `upload_progress=On` + `php_serialize` config + runtime switch to `php` + loaded re-entry `__destruct` | **patched 8.4.27 / 8.5.12 mod_php**; pre-auth; arm64 18-bit `main` brute | ✅ lab-only | `poc/verify_115560_vardestroy.py`; `lab-115560/` `:18200` (8.4.27) / `:18201` (8.5.12) | **High if preconditions** — session decoder is the sink; carrier seed per target |
| 5 | **CVE-2026-109619 core chain, mod_php (9bie ladder)** | OOM → stale state; in-band leak + per-build offsets + same-worker pairing | mod_php, ≤8.5.11; **verified on 8.4.26 amd64 + arm64** (3/3 ASLR gens, native arm64) | ✅ | `poc/verify_109619_remote.py`, `php2shell/remote.py`; `:18120`/`:18121` (amd64), `:18130`/`:18131` (arm64) | **High within mod_php** — 9bie claimed 10/10; reproduced here on two arches |
| 6 | **CVE-2026-109619 core chain, FPM (rung 5b)** | instrumented `[UAFDBG]` calibration oracle | FPM, 8.2.34 | ⚠️ instrumented | `poc/verify_109619_rce.py`, `lab-zendmm-fpm`/`lab-zendmm-fpm-8235` | mem-corruption proof; FPM leak unreliable (dinosn: DoS-only) |
| 7 | **CVE-2026-109618 mod_php pre-app** | OOM → unwritten bucket → `free_obj = zif_system`; leak on a 128M worker, fire on a fresh fork-shared 8M worker | mod_php, 8.4.26 (arm64); 8.4.27 blocks the lab-assisted path | ✅ **in-band** | `poc/verify_109618_inband.py`, `poc/verify_109618_zif.py`, `lab-109618-fork/` | **High** — in-band RCE on stock mod_php; no `/proc`, no debugger |
| 8 | **CVE-2026-109618 FPM** | Startup OOM → child exits; post-startup OOM source-susceptible | FPM | ⚠️ boundary mapped | `docs/ANALYSIS.md` §0.4–0.5 | **Low** — no complete exploit |
| 9 | **FrankenPHP / LSAPI** | Analogous to mod_php / FPM | Untested | ❌ | — | **Unknown** — should be measured |

### 2.1 115560 → var_destroy → `zif_system` — scope and best bets

**Proven:** pre-auth RCE on patched 8.4.27/8.5.12, **no application
`unserialize()` sink**, `uid=33`, arm64 no-`/proc` `main`-window brute (8.5.12
full window at attempt 351; 8.4.27 full window at attempt 307). **Also proven:**
the `disable_functions`-hardened 8.4.27 target (`:18203`;
`system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec`) still executes the
forged `zif_system` (`uid=33`), while `function_exists('system') === false` and
a direct `system()` is fatal; the `--bias-zif` control blocks
(`docs/NOFUNC_115560.md`). **Cleanup/default:** the `cleanup=On` race is proven
on both builds (`:18204`/`:18205`; deltas `0x6d875`/`0x80875`, multi-child +
`seed.php`); `__wakeup`/`__unserialize` are negative (locked), only `__destruct`
works (`docs/RACE_WAKEUP_115560.md`). **Deployment/arch:** 8-child prefork works with and
without 7-holder pinning (`docs/WORKERS_115560.md`); amd64/Rosetta works with
`measure_amd64.py` + explicit addresses (`docs/X86_64_115560.md`), but native
x86-64 is ~2^19 and still needs a leak. **Not proven /
not claimed:** default PHP (default handler is `php`, so 115560 does not
apply); a default app (needs a re-entry `__destruct`; no stock app combines the
switch + gadget); native x86-64 generality. The direct lab profile uses
`cleanup=Off`, but the default `cleanup=On` race is proven; multi-worker/pinning
are verified.

**Real-app chains (Phase 1/2, 2026-10-31):**
- **Drupal 11.4.11 P5 — G1 PASS.** Stock core
  `YamlCacheCollectorDiscovery → MenuActiveTrail → CacheCollector::updateCache
  → MemoryBackend::prepareItem → unserialize` reaches the var_destroy terminal
  through the real session decoder on stock ZendMM: `uid=33` on 8.4.27
  (`:18300`, `delta=0x7b019`) and 8.5.12 (`:18301`, same delta), with
  `nk=65,npad=4` heap shaping. The default **`cleanup=On` race** also lands on
  8.4.27 (`:18302`, `delta=0x7b875`, multi-child + `vd_seed.php` first
  record); controls negative. It needs the non-default
  `session.storage.options.serialize_handler: php` line. ASAN shows the UAF at
  `var_unserializer.c:906` through `php_session_decode`.
  Evidence: `docs/DRUPAL_115560.md`, `docs/DRUPAL_AUTOLOAD_PROBE.md`.
- **Roundcube 1.6.11 — G2 PASS for a plugin-assisted profile.** Plugin load
  order before `session_init()`, upload-progress file write path, simple gadget
  and var_destroy terminal all reproduce (`uid=33` on 8.4.27 `:18310` /
  8.5.12 `:18311`). **Structural blocker:** stock Roundcube only executes
  `ini_set('session.serialize_handler','php')` for db/redis/memcache drivers,
  and those read their own store, never the upload-progress file. The lab
  plugin supplies the switch while `session_storage='php'` reads the file.
  Evidence: `docs/ROUNDCUBE_115560.md`.
  **Redis variant tested 2026-10-31, negative:** the upload-progress record is
  written by phpredis and stock `rcube_session_redis` does run the `php`
  switch, but `read()` expects its own `a:3:{changed,ip,vars}` wrapper, so the
  hook's `a:1:{...}` blob is never decoded. Key namespaces can be aligned
  (`session.save_path="tcp://redis:6379?prefix="`), which isolates the envelope
  as the blocker. The plugin is still needed (switch for `php` storage, or a
  store adapter for `redis`). Evidence: `docs/ROUNDCUBE_REDIS_115560.md`.

**Novelty correction (2026-10-31):** the full composition is **public** —
`ACD421/PHP` published it in `weapons/lab/fa_jammy.sh` (2026-10-26) and the
`cleanup=On` race in `zero1` (2026-10-21). The prior “nobody published this
composition” claim is retracted. Our defensible delta is the **patched
8.4.27/8.5.12 pre-auth end-to-end, cleanup=On + var_destroy combination,
arm64 no-`/proc` final, and measured carrier/constants**. See
`docs/NOVELTY_115560_2026-10-31.md`.

**Best bets:** (A) `cleanup=On` race (proven); (B) real gadget: Drupal 11 P5
(config-gated, now terminal through 115560) and the Roundcube plugin profile;
no stock Roundcube gadget and stock db/redis is blocked (the Redis variant was
tested on 2026-10-31: same key namespace is configurable, but the driver's
`vars` envelope is a second, structural blocker); only `__destruct` runs
unlocked (`__wakeup`/`__unserialize` are locked, not a re-entry); (C)
`disable_functions`-hardened targets (proven); (D) multi-worker (proven); (E)
x86-64 needs a leak; (F) publication/defense framing. Details:
`docs/GADGET_SURVEY_115560.md`, `docs/PLAN_115560.md`.

---

## 3. Decision tree: do we get RCE?

```text
upload_progress = On?
├─ no  → Chain A / session poison dead; 109619 session consumer dead.
│         Still possible: Chain C (handler mismatch + gadget), 109618 mod_php.
└─ yes → Is there a reachable LFI?
         ├─ yes → Chain A or session poison → RCE (works on patched 8.2.35)
         └─ no  → Is there a cross-dir serialize_handler mismatch + loaded gadget?
                  ├─ yes → Chain C → RCE (works on patched 8.2.35)
                  └─ no  → Core chain only:
                           need same worker + in-band leak + build profile
                           → currently lab-only (rung 5b)
```

**Practical answer:** if you want RCE *today*, the reliable paths are
application-level, not the core CVEs. A stock WordPress/Joomla with no LFI
and no gadget does **not** get RCE from this repo — the adaptive driver
correctly declines (verified in `docs/PLAN.md` Phase 4).

---

## 4. Evidence index (how to re-verify)

| Claim | Command | Lab |
|---|---|---|
| Chain A RCE | `python3 poc/verify_chain_a_lfi.py --target http://127.0.0.1:18080` | `lab-chain-a/` |
| Chain C RCE | `python3 poc/verify_rce_gadget.py --target http://127.0.0.1:18080 --cmd id` | `lab-chain-a/` |
| 115560 → var_destroy → `zif_system` (8.4.27) | `python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18200 --container php2shell-115560-8427 --build 8.4.27 run` | `lab-115560/` `:18200` |
| 115560 → var_destroy → `zif_system` (8.5.12) | `python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18201 --container php2shell-115560-8512 --build 8.5.12 run` | `lab-115560/` `:18201` |
| 115560 scope + best bets | `docs/PLAN_115560.md` (not default PHP; cleanup=Off lab; re-entry gadget required) | — |
| Chain A/C survive 8.2.35 | same POCs against `:18081` | `lab-8235/` |
| Rung 5b terminal call | `python3 poc/verify_109619_rce.py --target http://127.0.0.1:18085 --cmd id` | `lab-zendmm-fpm/` |
| Rung 5b blocked on 8.2.35 | same POC against `:18086` | `lab-zendmm-fpm-8235/` |
| 109619 FPM ASAN UAF | `python3 poc/verify_109619_fpm_chain.py --target http://127.0.0.1:18084` | `lab-asan-fpm/` |
| 109619 mod_php ASAN UAF | `python3 poc/verify_109619_modphp_chain.py --host 127.0.0.1 --port 18082` | `lab-asan-modphp/` |
| 109618 OOM trigger | `python3 poc/verify_cve_109618_oom.py --host 127.0.0.1 --port 18082` | `lab-asan-modphp/` |
| post_max_size bypass | `python3 poc/verify_postmax_bypass.py --mode apache --host 127.0.0.1 --port 18082` | `lab-asan-modphp/` |
| Worker pinning (Apache) | `python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18110 --holders 3` | `lab-pure-modphp/` |
| Worker pinning (FPM) | `python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18097 --holders 3` | `lab-pinned/` |
| Amplification (32M) | `python3 poc/verify_amplification.py --target http://127.0.0.1:18110 --mb 1.5` | `lab-pure-modphp/` |
| Amplification (128M) | `python3 poc/verify_amplification.py --target http://127.0.0.1:18111 --mb 4 --container php2shell-pure-modphp-8m` | `lab-pure-modphp/` |
| Legacy 1005-part + bypass | `python3 poc/verify_legacy_chain.py --target http://127.0.0.1:18111 --path /probe.php --container php2shell-pure-modphp-8m` | `lab-pure-modphp/` |
| Auto-LFI | `python3 poc/verify_lfi_discovery.py --target http://127.0.0.1:18097` | `lab-pinned/` |
| Session poison + LFI | `python3 poc/verify_session_poison_lfi.py --target http://127.0.0.1:18097` | `lab-pinned/` |
| Content-Type bypass | `python3 poc/verify_content_type_bypass.py --target http://127.0.0.1:18110` | `lab-pure-modphp/` |
| SAPI/limit profile | `python3 poc/verify_sapi_profile.py --target http://127.0.0.1:18110` | `lab-pure-modphp/` |
| Leak derivation (offline) | `python3 poc/verify_psid_leak.py --self-test` | none |
| **Working leak + fire (rung 6)** | `python3 poc/verify_109619_remote.py --target http://127.0.0.1:18120 --cmd id` | `lab-pure-modphp :18120` (fires), `:18121` (8.4.27 blocks) |
| dinosn PS(id) shape (8.5.11) | `python3 poc/verify_psid_leak.py --target http://127.0.0.1:18110` | `lab-pure-modphp/` (harness; 8.5.11 target needs native arch) |
| Capability matrix | `python3 php2shell_adaptive.py --capabilities` | none |

---

## 5. Research backlog (prioritized)

### P0 — Close rung 6 (in-band leak) — **DONE**
`php2shell/remote.py` + `poc/verify_109619_remote.py` reproduce the 9bie
A1/B1 in-band leak on stock 8.4.26-apache: a >64-byte `Set-Cookie:
PHPSESSID` carries ~800 KB of heap, from which `zval_ptr_dtor` yields the
libphp base and the 87-pointer fingerprint yields the ZendMM chunk base.
No oracle, no gdb, no docker-log access.

- **Success:** `Set-Cookie` decoded length 819208 B; libphp base derived via
  `zval_ptr_dtor = 0x65EB60`; fire dispatches `zif_system = lib+0x465370`.
- **Remaining caveat:** the environment is amd64 under qemu-user, where the
  mmap layout is deterministic — a true multi-generation ASLR cross-check
  still needs a native amd64 (or aarch64) host. The leak is load-bearing
  regardless (see §7).

### P1 — Multi-worker chain at scale — **DONE for mod_php (amd64 + arm64)**
Rung 5b runs on `pm.max_children=1`; the un-instrumented ladder runs on the
official prefork (`MaxRequestWorkers=150`), pinning 149 workers with the
repo's own `pinning.WorkerPinner` and firing on the one remaining child.

- **Success (amd64):** chain fires at 150 workers on `:18120`.
- **Success (native arm64):** 3/3 across three fresh containers at 150
  workers on `:18132`, three different libphp/chunk bases each time —
  scale, pinning, and ASLR all hold natively.
- **Open:** the 8.2.34-FPM rung-5b pair on a multi-child FPM pool
  (`lab-pinned :18097`) — the FPM leak is the unsolved part (dinosn:
  DoS-only), not the pinning.

### P2 — Portability / build matrix — **IN PROGRESS (harness landed; version matrix is negative)**
`docs/OFFSETS.md` now has a repeatable extraction pipeline and 8 extracted
aarch64 rows (8.2.34, 8.2.35, 8.3.35, 8.3.36, 8.4.26, 8.4.27, 8.5.11,
8.5.12), each tied to a `libphp.so` SHA-256 + build-id
(`php2shell/offsets.py`, `profiles/offsets.json`). The 8.5.11 values match the
public dinosn calibration.

The triad runner is `poc/verify_matrix.py` (`php2shell/matrix.py`,
`lab-matrix/`): per row it requires **fire + output (pos)**, the **patched
build blocks at the leak (neg)**, and **`+0x1000` bias prevents the fire
(bias)**. Result on native arm64:

- **8.4 patch series — proven 6/6.** 8.4.10, 8.4.20, 8.4.23, 8.4.24, 8.4.25,
  8.4.26 each fire (`uid=33`), are blocked on 8.4.27, and are prevented by the
  bias. The same leak shape and 87-pointer/`S_OFF` geometry hold across the
  series; only symbols and the leak-side qword bias change.
- **8.2.34 / 8.3.35 / 8.5.11 — not proven.** The pos leg fails at the **leak
  shape**: a normal session id instead of a disclosure. A bounded sweep
  (parts 700–920, depth 56/64, five `LEAK_SPEC` variants) did not disclose.
  The neg/bias legs are reported `skip` when pos fails (vacuous without a
  leak).
- **8.4.1 — leak discloses but yields no usable pointers.** Early-series
  shape difference; excluded.

| build | arch | pos | neg | bias | proven |
|---|---|---|---|---|---|
| 8.4.10 | aarch64 | ok | ok | ok | ✅ |
| 8.4.20 | aarch64 | ok | ok | ok | ✅ |
| 8.4.23 | aarch64 | ok | ok | ok | ✅ |
| 8.4.24 | aarch64 | ok | ok | ok | ✅ |
| 8.4.25 | aarch64 | ok | ok | ok | ✅ |
| 8.4.26 | aarch64 | ok | ok | ok | ✅ |
| 8.4.1 | aarch64 | FAIL (no pointers) | skip | skip | ❌ |
| 8.2.34 | aarch64 | FAIL (leak shape) | skip | skip | ❌ |
| 8.3.35 | aarch64 | FAIL (leak shape) | skip | skip | ❌ |
| 8.5.11 | aarch64 | FAIL (leak shape) | skip | skip | ❌ |

Two portability fixes were required for the series: (1) the leaked qword is
the plain `zval_ptr_dtor` symbol on most builds but `symbol + 0xB` on 8.4.26 —
`parse_leak` now tries both and picks the page-aligned base; (2) the
libphp↔main-chunk delta is build-dependent (8.4.10 ≈ `0x260000`, 8.4.25 ≈
`0x21d0000`) — the sanity window was widened and the 87-pointer fingerprint
does the selecting.

**Plan A ground truth (2026-10-30).** `poc/probe_ps_globals.py` reads
`ps_globals.id` (offset `0x10`) straight out of a `--cap-add=SYS_PTRACE`
worker via `/proc/<pid>/mem`, plus the libphp base from maps. Measured after a
producer request:

| build | producer | `PS(id)` after | chunk offset | outcome |
|---|---|---|---|---|
| 8.4.26 | 9bie A1 | non-NULL | **`0x137000`** (stable) | B1 reclaims it → leak |
| 8.2.34 | 9bie A1 | NULL | — | no stale state |
| 8.2.34 | mod_php 2000×60 | non-NULL | `0x5b268` / `0x5c268` (**varies**) | B1 END-cleanup never runs (no `Set-Cookie`) |
| 8.3.35 | 9bie A1 | NULL | — | no stale state |
| 8.3.35 | mod_php 2000×60 | non-NULL | `0x5b268` / `0x5c268` (**varies**) | same as 8.2.34 |
| 8.5.11 | 9bie A1 | non-NULL | `0x136000` (A1) / `0x66080` | worker aborts `zend_mm_heap corrupted` → **DoS-only** |

Interpretation: only the 8.4 branch leaves a *stable, reclaimable* `PS(id)`
with the upload-progress END cleanup still wired. On 8.2/8.3 the stale slot is
non-deterministic (no fixed in-band `LEAK_SPEC` offset) and B1 does not reach
the rfc1867 cleanup. On 8.5 the OOM corrupts the heap and the child aborts
before a consumer can run. A fixed-page/`H:` forge sweep over the full 8.5
page space and over the 8.2 stale window was negative — consistent with the
mechanism, not a tuning miss.

A **dense forge spray** (`D:<pages>:<step>`, headers every 0x40–0x100 over the
window, 4–20 values) was also negative on both builds, and B1 still sent no
`Set-Cookie` at all — confirming the ceiling is the *cleanup path*, not the
offset. Two derived tools are retained: `poc/probe_ps_globals.py` (the oracle)
and the `H:<pages>:<offset>` / `D:<pages>:<step>` leak-B specs
(`php2shell/remote.py`) for byte-exact or sprayed header placement when the
slot is not page-aligned.

The calibration harness for exactly this gap is `php2shell/calibrate.py`
(`scripts/calibrate.sh`): `derive()` recovers `S_OFF`/`MAIN_BUCKET_COUNT` from
ground truth (self-test recovers the 8.4.26 values), `sweep()` searches chunk ×
`S_OFF`, `sweep_leak()` searches A1/B1 shapes, and `fingerprint()` ranks
profiles from the leaked bytes (leak-as-fingerprint).

- Remaining: a disclosing A1/B1 shape for 8.2/8.3/8.5, per-build heap
  calibration where it does disclose, a native amd64 host (G4), and the
  distro-`Apache` finding (Ubuntu 24.04's 2.4.58 parses only one field from the
  chunked body — the lengthless bypass is not universal; see
  `scripts/distro_defaults.sh`).
- **Success criterion unchanged:** the same chain fires on 3 distinct builds
  with the full triad.

### P3 — CVE-2026-109618 complete escalation — **DONE (in-band, arm64)**
The terminal call is now reproduced on mod_php 8.4.26 arm64:

- OOM leaves `$_POST["a"]`'s last bucket unwritten; shutdown walks it;
  `free_obj = zif_system` with a fake object that doubles as
  `zend_execute_data` runs the fixed command. **No libc ROP, no gdb at
  fire time.**
- Verified with ASLR **on** and with ASLR off; `+0x1000` bias on the
  terminal address prevents the fire; patched 8.4.27 blocks.
- Address sourcing is **lab-assisted** (`/proc`): libphp base + ZendMM
  chunk base, then `B = chunk + offset` (0x5e400 fresh ASLR-on; 0x67e00
  after a 128M leak sequence).

**In-band result (2026-10-29):** Apache prefork children are forked, so
all workers share the libphp and ZendMM chunk mappings. The 128M leak runs
on one worker; the 8M OOM fire runs on a **different, fresh** fork-shared
worker using the leaked addresses. No `/proc`, no debugger. `n=46` and the
bucket-45 layout hold on the fresh worker. `poc/verify_109618_inband.py`
on `lab-109618-fork/` prints `uid=33` from the HTTP proof.

Worker selection uses a lab `pid.php` endpoint; a target without it can use
the holder-rotation fallback (`--worker-id none --retries 6`), also verified.
The patched 8.4.27 in-band control fails at the leak (`no heap pointers`), as
expected.

- FrankenPHP / LSAPI still untested.
- The stall-based UAF arming relationship remains unclarified.

### P4 — Patch-gap chains (highest defender value)
Chains A and C are repo-verified on **8.2.35, 8.4.27, and 8.5.12** — the
app-level chains survive every patched release (the PHP fix does not touch
them; they are application vulnerabilities to which the CVE patch is
orthogonal). `lab-patched/` (:18087 8.4.27, :18088 8.5.12) is the repeatable
proof.

Still open:

- ~~Reproduce `var_destroy` re-entry UAF on patched~~ — **DONE**: an ASAN 8.4.27
  and 8.5.12 build (`lab-asan-85x/`) both still raise heap-use-after-free in
  `php_var_unserialize` (`var_unserializer.c:906`) on the same trigger that
  faults at `:850` on 8.2.34. The CVE patch (which fixed the OOM/stale-state
  paths) does **not** touch this adjacent `var_destroy` re-entry bug.
- **`var_destroy` patch-gap plan (B, 2026-10-30)** — minimized to **1018
  serialized elements** (`poc/verify_var_destroy_uaf.php`, ~6.1 KB); root
  cause is `i_zval_ptr_dtor(zv)` in `var_destroy()` running the object's
  `__destruct` **without** `BG(serialize_lock)`. Silent on stock ZendMM; with
  same-size heap grooming the freed `var_entries` chunk is reclaimed and
  `R:1020` dereferences attacker bytes as a `zval *` → **SIGSEGV on stock
  8.2.34, 8.4.27 and 8.5.12** (controllable wild-pointer dereference). Proposed
  fix: hold the lock across the dtor call. See `docs/VAR_DESTROY_UAF.md`.
- **Terminal call (2026-10-30)** — the forged
  `zend_reference → zend_object → dtor_obj = zif_system` ladder executes a
  fixed benign command (`uid=33`) on stock ZendMM 8.4.26 and **patched
  8.4.27 / 8.5.12**, under mod_php and FPM/WordPress. `+0x1000` bias and
  `allowed_classes=false` block it; `disable_functions` does not.
- **Disclosure packet held outside this repo.** The vendor report for this
  class is kept in the private working tree until it is sent; nothing here
  authorises a vendor contact. See `docs/RESPONSIBLE_PUBLICATION.md`.
- **Seed-leak verdict (2026-10-30, plan b)** — the patched-build front-end was
  tested and **falsified**: (1) the 109619 `Set-Cookie` leak on 8.4.27 returns
  a normal 32-hex session id with **zero** pointer-shaped qwords
  (`poc/verify_vardestroy_seed_scan.py`); (2) the UAF's own re-entry reader
  returns typed copies only (`int(4242)`), so `data[0]=&last_zval` is not
  disclosable as bytes (`poc/verify_vardestroy_seed_b2.php`); (3) `PS(id)` is
  NULL after both producers on 8.4.27 (`probe_ps_globals.py`). The chain is a
  **leak amplifier**; the core is now build-generic via `php2shell/vdseed.py`
  + `VD_CARRIER_DELTA` (8.4.26/27 `0x6a018`, 8.5.12 `0x7b018`; other builds
  refuse). The LFI/maps shim fires `uid=33` 2/2 on patched 8.4.27.
  **Front-end caveat:** the maps parser picks the first 2 MiB rw anon mapping
  and can select the wrong chunk — it must disambiguate the ZendMM main chunk.
- **Front-end hardened (2026-10-30, iteration 22)** — `leak_candidates()`
  returns every 2 MiB-aligned candidate (exactly-2 MiB first) and the driver
  retries each with a worker reset, so a wrong pick no longer ends the run.
  Verified `uid=33` on 8.4.27 (`main+0x6a018`) and 8.5.12 (`main+0x7b018`),
  `--bias-zif 0x1000` blocks, and the FPM/WordPress `--resolve-zif` path
  falls back to `fpm_base + 0x424c70` when `disable_functions=system` removes
  the handler from the function table.
- **WordPress impact (2026-10-30)** — `lab-wp-zendmm/uaf-harness/` (lab-only
  mu-plugin) models a plugin sink + double-unserialize gadget;
  `poc/verify_var_destroy_wp.py` gets `502` and the FPM log shows
  `[UAFDBG] INIT lock=0 level=2` → `child exited on signal 11 (SIGSEGV)`.
  Per-request **DoS** for a plugin with that shape; **not** a WP-core RCE
  (core has no re-entry gadget).
- Handler-transition (CVE-2026-115560) on patched builds.

### P5 — Detection validation — **DONE**
Rules were run through a live Suricata sidecar against A1/B1/legacy/
session-poison traffic. All 10 SIDs fired under the right stimulus, and the
test exposed three real defects: the multi-line `.rules` format (nothing
loaded), repeated `http.request_body` buffers in 210961805 (inert), and the
wrong `/tmp/sess_` path in 210961807 (cannot occur). Fixed; 805/807 are now
rev 2. See `detection/README.md` §4b for counts and sensor tuning notes.

### P6 — Operational (out of repo scope)
Post-exploitation, persistence, lateral movement — deliberately excluded.

---

## 6. Controls: what actually stops each path

| Control | Stops | Does **not** stop |
|---|---|---|
| Patch to 8.2.35+ | Core 109619 rung (verified negative control) | Chains A/C (verified on 8.2.35) |
| `upload_progress=0` admin + **all workers restarted** | Chain A, session poison, 109619 session consumer | Chain C, 109618 mod_php |
| Remove/repair LFI | Chain A, session poison | Core chain, Chain C |
| Remove the gadget class | Chain C | Chain A, core chain |
| `memory_limit=-1` | Partial 109618 (not complete) | 109619 |
| `post_max_size` + frontend streaming limits | Some 109618 delivery | In-memory amplification under the wire limit |
| Multiple workers / `pm.max_requests` | Same-worker core pairing | Chains A/C |
| `RLIMIT_AS` / `RLIMIT_DATA` | Nothing — **triggers the vulnerable path** | — |

---

## 7. Honest ceilings / non-claims

- **Plan B (`var_destroy`) is self-contained on arm64 with 18-bit mmap ASLR.**
  The complete ladder (forged reference → object → `dtor_obj=zif_system`,
  `uid=33`) survives patched 8.4.27 / 8.5.12 and needs **no separate memory
  leak** on this kernel/arch: the ZendMM 2 MiB main chunk has only **9 bits**
  of entropy (`vm.mmap_rnd_bits=18` → 512 slots), is stable for the Apache
  parent's life, and a wrong guess kills only a child. `poc/verify_vardestroy_bruteforce.py`
  finds it by scanning (`--parallel`): **8.5.12 in 384 / 80 / 464 attempts
  across three ASLR generations (54.7 / 11.2 / 64.1 s)**, and **8.4.27 in
  13,200 attempts / 27.6 min** (33 lib positions), with no maps/leak/app bug. The **fire sink** is still required (an
  app `unserialize()` with attacker bytes plus the re-entry gadget).
  **Ceiling:** on a host with `mmap_rnd_bits=28` (x86_64 default) the same scan
  is 2^19 slots and infeasible — there Plan B remains a leak amplifier needing
  one external address (LFI / curl-file SSRF / XXE, all proven). T1's
  4.1M-execution ASAN fuzz of `unserialize()`/`session_decode()` found **no**
  generic in-band seed, so a 28-bit host needs an external leak or a new bug.
  The scan is also **noisy**: a miss kills a worker, so a full sweep crashes
  hundreds of children (process-watcher / availability risk); and the **fire
  sink** (an app `unserialize()` plus the re-entry gadget) is still required —
  what is eliminated is the separate leak, not the sink.
- **Gadget precondition reduced for Joomla 5 (2026-10-30).** The re-entry
  destructor is available from **stock Composer-autoloaded classes**
  (`Mail::__destruct -> PHPMailer::smtpClose -> DataSet::__call ->
  FnStream::close -> Registry::__clone -> unserialize`), ASAN-confirmed on
  8.4.27/8.5.12 with no lab class. WordPress's real gadget is gated by
  `!gc_enabled()` (not reachable as shipped); built-ins are a clean negative.
  The sink (`unserialize()` or `Phar::getMetadata()`) is still required.
- **8.2 / 8.3 covered (2026-10-31).** Both 8.2.34 and 8.3.35 have 512 main
  slots (18-bit) and the same carrier/lib geometry (delta 0x6D018 post-crash,
  0x6E018 warm, 0x59018 cold; lib j=1..32). Full brute force: 8.2.34 13,519
  attempts/1516.6 s, 8.3.35 11,363/1232.4 s. The GH-22554 leak is reachable via
  the **old** `registerPhpFunctions` API (leak-seeded 16/3.5 s and 8/0.6 s).
- **Worker model (2026-10-30).** On a stock 150-worker prefork with a warm VM,
  `main+0x6a018` held 18/18; leak-seeded fire is 14–30 guesses / 3.4–4.7 s
  with no pinning/respawn. Cold start shifts the delta by `-0x11000` (one
  warm-up request fixes it). Stock FPM needs a per-request latch; with
  `pm.max_requests=1` the delta is stable at `0x10c018`.
- **Second self-contained path, 8.4.27 only (new in-band seed).** GH-22554 (a
  DOMXPath PHP-function foreign-document UAF) leaks a **raw ZendMM main-chunk
  pointer** to userland on patched 8.4.27; `main = leak & ~0x1FFFFF` needs no
  calibration. `poc/verify_vardestroy_xpathleak.py` fuses it: one request leaks
  `main`, then the 32 lib positions are scanned -> `uid=33` in ~24 attempts /
  5.7 s, no maps. The upstream commits (2026-10-22/23) land after 8.5.12, so the earlier
  "fixed in 8.5.12" note is withdrawn as unverified. Sink precondition: the app must use
  `DOMXPath::registerPHPFunctionNS` (niche), plus the `unserialize()` fire sink.
  GH-23352 gives a secondary 6-byte glibc safe-linked leak (8.4.27 only), not
  directly a ZendMM address.

- **A working local reproduction, not a remote weapon.** The core chain is
  reproduced un-instrumented against stock `php:8.4.26-apache` (mod_php) on
  **amd64 and natively on aarch64**, with a fixed benign command. It is
  per-build (8.4.26 offsets) and lab-only; no remote target packaging.
- **Three controls hold on both arches:** the chain fires (pos), is blocked
  on patched 8.4.27 (neg), and a `+0x1000` bias on `zif_system` prevents the
  fire (load-bearing — the exact leaked address is required).
- **ASLR cross-check closed on native arm64.** Three fresh containers gave
  three different libphp/chunk bases (`0xffffba7b0000` / `0xffffa9cc0000` /
  `0xffff9dc50000`), 3/3 fires. The amd64 runs are under qemu-user (whose
  mmap layout is deterministic) and are not an ASLR proof — the native arm64
  run is.
- **Pinning is proven at the official 150-worker prefork** (149 holders) on
  Apache — amd64 and natively on arm64, 3/3 across ASLR generations — and
  at 4 workers on FPM.
- **Chains A/C are verified on 8.2.35, 8.4.27, and 8.5.12** — every patched
  release. They are application-level and orthogonal to the CVE patch.
- **CVE-2026-109618 is complete on mod_php 8.4.26 (in-band) and open
  elsewhere** — the OOM → `zif_system` chain is proven on stock
  `php:8.4.26-apache`; the FPM path is still instrumented/boundary-only, and
  the 8.2/8.3/8.5 leak shape is not yet calibrated (P2).
- **SAPI scope of the core-chain claim is mod_php-only.** Apache + mod_php is
  still the default for LAMP/cPanel shared hosting; nginx + php-fpm is a
  separate track (the FPM in-band leak is unsolved). Do not read the matrix as
  FPM coverage.
- **The FPM core path (rung 5b) is still instrumented** — the FPM in-band
  leak is the unsolved piece, not the chain.
- **The Wiz IOC list is hunting context**, not a block list: Wiz observed
  failed attempts, not confirmed compromises.

---

## 8. Changelog

- **2026-10-31 (audit)** — iteration 64 independently audited
  (`evidence-auditor`, PASS-WITH-CAVEAT) and the two trees re-graphed
  (`gadget-hunter`): no stock re-entry destructor in WordPress core or
  Roundcube 1.6.11. The audit found two unsupported doc claims (shutdown
  overwrite, `cleanup=Off` label), now receipt-backed. Tool versions and the
  unmodelled `SimplePie` shape are recorded in
  `docs/GADGET_SURVEY_115560.md` §9.
- **2026-10-31 (Redis)** — Roundcube Redis same-store experiment (Track B
  precondition) run and **negative**: `lab-roundcube-redis/` (php 8.4.27 +
  phpredis 6.3.0, redis:7) shows the rfc1867 hook writes the `php_serialize`
  record via the Redis handler and stock `rcube_session_redis` performs the
  `php` switch, but `read()` requires its own `a:3:{changed,ip,vars}` wrapper
  and the hook writes `a:1:{...}`. Keys can be aligned with
  `session.save_path="tcp://redis:6379?prefix="`, so the envelope is the
  blocker, not the switch. `session_storage='php'` + Redis store still fires
  `uid=33`, with the plugin switch load-bearing. Evidence:
  `docs/ROUNDCUBE_REDIS_115560.md`, `poc/verify_roundcube_redis.py`.
- **2026-10-29 (later)** — portability harness landed and the version matrix
  produced its first real result. `php2shell/offsets.py` +
  `scripts/extract_offsets.sh` extract 8 aarch64 offset rows into
  `profiles/offsets.json` (values match the documented table);
  `php2shell/calibrate.py` + `scripts/calibrate.sh` add the geometry
  `derive`/`sweep`/`sweep_leak`/`fingerprint` harness (self-test recovers the
  8.4.26 geometry); `poc/verify_matrix.py` + `scripts/matrix.sh` + `lab-matrix/`
  run the pos/neg/bias triad. **Six 8.4-series builds proven 6/6**
  (8.4.10/20/23/24/25/26); 8.2.34/8.3.35/8.5.11 and 8.4.1 fail at the **leak
  shape** (not offsets). Two fixes made the series portable: leak-side qword
  bias auto-detect (symbol vs symbol+0xB) and a widened libphp↔chunk delta
  window. `scripts/distro_defaults.sh`
  adds two default-install models: the official no-`php.ini` image reproduces
  the lengthless bypass, Ubuntu 24.04's Apache 2.4.58 does not. Scope decided:
  the core-chain claim is **mod_php-only**; FPM is a separate track.
- **2026-10-29** — CVE-2026-109618 terminal call reproduced on mod_php
  8.4.26 arm64: OOM unwritten bucket → `free_obj = zif_system` + forged
  `execute_data` → `id`, with ASLR **on**. No libc ROP; controls: `+0x1000`
  bias holds, patched 8.4.27 blocks. Address sourcing is lab-assisted
  (`/proc`); the in-band leak at the 8M OOM profile remains the open gap.
  Artifacts: `php2shell/cve109618.py`, `poc/verify_109618_zif.py`.
- **2026-10-28 (later)** — session-poisoning + LFI re-verified on patched
  8.4.27 and 8.5.12 (`lab-patched :18087/:18088`): the branded
  app-level chain survives every patched release, like Chains A/C.
- **2026-10-28 (later)** — 8.5.11 arm64 second-version attempt, negative:
  exact dinosn config (`USE_ZEND_ALLOC=0`, `USE_TRACKED_ALLOC=1`, 16M/32M,
  `save_path=/tmp`, `cleanup=1`, single worker, 256 MB cgroup) plus a full
  `target` sweep (`0..741`) never yields the 512-byte PS(id) disclosure —
  always a normal 32-hex cookie. Offsets are right; heap geometry is not.
  Per-build recalibration remains the blocker (documented in OFFSETS/STATUS).
- **2026-10-28 (later)** — detection rules traffic-tested: all 10 SIDs
  fire under a live Suricata sidecar. Three real defects found and fixed:
  the multi-line `.rules` format loaded nothing; 210961805 repeated the
  `http.request_body` buffer (inert) and 210961807 matched `/tmp/sess_`
  instead of `/tmp/sessions/sess_`. 805/807 are rev 2; counts and sensor
  tuning in `detection/README.md` §4b.
- **2026-10-28 (later)** — second-version attempt, negative: native 8.5.11
  arm64 (offsets `0x761B80` / `0x5314F0`, matching public profiles) does not
  reproduce with either the dinosn PS(id) chain or the 9bie ladder — a
  heap-geometry recalibration problem, not an offset problem. Documented in
  `docs/OFFSETS.md` / STATUS P2; 8.4.26 remains the validated build.
- **2026-10-28 (later)** — native arm64 at scale: 3/3 at the official
  150-worker prefork (149 holders) across fresh containers, each with a
  different libphp/chunk base. `pure-arm64-workers` (:18132) added.
- **2026-10-28 (later)** — native arm64 validation: the same 8.4.26 chain
  fires 3/3 across three fresh containers with three different libphp/chunk
  bases (real ASLR), and both controls hold (`+0x1000` bias, patched 8.4.27
  arm64). This closes the native ASLR cross-check and adds a second
  architecture; `lab-pure-modphp` gained `pure-arm64` (:18130) and
  `pure-arm64-patched` (:18131).
- **2026-10-28 (later)** — `var_destroy` re-entry UAF verified to **survive
  the patch**: `lab-asan-85x/` (parameterized ASAN builds) shows the same
  heap-use-after-free in `php_var_unserialize` on 8.4.27 and 8.5.12
  (`var_unserializer.c:906`) as on 8.2.34 (`:850`). The CVE patch fixes the
  OOM/stale-state paths but not this adjacent `var_destroy` bug.
- **2026-10-28 (later)** — Chains A and C re-verified on the newest patched
  releases: `lab-patched/` (:18087 `php:8.4.27-fpm`, :18088
  `php:8.5.12-fpm`, official images, native arch) — Chain A marker executes
  and Chain C returns `uid=33(www-data)` on both. The app-level chains
  survive every patched release (orthogonal to the CVE patch).
- **2026-10-28 (later)** — rung 6 closed and the core chain reproduced
  un-instrumented: `php2shell/remote.py` + `poc/verify_109619_remote.py`
  (9bie ladder reimplemented) leak libphp+chunk in-band and dispatch
  `zif_system` on stock 8.4.26-apache; patched 8.4.27 blocks it; `+0x1000`
  bias control confirms the leaked address is load-bearing. Labs
  `lab-pure-modphp :18120` (fires) / `:18121` (8.4.27 negative).
- **2026-10-28** — initial status snapshot after the post-Wiz capability
  uplift: pinning, amplification, legacy shape, auto-LFI, session poison,
  Content-Type bypass, SAPI profile, rung-6 leak harness, detection SIDs
  210961804–810 and `detection/iocs_php2shell_2026-10-27.yml`.
- **2026-10-22** — adaptive driver, Joomla lab, detection pack.
- **2026-10-21** — rung 5b, negative control on 8.2.35, initial release.
