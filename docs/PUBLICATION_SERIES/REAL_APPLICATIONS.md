# Real applications, not lab classes

### Drupal 11 P5, Joomla 5, Roundcube 1.6.11 — and one theory that did not survive

**Date:** 2026-10-31 · **Scope:** lab-only, `127.0.0.1` · **Proof:** `id>/tmp/vd 2>&1` (fixed, benign) · **Series:** [index](https://github.com/pax-k/php2shell-hunt/blob/main/docs/PUBLICATION_SERIES/README.md)

> **Lab boundary.** Local containers only; targets `127.*`/`::1`; the only command executed was
> the fixed, benign `id>/tmp/vd 2>&1`; no command interface.

---

## 1. Why an app chain is the real test

A lab class `T` with `__destruct() { @unserialize('i:0;'); }` proves the engine mechanics of the
[`var_destroy` unlock](https://github.com/pax-k/php2shell-hunt/blob/main/docs/PUBLICATION_SERIES/PATCH_GAP.md),
not that a shipped application hands the decoder such an object — the gap where most gadget
write-ups stop.

So the survey asked stock code: is there a `__destruct()` that is autoloadable before
`session_start()`, calls `unserialize()` on attacker-placed data, and discards the result so a parse
failure does not short-circuit the walk? Across **46,508 PHP files in ~60 trees**
([`GADGET_SURVEY_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/GADGET_SURVEY_115560.md) §3) the answer splits five ways:

| App | Verdict | Missing half |
|---|---|---|
| Drupal 11.4.11 | **config-gated chain, executed to `uid=33`** | `serialize_handler: php`, one non-default line |
| Joomla 5.4.x | **gadget confirmed under ASAN, no terminal** | an app `unserialize()` / Phar sink |
| Roundcube 1.6.11 | **plugin-assisted profile** | a plugin switch **and** a plugin destructor |
| WordPress 7.1.3 | **gadget present, gated off as shipped** | `gc_disable()`, which core never calls |
| PHP built-ins | **clean negative** | nothing: no built-in re-enters |

The negative is load-bearing: a graph zero is not "no gadget exists", it is "no gadget in this tree,
with these patterns, under this autoload model". WordPress is the sharp case — real core code,
unreachable because `SimplePie::__destruct` only calls through when GC is disabled
([`JOOMLA_GADGET.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/JOOMLA_GADGET.md) §"WordPress and built-ins").
"Stock" is a property of a file tree, not a deployment, so a stock chain plus one config line is still
a config-gated chain — and every row below is labelled that way.

## 2. Drupal 11.4.11: the one stock core chain

**Gate:** `session.storage.options.serialize_handler: php` in `services.yml` (a line the scaffold
lacks) plus the producer's `php_serialize` and `upload_progress=On`. Pure core, present from
**11.4.0-rc1**, absent in 11.0.13–11.3.20 and 10.4.x:

```text
YamlCacheCollectorDiscovery::__destruct()  Discovery/YamlCacheCollectorDiscovery.php:64
  -> MenuActiveTrail::destruct()           Menu/MenuActiveTrail.php:81
  -> CacheCollector::updateCache()         Cache/CacheCollector.php:234
       $lock_name = $cid . ':' . __CLASS__ :251   <- the spray
  -> MemoryBackend::get() / prepareItem()  Cache/MemoryBackend.php:44, :89
       $prepared->data = unserialize(...)  :99    <- re-entry
```

**The spray is arithmetic.** `var_entries` is `16 + 8*1018 = 8160` bytes, two ZendMM pages; the lock
name `$cid . ':' . 'Drupal\Core\Cache\CacheCollector'` is 8135 bytes at `strlen($cid) = 8102`, so
`zend_string_alloc` asks for `24 + 8135 + 1 = 8160`, and `$cid[0:8]` carries the forged `zval *` to
chunk+24, i.e. `data[1]`. One allocation is not enough: best-fit takes the lowest exact two-page run
and lower runs survive `var_destroy`, so `npad=4` occupies them with four 8135-byte strings parsed
last, and `nk=65` string-keyed `keysToPersist` entries make `$data` a live two-page hashtable that
consumes the last one. Integer keys give a packed array and never match.

`payload_len=69819`, `cid_len=8102`, `nk=65 npad=4`. Delivered through the real session decoder
(`php_serialize` record -> `session_start()` with `php`) on stock ZendMM:

| build | port | `main` | `zif_system` | delta | proof |
|---|---|---|---|---|---|
| 8.4.27 | `:18300` | `0xffff9ee00000` | `0xffffa1401510` | `0x7b019` | `uid=33` |
| 8.5.12 | `:18301` | `0xffff82000000` | `0xffff7ef35490` | `0x7b019` | `uid=33` |

The response is empty because the worker dies right after `zif_system`; `/tmp/vd` is the receipt.
The gadget resolves during decode with no `class_exists()` preload
([`DRUPAL_AUTOLOAD_PROBE.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/DRUPAL_AUTOLOAD_PROBE.md)),
and ASAN reports the UAF at `var_unserializer.c:906` through `php_session_decode:279`, no app frame.

**Default `cleanup=On` race.** The direct profile is `cleanup=Off`; the default removes the progress
record at shutdown, so a second child must read the file inside the upload window. On 8.4.27
(`:18302`), four to eight prefork children, `MaxConnectionsPerChild=1`, and `vd_seed.php` writing a
persistent record #1:

```text
[m] race carrier=0xffff9d07b889 value_string=0xffff9d07b875 delta=0x7b875
[f] race proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

The seed makes the two-record geometry work: the file begins `a:1:{s:6:"seed_d";s:N:"|a:1018:{...`,
so the `php` decoder ignores the bytes before the `|`, parses the dummy as record #1, then parses the
exploit payload as record #2. Race delta `0x7b875` is not the direct delta `0x7b019`.

**Controls:** `--cid-len 100` (no spray, same shaping) → 200, no proof; `--bias-zif 0x1000` → no proof;
race `--settle 6.0` → hold pid, no raw input; race `--no-seed` → measure finds the payload
(`delta=0x79037`), fire 200. **Ceiling:** one version, one non-default line, single prefork child.

## 3. Joomla 5: the gadget exists, the terminal does not

**Gate:** an application or extension calling `unserialize()` on attacker data, or a
`Phar::getMetadata()` sink. Joomla supplies the classes, not the entry point — a stock re-entry
destructor with no lab-defined class:

```text
var_destroy()                                var_unserializer.c:319
  i_zval_ptr_dtor(zv)          (BG(serialize_lock)==0)
    Joomla\CMS\Mail\Mail::__destruct()              (inherits PHPMailer's)
      PHPMailer::smtpClose() -> DataSet::__call     PHPMailer.php:2357
        GuzzleHttp\Psr7\FnStream::close()           FnStream.php:108
          ($this->_fn_close)()                      FnStream.php:110
            Joomla\Registry\Registry::__clone()     Registry.php:78
              unserialize(serialize($data))         Registry.php:80  <- re-entry
```

`SMTP` exists only so `DataSet::__call('connected')` returns truthy; `quit()` is a no-op and
`close()` reaches FnStream. The graph is ~9.4 KB with no back-references, so it splices safely
([`poc/joomla_var_destroy_gadget.php`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/joomla_var_destroy_gadget.php)).

ASAN on 8.4.27 and 8.5.12 gives `heap-use-after-free ... READ of size 8` at
`var_unserializer.c:906` through `zend_call_function -> zend_objects_destroy_object ->
i_zval_ptr_dtor -> var_destroy`; it fired in real **FPM** workers on 8.4.27 (HTTP 502) and 8.2.34
(`:850`). On stock ZendMM the read is silent and the worker keeps serving with
`Uncaught LogicException: FnStream should never be unserialized`.

**The honest limit:** UAF/DoS, not execution. `Registry::__clone()` calls
`unserialize(serialize($this->data))`, and `serialize()` cannot emit an out-of-range `R:1020;` or put
a raw pointer at the stale `data[id]` slot. Joomla removes the "loaded gadget class" precondition
only
([`JOOMLA_GADGET.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/JOOMLA_GADGET.md) §"Terminal-call limitation").

**WordPress, for contrast.** `SimplePie::__destruct -> WP_HTML_Token::__destruct ->
call_user_func(...) -> unserialize` is real core code, but the direct destructor call is gated on
`!gc_enabled()` (`wp-includes/SimplePie/src/SimplePie.php:716-722`) and WP never disables GC —
**not reachable as shipped**. Built-ins are a clean negative: only
`Phar`/`PharData`/`PharFileInfo` declare `__destruct`, none re-enters.

## 4. Roundcube 1.6.11: best precondition, plugin-assisted gadget

**Gate:** a plugin that performs the handler switch and defines a re-entry destructor, with
`session_storage='php'`. Roundcube mirrors Drupal: the delivery precondition is stock, the gadget is
not. Plugins load at `program/include/rcmail.php:111` and `session_init()` runs at `:116`, so plugin
files are `include`d before `session_start()`; the log shows `simple-dtor` firing after
`handler-switched` and before `plugin-init`, with `proof: uid=33`.

Then the blocker. `rcube_session::register_session_handler()` (`rcube_session.php:109-116`) runs
`ini_set('session.serialize_handler','php')`, but only the `db`, `redis`, `memcache`, and `memcached`
drivers call it; native `session/php.php` does not, and 1.6.11 has no `'files'` option. `'db'` reads
its own table and never decodes the progress **file** (SQLite: the row held
`temp|b:1;language|s:5:"en_US";...`), while `'php'` reads the file but never switches — mutually
exclusive in stock 1.6.11
([`ROUNDCUBE_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/ROUNDCUBE_115560.md) §"Why the stock DB/Redis path is blocked").

The lab plugin does the switch itself — same `ini_set`, same point — while `session_storage='php'`
reads the hook's file. Controls are negative on both builds (`--bias-zif 0x1000`, `--noswitch`,
`--nogadget`):

| build | port | delta | spray | proof |
|---|---|---|---|---|
| 8.4.27 | `:18310` | `0x8d9c1` | `3048` | `uid=33` |
| 8.5.12 | `:18311` | `0x9e9c1` | `8135` | `uid=33` |

On disk the write reads `s:10294:"upload_progress_|a:1018:{i:0;s:4096:"...`; the carrier is the
**highest-address** hit preceded by `upload_progress_|`, with separate measure/fire SIDs.

### The Redis theory, falsified

Server `session.save_handler=redis` plus Roundcube `session_storage='redis'` should let stock
`rcube_session_redis` do the switch and drop the plugin. Tested on
[`lab-roundcube-redis/`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-roundcube-redis/setup.sh)
(phpredis 6.3.0, `redis:7-alpine`, `:18320` redis / `:18321` native) — **it does not work**.

The switch half is real: with `session.save_path="tcp://redis:6379?prefix="` the keyspaces align and
the log reads `handler-switch-DISABLED` before `simple-dtor`, so stock code switched. The envelope
blocks. The hook writes `a:1:{s:36:"upload_progress_|...";a:5:{...}}`, while `read()` unserializes
the value (`redis.php:133`) and takes `$arr['vars']` (`:136`), i.e. an
`a:3:{s:7:"changed";...;s:4:"vars";...}` wrapper. No `vars` key, so `read()` returns `''` and the
`php` decoder never sees the `|` payload; the 2×2 matrix isolates it (only *raw sid + Roundcube
wrapper* fires), and the app's shutdown write also overwrites the hook record at the same key.

The negative is the result: the hook serializes `[prefix.name => progress_array]` with a PHP-built
array, so it cannot produce `vars => <php-handler blob>`; reaching the wrapper needs write access to
the key or an app path storing attacker session vars, neither of which is unauthenticated
([`ROUNDCUBE_REDIS_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/ROUNDCUBE_REDIS_115560.md)).

## 5. What a reader must deploy to reproduce

Base for every profile: a loopback container, PHP 8.4.27 or 8.5.12, `php_serialize` for the
producer, `session.upload_progress.enabled=On`, a writable file `save_path`, and a consumer reaching
`session_start()` with `php`
([`lab-115560/docker-compose.yml`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-115560/docker-compose.yml)).

| Profile | Build | App gate | Worker | Driver |
|---|---|---|---|---|
| Drupal, direct | 8.4.27 / 8.5.12 | `serialize_handler: php` | single child, `cleanup=Off` | [`verify_115560_drupal.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_drupal.py) `run` |
| Drupal, default race | 8.4.27 | same line, `cleanup=On` | 4–8 children, seeded record #1 | same driver, `race` |
| Roundcube | 8.4.27 / 8.5.12 | `session_storage='php'` + plugin switch + destructor | single child | [`verify_115560_roundcube.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_roundcube.py) `run` |
| Roundcube + Redis | 8.4.27 | `session_storage='redis'`, `?prefix=` | single child | [`verify_roundcube_redis.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_roundcube_redis.py) `matrix` |
| Joomla, ASAN only | 8.4.27 / 8.5.12 FPM | endpoint calling `unserialize($_POST['d'])` | any | [`lab-joomla/setup.sh`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-joomla/setup.sh) |

The Drupal and Roundcube application **trees** are downloaded, not tracked:
`lab-drupal/html/` and `lab-roundcube/html/` are git-ignored because they hold
upstream application code. The labs themselves now ship tracked setup,
Compose/INI, endpoints, and plugin files, so a fresh clone can rebuild both:

- [`lab-drupal/README.md`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-drupal/README.md)
  — `./setup.sh` downloads Drupal 11.4.11, then `docker compose up -d`.
- [`lab-roundcube/README.md`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-roundcube/README.md)
  — `./setup.sh` downloads Roundcube 1.6.11 and installs the lab plugin.
- [`lab-roundcube-redis/setup.sh`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-roundcube-redis/setup.sh)
  calls the Roundcube setup before starting Redis and the web profiles.

The written transcripts remain in
[`DRUPAL_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/DRUPAL_115560.md) /
[`ROUNDCUBE_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/ROUNDCUBE_115560.md).

Two rules that are not optional. **Measure before firing:** deltas are per request shape (`0x7b019`
direct Drupal, `0x7b875` race, `0x8d9c1` / `0x9e9c1` Roundcube) and a rebuild can drift by
`+0x1e000..0x20000`. **Keep the controls:** `--bias-zif 0x1000`, `--cid-len 100` or `--nogadget`, and
the patched-build row; core proof:
[`verify_var_destroy_uaf.php`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_var_destroy_uaf.php).

## 6. Caveats

- **Every chain is gated.** Drupal needs one non-default `services.yml` line; Roundcube needs a
  plugin that does what stock 1.6.11 cannot; Joomla needs an application sink; WordPress is gated off
  by core. None is a default-application exposure, and none is "pre-auth everywhere": upload progress
  is required on the producer side, the named gate on the consumer side.
- **Drupal is one version window.** Present in 11.4.0-rc1 and later, absent in 11.0.13–11.3.20 and
  10.4.x. Do not generalise the row.
- **Joomla stops at the UAF.** ASAN shows the re-entry; stock ZendMM shows a caught `LogicException`
  and a live worker. DoS-shaped until an application supplies the forged-carrier destructor.
- **The Redis negative is narrower than "Redis is safe".** One build (8.4.27), phpredis 6.3.0,
  `cleanup=Off`, no race re-run: it rules out the upload-progress record as a `vars` envelope, not
  every layout.
- **Statics have a ceiling.** 46,508 files, same-method patterns plus a typed-property graph: no
  dataflow, no runtime autoload proof, plugin ecosystems unscanned.
- **The terminal is fixed and the prior art stands.** `id>/tmp/vd 2>&1`, loopback only, no command
  interface; the re-entry was published by dinosn (2026-05-02) and the composition by ACD421.

Mechanics: [`VAR_DESTROY_UAF.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/VAR_DESTROY_UAF.md),
[`RACE_WAKEUP_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/RACE_WAKEUP_115560.md),
[`NOFUNC_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/NOFUNC_115560.md).
State: [`STATUS.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/STATUS.md) §2.1. Long form:
[`BLOG_POST_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/PUBLICATION_115560/BLOG_POST_115560.md) §9–§10.
