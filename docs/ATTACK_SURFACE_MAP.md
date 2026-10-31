# PHP attack-surface map — vectors, chains, and the 0day frontier

**Date:** 2026-10-31  
**Scope:** lab-only research map (`localhost`, `127.*`, `::1`); fixed benign
allowlist (`id | uname | whoami`). This document is a *map*, not an exploit
pack. It records what is proven, what is public, what is closed, and which
unexplored surfaces are worth a lab experiment.

**Method:** read `AGENTS.md`, `docs/PIPELINE.md`, `docs/STATUS.md`,
`docs/ANALYSIS.md`, `docs/APP_SURVEY.md`, `docs/GADGET_SURVEY_115560.md`,
`docs/SPLIT_GADGET.md`, the held mbstring notes, the generated
`reports/gadgets/*`, and re-ran the static graph on the Roundcube and Joomla
trees. New micro-tests are labelled `EXECUTED` with the command and output.

Evidence levels used in every row:

| Level | Meaning |
|---|---|
| **EXECUTED** | a command in this repo produced the stated result |
| **READ** | source or generated report was inspected; no dynamic test |
| **PUBLIC** | already reported publicly (CVE/advisory/prior art) |
| **HYPOTHESIS** | plausible from the code shape; no test yet |
| **NEGATIVE** | tested or source-checked and closed for the stated tree |

**Coverage ceiling.** This is a source- and tool-driven map over one repo's
labs and one PHP build (8.4.27 / 8.5.12), not exhaustive fuzzing. A missing row
means "not enumerated here", not "cannot exist". An "open" row means "no
public report was found in this repo's survey", not proof of novelty. Every
dynamic claim still needs its own receipt.

### 0.1 Is this the entire PHP attack surface? No.

This is a **curated, prioritized map**, not an exhaustive audit. The 132 IDs
group families of functions, parsers, SAPIs, and gadgets; they are not one row
per entry point. The scale gap is measurable: the *minimal* Apache build used
by the 115560 lab (`php2shell-115560-8427`, PHP 8.4.27, 34 extensions) already
exposes **1,203 internal functions, 214 classes, 27 interfaces, and 86 core
constants**:

```sh
docker exec php2shell-115560-8427 php -r '
$f=get_defined_functions(); $c=get_declared_classes();
printf("internal_functions=%d classes=%d interfaces=%d extensions=%d\n",
  count($f["internal"]), count($c), count(get_declared_interfaces()),
  count(get_loaded_extensions()));'
# internal_functions=1203 classes=214 interfaces=27 extensions=34
```

A full production build with `gd`, `intl`, `soap`, `ldap`, `mysqli`, `pgsql`,
`imap`, `zip`, `ffi`, etc. adds hundreds more. The map covers roughly one row
per extension family, not one row per `PHP_FUNCTION`, stream wrapper, or
unserialize handler.

| Layer | Covered here | Deliberately not covered |
|---|---|---|
| Core engine | OOM/stale state, `var_destroy`, object store, shutdown, fibers, generators, JIT/opcache (hypotheses) | line-by-line audit of the compiler, VM, GC, `zend_hash`, `zend_string`, `zend_alloc`, `zend_smart_str`, every opcode handler |
| Core extensions | ~24 families, one row each | every function in `standard`, `SPL`, `DOM`, `SOAP`, `OpenSSL`, `curl`, `mbstring`, `iconv`, `intl`, `PDO`, `SQLite`, `zip`, `gd`, `exif`, `fileinfo`, `FFI`, `pcntl`, `posix`, `mail` |
| Wire/SAPI | mod_php and FPM measured; Apache/FPM/Nginx are the lab coverage | FrankenPHP, LSAPI, CGI, embedded, `php -S`, IIS, HTTP/2 edge cases, request smuggling |
| App/framework | Drupal, Joomla, Roundcube, WordPress; a few phpggc families | Symfony/Laravel/Magento/TYPO3/Craft/MediaWiki/Nextcloud, plugin ecosystems, template engines, thousands of packages |
| Client/outbound | 12 rows (SSRF, TLS, SOAP, Redis, MySQL, LDAP, mail, curl) | protocol-level parsing in every client, rogue-server bugs, DNS rebinding, gRPC/AMQP/Swoole |
| Deployment | 15 config rows | distro patches, seccomp/AppArmor, cgroups, shared-hosting isolation, supply chain, preload/build provenance |

**Major blind spots**

- **Unloaded extensions and PECL**: `igbinary`, `msgpack`, `redis`, `imagick`,
  `mongodb`, `swoole`, `grpc`, `yaml`, `apcu`, `xdebug` — separate C parsers,
  largely unaudited here.
- **Bundled C libraries**: libxml2, OpenSSL, ICU, PCRE2, libmagic, zlib,
  libzip, libsodium, SQLite, cURL, ImageMagick, GD, freetype, libjpeg/libpng.
  Many real bugs live in the library, not the PHP glue.
- **Non-memory vulnerability classes**: auth logic, business logic, crypto
  misuse, side channels, races beyond session, XSS/CSRF, cache poisoning,
  request smuggling, supply chain. Several are named as "app-level" but are
  not enumerated.
- **Build/platform matrix**: ZTS vs NTS, 32-bit, big-endian, musl vs glibc,
  Windows, macOS, debug vs release, JIT on/off, ASAN geometry vs stock.
- **Fuzzing depth**: blind mutation only; 4.1M ASAN executions over four
  corpora is a clean negative for those shapes, not coverage. No
  coverage-guided fuzzing, no Joern/CodeQL dataflow, no continuous fuzzing.
- **Patch history**: 8.4.26→8.4.27 was diffed, not every security release or
  EOL backport.

**What "entire" would require**

1. A scoped target: e.g. "php-src 8.4.27, all bundled extensions, all SAPIs,
   aarch64 and x86-64".
2. A function/parser inventory: every `PHP_FUNCTION`, every `unserialize`
   handler, every stream wrapper, every SAPI read/write path.
3. A patch diff of every security release and relevant EOL backport.
4. Coverage-guided fuzzing per parser, with ASAN and stock-ZendMM runs.
5. A SAPI/platform matrix, not one container.
6. An app/package corpus with autoload and version gates.

That is a multi-month campaign, not one document. Use this map to choose the
next experiment; do not cite it as proof that a surface does not exist.

---

## 1. Chain algebra — the only four shapes that matter

Every PHP RCE chain in this repo's record is a composition of four slots. The
useful question is never "is there a bug?" but "which slot is missing?".

```text
ENTRY          SINK                 PRIMITIVE              TERMINAL
wire bytes ──> parser/decoder ──> memory or object ──> call target
                 │                    state
                 ├─ multipart/OOM ──> stale global ─────> zif_system
                 ├─ session decode ─> var_destroy UAF ──> forged dtor_obj
                 ├─ app unserialize > gadget graph ─────> exec/system
                 └─ file/URL/XML ───> parser OOB ───────> leak -> address
```

The four proven archetypes:

| # | Archetype | Entry | Primitive | Terminal | Status |
|---|---|---|---|---|---|
| A | **OOM → stale global** | multipart/OOM | request heap freed under a live global | next request consumes it | REPO-PROVEN (109619 mod_php) |
| B | **OOM → unwritten bucket** | multipart/OOM | shutdown walks a half-built `$_POST` bucket | `free_obj = zif_system` | REPO-PROVEN (109618 mod_php) |
| C | **Session decode → `var_destroy`** | handler mismatch / 115560 / app sink | freed `var_entries` reused by `__destruct` | forged `zend_object → dtor_obj` | REPO-PROVEN (lab + patched builds) |
| D | **App sink → stock gadget** | `unserialize()` / `session_decode()` | object graph + magic method | terminal gadget (`exec`, `proc_open`, `zif_system`) | REPO-PROVEN (Drupal P5 + 115560) |

What each archetype still needs:

- **A** needs a producer, a fatal that skips the reset, a consumer on the same
  worker, and a per-build consumer shape. FPM is the open SAPI.
- **B** needs the OOM to leave a specific unwritten bucket, plus a fork-shared
  address for the forged object. 8.4.26 mod_php is proven; other builds are
  calibration work.
- **C** needs a reachable `unserialize()` of attacker bytes and a destructor
  that re-enters `unserialize()` (not `__wakeup` / `__unserialize`, which run
  under `BG(serialize_lock)`).
- **D** needs a guest-reachable sink and a stock terminal-capable gadget. This
  is the application-reachability bottleneck, not a PHP-core gap.

---

## 2. Layer map

| Layer | What lives here | Primary tools | Main failure classes |
|---|---|---|---|
| **L0 Wire/SAPI** | Apache mod_php, FPM/FastCGI, FrankenPHP, LSAPI, CGI, HTTP/1.1/2, multipart, chunked, headers, cookies | raw HTTP, `poc/verify_postmax_bypass.py`, `poc/verify_amplification.py`, `poc/verify_worker_pinning.py` | lengthless body, part/header amplification, boundary differentials, buffering |
| **L1 Engine** | ZendMM, executor globals, OOM/bailout, shutdown order, GC/object store, fibers, generators, opcache/JIT, INI | ASAN/stock ZendMM, `poc/probe_ps_globals.py`, `scripts/calibrate.sh`, `scripts/matrix.sh` | UAF, stale state, shutdown re-entry, type confusion |
| **L2 Core extensions** | session, standard/unserialize, SPL, reflection, Phar, DOM/XML, SOAP, OpenSSL, curl, mbstring/iconv/intl, PDO/SQLite, zip, exif/gd, fileinfo, FFI, pcntl/posix, mail | ASAN builds, `fuzz/gen.py`, `fuzz/asan_run.php`, micro-tests | OOB, UAF, underflow, deserialization, parser differentials |
| **L3 App/framework** | routing/auth, session stores, serialization sinks, templates, uploads, command wrappers, SQL, SSRF, XXE, phar, LFI | `scripts/gadget_sweep.sh`, `scripts/gadget_graph.sh`, `phpggc` corpus, source reading | object injection, gadget chains, auth bypass, injection |
| **L4 Deployment** | shared hosting, per-dir INI, FPM pools, reverse-proxy buffering, worker model, opcache/preload, containers | `scripts/distro_defaults.sh`, `docs/WORKERS_115560.md`, `poc/verify_sapi_profile.py` | config drift, worker pairing, cross-tenant, capability exposure |

---

## 3. Core / engine register (CORE)

These are interpreter-level surfaces. The CVE patch closed the named 109618 /
109619 paths; adjacent lifetime bugs remain.

| ID | Surface | Class | Status | Evidence / why it matters | Cheapest discriminating test |
|---|---|---|---|---|---|
| CORE-01 | OOM `longjmp` during request startup | stale state / UAF | PUBLIC + REPO-PROVEN | CVE-2026-109618; `docs/ANALYSIS.md` §0.1, §0.6 | `poc/verify_109618_oom.py`, `poc/verify_109619_modphp_chain.py` |
| CORE-02 | Stale executor/INI globals across requests | stale state | PUBLIC + REPO-PROVEN | `EG(user_error_handler)`, `EG(errors)`, `PG(modules_activated)`; 109619 consumer | `poc/verify_109619_fpm_chain.py` on ASAN FPM |
| CORE-03 | `var_destroy()` dtor walk without `BG(serialize_lock)` | UAF | PUBLIC (dinosn 2026-05-02) + REPO-PROVEN | survives 8.4.27 / 8.5.12; `docs/VAR_DESTROY_UAF.md` | `poc/verify_var_destroy_uaf.php`; ASAN `var_unserializer.c:906` |
| CORE-04 | `var_destroy()` / `tmp_var()` negative `used_slots` | OOB write | REPO-PROVEN (lab) | forged `var_dtor_entries` steers a 16-byte zval write; `docs/ANALYSIS.md` §0.8 rung 4 | `poc/verify_109619_weaponized_write.py` |
| CORE-05 | Forged `zend_object → handlers → dtor_obj` | control-flow | REPO-PROVEN (lab) | `docs/ANALYSIS.md` §0.8 rung 5a; `r:` reference keeps refcount clean | `poc/verify_109619_rip_control.py` |
| CORE-06 | `zend_execute_data` / `zif_system` call-shape | terminal | REPO-PROVEN | `docs/ANALYSIS.md` §0.9; `zif_system` compiled into every build | `poc/verify_109619_rce.py`, `poc/verify_109618_zif.py` |
| CORE-07 | OOM during hash/array/variable registration | half-init structure | PUBLIC + REPO-PROVEN (trigger) | `_zend_hash_str_add_or_update_i`; §0.5 | `poc/verify_empty_upload_expansion.py` |
| CORE-08 | Shutdown ordering with destructors, error handlers, output buffers | re-entry / UAF | HYPOTHESIS | destructor can run while `EG(error_handler)` or a buffer is half-torn-down; adjacent to CORE-03 | ASAN: register a destructor that calls `set_error_handler`/`ob_start`, force OOM |
| CORE-09 | Exception unwinding through destructors / `finally` | UAF / double free | HYPOTHESIS | object store destruction during unwind; forged `ce`/handlers | ASAN: throw from `__destruct`, destroy object graph, `gc_collect_cycles` |
| CORE-10 | Fibers: suspend/resume inside destructors and shutdown | UAF / state confusion | HYPOTHESIS | `zend_fiber` has its own stack and destructor path; not covered by the session work | ASAN: `Fiber::suspend()` in `__destruct`, resume after object free |
| CORE-11 | Generators: `yield` in destructors, `finally`, generator GC | UAF | HYPOTHESIS | generator frame lifetime vs. object store; `zend_generator_close` | ASAN: destroy a generator that owns an object with a re-entrant destructor |
| CORE-12 | WeakMap / WeakReference during GC and object destruction | UAF / type confusion | HYPOTHESIS | weak entries removed while the object store is being destroyed | ASAN: weak ref to an object whose destructor re-enters GC |
| CORE-13 | `zend_ast` / compiler OOM and constant folding | half-init AST | HYPOTHESIS | OOM in compile phase vs. request heap; eval/`include` of attacker code | OOM while compiling a deeply nested expression; ASAN |
| CORE-14 | Opcache file cache / preload poisoning | code injection | HYPOTHESIS | `opcache.file_cache`, `opcache.preload`, `validate_timestamps=0`; write access to cache dir | Lab: writable `opcache.file_cache` + crafted cache entry; read the docs, not a weapon |
| CORE-15 | JIT type confusion / stale trace | memory safety | HYPOTHESIS | `opcache.jit=tracing` is a large new code generator; fuzz with `unserialize`/destructor shapes | ASAN/JIT build: run the var_destroy corpus with JIT on |
| CORE-16 | `zend.exception_ignore_args=0` / trace args | info leak | PUBLIC-ish | secrets in stack traces; not RCE, but a leak slot for the address seed | `php -d zend.exception_ignore_args=0 -r 'throw new Exception'` |
| CORE-17 | INI parsing: `auto_detect_line_endings`, `filter.default`, `assert.*`, `mbstring.http_input`, `iconv.*` | pre-init diagnostic | PUBLIC | 109619 consumer #1; `docs/ANALYSIS.md` §0 | `poc/verify_109619_fpm_chain.py` with `.htaccess`/`PHP_VALUE` |
| CORE-18 | `fatal_error_backtraces` (8.5) | stale backtrace state | PUBLIC | named in the advisory; reset always missed in shutdown | 8.5 lab: fatal after a backtrace, next request consumer |

**Core front-runner.** CORE-08/09/10/11/12 are the genuinely under-enumerated
lifetime surfaces: every one is a destructor/GC re-entry shape, which is the
same primitive class the repo already knows how to drive. They need ASAN
harnesses, not new theory.

---

## 4. Session and serialization register (SER)

Session is the densest surface in this repo because it joins a wire parser
(multipart), a decoder (serializer), a store (file/Redis/DB), and magic methods
in one request. The same join exists in every session store.

| ID | Surface | Class | Status | Evidence / why it matters | Cheapest discriminating test |
|---|---|---|---|---|---|
| SER-01 | Upload-progress **filename** injection | code injection | PUBLIC + REPO-PROVEN | raw filename stored in session file; `docs/ANALYSIS.md` §3.2 | `poc/verify_chain_a_lfi.py` |
| SER-02 | Upload-progress **value** poisoning | code injection | PUBLIC + REPO-PROVEN | progress value is an unbounded POST field; §3.1 | `poc/verify_session_poison_lfi.py` |
| SER-03 | Cross-directory **handler mismatch** | object injection | PUBLIC + REPO-PROVEN | `php_serialize` write / `php` read; PHP Bug #71101 lineage; survives 8.2.35/8.4.27/8.5.12 | `poc/verify_handler_mismatch.py`, `poc/verify_rce_gadget.py` |
| SER-04 | 115560 runtime `ini_set` switch | object injection | PUBLIC + REPO-PROVEN | same family as SER-03 with a runtime switch; patched builds still affected | `poc/verify_115560_vardestroy.py` |
| SER-05 | `session_decode()` called on user input | object injection | **EXECUTED (micro-test, 8.5.12)** | direct userland decoder; no `allowed_classes`; classes instantiate and destructors run | see §4.1 below |
| SER-06 | `php_binary` / `php_serialize` decoder parity | parser bug / mismatch | HYPOTHESIS | three built-in decoders share `var_destroy` but differ in key/length framing; a cross-handler or truncation bug may exist | fuzz all three with the same 1018-element corpus; compare ASAN |
| SER-07 | Session keys with `\|`, NUL, length prefixes | parser confusion | HYPOTHESIS | `php` splits on the first `\|`; `php_binary` is length-prefixed; `php_serialize` is a serialized array | craft keys containing `\|`, `\0`, huge lengths; diff decode result per handler |
| SER-08 | `session_id()` validation / `save_path` traversal | path traversal | **NEGATIVE in 8.5.12 (micro-test)** | `../` and `/` make `session_start()` fail; comma is accepted literally (`sess_abc,def`) | see §4.2; retest per build and with `sid_bits_per_character` variants |
| SER-09 | Session fixation via POST `PHPSESSID` | auth bypass | PUBLIC | `use_only_cookies` ignored in multipart progress handler; PR #22113 | `poc/verify_session_injection.py` |
| SER-10 | `use_strict_mode=0` + attacker-chosen SID | session fixation | PUBLIC | default is off; combined with SER-01/02 | one request with a chosen cookie, then an authenticated victim request |
| SER-11 | `cleanup=On` unlink race | UAF / lost session | PUBLIC + REPO-PROVEN | session file removed while a decoder still holds it; `docs/RACE_WAKEUP_115560.md` | `poc/verify_115560_race.py` |
| SER-12 | `lazy_write` / `write_close` / GC concurrency | race / stale data | HYPOTHESIS | `session.lazy_write=On` and GC can free/rewrite a file during decode | multi-worker lab: lazy writer + GC + reader, then ASAN |
| SER-13 | Custom save handlers (`user`, Redis, memcache, DB) | object injection / store confusion | HYPOTHESIS | handler may read a different namespace than upload progress writes; Roundcube Redis was tested negative (APP-04); the open test is another store that feeds the hook value to a decoder | `poc/verify_roundcube_redis.py` / `lab-roundcube-redis` |
| SER-14 | `igbinary` / `msgpack` session serializers | memory safety | HYPOTHESIS (PECL) | separate C parsers with their own length/ref handling; not in stock 8.4.27 image | build PECL handlers, fuzz with the session corpus under ASAN |
| SER-15 | `allowed_classes` semantics | sandbox bypass | **EXECUTED (8.5.12): respected** | `C:` (Serializable), `__unserialize`, `__wakeup` all become `__PHP_Incomplete_Class` with `allowed_classes=false` | see §4.3; no bypass in this build |
| SER-16 | `__PHP_Incomplete_Class` property injection | object injection | HYPOTHESIS | incomplete objects still carry arbitrary properties; a later `(array)` cast or `serialize()` can leak/confuse | decode an incomplete object, cast/serialize/re-decode, watch magic methods |
| SER-17 | `Phar::getMetadata()` object injection | object injection | **READ + EXECUTED (8.5.12)** | metadata is lazy: `getMetadata()` instantiates loaded classes; `file_exists('phar://…')` alone did **not** run the destructor in this build | see §4.4; re-check per version |
| SER-18 | `phar://` on upload + file operation | object injection | PUBLIC (classic) | requires an app file operation on an attacker-controlled path; `phar.readonly` only blocks creation | lab: upload phar, call `file_exists`/`getMetadata`; measure which operation deserializes |
| SER-19 | `session.upload_progress.prefix` / `.name` collisions | parser confusion | HYPOTHESIS | attacker controls the form field name and value; prefix collisions can overwrite another key | set `.name` to an app key, upload, inspect session file |
| SER-20 | `session.serialize_handler` per-dir `.user.ini` / `.htaccess` | config drift | PUBLIC | the 115560 precondition is a server `php_serialize` plus an app `ini_set('php')` | `scripts/distro_defaults.sh`; grep app trees for switches |

### 4.1 SER-05 receipt — `session_decode()` is a first-class sink

Tool: host PHP 8.5.12, CLI, three built-in handlers, object `D` with a
destructor. Command:

```sh
php -d session.save_path=/tmp/p2s_map/sessdir4 -d session.use_cookies=0 \
    -d session.cache_limiter= -d session.serialize_handler=$h \
    /tmp/p2s_map/sess_obj.php
```

Output (all three handlers):

```text
php            decode=true S={"k":{"p":null}}   D::__destruct (session_decode sink)
php_binary     decode=true S={"k":{"p":null}}   D::__destruct (session_decode sink)
php_serialize  decode=true S={"k":{"p":null}}   D::__destruct (session_decode sink)
```

Why it matters: an application that calls `session_decode($_POST[...])`,
`session_decode(base64_decode(...))`, or restores a session from a cookie/DB
column is a direct attacker→decoder path with no multipart precondition and no
`allowed_classes` guard. Search pattern:

```sh
rg -uu -n --glob '*.php' 'session_decode\s*\(' <app-tree>
```

The stock trees scanned here have one internal call each (Roundcube
`rcube_session.php:441`, Drupal lab helper), not a guest route. The hypothesis
to test is a real app route that passes request data to it.

### 4.2 SER-08 receipt — session id traversal is rejected

```text
session_id("../../tmp/p2s_map/evil") -> session_start() false
session_id("abc/def")                -> session_start() false
session_id("abc,def")                -> session_start() true; file sess_abc,def
```

This is a **negative** for 8.5.12: `/` and `..` are rejected, comma is legal
and lands literally in the filename. Retest on each build and when
`session.sid_bits_per_character` / `sid_length` are non-default.

### 4.3 SER-15 receipt — `allowed_classes` is not bypassed by `C:`

```text
C:1:"S":20:{...}  allowed_classes=false -> __PHP_Incomplete_Class
C:1:"S":20:{...}  allowed_classes=true  -> S::unserialize ran
O:1:"U":0:{}      allowed_classes=false -> __PHP_Incomplete_Class
O:1:"U":0:{}      allowed_classes=true  -> U::__unserialize ran, then __destruct
O:1:"W":0:{}      allowed_classes=false -> __PHP_Incomplete_Class
O:1:"W":0:{}      allowed_classes=true  -> W::__wakeup ran, then __destruct
```

No bypass in 8.5.12. The interesting follow-up is SER-16: what an
`__PHP_Incomplete_Class` retains and whether a later cast/serialize can be
abused without ever instantiating the class.

### 4.4 SER-17 receipt — Phar metadata is lazy on 8.5.12

```text
$p = new Phar('/tmp/p2s_map/t.phar'); $p->getMetadata();
-> object(P), then P::__destruct
file_exists('phar:///tmp/p2s_map/t.phar/x.txt') with P defined
-> true, but no P::__destruct
```

So the classic "any `phar://` file operation deserializes metadata" is **not**
true in this build: `getMetadata()` is the sink, `file_exists` alone is not.
That narrows the app search to explicit `getMetadata()` calls or APIs that
call it (some stream wrappers, archive tools, `Phar` iteration).

---

## 5. Wire / SAPI register (WIRE)

The wire layer decides whether the entry is reachable at all. Most rows here
are already measured; the open ones are parser differentials and non-mod_php
SAPIs.

| ID | Surface | Class | Status | Evidence | Cheapest test |
|---|---|---|---|---|---|
| WIRE-01 | Lengthless/chunked body vs `post_max_size` | limit bypass | PUBLIC + REPO-PROVEN | mod_php parses 17 MB with no usable length; FPM parses zero | `poc/verify_postmax_bypass.py --mode apache` / `--mode fpm` |
| WIRE-02 | Unrestricted per-part headers | amplification | PUBLIC + REPO-PROVEN | 5.1 MB wire → 128 MB heap; §0.2 | `poc/verify_cve_109618_oom.py` |
| WIRE-03 | Empty-filename nested names | amplification | PUBLIC + REPO-PROVEN | 200 KB wire → 128 MB heap; bypasses `max_file_uploads` | `poc/verify_empty_upload_expansion.py` |
| WIRE-04 | `max_file_uploads` bypass | limit bypass | PUBLIC + REPO-PROVEN | empty parts are not counted; 40 > 20 | same as WIRE-03 |
| WIRE-05 | `max_multipart_body_parts` (8.4+) | limit bypass | HYPOTHESIS | stock value `-1` (unlimited); negative/overflow/part-count edge | send 10k parts on 8.4.27; compare heap and parser bail |
| WIRE-06 | Boundary / quoted-string / backslash parsing | parser differential | HYPOTHESIS | rfc1867 vs frontend vs WAF; `boundary="..."`, commas, NULs, long boundaries | differential corpus across Apache/FPM/nginx; compare `$_POST`/`$_FILES` |
| WIRE-07 | Duplicate `Content-Length` / `Transfer-Encoding` | smuggling / differential | HYPOTHESIS | frontend/backend disagreement is a classic; PHP sees one length | raw socket: CL+TE, duplicate CL, `TE: chunked, identity` |
| WIRE-08 | HTTP/2 → FPM/Apache translation | parser differential | HYPOTHESIS | h2 header normalization, `:authority`, cookies, body length | `nghttp`/`h2load` against the lab; compare parsed globals |
| WIRE-09 | `Expect: 100-continue` + early body | state confusion | HYPOTHESIS | frontend may send body before/after continue; PHP's read_post loop | raw socket: continue + body + abort, then a second request |
| WIRE-10 | `Content-Type: multipart/form-data, boundary=X` | WAF bypass | PUBLIC + REPO-PROVEN | PHP accepts comma separator; §0.10 | `poc/verify_content_type_bypass.py` |
| WIRE-11 | nginx `fastcgi_request_buffering on` | negative control | REPO-PROVEN | buffers the body, flattens the stall; no lengthless bypass | `poc/verify_worker_pinning.py` negative |
| WIRE-12 | Worker pinning / holder rotation | pairing | REPO-PROVEN | 4→1 on Apache and FPM; 149 holders at 150 workers | `poc/verify_worker_pinning.py` |
| WIRE-13 | FrankenPHP / LSAPI | SAPI parity | **UNTESTED** | advisory says FrankenPHP likely susceptible, LSAPI FPM-like; no lab | build FrankenPHP, rerun WIRE-01/02/03 and CORE-01/02 |
| WIRE-14 | Upload tmp dir / `move_uploaded_file` race | file race | HYPOTHESIS | predictable tmp names, symlink race, cleanup timing | local race harness with two workers |
| WIRE-15 | Multipart filename cap (~5 KB) | constraint | REPO-MEASURED | filename injections cannot carry large payloads; use the value field | `docs/ANALYSIS.md` §0.6.3 |
| WIRE-16 | `upload_progress.min_freq` stall | re-init / stale pointers | PUBLIC + REPO-PROVEN | burst/stall/burst re-runs `php_session_initialize()`; §0.3 | `poc/verify_stall_arming.py` |
| WIRE-17 | `post_max_size` vs decoded memory | limit model | PUBLIC | wire under limit, heap over limit; the core property of 109618 | measure peak vs wire for each producer |
| WIRE-18 | CGI / embedded / CLI server | SAPI parity | HYPOTHESIS | request shutdown and module activation differ; cheap to test with `php -S` and `php-cgi` | rerun CORE-01/02 with `php -S` and `php-cgi` |

---

## 6. Extension register (EXT)

The stock `php:8.4.27` image used by the 115560 lab loads: `Core, ctype,
curl, date, dom, fileinfo, filter, hash, iconv, json, libxml, mbstring,
mysqlnd, openssl, pcre, PDO, pdo_sqlite, Phar, posix, random, readline,
Reflection, session, SimpleXML, sodium, SPL, sqlite3, standard, tokenizer, xml,
xmlreader, xmlwriter, Zend OPcache, zlib`. Every one is a parser or a
capability; the ones with C-level object handlers are the memory-safety
candidates.

| ID | Extension / surface | Class | Status | Why it is interesting | Cheapest test |
|---|---|---|---|---|---|
| EXT-01 | mbstring **SJIS-mac** `mb_substr` / `mb_trim` | OOB write (1–2 B) | PUBLIC report + REPO-ASAN | underflow past a 24-byte glibc allocation; public June 2026, still unfixed; repo has a controlled write | `poc`/ASAN: `mb_substr("hello",6,null,"SJIS-mac")`; notes held pending disclosure |
| EXT-02 | mbstring sibling encodings / functions | OOB | HYPOTHESIS | same `MIN(len, in_len - from)` shape may exist for `SJIS-win`, `CP932`, `ISO-2022-JP`, `UTF-7`; `mb_trim`, `mb_strimwidth`, `mb_convert_encoding` | encoding × function matrix under ASAN; start > length, omitted length |
| EXT-03 | iconv `iconv_substr` / `iconv_strpos` | OOB / underflow | HYPOTHESIS | glibc iconv 2.41; no `SJIS-mac` special case; analogous out-of-range start | ASAN: `iconv_substr("abc", 99, null, "UTF-8")` and exotic encodings |
| EXT-04 | DOM / XPath foreign-document UAF (GH-22554) | UAF | PUBLIC (being patched) | five UAF shapes; `DOMXPath::registerPHPFunctionNS` leaks a raw ZendMM pointer on 8.4.27 | `poc/verify_vardestroy_xpathleak.py`; upstream commits 2026-10-22/23 |
| EXT-05 | libxml XXE / entity expansion | file read / SSRF / DoS | PUBLIC (classic) | `LIBXML_NOENT`, `LIBXML_DTDLOAD`, `LIBXML_PARSEHUGE`; default `libxml_disable_entity_loader` is gone in PHP 8 | `DOMDocument::loadXML` with a local DTD and a canary file |
| EXT-06 | SOAP client / server | SSRF, CRLF, UAF, object injection | PUBLIC + HYPOTHESIS | `SoapClient::__call` fetches attacker WSDL; `SOAP_PERSISTENCE_SESSION` UAF (CVE-2026-7261); `SoapServer` decodes objects | local WSDL server + `SoapClient`; `SoapServer` session persistence under ASAN |
| EXT-07 | OpenSSL wildcard-name underflow (CVE-2026-91767) | OOB read | PUBLIC | `php_openssl_matches_wildcard_name()` underflows `memchr()` length; reachable from default client streams with `verify_peer_name=on` | local TLS server with a crafted wildcard cert; `stream_socket_client` + `openssl_x509_parse` |
| EXT-08 | curl | SSRF, CRLF, protocol smuggling | PUBLIC (app-level) | `CURLOPT_URL`, redirects, `CURLOPT_PROTOCOLS`, `CURLOPT_HEADER`, proxy; file:// / gopher:// gaps | lab SSRF endpoint; `poc/verify_lfi_discovery.py` style marker |
| EXT-09 | SPL custom `unserialize()` handlers | memory safety | HYPOTHESIS | `ArrayObject`, `SplObjectStorage`, `SplDoublyLinkedList`, `SplFixedArray`, `DateTime` implement `Serializable`/`__unserialize` in C; length/ref handling | feed each `C:`/`O:` payload malformed lengths and refs under ASAN |
| EXT-10 | Reflection / attributes | object instantiation | HYPOTHESIS | `ReflectionClass::newInstance*`, attribute `newInstance()` run constructors on app-chosen class names; a gadget sink if the name is attacker-controlled | app route that reflects on a user-supplied class/attribute; read + lab |
| EXT-11 | FFI | capability escalation | PUBLIC (design) | `ffi.enable=preload` still allows `FFI::cdef` from preloaded files; any object-injection gadget that reaches `FFI::cdef` is a terminal | `php -d ffi.enable=1 -r 'FFI::cdef("int puts(char*);")->puts("x");'` |
| EXT-12 | PDO / SQLite | injection / extension load | PUBLIC (app) | `ATTR_EMULATE_PREPARES`, multi-statement, `SQLite3::loadExtension`; `sqlite3.defensive=On` in stock | app query reachable from guest input; read the query builder |
| EXT-13 | Zip / zlib | path traversal / bomb | PUBLIC (app) | `ZipArchive::extractTo` traversal, symlink entries, zip bomb; `phar` overlaps | build a zip with `../` and a symlink; extract in a lab dir |
| EXT-14 | exif / getimagesize / gd | parser OOB | HYPOTHESIS | image metadata parsers are classic memory-safety surfaces; `exif_read_data` runs on uploads | corpus of malformed JPEG/TIFF under ASAN |
| EXT-15 | fileinfo / libmagic | parser OOB | HYPOTHESIS | `finfo_file` on attacker uploads; libmagic has a long CVE history | malformed magic corpus under ASAN |
| EXT-16 | intl / ICU | parser OOB / DoS | HYPOTHESIS | `Collator`, `Normalizer`, `IntlDateFormatter`, `MessageFormatter` parse attacker strings and locales | locale/format fuzz under ASAN; check ICU version |
| EXT-17 | pcre / JIT | stack exhaustion / OOB | PUBLIC (DoS) | attacker regex or attacker input against a fixed regex; `pcre.jit`, backtrack limit | `preg_match` with catastrophic input; measure stack and limits |
| EXT-18 | filter / parse_url | parser differential | PUBLIC (app) | `FILTER_VALIDATE_URL`, `parse_url` vs frontend/browser; allowlist bypass and SSRF | differential corpus: `http://127.0.0.1@evil`, backslashes, unicode, NUL |
| EXT-19 | proc_open / mail / pcntl / posix | command execution | PUBLIC (capability) | `mail()` 5th param, `proc_open` env, `putenv`+`LD_PRELOAD`, `pcntl_exec`; `disable_functions` bypasses | app wrapper audit; `docs/NOFUNC_115560.md` for the `zif_system` bypass |
| EXT-20 | `random` / `sodium` | predictability / misuse | PUBLIC (app) | weak `mt_rand`, `random_bytes` misuse, nonce reuse; token forgery | app token analysis; not a core memory bug |
| EXT-21 | `hash` / `password_*` | type juggling / timing | PUBLIC (app) | `hash_equals` misuse, `==` on hashes, null-byte truncation (fixed) | app auth review |
| EXT-22 | `json` | depth / memory | PUBLIC (DoS) | `json_decode` depth, huge strings, `JSON_THROW_ON_ERROR`; not usually memory corruption | depth/size limits in a lab |
| EXT-23 | `zend_test` / debug extensions | test-only | NEGATIVE | not loaded in stock images; do not count as reachable | `php -m` |
| EXT-24 | PECL `igbinary` / `msgpack` / `redis` | memory safety / store | HYPOTHESIS | separate C serializers and session handlers; not in stock image but common in production | build PECL handlers; fuzz `session_decode` and `unserialize` under ASAN |

**Extension front-runner.** EXT-01/02/03 share one arithmetic shape
(`start > length` with an omitted length) and one allocator (glibc `malloc`,
not ZendMM). EXT-04 is a live leak; EXT-06/07 are client-side parsers that can
be reached through SSRF. These are the cheapest places to look for a *new*
memory-safety primitive because the repo already has the ASAN harnesses.

---

## 7. Application / gadget register (APP)

Track B is the reachability bottleneck: a PHP-core primitive is only an
application CVE when a guest route supplies the sink and a stock class supplies
the gadget. The generated graph is a *candidate filter*; every row below is
source-checked at the stated level.

| ID | App / chain | Sink → gadget | Status | Evidence | First test |
|---|---|---|---|---|---|
| APP-01 | **Drupal 11.4+ core P5** | `YamlCacheCollectorDiscovery::__destruct → MenuActiveTrail::destruct → CacheCollector::updateCache → MemoryBackend::prepareItem → unserialize()` | REPO-PROVEN (ASAN + stock) | `docs/APP_SURVEY.md`; `reports/gadgets/drupal-graph.md` | `poc/verify_115560_drupal.py`; needs a sink + `serialize_handler: php` |
| APP-02 | Drupal known phpggc chains (FI1, FD1, AT1, RCE4) | file include/delete, SQLi, container `system` | **CLOSED** in 11.4 | `ProceduralCall` empty; typed properties; `__unserialize` throws; regression tests in `core/tests/.../GadgetChainTest.php` | read the tests; no lab needed |
| APP-03 | Drupal contrib guest sink | any `unserialize()` of raw guest bytes | **NEGATIVE** (42 projects) | `docs/APP_SURVEY.md` D1/D2 | broaden to field/views modules; write-then-read test |
| APP-04 | Roundcube Redis same-store | server `save_handler=redis` + `php_serialize`, app `session_storage='redis'` | **NEGATIVE (tested 2026-10-31)** | `docs/ROUNDCUBE_REDIS_115560.md`; PROGRESS iteration 64 | keys align with `session.save_path="tcp://redis:6379?prefix="`, and the stock switch runs, but `rcube_session_redis::read()` expects its own `a:3:{changed,ip,vars}` envelope; the hook's `php_serialize` blob never reaches PHP's decoder. The plugin remains a store adapter. |
| APP-05 | Roundcube plugin profile | plugin `__destruct → unserialize` before `session_init()` | REPO-PROVEN (plugin-gated) | `docs/ROUNDCUBE_115560.md`; `reports/gadgets/roundcube.md` | stock code has no gadget; keep as a precondition proof |
| APP-06 | **WordPress LearnPress 4.4.13** | `_lp_custom_register_form → user meta → maybe_unserialize` | PUBLIC-ish (guest sink; no gadget) | `docs/APP_SURVEY.md` P1; `inc/user/lp-user-functions.php:1435/1447` | self-registration + `/profile/settings/`; graph 50–100 plugins for a dtor |
| APP-07 | WordPress core | `SimplePie::__destruct → WP_HTML_Token` gated by `!gc_enabled()` | **CLOSED as shipped** | `docs/JOOMLA_GADGET.md`; `docs/SPLIT_GADGET.md` §4 | no stock WP RCE; plugin-only |
| APP-08 | **Joomla 5.4 stock** | `Mail::__destruct → PHPMailer::smtpClose → DataSet::__call → FnStream::close → Registry::__clone → unserialize(serialize())` | UAF/DoS only | `docs/JOOMLA_GADGET.md`; `reports/gadgets/joomla-graph.md` | `serialize()` cannot emit `R:` or a raw pointer; needs a different dtor |
| APP-09 | Joomla PHPMailer `SMTP::edebug` | `call_user_func($this->Debugoutput, $str, $level)` | READ (dispatch candidate) | `SMTP.php:298`; graph path `Mail::__destruct → smtpClose → connected → edebug` | forge `Debugoutput='system'`; command is the SMTP response string — test with a local SMTP server |
| APP-10 | PrestaShop 8.2.1 + `ps_facetedsearch` | guest `unserialize(current($row))`; `FnStream` re-entry | Sink PUBLIC (CVE-2026-54159); gadget **BLOCKED** | `docs/APP_SURVEY.md` P3; `FnStream::__wakeup` throws since psr7 1.9 | hunt an alternate dtor → direct `unserialize($prop)` |
| APP-11 | Symfony `PrototypeConfigurator::__destruct` | graph edge to `PhpFileLoader::registerClasses → unserialize()` | **NEGATIVE (source-checked)** | `FileLoader.php:145` unserializes `serialize($prototype)` — not attacker bytes | no lab; record as a graph false positive |
| APP-12 | Symfony `PhpProcess::__destruct` | graph edge to `exec()` | **BLOCKED** | `Process::__unserialize`/`__serialize` throw; object cannot come from `unserialize()` | no lab |
| APP-13 | Laravel Mail `SentMessage`/`MessageSent` | `__unserialize → unserialize(base64_decode(...))` | **NOT A RE-ENTRY** | `__unserialize` runs under `BG(serialize_lock)`; no `__destruct` | no lab; use as a nested-decoder amplifier only |
| APP-14 | TYPO3 Extbase / Form | guest `__referrer[arguments]` / `__state` unserialize | **HMAC-gated** | `SYS.encryptionKey`; `allowed_classes=true` | needs a key leak first |
| APP-15 | Craft / Concrete / MediaWiki / SilverStripe / Magento / Sylius | assorted sinks | gated / allowlisted / no write | `docs/APP_SURVEY.md` P4 | do not prioritize |
| APP-16 | CakePHP 2/3/4/5 `cake`/`database` sessions | app switches to `php` | no stock gadget found | `docs/GADGET_SURVEY_115560.md` §4 | one request to see whether the store reads the progress file |
| APP-17 | **phpggc public corpus** | framework chains (Drupal, Laravel, Symfony, Magento, WordPress, Joomla, …) | PUBLIC | not vendored; reference only | treat as the baseline; version-gate every chain |
| APP-18 | Template engines (Twig, Smarty, Latte) | SSTI | PUBLIC (app-level) | `eval`/`call_user_func` in compiled templates; sandbox modes | lab template with a user-controlled template name/string |
| APP-19 | App SQL / PDO emulate | SQL injection | PUBLIC (app-level) | `ATTR_EMULATE_PREPARES`, multi-statement, identifier interpolation | app route review; not a core bug |
| APP-20 | App SSRF / XXE | outbound request / file read | PUBLIC (app-level) | `curl`, `file_get_contents`, `SoapClient`, `DOMDocument` | lab SSRF/XXE endpoint; chain to EXT-07 / EXT-05 |
| APP-21 | App file upload + image/archive parser | parser OOB | HYPOTHESIS | upload → `exif`/`gd`/`zip`/`Phar`/`finfo` | upload malformed files under ASAN; check the real route |
| APP-22 | App command wrappers | command injection | PUBLIC (app-level) | `mail`, `proc_open`, `shell_exec`, `ImageMagick` delegates | audit wrappers; fixed benign command only |
| APP-23 | App `session_decode()` sinks | object injection | HYPOTHESIS | see SER-05; stock trees have no guest route in this scan | grep + read every call site; build a minimal route if one exists |
| APP-24 | Plugin/theme ecosystems | unbounded gadget surface | **UNBOUNDED** | 22 WP plugins, 42 Drupal contrib, Roundcube plugins audited | pick the app with the precondition (Roundcube) and graph its plugin repo |

**Application front-runner.** APP-04 (Roundcube Redis same-store) was the
cheapest precondition-removal experiment and is now **falsified**: the stock
driver's own `vars` envelope blocks the upload-progress record, so the plugin
survives as a store adapter. APP-06 (LearnPress guest sink) is the best *sink
without a gadget* and is the next app experiment. APP-01 is the only stock
terminal gadget and is config-gated. No default guest sink + stock terminal
gadget exists in the audited set — that remains the honest ceiling.

---

## 8. Client / outbound register (CLI)

PHP is also an HTTP/SOAP/LDAP/SQL client. A malicious server can drive PHP's
parsers, and an SSRF can turn a server-side app into that client. These rows
are where a "server compromise" becomes a "client-side parser bug".

| ID | Surface | Class | Status | Why it matters | Cheapest test |
|---|---|---|---|---|---|
| CLI-01 | SSRF to cloud metadata / internal admin | credential theft | PUBLIC (app) | the most common real-world RCE detour; `curl`, `file_get_contents`, Guzzle | lab SSRF route + a local metadata stub |
| CLI-02 | Malicious TLS server → OpenSSL wildcard underflow | OOB read / leak | PUBLIC (CVE-2026-91767) | default `verify_peer_name=on`; a crafted wildcard cert reaches the underflow | local TLS server with a crafted cert; `stream_socket_client` |
| CLI-03 | SOAP WSDL / `__soapCall` | XXE / SSRF / object injection | PUBLIC + HYPOTHESIS | attacker WSDL is parsed with libxml; `SoapServer` persistence path | local WSDL + XXE canary |
| CLI-04 | ImageMagick / Ghostscript delegates | command execution | PUBLIC (app) | `convert` on an uploaded file can invoke delegates; policy.xml is the control | lab upload + `convert` with a benign marker |
| CLI-05 | Redis / Memcached session store | object injection / deserialization | HYPOTHESIS | if the app deserializes store values, a network-adjacent attacker can inject | `lab-roundcube-redis`; write a crafted value, read it back |
| CLI-06 | MySQL / PostgreSQL client | rogue server / `LOAD DATA LOCAL` | PUBLIC (app) | a malicious DB server can read client files or exploit the client parser | local rogue server; read the client options |
| CLI-07 | LDAP / IMAP / SMTP clients | injection / SSRF | PUBLIC (app) | filter injection, CRLF, `STARTTLS` downgrade, header injection | lab server; read the client code |
| CLI-08 | `mail()` / `sendmail_path` | command execution | PUBLIC (app) | 5th parameter injection; `sendmail_path` config | app wrapper audit; fixed benign command |
| CLI-09 | `curl` `file://` / `gopher://` / redirects | local file read / SSRF | PUBLIC (app) | `CURLOPT_PROTOCOLS` and redirect policy are the controls | lab SSRF; read the local file |
| CLI-10 | DNS rebinding | SSRF bypass | PUBLIC (app) | resolves a public name to `127.0.0.1` after the allowlist check | local DNS + two-request lab |
| CLI-11 | XXE external entity | file read / SSRF | PUBLIC (classic) | `LIBXML_NOENT` on attacker XML; PHP 8 does not disable entities globally | `DOMDocument` + local DTD + canary |
| CLI-12 | Phar over a stream / archive tool | object injection | PUBLIC (classic) | a local phar can be triggered by a file operation; see SER-17 for the lazy nuance | lab phar + the app's file operation |

---

## 9. Deployment / configuration register (DEP)

Config is not a bug, but it decides which chain is reachable. The repo has
measured several of these; the unmeasured ones are cheap labs.

| ID | Config surface | Effect | Status | Test |
|---|---|---|---|---|
| DEP-01 | Per-directory `.user.ini` `session.serialize_handler` | enables SER-03 across dirs | REPO-PROVEN | `poc/verify_handler_mismatch.py` |
| DEP-02 | FPM `php_value` vs `php_admin_value` | pool value allows the app `ini_set`; admin value blocks 115560 | READ + PUBLIC | two pools, one request each |
| DEP-03 | Worker model (`pm.max_children`, `MaxRequestWorkers`, `pm.max_requests`) | same-worker pairing; reset cadence | REPO-PROVEN | `poc/verify_worker_pinning.py`, `docs/WORKERS_115560.md` |
| DEP-04 | nginx `fastcgi_request_buffering` | on = flattens the stall and lengthless body; off = streaming | REPO-PROVEN | `poc/verify_stall_arming.py` / negative |
| DEP-05 | opcache / preload / file cache | code injection or stale-code surface | HYPOTHESIS | writable `opcache.file_cache`; `validate_timestamps=0` |
| DEP-06 | Shared hosting / cross-tenant | cross-account session or file access | HYPOTHESIS | two vhosts, shared save path, same worker pool |
| DEP-07 | cgroup / `RLIMIT_AS` / `RLIMIT_DATA` | an OOM trigger, not a control | PUBLIC | advisory explicitly warns; measure with `ulimit -v` |
| DEP-08 | `disable_functions` | blocks named functions, not forged `zif_system` | REPO-PROVEN | `docs/NOFUNC_115560.md` |
| DEP-09 | `open_basedir` | path restriction; bypass surface | PUBLIC | `glob://`, `phar://`, `realpath` race, `chdir` |
| DEP-10 | `allow_url_fopen` / `allow_url_include` | SSRF / RFI | PUBLIC | `data://`, `php://input`, `http://` include |
| DEP-11 | Shared `session.save_path` | cross-app session read/write | REPO-PROVEN (concept) | two apps, same path, different handlers |
| DEP-12 | Redis / DB session store | namespace collision / object injection | NEGATIVE for stock Roundcube; open for other stores | `lab-roundcube-redis`, `docs/ROUNDCUBE_REDIS_115560.md` |
| DEP-13 | Uploaded `.user.ini` / `.htaccess` | per-dir config injection | PUBLIC (app) | upload a `.user.ini` to a writable webroot |
| DEP-14 | Apache `.htaccess` `php_value` | per-dir INI before request startup | PUBLIC | 109619 INI consumer; `poc/verify_109619_modphp_chain.py` |
| DEP-15 | EOL PHP (7.4/8.0/8.1/8.2) | no fix for new bugs | PUBLIC | version fingerprint + advisory backports |

---

## 10. The 0day frontier — ranked candidates

Ranking rule: **new primitive first**, then reachability, then effort. A
candidate is not a finding; each row names the cheapest command that can
falsify it.

| Rank | Candidate | Why it could be new | Impact if real | Effort | Confidence | First falsifying test |
|---:|---|---|---|---|---|---|
| 1 | **EXT-02/03 — mbstring/iconv out-of-range start** | the SJIS-mac report is public but the *sibling encodings* and `iconv_substr` were not checked; same arithmetic shape | OOB write/read → leak or corruption | M | Medium | ASAN encoding × function matrix |
| 2 | **CORE-10 — Fiber suspend/resume inside destructors** | fibers have a separate stack and are not covered by the session work | UAF / arbitrary call | M | Low–Medium | ASAN harness: suspend in `__destruct`, free, resume |
| 3 | **CORE-08/09 — shutdown/destructor re-entrancy** | destructor runs while error handler / output buffer / object store is half-torn-down | UAF / double free | M | Medium | ASAN: throw from `__destruct`, force OOM, `gc_collect_cycles` |
| 4 | **SER-06/07 — `php_binary` / `php_serialize` parity** | three decoders, one `var_destroy`; cross-handler and malformed-length shapes are underexplored | UAF / object confusion | S–M | Medium | same 1018-element payload across all three under ASAN |
| 5 | **APP-06 — LearnPress guest sink + plugin gadget** | guest object injection is confirmed; the gadget is the missing half; Roundcube Redis is now falsified | 9.8-potential app RCE | M | Low–Medium | graph 50–100 WP plugins for `__destruct → unserialize` |
| 6 | **EXT-06 — SOAP client/server** | attacker WSDL + `SOAP_PERSISTENCE_SESSION`; parser and object paths | SSRF / XXE / UAF | M | Medium | local WSDL + session persistence under ASAN |
| 7 | **EXT-07 — OpenSSL wildcard underflow as a leak** | public OOB read, but no clean userland channel; a TLS client is one | address leak → terminal | M | Medium | local TLS server + `stream_socket_client` |
| 8 | **EXT-09 — SPL custom `unserialize()` handlers** | C-level `Serializable` implementations are less audited than `var_unserializer` | OOB / type confusion | S | Low | malformed `C:`/`O:` payloads for `ArrayObject`, `SplObjectStorage`, `SplFixedArray` |
| 9 | **APP-09 — Joomla `SMTP::edebug` dispatch** | stock `call_user_func` on an attacker property; result string is server-controlled | command dispatch (limited) | S | Low | forge `Debugoutput='system'` + local SMTP server |
| 10 | **WIRE-05/06 — multipart part/boundary differentials** | `max_multipart_body_parts=-1` and rfc1867 boundary parsing are untested on 8.4.27 | DoS / parser confusion | S–M | Medium | 10k-part body + boundary corpus against Apache/FPM |
| 11 | **CORE-14/15 — opcache file cache / JIT** | writable cache dir or JIT type confusion is a code-injection class | code execution | L | Low | writable `opcache.file_cache`; run the corpus with JIT on |
| 12 | **SER-14 — PECL `igbinary`/`msgpack` serializers** | separate C parsers, common in production, absent from the stock image | memory safety | M | Low | build PECL handlers; fuzz `session_decode`/`unserialize` |

**What would move the needle most.** Ranks 1–4 are all *primitive* hunts with
existing ASAN harnesses; ranks 5–8 are *reachability* hunts with existing
labs. Do not start a rank-11/12 project before a rank-1–4 experiment returns a
real ASAN report: the repo's ceiling is not "no more bugs", it is "few
unexplored shapes with cheap falsification".

---

## 11. What is closed, and should not be re-litigated

| Closed item | Why | Evidence |
|---|---|---|
| CVE-2026-109618 / 109619 named paths | patched in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | `docs/ANALYSIS.md` §0.1 |
| Chain A / session poison + LFI | public, survives the patch (app-level) | `poc/verify_chain_a_lfi.py`, `poc/verify_session_poison_lfi.py` |
| Chain C / handler mismatch | public, survives the patch (config-level) | `poc/verify_handler_mismatch.py` |
| `var_destroy` re-entry UAF | public since 2026-05-02; not a new CVE | `docs/RESEARCH_REVIEW_2026-10-30.md` §2.1 |
| Drupal phpggc FI1/FD1/AT1/RCE4 | fixed in 11.4 by empty `ProceduralCall`, typed props, throwing `__unserialize` | `core/tests/.../GadgetChainTest.php` |
| Symfony `Process` unserialize | `__serialize`/`__unserialize` throw | `Process.php:214` |
| Symfony `PrototypeConfigurator` graph edge | the `unserialize` is of `serialize($prototype)`, not attacker bytes | `FileLoader.php:145` |
| Laravel Mail `__unserialize` | runs under `BG(serialize_lock)`; no `__destruct` | `docs/GADGET_SURVEY_115560.md` §3.3 |
| `FnStream`-based re-entry | throwing `__wakeup` suppresses `__destruct` since psr7 1.9 | `docs/SPLIT_GADGET.md` §4 |
| WordPress `SimplePie` gadget | `!gc_enabled()`-gated; WP never disables GC | `docs/JOOMLA_GADGET.md` |
| Joomla `Registry::__clone` terminal | `serialize()` cannot emit `R:` or a raw pointer | `docs/SPLIT_GADGET.md` §2 |
| Session id path traversal | `/` and `..` rejected in 8.5.12 | §4.2 |
| Roundcube Redis same-store | keys align, but `rcube_session_redis::read()` expects its own `vars` envelope; plugin still needed | `docs/ROUNDCUBE_REDIS_115560.md`, PROGRESS iteration 64 |
| `allowed_classes=false` bypass via `C:` | respected in 8.5.12 | §4.3 |
| Phar metadata on any file op | lazy in 8.5.12; `getMetadata()` is the sink | §4.4 |

A closed item can still be a **control** or a **stepping stone**. It cannot be
the novelty claim.

---

## 12. Tool coverage and gaps

| Tool | What it answers | What it does **not** answer |
|---|---|---|
| `scripts/gadget_sweep.sh` | same-method magic → sink inventory; ranked `reentry`/`terminal`/`dispatch`/`file` | no cross-class, no guards, no dataflow |
| `scripts/gadget_graph.sh` | cross-class type/call edges, inheritance, traits, typed properties | no dataflow, no guard evaluation, no runtime autoload |
| `scripts/diff_builds.sh` | patch signal (function size) + per-symbol shift | no semantic proof; shifts are not reusable page deltas |
| `scripts/calibrate.sh` | ZendMM geometry from ground truth | per-build; needs a target |
| `scripts/matrix.sh` | pos/neg/bias across build × arch | only rows that already reproduce |
| `fuzz/gen.py` + `fuzz/asan_run.php` | blind mutation of serialization/multipart/XML/string corpora | no coverage guidance; 4.1M execs / 1.24M inputs was a clean negative |
| `poc/verify_*.py` | one claim per POC, with controls | only the shapes already written |
| `poc/probe_ps_globals.py` | ground truth for `PS(id)` / chunk offset | needs `SYS_PTRACE` and a live worker |
| ASAN build | memory-safety confirmation | allocator geometry differs from stock ZendMM |
| Stock ZendMM run | real heap impact | no ASAN report; silent corruption is possible |

**Gaps that matter for a 0day hunt:**

- **Coverage-guided fuzzing** — the current corpus is blind. AFL++/`php-fuzzer`
  on `session_decode`, `unserialize`, rfc1867, and the mbstring/iconv
  converters is the single biggest missing capability.
- **PECL serializers** — `igbinary`, `msgpack`, `redis` are not in the stock
  image and not fuzzed.
- **Non-mod_php SAPIs** — FrankenPHP and LSAPI are untested; FPM is only
  partially proven.
- **x86-64 native** — the arm64 18-bit ASLR shortcut does not transfer to the
  28-bit x86-64 default; a leak or a new seed is required.
- **Joern / interprocedural taint** — the graph is type/call only; a real
  dataflow engine would reduce the app false positives.
- **Fiber/JIT/shutdown harnesses** — no POC exists for CORE-08/09/10/11/12/15.

---

## 13. Next experiment batch (cheapest first)

Each item is one lab session and one receipt. Do not start the next until the
previous has a PASS/FAIL/BLOCKED result.

1. **Encoding arithmetic matrix (EXT-02/03).** Under `lab-asan-85x`, run
   `mb_substr`, `mb_trim`, `mb_strimwidth`, `mb_convert_encoding`,
   `iconv_substr` with `start > len`, omitted length, across `SJIS-mac`,
   `SJIS-win`, `CP932`, `ISO-2022-JP`, `UTF-7`, `UTF-8`, `EUC-JP`. Record every
   ASAN report and the exact encoding/function pair. This is the highest-value
   new-bug search because the arithmetic shape is already confirmed once.
2. **Session handler parity (SER-06/07).** Take the 1018-element
   `var_destroy` payload and the malformed-key corpus; decode each under
   `php`, `php_binary`, `php_serialize` via `session_decode()` and
   `session_start()`. Compare ASAN reports and `$_SESSION` shape. Look for a
   handler-specific UAF/OOB or a cross-handler truncation.
3. **Fiber/destructor harness (CORE-10).** On ASAN: create a Fiber, suspend
   inside a destructor, free the object, resume, and run
   `gc_collect_cycles()`. Add a nested `unserialize()` in the destructor to
   test whether the `var_destroy` lock model changes under a fiber.
4. **Roundcube Redis same-store (APP-04) — already falsified.** Do not
   re-open without a new store/adapter primitive. The executed result is in
   `docs/ROUNDCUBE_REDIS_115560.md`: keys align with `?prefix=`, the stock
   switch runs, but `rcube_session_redis::read()` expects its own
   `a:3:{changed,ip,vars}` wrapper, so the hook's blob is never decoded. Move
   to the LearnPress plugin graph (APP-06).
5. **SOAP client/server (EXT-06).** Stand up a local WSDL server and a
   `SoapServer` with `SOAP_PERSISTENCE_SESSION`; feed an external entity and a
   malformed object graph. ASAN + stock. This tests both XXE and the
   session-persistence UAF family.
6. **OpenSSL wildcard leak (EXT-07).** Build a local TLS server with a
   crafted wildcard certificate; connect with `stream_socket_client` and
   `verify_peer_name=on`; measure whether the underflow is observable as a
   crash, an OOB read, or a usable leak. If no userland channel, record the
   negative.
7. **SPL custom `unserialize()` handlers (EXT-09).** Feed malformed `C:`/`O:`
   payloads to `ArrayObject`, `SplObjectStorage`, `SplDoublyLinkedList`,
   `SplFixedArray`, `DateTime`, `DateInterval` under ASAN. Look for length/ref
   confusion distinct from `var_unserializer`.
8. **Joomla `SMTP::edebug` dispatch (APP-09).** Forge the `Mail → SMTP`
   graph with `Debugoutput='system'` and a local SMTP server that returns a
   benign marker as the response line. If the marker executes, it is a stock
   Joomla dispatch gadget; if not, record the guard.

**Stop rule.** If items 1–3 produce no ASAN report and item 4 produces no
namespace match, the frontier is not in this batch; move to the app sink hunt
(APP-06) or the PECL serializer fuzz (SER-14) rather than adding more shapes
to the same harness.

---

## 14. Honest ceilings / non-claims

- **"All possible" is not achievable.** This map enumerates surfaces and
  chain shapes; it does not prove absence. A negative is only a negative for
  the stated tree, build, config, and pattern set. §0.1 records the measured
  scale gap (1,203 internal functions in one minimal build) and what a truly
  exhaustive campaign would require.
- **No new CVE is claimed.** The core CVEs are public; `var_destroy` is public;
  the mbstring SJIS-mac report is public. The map's "frontier" rows are
  candidates, not disclosures.
- **The app graph is static.** It does not model dataflow, guards, runtime
  autoload, service containers, or version gates. Every APP row needs a lab
  receipt before it is a finding.
- **ASAN geometry is not exploit geometry.** A confirmed UAF/OOB in ASAN does
  not imply a stock-ZendMM primitive; the repo measures both separately.
- **The arm64 no-`/proc` result does not generalize to x86-64.** 18-bit mmap
  ASLR is 512 main slots; the x86-64 default is 2^19 and needs a leak.
- **The web layer is not exhaustively fuzzed.** WIRE-05/06/07/08/09 are
  hypotheses; the repo's measured rows are the ones with POCs.
- **No remote targeting, persistence, lateral movement, reverse shells, or
  arbitrary command packaging.** The terminal proof remains a fixed allowlisted
  command in a lab.
- **Documentation debt, resolved 2026-10-31.** The mbstring working notes are held
  and not shipped. The `var_destroy` and `split-gadget` headers now state the
  public prior art (mbstring, June 2026; var_destroy, May 2026). Treat
  `docs/RESEARCH_REVIEW_2026-10-30.md` §2 as the novelty status, not any
  earlier header.

---

## 15. Reproduction index

| Claim | Command / path |
|---|---|
| Core OOM trigger | `poc/verify_109618_oom.py` |
| OOM → stale global (mod_php) | `poc/verify_109619_modphp_chain.py` |
| OOM → stale global (FPM) | `poc/verify_109619_fpm_chain.py` |
| `var_destroy` UAF (ASAN) | `poc/verify_uaf_asan.php`, `poc/verify_var_destroy_uaf.php` |
| 115560 → var_destroy → `zif_system` | `poc/verify_115560_vardestroy.py` |
| Handler mismatch / Chain C | `poc/verify_handler_mismatch.py`, `poc/verify_rce_gadget.py` |
| Session poison + LFI | `poc/verify_session_poison_lfi.py` |
| Drupal P5 gadget | `docs/APP_SURVEY.md`; `reports/gadgets/drupal-graph.md` |
| Joomla gadget graph | `scripts/gadget_graph.sh lab-joomla/webroot --label joomla-graph` |
| Roundcube graph | `scripts/gadget_graph.sh lab-roundcube/roundcubemail-1.6.11 --label roundcube-graph` |
| mbstring SJIS-mac | held pending disclosure |
| Build diff | `scripts/diff_builds.sh php:8.4.26-apache php:8.4.27-apache` |
| Offline gate | `scripts/check.sh` |

**Bottom line.** The repo already owns the hard primitives (core UAF/OOM,
forged object → `zif_system`, stock Drupal gadget). The remaining novel-bug
probability is concentrated in **parser arithmetic in extensions**, **lifetime
re-entry in fibers/shutdown/GC**, **session decoder parity**, and **one
application reachability experiment (LearnPress plugin graph)** — not in re-proving
the 2026 CVEs.
