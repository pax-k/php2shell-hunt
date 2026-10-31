# What did not work

**Date:** 2026-10-31 · **Scope:** lab-only, `127.0.0.1` · **Proof command:** `id>/tmp/vd 2>&1` (fixed, benign) · **Series:** [index](https://github.com/pax-k/php2shell-hunt/blob/main/docs/PUBLICATION_SERIES/README.md)

> **Lab boundary.** Local containers only; targets `127.*`/`::1`; the only
> command executed was the fixed, benign `id>/tmp/vd 2>&1`; no command interface.

---

## 1. The 4.1M-execution campaign that found nothing

If `unserialize()` or `session_decode()` could leak one pointer in-band, the
arm64 brute force would stop mattering everywhere, so the obvious move was to
fuzz the decoders: `fuzz/gen.py` mutates seed corpora, `fuzz/asan_run.php`
prints `PROCESSING <idx>` *before* each call so a crash leaves the killing index
recoverable, and `fuzz/triage.py` fingerprints the report.

**Result: 4.1M ASAN executions over 1.24M inputs, four corpora, zero reports**
(`docs/RESEARCH_REVIEW_2026-10-30.md` §1).

Zero reports is the finding. It converts "the in-band seed is probably findable
by fuzzing" into a measured bound: at this mutation depth, against these
corpora, no crash is reachable by blind input variation. That is a negative
about the *search*, and it is what redirected the work toward an external leak
and the arm64 window scan instead of more random bytes.

The ceiling sits beside the number: the mutator is blind — no coverage guidance,
no grammar feedback — so 4.1M is a sample size, not a coverage statement
(`docs/BLIND_SPOTS.md` §5; `docs/ATTACK_SURFACE_MAP.md` §12). It says nothing
about PECL serializers, non-default ini combinations, version gates, or a seed
needing a request sequence: "no generic in-band seed for these four corpora",
never "no in-band seed exists". Receipts: `fuzz/gen.py`, `fuzz/asan_run.php`,
`fuzz/triage.py`.

## 2. The version matrix fails at the leak shape, not at offsets

Per build the matrix asks three questions: does the chain fire (pos), is it
blocked on the patched build (neg), and does a `+0x1000` bias on `zif_system`
prevent the fire (bias)? A row is proven only when all three hold
(`poc/verify_matrix.py`, `scripts/matrix.sh`).

The 8.4 series passes six for six on aarch64 — 8.4.10, 8.4.20, 8.4.23, 8.4.24,
8.4.25, 8.4.26 — each firing `uid=33`, each blocked on 8.4.27, each prevented by
the bias. 8.4.1 is excluded, not bent into a pass: it discloses but yields no
usable pointers. The other branches fail somewhere else:

| build | pos | what actually failed |
|---|---|---|
| 8.2.34 | FAIL | leak shape: a normal 32-hex session id, not a disclosure |
| 8.3.35 | FAIL | same |
| 8.5.11 | FAIL | same; the OOM path also aborts the worker (`zend_mm_heap corrupted`) |

A bounded sweep — parts 700–920, depth 56/64, five `LEAK_SPEC` variants — found
no disclosure on any of the three (`docs/STATUS.md` §5 P2). Those builds already
had extracted offsets pinned to a `libphp.so` SHA-256 in `profiles/offsets.json`
(`docs/OFFSETS.md`), so the constants were right; an "offset problem" verdict
would have sent the next iteration to re-derive numbers that were never wrong.

`poc/probe_ps_globals.py` explains the shape: it reads `ps_globals.id` (offset
`0x10`) out of a `SYS_PTRACE` worker after a producer.

| build | producer | `PS(id)` after | outcome |
|---|---|---|---|
| 8.4.26 | 9bie A1 | non-NULL, chunk `0x137000` stable | B1 reclaims it → leak |
| 8.2.34 / 8.3.35 | 9bie A1 | NULL | no stale state |
| 8.2.34 / 8.3.35 | mod_php 2000×60 | non-NULL, `0x5b268` / `0x5c268`, **varies** | B1 END-cleanup never runs (no `Set-Cookie`) |
| 8.5.11 | 9bie A1 | non-NULL | worker aborts before a consumer runs |

Only 8.4 leaves a stable, reclaimable `PS(id)` with the rfc1867 END cleanup
wired: the others fail at "there is no pointer to read", not "the pointer is at
the wrong offset". A dense forge spray (`D:<pages>:<step>`, headers every
`0x40`–`0x100`) was negative on 8.2/8.3 too, and B1 still sent no `Set-Cookie`
— the ceiling is the cleanup path. Receipts: `poc/verify_matrix.py`,
`poc/probe_ps_globals.py`, `docs/STATUS.md` §5 P2, `docs/OFFSETS.md`.

## 3. WordPress core: a negative for reachability, not for code

The sweep over `lab-wp-zendmm/webroot` covers **1,521 PHP files, 179 magic
methods, 896 candidates, 2 re-entry hits**; the graph adds 845 classes and 35
paths, and both hits are lab harness files in `wp-content/mu-plugins/`, not core
(`reports/gadgets/wordpress.md`, `reports/gadgets/wordpress-graph-graph.md`).
The nearest core shapes are dispatch, not re-entry:
`WP_HTML_Token::__destruct → call_user_func`
(`wp-includes/html-api/class-wp-html-token.php:112-114`) and
`PHPMailer::__destruct → smtpClose → edebug → call_user_func`
(`wp-includes/PHPMailer/SMTP.php:301`).

Then the honest part: a re-entry *does* exist in core code —
`SimplePie::__destruct → $item->__destruct → WP_HTML_Token::__destruct →
call_user_func($on_destroy, ...) → unserialize`
(`wp-includes/SimplePie/src/SimplePie.php:716-722`). It is gated on
`!gc_enabled()`, and WordPress never calls `gc_disable()`, so the verdict is
**negative for reachability as shipped**, not "no gadget in the codebase"
(`docs/GADGET_SURVEY_115560.md` §3.6, §9).

That also exposes the graph's ceiling: the traversal walks an untyped array
(`$this->data['items']`), so the SimplePie shape never appears in the PHP-Parser
graph — a graph zero describes modelled edges, not the tree. What the run does
establish is impact: the lab supplied both halves (`lab-wp-zendmm/uaf-harness/`),
the FPM child dies `SIGSEGV`, the response is `502`, and the result is a
per-request DoS for a plugin with that shape — not PHP core, not WP core
(`docs/VAR_DESTROY_UAF.md` §4b). Receipts: `reports/gadgets/wordpress.md`,
`reports/gadgets/wordpress-graph-graph.md`, `docs/GADGET_SURVEY_115560.md` §3.6/§9.

## 4. Roundcube + Redis: same store, falsified

The cheapest way to delete a precondition: if server `session.save_handler=redis`
plus Roundcube `session_storage='redis'` let stock `rcube_session_redis` perform
the `php` switch *and* read the hook's key, the lab plugin would be unnecessary.
On `lab-roundcube-redis/` (php 8.4.27-apache, phpredis 6.3.0, `redis:7-alpine`)
the answer is no.

The switch half is real: `?prefix=` on `session.save_path` aligns the keyspace to
the raw session id, and the log shows `handler-switch-DISABLED` then
`simple-dtor`, so stock code ran `ini_set('session.serialize_handler','php')`.
The envelope blocks: the hook writes
`a:1:{s:36:"upload_progress_|...";a:5:{...}}`, while `read()` does
`$arr = unserialize($value)` (`session/redis.php:133`) and takes `$arr['vars']`
(`:136`), expecting `a:3:{s:7:"changed";...;s:4:"vars";...}`. No `vars` key, so
`read()` returns `''` and the decoder never sees the payload. The 2×2 matrix
isolates it — only *raw sid + Roundcube wrapper* fires; *raw sid + phpredis
blob*, *prefixed + blob* and *prefixed + wrapper* are all `dtor=no`.

So "the stock Redis driver removes the plugin" is falsified here. The negative
is narrower than "Redis is safe": one build, phpredis 6.3.0, `cleanup=Off`, race
not re-run in Redis. It rules out the upload-progress record as a `vars`
envelope — the hook serialises `[prefix.name => progress_array]` with a
PHP-built array, so the wrapper needs write access to the key or an app path
storing attacker session vars, neither unauthenticated. The isolation control
still fires with `session_storage='php'` against the same Redis server, and only
with the plugin switch. Receipts: `lab-roundcube-redis/setup.sh`,
`poc/verify_roundcube_redis.py`, `docs/ROUNDCUBE_REDIS_115560.md`,
`lab-roundcube-redis/evidence/redis-8427.log`.

## 5. The FPM in-band leak is unsolved *here*

The mod_php path is the one with receipts. The FPM rung-5b proof on 8.2.34 still
needs the `[UAFDBG]` oracle (`lab-zendmm-fpm/instrument.py`) to aim, and the
8.2.35 control blocks; without it there is no in-band leak on the pool. The
public 8.5.11 result on this branch is DoS-only — the worker aborts
`zend_mm_heap corrupted`.

That is a ceiling on this repository, and §2.4 of the review says so plainly:
**our FPM ceiling is our ceiling, not the field's.** Trail of Bits described a
production-grade exploit on stock `php.ini-production` — multi-worker, ASLR,
ARM64 and x86-64, Apache/mod_php *and* nginx/php-fpm (private, not released);
VulnCheck had a weaponised 8.4/8.5 mod_php exploit by 2026-10-22 plus a public
ASLR-bypass PoC for 8.4.26; the Wiz/Calif writeup demonstrates nginx + PHP-FPM
(`docs/RESEARCH_REVIEW_2026-10-30.md` §2.4).

So the sentence has to read "unsolved **in this lab, on this build, with this
driver**"; "FPM is unsolved" would be a claim about other people's work that the
evidence here cannot support, and it would be wrong. What is defensible: the
core-chain matrix is mod_php-only, the FPM row is instrumented, and no FPM row
has the full pos/neg/bias triad. Receipts: `poc/verify_109619_rce.py`,
`lab-zendmm-fpm/`, `lab-zendmm-fpm-8235/`, `docs/STATUS.md` §7.
`docs/RESEARCH_REVIEW_2026-10-30.md` §2.4 is the honest-ceiling source above.

## 6. arm64 finds the seed; native x86-64 does not

On arm64 with `vm.mmap_rnd_bits = 18` the ZendMM `main` chunk has nine bits of
entropy: 512 possible 2 MiB slots, 576 candidates at `0x200000` steps. A wrong
guess kills a child and the parent respawns it; children inherit `main`, so one
correct slot serves the pool. Measured with no `/proc` and no maps: 8.5.12 at
attempt 351 (1406 s), 8.4.27 at 307 (1238.8 s); a brute-force run recovered
8.5.12 in 384 / 80 / 464 attempts across three ASLR generations, and 8.2.34 /
8.3.35 in 13,519 / 11,363.

Native x86-64 at the default 28 bits is roughly `2^19` slots, and there the scan
stops being a strategy: infeasible in time, and noisy, because every miss kills
a worker. That path needs a leak, not a wider loop. The amd64 numbers that exist
are Rosetta userspace with explicit addresses (`main = 0x7ffffc400000`,
`lib = 0x7ffffe007000`, `lib − main = 0x1c07000`, `zif_off = 0x46ad70`) — a
deterministic seed, not native coverage. Receipts:
`poc/verify_vardestroy_bruteforce.py`, `docs/X86_64_115560.md`, `docs/STATUS.md` §7.

## 7. The "not claimed" list

| Not claimed | Why (receipt) |
|---|---|
| **Default PHP config** | the default handler is `php`; 115560 needs `php_serialize`/`php_binary` configured *and* a runtime switch. None of the four matrix images overrides `serialize_handler` (`docs/LAB_MATRIX.md`; `docs/STATUS.md` §2.1) |
| **A default application** | Drupal needs one non-default `services.yml` line, Roundcube a plugin, Joomla an app sink, WordPress is gated off by core — all `CONFIG-GATED` or `LAB-ONLY`, none `STOCK` (`docs/PUBLICATION_SERIES/REAL_APPLICATIONS.md` §6) |
| **Native x86-64 generality** | Rosetta is not native coverage and the 28-bit seed is open (§6; `docs/STATUS.md` §7) |

A fourth: the constants are per request shape and per build (`0x6c019` direct,
`0x6d875` race, `0x7b019` Drupal), and a rebuild can drift by `+0x1e000..0x20000`.

## 8. Why the negatives belong in the record

| Negative | What it ruled out | Receipt |
|---|---|---|
| 4.1M-execution ASAN campaign | a generic in-band seed for those corpora | `fuzz/` |
| `__wakeup` / `__unserialize`, 8/8 combinations | every magic method except `__destruct` | `poc/verify_115560_wakeup.py` |
| WordPress core | a stock re-entry destructor reachable as shipped | `reports/gadgets/wordpress.md` |
| Roundcube + Redis | the stock driver reading the progress record | `ROUNDCUBE_REDIS_115560.md` |

Three effects repeat. A negative **moves the boundary**: the fuzz campaign did
not prove the seed impossible, it proved it is not free — which is why the arm64
scan and the external-leak front-ends exist. A negative **costs less than the
wrong assumption**: eight `__wakeup` runs against a positive control settled a
lock question that would otherwise have shipped as a broken payload. And a
negative **is auditable**: it names a tree, build, pattern set and command.

So every negative states its ceiling in the same paragraph as its result. "No
stock re-entry destructor in WordPress core" is true for that tree, those
patterns, that autoload model; "no in-band seed" is false. The gap between those
two sentences is the point of keeping the failures. Corrections are welcome as
repository issues; corrections that require exploit traffic against third-party
systems are not.
