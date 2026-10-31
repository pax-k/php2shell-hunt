# Research review — progress, external sweep, and the next weaponization target

**Date:** 2026-10-30
**Scope:** local labs only; benign command allowlist (`id | uname | whoami`); no remote target packaging.
**Purpose:** snapshot of what is proven, what the public record already contains, and which
direction gives the best chance of a *new or novel fully local weaponized RCE chain*.

> This file is a decision record, not a disclosure. Two items previously marked
> "EMBARGOED / new / unreported" are in fact publicly reported. Correct those headers
> before publishing anything from this repo.

---

## 1. Where the repo stands

Local branch is **73 commits ahead** of `origin/main`
(`github.com/ikow/php2shell-poc`). The public repo still carries only the initial release;
the work below is local-only.

### Proven (unchanged by the external sweep)

| Area | State | Evidence |
|---|---|---|
| **P0 / GOAL** | All 5 acceptance items checked: CVE-2026-109618 in-band `uid=33`, no `/proc`, patched 8.4.27 negative, holder-rotation fallback | `GOAL.md`, `poc/verify_109618_inband.py` |
| **109619 core chain** | Un-instrumented on mod_php, amd64 + native arm64, 150-worker prefork, 3/3 across ASLR generations | `poc/verify_109619_remote.py` |
| **Version matrix** | 8.4 series 6/6 (pos/neg/bias) | `poc/verify_matrix.py`, `lab-matrix/` |
| **8.2 / 8.3 / 8.5** | Still fail at **leak shape**, not offsets | `docs/STATUS.md` §5 P2 |
| **var_destroy patch-gap** | Terminal ladder on patched 8.4.27 / 8.5.12; 18-bit brute force; carrier inside `$_POST` (`main+0x72018`, 6/6); Joomla 5 stock gadget ASAN-confirmed; WP core negative | `poc/verify_vardestroy_*`, `docs/VAR_DESTROY_UAF.md`, `docs/JOOMLA_GADGET.md` |
| **mbstring SJIS-mac** | Controlled 1–2 byte heap WRITE past a 24-byte glibc allocation on stock 8.4.27 / 8.5.12 | held: mbstring working notes, pending vendor disclosure |
| **Fuzzing** | T1 clean negative: 4.1M ASAN execs / 1.24M inputs, 0 reports | `docs/STATUS.md` §5 P4 |
| **Detection** | 10 SIDs traffic-tested under Suricata | `detection/README.md` |

The open technical gap remains **the address seed on 28-bit ASLR hosts** (x86_64 default).
On the arm64 lab (`vm.mmap_rnd_bits=18`, 512 main slots) the var_destroy chain is already
self-contained.

---

## 2. External sweep — corrections to the record

### 2.1 `var_destroy` re-entry UAF is **not new**

Public since **2026-05-02**:

- `github.com/dinosn/php-8.5.5-var_destroy-uaf` (43★, 6 forks)
- Same root cause: `var_destroy()` frees the `var_entries` chain, then calls
  `i_zval_ptr_dtor(zv)` on the dtor list **without `BG(serialize_lock)`**
- Inner `unserialize('R:1500;')` from `__destruct` reuses the stale `var_hash`
- ASAN UAF at `var_unserializer.c:849`
- Ships `exploit_var_destroy_rce.php` → `uid=0(root)` on PHP 8.2.12, plus a leak primitive
  and two other trigger sites (L284, L309)

It is explicitly a sister bug to Calif.io's **MAD Bugs** finding
(`blog.calif.io/p/mad-bugs-finding-and-exploiting-a`, 2026-05-01). The author also notes
PHP's policy since **August 2017**: no CVEs for `unserialize()` memory-corruption bugs.

**Action:** rewrite the `docs/VAR_DESTROY_UAF.md` and
var_destroy disclosure draft (held). Do not claim a new bug or a new CVE.
Cite dinosn (2026-05-02) and Calif (2026-05-01).

**Our real delta (still publication-worthy):**

- survives the 2026-10-21 patch (8.4.27 / 8.5.12)
- no `/proc`: 18-bit ASLR brute force + `$_POST` carrier placement
- a **stock Joomla 5** re-entry gadget; WordPress DoS impact
- full terminal call (`zif_system`) on stock ZendMM

That is a **patch-gap exploitation paper**, not a new-bug disclosure.

### 2.2 mbstring SJIS-mac is **already publicly reported**

Public since **2026-06-19**:

- Khashayar Fereidani, *PHP 8.5.7 `mb_substr()` 'SJIS-mac' size_t underflow*
- `seclists.org/fulldisclosure/2026/Jun/12`
- Names the same guard:

```c
if (len == 0 || (from >= in_len && enc != &mbfl_encoding_sjis_mac))
```

- Same `mb_get_substr_slow` / `MIN(len, in_len - from)` underflow

Upstream status checked 2026-10-30: the guard is **still present** on `PHP-8.4`,
`PHP-8.5`, `PHP-8.6`, and `master`. The bug is **known and still unfixed** — not
"unreported" and not "embargoed".

**Our real delta:** a concrete **ASAN heap-buffer-overflow WRITE** (1–2 bytes,
attacker-chosen glyph) past a 24-byte glibc allocation, not just the OOM/DoS.
Reframe as a follow-up to a public report, not a new discovery.

### 2.3 CVE-2026-115560 is already publicly reproduced

Public, validated PoCs (all with labs and controls):

| Repo | What it proves |
|---|---|
| `github.com/googlesky/CVE-2026-115560` | `uid=33` on **php:8.4.27-apache**, 3.3 s; mitigation + no-switch controls |
| `github.com/basesixtythree/B63-POC-CVE-2026-115560` | both `php_binary` and `php_serialize`; race vs `cleanup=1` |
| `github.com/rafalohaki/php2shell-poc` (lab dir) | clean 8.5.12 lab, no memory corruption at all |

Root cause (write/read serializer mismatch):

1. upload hook writes the session file under the **configured** handler
   (`php_serialize` / `php_binary`), with the attacker's `PHP_SESSION_UPLOAD_PROGRESS`
   value as a raw array key;
2. app calls `ini_set('session.serialize_handler', 'php')` before `session_start()`;
3. the `php` decoder splits at the first `|` — inside the attacker key — and calls
   `php_var_unserialize()` on attacker bytes;
4. `PHP_VAR_UNSERIALIZE_DESTROY` runs on **success and failure**, so a gadget's
   `__destruct()` fires even when the overall decode fails.

This is the same family as our Chain C (`poc/verify_handler_mismatch.py`,
`poc/verify_rce_gadget.py`), with a runtime `ini_set()` instead of per-directory
`.user.ini`. `docs/STATUS.md` still lists it as open. It is unpatched on 8.4.27 / 8.5.12.

### 2.4 Our FPM ceiling is *our* ceiling, not the field's

`docs/STATUS.md` says the core chain is "mod_php-only; FPM in-band leak unsolved."
That is true **for this repo**, but not globally:

- **Trail of Bits** (Dan Guido, Oct 24–26) claims a **production-grade** exploit on stock
  `php.ini-production`, multi-worker, ASLR, ARM64 + x86-64, **Apache/mod_php *and*
  nginx/php-fpm**, shell on MediaWiki/WordPress/phpBB/Laravel → root (private, not released).
- **VulnCheck** had a weaponized 8.4/8.5 mod_php exploit by Oct 22 and identified a public
  ASLR-bypass PoC for 8.4.26.
- The Wiz/Calif writeup demonstrates **nginx + PHP-FPM**.

Keep the "not reproduced here" honesty; stop implying FPM is globally unsolved.

### 2.5 GH-22554 is about to be patched

The DOMXPath foreign-document UAF got upstream commits on **2026-10-22/23**
(`a44a529`, `d5d650d`), i.e. after 8.5.12. `docs/STATUS.md` says "fixed in 8.5.12" — that
looks wrong and should be verified. The XPath leak seed has a short shelf life.

### 2.6 Public wire fingerprint (honeypot ground truth)

`github.com/0x4D31/honeypot-data` — 35 confirmed Apache-parent shells, 4-stage chain:

| Stage | Shape | Decoded size |
|---|---|---|
| A1 | chunked multipart, ~973 parts, mostly `files*` | 1,060,211 B |
| B1 | chunked multipart, ~918 parts, 900 `x*` fields | 33,128,677 B |
| A2 | fixed multipart, ~997 parts, 880 `files*` | 279,369 B |
| B2 | fixed multipart, ~998 parts, 500 `s*` + 495 `t*` | 451,384 B |

Additional facts:

- decoded `PHPSESSID` is **819,200 bytes** (our docs say 819,208 — reconcile)
- dominant pointer repeated **1,095 times** (our docs say 87-pointer fingerprint)
- published body SHA-256s for A1/A2/B1 and 16 B2 variants
- header order `Host → Content-Type → Transfer-Encoding/Content-Length → Connection`,
  no `User-Agent`, 10-char boundary `CCCCCCCCCC`
- worker dies after `zif_system` → `/bin/sh` parented by Apache

Our Suricata pack matches `PHPSESSID`, `files[`, `filename=`, but **not** the 819,200-byte
cookie, the 33 MB B1 body, the body hashes, or the four-stage ordering.

---

## 3. New bugs / tips / PoCs worth tracking

| Item | Why it matters |
|---|---|
| **CVE-2026-115560** — session handler mismatch | Unpatched on 8.4.27 / 8.5.12; public PoCs exist; direct delivery vehicle for our var_destroy chain |
| **CVE-2026-91767** — OpenSSL wildcard-name underflow | `php_openssl_matches_wildcard_name()` underflows the `memchr()` length → up to `SIZE_MAX` OOB read; reachable from any default client stream (`verify_peer_name=on`). Potential leak via SSRF/malicious TLS server; no fixed RHEL version as of Sep 2026 |
| **CVE-2025-14181** — SOAP client signed-overflow heap overflow | Malicious SOAP server → undersized buffer → heap overflow; another client-side primitive |
| **CVE-2026-7261** — SoapServer `SOAP_PERSISTENCE_SESSION` UAF | Fixed 8.2.31/8.3.31/8.4.21/8.5.6 — historical, but relevant session-persistence pattern |
| **CVE-2026-6104** — mbstring NUL in encoding name | Global OOB read; fixed 8.4.21/8.5.6 |
| **CVE-2026-111497 "Brotli2Shell"** | PHP Windows Brotli decoder; out of Linux scope but shows expanding surface |
| **GH-22554 variations 2–5** | Five distinct UAF shapes (callback frees nodes, GC destructor, `replaceChild`) — reusable gadget/leak patterns |

### 9bie's current chain (reference, not vendored)

`github.com/9bie/php2shell-bypass-aslr-exp`:

- stock `php.ini-production`, `display_errors=Off`, 128M, **150 workers: 10/10** x86-64,
  **10/10 native aarch64**
- A2 uses `PS(hash_serialize_verifier)` → `main+0x7D720`; fake array `S` at
  `main+0xF8398`; `pDestructor = zif_system`
- offsets: `zval_ptr_dtor` `libphp+0x65EB60` (x86-64) / `+0x63812B` (aarch64);
  `zif_system` `+0x465370` / `+0x42CD70`
- 900-field leak spray produces the ~1,095 `zval_ptr_dtor` hits

Worth diffing the `hsv`/fake-array A2 trick and the leak spray against
`php2shell/remote.py`, especially for the 8.2/8.3/8.5 leak-shape blocker.

---

## 4. Recommendation: the next fully local weaponized chain

### 4.1 Target

**CVE-2026-115560 → var_destroy UAF → `zif_system`**

A pre-auth, fully local RCE on **PHP 8.4.27 / 8.5.12** — builds fully patched for
109618/109619 — with no `/proc`, no debugger, and **no application `unserialize()` sink**.

### 4.2 Why it composes

The two bugs fill each other's biggest gap:

- 115560 gives a pre-auth `unserialize()` of attacker bytes inside `session_start()`
- var_destroy needs exactly an `unserialize()` of a 1018-element payload with a
  duplicate-key object whose `__destruct()` re-enters `unserialize()`

Session value:

```
upload_progress_|a:1018:{ ... i:99999;O:...; i:99999;i:42; }
```

The `php` decoder parses it during `session_start()`; `var_destroy()` frees the extension
chunks; the dtor object fires; the nested `unserialize('R:...')` walks the freed chain;
the forged carrier reaches `zif_system`. Trailing session-wrapper junk can force decode
failure *after* the dtor list is populated — the public 115560 PoC confirms
`__destruct` still runs on failure.

### 4.3 Why it composes — novelty retraction (2026-10-31)

Public 115560 PoCs include simple-gadget RCE. Public var_destroy work initially
needed a direct app `unserialize()` sink, but the claim that **nobody had
published the composition was wrong** and is retracted. `ACD421/PHP` published
the full composition in `weapons/lab/fa_jammy.sh` (2026-10-26) and the
`cleanup=On` slow-upload race in `zero1` (2026-10-21), including the
`dtor_obj = zif_system` terminal. See
`docs/NOVELTY_115560_2026-10-31.md` for the source-checked matrix.

What remains defensible is narrower: a pre-auth end-to-end result on **patched
8.4.27 / 8.5.12**, with the **default `cleanup=On` race combined with the
var_destroy terminal**, on **arm64 with no `/proc` at fire time**, plus the
measured raw-session carrier and per-build constants. That is an
engineering/port result on a public composition, not a new primitive or CVE.

### 4.4 Scorecard

| Path | New bug? | Novel chain? | Fully local? | Effort | Risk |
|---|---|---|---|---|---|
| **115560 → var_destroy → zif_system** | No | No — composition public (`ACD421`); narrow patched-build/arm64 port result | Yes (arm64; x86-64 needs a seed) | 1–3 days | Low/medium |
| 115560 alone | No | No (public PoCs) | Yes | Hours | Low |
| mbstring off-by-one → glibc → RCE | **Yes** | Yes | Yes | 2–4 weeks | High |
| GH-22554 leak + var_destroy | No (public, being patched) | Somewhat | Yes on 8.4.27 | Done | Low |
| 109619 / 109618 core | No | No | Already done | — | — |
| CVE-2026-91767 leak | No | Maybe | Needs outbound TLS | Unknown | High |

### 4.5 Build plan

1. **Lab** (`lab-115560/`): app does
   `ini_set('session.serialize_handler','php'); session_start();`
   with `php_serialize` + `upload_progress=On`, `cleanup=Off` (or the race from the
   public PoC). Reuse `lab-patched` 8.4.27 / 8.5.12 images.
2. **Producer:** upload `PHP_SESSION_UPLOAD_PROGRESS` = `|` + the `a:1018:{...}`
   var_destroy payload. Confirm the session file content and that `T::__destruct` is reached.
3. **Terminal gadget:** replace `T` with the `CachePurge` pattern from
   `poc/verify_vardestroy_postcarrier.py` — destructor calls `unserialize()` with the
   forged `R:` payload and the carrier as its `key` property.
4. **Carrier placement:** measure the session-value delta instead of the `$_POST['p']`
   delta (`DOFF` changes), or use the existing 18-bit brute force. On this arm64 host,
   no leak is needed.
5. **Controls:** `upload_progress=0`, `--no-switch`, `--bias-zif 0x1000`. There is no fixed
   115560 build yet, so the mitigation control is the negative.
6. **Acceptance:** `uid=33` on 8.4.27 **and** 8.5.12; all controls block; no `/proc`,
   no gdb, no app `unserialize()`.

**Result (2026-10-31):** built as `lab-115560/` + `poc/verify_115560_vardestroy.py`.
`uid=33` on both patched builds; all three controls block. The final shape differs
from the sketch above: the payload goes in the **progress field value** (not the
filename — nulls truncate the filename), the carrier is the **raw session input
buffer**, and 8.4.27 needs a **second session record** (`/prime.php`), the
**1-page spray (3048)**, and skipping the dry mid-parse dtor. 8.5.12 uses 8135.
8.5.12's no-`/proc` 576-slot window scan found the proof at attempt 351; 8.4.27's
full window found it at attempt 307 (both no `/proc`). Details:
`lab-115560/README.md`, `PROGRESS.md` iterations 47/50.

**Scope (2026-10-31):** this is **not a default-PHP RCE**. Default
`session.serialize_handler` is `php`; the chain needs `php_serialize` (or
`php_binary`) plus a runtime switch to `php` plus a re-entry **`__destruct`**
(`__wakeup`/`__unserialize` are locked/negative). The direct lab profile uses
`cleanup=Off`; the default `cleanup=On` race is proven separately (multi-child +
`seed.php`), and 8-child/pinning + amd64/Rosetta are verified. Public 115560 PoCs
already give patched-build RCE with a **simple** `__destruct`; public
var_destroy UAF and `/proc/self/mem` → `zif_system` RCE also exist, and
`ACD421/PHP` published the full composition. Our defensible delta is the
**patched-build 8.4.27/8.5.12 pre-auth end-to-end, the `cleanup=On` race
combined with the var_destroy terminal, the no-`/proc` arm64 final, and the
measured carrier/constants** — an engineering/port result, not a new
composition. Best bets, gadget survey, and decision gates:
`docs/PLAN_115560.md`, `docs/GADGET_SURVEY_115560.md`,
`docs/RACE_WAKEUP_115560.md`, `docs/NOVELTY_115560_2026-10-31.md`.

### 4.6 Honest limit

On a 28-bit x86_64 host the 512-slot brute force becomes ~2^19 and infeasible, so
"fully local" is arm64 unless a leak is added. This is the same structural ceiling
already documented in `docs/STATUS.md` §7, not a new result.

---

## 5. Alternative if a *new bug* is required: mbstring

The SJIS-mac bug is the only primitive we hold that is not publicly exploited. Public
report (June 2026) claimed OOM/DoS and a hypothetical overflow; we have a confirmed
1–2 byte heap WRITE with attacker-chosen bytes.

Exploitation hypothesis:

- 24-byte user area → the write lands on the **next chunk's size field**
- variant (a): null-byte / off-by-one size corruption
- variant (b): choose 1–2 bytes of the size field
- goal: overlapping chunk → corrupt an adjacent `zend_string` length or libmbfl buffer
  → PHP-visible OOB read → feed the leaked pointer into the var_destroy terminal ladder

Main risk: `mb_convert_buf` is **glibc `malloc`**, while almost all PHP objects are
**ZendMM**. An overlap gives glibc heap objects, not directly a `zend_string` or
`zend_object`. A second step (tcache poisoning, a glibc-allocated struct with a function
pointer) is required before reaching PHP land.

**Go/no-go gates:**

1. Prove the overflow reliably hits the next chunk header under controlled grooming.
2. Turn it into a **PHP-visible** OOB read (not just a crash).
3. If gate 2 fails in ~1 week, stop — it is a hardening/DoS writeup, not an RCE.

---

## 6. Do not spend time on

- **115560 alone** — public, validated PoCs already exist. Reproduce only as a stepping stone.
- **GH-22554 + var_destroy** — already done; seed is being patched (Oct 22–23 commits).
- **CVE-2026-91767** — interesting OOB read, but no clean userland channel; background lead.

---

## 7. Action checklist

- [ ] Scaffold `lab-115560/` (8.4.27 + 8.5.12, runtime handler switch, `cleanup=Off`)
- [ ] `poc/verify_115560_vardestroy.py` — producer + consumer + terminal call
- [ ] Minimal proof first: session decoder reaches `T::__destruct`
- [ ] Terminal gadget (`CachePurge` pattern) embedded in the session value
- [ ] Calibrate session-value carrier delta, or use the 18-bit brute force
- [ ] Controls: `upload_progress=0`, `--no-switch`, `--bias-zif 0x1000`
- [ ] Record `uid=33` on 8.4.27 and 8.5.12; update `docs/STATUS.md`
- [ ] Rewrite var_destroy / mbstring headers to cite public prior work
- [ ] Fix the GH-22554 "fixed in 8.5.12" note
- [ ] Upgrade detection: 819,200-byte cookie, 33.1 MB B1, four-stage ordering, body hashes
- [ ] Reconcile 819,208 vs 819,200 and 87 vs 1,095 in the docs

---

## 8. References

**Progress / prior work**
- `docs/STATUS.md`, `docs/VAR_DESTROY_UAF.md`, and the held mbstring notes
- `docs/JOOMLA_GADGET.md`, `docs/CVSS.md`, `PROGRESS.md`
- `poc/verify_var_destroy_uaf.php`, `poc/verify_vardestroy_postcarrier.py`
- `poc/verify_handler_mismatch.py`, `poc/verify_rce_gadget.py`

**External**
- dinosn, *PHP 8.5.5 var_destroy `__destruct` reentrancy UAF* (2026-05-02): https://github.com/dinosn/php-8.5.5-var_destroy-uaf
- Calif.io, *MAD Bugs* (2026-05-01): https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a
- Fereidani, *PHP 8.5.7 mb_substr SJIS-mac size_t underflow* (2026-06-19): https://seclists.org/fulldisclosure/2026/Jun/12
- PHP informational advisory, CVE-2026-115560 (2026-10-23): https://www.php.net/archive/2026.php
- ACD421/PHP, four-stage composition + `cleanup=On` race (2026-10-21/26): https://github.com/ACD421/PHP
- googlesky/CVE-2026-115560: https://github.com/googlesky/CVE-2026-115560
- basesixtythree/B63-POC-CVE-2026-115560: https://github.com/basesixtythree/B63-POC-CVE-2026-115560
- rafalohaki/php2shell-poc 115560 lab: https://github.com/rafalohaki/php2shell-poc
- 9bie/php2shell-bypass-aslr-exp: https://github.com/9bie/php2shell-bypass-aslr-exp
- 0x4D31 honeypot confirmed-RCE report: https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md
- Trail of Bits demo thread: https://x.com/trailofbits/status/2114839775173906751
- VulnCheck php2shell analysis: https://www.vulncheck.com/blog/php2shell-vulnerabilities
- php-src GH-22554: https://github.com/php/php-src/issues/22554
- CVE-2026-91767: https://access.redhat.com/security/cve/CVE-2026-91767
- CVE-2025-14181 (SOAP client): https://github.com/php/php-src/security/advisories/GHSA-cj93-vc83-wgqv
