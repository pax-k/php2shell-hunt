# Next tracks — application chains after the 115560 real-app work

**Date:** 2026-10-31  
**Scope:** LAB-ONLY, `127.0.0.1` only, fixed benign command
`id>/tmp/vd 2>&1`. This is a planning/ranking document; it does not add a new
exploit or authorize any external send.

**Question:** after the Drupal and Roundcube 115560 profiles, what is the best
next attack surface, strategy, or vulnerable application to pursue?

**Sources:** `docs/APP_SURVEY.md`, `docs/GADGET_SURVEY_115560.md`,
`docs/JOOMLA_GADGET.md`, `docs/CVSS.md`, `docs/STATUS.md` §7,
`docs/PLAN_115560.md`, `docs/PHASE1_2_115560_RESULTS.md`,
the internal CVSS planning note (not shipped).

---

## 1. Position

Current defensible score for the composed `115560 → var_destroy →
zif_system` chain is **8.1** (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`).
There is **no 9.8** yet. The 9.8 scenario needs both:

1. a **default, guest-reachable** `unserialize()`/`Phar::getMetadata()` sink; and
2. a **stock, commonly loaded** terminal-capable re-entry destructor.

The PHP core RCEs (`CVE-2026-109618/109619`) carry the official **9.2**
(CVSS v4.0) score; that is the advisory's number, not our composition's score.

The practical bottleneck is therefore **application reachability**, not another
PHP-core primitive.

---

## 2. Ranking rule

- **Impact** = realistic CVSS/reach, not theoretical maximum.
- **Effort** = S (<1 day), M (1–3 days), L (1–2 weeks), XL (>2 weeks).
- **Confidence** = whether the required sink/gadget has already been observed,
  not whether the idea is interesting.

Rows are ordered by impact/effort ratio and by whether they can remove `AC:H`.

---

## 3. Ranked tracks

| Rank | Track / attack surface | Impact | Effort | Confidence | First discriminating test |
|---:|---|---|---|---|---|
| 1 | **Roundcube Redis same-store** — server `session.save_handler=redis`, Roundcube `session_storage='redis'`, `php_serialize` writer | **8.1–9.8 potential**; removes the plugin-supplied handler switch | **S/M** | Medium | **Tested negative (2026-10-31):** keys align with `?prefix=`, stock switch runs, but `rcube_session_redis::read()` expects its own `vars` wrapper, so the progress record is never decoded. See `docs/ROUNDCUBE_REDIS_115560.md` |
| 2 | **WordPress LearnPress guest sink + plugin gadget** — guest self-registration writes serialized user meta; need a same-request re-entry destructor | **9.8 potential** on the plugin/profile | **M** | Medium-low | Graph 50–100 popular plugins for `__destruct → unserialize` plus an ~8160-byte spray; test `/register/` + `/profile/settings/` |
| 3 | **PrestaShop CVE-2026-54159 alternate re-entry** — confirmed guest sink and length-mismatch primitive; `FnStream` route is blocked by `__wakeup` | **9.8 potential**; pre-auth | **M/L** | Low-medium | Graph PrestaShop + vendor for a dtor that calls `unserialize($prop)` and is not wakeup-suppressed |
| 4 | **Split-gadget graph across frameworks** — one stock spray class + one stock re-entry class in Symfony/Laravel/CakePHP/Joomla/WordPress | **9.8 potential**; removes the custom gadget | **L** | Low | Run `gadget_graph.py` on vendor trees; rank `__destruct` + `unserialize` + same-size allocation paths |
| 5 | **Drupal contrib guest sink + P5** — core P5 gadget is terminal; the 42-project contrib sweep was negative | **8.1–8.8**; still needs `serialize_handler: php` | **L** | Low-medium | Target modules with serialized fields, guest submissions, or `hook_views_data_alter`; test write-then-read |
| 6 | **Joomla 5 component/plugin sink + R-capable dtor** — stock autoloader gives UAF/DoS, but `Registry::__clone` cannot emit `R:` | **8.1–9.8** if a terminal dtor exists | **M/L** | Low | Graph Joomla extensions for dtor → `unserialize` on a raw property; discard `serialize()`-based re-entry |
| 7 | **PHP 109618 FPM in-band leak** — official 9.2; current FPM path is instrumented/boundary-only | **9.2 official**; broad nginx/FPM surface | **XL** | Low-medium | Port the rung-5b producer/consumer to multi-worker FPM; calibrate the leak shape |
| 8 | **x86_64 leak fusion** — arm64 no-`/proc` works; x86_64 needs one address from LFI/SSRF/XXE | Portability; **8.1 stays 8.1** | **M/L** | High mechanism | Find a real app LFI/SSRF/XXE route; fuse with the var_destroy sink |
| 9 | **Phar metadata on default upload** — upload a phar, trigger `Phar::getMetadata()`/file operation | **8.1–9.8** depending on route | **M/L** | Low-medium | Scan apps for `getMetadata()` plus guest upload; build a phar with a re-entry gadget |
| 10 | **CakePHP `cake`/`database` session profile** — presets switch to `php`, but the custom store likely never reads the progress file | **8.1 at best** | **S** | Low | Inspect the store path; one request to see whether upload progress is read at all |
| 11 | **TYPO3 HMAC-gated sink** — Extbase/Form guest sinks exist, gated by `SYS.encryptionKey` | **8.1–9.8** if the key leaks | **L/XL** | Low | Search for a key leak/debug/backup exposure; no key, no chain |
| 12 | **Craft / Concrete / MediaWiki / SilverStripe / Magento / Sylius** — survey tail; all gated or allowlisted | Low–medium | **L** | Low | Do not prioritize; no default guest sink + terminal gadget |
| 13 | **Scope change S:C** — cross-tenant, shared hosting, container escape | **10.0 only** | **XL** | Very low | Separate vulnerability class; likely out of scope |
| 14 | **New PHP core bug fuzzing** — fresh UAF/OOM in session/unserialize | Unknown, potentially 9.8+ | **XL** | Very low | Long-horizon; not a next-step bet |
| 15 | **Detection / defense / publication** | High defensive value; **no CVSS gain** | **S/M** | High | Rules, mitigations, disclosure package |

---

## 4. Top tracks in detail

### 4.1 Roundcube Redis same-store — cheapest high-value test

**Why:** Phase 2 found that stock Roundcube only runs
`ini_set('session.serialize_handler','php')` in its db/redis/memcache session
drivers, and those read their own store. The plugin supplied the switch for the
file profile. If the server save handler is Redis and Roundcube’s redis driver
reads the same key namespace, the upload-progress record may be decoded with
**no plugin switch**.

**Unknown:** whether PHP’s redis session prefix and Roundcube’s redis prefix
match. This is the whole experiment.
**Impact:** removes a precondition; still needs a re-entry gadget.
**First test:** start Redis, configure server `save_handler=redis` +
`php_serialize`, set Roundcube `session_storage='redis'`, upload to
`/prime.php`, inspect Redis for `upload_progress_` bytes, then run the existing
`simple`/`run` modes.
**Kill criterion:** different key namespaces, or the progress record is not
written through the Redis save handler.

**Result (2026-10-31) — tested, negative: `docs/ROUNDCUBE_REDIS_115560.md`.**
The hook *does* write the `php_serialize` record through the Redis handler, and
stock `rcube_session_redis` *does* perform the `php` switch (proven with the
plugin switch disabled). The default keyspaces differ
(`PHPREDIS_SESSION:<sid>` vs `<sid>`) but can be aligned with
`session.save_path="tcp://redis:6379?prefix="` (phpredis 6.3.0). Even aligned,
the real flow does not decode: `rcube_session_redis::read()` does
`unserialize($value)` and expects its own `a:3:{changed,ip,vars}` wrapper,
while the hook writes `a:1:{...}` with no `vars`. Only "raw key + rcube
wrapper" fires; the hook cannot write that envelope. The plugin is still needed,
as a store adapter (`session_storage='redis'`) or as the switch
(`session_storage='php'` + Redis store, verified `uid=33`). Track closed for
stock config; do not re-open without a new store/adapter primitive.

### 4.2 WordPress LearnPress guest sink + plugin gadget

**Why:** LearnPress 4.4.13 has a **guest** object-injection sink:
`_lp_custom_register_form` → user meta → `maybe_unserialize`
(`inc/user/lp-user-functions.php:1435/1447`), with self-registration enabled.
The 22-plugin audit found no qualifying destructor, but that is a bounded
sample.

**Need:** a plugin class loaded on `/register/` or `/profile/settings/` whose
`__destruct` calls `unserialize()` on a raw string property and can allocate or
precede an ~8160-byte spray.

**Impact:** pre-auth application RCE if the pairing exists; potentially 9.8 on
that plugin profile.
**First test:** graph the plugin ecosystem for `__destruct → unserialize` and
for same-size string allocations; verify autoload on the registration request.
**Fallback:** report the LearnPress guest object-injection sink on its own even
without RCE.

### 4.3 PrestaShop CVE-2026-54159 alternate re-entry

**Why:** PrestaShop 8.2.1 + bundled `ps_facetedsearch` 4.0.0 has a confirmed
guest sink (`?q=Price-...` → `unserialize(current($row))`) and a confirmed
length-mismatch primitive (`pSQL`/`strip_tags` shrinks a serialized value after
its length prefix).

**Blocker:** the earlier `GuzzleHttp\Psr7\FnStream::__destruct` →
`SerializedParsedExpression::getNodes` route is blocked by
`FnStream::__wakeup()` throwing on psr7 ≥ 1.9.0. Treat PrestaShop as a
**sink + alternate-gadget hunt**, not a ready terminal.

**Impact:** pre-auth, high; **9.8 potential** if another dtor re-enters
`unserialize` and the spray/carrier can be ordered.
**First test:** graph PrestaShop + vendor for `__destruct` bodies that call
`unserialize($this->prop)`, excluding wakeup-suppressed FnStream paths.

### 4.4 Split-gadget graph across frameworks

**Why:** the terminal ladder needs a spray and a re-entry. Drupal P5 builds
both inside one destructor chain; other apps may split them across two stock
classes in the delayed-dtor list.

**Search:** `__destruct` bodies that allocate ~8160-byte strings, and
`__destruct` bodies that call `unserialize($this->prop)`, in
Symfony/Laravel/CakePHP/Joomla/WordPress vendor trees.
**Impact:** **9.8 potential** without a custom class.
**Effort:** L; high uncertainty, but the graph tooling already exists.
**Kill criterion:** no stock pair with both autoload and an attacker-controlled
order.

### 4.5 Drupal contrib guest sink + P5

**Why:** the Drupal 11 P5 gadget is the best stock re-entry gadget and is
already terminal through 115560. The missing piece is a **guest-writable
serialized column** or a guest route that calls `unserialize()`.

**Status:** 42 contrib projects were audited with no stock default guest sink;
core sinks are server-generated, admin/CLI, or `allowed_classes`-restricted.
A `hook_views_data_alter` module works only as custom code.
**Impact:** 8.1–8.8; still needs the non-default
`session.storage.options.serialize_handler: php`.
**First test:** broaden the contrib sink hunt to popular field/views modules and
test a write-then-read path on a real install.

---

## 5. Lower-priority / do not chase yet

- **Joomla 5 stock gadget:** UAF/DoS only; `Registry::__clone` cannot emit
  `R:1020;` or place a raw pointer. A terminal needs a different dtor.
- **CakePHP `cake`/`database`:** quick negative; the custom store is unlikely to
  read the upload-progress file.
- **TYPO3:** strong sinks but HMAC-gated; needs a key leak first.
- **Craft / Concrete / MediaWiki / SilverStripe / Magento / Sylius:** gated,
  allowlisted, or no guest write; low ROI.
- **S:C / 10.0:** separate vulnerability class; do not fold a container escape
  or shared-host boundary into the PHP score.
- **New core fuzzing:** only if the app tracks are exhausted.

---

## 6. Recommended sequence

1. **Roundcube Redis** (days) and **LearnPress plugin graph** in parallel.
2. **PrestaShop alternate gadget** and **split-gadget graph**.
3. **Drupal contrib sink** only if the first three fail.
4. **FPM 109618** as a separate long track.
5. **No S:C or new-core-bug fuzzing** until an app track is exhausted.

**Decision gate for 9.8:** a default guest-reachable sink plus a stock,
autoloaded terminal gadget. Until both are demonstrated, the responsible score
remains **8.1**, and Drupal/Roundcube stay **config-gated / plugin-gated**.
