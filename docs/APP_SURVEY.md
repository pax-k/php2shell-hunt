# Application / plugin advisory survey

Companion to the CVSS plan (internal planning note, not shipped).
Purpose: find a **guest-reachable deserialization sink** and a **terminal-capable
re-entry gadget** in a real app, to move from the PHP-core 8.1 to an
application advisory.

## Criterion

For the `var_destroy` UAF (`docs/VAR_DESTROY_UAF.md`, `docs/SPLIT_GADGET.md`):

1. **sink** — attacker bytes reach `unserialize()`/`maybe_unserialize()`/
   `Phar::getMetadata()` on a default, guest (or self-registerable) route;
2. **re-entry** — a destructor (or a zero-arg callable invoked by a stock
   destructor such as Guzzle `FnStream::__destruct`) re-enters `unserialize()`
   on a string property, **without** `allowed_classes => false`;
3. **spray** — an ~8192-byte allocation before the re-entry (order is
   attacker-controlled via duplicate-key overwrite order).

Sink alone = object injection / possible DoS; sink + re-entry + spray =
application RCE.

## WordPress (P1, 2026-10-31)

22 priority plugins downloaded from `downloads.wordpress.org` and audited.

| Plugin | Sink | Auth | `allowed_classes` | Re-entry gadget | Verdict |
|---|---|---|---|---|---|
| **LearnPress 4.4.13** | `_lp_custom_register_form` → user meta → WP core `maybe_unserialize` (`inc/user/lp-user-functions.php:1435/1447`) | **guest** (self-registration; `users_can_register=1`) | none | no | **guest sink** |
| WPML 2.0.4.1 | `unserialize(base64_decode($_GET['data']))` (`menu/troubleshooting.php:504`) | admin, **no nonce** (CSRF-able) | none | no | admin/CSRF sink |
| UpdraftPlus 1.26.14 | no guest sink | — | — | `FnStream::__destruct → Migrator_Lite::restored_plugins → native unserialize` | **conditional terminal** (FnStream not autoloaded on default pages) |
| WooCommerce 11.3.0-beta | legacy CPT order meta `maybe_unserialize` | guest checkout (HPOS caveat) | none | no | weak/legacy |
| Duplicator 5.1.0 | JSON only | — | — | `FnStream` autoloaded, no native-unserialize callable | half-gadget |

LearnPress request shape (full detail in the P1 report):

```
GET  /register/                      -> scrape learn-press-register-nonce
POST /<any>/                          learn-press-register-nonce=...&reg_email=...&
                                      _lp_custom_register_form=<urlencoded serialized payload>
GET  /profile/settings/              -> maybe_unserialize on the stored meta
```

Negatives: no `__destruct` body in any of the 22 plugins (including vendor)
contains `unserialize`; no guest sink + gadget in one plugin. The closest
two-plugin pairing is **LearnPress (guest sink) + UpdraftPlus (gadget)**, but
the UpdraftPlus gadget is not autoloaded on a default request.

### Drupal core sink sweep (D2, 2026-10-31) — no stock guest sink

- **dblog** is the only core `serialized` views-handler binding
  (`DblogViewsHooks.php:100` → `watchdog.variables`); the default view uses
  `dblog_message` (not the raw handler) and `admin/reports/dblog` needs
  `access site reports`. `watchdog.variables` is written by `serialize()`
  (`DbLog.php:71`), so a guest-triggered log entry cannot inject raw bytes.
- `MapItem::setValue()` unserializes with `allowed_classes=>FALSE`; no core
  `map` fields exist. JSON:API rejects strings for serialized columns
  (`SerializedColumnNormalizerTrait`). `LinkItem` options and
  `LayoutSectionItem` are array-only / forbidden for JSON:API. `string_long`
  has no core unserialize-on-read path.
- Core sinks (`SqlContentEntityStorage:2235`, `MenuTreeStorage:658`,
  `RouteProvider:428/457`, `DatabaseQueue:150`, `BatchStorage:67`,
  `Container:166`, `PhpSerialize:decode`) all read server-generated columns or
  are admin/CLI. Batch load requires the CSRF token; autocomplete uses HMAC.
- **`Container::reset()` zero-arg `unserialize()`** exists only in 11.x-dev HEAD
  (`Container.php:206`), not in released 11.0.13–11.4.11; no core destructor
  calls `reset()`/`get()` on a container. No second core gadget.
- **Version matrix:** the `YamlCacheCollectorDiscovery` dtor (issue #3486503)
  first shipped in **11.4.0-rc1**; P5 is present in 11.4.0/11.4.11/11.x-dev,
  absent in 11.0.13–11.3.20 and 10.4.0–10.4.11 (the sink exists but no dtor
  reaches it). Payload 31281 bytes; ASAN UAF `var_unserializer.c:906`; stock
  8.4.27 `rc=139` with `x0=0x4141414141414141`.
- **Bottom line:** no stock guest sink in core 11.4/10.4. A stock advisory needs
  a contrib module writing raw serialized bytes into a serialized column or a
  custom `hook_views_data_alter` binding to a guest-writable field.

### Drupal contrib sink sweep (D1, 2026-10-31) — negative for stock guest sinks

42 contrib projects audited. **No stock, default-config, guest-writable
`unserialize()` sink.** Unrestricted sinks are server-generated, admin/cron, or
`allowed_classes`-restricted. The core gadget is terminal at every unrestricted
sink (ASAN `var_unserializer.c:906`).

| Sink | Why not guest |
|---|---|
| **webform_encrypt 8.x-1.x** (D8/D9 only, not D11) | guest webform POST + missing encryption profile -> raw serialized value stored -> `decrypt()` unserializes; **fixed in 2.0.x** (`allowed_classes=>FALSE`) |
| Paragraphs `getAllBehaviorSettings` | auth; `behavior_settings` array-only; JSON:API rejects raw strings |
| Core `SqlContentEntityStorage::handleNullableFieldUnserialize` (`:2235`) | **latent core sink**; stock save serializes (`:1113-1114`), no raw write |
| Redirect / Search API / Feeds / Simplenews / Devel / Flag | admin/cron/migration |
| Webform log / Metatag / Address / Field Group / Pathauto / IEF | allowlisted (`FALSE` or specific classes) |
| `serialized_field` 2.0.x | field type only; core does not unserialize the column |

Lab HTTP chain (not stock): core Views `serialized` handler over a
guest-writable `string_long` needs a `hook_views_data_alter`; anonymous
JSON:API create + guest view fires the marker (P6).

### Drupal 11 pure-core **terminal** gadget (P5, 2026-10-31)

The complete terminal primitive is **stock Drupal 11 core**, with the 8160-byte
spray built into the same destructor chain (no Guzzle, no lab class):

```text
YamlCacheCollectorDiscovery::__destruct()          Discovery/YamlCacheCollectorDiscovery.php:64
 -> MenuActiveTrail::destruct()                     Menu/MenuActiveTrail.php:81
 -> CacheCollector::updateCache()                   Cache/CacheCollector.php:234
      $lock_name = $cid . ':' . __CLASS__  (:251)   -> 8135 B string -> 8160 alloc
 -> MemoryBackend::get() -> prepareItem()           Cache/MemoryBackend.php:89
      $prepared->data = unserialize($prepared->data)  (:99)   <-- re-entry
```

- `cid` is attacker-controlled (private prop), length 8102 -> lock name 8135 ->
  `zend_string_alloc` **8160 B = sizeof(var_entries)**; the freed block is
  reclaimed and `data[1]` reads the first 8 bytes of the cid string.
- `unserialize()` has **no `allowed_classes => false`**; the result is dropped
  (`expire=0` -> `prepareItem()` returns false) — the “discard” shape.
- ASAN UAF at `var_unserializer.c:906` on 8.4.27/8.5.12; stock ZendMM
  `x0=0x41414141...` (gdb), rc 139.
- Control: cid length 100 -> no crash (spray size is causal); the UAF itself is
  independent of the spray.
- **Only missing piece: the forged-carrier address** — already solved by the
  post-carrier input technique / 512-slot brute force.

**Reproduction recipe (no Drupal install needed to build the serialized graph):**

- `cid` = a string of **8102 bytes** (private `\0*\0cid` on `MenuActiveTrail`);
  `CacheCollector::updateCache()` builds `$cid . ':' . __CLASS__` = 8135 B ->
  `zend_string_alloc` requests **8160 = 16 + 8*1018** (`sizeof(var_entries)`).
- Outer payload: `a:1018:{` + 1016 x `i:0;N;` + `i:99999;<YamlCacheCollectorDiscovery>
  i:99999;i:42;}` (duplicate key puts the object in the delayed-dtor list).
- Object graph: `YamlCacheCollectorDiscovery{\0*\0yamlCacheCollector ->
  MenuActiveTrail{cid, cache -> MemoryBackend{cache: {<cid> => stdClass{
  data: "<nested inner payload>", expire: 0, valid: true, created: ...}}},
  lock -> NullLockBackend, keysToPersist, storage, cacheLoaded, loadedData,
  cacheInvalidated}}`.
- `MemoryBackend::prepareItem()` does `$prepared->data = unserialize($prepared->data)`
  (no `allowed_classes`); `expire=0` makes it return FALSE and drop the value —
  the discard shape.
- Control: `cid` length 100 -> no crash (spray size causal); the UAF itself is
  independent of the spray.
- ASAN: `php-fuzz-full-8427:local php run_drupal_stock.php` -> `heap-use-after-free`
  at `var_unserializer.c:906`; stock gdb `x0=0x41414141...`, rc 139.

**FnStream correction:** the “FnStream `__destruct` + any zero-arg
`unserialize` method” idea does **not** work on 8.4.27: `FnStream::__wakeup()`
throws during the deferred wakeup, sets `IS_OBJ_DESTRUCTOR_CALLED`, and
suppresses the later `__destruct`. The Drupal chain avoids callable invokers
entirely. (P3's PrestaShop FnStream re-entry must be re-checked under the same
conditions — P7 is doing that.)

### Drupal contrib sink hunt (P6, 2026-10-31)

**No stock guest-writable `unserialize()` sink** in Drupal 11 core or the
audited contrib set. Unrestricted sinks are server-generated, admin-gated, or
allowlisted:

| Sink | Why not guest-writable |
|---|---|
| Core Views `Serialized` handler (`.../views/field/Serialized.php:73`) | needs a `views_data` binding (`hook_views_data_alter`) to a guest-writable `string_long` field — **no stock module does this** |
| Paragraphs `Paragraph::getAllBehaviorSettings` | writers pass arrays; `preSave` re-serializes |
| Redirect `RedirectSourceItem::setValue` | admin; `setSource(array)` |
| Search API `Task::getData` | admin/cron, server-serialized |
| Simplenews `SpoolList::nextMail` | cron |
| Feeds `ImportLog` | `feeds_log.access`, server-serialized |
| Webform submission values | raw in DB but **never unserialized** |
| Commerce cart/order `data` | `map` type; save serializes arrays; JSON:API rejects strings |

**Demonstrated (lab, not stock):** Drupal 11.4.11 + a proof module with one
`hook_views_data_alter` binding the core `serialized` handler to a
`string_long` field, anonymous JSON:API create, then anonymous view render.
The nested `unserialize` fires the core gadget and the marker `__wakeup`.
The same 6815-byte payload reproduces the ASAN UAF
(`var_unserializer.c:906`) in a harness loading the real Views handler.
So Drupal's core gadget is terminal **when a sink exists**, but a stock
advisory needs custom config/code.

## PrestaShop (P3, 2026-10-31) — sink + gadget in one app

| Piece | Detail |
|---|---|
| **Guest sink** | PrestaShop 8.2.1 + bundled `ps_facetedsearch` 4.0.0 (module 3.0.0–4.0.3): `modules/ps_facetedsearch/src/Filters/Block.php:190` `unserialize(current($row))`, write `:211` `pSQL(serialize($data))`. Route: `GET /<lang>/<category>?q=Price-$-<from>-<to>` (also Weight), via `SearchProvider.php:210/217`. **No auth**; cache enabled by default. This is the known **CVE-2026-54159**. |
| **Length-mismatch primitive** | A plain `?q=Price-O:...` is stored as an inert `s:<len>:"O:…"`. The real primitive: `pSQL()` → `Db::escape()` runs `strip_tags(Tools::nl2br(...))` **after** `serialize()` set the length prefixes (`classes/db/Db.php:773-783`). Put a tag-heavy value in `from`, land `";i:2;O:…` at the overstated offset (52-byte shrink reproduced; `Probe::__wakeup()` fires). |
| **Re-entry gadget** | `GuzzleHttp\Psr7\FnStream::__destruct` → `call_user_func($this->_fn_close)` → `Symfony\Component\ExpressionLanguage\SerializedParsedExpression::getNodes()` → `unserialize($this->nodes)` on a string property, **no allowlist**; `R:` accepted. Runtime-verified (PHP 8.5): inner object instantiated through the destructor. |
| **Other apps** | Sylius has the gadget but no guest sink; Magento's only runtime deserializer is `allowed_classes=>false` and it has no expression-language; OpenCart uses JSON sessions. |

**Status:** sink + gadget confirmed locally; the **terminal** still needs a
same-size spray ordered before the re-entry and the carrier/address seed.
This is the strongest application-RCE candidate so far.

## Drupal (P2, 2026-10-31)

- **Guest sink on arbitrary bytes: negative** for stock Drupal 11.x/10.4 and 15
  contrib projects. Guest routes that decode serialized data read
  server-written values (`/batch` is bid+CSRF-gated; autocomplete is
  HMAC-gated; `/cron`).
- **Double-unserialize gadget: POSITIVE in pure Drupal 11 core**, ASAN
  `heap-use-after-free` at `var_unserializer.c:906` on 8.4.27:
  `YamlCacheCollectorDiscovery::__destruct`
  (`core/lib/Drupal/Core/Discovery/YamlCacheCollectorDiscovery.php:64`)
  -> `MenuActiveTrail::destruct` (`core/lib/Drupal/Core/Menu/MenuActiveTrail.php:81`)
  -> `CacheCollector::updateCache` (`core/lib/Drupal/Core/Cache/CacheCollector.php:262`)
  -> `MemoryBackend::prepareItem` (`.../Cache/MemoryBackend.php:99`)
  -> `unserialize($prepared->data)`.
  The controlled string is `MemoryBackend::$cache[$cid]->data` in the
  serialized graph; `NullLockBackend` satisfies the lock.
- Contrib zero-arg gadgets: Paragraphs `Paragraph::getAllBehaviorSettings`
  (`behavior_settings`), Search API `Task::getData` (`data`), and vendor
  `Container::reset()` via Guzzle `FnStream` (with a `__wakeup` caveat).
- **Combined:** Drupal 11 has the **gadget**, not the guest **sink**. Any
  Drupal 11 module/route that unserializes attacker bytes becomes terminal.
  No default application RCE yet.

## Other CMS/apps (P4, 2026-10-31)

Nine apps cloned (`--depth 1`) + six stable tags; every `__destruct()` body was
brace-matched (including bundled `lib/`/`3rdparty/`).

**No app has a double-unserialize destructor gadget.** No `__destruct()` body
in any tree calls `unserialize()` on a property; checking `parent::__destruct`
and `close/save/flush/clean/release/destroy` callees found none either.
(**Caveat:** this scanned *destructors*; the zero-arg/FnStream route is P5's
scope.)

No default-config guest `unserialize()` on arbitrary bytes. Closest sinks:

| App | Sink | Trigger | Guard | Verdict |
|---|---|---|---|---|
| TYPO3 | Extbase `ActionController.php:612` (`__referrer[arguments]`) | guest plugin error path | HMAC-SHA3-256 with `SYS.encryptionKey`; `allowed_classes=>true` | strongest near-miss (key-gated) |
| TYPO3 | Form `FormRuntime.php:252` (`__state`) | guest form POST | same HMAC; `allowed_classes=>true` | key-gated |
| Concrete 9.5.1/9.5.7 | form block / cached block | guest submit / poisoned cache | no allowlist | editor/DB-gated; block cache off by default |
| Craft CMS | `queue/Queue.php:493` | `GET /actions/queue/run` anonymous | none | anon trigger, **no HTTP write** of the job |
| MediaWiki | `HistoryBlobUtils.php` → `HistoryBlobStub` | old revision view | allowlist + DB bytes | double unserialize, static/allowlisted |
| SilverStripe | `Forms/Form.php:505` | any form GET | none | session value, not attacker bytes |

## Other surveys

- P2 Drupal (core 10.4 + Webform/Views/Commerce/Feeds/Paragraphs/Metatag/
  Search API/Token/Pathauto/Group/Flag/Migrate) — running.
- P3 Magento/PrestaShop/OpenCart/Sylius — running.
- P4 Moodle/phpBB/TYPO3/Craft/SuiteCRM/Nextcloud/MediaWiki/Concrete/SilverStripe
  — running.
- P5 zero-arg re-entry composition (invoker destructor + zero-arg
  `unserialize($this->prop)` + spray) — running. First-pass leads: SuiteCRM
  `InboundEmail::getStoredOptions`, Magento `getWidgetParameters`/
  `getBuyRequest`, Drupal `InlineBlock::getEntity`; TYPO3 `unpack_uc` is
  `allowed_classes=false`-gated.

## Drupal follow-ups (running)

- D1 broad contrib sink sweep (guest-writable serialized blob).
- D2 core sink paths (field/Views `serialized`, JSON:API guest write, batch,
  autocomplete, `Container::reset`, 11.0–11.4 matrix).
- D3 terminal completion for the pure-core gadget + advisory phrasing.

PrestaShop is deferred (FnStream terminal is version-dependent).

## Status

No default guest sink + terminal gadget in one app **yet**. The strongest
current application finding is the **LearnPress guest object-injection sink**
(reportable on its own; RCE depends on an installed gadget).
