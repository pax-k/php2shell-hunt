# Gadget survey for CVE-2026-115560 → var_destroy → `zif_system`

**Status:** read-only source survey, 2026-10-31. No lab, container, or application
code was changed. Companion to `docs/PLAN_115560.md` (action B).
**Question:** is there a real, stock class that is loaded/autoloadable before
`session_start()` and whose `__destruct`, `__wakeup`, or `__unserialize` calls
`unserialize()` on an attacker-controlled property, so the 115560 session
decoder can reach the `var_destroy` re-entry UAF?

**Confidence labels used below**

- **executed** — the repo previously ran it under ASAN/stock ZendMM (cited doc).
- **read** — source was inspected; no dynamic test was performed in this survey.
- **blocked** — the shape exists but a magic-method guard prevents the re-entry.

---

## 0. Answer up front

**No stock, default application was found that combines the 115560 handler
switch with a qualifying re-entry gadget.** The honest result for action B is a
split result, not a chain:

| Half | Best real finding | Why it is not enough |
|---|---|---|
| **Re-entry gadget** | **Drupal 11 core** `YamlCacheCollectorDiscovery::__destruct` → `MemoryBackend::prepareItem` → `unserialize()` (the P5 chain) | Drupal does **not** switch `session.serialize_handler` to `php` by default |
| **115560 precondition** | **Roundcube** runs `ini_set('session.serialize_handler','php')` before `session_start()` in its `db`/`redis`/`memcache` drivers; **CakePHP** `cake`/`database` session defaults do the same. The Roundcube file driver does not switch, and the db/redis drivers read their own store (Phase 2 blocker) | No stock Roundcube/CakePHP class was found whose destructor re-enters `unserialize()`, and stock Roundcube cannot combine the switch with the progress-file read |
| **Both, but wrong gadget** | **Roundcube + `Crypt_GPG_Engine::__destruct`** (CVE-2025-49113 shape, requires `pear/crypt_gpg`) | It runs `proc_open` directly; it does **not** call `unserialize()`, so it cannot drive the var_destroy UAF |

Two important corrections to earlier working assumptions:

1. **`__wakeup` / `__unserialize` are not the re-entry.** They run in
   `var_destroy()` under `BG(serialize_lock)++`, so a nested `unserialize()`
   takes the *fresh* `var_hash` branch. Only `__destruct` runs after the lock is
   released. A class with both a non-throwing `__unserialize` and a
   `__destruct` is still usable — via the destructor.
2. **Placement depends on the magic method.**
   - A **destructor-only** gadget (the lab `CachePurge` shape) must be the
     overwritten value: `var_push_dtor_value()` enqueues it only on a duplicate
     array key or object-property overwrite. At a non-duplicate key it is not
     destroyed in `var_destroy()`.
   - A `__wakeup`/`__unserialize` object is enqueued **regardless of key**
     (`ZVAL_COPY` + flag), so its magic method does run at `var_destroy()` even
     at a non-duplicate key — but under `BG(serialize_lock)`, so its nested
     `unserialize()` is fresh. Its own `__destruct` is deferred while the array
     still holds a reference.
   - A class with **both** a non-throwing `__wakeup`/`__unserialize` and a
     `__destruct` therefore needs the **overwritten** placement to make the
     destructor run at `var_destroy()`; then the locked magic call is followed
     by the unlocked destructor. The parent session's
     `poc/verify_115560_wakeup.py` already tests the wakeup/unserialize branch
     with `nondup` and `dup` placements and expects the magic call itself to be
     negative (lock held); Test 1 below adds the both-methods case.

---

## 1. Qualifying shape and the exact PHP mechanics

Source: PHP 8.4.27 `ext/standard/var_unserializer.re` (the generated C is what the
repo docs cite as `var_unserializer.c:906` / `:319`). The same flags and lock
order exist on 8.2.34 and 8.5.12.

```c
/* var_destroy(), abridged */
while (var_hash) {                      /* 1. free every var_entries chunk */
    next = var_hash->next;
    efree_size(var_hash, sizeof(var_entries));
    var_hash = next;
}

while (var_dtor_hash) {
    for (i = 0; i < var_dtor_hash->used_slots; i++) {
        zval *zv = &var_dtor_hash->data[i];

        if (Z_EXTRA_P(zv) == VAR_WAKEUP_FLAG) {
            BG(serialize_lock)++;       /* 2. __wakeup under the lock */
            zend_call_function(...);
            BG(serialize_lock)--;
        } else if (Z_EXTRA_P(zv) == VAR_UNSERIALIZE_FLAG) {
            BG(serialize_lock)++;       /* 2. __unserialize under the lock */
            zend_call_known_instance_method_with_1_params(...);
            BG(serialize_lock)--;
        }

        i_zval_ptr_dtor(zv);            /* 3. __destruct UNLOCKED */
    }
    ...
}
```

`php_var_unserialize_init()` chooses the stale chain only when the lock is zero:

```c
if (BG(serialize_lock) || !BG(unserialize).level) {
    /* fresh var_hash */
} else {
    d = BG(unserialize).data;       /* stale, just-freed chain */
    ++BG(unserialize).level;
}
```

Therefore:

- `__destruct { unserialize($this->p); }` → **UAF path** (lock 0, level > 0).
- `__wakeup { unserialize($this->p); }` → **fresh path** (lock 1); no UAF.
- `__unserialize { unserialize($this->p); }` → **fresh path** (lock 1); no UAF.
- A throwing `__wakeup`/`__unserialize` sets `IS_OBJ_DESTRUCTOR_CALLED` on failure
  (`var_unserializer.re:288-291` / `:307-309`) and **suppresses the later
  `__destruct`**. This is why every `FnStream`-based chain dies under a real
  `unserialize()` sink.

**Delayed-list population has two sources.**

1. **Overwritten values** — `var_push_dtor_value()` is called only on an
   overwrite: array duplicate key (`process_nested_array_data`,
   `var_unserializer.re:501-518`) or object-property overwrite (`:657-668`).
   These entries are destroyed by the final `i_zval_ptr_dtor(zv)`; a
   destructor-only gadget must be placed this way.
2. **Objects with `__wakeup`/`__unserialize`** — every such object is enqueued
   when parsed (`ZVAL_COPY` + `VAR_WAKEUP_FLAG`/`VAR_UNSERIALIZE_FLAG`,
   `var_unserializer.re:895-901`), even at a non-duplicate key. At
   `var_destroy()` its magic method is called under the lock, then
   `i_zval_ptr_dtor(zv)` drops the dtor-list reference. If the array still holds
   the object, that drop does not reach zero, so its `__destruct` is deferred;
   if the object was overwritten, the drop reaches zero and the destructor runs
   unlocked.

The 115560 lab payload for a destructor-only gadget is therefore:

```text
a:1018:{ <1016 × i:0;N;>  i:99999;<GADGET GRAPH>  i:99999;i:42; }
```

The gadget root is the value of the first `i:99999`; the second `i:99999`
overwrites it and enqueues it. Its `p`/`cid`/`serviceDefinitions` properties are
non-duplicate properties and survive until the destructor runs.

**Spray.** The re-entry needs a same-size (8160-byte / 8192-bin on 8.4.27)
allocation before the nested `unserialize()`. The lab `CachePurge` does this in
the destructor. A real gadget must either build the spray in the same destructor
chain (Drupal P5 does) or be preceded by a separate spray object in the
attacker-controlled dtor order (`docs/SPLIT_GADGET.md` §1).

**Autoload.** `unserialize()` autoloads object classes by default. In normal
Composer apps the autoloader is registered before `session_start()`; preloading
is not required. The class only has to be reachable through the app's autoloader
at decode time. Roundcube loads plugins *before* `session_init()`, CakePHP loads
plugins during bootstrap before the lazy session starts, and Drupal's Composer
autoloader is registered in `index.php`.

---

## 2. Ranked candidates

Ranking is by **real-world reachability for the 115560 chain**, not by how
interesting the class is in isolation.

| # | Candidate (root → `unserialize()`) | Package / version | Controlled property | In delayed-dtor list | Spray | Confidence | 115560 app? | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | `Drupal\Core\Discovery\YamlCacheCollectorDiscovery::__destruct` → `MenuActiveTrail::destruct` → `CacheCollector::updateCache` → `MemoryBackend::prepareItem` → `unserialize($prepared->data)` | Drupal **11.4.0-rc1+** core | `MenuActiveTrail::$cid` (private) and `MemoryBackend::$cache[$cid]->data` (private) | yes, root overwritten | **built-in** 8135 B lock name → 8160 alloc | **executed** (ASAN, prior P5 lab; not under 115560) | **no** by default (Drupal does not switch to `php`); yes only with a non-default `session.storage.options.serialize_handler: php` | Best real gadget; wrong app default |
| 2 | `GuzzleHttp\Cookie\FileCookieJar::__destruct` → `save($this->filename)` → `Laminas\Diactoros\RelativeStream::__toString` → `PumpStream::read` → `Drupal\Core\Config\CachedStorage::read` → `Drupal\Component\DependencyInjection\Container::get` → `unserialize($definition)` | Drupal 8.9.6–11.x + **Guzzle 7 ≤ 7.16.1** + psr7 2.x + Laminas Diactoros 3.x (phpggc `Drupal/RCE/1`) | `Container::$serviceDefinitions` (protected) keyed serialized string; `FileCookieJar::$filename` graph | yes, root overwritten | **none**; needs a split spray before it | **read** (phpggc chain + source; not ASAN-executed here) | **no** by default (same Drupal issue) | Real destructor→`unserialize`, version-fragile |
| 3 | `Illuminate\Mail\SentMessage::__unserialize` and `Illuminate\Mail\Events\MessageSent::__unserialize` → `unserialize(base64_decode($data[...]))` | Laravel framework (`master`; verify the target's Laravel version) | `$data['sentMessage']` / `$data['data']` (base64 string) | yes (unserialize flag, any key; magic under lock) | none | **read** (direct nested call verified in source) | **no** (Laravel uses its own session store, not native `session_start`) | **Not a re-entry**: `__unserialize` runs under the lock; no `__destruct` |
| 4 | `GuzzleHttp\Psr7\FnStream::__destruct` → `call_user_func($this->_fn_close)` → `Symfony\Component\ExpressionLanguage\SerializedParsedExpression::getNodes` → `unserialize($this->nodes)` | PrestaShop 8.2.1 + bundled `ps_facetedsearch` 4.0.0 (prior P3); any app with Guzzle psr7 | `SerializedParsedExpression::$nodes` | yes (wakeup flag; wakeup throws) | none | **read + prior runtime construction**; not a real sink test | **no** (PrestaShop does not switch to `php`) | **Blocked** by `FnStream::__wakeup()` throwing (psr7 ≥ 1.9.0) |
| 5 | `Joomla\CMS\Mail\Mail::__destruct` → `PHPMailer::smtpClose` → `DataSet::__call` → `FnStream::close` → `Joomla\Registry\Registry::__clone` → `unserialize(serialize($this->data))` | Joomla 5.4.x stock | `Registry::$data` | yes (root overwritten; dtor-only; `FnStream::close()` is a method call, not FnStream's dtor) | Joomla `Uri` split spray exists | **executed** (ASAN UAF, prior J1/J2) | **no** (Joomla session handler is `database`; no `php` switch) | UAF/DoS only: `serialize()` cannot emit `R:` or a raw pointer |
| 6 | `SimplePie::__destruct` → `WP_HTML_Token::__destruct` → `call_user_func($on_destroy, ...)` → `unserialize` | WordPress 7.1.3 core | `WP_HTML_Token::$bookmark_name` / `$on_destroy` | yes (root overwritten; dtor-only) | none | **read** (prior P1/S2) | **no** (WP does not use native sessions) | **Blocked**: `SimplePie`'s direct destructor is `!gc_enabled()`-gated; WP never disables GC |
| 7 | `FnStream::__destruct` → `Migrator_Lite::restored_plugins` → native `unserialize` | UpdraftPlus 1.26.14 | `restored_plugins` | yes (wakeup flag; wakeup throws) | none | **read** (prior P1) | **no** | **Blocked**: `FnStream` not autoloaded on default pages; `__wakeup` throws |
| 8 | `Crypt_GPG_Engine::__destruct` → `_closeIdleAgents`/`_closeSubprocess` → `proc_open` | Roundcube + `pear/crypt_gpg` 1.x (enigma); CVE-2025-49113 | `_gpgconf` / `_homedir` | yes (root overwritten; dtor-only) | none | **read** (public CVE writeup; not run here) | **yes precondition** (Roundcube always switches to `php`) | **Simple gadget, not re-entry**: executes a command via `proc_open`; does not call `unserialize()` |
| 9 | `Symfony\Component\Messenger\Envelope::__wakeup` | Symfony Messenger | n/a | yes (wakeup flag; no unserialize) | none | **read** | n/a | **Negative**: only validates and throws; no `unserialize()` call (the scan hit was a comment) |
| 10 | **No qualifying stock candidate** | — | — | — | — | — | — | **Explicit negative for the intersection** |

“115560 app?” means the app performs the required runtime switch to the `php`
handler *and* can be configured with `php_serialize`/`php_binary` server-side.

---

## 3. Candidate detail

### 3.1 Drupal 11 core P5 — the best real re-entry gadget

**Call path (all stock Drupal 11 core):**

```text
YamlCacheCollectorDiscovery::__destruct()        core/lib/Drupal/Core/Discovery/YamlCacheCollectorDiscovery.php:64
 -> MenuActiveTrail::destruct()                   core/lib/Drupal/Core/Menu/MenuActiveTrail.php:81
 -> CacheCollector::updateCache()                 core/lib/Drupal/Core/Cache/CacheCollector.php:234
      $lock_name = $cid . ':' . __CLASS__         :251  -> 8135 B -> 8160 alloc (the spray)
 -> MemoryBackend::get()                          core/lib/Drupal/Core/Cache/MemoryBackend.php:44
 -> MemoryBackend::prepareItem()                  :89
      $prepared->data = unserialize($prepared->data)   :99   <-- re-entry, no allowed_classes
```

- **Controllable:** `MenuActiveTrail::$cid` (private) is the spray length/source;
  `MemoryBackend::$cache[$cid]->data` (private) is the string handed to
  `unserialize()`. `expire=0` makes `prepareItem()` return `FALSE`, so the
  result is discarded (the lab's `unset($r)` shape).
- **Autoload:** `Drupal\Core\Discovery\YamlCacheCollectorDiscovery` is PSR-4
  autoloadable from Drupal's Composer autoloader, which is registered before
  `session_start()` in a normal Drupal request. No preload needed.
- **Placement:** root `YamlCacheCollectorDiscovery` at the duplicate key; the
  `yamlCacheCollector` → `MenuActiveTrail` → `MemoryBackend` graph is nested in
  non-duplicate properties and survives.
- **Spray:** built inside the destructor; no split gadget needed.
- **Confidence:** **executed** under ASAN on 8.4.27 in the prior P5 lab
  (`docs/APP_SURVEY.md` §“Drupal 11 pure-core terminal gadget”), with the
  cid-length control (cid 100 → no crash). It has **not** been executed through
  the 115560 session decode path.
- **Version:** gadget present in Drupal **11.4.0-rc1+**; absent in 11.0.13–11.3.20
  and 10.4.x (per `docs/APP_SURVEY.md` D2).
- **115560 gap:** Drupal's default `session.storage.options` does not include
  `serialize_handler` (`core/assets/scaffold/files/default.services.yml`).
  A site can add `serialize_handler: php` in `services.yml`; that is the only
  way this gadget meets 115560. It is a non-default config, but a single line.

**Why this is the best gadget:** it is pure core, it builds its own spray, it
does not depend on Guzzle/psr7 version drift, and its destructor is not
suppressed by a throwing wakeup.

### 3.2 Drupal 9/10/11 + Guzzle 7 — phpggc `Drupal/RCE/1`

**Call path:**

```text
GuzzleHttp\Cookie\FileCookieJar::__destruct()     guzzle/src/Cookie/FileCookieJar.php:61
 -> save($this->filename)                          :64, :91
 -> file_put_contents($filename, ...)              (coerces the RelativeStream object)
 -> Laminas\Diactoros\RelativeStream::__toString()  src/RelativeStream.php:32
 -> getContents()                                   :166
 -> GuzzleHttp\Psr7\PumpStream::getContents()       psr7/src/PumpStream.php
 -> read($length)                                   :146 (psr7 2.x) -> $this->buffer->read($length)
 -> Drupal\Core\Config\CachedStorage::read($name)   core/lib/Drupal/Core/Config/CachedStorage.php:65
 -> $this->cache->get($cache_key)
 -> Drupal\Component\DependencyInjection\Container::get($id)  core/lib/Drupal/Component/DependencyInjection/Container.php:162
 -> unserialize($definition)                        :166   <-- re-entry, no allowed_classes
```

- **Controllable:** `Container::$serviceDefinitions` is a protected array;
  set a key whose value is a serialized string starting with an array index
  (`$definition[0]` set). `FileCookieJar::$filename` is the `RelativeStream`
  graph. The phpggc generator is the reference:
  <https://github.com/ambionics/phpggc/blob/master/gadgetchains/Drupal/RCE/1/chain.php>.
- **Autoload:** Guzzle, Laminas Diactoros, and Drupal's `Container`/`CachedStorage`
  are all Composer-autoloadable in Drupal 9/10/11.
- **Placement:** root `FileCookieJar` at the duplicate key; the entire
  `filename` graph is nested and survives.
- **Spray:** none. It must be paired with a same-size spray destructor before it
  in the dtor order (split gadget).
- **Confidence:** **read** — phpggc chain + current Drupal/Guzzle/Laminas source.
  It has not been ASAN-tested under 115560 in this survey.
- **Version gates (critical):**
  - Guzzle **7.16.1** still has the unguarded `__destruct` and no
    `__wakeup`/`__unserialize` (<https://github.com/guzzle/guzzle/blob/7.16.1/src/Cookie/FileCookieJar.php>).
  - Guzzle **8.0.0+** adds `__unserialize()` that throws
    `LogicException('... should never be unserialized')`; a throwing
    `__unserialize` suppresses the destructor
    (<https://github.com/guzzle/guzzle/blob/8.0.0/src/Cookie/FileCookieJar.php>).
  - Drupal 10.4 requires `guzzlehttp/guzzle ^7.5` → 7.16.1 (chain live).
    Drupal 9.5 requires `^6.5.8 || ^7.4.5` → 7.16.1 (chain live).
    Drupal 11 requires `^7.15.2 || ^8.0.1`; a fresh install can resolve to
    Guzzle 8.3.1 (chain blocked), while an existing 7.16.1 install is live.
  - psr7 **2.13.2** `PumpStream::read()` calls `$this->buffer->read($length)`
    directly (chain live). psr7 **3.x** calls `$this->buffer->getSize()` first;
    `CachedStorage` has no `getSize()`, so the chain breaks. Drupal 11 allows
    `^2.13 || ^3.0`; Drupal 9.5/10.4 require `^2.x`.
- **Result-use caveat:** after `unserialize($definition)`, `Container::get()`
  passes the result to `createService(array $definition, $id)`. A terminal
  forged `R:` value is not an array and may raise a `TypeError`; whether the
  forged reference is destroyed during unwinding (terminal) or the type check
  faults first is exactly the `json_encode`-style blocker from
  `docs/SPLIT_GADGET.md` §4. Test 3 below is designed to answer this.

### 3.3 Laravel Mail `__unserialize` — a nested `unserialize`, but not a re-entry

`Illuminate\Mail\SentMessage::__unserialize()` (`src/Illuminate/Mail/SentMessage.php:76`)
does:

```php
$this->sentMessage = $hasAttachments
    ? unserialize(base64_decode($data['sentMessage']))
    : $data['sentMessage'];
```

`Illuminate\Mail\Events\MessageSent::__unserialize()` (`.../Events/MessageSent.php:48`)
has the same shape for `$data['data']` (`:53`).

- **Attacker control:** full, via the base64 property.
- **Why it does not work:** this is `__unserialize`, so `var_destroy()` calls it
  under `BG(serialize_lock)++` (see §1). The nested `unserialize()` takes the
  fresh `var_hash` branch; it never reads the freed chain. Neither class has a
  `__destruct`. The class is a nested-deserialization *amplifier*, not a
  var_destroy re-entry.
- **If a real app subclassed one of these and added a `__destruct` that re-enters
  `unserialize()`**, that subclass would qualify — but no stock Laravel class
  does.

### 3.4 PrestaShop `FnStream` → `SerializedParsedExpression` — blocked

The shape in `docs/APP_SURVEY.md` P3 is real in source:
`GuzzleHttp\Psr7\FnStream::__destruct()` invokes `$this->_fn_close`; a
`SerializedParsedExpression::getNodes()` callable then does
`unserialize($this->nodes)` (no allowlist).

But `FnStream::__wakeup()` has thrown
`LogicException('FnStream should never be unserialized')` since psr7 **1.9.0**
(<https://github.com/guzzle/psr7/blob/1.9.0/src/FnStream.php#L64-L66>), and the
same guard exists in 2.x/3.x. Under a real `unserialize()` sink:

1. `FnStream::__wakeup()` runs (delayed, under lock) and throws;
2. `var_destroy()` sets `IS_OBJ_DESTRUCTOR_CALLED`;
3. the later `i_zval_ptr_dtor()` does **not** call `__destruct`;
4. the nested `unserialize()` never runs through the destructor.

P3's “runtime-verified” result constructed the graph in PHP (so `__wakeup` did
not run), not through an attacker `unserialize()`. P5 flagged this; P7 was
deferred. Treat PrestaShop's FnStream re-entry as **blocked** on current psr7.

### 3.5 Joomla — UAF, but no terminal

`docs/JOOMLA_GADGET.md` is accurate: the stock Joomla 5 Composer autoloader
provides `Mail::__destruct → PHPMailer::smtpClose → DataSet::__call →
FnStream::close → Registry::__clone → unserialize(serialize($this->data))`.
It reaches the ASAN UAF, but `serialize()` cannot emit an out-of-range
`R:1020;` or place a raw pointer at the stale `data[id]` slot. Note that the
Joomla chain reaches `FnStream` through `close()` — a normal method call from
`Mail::__destruct()` — not through FnStream's own destructor, so the throwing
`FnStream::__wakeup()` does not block this particular chain. **UAF/DoS only;
not the terminal gadget.**

### 3.6 WordPress — real gadget, gated off

`SimplePie::__destruct → WP_HTML_Token::__destruct → call_user_func(...) →
unserialize` exists, but `SimplePie`'s direct destructor call is
`!gc_enabled()`-gated and WordPress never disables GC. Not reachable as shipped
(`docs/JOOMLA_GADGET.md` “WordPress and built-ins for contrast”).

### 3.7 UpdraftPlus — FnStream autoload + wakeup

`FnStream::__destruct → Migrator_Lite::restored_plugins → native unserialize`
exists in UpdraftPlus 1.26.14, but `FnStream` is not autoloaded on default pages
and `FnStream::__wakeup()` blocks the destructor. Not reachable.

### 3.8 Roundcube + `Crypt_GPG_Engine` — a real 115560 target, but a simple gadget

Roundcube is the best 115560 **precondition** match. CVE-2025-49113's public
gadget is:

```text
Crypt_GPG_Engine::__destruct()
 -> _closeIdleAgents() / _closeSubprocess()
 -> proc_open($cmd, ...)
```

- `pear/crypt_gpg` is a Roundcube Composer dependency (`~1.7.0` in the
  `require-dev`/enigma path), so the class can be autoloadable before
  `session_start()`.
- It is a **command-execution** destructor, not a nested `unserialize()`. It
  satisfies the public 115560 simple-gadget path (and would be pre-auth if the
  upload-progress session write reaches Roundcube's save handler), but it does
  **not** satisfy action B (var_destroy → forged `zif_system`).
- Current `pear/crypt_gpg` 2.0.0 is namespaced (`Crypt\GPG\Engine`) and its
  destructor calls `_closeSubprocess()`; the old `Crypt_GPG_Engine` class is the
  1.x shape. Treat this as version/plugin dependent.
- Near-miss: Roundcube's own `rcube_session::unserialize()` is a custom parser
  that ends in a real `unserialize('a:...')`, but its callers are the session
  read/update and cache read paths, not a destructor. It does not close the
  re-entry gap.

### 3.9 Symfony Messenger `Envelope::__wakeup` — negative

`Envelope::__wakeup()` (`src/Symfony/Component/Messenger/Envelope.php:128`)
validates `$this->message`/`$this->stamps` and throws `BadMethodCallException`.
The scanner's “`unserialize`” hit was a **comment** in the body, not a call.
Not a gadget.

### 3.10 Clean negatives from the source sweep

A brace-matching scanner was run over **46,508 PHP files** in ~60 source
trees/packages (Symfony, Laravel, CakePHP 2/5, Yii2, CodeIgniter4, Slim,
Doctrine ORM/cache/common, Monolog, Guzzle, psr7, Laminas/Zend Session/Cache,
Roundcube, phpBB, phpMyAdmin, Adminer, PrestaShop, Composer, PHPUnit,
PhpSpreadsheet, Twig, Smarty, HTMLPurifier, Predis, Flysystem, phpseclib,
TCPDF, Dompdf, AWS SDK, Google API, Nette, Latte, SwiftMailer, Spiral, PEAR,
and the Roundcube/CakePHP dependency sets).

Result:

- **2 real direct `__destruct`/`__wakeup`/`__unserialize` → `unserialize()` hits**
  (both Laravel Mail `__unserialize`; plus one comment-only Symfony hit).
- **0 direct `__destruct` → `unserialize()` hits.**
- **0 one-level `$this->helper()` → `unserialize()` hits.**
- The multi-object destructor → `unserialize()` chains found are the two Drupal
  chains above (P5 core and phpggc `Drupal/RCE/1`), the Joomla
  `Registry::__clone` chain (which only re-serializes, so it cannot emit the
  forged `R:`), and the PrestaShop `FnStream` → `SerializedParsedExpression`
  chain (blocked by `FnStream::__wakeup`). All were reviewed manually because
  the sink is several objects away.

This is consistent with the earlier surveys: outside Drupal 11 core (P5), no
stock app in the scanned set has the `__destruct { @unserialize($this->p); }`
discard shape (`docs/SPLIT_GADGET.md` §4, `docs/APP_SURVEY.md` P1–P6).

---

## 4. The 115560 precondition: apps that switch to `php`

The switch must be a **runtime `ini_set`/`session_start` option** that changes a
server-side `php_serialize`/`php_binary` config to `php` before
`session_start()`. A non-default server config alone is not enough; the app must
switch.

| App / framework | Switch site | Default? | Notes |
|---|---|---|---|
| **Roundcube 1.x** | `program/lib/Roundcube/rcube_session.php:109` — `ini_set('session.serialize_handler', 'php')` in `register_session_handler()` | **unconditional inside** the `db`/`redis`/`memcache` drivers; the native `php` (file) driver does not call it | `rcmail::startup()` loads plugins (`rcmail.php:111`) **before** `session_init()` (`:116`); plugin/Composer classes are available during decode. No stock re-entry gadget found. The db/redis drivers read their own store, so the upload-progress file is not decoded (Phase 2). |
| **CakePHP 2.10.x** | `lib/Cake/Model/Datasource/CakeSession.php:681, 712` — `'session.serialize_handler' => 'php'` in the `cake` and `database` presets | only for `cake`/`database`; the `php` preset does not switch | Legacy but widely deployed. No stock re-entry gadget found. |
| **CakePHP 3/4/5** | CakePHP 3: `src/Network/Session.php`; CakePHP 4/5: `src/Http/Session.php:156, 177` — same `'php'` value in `cake`/`database` presets | only for `cake`/`database`; default app skeleton uses `defaults => 'php'` | App/plugin classes are autoloadable during bootstrap; session starts lazily. No stock re-entry gadget found. |
| **Zend / Laminas Session** | `Zend\Session\Config\SessionConfig::setSerializeHandler()` → `ini_set('session.serialize_handler', $handler)`; same in Laminas | only if the app config sets `php` | No default switch; no stock gadget. |
| **Symfony** | `NativeSessionStorage::setOptions()` accepts `serialize_handler` and `ini_set`s it (`:315-329`) | **no** — FrameworkBundle's `registerSessionConfiguration()` does not pass `serialize_handler`; only custom code/manual options do | A `framework.session.serialize_handler` key is not in the standard option list. |
| **Drupal 9/10/11** | `SessionManager::start()` → `setOptions($sessionConfiguration->getOptions())` → Symfony `NativeSessionStorage` | **no by default** — `default.services.yml` `session.storage.options` has no `serialize_handler` | A site can add `serialize_handler: php` under `session.storage.options` in `services.yml`; then Drupal + P5 is a stock-code profile. |
| **Matomo 3.7+** | `core/Session.php:110-111` forces `php_serialize`, not `php` | inverse | A `php_serialize` writer (Chain C), not a 115560 reader. |
| **phpBB / phpMyAdmin / Adminer / PrestaShop / WordPress / Joomla / MediaWiki / Moodle / Nextcloud / TYPO3 / Magento** | no `session.serialize_handler` switch found in the scanned bootstrap/session code | — | Most use custom session stores or leave the ini value alone. |

**Server-config variants** (from the advisory/response guides):

- `php.ini` / `conf.d`: `session.serialize_handler = php_serialize`
  (or `php_binary`).
- Per-directory `.user.ini`: `session.serialize_handler = php_serialize`
  (`INI_PERDIR`, honored by FPM/CGI).
- Apache `.htaccess` (mod_php): `php_value session.serialize_handler php_serialize`.
- FPM pool: `php_value[session.serialize_handler] = php_serialize` — **allows**
  the app's `ini_set` to switch to `php`.
- FPM pool: `php_admin_value[session.serialize_handler] = php_serialize` —
  **blocks** the runtime `ini_set`, so it prevents 115560 (the `ini_set` fails).
- `session_start(['serialize_handler' => 'php'])` is a direct per-call switch
  (PHP 7.1+), equivalent to the `ini_set` shape.

The advisory itself calls this combination “unlikely in practice”
(<https://safeguard.sh/resources/blog/php-cve-2026-115560-session-upload-progress-mitigation>).
That is consistent with the survey: the precondition is rare and the gadget is
rarer.

---

## 5. Best target app profiles

Ranked by **real-world reachability of the 115560 precondition**, with the gadget
gap called out.

### Profile A — Roundcube 1.6.x (best precondition; missing re-entry)

- Server: `session.serialize_handler = php_serialize` (php.ini/.user.ini/FPM
  `php_value`), `session.upload_progress.enabled = On`.
- App: Roundcube's `db`/`redis`/`memcache` session drivers call
  `ini_set(...,'php')` unconditionally before `session_start()`; the native
  `php` (file) driver does not, and the db/redis drivers read their own store
  rather than the upload-progress file.
- Autoload: plugins loaded before `session_init()`; Composer autoload registered.
- Stock gadget: `Crypt_GPG_Engine::__destruct` (simple command exec) if
  `pear/crypt_gpg` is installed. **Not** a re-entry; does not drive var_destroy.
- Missing piece: a Roundcube plugin (or PEAR/Composer class) with
  `__destruct { @unserialize($this->p); }` and a same-size spray. None found in
  core or the bundled plugins.
- Why it matters: Roundcube is internet-facing and its **app-side** switch is
  stock (the server-side `php_serialize` config is non-default); this is the
  most likely place for a real 115560 **simple-gadget** RCE, but not for the
  `zif_system` var_destroy chain without a new plugin gadget.

### Profile B — Drupal 11.4+ with a non-default session option (best gadget)

- Server: `session.serialize_handler = php_serialize` + upload progress On.
- App: Drupal 11.4+ with
  `session.storage.options: { serialize_handler: php }` in `services.yml`
  (non-default; a single line).
- Gadget: stock P5 core chain; self-spraying; ASAN-proven in the direct
  `unserialize()` harness.
- Why it matters: this is the only profile where **both halves are stock code**
  (no plugin, no vendor version gamble). It is config-gated, not default.
- Next step: Test 2 below (put the P5 graph into the 115560 session payload).

### Profile C — CakePHP 2/3/4/5 with `cake`/`database` sessions

- Server: `php_serialize` + upload progress On.
- App: `Session.defaults = 'cake'` or `'database'` (common in legacy apps);
  the preset sets `session.serialize_handler => 'php'`.
- Autoload: app/plugin classes available before the lazy session start.
- Gadget: none found in Cake core, DebugKit, or the Cake dependency set.
- Missing piece: an app/plugin class with the destructor shape.

### Profile D — custom Composer app

- Any app that calls `ini_set('session.serialize_handler','php')` (or
  `session_start(['serialize_handler'=>'php'])`) before `session_start()`.
- Vendor autoload is normally registered by then; any Composer package with the
  shape is usable.
- This is the broadest fallback, but the survey found no popular package with a
  direct destructor→`unserialize` gadget.

---

## 6. Next 3 concrete tests

These are proposed, not executed here. They do not require lab config edits; use
a temporary harness/copy.

### Test 1 — prove that only `__destruct` re-enters (ASAN control)

Purpose: settle the `__wakeup`/`__unserialize` question empirically on 8.4.27
(and 8.2.34 / 8.5.12).

```php
class W {                              // wakeup-only control
    public $p;
    public function __unserialize(array $d): void {
        $this->p = $d['p'];
        @unserialize($this->p);          // runs under serialize_lock
    }
}
class D {                              // destructor-only control
    public $p;
    public function __destruct() {
        @unserialize($this->p);          // runs unlocked from var_destroy
    }
}
class WD {                             // both: wakeup restores, dtor re-enters
    public $p;
    public function __unserialize(array $d): void { $this->p = $d['p']; }
    public function __destruct() { @unserialize($this->p); }
}
```

Build 1018-element payloads and test four cases:

| Case | Payload tail | Expected |
|---|---|---|
| `W` dup | `i:99999;O:1:"W":1:{s:1:"p";s:7:"R:1020";} i:99999;i:42;` | no ASAN report (nested call under lock, fresh `var_hash`) |
| `D` dup | `i:99999;O:1:"D":1:{s:1:"p";s:7:"R:1020";} i:99999;i:42;` | `heap-use-after-free` at `var_unserializer.c:906` (8.4.27; `:850` on 8.2.34) |
| `WD` dup | `i:99999;O:2:"WD":1:{s:1:"p";s:7:"R:1020";} i:99999;i:42;` | UAF: `__unserialize` under lock, then `i_zval_ptr_dtor` reaches zero and `__destruct` runs unlocked |
| `WD` nondup | `i:99999;O:2:"WD":1:{s:1:"p";s:7:"R:1020";} i:99998;i:42;` | no UAF at `var_destroy`: the array reference keeps the object alive, so `__destruct` is deferred |

Run under the repo's ASAN image (`lab-asan-85x`, PHP 8.4.27). If `W` reports,
the lock/timing model in §1 is wrong; if `WD` nondup reports, the refcount /
placement model is wrong. Both must be fixed before any gadget is trusted.
This complements the parent's `poc/verify_115560_wakeup.py` (which tests the
`W`/`WU` magic call itself with `nondup` and `dup`).

### Test 2 — 115560 session decode + the Drupal 11 P5 graph (real gadget)

Purpose: the first end-to-end test of a **real** re-entry gadget through the
115560 session decoder.

1. Build the P5 object graph from `docs/APP_SURVEY.md`:
   `YamlCacheCollectorDiscovery{ yamlCacheCollector: MenuActiveTrail{ cid:
   8102-byte string, cache: MemoryBackend{ cache: { <cid> => stdClass{
   data: "<inner payload>", expire: 0, ... } } }, lock: NullLockBackend, ... } }`.
2. Place the root at the duplicate key in the upload-progress value:
   `|a:1018:{ ... i:99999;<P5 graph>; i:99999;i:42; }`.
3. Use a harness that autoloads the real Drupal 11.4.11 classes (a minimal
   PSR-4 autoloader for the four classes, or Drupal's `vendor/autoload.php` +
   `core/lib`).
4. Fire through `lab-115560` (`session.serialize_handler=php_serialize`,
   upload progress On, app switches to `php`) under ASAN.
5. Expected: the P5 destructor chain runs inside the session `var_destroy`,
   builds the 8135 B lock name → 8160 alloc, and re-enters
   `unserialize($prepared->data)`; ASAN UAF at `var_unserializer.c:906`.
6. Then measure the carrier for the **session raw input buffer** (not the POST
   body) and check whether the P5 spray survives the session-decode heap shape.
7. If the UAF fires, the remaining gap is only the Drupal `serialize_handler`
   config line and the carrier seed — i.e. Profile B becomes a real chain.

### Test 3 — 115560 + phpggc `Drupal/RCE/1`: is the result-use a blocker?

Purpose: determine whether the FileCookieJar→Container chain can deliver the
terminal call or only the UAF (the `json_encode`-style blocker from
`docs/SPLIT_GADGET.md` §4).

1. Build the phpggc graph with Guzzle **7.16.1** and psr7 **2.13.2**:
   `FileCookieJar{ filename: RelativeStream{ PumpStream{ buffer:
   CachedStorage{ cache: Container{ serviceDefinitions: ["1000000" =>
   "<inner>"] } } } } }`.
2. Use the inner payload `R:1020;` (or a serialized array that places the forged
   reference at the point the lab’s `unserialize('R:1020;')` uses).
3. Place the root `FileCookieJar` at the duplicate key in the 115560 progress
   value; fire under ASAN and then on stock ZendMM with a sentinel `dtor_obj`.
4. Observe whether `Container::get()` → `createService(array $definition, $id)`
   touches the forged value before `zend_reference_destroy`, or whether the
   `TypeError` unwinding destroys it.
5. Expected outcomes:
   - UAF read + `zif_system` sentinel hit → terminal chain (new finding);
   - UAF read + fault in a type/`instanceof` check → same class of blocker as
     `Manifest::deserializeMetaData`; record it and fall back to P5.
6. Repeat with Guzzle 8.3.1 / psr7 3.2.0 as a negative control: the
   `FileCookieJar::__unserialize` throw should suppress the destructor, and the
   `PumpStream::getSize()` call should break the chain before the nested
   `unserialize()`.

**Stretch test (profile validation, not a gadget test):** run Roundcube 1.6.11
with `php_serialize` + upload progress On and a temporary plugin that defines
`__destruct { @unserialize($this->p); }`, loaded before `session_init()`. This
proves the Roundcube precondition and plugin load order without claiming a stock
gadget. It also tells us whether the upload-progress write reaches Roundcube's
custom save handler (DB/Redis) rather than a file.

---

## 7. Sources

**Repo prior work**

- `docs/APP_SURVEY.md` — WordPress (P1), Drupal core/contrib (P2/P5/P6),
  PrestaShop (P3), other apps (P4), FnStream correction (§P5).
- `docs/SPLIT_GADGET.md` — dtor order, stock Joomla split, `json_encode` blocker.
- `docs/JOOMLA_GADGET.md` — stock Joomla chain, FnStream/`__wakeup` caveat.
- `docs/VAR_DESTROY_UAF.md` — root cause, minimal payload, terminal ladder.
- `docs/PLAN_115560.md` — action B definition and best bets.
- `PROGRESS.md` iterations 30, 33, 37, 43, 47, 48.

**PHP internals**

- `var_destroy()` and the delayed flags:
  <https://github.com/php/php-src/blob/PHP-8.4.27/ext/standard/var_unserializer.re#L245-L325>
- `php_var_unserialize_init()` lock/fresh branch:
  <https://github.com/php/php-src/blob/PHP-8.4.27/ext/standard/var_unserializer.re#L65-L87>
- 8.2.34 equivalent:
  <https://github.com/php/php-src/blob/PHP-8.2.34/ext/standard/var_unserializer.re#L255-L301>
- 8.5.12 equivalent:
  <https://github.com/php/php-src/blob/PHP-8.5.12/ext/standard/var_unserializer.re#L265-L311>

**Gadget sources**

- Drupal P5:
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Discovery/YamlCacheCollectorDiscovery.php#L64>,
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Menu/MenuActiveTrail.php#L81>,
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Cache/MemoryBackend.php#L89-L99>.
- Drupal `Container::get()`:
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Component/DependencyInjection/Container.php#L162-L167>.
- phpggc `Drupal/RCE/1`:
  <https://github.com/ambionics/phpggc/blob/master/gadgetchains/Drupal/RCE/1/chain.php>.
- Guzzle `FileCookieJar` 7.16.1:
  <https://github.com/guzzle/guzzle/blob/7.16.1/src/Cookie/FileCookieJar.php>.
- Guzzle 8.0.0 `__unserialize` throw:
  <https://github.com/guzzle/guzzle/blob/8.0.0/src/Cookie/FileCookieJar.php>.
- psr7 `FnStream::__wakeup`:
  <https://github.com/guzzle/psr7/blob/2.13.2/src/FnStream.php#L66-L68>.
- Laravel `SentMessage`:
  <https://github.com/laravel/framework/blob/master/src/Illuminate/Mail/SentMessage.php#L74-L81>.
- Laravel `MessageSent`:
  <https://github.com/laravel/framework/blob/master/src/Illuminate/Mail/Events/MessageSent.php#L46-L54>.
- Symfony `Envelope::__wakeup`:
  <https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/Messenger/Envelope.php#L128-L152>.

**115560 precondition sources**

- Roundcube `rcube_session.php:109`:
  <https://github.com/roundcube/roundcubemail/blob/master/program/lib/Roundcube/rcube_session.php#L100-L115>.
- Roundcube startup/plugin order:
  <https://github.com/roundcube/roundcubemail/blob/master/program/include/rcmail.php#L100-L120>.
- CakePHP 5 `Session.php:156/177`:
  <https://github.com/cakephp/cakephp/blob/5.x/src/Http/Session.php#L150-L180>.
- CakePHP 2.10.24 `CakeSession.php:681/712`:
  <https://github.com/cakephp/cakephp/blob/2.10.24/lib/Cake/Model/Datasource/CakeSession.php#L675-L715>.
- CakePHP app default `defaults => 'php'`:
  <https://github.com/cakephp/app/blob/5.x/config/app.php>.
- Zend `SessionConfig`:
  <https://github.com/zendframework/zend-session/blob/master/src/Config/SessionConfig.php#L239-L252>.
- Laminas `SessionConfig`:
  <https://github.com/laminas/laminas-session/blob/master/src/Config/SessionConfig.php#L273-L285>.
- Symfony `NativeSessionStorage::setOptions()`:
  <https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/HttpFoundation/Session/Storage/NativeSessionStorage.php#L315-L329>.
- Drupal session options:
  <https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/Session/SessionConfiguration.php>,
  <https://github.com/drupal/drupal/blob/11.x/core/assets/scaffold/files/default.services.yml>.
- Roundcube CVE-2025-49113 writeups:
  <https://www.offsec.com/blog/cve-2025-49113/>,
  <https://fearsoff.org/research/roundcube>.
- 115560 precondition/mitigation:
  <https://safeguard.sh/resources/blog/php-cve-2026-115560-session-upload-progress-mitigation>,
  <https://www.php.net/manual/en/session.configuration.php#ini.session.serialize-handler>.
- Public 115560 simple-gadget PoCs (context, not re-entry):
  <https://github.com/basesixtythree/B63-POC-CVE-2026-115560>,
  <https://github.com/googlesky/CVE-2026-115560>.

---

## 8. Limits and honest negative

- **No qualifying stock candidate found** for the exact intersection:
  an app that performs the 115560 `php` handler switch **and** has a stock
  `__destruct` that calls `unserialize()` on attacker-controlled data with the
  result discarded. The two halves exist in different applications.
- The survey is a **source sweep**, not an exploit run. Only the Drupal P5
  gadget and the Joomla chain have prior ASAN execution in this repo; neither
  was executed through 115560 in this survey.
- The gadget surface is **version-sensitive**: Guzzle 8 and psr7 3.x close the
  phpggc Drupal chain; `FnStream::__wakeup` closes every FnStream composition;
  Drupal P5 is the version-stable option.
- The scanner covered direct magic-method bodies and one-level
  `$this->helper()` calls. Arbitrary `$this->other->method()` chains were
  reviewed through phpggc and the prior surveys, not exhaustively enumerated;
  a multi-object chain in an unscanned package remains possible.
- Third-party plugin ecosystems (Roundcube plugins, CakePHP plugins, WordPress
  plugins beyond the 22 audited, Drupal contrib beyond the 42 audited) were not
  exhaustively downloaded. A plugin with the exact discard shape could still
  bridge Profile A/B/C; the next search should target the plugin/package
  ecosystems of the app that already has the precondition.
- The 115560 `cleanup=On` race and the carrier seed are out of scope here; see
  `docs/PLAN_115560.md` actions A/D/E.

---

## 9. Cross-class graph re-run (2026-10-31)

Re-ran the structured tools on the two trees this track depends on, to check
the "no stock re-entry destructor" finding with the current graph.

**Tools / coverage**

| item | value |
|---|---|
| ctags | Universal Ctags 6.2.1 |
| ast-grep | 0.45.3 |
| semgrep | 1.176.0 |
| ripgrep | 15.2.0 |
| PHP (facts) | 8.5.12 CLI, `tools/gadget/php` nikic/php-parser (vendor installed) |
| roots | `lab-wp-zendmm/webroot` (845 classes), `lab-roundcube/roundcubemail-1.6.11` (583 classes) |
| exclusions (lab scaffolding, not stock) | `plugins/vd115560/*`, `wp-content/mu-plugins/uaf-harness.php`, `wp-content/mu-plugins/vd-harness.php`, `api/endpoint.php` |
| reports | `reports/gadgets/wordpress-graph-graph.{json,md}`, `reports/gadgets/roundcube-graph-graph.{json,md}` |

**Result — unchanged.** The only `reentry` entries are lab or locked:

- Roundcube `CachePurge::__destruct -> unserialize()`
  (`plugins/vd115560/vd115560.php:108`) — lab class.
- Roundcube `EnumMap::__unserialize -> EnumMap::unserialize -> unserialize()`
  (`vendor/dasprid/enum/src/EnumMap.php:294`) — runs under
  `BG(serialize_lock)`, so it takes the fresh `var_hash` branch (`blocked`, per
  §1 of this survey), not the re-entry.
- WordPress `WP_UAF_Gadget` / `WP_VD_Gadget` `__destruct -> unserialize()`
  (`wp-content/mu-plugins/uaf-harness.php:33`, `vd-harness.php:46`) — lab
  harness, excluded from the stock count.

Stock sinks exist but not through a destructor: Roundcube
`rcube_session::unserialize()` (`rcube_session.php:603`) is called from
`read`/`update` (`:220`, `:237`); `session/redis.php:133` is the store wrapper.
WordPress reaches `call_user_func` via `WP_HTML_Token::__destruct`
(`wp-includes/html-api/class-wp-html-token.php:112-114`, with a throwing
`__wakeup` at `:123-124`) and `PHPMailer::__destruct -> smtpClose -> edebug`
(`wp-includes/PHPMailer/SMTP.php:301`) — dispatch, not re-entry.

**Ceiling.** PHP-Parser edges only: no dataflow, no guard evaluation, no
autoload-order proof. Untyped-array traversal is not modelled — concretely,
`SimplePie::__destruct -> $item->__destruct()` over `$this->data['items']`
(`wp-includes/SimplePie/src/SimplePie.php:716-722`, guarded by
`!gc_enabled()`) never appears in the graph. A graph zero is therefore not
evidence of absence for that shape. Plugin/package ecosystems remain
unscanned (Roundcube plugins, WordPress plugins beyond the 22 audited).
