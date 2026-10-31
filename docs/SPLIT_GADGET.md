# Split-gadget terminalization for the var_destroy UAF

**Status:** mechanics proven; stock-only terminal blocked by one narrow shape.
**Scope:** part of the `var_destroy` patch-gap (`docs/VAR_DESTROY_UAF.md`).
Published 2026-10-31; see `docs/RESPONSIBLE_PUBLICATION.md`.

## 1. `var_destroy` walk order is attacker-controlled

In `ext/standard/var_unserializer.c` (8.4.27):

- `var_dtor_entries` (l.44) is an append-only **FIFO**, built in `tmp_var()`
  (l.170–197) and walked `first_dtor → next` in `var_destroy()` (l.259–322).
- Entries are appended **only by `var_push_dtor_value()` on a duplicate-key
  overwrite** (`process_nested_array_data` l.500; object props l.652/662).
- So the destruction order is the order of overwrite events in the serialized
  stream; objects that are never overwritten are not in the walk.

Measured (exactly 1018 elements, 3 overwritten objects): `ABC → A,B,C`,
`CBA → C,B,A`, `BAC → B,A,C`. End-to-end, swapping the spray and re-entry
objects flips a 502 (crash) to 200 (no terminal) and vice versa.

## 2. Stock Joomla pair (no lab classes)

**(A) spray** — `Joomla\CMS\Mail\Mail::__destruct` →
`PHPMailer::smtpClose()` (`PHPMailer.php:2357`) →
`Joomla\Data\DataSet::__call('close')` (`DataSet.php:66`) →
`FnStream::close()` (`FnStream.php:108–110`) →
`Joomla\CMS\Uri\Uri::__toString` → `AbstractUri::render()` (`AbstractUri.php:160`)
concatenates attacker properties into one zend_string of
24+4+8000+1 = **8029 B** → ZendMM **8192 bin** (same as `sizeof(var_entries)=8160`).

**(B) re-entry** — `TYPO3\PharStreamWrapper\Phar\Manifest::deserializeMetaData`
(`Manifest.php:131`) → `unserialize($this->metaData, ['allowed_classes'=>false])`
(`:137`), metadata attacker-controlled → raw uppercase `R:1021;`.

## 3. Evidence

- ASAN (stock pair, `php-fuzz-full-8427:local`): `heap-use-after-free READ of
  size 8` at `var_unserializer.c:906`, `#13 var_destroy :319`, through
  `zend_objects_destroy_object → FnStream::close → Manifest::deserializeMetaData`.
- gdb controlled deref: `x0 = 0x4141414141414141` inside
  `php_var_unserialize` — the reclaimed chunk's slot is attacker bytes.
- Stock Joomla FPM (`:18188`): payload → **502 + child SIGSEGV**; reversed
  order → **200** (LogicException only).

## 4. Why the stock-only terminal is blocked — the precise blocker

`Manifest::deserializeMetaData()` calls `json_encode($result)` (`:139`) before
`$result` is destroyed. `json_encode` performs a `JsonSerializable`/`instanceof`
check on the forged object (`ce = NULL`) and faults in
`instanceof_function_slow` **before** `zend_reference_destroy →
i_zval_ptr_dtor → dtor_obj` can run.

So the remaining requirement is exact: **a stock destructor that calls
`unserialize()` on attacker data and discards the result** (no
`json_encode`/`serialize`/property use). WordPress's `WP_HTML_Token` has the
right shape (`call_user_func($on_destroy, $bookmark_name)` discards) but a
throwing `__wakeup()` marks the object `IS_OBJ_DESTRUCTOR_CALLED`, suppressing
the destructor; `SimplePie`'s direct call is `!gc_enabled()`-gated. No stock WP
spray class hits the 8192 bin.

## 5. Partial split proves the mechanics

Stock Joomla `Uri` spray + a **3-line lab sink**
(`VDSink::__destruct { $r = @unserialize($this->p); unset($r); }`), carrier in
the POST string:

```
[EVIDENCE] STOCK-CLASS SPLIT TERMINAL CALL:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

2/2 reproducible. Controls: order BA (sink before spray) → 200, no terminal;
`zif_system + 0x1000` → no terminal (SIGSEGV); non-8192 spray size → no
controlled deref.

## 5b. Better: stock Drupal 11 core chain (spray included)

P5 found a stock-only composition that avoids FnStream entirely and builds the
spray in the same destructor chain: `YamlCacheCollectorDiscovery::__destruct ->
MenuActiveTrail::destruct -> CacheCollector::updateCache` (`$cid . ':' .
__CLASS__` = 8135 B -> 8160 alloc) `-> MemoryBackend::prepareItem ->
unserialize($prepared->data)` (no allowlist, result discarded).
ASAN UAF at `var_unserializer.c:906`; stock `x0=0x41414141...`, rc 139. The
only missing piece is the carrier address (solved by the post-carrier/brute
force). See `docs/APP_SURVEY.md`.

**FnStream caveat:** its throwing `__wakeup()` suppresses `__destruct` on
8.4.27, so callable-invoker gadgets must be validated per version.

## 6. What this means for an application advisory

- The gadget set is now: **(A) stock Joomla spray exists**, **(B) stock Joomla
  re-entry exists but consumes the result**. A single stock class of the form
  `__destruct() { @unserialize($this->p); }` would close the terminal.
- Plugin/app surveys should look for exactly: `__destruct` (not `__wakeup`)
  containing `unserialize($this->something)` where the return value is
  **ignored** — that is the AC-reducing find.
