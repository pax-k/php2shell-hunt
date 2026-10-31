# Defense note — CVE-2026-115560 + var_destroy carrier

**Date:** 2026-10-31  
**Scope:** lab-verified behavior in this repo. Targets `127.0.0.1`; fixed
benign command `id>/tmp/vd 2>&1`. Published 2026-10-31; see
`docs/RESPONSIBLE_PUBLICATION.md`.

This note separates **what was verified here** from general advice. Commands
and evidence live in `docs/PHASE0_115560_FREEZE.md`,
`docs/RACE_WAKEUP_115560.md`, `docs/NOFUNC_115560.md`,
`docs/DRUPAL_115560.md`, `docs/ROUNDCUBE_115560.md`, and
`docs/GADGET_SURVEY_115560.md`.

## 1. What the verified chain does

```text
session.upload_progress (php_serialize write)
  -> app/runtime ini_set('session.serialize_handler','php')
  -> session_start() decodes the progress value after "|"
  -> var_destroy frees the 1018-element var_entries chunk
  -> attacker __destruct sprays + re-enters unserialize('R:1020;')
  -> freed chunk is reclaimed; forged reference/object
  -> handlers->dtor_obj = zif_system
  -> fixed command (proof: uid=33)
```

The important property is that the **session decoder is the
`unserialize()` sink**. Application-level `unserialize()` hardening does not
apply to this path.

## 2. Verified non-mitigations

### 2.1 `disable_functions` does not block the terminal

On 8.4.27 `:18203` with
`disable_functions=system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec`:

- `function_exists('system') === false`;
- a direct `system()` call is fatal;
- the forged `zif_system` pointer still writes `uid=33` to `/tmp/vd`.

The forged call enters the C function directly, so PHP-level function
removal is irrelevant. Control: `--bias-zif 0x1000` produces no proof.
Evidence: `docs/NOFUNC_115560.md`.

### 2.2 Application `unserialize()` controls do not apply

The payload reaches `php_var_unserialize()` inside the session decoder, not an
application call. Therefore:

- replacing app `unserialize($x)` with
  `unserialize($x, ['allowed_classes' => false])`;
- avoiding app-level deserialization;
- input validation on app parameters;

does **not** stop this delivery path. The session decoder still runs.

### 2.3 A simple `__destruct` gadget is enough for the public path

Even without the var_destroy carrier, the public 115560 path reaches a plain
destructor (`FileCache`, `Logger`, `VdSimple`) and executes a command. A WAF
rule aimed only at the var_destroy payload shape does not cover that path.
Evidence: `docs/GADGET_SURVEY_115560.md`, `docs/ROUNDCUBE_115560.md`
(simple-gadget proof).

## 3. Effective mitigations

Ordered by how directly they remove the precondition.

1. **Disable upload progress** — `session.upload_progress.enabled=0`.
   This removes the writer that puts attacker bytes in the session file before
   the app runs. Verified negative on `:18202`: no dtor, no proof.
2. **Remove the runtime handler switch** — do not call
   `ini_set('session.serialize_handler','php')` (or pass
   `serialize_handler => php` to `session_start()`) on a server configured for
   `php_serialize`/`php_binary`. Verified negative on `/noswitch.php`: HTTP
   200, no proof.
3. **Pin the handler with `php_admin_value`** — in FPM/mod_php config use
   `php_admin_value[session.serialize_handler] = php_serialize` (or the
   intended handler). `php_admin_value` makes the runtime `ini_set()` fail;
   `php_value` does **not** (the app can still switch). This is the strongest
   server-side control when the app needs a different handler.
4. **Single consistent handler** — if the site must use `php_serialize`
   everywhere, do not run code paths that switch to `php` for the same session.
   The mismatch is the enabling condition.
5. **Session file isolation** — keep `session.save_path` outside the web root
   and not includable. This does not stop 115560 by itself, but it blocks
   session-file-inclusion variants (Chain A).
6. **Patch tracking** — the var_destroy UAF survives the 109618/109619 patch
   (verified on 8.4.27/8.5.12). Treat it as a separate memory-safety issue, not
   as fixed by the 115560 mitigations.

## 4. Application-profile notes

### Drupal 11.4.11

- The stock P5 gadget reaches the terminal through 115560, but only with the
  non-default `session.storage.options.serialize_handler: php` line.
- Removing that line removes the 115560 precondition for this gadget. The
  var_destroy UAF still needs a different sink.
- Evidence: `docs/DRUPAL_115560.md` (G1 PASS on 8.4.27/8.5.12).

### Roundcube 1.6.11

- Stock Roundcube does **not** combine both halves: the
  `ini_set(...,'php')` call exists only in db/redis/memcache session drivers,
  and those read their own store, so the upload-progress file is never
  decoded.
- A plugin that switches the handler before `session_init()` while
  `session_storage='php'` reads the same file reproduces the terminal. That is
  a plugin/custom-code profile, not a stock chain.
- A server-level `session.save_handler=redis` aligned with Roundcube's redis
  keyspace is theoretically possible but was **not** tested or claimed.
- Evidence: `docs/ROUNDCUBE_115560.md` (G2 PASS for the plugin-assisted
  profile; stock db/redis blocker reproduced).

## 5. Detection notes (candidate, not validated)

These are candidate signals, not tested detection rules:

- a session file/record containing `upload_progress_` followed by a long
  `a:1018:{...}` array with duplicate `i:99999` keys;
- multipart uploads that keep a progress record alive across requests
  (streaming body + concurrent same-SID request), especially with
  `session.upload_progress.cleanup=On`;
- `session.serialize_handler` changing from `php_serialize` to `php` within a
  request (PHP-level logging/audit hook, if available);
- workers dying during `session_start()` after a progress upload (SIGSEGV),
  which is a symptom, not proof of RCE.

Validation of any rule belongs in `detection/`; this section is not a
detection claim.

## 6. Bottom line

- `disable_functions` and application `unserialize()` fixes are not
  sufficient.
- The robust controls are to **remove the upload-progress writer** and/or
  **remove/pin the runtime handler switch**.
- Drupal P5 and the Roundcube plugin profile are config/plugin-gated, not
  default-app chains. The novelty check (`docs/NOVELTY_115560_2026-10-31.md`)
  shows the composition itself is public; this note is about defense and
  evidence, not a new vulnerability claim.
