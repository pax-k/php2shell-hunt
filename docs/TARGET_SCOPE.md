# Target scope

## Baseline — stock default only

```text
image:      php:8.4.26-apache, linux/amd64
config:     none; no php.ini mount, no -d flags
extensions: image defaults only (opcache, sodium)
SAPI:       mod_php
allocator:  stock ZendMM
target:     loopback Apache, stock webroot
control:    php:8.4.27-apache, same defaults
```

The baseline must match a default Linux/cloud deployment. The image's `php
--ini` must report no loaded `php.ini`; the relevant `php -i` values are
captured as the baseline receipt. If the actual target is a distro package or a
cloud vendor image, capture that package's default `php.ini` and use it as the
baseline instead. Do not blend the two.

## Current first pass

One chain: **core primitive + application sink + wire trigger → allowlisted
terminal call**. Nothing else is in scope until that chain either reaches the
terminal or is proven structurally blocked.

- ASAN is a diagnostic variant, not the exploit baseline.
- A PECL extension or bundled library is opened only when the chain needs it.
- ZTS, 32-bit, big-endian, musl, Windows, macOS, and JIT variants are deferred
  until the terminal call exists and an axis is shown to matter.
- The 8.5 branch is a later control, not a first-pass target.

## Out of scope

- remote targets or production systems;
- persistence, lateral movement, reverse shells;
- arbitrary command execution;
- coverage claims from inventory rows, scanner verdicts, or blind fuzzing.

## Scope expansion rule

1. Name the exact chain precondition that is missing.
2. Show the stock baseline is negative for that precondition.
3. Add **one** axis: extension, library, SAPI, config variant, or platform.
4. Record the config diff and a control for the new axis.
5. Keep the result labeled `CONFIG-GATED` or `VARIANT` unless the stock
   baseline also reaches the terminal.

Do not expand the target because the inventory is large. Expand when the
current chain cannot proceed without it.
