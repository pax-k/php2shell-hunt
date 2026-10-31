# lab-drupal — Drupal 11.4.11 P5 profile

LAB-ONLY, loopback only. This lab tests the CVE-2026-115560 session-decoder
entry point against Drupal 11.4.11 core. The fixed terminal command is
`id>/tmp/vd 2>&1`; there is no arbitrary-command interface.

## What it shows

Drupal 11.4.11 supplies a re-entry path through shipped core classes:

```text
YamlCacheCollectorDiscovery::__destruct()
  -> MenuActiveTrail::destruct()
  -> CacheCollector::updateCache()      (8135-byte lock-name spray)
  -> MemoryBackend::get() -> prepareItem()
  -> unserialize($prepared->data)       (var_destroy re-entry)
```

The consumer endpoint switches the session serializer to `php` at runtime
before `session_start()`. On the producer side, upload progress writes the
record under `php_serialize`. The gate is the consumer configuration:
`session.storage.options.serialize_handler: php` is not in Drupal's default
scaffold.

## Build and run

```sh
./setup.sh                 # downloads Drupal 11.4.11 into html/ (not tracked)
docker compose up -d       # :18300 (8.4.27), :18301 (8.5.12), :18302 (race)
```

Requirements: `docker`, `curl`, `tar`. The application tree is downloaded from
the official Drupal release and is deliberately excluded from Git.

## Profiles

| Port | Build | Profile |
|---|---|---|
| 18300 | 8.4.27 | direct, `session.upload_progress.cleanup=Off`, one child |
| 18301 | 8.5.12 | direct, `session.upload_progress.cleanup=Off`, one child |
| 18302 | 8.4.27 | default `cleanup=On` race, multiple children, persistent seed |

The direct profile and the race profile have different worker models and
carrier placement. Do not reuse one profile's delta for the other.

## Driver

```sh
python3 poc/verify_115560_drupal.py --target 127.0.0.1:18300 --build 8.4.27
```

Controls: `--cid-len 100` removes the required allocation shape,
`--bias-zif 0x1000` uses the wrong target address, and the race profile adds
`--settle`/`--no-seed` negatives. `endpoints/vd_nopreload.php` checks decoding
without the harness `class_exists()` preload.

## Limits

- Configuration-gated: requires the non-default consumer serializer line.
- Lab harness supplies carrier placement; this is not a remote-ready exploit.
- The race result is recorded on 8.4.27 only.
- See `docs/DRUPAL_115560.md`, `docs/DRUPAL_AUTOLOAD_PROBE.md`, and
  `docs/PUBLICATION_SERIES/REAL_APPLICATIONS.md`.
