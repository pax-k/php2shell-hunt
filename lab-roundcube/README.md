# lab-roundcube — plugin-assisted Roundcube 1.6.11 profile

LAB-ONLY, loopback only. Compose publishes each web port on `127.0.0.1` only. This lab tests the CVE-2026-115560 session-decoder
entry point against Roundcube 1.6.11. The fixed terminal command is
`id>/tmp/vd 2>&1`; there is no arbitrary-command interface.

## What it shows

Plugins load before session initialization (`rcmail.php:111` vs `:116`), so a
plugin's top-level code runs before `session_start()`. The tracked plugin
`plugin/vd115560/vd115560.php` uses that window to:

1. perform the same `ini_set('session.serialize_handler', 'php')` that stock
   `rcube_session::register_session_handler()` performs only for `db`, `redis`,
   `memcache`, and `memcached` storage;
2. define the `VdSimple` and `CachePurge` gadget classes used by the proof.

Stock Roundcube 1.6.11 does not combine both halves: the database and Redis
drivers perform the switch but read their own store, while the native `php`
driver reads the upload-progress file but does not switch the handler. This
profile is therefore **plugin-assisted**, not a stock Roundcube result.

With the plugin, the profile reaches the fixed command on PHP 8.4.27 and
8.5.12. `touch /tmp/rc-vd-noswitch` or `/tmp/rc-vd-nogadget` disables the two
plugin contributions; `--bias-zif 0x1000` is the address control. Recorded
outputs are in `evidence/`.

## Build and run

```sh
./setup.sh                 # downloads Roundcube 1.6.11 into html/ (not tracked)
docker compose up -d       # :18310 (8.4.27), :18311 (8.5.12)
```

Requirements: `docker`, `curl`, `tar`, `shasum`. The setup verifies the pinned release archive before extraction. The application tree is downloaded from
the official release asset and is deliberately excluded from Git.

## Driver

```sh
python3 poc/verify_115560_roundcube.py --target 127.0.0.1:18310 --build 8.4.27
```

The 8.5.12 profile includes `disable_functions=array_first` so the Roundcube
1.6.11 polyfill can load; that is a compatibility shim for this lab, not part
of the vulnerability.

## Limits

- Plugin-assisted: the switch and the re-entry destructor are lab code.
- The carrier placement and address are measured per request shape and build.
- No default-Roundcube or remote-target claim follows from this profile.
- See `docs/ROUNDCUBE_115560.md` and `docs/PUBLICATION_SERIES/REAL_APPLICATIONS.md`.
