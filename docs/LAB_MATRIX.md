# Lab matrix

Four unprivileged official Apache images, bound to loopback only, running their
own defaults. The 8.4 pair is the active first-pass baseline; the 8.5 pair is a
later control.

| Version | Port | Expected | Purpose |
|---|---|---|---|
| 8.4.26 | 18091 | vulnerable | active baseline |
| 8.4.27 | 18092 | patched | required negative control |
| 8.5.11 | 18093 | vulnerable | deferred branch control |
| 8.5.12 | 18094 | patched | deferred branch control |

## Commands

```sh
scripts/lab_matrix.sh list
scripts/lab_matrix.sh defaults
scripts/lab_matrix.sh up php-8.4.26 php-8.4.27
scripts/lab_matrix.sh status
scripts/lab_matrix.sh logs
scripts/lab_matrix.sh down
```

With no service names, `up` starts only the 8.4.26/8.4.27 pair. Pass
`php-8.5.11` / `php-8.5.12` only when that control is needed. `up` runs
`lab/setup.sh` first. Setup is idempotent and writes only:

```text
lab/webroot/index.php     version and SAPI
lab/webroot/echo.php      session contents
lab/webroot/nosession.php no session_start()
lab/webroot/ini.php       selected stock ini values as JSON
```

There is **no** `lab/php.ini` and no `-d` override. The container runs the
image's compiled defaults plus its own `conf.d` files.

## Baseline receipt

```sh
docker run --rm php:8.4.26-apache php --ini
docker run --rm php:8.4.26-apache php -r \
  'foreach (["session.upload_progress.enabled","session.upload_progress.cleanup","session.use_strict_mode","session.use_only_cookies","memory_limit","post_max_size","upload_max_filesize"] as $k) echo $k,"=",ini_get($k),"\n";'
```

Stock values observed for 8.4.26:

```text
session.upload_progress.enabled=1
session.upload_progress.cleanup=1
session.use_strict_mode=0
session.use_only_cookies=1
memory_limit=128M
post_max_size=8M
upload_max_filesize=2M
```

With the lab up, the Apache SAPI reports the same values:

```sh
curl -s http://127.0.0.1:18091/ini.php
```

These are facts about the baseline, not settings to tune.

## Safety

- Ports bind to `127.0.0.1`, not `0.0.0.0`.
- Containers are not privileged and do not disable seccomp.
- No host network, no host PID, no Docker socket mount.
- No php.ini mount, no `-d` flags, no copied distro config.
- `--active` OOM probes may kill a worker; restart with
  `scripts/lab_matrix.sh down && scripts/lab_matrix.sh up`.

## Expected scanner results

```sh
python3 scanner/check.py http://127.0.0.1:18091  # vulnerable
python3 scanner/check.py http://127.0.0.1:18092  # patched
```

The scanner must never be pointed at a container port published on a non-loopback
interface. If a Docker image tag is unavailable, record `BLOCKED` with the tag
name; do not substitute a different build silently.
