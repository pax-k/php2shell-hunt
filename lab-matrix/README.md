# lab-matrix — version × arch triad + distro defaults

One service per stock image, no instrumentation. Every row runs the **triad**:
fire + output (pos), patched build blocks at the leak (neg), `+0x1000` bias
prevents the fire (bias).

| Row | Vuln | Port | Patched | Port |
|---|---|---|---|---|
| 8.2 | `php:8.2.34-apache` | 18160 | `php:8.2.35-apache` | 18161 |
| 8.3 | `php:8.3.35-apache` | 18162 | `php:8.3.36-apache` | 18163 |
| 8.4.10 | `php:8.4.10-apache` | 18126 | `php:8.4.27-apache` | 18165 |
| 8.4.20 | `php:8.4.20-apache` | 18127 | `php:8.4.27-apache` | 18165 |
| 8.4.23 | `php:8.4.23-apache` | 18123 | `php:8.4.27-apache` | 18165 |
| 8.4.24 | `php:8.4.24-apache` | 18124 | `php:8.4.27-apache` | 18165 |
| 8.4.25 | `php:8.4.25-apache` | 18125 | `php:8.4.27-apache` | 18165 |
| 8.4.26 | `php:8.4.26-apache` | 18164 | `php:8.4.27-apache` | 18165 |
| 8.5 | `php:8.5.11-apache` | 18166 | `php:8.5.12-apache` | 18167 |
| distro: no `php.ini` | `php:8.4.26-apache` | 18170 | `php:8.4.27-apache` | 18175 |
| distro: Ubuntu 24.04 | apt `libapache2-mod-php` | 18171 | — | — |

```sh
docker compose up -d                    # matrix rows
docker compose --profile distro up -d --build   # G7 distro models

python3 poc/verify_matrix.py --dry-run
python3 poc/verify_matrix.py --rows 8.4 --proof lab-matrix/out/p1
```

Each service copies the untouched `php.ini-production` (single prefork child,
`/out` proof volume) so the row is a faithful "default install" model. The
`distro` services are different: `default-*` uses no `php.ini` at all
(compiled defaults), and `ubuntu-modphp` is the apt package (PHP 8.3.6,
Apache 2.4.58).

Result (2026-10-29, native arm64): **the 8.4 series is proven 6/6**
(8.4.10/20/23/24/25/26), all blocked on 8.4.27 and prevented by the `+0x1000`
bias. 8.2/8.3/8.5 and early 8.4.1 fail at the **leak shape**, not the offsets.
The Ubuntu Apache does not reproduce the lengthless `post_max_size` bypass
(parses one field); the no-`php.ini` image does. See `docs/STATUS.md` §5 P2 and
`docs/OFFSETS.md`.
