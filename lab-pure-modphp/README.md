# lab-pure-modphp — stock 8.4.26 mod_php control lab

The public chains (9bie, dinosn, devploit) are calibrated against the stock
`php:8.4.26-apache` prefork image. The repo's rung-5b lab is instrumented
(`[UAFDBG]`) and FPM; this lab is the **non-instrumented mod_php control**
needed to test the two capabilities Wiz reports as unsolved in the wild:

- **worker pinning** — 4 prefork children, 3 held with partial bodies;
- **in-band PS(id) cookie disclosure** — `display_errors=On`,
  `memory_limit=32M`, `post_max_size=48M`.

Three services, same image:

| Service | Port | Posture | Use |
|---|---|---|---|
| `php` | 18110 | `display_errors=On`, 32M/48M | leak + pinning + amplification (in-body OOM) |
| `php8m` | 18111 | `display_errors=Off`, 128M/8M | legacy 1005-part chain + chunked bypass |
| `phpA1` | 18112 | `display_errors=Off`, 128M/8M, `max_input_vars=100000`, `max_file_uploads=1000` | 9bie A1/B1 shape without parser truncation |

```sh
docker compose up -d
curl -s http://127.0.0.1:18110/probe.php
curl -s http://127.0.0.1:18111/probe.php
curl -s http://127.0.0.1:18112/probe.php
```

Note on the A1 service: stock `max_input_vars=1000` / `max_file_uploads=20`
truncate the 860 nested parts (POST count ~114), so the A1 shape cannot be
evaluated there. `:18112` lifts only those parser-count limits; memory and
post limits stay stock.

Stock upstream image; no build step. Research lab only.
