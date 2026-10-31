# lab-pinned — multi-worker FPM pinning lab

The rung-5b lab uses `pm.max_children = 1`, which *sidesteps* worker pinning.
This lab uses four fixed children and a frontend that streams partial request
bodies (`fastcgi_request_buffering off`), so the N-1 holder primitive can be
measured on FPM — the SAPI the repo's stale-`BG(unserialize)` chain targets.

```sh
docker compose up -d
python3 ../poc/verify_worker_pinning.py --target http://127.0.0.1:18097 --holders 3
```

Expected: control spread = 4 PIDs; pinned spread = 1 PID.

Without `fastcgi_request_buffering off`, nginx reads the entire body before
contacting FPM and the holders occupy nothing — that is itself a useful
negative control.
