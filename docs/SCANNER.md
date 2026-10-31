# Scanner contract

`scanner/check.py` is a **lab tool**. It opens a socket only after the target
host passes the loopback check.

## Scope

Accepted hosts:

- `localhost`
- `127.0.0.0/8`
- `::1`

Any DNS name, public IP, private-network IP, or `0.0.0.0` is rejected with exit
code `2` before a connection is attempted. There is no remote override.

## Stock baseline

The lab is the official image with **no** `php.ini` mount and no `-d` flags.
Relevant stock values: upload-progress on, cleanup on, `use_strict_mode=0`,
`use_only_cookies=1`, `memory_limit=128M`, `post_max_size=8M`,
`upload_max_filesize=2M`. A scanner result obtained after changing those values
is `CONFIG-GATED`, not a default deployment result.

## Tiers

| Tier | Name | Request | Risk |
|---|---|---|---|
| 1 | version | `GET /` and header/body fingerprint | passive |
| 2 | upload_progress | multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` | low |
| 3 | session_write | marker filename + session readback | low |
| 4 | oom | 4 MiB multipart body | destructive, `--active` only |

Tier 3 runs only when tier 2 found a reachable upload-progress path. With stock
`cleanup=1`, the marker usually disappears before readback, so a tier-3
negative is expected and only says the endpoint does not dump the post-upload
session. Tier 4 is never implicit; it is a behavior differential against stock
size limits, not a memory-safety verdict.

## Version boundaries

| Branch | Fixed in |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

Versions below the 5.4 floor are treated as not affected. Unknown versions
produce `UNKNOWN`, not `PATCHED`.

## Verdicts

- `VULNERABLE` — version below the branch fix and upload-progress reachable, or
  the active OOM probe faulted.
- `LIKELY_VULNERABLE` — upload-progress reachable but version unknown.
- `PATCHED` — known fixed version and no active OOM signal.
- `UNKNOWN` — insufficient evidence, reachable endpoint, or skipped tiers.
- `ERROR` — no response from the target.

A verdict is a triage result, not proof of memory corruption or RCE.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | at least one target is `VULNERABLE` or `LIKELY_VULNERABLE` |
| `1` | every target is `PATCHED` |
| `2` | at least one `UNKNOWN`/`ERROR`, bad input, or scope rejection |

Batch exit codes preserve vulnerable precedence: `PATCHED` + `VULNERABLE` is
still `0`; `PATCHED` + `UNKNOWN` is `2`.

## Usage

```sh
python3 scanner/check.py http://127.0.0.1:18091
python3 scanner/check.py http://127.0.0.1:18091 --json
python3 scanner/check.py --targets - --json < targets.txt
python3 scanner/check.py http://127.0.0.1:18091 --active
```

`--active` prints a warning to stderr. Use it only against a disposable lab.

## JSON shape

A single target returns one object; a batch returns a list. Fields:

```text
target, verdict, confidence, version, sapi, checks, chains,
recommendation, error
```

`checks` contains `version`, `upload_progress`, and optional `session_write`
and `oom` objects. Per-tier exceptions are recorded in `checks` and do not
abort the batch.

## Ceiling

- Fingerprinting depends on headers exposing `PHP/x.y.z`.
- Upload-progress reachability requires the endpoint to call `session_start()`.
- A reflected marker depends on the endpoint echoing session state.
- The OOM probe is a behavior differential, not a memory-safety verdict.
- The scanner does not attempt exploitation, file inclusion, or command
  execution.
