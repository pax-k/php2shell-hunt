# Testing

Tests are offline. `scanner.check.socket.create_connection` is patched to fail
the test if a tier tries to open a socket.

```sh
python3 -m unittest discover -s tests -v
scripts/check.sh
```

## Suites

| File | Covers |
|---|---|
| `tests/test_scanner.py` | loopback scope, version boundaries, exit-code matrix, quiet/JSON output, network ban |
| `tests/test_pocs.py` | command allowlist, loopback scope, verifier help and remote rejection |
| `tests/test_baseline.py` | stock defaults, no php.ini/`-d`, RCE goal is unmet, blind spots deferred |

## Exit-code matrix

The scanner test exercises every ordered pair of:

```text
VULNERABLE, LIKELY_VULNERABLE, PATCHED, UNKNOWN, ERROR
```

and asserts:

- any vulnerable → `0`;
- all patched → `1`;
- any unknown/error mixed with patched → `2`.

## Adding a verifier

1. Add `poc/verify_<claim>.py`.
2. Use `poc.lib.parse_target` before any socket.
3. Use `poc.lib.require_command` for every command.
4. Expose `--target` and `--help`; never expose `--command`.
5. Add a scope/allowlist test with no network.
6. Record the expected lab precondition in the verifier docstring.

## Adding a manifest row

`scripts/check.py` validates every `research/*.json` file and requires a
`status` field on each row. A row may stay `not-inventoried`; it may not claim
`covered` without a linked receipt.

## Ceiling

Passing tests prove the contracts above. They do not prove a target is
vulnerable, a gadget executes, or a fuzz corpus is complete.
