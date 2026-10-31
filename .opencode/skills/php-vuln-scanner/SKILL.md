---
name: php-vuln-scanner
description: Drive a loopback PHP lab toward a stock-default RCE, run its offline gates, and open one blind-spot row only when the active chain needs it. Use for PHP session, extension, bundled-library, or scanner work in this repo.
---

# PHP vulnerability scanner and hunt workflow

## Safety

- Targets: `localhost`, `127.*`, `::1` only.
- Commands: `id`, `uname`, `whoami` only.
- No remote packaging, persistence, lateral movement, or arbitrary commands.
- Stock defaults only: no `php.ini` mount, no `-d` flags, no custom extensions.
  A tuned lab result is `CONFIG-GATED`, not the holy grail.
- `--active` is destructive; use only on a disposable lab.

## Quick commands

```sh
python3 scanner/check.py --help
scripts/scan.sh http://127.0.0.1:18091
scripts/scan.sh --targets - --json < targets.txt
scripts/lab_matrix.sh up
scripts/lab_matrix.sh status
python3 -m unittest discover -s tests -v
scripts/check.sh
python3 scripts/inventory_extensions.py --self-test
python3 scripts/inventory_extensions.py
```

## Workflow

1. Read `GOAL.md` and `docs/RCE_PATH.md`. Until G2 is met, every step must move
   the core+app chain toward the terminal call or produce a control.
2. Establish the stock baseline: image digest, `php --ini`, relevant `php -i`
   values. No overrides.
3. Run tier 1–3. Use tier 4 only with `--active` in a disposable lab.
4. Open a `research/<area>.json` row only if the active chain needs it. Move it
   one state: inventory -> function/parser map -> harness -> reproduce ->
   control.
5. Record the command and output. A loaded extension is not an audit; a fuzz
   negative is only for that harness and budget; a crash is not RCE.
6. Append `PROGRESS.md` and run `scripts/check.sh`.

## Exit codes

- `0` vulnerable or likely vulnerable
- `1` all patched
- `2` inconclusive, error, or scope rejection
