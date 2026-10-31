# Gadget sweep: `lab`

Root `lab/webroot` — 14 PHP files, 3 magic methods, 4 candidates, 0 re-entry.

Candidate generation only. A hit means *read this next*, not *exploitable*; dynamic reachability and the lab decide that.

## Ranked candidates

| score | kind | class | method | sinks | where |
|---|---|---|---|---|---|
| 90 | terminal | FileLogger | __destruct | file, terminal | lab/webroot/api/endpoint.php:16 |
| 45 | terminal | - | lab_pwn | terminal | lab/webroot/pwn_probe.php:10 |
| 30 | file | - | <file> | file | lab/webroot/lfi.php:11 |
| 30 | file | - | <file> | file | lab/webroot/vuln.php:3 |

## Re-entry candidates (magic -> unserialize)

None in this tree.

## Magic method inventory

| magic method | count |
|---|---|
| __destruct | 3 |

| class | method | where |
|---|---|---|
| FileLogger | __destruct | lab/webroot/api/endpoint.php:16 |
| FileLogger | __destruct | lab/webroot/api/endpoint.php:16 |
| FileLogger | __destruct | lab/webroot/api/endpoint.php:16 |

## Stream / session markers

| file | line | text |
|---|---|---|
| index.php | 5 | echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n"; |
| probe.php | 6 | echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n"; |
| api/handler_probe.php | 2 | echo "handler=" . ini_get("session.serialize_handler") . " |

## Semgrep (candidate files only)

| rule | file | line | message |
|---|---|---|---|
| php-magic-terminal | lab/webroot/api/endpoint.php | 22 | magic method reaches a terminal command sink |

## Tools

- **ast-grep**: 6 matches
- **ctags**: ok
- **semgrep**: 1 findings
- **rg**: ok

## Reproduce

```sh
scripts/gadget_sweep.sh lab/webroot --label lab
```
