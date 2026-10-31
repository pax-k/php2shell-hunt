# Gadget sweep: `matrix`

Root `lab-matrix/webroot` — 5 PHP files, 0 magic methods, 0 candidates, 0 re-entry.

Candidate generation only. A hit means *read this next*, not *exploitable*; dynamic reachability and the lab decide that.

## Ranked candidates

| score | kind | class | method | sinks | where |
|---|---|---|---|---|---|

## Re-entry candidates (magic -> unserialize)

None in this tree.

## Magic method inventory

| magic method | count |
|---|---|

## Stream / session markers

| file | line | text |
|---|---|---|
| probe.php | 6 | echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n"; |

## Semgrep (candidate files only)

skipped

## Tools

- **ast-grep**: 0 matches
- **ctags**: ok
- **semgrep**: skipped
- **rg**: ok

## Reproduce

```sh
scripts/gadget_sweep.sh lab-matrix/webroot --label matrix
```
