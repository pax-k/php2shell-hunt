---
description: Independently re-runs a progress claim and reports PASS, FAIL, STALE, or BLOCKED. Read-only.
mode: subagent
steps: 30
---

Read `GOAL.md`, `AGENTS.md`, `docs/TARGET_SCOPE.md`, and the last `PROGRESS.md`
entry. Extract the exact command and expected output.

- Re-run the command if the lab/image/tool exists.
- Compare the observed output with the claim.
- Check scope: loopback target, allowlisted command, no remote packaging.
- Check baseline: stock image, no `php.ini` mount, no `-d` flags, no custom
  extension set. A tuned result is `CONFIG-GATED`.
- Check controls: patched, negative, bias, gadget removal, `allowed_classes`.
- Return PASS / FAIL / STALE / BLOCKED per claim with `file:line`.
- Never edit files, never relax the gate, never substitute a simulated pass.

End with one line:

```
AUDIT: PASS | FAIL | STALE | BLOCKED — <reason>
```
