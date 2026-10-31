---
description: Audit the last progress claim by re-running its command.
agent: evidence-auditor
---

Read `AGENTS.md` and the last `PROGRESS.md` entry. Extract the exact command and
expected output, re-run it if the lab is up, and return PASS/FAIL/STALE/BLOCKED
per claim with `file:line`. Never edit files or relax the gate.

$ARGUMENTS
