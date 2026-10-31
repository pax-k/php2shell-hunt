# RCE path — from a proven chain to a `STOCK` chain

The repository now has proven terminal calls. The remaining objective is
`GOAL.md` G2: the same terminal call with **no gate at all**. This document
tracks that single transition and nothing else.

## Required components

```text
core primitive  ->  app/extension sink  ->  wire trigger  ->  worker pairing
                ->  allowlisted terminal call (id | uname | whoami)
```

All five components are demonstrated. What is missing is the absence of a gate:
every proven chain needs a named non-default setting, an application
precondition, or a lab endpoint.

## Stage gates

| Stage | Question | Status | Receipt |
|---|---|---|---|
| 0 | Does the stock 8.4.26/8.4.27 baseline run with image defaults? | **PASS** | `docs/STATUS.md` §0 |
| 1 | Is there a reproducible core memory primitive on 8.4.26, absent on 8.4.27? | **PASS** (`CONFIG-GATED`) | 8.4 series 6/6, pos/neg/bias |
| 2 | Does one real sink decode attacker-controlled data before the trigger? | **PASS** (`CONFIG-GATED` / `LAB-ONLY`) | Chain A, Chain C, Drupal P5, 115560 |
| 3 | Can producer and consumer share or be routed to one worker? | **PASS** | 150-worker prefork, 3/3 ASLR generations |
| 4 | Does the chain reach one allowlisted terminal call? | **PASS** under a named gate | `uid=33`, labs under `lab-*/` |
| 5 | Do the patched, removal, and bias controls stay negative? | **PASS** | per-chain controls in `docs/STATUS.md` §6 |
| 6 | **Does the terminal call survive with the gate removed?** | **not started** | — |

Stage 6 is the only unmet row. A stage-1-to-5 pass under a gate is not a stage-6
pass, and the tiers in `GOAL.md` exist so that distinction cannot blur.

## The gates, cheapest first

Ranked by how little the target has to do differently from a stock install. Each
is a hypothesis until a lab run removes it.

1. **One configuration line.** Drupal 11.4.11 P5 needs
   `session.storage.options.serialize_handler: php`, a documented but non-default
   setting. Removing the gate means finding a stock app whose session storage
   already reads with that handler.
2. **An application `ini_set()`.** The 115560 chain needs a runtime switch to the
   `php` serialize handler before `session_start()`. Any application that ships
   such a call, for any reason, removes the gate. Roundcube does it for db/redis
   drivers but then reads its own store, so the store envelope is the second
   blocker there.
3. **An application sink.** Chain A and Chain C need a reachable `unserialize()`
   or an includable session path. A stock app that decodes attacker bytes with a
   loaded gadget class is the gate removal.
4. **A wire shape.** CVE-2026-109618/109619 need the OOM and leak shapes
   delivered through a front end that forwards them. The stock image reproduces
   it; a proxy or WAF that normalises the body does not.

Do not open a new surface because a gate looks hard. Removing one gate is the
whole programme.

## What counts at the terminal

A successful run shows the command, the target, the request path, the worker, and
the output of `id`, `uname`, or `whoami`. A crash, ASAN report, reflection, or
scanner verdict does not satisfy this document.

## Controls required with the terminal

- patched-build negative;
- sink/gadget removal negative;
- stock config unchanged, or the gate named in one line;
- bias / `allowed_classes` control where applicable;
- at least two fresh containers and a stated attempt count.
