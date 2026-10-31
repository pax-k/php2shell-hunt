# GOAL — proven chains, labelled by precondition

The primary objective is unchanged: a reproducible, end-to-end **RCE** against a
loopback lab that matches a stock, generally accepted PHP deployment. The only
command that may be executed is `id`, `uname`, or `whoami`.

**Current status: NOT ACHIEVED for the stock baseline.** No chain in this
repository runs on an unmodified official image with image defaults and no
application precondition. What the repository does contain is a set of
end-to-end chains that are proven, labelled, and controlled, under the tiers
below. Do not read a `CONFIG-GATED` result as the holy grail.

## Claim tiers

Every result in this repository carries exactly one tier.

| Tier | Meaning | What it requires |
|---|---|---|
| `STOCK` | Runs on the official image, image defaults, no app precondition | The holy grail. **Nothing here is `STOCK`.** |
| `CONFIG-GATED` | Needs a named non-default setting, app behaviour, or delivery shape | The gate is named in one line and has its own control |
| `LAB-ONLY` | Needs a lab endpoint, harness, or planted class | The harness is in the repo and labelled |

A chain is promoted only by removing a gate, not by rewording the claim.

## Non-negotiable baseline

The stock baseline is the image's own default, not a tuned lab:

- official `php:8.4.26-apache` image, linux/amd64;
- no `php.ini` mount, no `-d` overrides, no copied distribution config;
- only the image's own `conf.d` extensions (`opcache`, `sodium`) and compiled
  defaults;
- loopback binding only.

A config override is allowed only as a **labelled control or variant**, never as
the only way the chain works. If a chain needs an override, the result is
`CONFIG-GATED`, not the holy grail.

## Acceptance list — stock baseline

- [x] **G1 — baseline.** The vulnerable image runs with stock defaults and its
      `php --ini` / `php -i` receipt is recorded (see `docs/STATUS.md`).
- [ ] **G2 — terminal.** One wire-level request path reaches a local command
      call and returns the output of an allowlisted command, with no config
      gate and no application precondition.
- [ ] **G3 — source.** The chain cites `file:line` for the core primitive, the
      app/extension sink, and the trigger mapping. `read` and `executed`
      evidence are separate.
- [ ] **G4 — controls.** The patched image is negative, the gadget/sink removal
      is negative, and a bias/`allowed_classes` control is recorded.
- [ ] **G5 — worker.** Producer and consumer worker model is measured, not
      assumed.
- [ ] **G6 — reliability.** The terminal call succeeds across a stated number
      of attempts and at least two fresh containers.
- [x] **G7 — scope.** No remote target, persistence, lateral movement, reverse
      shell, or arbitrary command. Enforced in `poc/lib.py`, `scanner/check.py`,
      and `AGENTS.md`.

## Proven results — labelled, with receipts

Each row prints the output of an allowlisted command in a lab. `read` evidence
is the source or ASAN trace; `executed` is the lab run that printed the command
output.

| Chain | Tier | Build / SAPI | Printed receipt | Doc |
|---|---|---|---|---|
| CVE-2026-109618 OOM → `zif_system`, in-band, no `/proc` | `CONFIG-GATED` | 8.4.26 mod_php, arm64 | `uid=33` | `docs/STATUS.md` §2 |
| CVE-2026-109619 leak → `zif_system` | `CONFIG-GATED` | 8.4.10–8.4.26 mod_php | `uid=33` | `docs/STATUS.md` §2 |
| Chain A — session poisoning + LFI | `CONFIG-GATED` | 8.2.35 / 8.4.27 / 8.5.12 | marker + `uid=33` | `docs/STATUS.md` §2 |
| Chain C — handler mismatch + gadget | `CONFIG-GATED` | 8.2.35 / 8.4.27 / 8.5.12 | `uid=33` | `docs/STATUS.md` §2 |
| CVE-2026-115560 → `var_destroy` → `zif_system` | `CONFIG-GATED` | 8.4.27 / 8.5.12 | `uid=33` | `docs/PUBLICATION_115560/` |
| `var_destroy` re-entry UAF → terminal | `LAB-ONLY` | 8.4.26 / 8.4.27 / 8.5.12 | `uid=33` | `docs/VAR_DESTROY_UAF.md` |
| Drupal 11.4.11 P5 real session decoder | `CONFIG-GATED` | 8.4.27 / 8.5.12 | `uid=33` | `docs/DRUPAL_115560.md` |
| Roundcube 1.6.11 plugin-assisted | `LAB-ONLY` | 8.4.27 / 8.5.12 | `uid=33` | `docs/ROUNDCUBE_115560.md` |

The stock-default objective is met by none of these. Each carries the gate that
keeps it off the top tier; `docs/STATUS.md` §6 lists what actually stops each
one.

## What does not count

- a scanner verdict;
- a SIGSEGV or ASAN report on its own;
- a static gadget path;
- a session marker;
- a config-gated demo presented as stock;
- "the extension is loaded" or "the library is present";
- a reproduction of a published chain presented as a discovery.

## Work selection

For the stock baseline, until G2 is met, every iteration must either:

1. remove one named gate from a proven chain, with a control showing the gate
   is what was doing the work; or
2. produce a required control for that chain.

Blind-spot breadth is backlog. Open one blind-spot row only when the current
chain needs that extension, library, parser, or non-memory condition.
