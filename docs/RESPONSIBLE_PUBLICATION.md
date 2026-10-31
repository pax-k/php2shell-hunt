# Responsible publication

**Published:** 2026-10-31
**Owner:** Andrei Popa, PaxDynamics
**Scope:** this repository as published at its first commit.

This repository contains working exploit code for PHP memory-safety bugs,
including chains that run on patched releases. That is a deliberate choice, and
this document records why, what was withheld, and what we are not claiming.

## What is published

- End-to-end chains for CVE-2026-109618 and CVE-2026-109619, both patched.
- Chain A and Chain C, application-level and orthogonal to the CVE patch.
- A pre-auth chain through CVE-2026-115560 to the `var_destroy` re-entry UAF,
  reaching `zif_system` on 8.4.27 and 8.5.12.
- The `var_destroy` re-entry UAF with its forged-object ladder on stock ZendMM.
- Real-application profiles (Drupal 11, Roundcube 1.6.11, Joomla 5) and the
  gadgets each does or does not provide.
- The full engine, labs, offsets, detection pack, and the negatives.

Every chain is labelled `CONFIG-GATED` or `LAB-ONLY`. Nothing is `STOCK`.

## Why publish

1. **The compositions are already public as working code.** The four-stage
   115560 chain was published by ACD421/PHP (2026-10-26); the `var_destroy` UAF
   by dinosn (2026-05-02), as a sister of Calif.io's MAD Bugs (2026-05-01);
   independent 115560 PoCs exist from B63 and googlesky. Withholding a port of
   public work protects nobody.
2. **The delta is measurement, not reachability.** What this repository adds is
   the patched-build and arm64 result, the control matrix (patched-negative,
   bias, `allowed_classes`, gadget removal), the worker model, the carrier
   constants, and the detection pack. Measurements are more useful published and
   falsifiable than held.
3. **The negative results are the point.** 8.2/8.3/8.5 fail at the leak shape;
   the FPM in-band leak is unsolved; x86-64 at `mmap_rnd_bits=28` is infeasible
   without an external seed; a 4.1M-execution ASAN fuzz campaign on
   `unserialize()`/`session_decode()` found no generic in-band seed. A repo that
   only published wins would misrepresent the state of the art.

## What is withheld, and why

| Item | Reason | Release condition |
|---|---|---|
| A `mbstring` SJIS-mac heap-buffer-overflow **write** | Published June 2026 as OOM/DoS with a hypothetical overflow. Our ASAN write primitive is a genuine step past that, and the bug is still unfixed on `master`. | After the vendor is contacted and acknowledges, or a stated review date |

That is the only withheld finding. The two disclosure drafts in the private
working tree are drafts; a draft is not publishable material.

## What we are not claiming

- Not a new CVE. No CVE is requested or claimed for the `var_destroy` patch-gap;
  the PHP project's policy since August 2017 has been not to issue CVEs for
  `unserialize()` memory-corruption bugs.
- Not "first" and not "novel composition" for the 115560 chain. Earlier drafts
  of that claim were retracted on 2026-10-31; the retraction is shipped in
  `docs/NOVELTY_115560_2026-10-31.md`.
- Not a stock-default RCE. `GOAL.md` G2 is unmet and stays unmet.
- Not a remote weapon. Every lab is loopback-only and pinned to `id`, `uname`,
  or `whoami`.

## Credits

9bie (core CVE ladders), dinosn (PS(id) leak shape; `var_destroy` UAF), Calif.io
(MAD Bugs), ACD421/PHP (four-stage composition), B63 and googlesky (independent
115560 PoCs), mnk-works and TheCyberGeek/Qi Deng (wire shapes), Khashayar
Fereidani (the public SJIS-mac report that the held finding extends).

## Safe use

The code here assumes a loopback lab you own. Pointing a verifier at a host you
do not own is out of scope and is not supported. The fixed command allowlist
exists so that a successful chain proves execution without producing a payload.

## Review

Review date: **2027-01-31**. At review: re-check the held `mbstring` item, re-run
the control matrix on the then-current branch, and correct any claim that has
aged out. Corrections to this repository's analysis are welcome as issues;
corrections that require exploit traffic against third-party systems are not.
