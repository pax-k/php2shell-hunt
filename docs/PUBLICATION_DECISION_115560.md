# Publication / embargo decision — 115560 + var_destroy

> **Superseded on 2026-10-31.** Section 6 recorded a local-only decision with no
> external send. The repository is now published, including this package, under
> the decision recorded in `docs/RESPONSIBLE_PUBLICATION.md`. The novelty
> corrections and the credits in this document still stand; the "no publish"
> boundary does not.

**Date:** 2026-10-31  
**Status:** **DECISION: document everything locally.** The user selected
“document everything locally and write security reports and a blog post
containing everything — in `.md` format.” No external send, no publish, and no
vendor contact has occurred; the package is a local draft. The carrier
technique remains unpublished externally until a separate send decision.

Inputs: `NOVELTY_115560_2026-10-31.md`, `PHASE1_2_115560_RESULTS.md`,
`DEFENSE_115560.md`, `PHASE0_115560_FREEZE.md`.

## 1. What the novelty pass established

The four-stage composition is **public**:

```text
pre-auth upload-progress write (php_serialize)
  -> runtime switch to php + session_start()
  -> var_destroy re-entry UAF
  -> forged dtor_obj = zif_system
```

`ACD421/PHP` published it in `weapons/lab/fa_jammy.sh` (2026-10-26) and the
default `cleanup=On` slow-upload race in `zero1` (2026-10-21). The internal
“nobody published this composition” sentence is retracted.

The defensible delta is an **engineering/port result**:

- patched **8.4.27 / 8.5.12** pre-auth end-to-end;
- **cleanup=On race + var_destroy terminal** on both builds;
- **arm64 no-`/proc`** measured full-window result;
- measured raw-session carrier and per-build constants;
- real-app profiles: Drupal 11.4.11 P5 (config-gated) and Roundcube 1.6.11
  (plugin-assisted; stock db/redis blocked).

No new CVE, no “first”, no “default PHP”, no new `disable_functions` or
multi-worker technique.

## 2. Options

### A. Publish everything now

Include the carrier placement, constants, race timing, Drupal/Roundcube
profiles, and the defense note.

- Pro: maximum reproducibility; honest record; the composition is already
  public, so the marginal uplift is limited.
- Con: publishes a working pre-auth exploit for an unpatched CVE; the narrow
  delta is engineering, so there is little novelty gain.
- Risk: **high misuse**; no defensible “new research” claim.

### B. Publish composition + patched-build/arm64 result; withhold the turnkey
carrier/constants/timing for a fixed period

- Pro: least misleading if a citable result is wanted; credits prior art;
  documents the real-app profiles and the defense gap without shipping a
  turnkey exploit; can coordinate with the PHP project or a vendor.
- Con: the withheld material is not conceptually novel and is partially
  inferable from public work; a determined reader can reconstruct it.
- Risk: **medium**; requires a review date and a clear disclosure policy.

### C. Publish only a defensive/measurement note; keep the carrier indefinite

- Pro: lowest misuse risk; focuses on `upload_progress=Off`, removing/pinning
  the runtime handler switch, and the non-mitigations
  (`disable_functions`, app `unserialize()` fixes).
- Con: low reproducibility; the composition is already public, so this does
  not remove the underlying issue; may look like withholding known public
  mechanics.
- Risk: **low misuse**; high ambiguity about what is actually being withheld.

## 3. Recommendation (for discussion, not a decision)

If the goal is a citable, defensible result: **Option B**, with a fixed review
date, explicit credit to `ACD421/PHP`, B63, googlesky, mnk-works,
TheCyberGeek/Qi Deng, dinosn, and Calif, and a clear statement that the
composition is public.

If the goal is defensive impact: **Option C**, expanded with the verified
non-mitigations and the Drupal/Roundcube config/plugin caveats.

Option A is hard to justify on novelty grounds after the public prior art.

## 4. Claims to use / avoid

Use:

> CVE-2026-115560 as a pre-auth delivery path for the var_destroy UAF on
> patched PHP 8.4.27 / 8.5.12 — a patched-build, default-`cleanup=On`,
> no-`/proc` arm64 reproduction and carrier/race engineering result. The
> composition is public (`ACD421/PHP`); this work extends it to the patched
> builds and arm64 deployment profile.

Avoid:

- “first”, “nobody”, “novel composition”, “new class of exploit”;
- “new CVE”, “default PHP”, “works on any PHP”;
- “new `disable_functions` bypass”, “new multi-worker/pinning technique”;
- “stock Roundcube chain” (it is plugin-assisted);
- “default Drupal chain” (it needs the non-default `serialize_handler: php`).

## 5. Required before any external send

1. User chooses A, B, or C.
2. If B/C: define the withheld set, review date, and recipient/venue.
3. Credit prior art and link the novelty matrix.
4. Re-read `AGENTS.md`: lab-only, benign allowlist, no remote targets.
5. No attacker tooling beyond the fixed benign command.

## 6. Decision (2026-10-31)

The user chose: **document everything locally and write security reports and a
blog post containing everything, in `.md` format; launch subagents; do not omit
anything of value.**

This is effectively a **local full-disclosure package** (closest to Option A
for content), with an explicit **no-external-send** boundary. The package is:

- `docs/PUBLICATION_115560/SECURITY_REPORT_115560.md` — full technical report.
- `docs/PUBLICATION_115560/BLOG_POST_115560.md` — narrative blog draft.
- `docs/PUBLICATION_115560/EVIDENCE_AND_CREDITS_115560.md` — reproduction,
  evidence, constants, controls, prior art/credits.
- `docs/PUBLICATION_115560/README.md` — package index and send checklist.
- Supporting docs: `PHASE0_115560_FREEZE.md`, `PHASE1_2_115560_RESULTS.md`,
  `DRUPAL_115560.md`, `DRUPAL_AUTOLOAD_PROBE.md`, `ROUNDCUBE_115560.md`,
  `NOVELTY_115560_2026-10-31.md`, `DEFENSE_115560.md`,
  `GADGET_SURVEY_115560.md`, `RACE_WAKEUP_115560.md`, `NOFUNC_115560.md`,
  `WORKERS_115560.md`, `X86_64_115560.md`, `VAR_DESTROY_UAF.md`.

Any future external send still requires a separate explicit user decision and a
final claims/credits check. The local package does not itself authorize
publication.
