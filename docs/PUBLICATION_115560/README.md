# Publication package — CVE-2026-115560 + var_destroy

**Status:** published 2026-10-31 with <https://github.com/pax-k/php2shell-hunt>.
The package was written as a local draft; it is now the public record, with the
hold policy in [`../RESPONSIBLE_PUBLICATION.md`](../RESPONSIBLE_PUBLICATION.md).

**Scope:** LAB-ONLY. Targets are `127.0.0.1`; the only command executed is the
fixed benign `id>/tmp/vd 2>&1`; there is no arbitrary-command interface.

## What is in this package

| File | Purpose | Audience |
|---|---|---|
| [`SECURITY_REPORT_115560.md`](SECURITY_REPORT_115560.md) | Full technical report: mechanics, evidence, gates, impact, limitations, prior art, defense | Researchers, vendors, reviewers |
| [`BLOG_POST_115560.md`](BLOG_POST_115560.md) | Narrative blog draft: the bug, the chain, the real-app work, the novelty reality check | Security blog readers |
| [`EVIDENCE_AND_CREDITS_115560.md`](EVIDENCE_AND_CREDITS_115560.md) | Reproduction commands, outputs, constants, controls, lab inventory, credits/prior art | Anyone re-running the work |
| [`../PHASE0_115560_FREEZE.md`](../PHASE0_115560_FREEZE.md) | Frozen G0 evidence and constants | Reviewers |
| [`../PHASE1_2_115560_RESULTS.md`](../PHASE1_2_115560_RESULTS.md) | Gate summary for the real-app work | Reviewers |
| [`../DRUPAL_115560.md`](../DRUPAL_115560.md) | Drupal 11 P5 direct + `cleanup=On` race | Deep dive |
| [`../DRUPAL_AUTOLOAD_PROBE.md`](../DRUPAL_AUTOLOAD_PROBE.md) | Proof that harness class preloading is not required | Deep dive |
| [`../ROUNDCUBE_115560.md`](../ROUNDCUBE_115560.md) | Roundcube plugin profile + stock db/redis blocker | Deep dive |
| [`../NOVELTY_115560_2026-10-31.md`](../NOVELTY_115560_2026-10-31.md) | Source-checked prior art and claim matrix | Editors, reviewers |
| [`../PUBLICATION_DECISION_115560.md`](../PUBLICATION_DECISION_115560.md) | Decision record and send checklist | Project owner |
| [`../DEFENSE_115560.md`](../DEFENSE_115560.md) | Verified non-mitigations and effective controls | Defenders |
| [`../GADGET_SURVEY_115560.md`](../GADGET_SURVEY_115560.md) | Stock-app gadget survey (read-only) | Researchers |
| [`../RACE_WAKEUP_115560.md`](../RACE_WAKEUP_115560.md) | `cleanup=On` race and `__wakeup` negative | Deep dive |
| [`../NOFUNC_115560.md`](../NOFUNC_115560.md) | `disable_functions` non-mitigation | Defenders |
| [`../WORKERS_115560.md`](../WORKERS_115560.md) | Multi-worker / pinning | Deep dive |
| [`../X86_64_115560.md`](../X86_64_115560.md) | amd64/Rosetta profile | Deep dive |
| [`../VAR_DESTROY_UAF.md`](../VAR_DESTROY_UAF.md) | Underlying UAF mechanics | Deep dive |

## The claim in one paragraph

CVE-2026-115560 provides a **pre-auth delivery path** into the `var_destroy`
re-entry UAF on patched PHP 8.4.27 / 8.5.12. The attack writes attacker bytes
through the upload-progress hook under `php_serialize`, the application switches
to the `php` handler, and `session_start()` decodes the value after `|`; the
session decoder itself is the `unserialize()` sink. A 1018-element array with a
duplicate key puts a destructor in the delayed-dtor list; the destructor sprays
a same-size string and re-enters `unserialize('R:1020;')`, reclaiming the freed
`var_entries` chunk with a forged reference/object whose `dtor_obj` is
`zif_system`. On stock ZendMM the fixed benign command writes `uid=33`.

The **composition is public** (`ACD421/PHP`, `fa_jammy.sh`, 2026-10-26; the
`cleanup=On` race in `zero1`, 2026-10-21). This package's defensible delta is
the **patched-build, default-`cleanup=On`, no-`/proc` arm64** end-to-end result,
the measured raw-session carrier/constants, and the real-app profiles:

- **Drupal 11.4.11 P5** — stock core gadget, **config-gated** by the non-default
  `session.storage.options.serialize_handler: php` line; direct + race PASS.
- **Roundcube 1.6.11** — **plugin-assisted** profile PASS; stock db/redis
  sessions cannot combine the switch with the upload-progress file read.

Not claimed: default PHP, “first”, a new composition, a new CVE, a new
`disable_functions` bypass, or a new pinning/multi-worker technique.

## Pre-send checklist (if a send is ever approved)

- [ ] User explicitly approves the external send separately.
- [ ] Credit `ACD421/PHP`, B63, googlesky, mnk-works, TheCyberGeek/Qi Deng,
      dinosn, Calif, 9bie, devploit, and the Roundcube CVE authors.
- [ ] State that the composition is public and this is a patched-build/arm64
      engineering result.
- [ ] Keep the Drupal/Roundcube framing config-gated / plugin-gated.
- [ ] Re-check `AGENTS.md`: lab-only, benign allowlist, no remote targets.
- [ ] Choose venue/date and a review period for the carrier/constants.
- [ ] Re-run `scripts/check.sh` and confirm no unintended files changed.
