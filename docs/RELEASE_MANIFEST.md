# Release manifest — 2026-10-31

What this repository publishes, what stays in private working trees, and the
disclosure state that decided each row. Machine-checkable: every `shipped` path
exists in the tree; every `held` path is absent and exists only in a private
working tree. A published document outside this tree is linked in the row.

## How the split was made

Three inputs, in order:

1. **Disclosure state.** Public and patched, public and unfixed, or not public.
   Public-and-unfixed is not automatically publishable, but it is not a bar
   either; the deciding question is whether the composition is already
   available as working code.
2. **Prior-art review.** `docs/RESEARCH_REVIEW_2026-10-30.md` and
   `docs/NOVELTY_115560_2026-10-31.md` corrected two novelty claims. Anything
   whose delta is a port or a measurement is published with those credits
   attached, not as a discovery.
3. **Marginal uplift.** If a working exploit for the same bug is already
   public, publishing a measured port adds reproducibility and defence without
   adding reachability.

## Shipped

| Area | Files | Disclosure state | Tier | Note |
|---|---:|---|---|---|
| `README.md`, `GOAL.md`, `AGENTS.md`, `SECURITY.md`, `NOTICE`, `LICENSE`, `CITATION.cff` | 7 | n/a | n/a | framing and licensing |
| `docs/PIPELINE.md`, `TOOLING.md`, `TARGET_SCOPE.md`, `BLIND_SPOTS.md` | 4 | n/a | n/a | method |
| `docs/STATUS.md`, `CVSS.md`, `ANALYSIS.md`, `ATTACK_SURFACE_MAP.md` | 4 | mixed | mixed | status, scoring, surface map |
| `php2shell/` | 28 | n/a | n/a | engine: leak, offsets, matrix, ELF, gadget graph |
| `scripts/` | 14 | n/a | n/a | wrappers, report generation, offline gate |
| `tools/gadget/php/` | 12 | n/a | n/a | PHP-Parser facts emitter |
| `fuzz/` | 4 | n/a | n/a | ASAN corpus generator, runner, triage |
| `poc/` | 62 | mixed | n/a | one verifier per claim |
| `profiles/`, `reports/` | 27 | n/a | n/a | generated offsets and report output |
| `detection/` | 9 | public | n/a | ten SIDs traffic-tested under Suricata |
| `lab-*/`, `lab/`, `lab-chain-a/` | 116 | n/a | n/a | disposable labs, `setup.sh` rebuilds each |
| `tests/`, `scanner/`, `research/` | 12 | n/a | n/a | offline contracts and blind-spot manifests |
| CVE-2026-109618 / 109619 docs and PoCs | — | public, patched | `CONFIG-GATED` | reproduced un-instrumented; matrix 6/6 |
| Chains A and C | — | public, app-level | `CONFIG-GATED` | survive every patched release |
| `docs/VAR_DESTROY_UAF.md` + `poc/verify_vardestroy_*` | 14 | public since 2026-05-02 (dinosn; Calif.io) | `LAB-ONLY` | patch-gap port with controls |
| `docs/*115560*`, `docs/PUBLICATION_115560/` | 18 | composition public 2026-10-26 (ACD421) | `CONFIG-GATED` | patched-build and arm64 port |
| `docs/DRUPAL_115560.md`, `ROUNDCUBE_115560.md`, `JOOMLA_GADGET.md`, `SPLIT_GADGET.md` | 4 | public prior art where applicable | mixed | real-application profiles |
| `docs/DEFENSE_115560.md` | 1 | n/a | n/a | mitigation note shipped in the same commit |

## Held

| Path (private working tree) | Why |
|---|---|
| `docs/MBSTRING_SJISMAC_OVERFLOW.md` | Internal analysis; the corrected public version is [One byte past the buffer](https://paxdynamics.com/blog/php-mbstring-sjis-mac), published 2026-10-31. This file stays private. |
| `docs/disclosure/php-mbstring-sjismac-overflow-report.md` | Private vendor draft; not sent. Publication of the article is not vendor acknowledgement. |
| `docs/disclosure/php-var-destroy-uaf-report.md` | Superseded: the underlying bug is public, and this document restates it as a patch-gap. Kept as history to avoid implying a CVE request that the project's own policy excludes. |

References to held material were rewritten in `docs/STATUS.md`,
`docs/ATTACK_SURFACE_MAP.md`, and `docs/RESEARCH_REVIEW_2026-10-30.md` to
"held pending disclosure", with no links.

## Controls that make the shipped set defensible

- Prior art credited in `README.md`, `NOTICE`, and per-document headers.
- Two retractions (`docs/NOVELTY_115560_2026-10-31.md`,
  `docs/RESEARCH_REVIEW_2026-10-30.md`) shipped rather than hidden.
- Every chain carries its tier and its gate; `GOAL.md` keeps the stock
  objective marked unmet.
- `docs/DEFENSE_115560.md` ships with the weaponized material.
- No remote-target packaging, no post-exploitation, fixed benign command.

## Verification

```sh
grep -rlE '/Users/[a-z]+/' . --exclude-dir=.git     # empty (no absolute host paths)
test ! -d docs/disclosure                         # 0
grep -rln 'SJISMAC_OVERFLOW\.md' docs/ | grep -v RELEASE_MANIFEST  # empty
scripts/check.sh                                  # passes
```
