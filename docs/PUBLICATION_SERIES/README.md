# Publication series — patch gaps, applications, negatives

**Series scope:** LAB-ONLY. Targets are loopback (`127.0.0.1`/`::1`); the only
command executed is the fixed, benign `id>/tmp/vd 2>&1`; there is no
arbitrary-command interface.

This series is the **method record** of the PHP session and `unserialize()`
work in <https://github.com/pax-k/php2shell-hunt>: what a lab command showed,
what it only suggested, and what it failed to show. It is not a novelty claim.

## Why this series exists

The individual primitives here are public. The `var_destroy` re-entry UAF was
published by dinosn on 2026-05-02; the four-stage 115560 composition was
published by ACD421/PHP on 2026-10-26. What is worth writing down is the
engineering between "the primitive is public" and "the chain fires on a patched
build with controls": carrier placement, per-build constants, worker order,
which magic method actually runs unlocked, and the negatives.

Each post therefore follows the same shape:

- one claim per section, with the command that produced it;
- `file:line` for source claims, a verifier path for lab claims;
- read evidence and executed evidence kept apart;
- the controls (patched build, `+0x1000` bias, gadget removal,
  `allowed_classes=false`) beside the positive;
- a caveats block that states the ceiling.

## Posts

| # | File | Question | Status |
|---|---|---|---|
| 1 | [`PATCH_GAP.md`](./PATCH_GAP.md) | What did 109618/109619 fix, and why does the `var_destroy` dtor walk still run unlocked on 8.4.27 / 8.5.12? | published |
| 2 | [`REAL_APPLICATIONS.md`](./REAL_APPLICATIONS.md) | Which stock applications provide the re-entry destructor, and which only look like they do? | published |
| 3 | [`NEGATIVES.md`](./NEGATIVES.md) | Which leak, FPM, and magic-method routes failed, and what does each failure rule out? | published |

Post 1 carries the patch-gap evidence: ASAN at `var_unserializer.c:906`, the
stock-ZendMM ladder to the fixed benign command, the hardened
`disable_functions` run, and the arm64 window scan. Post 2 covers Drupal 11 P5
(config-gated), the Joomla 5 gadget, Roundcube 1.6.11 (plugin-assisted), and the
Redis survey negative. Post 3 collects the falsified hypotheses, including the
`__wakeup` / `__unserialize` re-entry, the in-band seed search, the version
matrix, and the FPM leak.

## Held

| Item | Status | Reason | Release condition |
|---|---|---|---|
| An `mbstring` SJIS-mac heap-buffer-overflow **write** | withheld | The June 2026 public report described OOM/DoS with a hypothetical overflow. The ASAN write primitive is a step past that, and the bug is still unfixed on `master`. | After the vendor is contacted and acknowledges, or a stated review date. |

The hold policy, the review date (2027-01-31), and the reason this is the only
withheld item are in [`../RESPONSIBLE_PUBLICATION.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/RESPONSIBLE_PUBLICATION.md).
No trigger or code for the held item appears in this series; the index names it
only so the record is complete.

## What the series does not claim

- No novelty for the composition. ACD421's `fa_jammy.sh` (2026-10-26) and
  `zero1` (2026-10-21) precede the patched-build result; the retraction is
  shipped in [`../NOVELTY_115560_2026-10-31.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/NOVELTY_115560_2026-10-31.md).
- No CVE for the `var_destroy` gap. CVE-2026-115560 is assigned; PHP's policy
  since August 2017 has been not to issue CVEs for `unserialize()` memory
  corruption.
- No default-PHP or default-application exposure. Every chain is
  `CONFIG-GATED` or `LAB-ONLY`; none is `STOCK`.
- No remote weapon. The labs are loopback-only and the terminal command is
  fixed.

## Reading order

1. [`PATCH_GAP.md`](./PATCH_GAP.md) — the core patch-gap result and its
   controls.
2. [`../VAR_DESTROY_UAF.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/VAR_DESTROY_UAF.md)
   — mechanics, the full ladder, and the honest ceilings.
3. [`REAL_APPLICATIONS.md`](./REAL_APPLICATIONS.md) — the app half, and what the
   applications do not provide.
4. [`NEGATIVES.md`](./NEGATIVES.md) — the failures that constrain every claim
   above.
5. [`../NOFUNC_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/NOFUNC_115560.md)
   — the hardened-target run.
6. [`../RACE_WAKEUP_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/RACE_WAKEUP_115560.md)
   — default `cleanup=On` and the magic-method negative.
7. [`../PUBLICATION_115560/BLOG_POST_115560.md`](https://github.com/pax-k/php2shell-hunt/blob/main/docs/PUBLICATION_115560/BLOG_POST_115560.md)
   — the long-form account this series indexes.

Corrections are welcome as repository issues. Corrections that would require
traffic against third-party systems are not.
