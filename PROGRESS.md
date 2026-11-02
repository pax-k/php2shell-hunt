# Progress

Append-only. Newest last.

## 2026-10-31 — scaffold and stock-baseline correction

**Change**

- Created the repo scaffold: scanner, POC transport, offline tests, lab compose,
  detection packaging, research manifests, docs, OpenCode surfaces.
- Added `GOAL.md` and `docs/RCE_PATH.md`. The primary objective is local RCE on
  a stock-default deployment; current status is **NOT ACHIEVED**.
- Removed the custom `lab/php.ini` and its compose mount. The lab now runs the
  official image's own defaults.
- Added `tests/test_baseline.py` and gate checks that reject a php.ini mount,
  `php -d`, `0.0.0.0`, privileged mode, host networking, and unconfined
  seccomp.
- Reframed the blind-spot manifests as deferred backlog.

**Verification**

```text
$ docker run --rm php:8.4.26-apache php --ini
Loaded Configuration File: (none)
Additional .ini files parsed: .../docker-php-ext-opcache.ini,
                             .../docker-php-ext-sodium.ini

$ curl -s http://127.0.0.1:18091/ini.php
php 8.4.26, sapi apache2handler
session.upload_progress.enabled=1, cleanup=1, use_strict_mode=0,
use_only_cookies=1, memory_limit=128M, post_max_size=8M,
upload_max_filesize=2M, disable_functions=""

$ python3 scanner/check.py http://127.0.0.1:18091 --json
verdict=VULNERABLE, exit=0

$ python3 scanner/check.py http://127.0.0.1:18092 --json
verdict=PATCHED, exit=1

$ scripts/check.sh
[gate] 66 checks passed
Ran 21 tests ... OK
```

**Failure**

- G1 is met; G2 is not. No memory primitive, app sink, wire trigger, or
  terminal call was shown.
- The stock image alone is not an RCE target; the sink provider is still
  unchosen.

**Next**

- Stage 1 of `docs/RCE_PATH.md`: reproduce one core primitive on the stock
  8.4.26/8.4.27 pair, or record `BLOCKED` with the exact missing lab.
- Do not open a blind-spot row or expand the platform matrix until that stage
  needs it.

## 2026-10-31 — findings import and publication

**Change**

- Imported the research track from the private `php2shell-poc` tree: 291 files
  covering `php2shell/`, `poc/` (62 verifiers), `scripts/`, `tools/gadget/php/`,
  `fuzz/`, `profiles/`, `reports/`, `detection/`, and 17 `lab-*` labs. The
  private `lab/` became `lab-chain-a/` so the stock baseline in `lab/` keeps its
  no-`php.ini` contract.
- Rewrote the framing: `GOAL.md` now tiers every claim `STOCK` / `CONFIG-GATED` /
  `LAB-ONLY` and keeps the stock objective marked unimplemented; `README.md`
  leads with the proof table, the credits, and the stated ceilings.
- Merged `docs/STATUS.md` (findings + repository contract), `docs/PIPELINE.md`
  (method + baseline invariant + Track C), `detection/README.md` (both SID sets),
  and rewrote `docs/RCE_PATH.md` around gate removal.
- Added `docs/RELEASE_MANIFEST.md`, `docs/RESPONSIBLE_PUBLICATION.md`, `LICENSE`,
  `NOTICE`, `SECURITY.md`, `CITATION.cff`, and `tests/test_poc_inventory.py`.

**Verification**

```sh
$ scripts/check.sh
[gate] 66 checks passed
Ran 25 tests ... OK

$ grep -rlE '/Users/[a-z]+/' . --exclude-dir=.git
(no output)

$ test ! -d docs/disclosure && echo absent
absent

$ grep -rn "\.\./lab/" --include="*.yml" --include="*.sh" .
(no output; imported labs now mount ../lab-chain-a/)
```

**Failure**

- The withheld `mbstring` finding is excluded from the tree; the vendor message
  has not been sent, so publication of that primitive is still pending.
- Imported verifiers predate the "new verifier needs an offline test" rule. They
  are covered by compile, by the loopback-default invariant test, and by the
  manifest, not by per-verifier tests. Recorded rather than papered over.
- `docs/PUBLICATION_DECISION_115560.md` §6 said "no external send"; superseded by
  `docs/RESPONSIBLE_PUBLICATION.md` and annotated in place.

**Next**

- Send the held `mbstring` report, then revisit the review date (2027-01-31).
- Stock-baseline work: remove one gate from a proven chain (`docs/RCE_PATH.md`
  stage 6), cheapest first.

## 2026-11-02 — Application lab package checks

**Change:** The published Drupal and Roundcube setup scripts now verify the SHA-256 of their pinned upstream archives before extraction. They preserve an existing application tree. The Drupal, Roundcube, and dependent Redis Compose files bind their exposed ports to `127.0.0.1`.

**Verification:** Isolated clean setup from the public scripts succeeded for Drupal 11.4.11 and Roundcube 1.6.11; both archive checks passed. Shell syntax and Compose parsing passed. `scripts/check.sh` passed: 66 gate checks and 25 tests.

**Limit:** No exploit reproduction was rerun for this packaging change. The published application results remain the dated lab receipts in `docs/DRUPAL_115560.md` and `docs/ROUNDCUBE_115560.md`. This is publication support, not progress on the stock-baseline G2 objective.

**Next:** A reader can rebuild either app lab from its README and run the named verifier against local containers.
