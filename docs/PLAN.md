# Adaptive RCE Verification Driver — Plan

Author: (this repo) · Status: Phase 6 done; see [`STATUS.md`](STATUS.md)
for the current RCE scenario matrix and prioritized research backlog.

## Objective

A single driver script that, against **this repo's own labs**, automatically:

1. **fingerprints** the target (application type, PHP version, SAPI, session config),
2. **determines conditions** and maps them to an applicable RCE strategy,
3. **executes** the selected chain end-to-end and **returns `id` output**
   (`uid=33(www-data) ...`) over HTTP.

Invocation:

```
python3 php2shell_adaptive.py <lab-host> [-p PORT] [-c id] [--app auto|generic|wordpress|joomla] [--strategy auto|rung5b|chain_c|chain_a]
```

## Scope guardrails (locked, non-negotiable)

These mirror the guardrails already enforced by this repo's `php2shell.py`
and `poc/*` scripts:

- **Lab targets only** — `localhost`, `::1`, or `127.*`. Remote hosts are
  refused with a pointer to the authorized-engagement tooling.
- **Benign allowlist only** — `id | uname | whoami`. No arbitrary commands,
  no reverse shells, no shell metacharacters.
- **No remote ASLR / base-discovery leak stages.** The memory-corruption
  chain (rung-5b) runs only against the instrumented lab, where the
  `[UAFDBG] zsys=` calibration oracle exists.
- **Output** is a fixed, allowlisted command with webroot redirection
  (`cmd>/var/www/html/p 2>&1`) or the Chain-C gadget echo — no
  arbitrary-target packaging.

## Architecture

```
php2shell_adaptive.py         # thin entry -> php2shell.driver:main()
php2shell/
  __init__.py
  guard.py                    # host allowlist + command allowlist
  probe.py                    # raw-socket HTTP + multipart helpers
  apps.py                     # per-app adapters (no static port registry)
  fingerprint.py              # TargetProfile + detection
  dockerutil.py               # dynamic [UAFDBG]-container discovery + docker helpers
  strategies.py               # condition -> chain decision table
  engine.py                   # Chain A (inline), Chain C + rung-5b (POC-backed)
  driver.py                   # orchestration + structured report
  pinning.py                  # post-Wiz: N-1 stalled holders + PID oracle
  amplify.py                  # post-Wiz: duplicate-header amplification + chunked send
  sapi.py                     # post-Wiz: SAPI/limit/worker profile
  lfi.py                      # post-Wiz: auto-LFI parameter discovery
  leak.py                     # post-Wiz: rung-6 leak shapes + derivation
  capabilities.py             # post-Wiz: capability registry (--capabilities)
```

The post-Wiz capabilities are **orthogonal to the RCE strategy table**:
`--capabilities` prints the matrix, `--capability <key>` runs one primitive
against a lab. They do not weaken the existing host/command guards.

There is **no static port → flags/container map**. The instrumented rung-5b
container is discovered at run time (`dockerutil.discover_container`): the
driver triggers `obj_probe.php` on the target, then looks for the `[UAFDBG]`
oracle print in the fresh docker logs of the PHP containers — so the target
is tied to its own container regardless of port.

## Strategy decision table

Priority-ordered; the driver verifies preconditions live before firing and
reports why it declined when nothing applies.

| # | Strategy | Preconditions | Target | Portable |
|---|----------|---------------|--------|----------|
| 1 | rung5b (CVE-2026-109619 weaponized) | docker + `obj_probe.php` + a `[UAFDBG]`-instrumented FPM container behind the target | discovered dynamically (e.g. `lab-zendmm-fpm`, `lab-wp-zendmm`) | per-build calibration |
| 2 | chain_c (handler mismatch → `__destruct`) | `php_serialize` write dir + `php` read dir + loaded gadget class | generic (`/app` + `/api`) | 5.4–8.5 |
| 3 | chain_a (session inject + LFI) | `upload_progress.enabled=On` + reachable LFI | generic (`/lfi.php`) | 5.4–8.5 |

## Honest ceilings (must not be papered over)

- **rung-5b is per-build.** Its forge offsets and `zif_system` address are
  derived for each instrumented build; it is not portable to arbitrary
  PHP builds.
- **CVE-2026-109618 has no public escalation** — it is trigger/reachability
  only; the `id` RCE proof rides CVE-2026-109619 (rung-5b) or Chains A/C.
- **A / C require application-level preconditions** (LFI, loader gadget,
  handler mismatch). A *stock* WordPress/Joomla install with none of these
  must be reported as "no applicable strategy" — not faked into success.
- **Pinning is proven at 4 workers, not at the public 150-worker default.**
  The mechanism is identical, but the lab does not claim the 149-holder
  scale or internet-latency behaviour.
- **Rung 6 is a harness, not a working leak.** The derivation is
  deterministic and unit-tested; the live B1 stage does not disclose on the
  stock 8.4.26 lab yet. Do not describe the repo as having a working remote
  ASLR bypass.

## Phases

- **Phase 1 — DONE (validated live).** `php2shell_adaptive.py` +
  `php2shell/` (guard/probe/apps/fingerprint/strategies/engine/driver).
- **Phase 2 — DONE.** `lab-joomla/` (Joomla 5.4.10 on `php:8.2-fpm` +
  mysqli/pdo_mysql Dockerfile + chain scaffolding + `sysinfo.php`),
  installed via the non-interactive CLI installer, served on `:18096`.
- **Phase 3 — DONE.** `id` output returned for all three app types:
  generic (`:18085`, Chains A/C + rung-5b), WordPress (`:18095`, rung-5b),
  Joomla (`:18096`, Chains A/C). Each returns
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.
- **Phase 4 — DONE.** Declines verified: patched builds (`:18081`,
  `:18086`) block rung-5b; `lab-defender` (`:18083`) kills Chain A
  (`upload_progress=False`) and Chain C (admin `php_serialize` removes
  the mismatch); stock WP (`:18090`) has no LFI/gadget so Chains A/C
  decline. Driver now also reports unreachable targets cleanly instead
  of tracebacking.
- **Phase 5 — DONE.** Detection pack extended (Suricata network rules +
  Sigma `file_event` rule), `detection/README.md` + `README.md` updated,
  `ANALYSIS.md` addendum (below).
- **Phase 6 — DONE (post-Wiz uplift, 2026-10-28).** Surveyed the public
  ecosystem (`docs/ECOSYSTEM.md`) and added the capabilities Wiz's
  2026-10-27 telemetry says public kits lack:
  - `php2shell/pinning.py` + `poc/verify_worker_pinning.py` — N-1 stalled
    holders; validated 4→1 PIDs on Apache prefork (`:18110`) and FPM
    (`:18097`, with `fastcgi_request_buffering off`);
  - `php2shell/amplify.py` + `poc/verify_amplification.py` — duplicate
    header amplification (21× @32M, 32× @128M) and chunked delivery;
  - `poc/verify_legacy_chain.py` — Wiz Variant-1 1005-part shape, gate
    rejection, chunked bypass;
  - `php2shell/lfi.py` + `poc/verify_lfi_discovery.py` — auto-LFI;
  - `poc/verify_session_poison_lfi.py` — Wiz's "branded but unrelated"
    session-poisoning + app LFI chain;
  - `poc/verify_content_type_bypass.py` — comma-separated Content-Type;
  - `php2shell/sapi.py` + `poc/verify_sapi_profile.py` — version/SAPI/
    exact memory_limit/worker count;
  - `php2shell/leak.py` + `poc/verify_psid_leak.py`,
    `poc/verify_a1b1_leak.py` — rung-6 harness (derivation validated;
    live B1 not yet disclosing);
  - new labs `lab-pure-modphp/` (stock 8.4.26 mod_php, :18110/:18111/:18112)
    and `lab-pinned/` (4-child FPM, :18097);
  - `php2shell/capabilities.py` + driver `--capabilities` / `--capability`;
  - detection SIDs 210961804–810 and
    `detection/iocs_php2shell_2026-10-27.yml`.
- **Phase 7 — DONE (Track B, un-instrumented core RCE, 2026-10-28).**
  Closed rung 6 and reproduced the core chain without an oracle:
  `php2shell/remote.py` + `poc/verify_109619_remote.py` reimplement the
  9bie A1/B1 → A2/B2 ladder on stock `php:8.4.26-apache`: the in-band
  `Set-Cookie` leak yields the libphp and ZendMM chunk bases, and
  `zif_system` dispatches the fixed benign `id`. Controls: patched
  `8.4.27-apache` blocks (B1 yields no heap pointers); `--bias-zif +0x1000`
  prevents the fire (load-bearing). Labs: `lab-pure-modphp :18120` (pure,
  official config, 150 workers) and `:18121` (purepatched 8.4.27).
  Remaining: Phase-4b portability, the FPM leak (4c), native-arch ASLR
  cross-check. See the Track-B plan and `docs/STATUS.md` §5.

- **Phase 8 — IN PROGRESS (portability / general-defaults, 2026-10-29).**
  Plan: internal planning notes and
  `docs/STATUS.md` §5 P2. Decisions: **mod_php-only** SAPI scope (FPM is a
  separate track); version-first on **native arm64**; native amd64 via an
  ephemeral runner. Landed so far:
  - **G2 (offsets)** — `php2shell/offsets.py` + `scripts/extract_offsets.sh`;
    8 aarch64 rows in `profiles/offsets.json`, matching the documented table.
  - **G1 (geometry)** — `php2shell/calibrate.py` + `scripts/calibrate.sh`:
    `derive`/`sweep`/`sweep_leak`/`fingerprint`; self-test recovers the 8.4.26
    geometry and fingerprints 8.4.26 vs 8.5.11.
  - **G3 (matrix)** — `poc/verify_matrix.py` + `scripts/matrix.sh` +
    `lab-matrix/`; **8.4 patch series proven 6/6** (8.4.10/20/23/24/25/26 —
    pos/neg/bias), 8.4.1 and 8.2/8.3/8.5 negative at the leak. Two series
    fixes: leak-side qword bias auto-detect and a widened libphp↔chunk delta.
  - **G6 (scope)** — mod_php-only, recorded in `docs/STATUS.md` §7.
  - **G7 (distro defaults)** — `scripts/distro_defaults.sh` + `lab-matrix/`
    `distro` profile (no-`php.ini` + Ubuntu 24.04 apt). The bypass reproduces
    on the former, not on Ubuntu's Apache 2.4.58.
  - **A1 ground truth (2026-10-30)** — `poc/probe_ps_globals.py` reads
    `ps_globals.id` via `/proc`; 8.4.26's stale slot is `+0x137000` and stable,
    8.2/8.3 are non-deterministic and never reach the END cleanup, 8.5.11
    aborts (`zend_mm_heap corrupted` → DoS-only). Added the byte-exact
    `H:<pages>:<offset>` leak-B spec. **8.2/8.3/8.5 are measured hard
    negatives for the in-band path**, not tuning misses.
  - **Open:** the G4 native amd64 ASLR run (arm64 host only) and distro-Apache
    tuning (G7).

## Public full-chain cross-reference (78ResearchLab)

Reviewed `78ResearchLab/PHP2Shell-Full-Chain-Exploit` (README only, not
`exploit.py` source). It is the same two CVEs; takeaways folded into
detection: (1) network-layer `PHP_SESSION_UPLOAD_PROGRESS` detection (now
in the Suricata rules), (2) the file-oracle + blind-timing-oracle receipt
shapes (now in the Sigma file_event rule + Suricata `sid 210961802/03`),
(3) version-matrix additions — **PHP 8.6 RC1–RC3 affected (fixed RC4)**
and the **distro-backport caveat** (USN/DSA/RHSA/ALSA versions may stay
`8.2.34` while patched; check the vendor advisory, not `php -v`), (4) its
`exploit.py` brute-forces `r0` remotely — the ASLR stage this repo
deliberately excludes. Not ported into `php2shell/`.

## Locked decisions (defaults applied; reversible)

1. **Scope:** lab-only + allowlist + fixed benign command — as the repo
   already requires.
2. **Joomla:** detect now; build the lab in Phase 2 (current 5.x).
3. **WP/Joomla `id` proof:** portable Chains A/C where preconditions exist;
   rung-5b only on the instrumented lab.