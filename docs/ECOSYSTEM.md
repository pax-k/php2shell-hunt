# Public PHP2Shell ecosystem — survey and adoption map

Compiled 2026-10-28 from the Wiz telemetry post (2026-10-27), the GitHub
repositories it references, and the wider search results for
`php2shell` / `CVE-2026-109618` / `CVE-2026-109619` (1,100+ repos, most
forks or scanners). This document records **what each project contributes**,
**what this repo adopted**, and **what it deliberately did not**.

The repo's scope guardrails are unchanged: lab targets only, benign
command allowlist (`id|uname|whoami`), no reverse shells, no mass scanning,
no arbitrary-target packaging. The new rung-6 leak harness is lab-only.

---

## 1. The ecosystem in five layers

| Layer | What it answers | Representative public work |
|---|---|---|
| **1. Trigger / OOM** | How do you make PHP abandon request state? | 9bie `mk_a1.py`, dinosn amplification, advisory part-header vector, our `verify_cve_109618_oom.py` / `verify_empty_upload_expansion.py` |
| **2. Delivery / bypass** | How do you get the bytes past `post_max_size` / the parser? | 9bie chunked A1, dinosn 52x duplicate headers, Wiz legacy 1005-part shape, our `verify_postmax_bypass.py` |
| **3. Leak / ASLR** | How do you learn libphp + chunk addresses in-band? | dinosn `PS(id)` cookie, 9bie B1 stale-id OOB, devploit two-stage heap + libphp leak, 78ResearchLab `r0` brute force |
| **4. Pinning / orchestration** | How do you make A/B land on one worker? | 9bie 149/150 holders, devploit N-1 keep-alive, murrez keep-alive pools, our new `php2shell/pinning.py` |
| **5. Application chains** | What if the core chain is blocked? | Chain A (upload-progress injection + LFI), Chain C (handler mismatch + gadget), murrez auto-LFI, our existing chains |
| **6. Detection / defense** | How do you see or stop it? | Wiz IOCs, Assetnote scanner, CypherSecurity/Zeek/YARA, HOSTED-POWER extension guard, Anton-Barinov EOL patches |

Wiz's contribution is mainly **layer 3 and 4 negative evidence**: public
kits reach layer 1, sometimes layer 2, and fail at 3/4. That is exactly the
gap this uplift targets.

---

## 2. Project-by-project

### 2.1 Full-chain / leak research

| Project | Claim | What we took |
|---|---|---|
| [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp) | 10/10 on stock `php:8.4.26-apache`, display_errors off, 150 workers; A1 → B1 (800 KB cookie) → A2/B2 → `zif_system` | A1/B1 body shapes (`poc/verify_a1b1_leak.py`), the 149-holder pinning primitive (`php2shell/pinning.py`), the offset table entries, and the "worker crash is fine, it respawns" operational note |
| [dinosn/php-cve-2026-10961x-lab-poc](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) | self-contained 4-request RCE on 8.5.11; 12/12 over 8 ASLR generations; 52x amplification; FPM stale `BG(unserialize)` is DoS-only | The `PS(id)` leak-A/leak-B shape (`php2shell/leak.py`), the duplicate-header amplifier (`php2shell/amplify.py`), the "chunk−libphp delta is not constant" warning, and the honest FPM ceiling |
| [78ResearchLab/PHP2Shell-Full-Chain-Exploit](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit) | full chain, remote `r0` brute force | Version-matrix additions (8.6 RC1–RC3) and the distro-backport caveat; the brute-force stage is **not** ported |
| [devploit/php2shell](https://github.com/devploit/php2shell) | version-aware dispatcher, 13 heap profiles, 5 verified RCE builds | Per-build offset inventory (`php2shell/leak.py OFFSETS`), memory-limit probe, N-1 keep-alive pinning, and the "refuse to guess on an unknown build" discipline |
| [cookiengineer/actual-php2shell](https://github.com/cookiengineer/actual-php2shell) | OOM `HashTable` unwritten-bucket → `free_obj` pivot; ASLR-off ROP | Root-cause framing for the 109618 primitive; not ported (our rung-5b uses the 109619 stale-decoder path) |
| [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) | high-fidelity scanner; 62-level nested keys; SAPI-specific verdicts | Scanner-style profiling (`php2shell/sapi.py`), the patched-OOM false-positive caveat, and the "version string is not patch status" rule |
| [murrez/php2shell](https://github.com/murrez/php2shell) | hybrid core + application toolkit; auto-LFI; handler-transition probes; worker pools | Auto-LFI discovery (`php2shell/lfi.py`), the CVE-2026-115560 handler-transition framing, and keep-alive pinning |
| [aarsaputra/php2shell](https://github.com/aarsaputra/php2shell) | pure HTTP, JA3 impersonation, mass-scan framing | **Not adopted** (stealth + mass scanning are out of scope) |
| [JoasASantos](https://github.com/JoasASantos/php2shell-exploit), [murat-levi](https://github.com/murat-levi/php2shell-poc), [0xgh057r3c0n](https://github.com/0xgh057r3c0n/PHP2shell) | one-click / "safe webshell" packaging | **Not adopted** (arbitrary command / webshell surface) |
| [JoshRob297/php2shell-research](https://github.com/JoshRob297/php2shell-research) | ASLR boundary analysis, memory-default impact | Read for framing; no code ported |

### 2.2 Defensive / operational

| Project | Contribution | Use here |
|---|---|---|
| [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) | verdict rules + FP caveat | `php2shell/sapi.py`, detection README §3c |
| [CypherSecurity/php2shell-detection](https://github.com/CypherSecurity/php2shell-detection) | Suricata/Zeek/YARA/Sigma pack | Shape catalogue; our rules stay in one Suricata file + IOC file |
| [scadastrangelove/php2shell](https://github.com/scadastrangelove/php2shell) | safe checks, Snort/Suricata/ModSecurity | Cross-check for the Content-Type/field-name matches |
| [cseelhoff-ms/php2shell-hunting-pack](https://github.com/cseelhoff-ms/php2shell-hunting-pack) | Defender/Sentinel hunting | Host-side hunting ideas (not shipped) |
| [HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) | runtime extension mirroring the fix | Best stop-gap for EOL PHP; referenced, not vendored |
| [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches) | backports for PHP 5.4–8.1 | Referenced for the EOL tail |
| [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) | operational guidance | Referenced |
| [pagvac/php2shell-trends](https://github.com/pagvac/php2shell-trends) | hourly patch-adoption tracker | Context for Wiz's 67% / 47.9% figures |
| [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) | Apache/nginx mitigation toolkit | Referenced |

### 2.3 Social / X sources

The two high-signal social items are the Wiz research thread (the post
above) and Adel Karimi's honeypot report
([@0x4D31](https://x.com/0x4D31/status/2114026826141945874)), which is the
only public confirmed RCE Wiz cites. We did **not** use social posts as
code sources; the reproducible claims all trace to a repository or the Wiz
post. Karimi's data is cited as the strongest public evidence, with the
caveat Wiz gives: single-worker mod_php, so it does not establish
reliability across deployments.

---

## 3. What Wiz adds that no repo had packaged

1. **Negative evidence at scale.** A 67% drop in exposed vulnerable
   machines, 47.9% of organizations remediated, and <53% still vulnerable
   after one week. This is the first population-level view of remediation,
   and it explains why the EOL tail matters.
2. **The exact failure modes of the public kits.** Legacy 1005-part dies
   at `post_max_size`; current A1 exhausts memory but B1 never leaks;
   worker pinning is the other blocker. The repo now reproduces each of
   those three facts in a lab (`verify_legacy_chain.py`,
   `verify_a1b1_leak.py`, `verify_worker_pinning.py`).
3. **IOCs and request shapes.** Folded into
   `detection/iocs_php2shell_2026-10-27.yml` and SIDs 210961804–810.
4. **The "branded but unrelated" category.** Session poisoning + app LFI
   wearing a PHP2Shell label. Our LFI-receipt rule (`/tmp/sess_`) and the
   inline-PHP rule cover it.

---

## 4. Where this repo now stands

See [`STATUS.md`](STATUS.md) for the full RCE scenario matrix, evidence
index and prioritized backlog, and `php2shell_adaptive.py --capabilities`
for the live matrix. Summary:

| Capability | Status | Evidence |
|---|---|---|
| SAPI / limit / worker profile | validated | `poc/verify_sapi_profile.py`, :18110 |
| Worker pinning (Apache + FPM) | validated | 4→1 PIDs, `poc/verify_worker_pinning.py` |
| Duplicate-header amplification | validated | 21x @32M, 32x @128M |
| Legacy 1005-part + chunked bypass | validated | `poc/verify_legacy_chain.py`, :18111 |
| Auto-LFI discovery | validated | `poc/verify_lfi_discovery.py`, :18097 |
| Content-Type comma bypass | validated | `poc/verify_content_type_bypass.py`, :18110 |
| Session poisoning + app LFI | validated | `poc/verify_session_poison_lfi.py`, :18097 |
| In-band leak (rung 6) | **validated (9bie A1/B1)** | `poc/verify_109619_remote.py`, `php2shell/remote.py`, :18120 |
| Un-instrumented core RCE | **validated** | `poc/verify_109619_remote.py`, :18120 fires / :18121 (8.4.27) blocks |
| Per-build offsets | documented | `php2shell/leak.py OFFSETS`, `php2shell/remote.py PROFILES` |
| Handler mismatch / transition | validated | existing Chain C POCs |
| Wiz IOCs + shapes | documented | `detection/iocs_php2shell_2026-10-27.yml` |

**Honest position:** the core chain is now reproduced un-instrumented on
stock 8.4.26-apache (`:18120`), blocked on patched 8.4.27 (`:18121`), with
the leaked address proven load-bearing (`--bias-zif`). What remains is
generalization — per-build portability and a native-arch ASLR cross-check —
not feasibility. The FPM core path (rung 5b) is still instrumented; its
in-band leak is the unsolved piece.

---

## 5. Deliberately not adopted

| Capability | Why |
|---|---|
| Remote ASLR brute force (`r0` sweep) | noisy, unreliable, and the repo already has a leak harness; brute force without a leak is an availability attack |
| JA3 / TLS impersonation | evasion for mass scanning; no lab value |
| Arbitrary command / reverse shell / "safe webshell" | out of scope; fixed benign allowlist only |
| Mass scanning / target lists | out of scope |
| Public exploit redistribution | this repo keeps mechanisms + detection, not a turnkey kit |

If the rung-6 leak is completed later, the result should be published as
**mechanism + detection + patch verification**, not as a remote exploit
pack. The dual-use line matters more once the leak fires.

---

## 6. Next research steps

1. **Close rung 6.** The remaining gap is B1 heap calibration on a specific
   build. The harness already supports the public shapes; the missing piece
   is the per-build `target`/`fake_len`/`spec` values and a worker-survival
   check after A1. Do this against `lab-pure-modphp` only.
2. **Multi-worker FPM chain.** Port the rung-5b producer/consumer pair onto
   `lab-pinned` (:18097) with `pm.max_children=4` and holders=3, proving the
   chain survives a realistic pool instead of a single static child.
3. **Heap-profile matrix.** Add offsets/heap parameters for 8.2.34, 8.3.35,
   8.4.26, 8.5.11 (amd64 + arm64) using the devploit inventory as the
   starting point, and record which profiles actually fire.
4. **Detection validation.** Replay the A1/B1/legacy pcaps against the new
   SIDs; the rules are syntactically valid but not yet traffic-tested.
5. **EOL residual-risk note.** Chains A/C survive 8.2.35; quantify which
   EOL branches still have the `session.upload_progress` surface and which
   backports exist.
