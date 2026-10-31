# php2shell-hunt

Local-lab PHP vulnerability research: a verification-first pipeline that drives a
hypothesis to a reproducible exploit chain with controls, plus the labs, PoCs,
and detection rules that back every claim.

The working thesis is that **generation is commoditising and verification is
not**. Plenty of tooling now produces candidate findings. This repository is
about the other half: a candidate is not a finding until a lab command shows it,
and a crash is not RCE until an allowlisted command prints its output.

> Lab targets only: `localhost`, `127.0.0.0/8`, `::1`. Fixed benign command
> allowlist: `id`, `uname`, `whoami`. No remote scanning, persistence, lateral
> movement, reverse shells, or arbitrary command execution.

## What this repository proves

Every row is a lab run that printed the output of an allowlisted command.
`STOCK` means the official image with image defaults and no application
precondition; `CONFIG-GATED` means one named non-default setting or application
behaviour; `LAB-ONLY` means a lab endpoint or planted class. See
[`GOAL.md`](GOAL.md) for the definitions and the unmet stock objective.

| Chain | Tier | Target | Receipt |
|---|---|---|---|
| CVE-2026-109619 leak -> `zif_system`, 150-worker prefork | `CONFIG-GATED` | 8.4.10-8.4.26 mod_php, arm64 + amd64 | `uid=33` |
| CVE-2026-109618 OOM -> `zif_system`, in-band, no `/proc` | `CONFIG-GATED` | 8.4.26 mod_php, arm64 | `uid=33` |
| CVE-2026-115560 -> `var_destroy` UAF -> `zif_system` | `CONFIG-GATED` | 8.4.27 / 8.5.12, pre-auth | `uid=33` |
| `var_destroy` re-entry UAF -> forged `dtor_obj` | `LAB-ONLY` | 8.4.26 / 8.4.27 / 8.5.12 | `uid=33` |
| Chain A - session poisoning + LFI | `CONFIG-GATED` | 8.2.35 / 8.4.27 / 8.5.12 | marker + `uid=33` |
| Chain C - handler mismatch + gadget | `CONFIG-GATED` | 8.2.35 / 8.4.27 / 8.5.12 | `uid=33` |
| Drupal 11.4.11 P5 via the real session decoder | `CONFIG-GATED` | 8.4.27 / 8.5.12 | `uid=33` |
| Roundcube 1.6.11, plugin-assisted | `LAB-ONLY` | 8.4.27 / 8.5.12 | `uid=33` |

Each chain is run against three controls: a patched-build negative, a bias or
`allowed_classes` negative, and a removal control for the sink or gadget. The
8.4 matrix is positive / negative / bias per build, six builds deep, across three
ASLR generations at the stock 150-worker prefork.

Detection is traffic-tested, not just written: ten Suricata SIDs under a live
sidecar against A1/B1, legacy, and session-poison traffic
([`detection/README.md`](detection/README.md)).

## What this repository does not prove

- **No stock-default RCE.** Every chain is `CONFIG-GATED` or `LAB-ONLY`. There is
  no chain that runs on an unmodified image with no application precondition.
  `GOAL.md` G2 is unmet and stays unmet until a gate is removed, not reworded.
- **No remote weapon.** Labs are loopback-only and pinned to a fixed benign
  command. There is no target packaging and no post-exploitation.
- **Coverage is partial by construction.** 8.2/8.3/8.5 fail at the leak shape,
  not at offsets; the FPM in-band leak is unsolved; x86-64 needs an address seed;
  FrankenPHP and LSAPI are untested. Each ceiling is stated in
  [`docs/STATUS.md`](docs/STATUS.md) §7.
- **A negative here is only a negative for that build, config, and pattern set.**
- **Static output is candidate generation.** The gadget graph does not model
  dataflow, guards, or runtime autoload, and every candidate needs a source read
  before it is called an edge.

## The method

Four evidence gates, applied in order: scope, receipt, static-to-dynamic, and
crash-to-impact, then controls and portability. The full method, including the
core and application tracks, the exploit ladder, and the commands, is
[`docs/PIPELINE.md`](docs/PIPELINE.md). Scope is
[`docs/TARGET_SCOPE.md`](docs/TARGET_SCOPE.md); the honest backlog is
[`docs/BLIND_SPOTS.md`](docs/BLIND_SPOTS.md).

## Repository map

| Path | What lives there |
|---|---|
| `scanner/check.py` | default-safe, tiered session scanner with JSON and exit codes |
| `poc/` | loopback-only verifiers, one per claim, plus shared transport |
| `php2shell/` | research engine: leaks, pinning, offsets, matrix, ELF/build diff, gadget graph |
| `scripts/` | thin wrappers, report generation, and the offline gate |
| `tools/gadget/php/` | PHP-Parser facts emitter for the cross-class gadget graph |
| `fuzz/` | ASAN corpus generator, runner, and triage |
| `lab/` | unprivileged PHP 8.4/8.5 matrix, stock image defaults only |
| `lab-chain-a/` | Chain A session/LFI lab, the one lab with a labelled `php.ini` |
| `lab-*/` | one disposable lab per build, app, or precondition; `setup.sh` rebuilds each |
| `profiles/` | per-build offsets and heap geometry |
| `reports/` | generated sweep and diff output; machine input, never hand-edited |
| `detection/` | Suricata, Sigma, ModSecurity, OpenResty patterns |
| `tests/` | offline contract tests; socket use is forbidden |
| `research/` | blind-spot manifests; not coverage claims |
| `docs/` | pipeline, status, analysis, and per-chain evidence |

## Quick start

```sh
# offline gate: consistency, manifests, compile, tests
scripts/check.sh

# scanner (triage only; never an RCE claim)
python3 scanner/check.py http://127.0.0.1:18091 --json

# stock lab matrix
scripts/lab_matrix.sh list
scripts/lab_matrix.sh up php-8.4.26 php-8.4.27
scripts/lab_matrix.sh status

# one claim, one command
python3 poc/verify_matrix.py --help
python3 poc/verify_109619_remote.py --target http://127.0.0.1:18120 --cmd id
```

`docker`, `python3`, and `php` are expected. A missing image, lab, or tool is
reported as `BLOCKED` with its rebuild command, never as a zero.

## Prior art and credits

Nothing here was discovered in a vacuum. The core CVE chains are public work by
**9bie** and **dinosn**; the `var_destroy` re-entry UAF is public since May 2026
by **dinosn**, as a sister finding to **Calif.io**'s MAD Bugs; the four-stage
115560 composition was published by **ACD421/PHP**; independent 115560 PoCs by
**B63** and **googlesky**; PS(id) and wire-shape work by **mnk-works** and
**TheCyberGeek/Qi Deng**. What this repository adds is the patched-build and
arm64 port, the control matrix, the measured constants, the real-application
profiles, and the detection pack. Disagreements with that split are recorded in
[`docs/NOVELTY_115560_2026-10-31.md`](docs/NOVELTY_115560_2026-10-31.md) and
[`docs/RESEARCH_REVIEW_2026-10-30.md`](docs/RESEARCH_REVIEW_2026-10-30.md),
which also retract two earlier novelty claims.

## Publication

What shipped, what was withheld, and why:
[`docs/RESPONSIBLE_PUBLICATION.md`](docs/RESPONSIBLE_PUBLICATION.md).

## License

Code is Apache-2.0; see [`LICENSE`](LICENSE). Documentation and reports in
`docs/` are CC BY 4.0. No license is granted over the third-party applications
the labs download at setup time; they remain under their own terms.
