# Pipeline — PHP core and application vulnerability research

Read `AGENTS.md` first. This document is the end-to-end method; it does not
replace the acceptance list in `GOAL.md` or the current state in
`docs/STATUS.md`.

**Scope:** local labs only (`localhost`, `127.*`, `::1`), fixed benign command
allowlist (`id`, `uname`, `whoami`), no persistence, lateral movement, reverse
shells, or remote packaging. A candidate is not a finding until a command in
this repository demonstrates it.

## Baseline invariant

The baseline is the image's own default, not a tuned lab:

- official `php:8.4.26-apache`, linux/amd64;
- no `php.ini` mount, no `-d` flags, no copied distribution config;
- no added extension, handler, or ini setting;
- loopback binding only.

A chain that needs an override is `CONFIG-GATED`, never `STOCK`. Every variant
is labelled and carries its own control. `lab/` is the stock baseline;
`lab-chain-a/` is the one lab with a labelled `php.ini`.

## Two tracks, one terminal

```text
Track A — PHP core/version
  advisory + fix commit -> image diff -> source hypothesis -> ASAN
  -> stock ZendMM -> leak/trigger -> exploit ladder -> build/arch matrix

Track B — application gadget
  app + vendor tree -> same-method sweep -> cross-class graph
  -> source/type confirmation -> minimal app lab -> real sink

Convergence
  app sink + core bug + wire trigger + worker model
  -> fixed benign terminal call -> controls -> portability
```

Track A answers **is the interpreter bug real and reachable?** Track B answers
**does the target application provide the sink and object graph?** Neither is
enough alone. Chain A/C is app-only and survives patched PHP; the core chains
need an app sink or wire-level consumer.

## Stage 0 — establish the target model

Record before running anything:

- PHP build/tag, SAPI (`mod_php`, FPM, FrankenPHP), arch, worker count.
- Config: `upload_progress`, `session.serialize_handler`, `session.save_path`,
  `memory_limit`, `post_max_size`, `cleanup`, `disable_functions`,
  `allowed_classes`.
- App/framework, Composer autoload order, vendor tree, reachable LFI or
  `unserialize()` sinks.
- Whether the target is pre-auth and whether producer/consumer can share a
  worker.

If a required lab or image is missing, record `BLOCKED` with the rebuild
command; never substitute a simulated success.

## Track A — PHP core/version

### A1. Patch diff first

Fix commits are the highest-signal source. Prefer this over blind fuzzing.

```sh
scripts/diff_builds.sh php:8.4.26-apache php:8.4.27-apache
```

Read function **size** changes as patch evidence and per-symbol **shift** as
offset drift. Never reuse one page delta across builds. Record the build IDs,
hashes, and the exact functions that moved.

### A2. Source hypothesis

Read the changed code and state a lifetime hypothesis, for example:

- use-after-free or double free in session/unserialize cleanup;
- OOM leaves an unwritten bucket or stale global;
- destructor re-entry without the serialize lock;
- missing/incorrect ownership transfer in ZendMM;
- parser state reused across requests.

Check whether the patch fixes only the reported path. A patch-gap (an adjacent
bug left alive) is often more valuable than re-proving the advisory.

### A3. ASAN proof

Build or select an instrumented lab and drive the smallest input that reaches
the disputed line.

```sh
python3 poc/verify_<bug>.py --target 127.0.0.1:<port>
```

Record the exact ASAN report and source line. A crash without a matching
lifetime explanation is not yet a weaponizable primitive.

### A4. Stock-ZendMM proof

Re-run the same trigger on a stock image with ZendMM enabled. Separate:

- `read` evidence: source/ASAN says the edge exists;
- `executed` evidence: the stock run reaches the terminal or faults at the
  expected point.

ASAN geometry is not exploit geometry. Measure the stock heap separately.

### A5. Trigger and worker model

Map producer and consumer. Confirm whether they must share a process.

- Wire-level producers: upload progress, multipart bounds, lengthless bodies,
  chunked delivery, duplicate headers.
- Session paths: write handler vs read handler, cleanup mode, save path.
- Worker selection: `pm.max_children`, `MaxRequestConnectionsPerChild`,
  pinning, respawn, holder rotation.
- Autoload: how the gadget or sink class is loaded before the trigger.

Measure rather than assume. A same-worker claim needs a worker identity or a
reliable rotation proof.

### A6. Exploit ladder

Climb one rung at a time and keep the control for each:

1. crash / DoS;
2. controlled UAF or OOM;
3. reclaim the freed allocation;
4. leak or derive a usable address;
5. forge a zval/object/reference;
6. control a destructor or call target;
7. terminal call with the fixed benign command.

Prefer data-only/forged-object paths over full ROP. Stop at the fixed command.
Do not add persistence, privilege escalation, or post-exploitation.

### A7. Matrix and controls

```sh
scripts/extract_offsets.sh <image> --write
scripts/matrix.sh
```

Every row needs positive, patched-negative, and bias controls. Record arch,
ASLR generation, worker model, and attempts/time. A single container is a
proof of concept, not coverage.

## Track B — application gadget

### B1. Same-method inventory

```sh
scripts/gadget_sweep.sh --self-test
scripts/gadget_sweep.sh lab-drupal --label drupal
```

Starts from magic methods and attributes sinks in the same method. Rank
`reentry` (`unserialize`) first, then `terminal`, `dispatch`, `file`. This is a
filter, not proof.

### B2. Cross-class graph

```sh
composer install -d tools/gadget/php     # one-time; vendor/ is ignored
scripts/gadget_graph.sh --self-test
scripts/gadget_graph.sh lab-drupal --label drupal --max-depth 10 --top 200
```

`tools/gadget/php/facts.php` emits typed properties, inheritance, traits,
interfaces, calls, and string contexts. `php2shell/gadget_graph.py` expands
interface/abstract property types to concrete implementors and searches
shortest-first. Read `reports/gadgets/<label>-graph.md`.

If the vendor tree is missing, the graph is `BLOCKED`; that is not a negative.
`docs/TOOLING.md` has the detailed coverage and Drupal P5 example.

### B3. Source and type confirmation

For every candidate edge, open the cited `file:line` and check:

- Does the property type or interface expansion really admit this concrete
  class?
- Is the method call unconditional, or behind a guard/return?
- Is the object autoloadable before the trigger?
- Is the argument attacker-controlled, or a constant/test fixture?
- Does the real deployment config reach the same branch?

State the answer as `read` evidence. Do not call a chain `executed` yet.

### B4. Minimal application lab

Build the smallest app that preserves the real autoload order and config.
Exercise the sink directly first, then through the wire trigger. Use ASAN to
confirm the memory effect, then stock ZendMM to measure impact. A lab plugin or
non-default config is allowed, but must be labeled as such.

### B5. Fuse and verify

Connect the app sink to the core primitive:

- app `unserialize()` / session decode / Phar sink;
- core UAF/OOM or stale state;
- wire trigger and worker pairing.

Record the terminal output, then re-run with the gadget removed, the patched
build, and the bias/`allowed_classes` control. A structural blocker (e.g., the
real driver never reads the upload file) is a valid negative result.

## Track C — deferred blind spots

A backlog, not a parallel mandate. Open a row only when Track A or Track B names
a concrete need, and move it through one state at a time:

```text
not-inventoried
  -> inventory (functions/handlers/stream wrappers/SAPI reads)
  -> harness (lab or unit)
  -> fuzz/reproduce
  -> triage (crash? memory? logic?)
  -> control (patched/negative/bias)
  -> documented
```

Manifests live in `research/`: `extensions.json`, `bundled_libs.json`,
`non_memory.json`, `build_matrix.json`, `fuzz_targets.json`, `patch_history.json`.
A row is not covered because the extension is loaded or the library is present;
it is covered when a function/parser map and a receipt exist. A non-memory class
needs an oracle before it can produce a finding.

## Convergence and impact

The useful question is not “is there a gadget?” but “which precondition can I
remove while keeping the terminal call?” Measure impact by:

- pre-auth vs authenticated;
- no `/proc`, debugger, or oracle;
- patched build still affected;
- hardened `disable_functions`;
- multi-worker without pinning;
- native arch and multiple ASLR generations;
- reliability across attempts/containers.

The current practical hierarchy is in `docs/STATUS.md` §2:
app-level Chain A/C is the most reliable; the 109619/109618 mod_php in-band
chains are the highest core severity; 115560 + Drupal P5 is pre-auth on
patched builds but config-gated; `var_destroy` survives the patch but still
needs an app sink or external leak on high-entropy x86-64.

## Evidence gates

1. **Scope and defaults** — loopback target; allowlisted command; no remote
   packaging; stock image defaults, or the result is `CONFIG-GATED`.
2. **Receipt** — one claim, one command, one quoted output, `file:line` for
   static claims.
3. **Static → dynamic** — the graph names the edge; ASAN or a stock run proves
   it executes. Confirm the concrete class, autoload order, and guards.
4. **Crash → impact** — demonstrate every rung separately; do not jump from
   SIGSEGV to RCE.
5. **Controls** — patched build, bias, gadget removal, `allowed_classes`.
6. **Portability** — build, arch, ASLR, worker model, cleanup mode.
7. **Close-out** — regenerate reports, append `PROGRESS.md`, run
   `scripts/check.sh`, state the ceiling.

## Command map

| Stage | Command | Output |
|---|---|---|
| Patch diff | `scripts/diff_builds.sh <old> <new>` | `docs/DIFF_*.md`, `reports/build-diff/*.json` |
| Same-method sweep | `scripts/gadget_sweep.sh <root> --label <name>` | `reports/gadgets/<name>.{json,md}` |
| Cross-class graph | `scripts/gadget_graph.sh <root> --label <name>` | `reports/gadgets/<name>-graph.{json,md}` |
| Heap geometry | `scripts/calibrate.sh` | calibration row |
| Offsets | `scripts/extract_offsets.sh <image>` | `profiles/offsets.json` |
| Build/arch matrix | `scripts/matrix.sh` | pos/neg/bias receipts |
| Claim proof | `python3 poc/verify_*.py` | terminal/ASAN receipt |
| Scanner triage | `scripts/scan.sh <target>` | stdout JSON, never an RCE claim |
| Stock lab matrix | `scripts/lab_matrix.sh up` | loopback containers |
| Offline gate | `scripts/check.sh` | consistency result |

## Roles and handoffs

- `pipeline-runner` (primary) — selects one stage, runs the cheapest
  discriminating command, delegates, and records the result.
- `gadget-hunter` (subagent) — static sweep/graph triage into source-checked
  hypotheses; read-only.
- `build-differ` (subagent) — image diffs and generated DIFF docs.
- `evidence-auditor` (subagent) — independent re-run; PASS/FAIL/STALE/BLOCKED.
- `goal-runner` / `loop-runner` — the acceptance-list iteration contract; do
  not duplicate it per stage.

Use `/pipeline` for one stage, `/sweep` or `/graph` for static-only work,
`/diff` for a build pair, and `/audit` before calling a claim done.

## One-iteration template

1. Name one unproven link.
2. Run the cheapest command that distinguishes PASS from FAIL.
3. Record the exact output and the `file:line` or lab receipt.
4. If PASS, move one rung; if FAIL, refine or record the ceiling.
5. Append `PROGRESS.md`: change / verification / failure / next.
6. Run `scripts/check.sh`.

Do not start a second acceptance item because the first was easy.

## Artifacts and ceilings

- Generated: `reports/gadgets/*`, `docs/DIFF_*.md`, `reports/build-diff/*`.
  Regenerate with the script; do not hand-edit.
- Machine input: JSON; readable view: Markdown. Keep both.
- Static claims state tool, version, roots, exclusions, and the ceiling
  (“no dataflow”, “no autoload proof”, “same-method only”).
- Dynamic claims state build, SAPI, arch, worker model, ASLR generation, and
  controls.
- A negative is only a negative for that tree, config, and pattern set.

