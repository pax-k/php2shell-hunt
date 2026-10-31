# Tooling map — static, dynamic, binary and agent automation

Read `AGENTS.md` first, then `docs/PIPELINE.md` for the end-to-end method. This
file explains *which* tool to reach for and how the repo's automation wires
them together. Scope and guardrails are unchanged:
loopback labs only, benign allowlist (`id | uname | whoami`), no remote targets.

## Pipeline

```
source trees ──> gadget_sweep (ctags + ast-grep + semgrep) ──> reports/gadgets/*
                      │
                      ├─ candidates ──> gadget_graph (PHP-Parser facts + path search)
                      │                    └─> reports/gadgets/*-graph.*
                      └─ candidates ──> source reading / Joern ──> poc/verify_*
stock images ──> diff_builds (ELF parser + optional ghidriff/abidiff) ──> docs/DIFF_*
                      │
                      └─ offsets / size deltas ──> profiles/offsets.json
labs ──> poc/verify_* ──> ASAN / stock ZendMM ──> PROGRESS.md receipts
```

## What is wired now

| Script | Input | Output | Use |
|---|---|---|---|
| `scripts/gadget_sweep.sh` | app root(s) | `reports/gadgets/<label>.{json,md}` | same-method magic→sink inventory; ranked `reentry`/`terminal`/`dispatch`/`file` |
| `scripts/gadget_graph.sh` | app root(s) | `reports/gadgets/<label>-graph.{json,md}` | cross-class chains via PHP-Parser facts: inheritance, traits, interfaces, typed properties, `__toString`/`__call` |
| `scripts/diff_builds.sh` | two image tags | `docs/DIFF_*.md` + `reports/build-diff/*.json` | patch size deltas, per-symbol shift, build-id/hash identity |
| `scripts/extract_offsets.sh` | image tags | `profiles/offsets.json` row | portable offsets (ASLR-independent) |
| `scripts/calibrate.sh` | lab target | heap-geometry row | ZendMM chunk math per build |
| `scripts/matrix.sh` | build matrix | pos/neg/bias receipts | version × arch triad |
| `scripts/check.sh` | repo | offline gate | compile/import/schema/required files/self-tests |

`php2shell/elf.py` is a dependency-free ELF64 reader, so stock images without
binutils can still be diffed. `php2shell/build_diff.py`,
`php2shell/gadget_sweep.py` and `php2shell/gadget_graph.py` each carry
`--self-test`.

### Cross-class gadget graph

```sh
composer install -d tools/gadget/php          # one-time; vendor/ is gitignored
scripts/gadget_graph.sh --self-test
scripts/gadget_graph.sh lab-drupal --label drupal --max-depth 10 --top 200
```

`facts.php` reads a newline-separated file list on stdin and emits one JSON
record per file: classes, resolved `extends`/`implements`, traits, native and
promoted property types, method signatures, calls, and string contexts. The
Python side merges trait methods, expands interface/abstract property types to
concrete implementors (including subclasses), treats `$this` calls at the
runtime class, and searches shortest-first with a per-path visited set.

The Drupal run (7,925 files, 7,494 classes, 199 entries) surfaces the P5 chain:

```
YamlCacheCollectorDiscovery::__destruct
  -> MenuActiveTrail::destruct
  -> MenuActiveTrail::updateCache          (body from CacheCollector)
  -> MemoryBackend::get
  -> MemoryBackend::prepareItem
  -> unserialize()                          core/lib/Drupal/Core/Cache/MemoryBackend.php:99
```

It also surfaces proxy-class, `StorageComparer`, Symfony, and other branches;
rank is a triage hint, not proof. **Ceiling:** no dataflow/taint, no guard
evaluation, no runtime autoload or service-container resolution. A path proves
only that the static call/type edges exist. Joern remains optional and is not
wired into the gate.

## Static analysis: what each tool is good for

| Tool | Strength | Limit here |
|---|---|---|
| **ctags** | fast class/method ranges, scope | no dataflow |
| **ast-grep** | structural PHP patterns (magic names, sinks), JSON, fast | no cross-file/type resolution |
| **Semgrep** | per-file taint + magic-method rules | OSS taint is intra-file; cross-file is Pro |
| **nikic/PHP-Parser** | exact PHP 8 AST, property types, promoted params | wired in `tools/gadget/php/facts.php`; needs `composer install` |
| **Joern `php2cpg`** | interprocedural CPG, taint, reachability | PHP maturity "Medium"; parser gaps on new syntax |
| **PHPGGC / BlackSerial** | known chains, payload shapes | baseline, not discovery; test only in a lab |
| **CodeQL** | C/C++ on php-src (OOM/cleanup paths) | **no PHP support**; not for app gadgets |

Rule to keep: a static hit is a *candidate*. Only a lab command with a receipt
turns it into a finding. Cross-class chains (Joomla split gadget, Drupal P5)
need PHP-Parser/Joern or line-by-line reading — the sweep deliberately does not
claim them.

## Dynamic and binary

| Tool | Use | Note |
|---|---|---|
| **gdb + php-src `.gdbinit`** | `zbacktrace`, `printzv`, `print_ht`, `print_pi`, `lookup_root` | best for `var_destroy`/HashTable state |
| **rr** | deterministic replay of a UAF/heap-groom | x86_64 in practice; use the amd64 runner |
| **pwndbg / gef** | arm64 gdb ergonomics | pwndbg/gef support varies; pin a version |
| **ASAN/UBSAN** | primary detector (`USE_ZEND_ALLOC=0`) | changes allocator geometry; keep a ZendMM-on build for exploit work |
| **valgrind / MSan** | uninitialised reads ASAN misses | slow; needs instrumented deps for MSan |
| **CASR** | crash dedup/severity/exploitability | better than ad-hoc triage; feed `fuzz/triage.py` output |
| **AFL++ / php-fuzzer** | coverage-guided serialization/multipart | current `fuzz/gen.py` is blind mutation |
| **afl-tmin / creduce / halfempty** | minimise the killing input | shrink 1005-part shapes before replay |
| **ghidriff** | Ghidra CLI patch diff | free; works on libphp |
| **abidiff / libabigail** | ABI/struct drift | needs debug info; may refuse stock images |
| **LIEF / pyelftools / capstone** | scripted ELF parsing | no native deps; good for offsets |
| **pahole / readelf / nm / objdump** | structs, symbols, disasm | need binutils in the image or a debug build |
| **blint / checksec** | hardening drift across the matrix | quick sanity check |

`diff_builds.sh` already reports the patch signal: in 8.4.26→8.4.27
`php_session_initialize` shrinks 1020→988, `php_var_unserialize` 124→120, and
the address shift is not constant (`zif` +0x47a0, `zval_ptr_dtor` +0x88c0).
That is why per-build extraction beats a page delta.

## Web / wire and detection

- Raw HTTP: `curl --trace-ascii`, `h11`, `httpx`, `mitmproxy`, `socat`/`nc`,
  `nghttp2` (`nghttp`, `h2load`).
- Discovery/racing: `ffuf` + SecLists, `turbo-intruder`, `vegeta`/`hey`.
- Wire truth: `tcpdump`/`tshark`; replay with `zeek -r`.
- Detection CI: `sigma-cli check`, `yara -r`, `suricata -T -S` — currently
  `detection/` is reviewed by reading, not executed in the gate.

## Suggested installs (host)

```sh
brew install joern ghidra rizin yara suricata hyperfine just ffuf
brew install --cask ghidra            # or use the release zip
pipx install sigma-cli blint ghidriff
cargo install casr
uv tool install semgrep               # already present here
```

`composer` is installed (`/opt/homebrew/bin/composer`, 2.11.1) and the
PHP-Parser facts dependency is pinned in `tools/gadget/php/composer.lock`.
Joern is `joern-parse <dir> --language PHP`; it is optional and not required by
`gadget_graph.sh`.

## Automation map

| Surface | What it does |
|---|---|
| `AGENTS.md` | operating contract: read order, guardrails, evidence, static ceiling |
| `docs/PIPELINE.md` | end-to-end core/app tracks, gates, ladder, commands, handoffs |
| `opencode.json` | loads `AGENTS.md` + `docs/PIPELINE.md` as project instructions |
| `pipeline-runner` | primary agent: one pipeline stage, delegates, records evidence |
| `gadget-hunter` | subagent: triage sweep and graph output into source-checked hypotheses |
| `build-differ` | subagent: run `diff_builds`, explain size/shift, update generated DIFF |
| `evidence-auditor` | subagent: re-run a claim's command; PASS/FAIL/STALE/BLOCKED |
| `php-gadget-sweep` skill | workflow + extension points for the sweep and graph |
| `php-vuln-pipeline` skill | routing layer for core/app stages and handoffs |
| `build-diff` skill | interpretation rules for image diffs |
| `evidence-first` skill | claim → command → receipt → PROGRESS loop |
| `/pipeline` | one stage via `pipeline-runner` |
| `/sweep`, `/graph`, `/diff`, `/audit` | focused command wrappers for the subagents |

## Not worth adding for this lab

Generic SCA/Snyk/Aikido, SonarQube, commercial RIPS, Metasploit, and broad
scanners add noise without answering "does this magic method reach this sink
under these preconditions". Full CodeQL-for-PHP does not exist. Add a tool only
if it changes a decision the lab can test.
