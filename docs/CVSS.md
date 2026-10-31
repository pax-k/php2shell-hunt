# CVSS scoring — php2shell findings

**Rule:** score what is proven. The maximum is raised by **removing attack
conditions** (AC:H→AC:L) or by **demonstrating scope change** (S:U→S:C), never
by editing the vector.

## Current vectors (proof-backed)

| Finding | Vector (v3.1) | Score | Notes |
|---|---|---|---|
| `var_destroy` re-entry UAF | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | **8.1** | code execution proven on 8.2.34/8.3.35/8.4.27/8.5.12; AC:H from the app sink + terminal gadget + carrier calibration. `C/I/A:H` is the arbitrary-command capability (the forged `zend_string` carries the command); the lab pins it to `id`/`uname`/`whoami` as a safety policy only |
| mbstring SJIS-mac overflow | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L` | **4.8** | controlled 1–2 byte glibc heap write; no RCE |
| CVE-2026-109618/109619 | per advisory | **9.2** | official; not our score |

## The two levers

**AC:H → AC:L (→ 9.8)**
Requires a **default, guest-reachable sink** (no plugin, no admin option) and a
**terminal-capable gadget that is commonly loaded** (ideally built-in). Then:
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8** (v3.1 ceiling without S:C).

**S:U → S:C (→ 10.0)**
Requires demonstrated impact **beyond the PHP worker's security scope** — a
privilege, tenant, or sandbox boundary crossing. Not demonstrated; `www-data`
in a container is same-scope. A container escape / host compromise is a
separate vulnerability class; do not fold it into this score.

## Scenario matrix

| Scenario | v3.1 vector | Score | Status | Evidence needed |
|---|---|---|---|---|
| In-scope, lab sink + custom gadget | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | **8.1** | **proven** | postcarrier chain, 6/6; controls |
| Third-party/default plugin sink + stock terminal gadget | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | **not achievable in stock apps** | Track A found no stock route; requires a plugin/default third-party route (or leaked salts + author) |
| + demonstrated scope change | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0** | **not claimed** | Track D evidence (cross-tenant / privilege / sandbox) |
| mbstring overflow | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L` | **4.8** | **proven** | ASAN + stock trigger; no RCE |

**Responsible ceiling for this bug as currently evidenced: 8.1.**
Track A (2026-10-31) found **no default, no-plugin, guest-reachable sink** in
stock Joomla 5.4.10 or WordPress 7.1.3: every `unserialize`/`maybe_unserialize`/
`Phar::getMetadata` site is server-generated, auth-gated (author/editor/admin),
HMAC-gated (`AUTH_SALT`), or `allowed_classes`-constrained. So `AC:L` is not
available in stock; **9.8 requires a plugin/default third-party route** (a
different scored component) or leaked salts plus author access. 10.0 remains a
separate research program.

## CVSS v4.0 (vectors; score per FIRST calculator)

| Scenario | v4.0 vector |
|---|---|
| current in-scope | `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| default sink + stock gadget | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| + scope change | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |

v4 separates *attack requirements* (`AT`) from complexity; our gadget/sink
precondition is `AT:P`. The 10.0 ceiling needs `AT:N` **and** all
subsequent-system impacts High.

## What would move it (and what would not)

Moves it:
- a real guest-reachable `unserialize`/`Phar::getMetadata` route;
- a terminal-capable gadget from commonly-loaded classes;
- a demonstrated boundary crossing for S:C.

Does **not** move it:
- adding `C:H/I:H/A:H` detail (already assumed by code execution);
- relabeling the lab endpoint as a product route;
- claiming S:C from "it runs in a container".

## Track A result (sink) — negative in stock

- WP `core/legacy-widget` unserialize was proven live (post + forged `wp_hash`,
  marker rendered), but it needs `edit_posts` **and** the secret `AUTH_SALT`.
- WP REST widgets / Customizer → admin (`edit_theme_options`).
- WP `maybe_unserialize` is not injectable: `maybe_serialize()` double-serializes
  serialized-looking strings (object reads back as string).
- Joomla finder/storage/cache sinks are guest-*triggerable* but need an
  author/admin write; webauthn is CSRF+logged-in with server-generated options;
  `com_joomlaupdate/extract.php` is admin + `allowed_classes`.
- Joomla upload-progress session injection is dead in the real app: the stock
  handler is `database`, and `session_start()` replaces `$_SESSION`
  (`NativeStorage.php:450` throws before the sink).
- Phar: no app `getMetadata()`; the bundled `typo3/phar-stream-wrapper` uses
  `allowed_classes => false`.

## Scope verdict (2026-10-31) — S:U

Reviewed in the lab as the `www-data` worker (not the root `docker exec` shell):
non-privileged container, private PID/net/IPC, no `docker.sock`, worker
`CapEff=0`, `kill -0 1` → EPERM, no writable `/etc/passwd`/cron/`core_pattern`,
no sudo, single vhost. Numeric uid 33 across containers is per-namespace UID
reuse, not a shared authority. The vulnerable component and every resource it
can reach are the same authority → **S:U**.

CVSS 3.1 math (C:H/I:H/A:H, PR:N/UI:N/AV:N):

| Scope / AC | Score |
|---|---|
| S:U, AC:H | **8.1** (publish) |
| S:U, AC:L | **9.8** (in-scope ceiling) |
| S:C, AC:H | 9.0 |
| S:C, AC:L | 10.0 |

10.0 therefore requires stacking an unjustified S:C **and** AC:L. Do not.

Separate vulnerability classes (do not fold in): seccomp-unconfined +
`CAP_SYS_PTRACE` in one lab, missing `open_basedir` / shared-uid vhosts /
shared `/tmp` (deployment), worker→root (local privesc), docker.sock exposure /
container escape.

## CSV

See `docs/cvss.csv` for the machine-readable matrix (finding, scenario, v3.1
vector/score, v4 vector, status, evidence path).
