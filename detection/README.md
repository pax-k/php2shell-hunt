# Detection rules

Lab-validated patterns, not production-certified signatures. Test against a
local target before deployment. Two SID namespaces are shipped: `2109618xx`
(the CVE-2026-109618/109619 wire pack, traffic-tested) and `20262xx` (the
repo-local triage set used by `scanner/`).

Aligned with the public ecosystem's defensive tooling (process-watcher,
SigmaHQ, nuclei templates, Suricata) — the part the exploit research
alone doesn't cover.

Artifacts in this directory:

| File | Scope | What it catches |
|------|-------|-----------------|
| `suricata_php2shell_upload_progress.rules` | network (pre-exploitation) | multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS`; Wiz variant shapes; proof-file fetch; LFI receipt; Content-Type bypass |
| `suricata.rules` | network (triage) | repo-local set, SIDs 2026200-2026210, paired with `scanner/check.py` |
| `modsecurity.conf` | WAF | upload-progress and oversized-cookie shapes |
| `openresty.lua` | reverse proxy | request-body and cookie-length checks |
| `sigma/php2shell_upload_progress.yml` | SIEM | upload-progress field in web logs |
| `iocs_php2shell_2026-10-27.yml` | threat intel | 9 Wiz IPv4 IOCs, 6 observed request shapes, response signatures, exposure context |
| `proc_creation_lnx_php2shell_post_exploitation.yml` | host (post-exploitation) | shell/interpreter/download tool as a PHP-worker descendant |
| `file_event_lnx_php2shell_webroot_artifact.yml` | host (post-exploitation) | proof-file write (`/p`, `pwn.txt`, `rce-proof.txt`, `oob.txt`) into a served webroot |

## 0. Network-layer detection (pre-exploitation)

`suricata_php2shell_upload_progress.rules` — matches the request *before*
exploitation lands, unlike the two host rules which only see the aftermath:

- `sid 210961801` — `POST` + `multipart/form-data` + the reserved
  `PHP_SESSION_UPLOAD_PROGRESS` field name. Legitimate apps rarely send
  this field; high-confidence trigger indicator.
- `sid 210961802` — `GET` of a short proof file (`/p`, `/pwn.txt`,
  `/rce-proof.txt`, `/oob.txt`) — the file-oracle receipt shape.
- `sid 210961803` — threshold rule: repeated upload-progress POSTs from a
  source (the blind timing-oracle fingerprint).

Wiz telemetry (2026-10-27) added four shapes the original rule set missed:

- `sid 210961804` — **legacy 1005-part chain**: null-byte `PHPSESSID` +
  `name="big"` + progress field. This is the kit Wiz saw die at
  `post_max_size`; the fingerprint matters even when the run fails.
- `sid 210961805` — **A1 chunked arming**: `Transfer-Encoding: chunked`,
  null-byte `PHPSESSID`, `filename=""` empty file controls and nested
  `files[` names. This is the stage that consistently exhausts memory.
- `sid 210961806` — **B1 leak follow-up**: `aNNNN[k]` array reclaim names;
  low-confidence alone, correlate with a preceding A1 from the same source.
- `sid 210961807` — **session-file LFI receipt**: `/tmp/sess_` in the URI
  (the branded session-poisoning tools' `lfi_sink.php` step).
- `sid 210961808` — **inline PHP in the progress field** (fake PHP2Shell
  tools that do not touch either CVE).
- `sid 210961809` — **Content-Type comma bypass**: PHP accepts
  `multipart/form-data, boundary=X`; rules anchored on `;` miss it.
- `sid 210961810` — **worker-occupation burst**: 40+ multi-MB declared
  bodies from one source in 60 s (the pinning stalls).

The highest-value *response* signature is not in the request list: a
successful leak returns `Set-Cookie: PHPSESSID=` carrying hundreds of KB
of URL-encoded heap instead of a 22–32 char id. Alert on
`PHPSESSID` cookie length > 64 and preserve the value — it contains live
libphp/chunk addresses, which is also the fastest way to confirm a
successful chain.

## 1. `proc_creation_lnx_php2shell_post_exploitation.yml`

Sigma rule: a shell / interpreter / download tool appearing as a
**descendant of a PHP worker** (`php-fpm*`, `php-cgi`, `httpd`,
`apache2`, `lsphp`, `php`). Payloads via `shell_exec()`/`system()`/
`exec()`/`passthru()`/`popen()` show as `sh -c -- <command>` children.
Baseline before alerting — many applications legitimately shell out
(image conversion, mail, queue jobs).

Windows counterpart (community):
[SigmaHQ `proc_creation_win_php_inline_command_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_php_inline_command_execution.yml).

## 2. process-watcher (Florian Roth) — free, no endpoint agent

eBPF-based; watches everything PHP workers spawn, with full command
lines, and can SIGKILL matches (dry-run first):

```bash
# quick start (see the repo's php-rce-october-26 guide for full detail)
VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
  https://github.com/Neo23x0/process-watcher/releases/latest | sed 's#.*/##')
curl -fsSLO https://github.com/Neo23x0/process-watcher/releases/download/$VERSION/process-watcher_${VERSION}_linux_amd64.tar.gz
tar xzf process-watcher_${VERSION}_linux_amd64.tar.gz
sudo ./process-watcher-* /process-watcher check-config --config php/php-observe.yaml
sudo ./process-watcher-* /process-watcher --config php/php-observe.yaml
sudo tail -f /var/log/process-watcher/events.jsonl | jq -r '
  select(.event_type=="process.exec" and .lineage.role=="descendant")
  | "\(.timestamp) \(.root.image) > \(.process.image) \(.process.argv // [] | join(" "))"'
```

Repo: <https://github.com/Neo23x0/process-watcher/tree/main/emerging-threats/php-rce-october-26>

## 3. Corroborating signals (SIEM/log pipeline)

- **Trigger signature:** unusual multipart requests followed by
  `PHP Fatal error: Allowed memory size ... exhausted (tried to
  allocate ...) in Unknown on line 0`, repeated 500s, PHP worker churn
- **Leak signature:** unexpectedly large / malformed `PHPSESSID`
  *response* cookies (the PS(id) -> cookie disclosure primitive)
- **Recon from the web account:** `whoami` / `id` / `uname -a` /
  `ipconfig` executed by the UID/GID serving web requests
- **Persistence:** new/unknown PHP files in web roots; new cron jobs
  or accounts created by web-server-UID processes

## 3b. Webroot proof-file write (Sigma `file_event`)

`file_event_lnx_php2shell_webroot_artifact.yml` — the host-side receipt:
the file-oracle chains redirect command output into a webroot file
(`id>/var/www/html/p` in `verify_109619_rce.py`, `pwn.txt`/`oob.txt` in
the public full chains, `rce-proof.txt` in `verify_rce_gadget.py`) and
fetch it over HTTP. Matches a www-data-owned write of those artifact
names directly in a served document root. Pair with the Suricata receipt
rule (`sid 210961802`) to correlate write + fetch.

## 3c. Wiz IOCs and scanner false positives

`iocs_php2shell_2026-10-27.yml` carries the nine IPv4 indicators from Wiz's
telemetry (2026-10-21 → 2026-10-27), the observed request shapes, and the
response signatures. Two cautions:

- **These are failed attempts, not confirmed compromises.** Wiz explicitly
  did not observe end-to-end success in its own telemetry. Treat the IPs as
  hunting pivots, not block-list gospel.
- **Scanner verdicts are weaker than they look.** Assetnote documents a
  false positive on patched PHP: when `memory_limit` is low (2M–32M) or
  `max_multipart_body_parts` is high (≥2785), patched and vulnerable builds
  can both return an empty HTTP 500. Do not close a finding from an OOM
  signal alone; check the vendor package version / backport, not `php -v`.

## 4. Deployment audit gaps (the operational miss)

- **Un-restarted workers:** patched package + old running workers =
  still vulnerable. Alert on package update time vs. worker start time
  (`/proc/<pid>/stat` vs. package manager timestamps)
- `session.upload_progress.enabled=0` must be set administratively
  (FPM pool / Apache `php_admin_value`) AND every worker restarted —
  `.user.ini` / `ini_set()` do not work; per-directory `php_value` can
  re-enable the surface
- `pm.max_requests=1` (if performance allows) breaks the
  same-worker producer/consumer pairing the chains require
- Cgroup/container memory limits are an acceptable availability
  boundary; `RLIMIT_AS`/`RLIMIT_DATA` are NOT (they trigger the
  vulnerable `longjmp()` allocation-failure path)

## 4b. Traffic-tested (2026-10-28)

The rules were exercised against real exploit traffic with a Suricata
sidecar (`jasonish/suricata`) sharing the target container's network
namespace. **All 10 SIDs fired** under the right stimulus. The test found
three real defects, now fixed:

1. **The file was never valid Suricata syntax.** `.rules` files are
   line-oriented; every signature here was split across lines, so zero
   rules loaded. Reformatted to one rule per line (comments preserved).
2. **`sid 210961805` used `http.request_body` four times.** Suricata
   permits one instance of a sticky buffer per rule; the duplicates made
   the rule inert. Rewritten to a single body buffer with three `content`
   matches (PHPSESSID, `filename=`, `files[`) plus one `pcre` for the
   null-byte session id — **rev 2**.
3. **`sid 210961807` matched `/tmp/sess_`, which cannot occur.** The real
   path is `/tmp/sessions/sess_<id>`; the rule now uses
   `http.uri.raw; content:"/tmp/sessions/sess_"` — **rev 2**.

Observed firing counts (one full replay + targeted stimuli):

| SID | Alert | Stimulus |
|---|---|---|
| 210961801 | 5+ | any progress-bearing multipart POST |
| 210961802 | 1 | `GET /p` |
| 210961803 | 1 | 12 progress POSTs in 60 s (threshold 10) |
| 210961804 | 2 | legacy 1005-part, declared + chunked |
| 210961805 | 1 | A1 chunked, null-byte PHPSESSID, empty file parts |
| 210961806 | 1 | dinosn `barr` (`aNNNN[k]`) body |
| 210961807 | 1 | `GET /lfi.php?page=/tmp/sessions/sess_…` |
| 210961808 | 1 | `<?php` in the upload-progress value |
| 210961809 | 1 | comma Content-Type + progress field |
| 210961810 | 1 | 42 large declared bodies in 60 s (threshold 40) |

Operational notes from the test:

- Raise `app-layer.protocols.http.request-body-limit` and
  `stream.reassembly.depth` (e.g. `64mb`) on the sensor, or the ~30 MB B1
  body and late fields are not inspected.
- A1's `PHP_SESSION_UPLOAD_PROGRESS` field sits near the end of a 1 MB
  body and can fall outside the inspected window; `210961805` therefore
  anchors on the early markers plus the null-byte pcre, not on the
  progress field.
- Threshold rules (`210961803`, `210961810`) need the full burst window;
  a single request will not fire them.

## 4c. Repo-local triage set (`suricata.rules`, SIDs 2026200-2026210)

Paired with `scanner/check.py`, these are for local triage rather than fleet
deployment. They cover the shapes the scanner emits: the progress field, a
`PHPSESSID` form field, `<?php` in an upload filename, a serialized object in an
upload filename, and an oversized `PHPSESSID` cookie.

The single highest-value rule is **2026200**: upload-progress has near-zero
legitimate use on most applications.

Ceilings for this set: rules inspect only the body/header window the sensor
exposes, so padding moves a payload out of view; a match is a detection, not
proof of exploitability; and the PHP-level mitigation
(`session.upload_progress.enabled = Off`, with every worker restarted) is more
reliable than any single signature.

## 4d. What none of these rules do

They do not detect the `var_destroy` or 115560 session-decoder paths, which are
shape-identical to a legal session write at the HTTP layer. Those need the
decoder-level or host-level signal described in `docs/DEFENSE_115560.md`, or the
process-watcher lineage check above.

## 5. External references

- Wiz exploitation telemetry & IOCs (2026-10-27):
  <https://www.wiz.io/blog/php2shell-exploitation-so-far>
- Huntress rapid response: <https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities>
- watchTowr FAQ & rapid-reaction briefing: <https://watchtowr.com/intelligence/php-cve-2026-109618-faq/>
- Cloudflare WAF coverage: <https://blog.cloudflare.com/php-vulnerabilities-waf-protection/>
- Community nuclei templates: <https://github.com/Ademking/php2shell-nuclei-templates>
- Host-audit tooling (panels, containers, un-restarted workers): <https://github.com/Kindredman/php2shell-host-audit>
- Detection packs: [Assetnote scanner](https://github.com/assetnote/php2shell-scanner),
  [CypherSecurity](https://github.com/CypherSecurity/php2shell-detection),
  [scadastrangelove](https://github.com/scadastrangelove/php2shell),
  [cseelhoff-ms hunting pack](https://github.com/cseelhoff-ms/php2shell-hunting-pack)
- EOL patches: [Anton-Barinov](https://github.com/Anton-Barinov/php2shell-patches),
  runtime guard: [HOSTED-POWER](https://github.com/HOSTED-POWER/php_uploadprogress_guard)
- Exposure tracker: [pagvac/php2shell-trends](https://github.com/pagvac/php2shell-trends)
- Operational guidance: [NCSC-NL](https://github.com/NCSC-NL/php2shell)

**Reminder:** detection is post-exploitation. Updating PHP
(8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) and restarting every worker is the
only complete mitigation.