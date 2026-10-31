# Major blind spots — deferred backlog

This is a **deferred backlog**, not the current target. The primary objective is
the stock-default RCE in `GOAL.md`. Open a row here only when the active
core+app chain names a concrete need for that extension, library, class, or
platform axis. Do not run a breadth sweep first.

The session/serialization work in the parent lab is a narrow slice. This page
records the missing areas so they are not forgotten, not a claim of coverage.

**Baseline when a row is opened:** the stock official image from
`docs/TARGET_SCOPE.md`, with no `php.ini` override. A row that needs an override
is a labeled variant and cannot be used as the holy-grail baseline.

## 1. Unloaded extensions and PECL

The parsers are separate C code. Loading the extension is not auditing it.

| Extension | Surface | First move |
|---|---|---|
| igbinary | serialize/unserialize callbacks | map `php_igbinary_unserialize`; craft nested references |
| msgpack | serialize/unserialize callbacks | map unpack paths; test depth/refcounts |
| redis | protocol/reply parser, session handler | malformed RESP, nested arrays, timeout paths |
| imagick | ImageMagick blob/read paths | map read/blob calls; fuzz formats in a lab |
| mongodb | BSON and wire protocol | malformed BSON, nested documents, length fields |
| swoole | HTTP/WebSocket parser, coroutines | parser boundaries, upgrade paths, worker lifetime |
| grpc | HTTP/2 and protobuf bindings | frame/length handling, metadata |
| yaml | libyaml parser callbacks | alias/anchor depth, document boundaries |
| apcu | shared-memory cache, serializer | key/value lifetime, expiry, serializer |
| xdebug | debug protocol, stack/var formatting | protocol framing, var depth, property access |

Commands:

```sh
php -m
python3 scripts/inventory_extensions.py
php --ri <extension>
pecl remote-info <extension>
```

Inventory manifest: `research/extensions.json`.

## 2. Bundled C libraries

Real bugs often live below the PHP glue. Track both the library version and the
PHP call sites.

| Library | PHP surface | First move |
|---|---|---|
| libxml2 | DOM, SimpleXML, XMLReader, XSLT | version diff; entity/DTD limits |
| OpenSSL | streams, crypto, TLS | version diff; cert/ASN.1 paths |
| ICU | intl, collation, locale | version diff; resource bounds |
| PCRE2 | `preg_*` | version diff; backtracking/JIT limits |
| libmagic | fileinfo | version diff; crafted magic databases |
| zlib | zlib, gz streams, phar | decompression bounds |
| libzip | zip, phar | archive entry/path handling |
| libsodium | sodium | version diff; API misuse |
| SQLite | PDO_SQLITE, sqlite3 | version diff; extension loading |
| cURL | curl, HTTP/2, URL parsing | version diff; protocol handlers |
| ImageMagick | imagick | version diff; delegate policy |
| GD | imagecreate*, imagegd* | decoder bounds |
| freetype | gd fonts | font parsing |
| libjpeg/libpng | gd JPEG/PNG | decoder bounds |

Inventory manifest: `research/bundled_libs.json`.

## 3. Non-memory vulnerability classes

These need different oracles; a crash fuzzer will not find them.

| Class | Example hypotheses | Method |
|---|---|---|
| Authentication | session fixation, MFA bypass, reset-token reuse | state-machine tests |
| Authorization | IDOR, missing capability check, tenant isolation | role/tenant matrix |
| Business logic | price/quantity, refund, coupon race | invariant tests |
| Crypto misuse | ECB, static IV, weak KDF, signature bypass | test vectors + code review |
| Side channels | timing, error oracle, cache | repeatable timing harness |
| Race conditions | TOCTOU, session/file race, double-consume | concurrent lab drivers |
| XSS/CSRF | stored/reflected, postMessage, same-site gaps | browser/lab harness |
| Cache poisoning | host header, key confusion, purge | proxy + cache matrix |
| Request smuggling | CL/TE, HTTP/2 downgrade, normalization | two-proxy lab |
| Supply chain | typosquat, abandoned package, build script | Composer/lockfile audit |

Inventory manifest: `research/non_memory.json`. Each class needs a lab oracle
before it can produce a finding.

## 4. Build/platform matrix

One container is a proof of concept, not coverage.

Axes:

- ZTS vs NTS;
- aarch64, x86-64, 32-bit;
- little vs big endian;
- musl vs glibc;
- Linux, macOS, Windows;
- debug vs release;
- JIT on/off;
- ASAN geometry vs stock ZendMM.

Manifest: `research/build_matrix.json`. Each non-default row needs a build
recipe, a smoke test, and a reason it matters to the hypothesis.

## 5. Fuzzing depth

The parent corpus was blind mutation. A clean ASAN negative on four corpora is
not parser coverage.

Per target:

1. enumerate entry points (PHP_FUNCTION, unserialize callbacks, stream
   wrappers, SAPI readers);
2. build a seed corpus from valid and near-valid inputs;
3. run coverage-guided fuzzing with ASAN;
4. replay interesting inputs on stock ZendMM;
5. triage: crash vs memory vs logic;
6. minimize and add to the regression corpus.

Manifest: `research/fuzz_targets.json`. "4.1M executions" is a sample size, not
a coverage statement.

## 6. Patch history

Diff every security release and relevant EOL backport, not just one pair.

- php-src branches: 8.5, 8.4, 8.3, 8.2, and EOL backports;
- function/parser changes and symbol shifts;
- backport deltas, because a fix may be incomplete or absent.

Manifest: `research/patch_history.json`.

## What a complete map would require (not current scope)

1. A scoped target, e.g. `php-src 8.4.27`, all bundled extensions, all SAPIs,
   aarch64 and x86-64.
2. A function/parser inventory, not extension-level rows: every PHP_FUNCTION,
   unserialize handler, stream wrapper, and SAPI read/write path.
3. Patch-diff every security release and relevant EOL backport.
4. Coverage-guided fuzzing per parser, with ASAN and stock-ZendMM runs.
5. A SAPI/platform matrix, not one container.
6. An app/package corpus with autoload and version gates.

None of the above is a reason to widen the current pass. They are the cost of a
later coverage claim.

## Opening order (only when the active chain needs it)

1. Extension or library the chain actually reaches.
2. One function/parser map for that entry point.
3. One harness or reproducer on the stock baseline.
4. One control: patched, removed, or bias.
5. Only then, the next row.

Build matrix, fuzz breadth, and patch history wait until the terminal call
exists. No "all parsers" claim is allowed.

## Evidence and ceilings

- Inventory is not audit.
- Extension loaded is not extension covered.
- A library version is not a vulnerability.
- A fuzz negative is only for that harness, seed corpus, and time budget.
- A logic finding needs a state-machine oracle, not a crash.

