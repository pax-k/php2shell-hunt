<?php
/* LAB-ONLY diagnostic twin of index.php for the race vs direct dtor-count
 * investigation. Same decode path; every destructor invocation logs a
 * backtrace. Not used by the exploit drivers. */
function dlog($s) { @file_put_contents('/tmp/dtor_log', sprintf("%.6f %s %s\n", microtime(true), $_SERVER['REQUEST_URI'] ?? '-', $s), FILE_APPEND); }

class CachePurge
{
    public $key;
    public function __destruct()
    {
        static $inv = 0;
        $inv++;
        dlog("dtor inv=$inv pid=" . getmypid());
        ob_start();
        debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
        dlog(ob_get_clean());
    }
}

register_shutdown_function(function () { dlog("shutdown"); });
@ini_set('session.serialize_handler', 'php');
session_start();
dlog("after-session-start");
echo "decoy ok\n";
