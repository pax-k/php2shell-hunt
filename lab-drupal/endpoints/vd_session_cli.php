<?php
/*
 * LAB-ONLY CLI session-decoder harness (ASAN/stock CLI).
 *
 * This does NOT use the rfc1867 upload hook. The caller writes a session file
 * in the "php" wire shape ("<ignored-key>|" + payload) and this script starts
 * a session with the "php" handler, so php_session_decode() runs the same
 * php_var_unserialize() on the bytes after "|" as the HTTP consumer.
 *
 * Usage: php vd_session_cli.php <sid>
 * Env:   VD_SESSION_DIR (default /tmp/sessions)
 */
require __DIR__ . '/vendor/autoload.php';

class VdDtorProbe
{
    public function __destruct()
    {
        @file_put_contents('/tmp/vd_probe', "probe dtor pid=" . getmypid() . "\n", FILE_APPEND);
    }
}

$sid = $argv[1] ?? 'vdsession';
$dir = getenv('VD_SESSION_DIR') ?: '/tmp/sessions';
if (!is_dir($dir)) {
    @mkdir($dir, 01777, true);
}
@ini_set('session.save_handler', 'files');
@ini_set('session.save_path', $dir);
@ini_set('session.use_cookies', '0');
@ini_set('session.use_only_cookies', '0');
@ini_set('session.use_strict_mode', '0');
@ini_set('session.serialize_handler', 'php');
session_id($sid);
@session_start();
echo "session decoder returned\n";
