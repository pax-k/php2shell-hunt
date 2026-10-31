<?php
/*
 * LAB-ONLY fidelity probe: identical to vd.php but WITHOUT the class_exists()
 * preload loop. Used to test whether the stock Drupal P5 classes are found by
 * the Composer autoloader during the normal session_start() decode (i.e.
 * without the harness preloading them).
 *
 * No command interface; only starts a session. ?hold=1 is for measurement.
 */
require __DIR__ . '/vendor/autoload.php';

@ini_set('session.serialize_handler', 'php');
$r = @session_start();
@file_put_contents('/tmp/vd_nopreload_log',
    "start r=" . var_export($r, true) . " status=" . session_status() .
    " sid=" . session_id() . " handler=" . ini_get('session.serialize_handler') . "\n",
    FILE_APPEND);

if (!empty($_GET['hold'])) {
    @file_put_contents('/tmp/meas_pid', getmypid());
    sleep(20);
}

echo "drupal nopreload consumer ok\n";
