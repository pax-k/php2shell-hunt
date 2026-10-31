<?php
/*
 * LAB-ONLY probe: reports the session-module state the exploit request has at
 * script start, BEFORE any application code. Does NOT call session_start() so
 * the upload-progress record is left untouched.
 *
 * Discriminating facts for the Redis precondition:
 *   - whether the rfc1867 hook already activated the session (session_status 2)
 *     which would make rcmail::session_init() return early, and
 *   - which server handlers wrote the record.
 */
header('Content-Type: application/json');
$out = [
    'php'               => PHP_VERSION,
    'redis_ext'         => extension_loaded('redis'),
    'session_status'    => session_status(),
    'session_id'        => session_id(),
    'session_name'      => session_name(),
    'save_handler'      => ini_get('session.save_handler'),
    'save_path'         => ini_get('session.save_path'),
    'serialize_handler' => ini_get('session.serialize_handler'),
    'upload_progress'   => ini_get('session.upload_progress.enabled'),
    'cleanup'           => ini_get('session.upload_progress.cleanup'),
    'cookies'           => array_keys($_COOKIE),
    'session_keys'      => is_array($_SESSION ?? null) ? array_keys($_SESSION) : null,
    'post_keys'         => array_keys($_POST),
    'files'             => array_keys($_FILES),
];
echo json_encode($out), "\n";
