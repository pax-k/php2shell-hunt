<?php
/*
 * LAB-ONLY prime endpoint for the Drupal 115560 harness.
 *
 * Accepts the upload-progress POST and deliberately does NOT call
 * session_start(). The rfc1867 hook initialises the session itself and writes
 * one dummy record under the configured php_serialize handler. The exploit
 * request then appends the real record, which is what makes the "php" decoder
 * loop reach the decode-failure var_destroy on 8.4.27.
 */
echo "drupal prime ok\n";
