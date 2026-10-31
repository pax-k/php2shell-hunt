<?php
/* php2shell stock mod_php lab — on-demand OOM probe.
 * Forces display_errors so the fatal message carries the exact
 * memory_limit; used by php2shell/sapi.py and the scanner-style profile. */
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);
$a = str_repeat('x', 256 * 1024 * 1024);
echo "no oom\n";
