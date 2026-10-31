<?php
/* LAB-ONLY worker identity oracle (action D). Returns the handling prefork
 * child's pid so poc/verify_worker_pinning.py can measure spread. */
header('Content-Type: text/plain');
echo 'pid=' . getmypid() . "\n";
