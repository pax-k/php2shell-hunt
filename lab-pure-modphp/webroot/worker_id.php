<?php
header('Content-Type: text/plain');
echo "pid=" . getmypid() . "\n";
echo "sapi=" . php_sapi_name() . "\n";
