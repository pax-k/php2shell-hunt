<?php
header('Content-Type: text/plain');
echo "pid=" . getmypid() . "\n";
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
echo "memory_limit: " . ini_get('memory_limit') . "\n";
echo "post_max_size: " . ini_get('post_max_size') . "\n";
echo "max_input_vars: " . ini_get('max_input_vars') . "\n";
echo "display_errors: " . ini_get('display_errors') . "\n";
echo "POST count: " . count($_POST) . "\n";
echo "FILES count: " . count($_FILES) . "\n";
