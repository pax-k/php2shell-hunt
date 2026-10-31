#!/usr/bin/env bash
# Generate the local scanner webroot. Idempotent.
# No php.ini is written: the lab runs the image's stock defaults.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB="$ROOT/webroot"
mkdir -p "$WEB"

cat > "$WEB/index.php" <<'PHP'
<?php
session_start();
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
PHP

cat > "$WEB/echo.php" <<'PHP'
<?php
session_start();
header('Content-Type: text/plain');
foreach ($_SESSION as $key => $value) {
    echo $key, '=', is_scalar($value) ? $value : json_encode($value), "\n";
}
PHP

cat > "$WEB/nosession.php" <<'PHP'
<?php
header('Content-Type: text/plain');
echo "no session_start\n";
PHP

cat > "$WEB/ini.php" <<'PHP'
<?php
header('Content-Type: application/json');
$keys = [
    'session.upload_progress.enabled',
    'session.upload_progress.cleanup',
    'session.use_strict_mode',
    'session.use_only_cookies',
    'memory_limit',
    'post_max_size',
    'upload_max_filesize',
    'max_file_uploads',
    'disable_functions',
];
$out = ['php' => PHP_VERSION, 'sapi' => php_sapi_name()];
foreach ($keys as $key) {
    $out[$key] = ini_get($key);
}
echo json_encode($out, JSON_PRETTY_PRINT), "\n";
PHP

echo "[ok] lab webroot generated at $ROOT"
echo "     no php.ini override: image defaults are the baseline"
echo "     docker compose -f $ROOT/docker-compose.yml up -d php-8.4.26 php-8.4.27"
