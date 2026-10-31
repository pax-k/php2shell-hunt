<?php
/* LAB-ONLY: find every MAGIC occurrence in a worker's anon rw mappings and
 * report the candidate input-value start (hit - MOFF - DOFF) together with the
 * bytes found there. The real raw session input buffer has the serialized
 * array prefix (`a:1018:{i:0;s:4096:"`) immediately before the blob; the
 * `s:4096` zend_string copy does not.
 *
 * Usage: php scan_prefix.php PID HEXMAGIC MOFF DOFF PREFIX_LEN
 */
$pid = (int)($argv[1] ?? 0);
$magic = hex2bin($argv[2] ?? '');
$moff = (int)($argv[3] ?? 0x800);
$doff = (int)($argv[4] ?? 0x14);
$plen = (int)($argv[5] ?? 20);
if ($pid <= 0 || $magic === false || $magic === '') {
    fwrite(STDERR, "bad args\n");
    exit(2);
}
$maps = @file("/proc/$pid/maps");
$fh = @fopen("/proc/$pid/mem", "rb");
$fh2 = @fopen("/proc/$pid/mem", "rb");
if (!$maps || !$fh || !$fh2) {
    fwrite(STDERR, "no maps/mem\n");
    exit(2);
}
$hits = 0;
foreach ($maps as $line) {
    if (!preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/', $line, $m)) {
        continue;
    }
    if ($m[3][0] !== 'r') {
        continue;
    }
    $path = trim($m[5]);
    if ($path !== '' && $path !== '[heap]') {
        continue;
    }
    $start = hexdec($m[1]);
    $end = hexdec($m[2]);
    $len = $end - $start;
    if ($len <= 0 || $len > 512 * 1024 * 1024) {
        continue;
    }
    if (@fseek($fh, $start) !== 0) {
        continue;
    }
    $chunk = 1 << 20;
    $overlap = strlen($magic) - 1;
    $carry = '';
    $off = 0;
    while ($off < $len) {
        $want = min($chunk, $len - $off);
        $data = fread($fh, $want);
        if ($data === '' || $data === false) {
            break;
        }
        $buf = $carry . $data;
        $baseoff = $off - strlen($carry);
        $p = 0;
        while (($p = strpos($buf, $magic, $p)) !== false) {
            $abs = $start + $baseoff + $p;
            $vstart = $abs - $moff - $doff;
            $pre = '';
            if ($vstart >= $start && $vstart + $plen <= $end) {
                if (@fseek($fh2, $vstart) === 0) {
                    $pre = (string)fread($fh2, $plen);
                }
            }
            $ctx = '';
            if ($vstart >= 32 && @fseek($fh2, $vstart - 32) === 0) {
                $ctx = bin2hex((string)fread($fh2, 32));
            }
            printf("0x%x vstart=0x%x prefix=%s ctx=%s\n",
                   $abs, $vstart, bin2hex($pre), $ctx);
            $hits++;
            $p++;
        }
        $carry = substr($buf, -$overlap);
        $off += $want;
    }
}
if (!$hits) {
    fwrite(STDERR, "no hits\n");
    exit(1);
}
