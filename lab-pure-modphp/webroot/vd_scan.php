<?php
/* LAB-ONLY /proc/<pid>/mem scanner: find a magic byte pattern in the
 * writable anonymous mappings of a worker and print its virtual address.
 * Usage: php vd_scan.php <pid> <hex-magic> [max-mb]
 */
$pid = (int)($argv[1] ?? 0);
$magic = hex2bin($argv[2] ?? '');
$maxmb = (int)($argv[3] ?? 1024);
if ($pid <= 0 || $magic === false || $magic === '') { fwrite(STDERR, "bad args\n"); exit(2); }
$maps = @file("/proc/$pid/maps");
if (!$maps) { fwrite(STDERR, "no maps\n"); exit(2); }
$fh = @fopen("/proc/$pid/mem", "rb");
if (!$fh) { fwrite(STDERR, "no mem\n"); exit(2); }

$scanned = 0;
foreach ($maps as $line) {
    if (!preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/', $line, $m)) {
        continue;
    }
    if ($m[3][0] !== 'r') { continue; }
    $path = trim($m[5]);
    /* anonymous private mappings (ZendMM heap) and [heap] only */
    if ($path !== '' && $path !== '[heap]') { continue; }
    $start = hexdec($m[1]);
    $end = hexdec($m[2]);
    $len = $end - $start;
    if ($len <= 0 || $len > 512 * 1024 * 1024) { continue; }
    if ($scanned + $len > $maxmb * 1024 * 1024) { break; }
    $scanned += $len;
    if (@fseek($fh, $start) !== 0) { continue; }
    $chunk = 1 << 20;
    $overlap = strlen($magic) - 1;
    $carry = '';
    $off = 0;
    while ($off < $len) {
        $n = min($chunk, $len - $off);
        $buf = @fread($fh, $n);
        if ($buf === false || $buf === '') { break; }
        $hay = $carry . $buf;
        $from = 0;
        while (($p = strpos($hay, $magic, $from)) !== false) {
            /* reject the scanner's own needle string: the carrier has zero
             * padding right before the marker, the needle has its len there */
            if ($p >= 8 && unpack('P', substr($hay, $p - 8, 8))[1] === 0) {
                echo "0x" . dechex($start + $off - strlen($carry) + $p) . "\n";
                exit(0);
            }
            $from = $p + 1;
        }
        $carry = $overlap > 0 ? substr($hay, -$overlap) : '';
        $off += strlen($buf);
    }
}
fwrite(STDERR, "not found (scanned $scanned bytes)\n");
exit(1);
