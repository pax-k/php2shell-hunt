<?php
/* LAB-ONLY: find the zend_string whose buffer contains MAGIC at offset MOFF
 * and whose header (base-24) says len == VLEN and type == IS_STRING.
 * Usage: php scan_value.php PID HEXMAGIC VLEN [MOFF] */
$pid = (int)($argv[1] ?? 0);
$magic = hex2bin($argv[2] ?? '');
$vlen = (int)($argv[3] ?? 0);
$moff = (int)($argv[4] ?? 0x800);
if ($pid <= 0 || $magic === false || $magic === '' || $vlen <= 0) { fwrite(STDERR, "bad args\n"); exit(2); }
$maps = @file("/proc/$pid/maps"); $fh = @fopen("/proc/$pid/mem", "rb");
if (!$maps || !$fh) { fwrite(STDERR, "no maps/mem\n"); exit(2); }
$found = 0;
foreach ($maps as $line) {
    if (!preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/', $line, $m)) continue;
    if ($m[3][0] !== 'r') continue;
    $path = trim($m[5]);
    if ($path !== '' && $path !== '[heap]') continue;
    $start = hexdec($m[1]); $end = hexdec($m[2]); $len = $end - $start;
    if ($len <= 0 || $len > 512*1024*1024) continue;
    if (@fseek($fh, $start) !== 0) continue;
    $off = 0; $carry = ''; $overlap = strlen($magic) - 1;
    while ($off < $len) {
        $n = min(1 << 20, $len - $off);
        $buf = @fread($fh, $n);
        if ($buf === false || $buf === '') break;
        $hay = $carry . $buf; $from = 0;
        while (($p = strpos($hay, $magic, $from)) !== false) {
            $abs = $start + $off - strlen($carry) + $p;
            $base = $abs - $moff;
            if (@fseek($fh, $base - 24) === 0) {
                $hdr = @fread($fh, 24);
                if ($hdr !== false && strlen($hdr) === 24) {
                    $rc = unpack('V', substr($hdr, 0, 4))[1];
                    $ti = unpack('V', substr($hdr, 4, 4))[1];
                    $l  = unpack('P', substr($hdr, 16, 8))[1];
                    if ($l === $vlen && ($ti & 0x0f) === 6) {
                        printf("%x delta_unknown refcount=%d type=0x%x len=%d\n", $base, $rc, $ti, $l);
                        $found++;
                    }
                }
            }
            $from = $p + 1;
        }
        $carry = $overlap > 0 ? substr($hay, -$overlap) : '';
        $off += strlen($buf);
    }
}
fwrite(STDERR, "value_hits=$found\n");
exit($found ? 0 : 1);
