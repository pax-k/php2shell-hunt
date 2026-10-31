<?php
/* LAB-ONLY scanner diagnostic. */
$magic = hex2bin('56445541464d41474943307864656164');
$carrier = str_repeat("\x00", 0x1000);
for ($i = 0; $i < 16; $i++) { $carrier[0x800 + $i] = $magic[$i]; }
for ($i = 0; $i < 16; $i++) { $carrier[0x810 + $i] = $magic[$i]; }
$needle = $magic . $magic;
$pid = getmypid();
$maps = file("/proc/$pid/maps");
$fh = fopen("/proc/$pid/mem", "rb");
$found = array();
$scanned = 0;
foreach ($maps as $line) {
    if (!preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+(....)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/', $line, $m)) { continue; }
    if ($m[3][0] !== 'r') { continue; }
    $path = trim($m[5]);
    if ($path !== '' && $path !== '[heap]') { continue; }
    $start = hexdec($m[1]); $end = hexdec($m[2]); $len = $end - $start;
    if ($len <= 0 || $len > 512 * 1024 * 1024) { continue; }
    if (@fseek($fh, $start) !== 0) { continue; }
    $scanned += $len;
    $off = 0; $carry = '';
    while ($off < $len) {
        $n = min(1 << 20, $len - $off);
        $buf = @fread($fh, $n);
        if ($buf === false || $buf === '') { break; }
        $hay = $carry . $buf;
        $from = 0;
        while (($p = strpos($hay, $needle, $from)) !== false) {
            $found[] = dechex($start + $off - strlen($carry) + $p);
            $from = $p + 1;
        }
        $carry = substr($hay, -31);
        $off += strlen($buf);
    }
}
echo "scanned=$scanned maps=" . count($maps) . " found=" . implode(",", $found) . "\n";
