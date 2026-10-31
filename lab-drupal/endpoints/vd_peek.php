<?php
/* LAB-ONLY: dump N bytes ending at ADDR from /proc/PID/mem.
 * Usage: php vd_peek.php PID ADDR N */
$pid = (int)($argv[1] ?? 0);
$addr = hexdec($argv[2] ?? '0');
$n = (int)($argv[3] ?? 64);
$fh = @fopen("/proc/$pid/mem", "rb");
if ($pid <= 0 || !$fh || @fseek($fh, $addr - $n) !== 0) {
    exit(2);
}
$b = fread($fh, $n);
echo bin2hex($b), "\n", preg_replace('/[^\x20-\x7e]/', '.', $b), "\n";
