<?php
/**
 * Generic ASAN fuzz loop for the disclosure campaign.
 *
 * Usage: php asan_run.php <corpus.b64> <callback.php> [start_index]
 *
 * - corpus.b64 : one base64-encoded input per line
 * - callback.php : must define  fuzz_one(string $bytes): mixed
 *   (return a string to have its bytes checked, or any value)
 *
 * For every input it prints "PROCESSING <idx>" to stderr BEFORE running, so a
 * crash leaves the killing index recoverable (the runner bisects from there).
 * It also prints "RESULT <idx> <len> <sha1>" to stdout for differential
 * comparison across runs / heap states.
 *
 * Lab-only. Runs under ASAN; USE_ZEND_ALLOC=0 in the image.
 */
if ($argc < 3) {
    fwrite(STDERR, "usage: asan_run.php corpus.b64 callback.php [start]\n");
    exit(2);
}
$corpus = $argv[1];
$cb = $argv[2];
$start = (int)($argv[3] ?? 0);
require $cb;

$lines = file($corpus, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$n = count($lines);
for ($i = $start; $i < $n; $i++) {
    fwrite(STDERR, "PROCESSING $i\n");
    $bytes = base64_decode($lines[$i], true);
    if ($bytes === false) { continue; }
    $out = fuzz_one($bytes);
    $s = is_string($out) ? $out : serialize($out);
    printf("RESULT %d %d %s\n", $i, strlen($s), sha1($s));
}
fwrite(STDERR, "DONE $n\n");
