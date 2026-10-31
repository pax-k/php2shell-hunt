<?php
/**
 * php2shell LAB-ONLY UAF harness (NOT a real plugin).
 *
 * Models the two conditions the var_destroy patch-gap needs:
 *   1. a sink: user input reaches unserialize();
 *   2. a gadget: a loaded class whose __destruct() performs a same-size
 *      allocation and then re-enters unserialize().
 *
 * That is the shape of a plugin-level double-unserialize bug, not a
 * WordPress core issue. It exists to measure the impact inside a real
 * WordPress/FPM worker in this repo's own lab. Do NOT install on a live site.
 *
 * Request: POST /?uaf=1  with form field d=<serialized payload>.
 */
if (!defined('ABSPATH')) {
    exit;
}

class WP_UAF_Gadget
{
    public $p = 'i:0;';
    public $n = 64;

    public function __destruct()
    {
        // Same-size allocations reclaim the freed var_entries chunk
        // (sizeof(var_entries) = 8160 B; zend_string 24 + 8135 + 1).
        $spray = array();
        for ($i = 0; $i < (int) $this->n; $i++) {
            $spray[] = str_repeat("\x41", 8135);
        }
        @unserialize($this->p);
    }
}

add_action('init', function () {
    if (!isset($_GET['uaf']) || $_GET['uaf'] !== '1') {
        return;
    }
    if (!isset($_POST['d'])) {
        return;
    }
    // WordPress slashes superglobals; undo that before unserialize().
    @unserialize(wp_unslash($_POST['d']));
    echo "uaf-harness: outer unserialize returned\n";
});
