<?php
/*
 * LAB-ONLY negative control: the same application without the runtime handler
 * switch. The configured php_serialize handler decodes the progress record as
 * a normal array; the "|" inside the key is just data. No attacker-controlled
 * php_var_unserialize() runs, so the CachePurge dtor never fires.
 */
class CachePurge
{
    public $key;
    public function __destruct()
    {
        @file_put_contents('/tmp/noswitch_dtor', getmypid());
    }
}

session_start();
echo "115560 noswitch ok\n";
