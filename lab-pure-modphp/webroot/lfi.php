<?php
/*
 * php2shell LAB-ONLY external-leak surface: a trivial LFI, used to read
 * /proc/self/maps and recover the ZendMM / libphp bases (the amplifier's
 * missing seed). This models a common application-level file-read bug.
 */
$page = $_GET['page'] ?? 'index.php';
@include($page);
