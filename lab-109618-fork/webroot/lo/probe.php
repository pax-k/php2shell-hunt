<?php
/* Effective per-directory limits + parsed POST size, for lab debugging. */
echo "mem=", ini_get("memory_limit"),
     " post=", ini_get("post_max_size"),
     " count=", count($_POST),
     " peak=", memory_get_peak_usage(true), "\n";
