<?php
/* 128M leak profile. The header lets the lab POC identify the leak worker. */
header("X-Worker: " . getmypid());
echo "OK\n";
