<?php
/*
 * LAB-ONLY second profile: server store is Redis, but Roundcube uses its
 * native `php` session driver (session_storage='php'). rcube_session_php does
 * NOT install a save handler, so PHP's own phpredis session handler reads and
 * writes, and the lab plugin's runtime ini_set('php') is the only switch.
 *
 * This isolates store from driver: if this fires, the Redis store is not the
 * blocker for the plugin-assisted profile — the wrapper envelope in
 * rcube_session_redis::read() is.
 */
$config['db_dsnw'] = 'sqlite:////tmp/rc.sqlite?mode=0646';

$config['session_storage'] = 'php';
$config['session_name']    = 'roundcube_sessid';
$config['session_lifetime'] = 10;

$config['temp_dir'] = '/tmp/rc-temp';
$config['log_dir']  = '/tmp/rc-logs';

$config['enable_installer'] = false;
$config['skin'] = 'elastic';

$config['plugins'] = ['vd115560'];
