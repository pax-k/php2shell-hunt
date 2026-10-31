<?php
/*
 * LAB-ONLY Roundcube 1.6.11 configuration — Redis session store.
 *
 * The only difference from lab-roundcube/config/config.inc.php is
 * session_storage='redis' + the redis_hosts entry. Stock Roundcube's
 * rcube_session_redis constructor calls register_session_handler(), which runs
 * ini_set('session.serialize_handler','php') and session_set_save_handler().
 *
 * Targets 127.0.0.1 only. Lab plugin vd115560 is unchanged (fixed benign
 * command "id>/tmp/vd 2>&1").
 */
$config['db_dsnw'] = 'sqlite:////tmp/rc.sqlite?mode=0646';

$config['session_storage'] = 'redis';
$config['redis_hosts']     = ['redis:6379'];
$config['session_name']    = 'roundcube_sessid';
$config['session_lifetime'] = 10;

$config['temp_dir'] = '/tmp/rc-temp';
$config['log_dir']  = '/tmp/rc-logs';

$config['enable_installer'] = false;
$config['skin'] = 'elastic';

$config['plugins'] = ['vd115560'];
