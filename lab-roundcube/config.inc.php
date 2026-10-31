<?php
/*
 * LAB-ONLY Roundcube 1.6.11 configuration for the CVE-2026-115560 precondition
 * harness. Targets 127.0.0.1 only; the lab plugin executes the fixed benign
 * command "id>/tmp/vd 2>&1".
 *
 * session_storage='php' selects rcube_session_php, which uses PHP's native
 * file save handler. That is required so the record written by the
 * session.upload_progress hook (server side: files + php_serialize) is the
 * same record the application decodes at session_start(). Stock Roundcube's
 * db/redis/memcache drivers read their own store and never see that record
 * (documented in docs/ROUNDCUBE_115560.md).
 */
$config['db_dsnw'] = 'sqlite:////tmp/rc.sqlite?mode=0646';

// Native PHP sessions (files). No DB/Redis save handler on this path.
$config['session_storage'] = 'php';
$config['session_name']    = 'roundcube_sessid';
$config['session_lifetime'] = 10;

// Writable scratch dirs created by the container command.
$config['temp_dir'] = '/tmp/rc-temp';
$config['log_dir']  = '/tmp/rc-logs';

$config['enable_installer'] = false;
$config['skin'] = 'elastic';

// Lab plugin: loaded in rcmail::startup() BEFORE session_init(). Its top-level
// code performs the runtime serialize-handler switch and defines the gadget
// classes (VdSimple / CachePurge).
$config['plugins'] = ['vd115560'];
