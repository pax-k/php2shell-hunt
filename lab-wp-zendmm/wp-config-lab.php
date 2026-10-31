<?php
// php2shell WordPress lab — disposable config (never reuse elsewhere).
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp' );
define( 'DB_PASSWORD', 'wppass' );
define( 'DB_HOST', 'db' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

// Lab-only placeholder salts.
define( 'AUTH_KEY',         'php2shell-lab-salt-1' );
define( 'SECURE_AUTH_KEY',  'php2shell-lab-salt-2' );
define( 'LOGGED_IN_KEY',    'php2shell-lab-salt-3' );
define( 'NONCE_KEY',        'php2shell-lab-salt-4' );
define( 'AUTH_SALT',        'php2shell-lab-salt-5' );
define( 'SECURE_AUTH_SALT', 'php2shell-lab-salt-6' );
define( 'LOGGED_IN_SALT',   'php2shell-lab-salt-7' );
define( 'NONCE_SALT',       'php2shell-lab-salt-8' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
