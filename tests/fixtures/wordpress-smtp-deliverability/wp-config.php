<?php
define( 'DB_NAME', 'wordpress' );
define( 'WPMS_ON', true );
define( 'WPMS_SMTP_HOST', 'smtp.esp.example.net' );
define( 'WPMS_SMTP_PORT', 587 );
define( 'WPMS_SMTP_USER', 'apikey' );
define( 'WPMS_SMTP_PASS', 'FIXTURE-NOT-A-REAL-VALUE' ); // gitleaks:allow
define( 'DISABLE_WP_CRON', true );
$table_prefix = 'wp_';
require_once ABSPATH . 'wp-settings.php';
