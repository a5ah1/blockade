<?php

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/includes/class-database.php';

global $wpdb;

$wpdb->query( 'DROP TABLE IF EXISTS ' . Blockade_Database::attempts_table() );
$wpdb->query( 'DROP TABLE IF EXISTS ' . Blockade_Database::log_table() );

delete_option( Blockade_Database::OPTION_ALLOWED_IPS );
delete_option( Blockade_Database::OPTION_BANNED_IPS );
delete_option( Blockade_Database::OPTION_EMAIL_NEW_LOCATION_ENABLED );

// Literal kept in sync with BLOCKADE_CRON_HOOK in blockade.php — plugin bootstrap
// isn't loaded during uninstall, so the constant isn't defined here.
wp_clear_scheduled_hook( 'blockade_daily_cleanup' );
