<?php

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$attempts_table = $wpdb->prefix . 'blockade_attempts';
$log_table      = $wpdb->prefix . 'blockade_log';

$wpdb->query( "DROP TABLE IF EXISTS {$attempts_table}" );
$wpdb->query( "DROP TABLE IF EXISTS {$log_table}" );

delete_option( 'blockade_allowed_ips' );
delete_option( 'blockade_banned_ips' );

wp_clear_scheduled_hook( 'blockade_daily_cleanup' );
