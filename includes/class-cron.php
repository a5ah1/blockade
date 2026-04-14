<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_Cron {

	public static function register() {
		add_action( BLOCKADE_CRON_HOOK, array( __CLASS__, 'run_cleanup' ) );
	}

	public static function schedule() {
		if ( ! wp_next_scheduled( BLOCKADE_CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', BLOCKADE_CRON_HOOK );
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( BLOCKADE_CRON_HOOK );
	}

	public static function run_cleanup() {
		Blockade_Database::cleanup_attempts( BLOCKADE_ATTEMPTS_RETENTION );
		Blockade_Database::cleanup_log( BLOCKADE_LOG_RETENTION );
	}
}
