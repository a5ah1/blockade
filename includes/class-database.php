<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_Database {

	public static function attempts_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockade_attempts';
	}

	public static function log_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockade_log';
	}

	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$attempts        = self::attempts_table();
		$log             = self::log_table();

		$attempts_sql = "CREATE TABLE {$attempts} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(45) NOT NULL,
			username VARCHAR(255) NOT NULL,
			attempted_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY ip_attempted_at (ip, attempted_at)
		) {$charset_collate};";

		$log_sql = "CREATE TABLE {$log} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT UNSIGNED NOT NULL,
			ip VARCHAR(45) NOT NULL,
			logged_in_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY user_logged_in_at (user_id, logged_in_at),
			KEY ip_user (ip, user_id)
		) {$charset_collate};";

		dbDelta( $attempts_sql );
		dbDelta( $log_sql );

		if ( false === get_option( 'blockade_allowed_ips', false ) ) {
			add_option( 'blockade_allowed_ips', '' );
		}
		if ( false === get_option( 'blockade_banned_ips', false ) ) {
			add_option( 'blockade_banned_ips', '' );
		}
	}

	public static function record_failed_attempt( $ip, $username ) {
		global $wpdb;

		$wpdb->insert(
			self::attempts_table(),
			array(
				'ip'           => $ip,
				'username'     => mb_substr( (string) $username, 0, 255 ),
				'attempted_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s' )
		);
	}

	public static function record_successful_login( $user_id, $ip ) {
		global $wpdb;

		$wpdb->insert(
			self::log_table(),
			array(
				'user_id'      => (int) $user_id,
				'ip'           => $ip,
				'logged_in_at' => current_time( 'mysql', true ),
			),
			array( '%d', '%s', '%s' )
		);
	}

	public static function count_failures_for_ip( $ip, $window_seconds ) {
		global $wpdb;

		$threshold = gmdate( 'Y-m-d H:i:s', time() - (int) $window_seconds );

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . self::attempts_table() . ' WHERE ip = %s AND attempted_at >= %s',
				$ip,
				$threshold
			)
		);
	}

	public static function ip_has_login_history_for_user( $ip, $username ) {
		global $wpdb;

		$log_table = self::log_table();

		$found = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT 1 FROM {$log_table} l
				 INNER JOIN {$wpdb->users} u ON u.ID = l.user_id
				 WHERE l.ip = %s AND u.user_login = %s
				 LIMIT 1",
				$ip,
				$username
			)
		);

		return ! empty( $found );
	}

	public static function ip_has_login_for_user_id( $ip, $user_id ) {
		global $wpdb;

		$found = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT 1 FROM ' . self::log_table() . ' WHERE ip = %s AND user_id = %d LIMIT 1',
				$ip,
				(int) $user_id
			)
		);

		return ! empty( $found );
	}

	public static function get_recent_logins( $limit = 100 ) {
		global $wpdb;

		$limit = max( 1, (int) $limit );

		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT l.id, l.user_id, l.ip, l.logged_in_at, u.user_login
				 FROM ' . self::log_table() . ' l
				 LEFT JOIN ' . $wpdb->users . ' u ON u.ID = l.user_id
				 ORDER BY l.logged_in_at DESC
				 LIMIT %d',
				$limit
			)
		);
	}

	public static function get_recent_attempts( $limit = 100 ) {
		global $wpdb;

		$limit = max( 1, (int) $limit );

		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, ip, username, attempted_at FROM ' . self::attempts_table() . ' ORDER BY attempted_at DESC LIMIT %d',
				$limit
			)
		);
	}

	public static function get_distinct_recent_ips( $window_seconds ) {
		global $wpdb;

		$threshold = gmdate( 'Y-m-d H:i:s', time() - (int) $window_seconds );

		return $wpdb->get_col(
			$wpdb->prepare(
				'SELECT DISTINCT ip FROM ' . self::attempts_table() . ' WHERE attempted_at >= %s',
				$threshold
			)
		);
	}

	public static function latest_attempt_for_ip( $ip ) {
		global $wpdb;

		return $wpdb->get_var(
			$wpdb->prepare(
				'SELECT MAX(attempted_at) FROM ' . self::attempts_table() . ' WHERE ip = %s',
				$ip
			)
		);
	}

	public static function cleanup_attempts( $retention_seconds ) {
		global $wpdb;

		$threshold = gmdate( 'Y-m-d H:i:s', time() - (int) $retention_seconds );

		return $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . self::attempts_table() . ' WHERE attempted_at < %s',
				$threshold
			)
		);
	}

	public static function cleanup_log( $retention_seconds ) {
		global $wpdb;

		$threshold = gmdate( 'Y-m-d H:i:s', time() - (int) $retention_seconds );

		return $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . self::log_table() . ' WHERE logged_in_at < %s',
				$threshold
			)
		);
	}
}
