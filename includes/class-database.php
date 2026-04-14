<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_Database {

	const OPTION_ALLOWED_IPS                = 'blockade_allowed_ips';
	const OPTION_BANNED_IPS                 = 'blockade_banned_ips';
	const OPTION_EMAIL_NEW_LOCATION_ENABLED = 'blockade_email_new_location_enabled';

	public static function attempts_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockade_attempts';
	}

	public static function log_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockade_log';
	}

	private static function threshold( $seconds ) {
		return gmdate( 'Y-m-d H:i:s', time() - (int) $seconds );
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

		if ( false === get_option( self::OPTION_ALLOWED_IPS, false ) ) {
			add_option( self::OPTION_ALLOWED_IPS, '' );
		}
		if ( false === get_option( self::OPTION_BANNED_IPS, false ) ) {
			add_option( self::OPTION_BANNED_IPS, '' );
		}
		if ( false === get_option( self::OPTION_EMAIL_NEW_LOCATION_ENABLED, false ) ) {
			add_option( self::OPTION_EMAIL_NEW_LOCATION_ENABLED, '1' );
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

	/**
	 * Count this IP's failures in each of the given windows with a single query.
	 * Returns counts keyed by the same keys as $windows.
	 */
	public static function count_failures_for_ip_buckets( $ip, array $windows ) {
		global $wpdb;

		if ( empty( $windows ) ) {
			return array();
		}

		$selects = array();
		$args    = array();
		foreach ( $windows as $index => $seconds ) {
			$selects[] = 'SUM(CASE WHEN attempted_at >= %s THEN 1 ELSE 0 END) AS c_' . (int) $index;
			$args[]    = self::threshold( $seconds );
		}
		$args[] = $ip;
		$args[] = self::threshold( max( $windows ) );

		$sql = 'SELECT ' . implode( ', ', $selects ) . ' FROM ' . self::attempts_table()
			. ' WHERE ip = %s AND attempted_at >= %s';

		$row = $wpdb->get_row( $wpdb->prepare( $sql, $args ), ARRAY_A );

		$out = array();
		foreach ( $windows as $index => $seconds ) {
			$key           = 'c_' . (int) $index;
			$out[ $index ] = isset( $row[ $key ] ) ? (int) $row[ $key ] : 0;
		}
		return $out;
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

	/**
	 * Per-IP failure counts across all windows plus latest attempt, in one query.
	 * Returns rows with: ip, latest, c_0..c_N matching $windows keys.
	 */
	public static function get_locked_out_summary( array $windows ) {
		global $wpdb;

		if ( empty( $windows ) ) {
			return array();
		}

		$selects = array( 'ip', 'MAX(attempted_at) AS latest' );
		$args    = array();
		foreach ( $windows as $index => $seconds ) {
			$selects[] = 'SUM(CASE WHEN attempted_at >= %s THEN 1 ELSE 0 END) AS c_' . (int) $index;
			$args[]    = self::threshold( $seconds );
		}
		$args[] = self::threshold( max( $windows ) );

		$sql = 'SELECT ' . implode( ', ', $selects ) . ' FROM ' . self::attempts_table()
			. ' WHERE attempted_at >= %s GROUP BY ip';

		return $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );
	}

	public static function cleanup_attempts( $retention_seconds ) {
		return self::cleanup_table( self::attempts_table(), 'attempted_at', $retention_seconds );
	}

	public static function cleanup_log( $retention_seconds ) {
		return self::cleanup_table( self::log_table(), 'logged_in_at', $retention_seconds );
	}

	private static function cleanup_table( $table, $time_column, $retention_seconds ) {
		global $wpdb;

		return $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE {$time_column} < %s",
				self::threshold( $retention_seconds )
			)
		);
	}
}
