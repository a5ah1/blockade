<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_Auth_Guard {

	const HARD_BLOCK_MESSAGE = 'Access temporarily restricted. Please try again later.';
	const SOFT_BLOCK_MESSAGE = 'Too many login attempts. Please wait a few minutes before trying again.';

	public static function register() {
		add_filter( 'authenticate', array( __CLASS__, 'pre_authenticate' ), 5, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ), 10, 1 );
		add_action( 'wp_login', array( __CLASS__, 'on_login_success' ), 10, 2 );
	}

	public static function pre_authenticate( $user, $username, $password ) {
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user;
		}

		$ip = Blockade_IP_Utils::get_client_ip();

		if ( '' === $ip ) {
			return $user;
		}

		$banned = (string) get_option( Blockade_Database::OPTION_BANNED_IPS, '' );
		if ( Blockade_IP_Utils::list_contains_ip( $ip, $banned ) ) {
			self::hard_block();
		}

		$allowed = (string) get_option( Blockade_Database::OPTION_ALLOWED_IPS, '' );
		if ( Blockade_IP_Utils::list_contains_ip( $ip, $allowed ) ) {
			return $user;
		}

		$tiers = BLOCKADE_TIERS;
		if ( '' !== (string) $username && Blockade_Database::ip_has_login_history_for_user( $ip, $username ) ) {
			$tiers = BLOCKADE_KNOWN_IP_TIERS;
		}

		$windows    = array_column( $tiers, 1 );
		$counts     = Blockade_Database::count_failures_for_ip_buckets( $ip, $windows );
		$last_index = count( $tiers ) - 1;

		foreach ( $tiers as $index => $tier ) {
			$max_attempts = $tier[0];

			if ( $counts[ $index ] >= $max_attempts ) {
				$is_tier_one = ( $index === $last_index );

				if ( $is_tier_one ) {
					remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
					remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );

					return new WP_Error(
						'blockade_rate_limited',
						self::SOFT_BLOCK_MESSAGE
					);
				}

				self::hard_block();
			}
		}

		return $user;
	}

	public static function on_login_failed( $username ) {
		$ip = Blockade_IP_Utils::get_client_ip();
		if ( '' === $ip ) {
			return;
		}

		Blockade_Database::record_failed_attempt( $ip, (string) $username );
	}

	public static function on_login_success( $user_login, $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}

		$ip = Blockade_IP_Utils::get_client_ip();
		if ( '' === $ip ) {
			return;
		}

		$is_new_ip = ! Blockade_Database::ip_has_login_for_user_id( $ip, $user->ID );

		Blockade_Database::record_successful_login( $user->ID, $ip );

		if ( $is_new_ip ) {
			self::send_new_ip_notification( $user, $ip );
		}
	}

	protected static function send_new_ip_notification( $user, $ip ) {
		$to = $user->user_email;
		if ( empty( $to ) ) {
			return;
		}

		$subject = 'New login to your account from a new location';

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$timestamp = wp_date( 'Y-m-d H:i:s T' );

		$body  = sprintf( "A login to your %s account was just recorded from a new IP address.\n\n", $site_name );
		$body .= 'Username: ' . $user->user_login . "\n";
		$body .= 'IP address: ' . $ip . "\n";
		$body .= 'Time: ' . $timestamp . "\n\n";
		$body .= "If this was you, no action is needed.\n";
		$body .= "If you do not recognize this login, please change your password immediately.\n";

		wp_mail( $to, $subject, $body );
	}

	protected static function hard_block() {
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html( self::HARD_BLOCK_MESSAGE ),
			'',
			array( 'response' => 403 )
		);
	}
}
