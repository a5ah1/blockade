<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_IP_Utils {

	public static function get_client_ip() {
		$candidates = array();

		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidates[] = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			$parts     = explode( ',', $forwarded );
			$candidates[] = trim( $parts[0] );
		}

		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$candidates[] = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		foreach ( $candidates as $ip ) {
			$ip = trim( $ip );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '';
	}

	public static function is_valid_ip( $value ) {
		return (bool) filter_var( $value, FILTER_VALIDATE_IP );
	}

	public static function is_valid_ip_or_cidr( $entry ) {
		if ( strpos( $entry, '/' ) !== false ) {
			$parts = explode( '/', $entry, 2 );
			if ( count( $parts ) !== 2 ) {
				return false;
			}
			list( $addr, $bits ) = $parts;
			if ( ! filter_var( $addr, FILTER_VALIDATE_IP ) ) {
				return false;
			}
			if ( ! ctype_digit( $bits ) ) {
				return false;
			}
			$bits = (int) $bits;
			if ( filter_var( $addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $bits >= 0 && $bits <= 32;
			}
			return $bits >= 0 && $bits <= 128;
		}
		return (bool) filter_var( $entry, FILTER_VALIDATE_IP );
	}

	public static function cidr_match( $ip, $range ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		if ( strpos( $range, '/' ) === false ) {
			if ( ! filter_var( $range, FILTER_VALIDATE_IP ) ) {
				return false;
			}
			$a = inet_pton( $ip );
			$b = inet_pton( $range );
			return ( false !== $a && false !== $b && $a === $b );
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$bits = (int) $bits;

		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$full_bytes = intdiv( $bits, 8 );
		$remainder  = $bits % 8;

		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( $remainder > 0 ) {
			$mask_byte   = chr( ( 0xFF << ( 8 - $remainder ) ) & 0xFF );
			$ip_byte     = $ip_bin[ $full_bytes ];
			$subnet_byte = $subnet_bin[ $full_bytes ];
			if ( ( ord( $ip_byte ) & ord( $mask_byte ) ) !== ( ord( $subnet_byte ) & ord( $mask_byte ) ) ) {
				return false;
			}
		}

		return true;
	}

	public static function parse_list( $raw ) {
		$valid   = array();
		$invalid = array();

		foreach ( self::normalize_lines( $raw ) as $line ) {
			if ( self::is_valid_ip_or_cidr( $line ) ) {
				$valid[ $line ] = true;
			} else {
				$invalid[] = $line;
			}
		}

		return array( array_keys( $valid ), $invalid );
	}

	public static function list_contains_ip( $ip, $raw_list ) {
		if ( '' === $ip ) {
			return false;
		}

		foreach ( self::normalize_lines( $raw_list ) as $line ) {
			if ( self::cidr_match( $ip, $line ) ) {
				return true;
			}
		}

		return false;
	}

	private static function normalize_lines( $raw ) {
		$lines = preg_split( '/\r\n|\r|\n/', (string) $raw );
		if ( ! is_array( $lines ) ) {
			return array();
		}

		$out = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}
}
