<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_IP_Utils {

	const SOURCE_LEGACY     = 'legacy';
	const SOURCE_DIRECT     = 'direct';
	const SOURCE_CLOUDFLARE = 'cloudflare';
	const SOURCE_PROXY      = 'proxy';

	const SOURCES = array(
		self::SOURCE_LEGACY,
		self::SOURCE_DIRECT,
		self::SOURCE_CLOUDFLARE,
		self::SOURCE_PROXY,
	);

	// Published at https://www.cloudflare.com/ips/ — checked 2026-11-11.
	// Override with the `blockade_cloudflare_ranges` filter if Cloudflare adds ranges
	// before a plugin release catches up.
	const CLOUDFLARE_RANGES = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	public static function get_client_ip() {
		return self::resolve_ip(
			Blockade_Database::get_ip_source(),
			$_SERVER,
			(string) get_option( Blockade_Database::OPTION_TRUSTED_PROXIES, '' )
		);
	}

	/**
	 * Resolve the client IP for a given source mode. Pure apart from the
	 * Cloudflare-ranges filter, so the admin diagnostic can preview every mode.
	 */
	public static function resolve_ip( $source, array $server, $trusted_proxies_raw = '' ) {
		$remote = self::normalize_ip( self::server_value( $server, 'REMOTE_ADDR' ) );

		switch ( $source ) {
			case self::SOURCE_DIRECT:
				return $remote;

			case self::SOURCE_CLOUDFLARE:
				if ( '' !== $remote && self::is_cloudflare_ip( $remote ) ) {
					$cf = self::normalize_ip( self::server_value( $server, 'HTTP_CF_CONNECTING_IP' ) );
					if ( '' !== $cf ) {
						return $cf;
					}
				}
				return $remote;

			case self::SOURCE_PROXY:
				return self::resolve_forwarded_ip( $remote, $server, $trusted_proxies_raw );

			default:
				return self::resolve_legacy_ip( $server );
		}
	}

	/**
	 * Pre-1.0.5 behavior, kept as the default: CF-Connecting-IP, then the first
	 * X-Forwarded-For entry, then REMOTE_ADDR. The headers are trusted from any
	 * sender, so this can be spoofed on servers reachable without a proxy.
	 */
	protected static function resolve_legacy_ip( array $server ) {
		$candidates = array( self::server_value( $server, 'HTTP_CF_CONNECTING_IP' ) );

		$forwarded    = self::server_value( $server, 'HTTP_X_FORWARDED_FOR' );
		$parts        = explode( ',', $forwarded );
		$candidates[] = trim( $parts[0] );

		$candidates[] = self::server_value( $server, 'REMOTE_ADDR' );

		foreach ( $candidates as $ip ) {
			if ( self::is_valid_ip( $ip ) ) {
				return $ip;
			}
		}

		return '';
	}

	/**
	 * Walk X-Forwarded-For right to left, skipping trusted proxies. Entries to the
	 * left of the first untrusted hop were written by the client and are ignored.
	 */
	protected static function resolve_forwarded_ip( $remote, array $server, $trusted_proxies_raw ) {
		if ( '' === $remote || ! self::list_contains_ip( $remote, $trusted_proxies_raw ) ) {
			return $remote;
		}

		$hop = $remote;
		foreach ( array_reverse( self::forwarded_entries( $server ) ) as $raw_entry ) {
			if ( '' === trim( $raw_entry ) ) {
				continue;
			}
			$entry = self::normalize_ip( $raw_entry );
			if ( '' === $entry ) {
				return $hop;
			}
			$hop = $entry;
			if ( ! self::list_contains_ip( $entry, $trusted_proxies_raw ) ) {
				return $entry;
			}
		}

		return $hop;
	}

	/**
	 * X-Forwarded-For split into raw entries. Deliberately not run through
	 * sanitize_text_field: it empties the whole string on invalid UTF-8, which
	 * would let a client discard the hops a trusted proxy appended. Each entry
	 * is validated by normalize_ip() before use.
	 */
	public static function forwarded_entries( array $server ) {
		if ( empty( $server['HTTP_X_FORWARDED_FOR'] ) || ! is_string( $server['HTTP_X_FORWARDED_FOR'] ) ) {
			return array();
		}
		return explode( ',', wp_unslash( $server['HTTP_X_FORWARDED_FOR'] ) );
	}

	/**
	 * Reduce a header or REMOTE_ADDR value to a bare IP: strips "[v6]:port" and
	 * "v4:port", and turns IPv4-mapped IPv6 (::ffff:1.2.3.4) into plain IPv4 so it
	 * matches IPv4 ranges. Returns '' when no valid IP remains. Not used by legacy.
	 */
	public static function normalize_ip( $value ) {
		$value = trim( (string) $value );

		if ( preg_match( '/^\[([^\]]+)\](?::\d+)?$/', $value, $m ) ) {
			$value = $m[1];
		} elseif ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $value, $m ) ) {
			$value = $m[1];
		}

		if ( preg_match( '/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $value, $m ) ) {
			$value = $m[1];
		}

		return self::is_valid_ip( $value ) ? $value : '';
	}

	public static function get_cloudflare_ranges() {
		$ranges = apply_filters( 'blockade_cloudflare_ranges', self::CLOUDFLARE_RANGES );
		return is_array( $ranges ) ? $ranges : self::CLOUDFLARE_RANGES;
	}

	public static function is_cloudflare_ip( $ip ) {
		return self::list_contains_ip( $ip, implode( "\n", self::get_cloudflare_ranges() ) );
	}

	public static function is_public_ip( $ip ) {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	protected static function server_value( array $server, $key ) {
		if ( empty( $server[ $key ] ) || ! is_string( $server[ $key ] ) ) {
			return '';
		}
		return trim( sanitize_text_field( wp_unslash( $server[ $key ] ) ) );
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
