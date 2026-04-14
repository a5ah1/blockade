<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_Admin {

	const MENU_SLUG             = 'blockade';
	const SAVE_ACTION           = 'blockade_save_ips';
	const UNLOCK_ACTION         = 'blockade_unlock_ip';
	const CLEAR_LOCKOUTS_ACTION = 'blockade_clear_lockouts';
	const NOTICE_QUERY          = 'blockade_notice';

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'add_menu' ) );
		add_action( 'admin_post_' . self::SAVE_ACTION, array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_' . self::UNLOCK_ACTION, array( __CLASS__, 'handle_unlock' ) );
		add_action( 'admin_post_' . self::CLEAR_LOCKOUTS_ACTION, array( __CLASS__, 'handle_clear_lockouts' ) );
	}

	public static function add_menu() {
		add_options_page(
			'Blockade',
			'Blockade',
			'manage_options',
			self::MENU_SLUG,
			array( __CLASS__, 'render_page' )
		);
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.', '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::SAVE_ACTION );

		$raw_allowed = isset( $_POST[ Blockade_Database::OPTION_ALLOWED_IPS ] ) ? (string) wp_unslash( $_POST[ Blockade_Database::OPTION_ALLOWED_IPS ] ) : '';
		$raw_banned  = isset( $_POST[ Blockade_Database::OPTION_BANNED_IPS ] ) ? (string) wp_unslash( $_POST[ Blockade_Database::OPTION_BANNED_IPS ] ) : '';

		list( $allowed_valid, $allowed_invalid ) = Blockade_IP_Utils::parse_list( $raw_allowed );
		list( $banned_valid, $banned_invalid )   = Blockade_IP_Utils::parse_list( $raw_banned );

		update_option( Blockade_Database::OPTION_ALLOWED_IPS, implode( "\n", $allowed_valid ) );
		update_option( Blockade_Database::OPTION_BANNED_IPS, implode( "\n", $banned_valid ) );
		update_option(
			Blockade_Database::OPTION_EMAIL_NEW_LOCATION_ENABLED,
			isset( $_POST[ Blockade_Database::OPTION_EMAIL_NEW_LOCATION_ENABLED ] ) ? '1' : ''
		);

		$invalid = array_merge( $allowed_invalid, $banned_invalid );

		if ( ! empty( $invalid ) ) {
			set_transient( self::invalid_entries_transient_key(), $invalid, 60 );
		}

		self::redirect_with_notice( empty( $invalid ) ? 'saved' : 'saved_with_invalid' );
	}

	public static function handle_unlock() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.', '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::UNLOCK_ACTION );

		$ip = isset( $_POST['ip'] ) ? trim( (string) wp_unslash( $_POST['ip'] ) ) : '';

		if ( ! Blockade_IP_Utils::is_valid_ip( $ip ) ) {
			self::redirect_with_notice( 'unlock_invalid' );
		}

		Blockade_Database::delete_attempts_for_ip( $ip );
		self::redirect_with_notice( 'unlocked' );
	}

	public static function handle_clear_lockouts() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.', '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::CLEAR_LOCKOUTS_ACTION );

		$summary = Blockade_Database::get_locked_out_summary( array_column( BLOCKADE_TIERS, 1 ) );
		$locked  = self::compute_locked_out_rows( $summary );

		if ( empty( $locked ) ) {
			self::redirect_with_notice( 'cleared_none' );
		}

		$ips = array();
		foreach ( $locked as $entry ) {
			$ips[] = $entry['ip_row']['ip'];
		}

		Blockade_Database::delete_attempts_for_ips( $ips );
		set_transient( self::cleared_count_transient_key(), count( $ips ), 60 );
		self::redirect_with_notice( 'cleared' );
	}

	protected static function redirect_with_notice( $notice ) {
		$redirect = add_query_arg(
			array(
				'page'             => self::MENU_SLUG,
				self::NOTICE_QUERY => $notice,
			),
			admin_url( 'options-general.php' )
		);

		wp_safe_redirect( $redirect );
		exit;
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.', '', array( 'response' => 403 ) );
		}

		$allowed       = (string) get_option( Blockade_Database::OPTION_ALLOWED_IPS, '' );
		$banned        = (string) get_option( Blockade_Database::OPTION_BANNED_IPS, '' );
		$email_enabled = '1' === (string) get_option( Blockade_Database::OPTION_EMAIL_NEW_LOCATION_ENABLED, '1' );

		$notice = isset( $_GET[ self::NOTICE_QUERY ] ) ? sanitize_key( $_GET[ self::NOTICE_QUERY ] ) : '';

		?>
		<style>
			.blockade-ip-lists {
				display: grid;
				grid-template-columns: 1fr;
				gap: 1.25em;
				margin: 0.5em 0 1em;
			}
			@media (min-width: 1280px) {
				.blockade-ip-lists {
					grid-template-columns: 1fr 1fr;
					gap: 2em;
				}
			}
			.blockade-ip-lists .blockade-field label {
				display: block;
				font-weight: 600;
				margin-bottom: 0.35em;
			}
			.blockade-ip-lists textarea {
				width: 100%;
				box-sizing: border-box;
			}
			.blockade-section-intro {
				margin-top: 0.25em;
			}
			.blockade-inline-form {
				display: inline;
				margin: 0;
			}
			.blockade-clear-all {
				margin-top: 0.75em;
			}
		</style>
		<div class="wrap">
			<h1>Blockade</h1>

			<?php self::render_notice( $notice ); ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::SAVE_ACTION ); ?>" />
				<?php wp_nonce_field( self::SAVE_ACTION ); ?>

				<h2>Notifications</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">New-location login alerts</th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( Blockade_Database::OPTION_EMAIL_NEW_LOCATION_ENABLED ); ?>"
									value="1"
									<?php checked( $email_enabled ); ?>
								/>
								Email the user when they log in from an IP address they haven't used before.
							</label>
							<p class="description">Sent once per (user, IP) pair on the first successful login from that IP. Uncheck to disable all Blockade emails.</p>
						</td>
					</tr>
				</table>

				<h2>IP Lists</h2>
				<p class="description blockade-section-intro">One entry per line. IPv4, IPv6, and CIDR notation are supported.</p>

				<div class="blockade-ip-lists">
					<div class="blockade-field">
						<label for="<?php echo esc_attr( Blockade_Database::OPTION_ALLOWED_IPS ); ?>">Allowed IPs</label>
						<textarea
							id="<?php echo esc_attr( Blockade_Database::OPTION_ALLOWED_IPS ); ?>"
							name="<?php echo esc_attr( Blockade_Database::OPTION_ALLOWED_IPS ); ?>"
							rows="10"
							class="large-text code"
						><?php echo esc_textarea( $allowed ); ?></textarea>
						<p class="description">These IPs will never be rate limited. Useful for your own IP, office networks, or VPNs.</p>
					</div>
					<div class="blockade-field">
						<label for="<?php echo esc_attr( Blockade_Database::OPTION_BANNED_IPS ); ?>">Banned IPs</label>
						<textarea
							id="<?php echo esc_attr( Blockade_Database::OPTION_BANNED_IPS ); ?>"
							name="<?php echo esc_attr( Blockade_Database::OPTION_BANNED_IPS ); ?>"
							rows="10"
							class="large-text code"
						><?php echo esc_textarea( $banned ); ?></textarea>
						<p class="description">These IPs will always be blocked from logging in.</p>
					</div>
				</div>

				<?php submit_button( 'Save Settings' ); ?>
			</form>

			<hr />

			<h2>Currently Locked Out IPs</h2>
			<?php self::render_locked_out_table(); ?>

			<hr />

			<h2>Recent Successful Logins</h2>
			<?php self::render_login_log_table(); ?>

			<hr />

			<h2>Recent Failed Attempts</h2>
			<?php self::render_failed_attempts_table(); ?>
		</div>
		<?php
	}

	protected static function render_notice( $notice ) {
		if ( 'saved' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>';
		} elseif ( 'saved_with_invalid' === $notice ) {
			$key     = self::invalid_entries_transient_key();
			$invalid = get_transient( $key );
			delete_transient( $key );

			echo '<div class="notice notice-warning is-dismissible"><p><strong>Settings saved, but the following IP list entries were invalid and discarded:</strong></p><ul style="list-style:disc;padding-left:20px;">';
			if ( is_array( $invalid ) ) {
				foreach ( $invalid as $entry ) {
					echo '<li><code>' . esc_html( $entry ) . '</code></li>';
				}
			}
			echo '</ul></div>';
		} elseif ( 'unlocked' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>Lockout cleared.</p></div>';
		} elseif ( 'unlock_invalid' === $notice ) {
			echo '<div class="notice notice-error is-dismissible"><p>Could not unlock: the submitted IP was invalid.</p></div>';
		} elseif ( 'cleared' === $notice ) {
			$key   = self::cleared_count_transient_key();
			$count = (int) get_transient( $key );
			delete_transient( $key );
			$label = 1 === $count ? '1 lockout' : sprintf( '%d lockouts', $count );
			echo '<div class="notice notice-success is-dismissible"><p>Cleared ' . esc_html( $label ) . '.</p></div>';
		} elseif ( 'cleared_none' === $notice ) {
			echo '<div class="notice notice-warning is-dismissible"><p>No IPs were locked out.</p></div>';
		}
	}

	protected static function invalid_entries_transient_key() {
		return 'blockade_invalid_entries_' . get_current_user_id();
	}

	protected static function cleared_count_transient_key() {
		return 'blockade_cleared_count_' . get_current_user_id();
	}

	protected static function render_table( array $headers, array $rows, $empty_message ) {
		echo '<table class="widefat striped"><thead><tr>';
		foreach ( $headers as $header ) {
			echo '<th>' . esc_html( $header ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		if ( empty( $rows ) ) {
			echo '<tr><td colspan="' . (int) count( $headers ) . '"><em>' . esc_html( $empty_message ) . '</em></td></tr>';
		} else {
			foreach ( $rows as $cells ) {
				echo '<tr>';
				foreach ( $cells as $cell ) {
					echo '<td>' . $cell . '</td>';
				}
				echo '</tr>';
			}
		}

		echo '</tbody></table>';
	}

	protected static function render_login_log_table() {
		$rows = array();
		foreach ( Blockade_Database::get_recent_logins( 100 ) as $row ) {
			$username = $row->user_login ? $row->user_login : '(deleted user #' . (int) $row->user_id . ')';
			$rows[]   = array(
				esc_html( $username ),
				'<code>' . esc_html( $row->ip ) . '</code>',
				esc_html( self::format_timestamp( $row->logged_in_at ) ),
			);
		}

		self::render_table(
			array( 'Username', 'IP Address', 'Date/Time' ),
			$rows,
			'No successful logins recorded yet.'
		);
	}

	protected static function render_failed_attempts_table() {
		$rows = array();
		foreach ( Blockade_Database::get_recent_attempts( 100 ) as $row ) {
			$rows[] = array(
				'<code>' . esc_html( $row->ip ) . '</code>',
				esc_html( $row->username ),
				esc_html( self::format_timestamp( $row->attempted_at ) ),
			);
		}

		self::render_table(
			array( 'IP Address', 'Username Attempted', 'Date/Time' ),
			$rows,
			'No failed attempts recorded yet.'
		);
	}

	protected static function render_locked_out_table() {
		$summary    = Blockade_Database::get_locked_out_summary( array_column( BLOCKADE_TIERS, 1 ) );
		$locked     = self::compute_locked_out_rows( $summary );
		$tier_count = count( BLOCKADE_TIERS );

		$rows = array();
		foreach ( $locked as $entry ) {
			$ip_row = $entry['ip_row'];
			$index  = $entry['tier_index'];
			list( $max_attempts, $window_seconds, $lockout_seconds ) = BLOCKADE_TIERS[ $index ];

			$count      = (int) $ip_row[ 'c_' . $index ];
			$latest     = $ip_row['latest'];
			$expires_at = $latest ? strtotime( $latest . ' UTC' ) + $lockout_seconds : time() + $lockout_seconds;

			$rows[] = array(
				'<code>' . esc_html( $ip_row['ip'] ) . '</code>',
				'Tier ' . (int) ( $tier_count - $index ),
				(string) $count,
				esc_html( self::format_timestamp( gmdate( 'Y-m-d H:i:s', $expires_at ) ) ),
				self::render_unlock_form( $ip_row['ip'] ),
			);
		}

		self::render_table(
			array( 'IP Address', 'Tier', 'Failures in Window', 'Lockout Expires (approx.)', 'Actions' ),
			$rows,
			'No IPs currently locked out.'
		);

		if ( ! empty( $rows ) ) {
			self::render_clear_all_form( count( $rows ) );
		}
	}

	protected static function compute_locked_out_rows( array $summary ) {
		$rows = array();
		foreach ( $summary as $ip_row ) {
			foreach ( BLOCKADE_TIERS as $index => $tier ) {
				$max_attempts = $tier[0];
				$count        = isset( $ip_row[ 'c_' . $index ] ) ? (int) $ip_row[ 'c_' . $index ] : 0;
				if ( $count >= $max_attempts ) {
					$rows[] = array(
						'ip_row'     => $ip_row,
						'tier_index' => $index,
					);
					break;
				}
			}
		}
		return $rows;
	}

	protected static function render_unlock_form( $ip ) {
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="blockade-inline-form">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::UNLOCK_ACTION ); ?>" />
			<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>" />
			<?php wp_nonce_field( self::UNLOCK_ACTION ); ?>
			<button type="submit" class="button-link button-link-delete">Unlock</button>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	protected static function render_clear_all_form( $count ) {
		$confirm = sprintf(
			'Clear %d lockout%s? This removes failed-attempt records for currently locked-out IPs only.',
			(int) $count,
			1 === (int) $count ? '' : 's'
		);
		?>
		<form
			method="post"
			action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
			class="blockade-clear-all"
			onsubmit="return confirm(<?php echo esc_attr( wp_json_encode( $confirm ) ); ?>);"
		>
			<input type="hidden" name="action" value="<?php echo esc_attr( self::CLEAR_LOCKOUTS_ACTION ); ?>" />
			<?php wp_nonce_field( self::CLEAR_LOCKOUTS_ACTION ); ?>
			<button type="submit" class="button button-secondary">Clear all lockouts</button>
		</form>
		<?php
	}

	protected static function format_timestamp( $utc_mysql ) {
		if ( empty( $utc_mysql ) ) {
			return '';
		}
		$timestamp = strtotime( $utc_mysql . ' UTC' );
		if ( false === $timestamp ) {
			return (string) $utc_mysql;
		}
		return wp_date( 'Y-m-d H:i:s', $timestamp );
	}
}
