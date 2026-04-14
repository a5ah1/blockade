<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Blockade_Admin {

	const MENU_SLUG    = 'blockade';
	const SAVE_ACTION  = 'blockade_save_ips';
	const NOTICE_QUERY = 'blockade_notice';

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'add_menu' ) );
		add_action( 'admin_post_' . self::SAVE_ACTION, array( __CLASS__, 'handle_save' ) );
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

		$raw_allowed = isset( $_POST['blockade_allowed_ips'] ) ? (string) wp_unslash( $_POST['blockade_allowed_ips'] ) : '';
		$raw_banned  = isset( $_POST['blockade_banned_ips'] ) ? (string) wp_unslash( $_POST['blockade_banned_ips'] ) : '';

		list( $allowed_valid, $allowed_invalid ) = Blockade_IP_Utils::parse_list( $raw_allowed );
		list( $banned_valid, $banned_invalid )   = Blockade_IP_Utils::parse_list( $raw_banned );

		update_option( 'blockade_allowed_ips', implode( "\n", $allowed_valid ) );
		update_option( 'blockade_banned_ips', implode( "\n", $banned_valid ) );

		$invalid = array_merge( $allowed_invalid, $banned_invalid );

		if ( ! empty( $invalid ) ) {
			set_transient(
				'blockade_invalid_entries_' . get_current_user_id(),
				$invalid,
				60
			);
		}

		$redirect = add_query_arg(
			array(
				'page'             => self::MENU_SLUG,
				self::NOTICE_QUERY => empty( $invalid ) ? 'saved' : 'saved_with_invalid',
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

		$allowed = (string) get_option( 'blockade_allowed_ips', '' );
		$banned  = (string) get_option( 'blockade_banned_ips', '' );

		$notice = isset( $_GET[ self::NOTICE_QUERY ] ) ? sanitize_key( $_GET[ self::NOTICE_QUERY ] ) : '';

		?>
		<div class="wrap">
			<h1>Blockade</h1>

			<?php self::render_notice( $notice ); ?>

			<h2>IP Lists</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::SAVE_ACTION ); ?>" />
				<?php wp_nonce_field( self::SAVE_ACTION ); ?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="blockade_allowed_ips">Allowed IPs (one per line, CIDR notation supported)</label>
						</th>
						<td>
							<textarea
								id="blockade_allowed_ips"
								name="blockade_allowed_ips"
								rows="8"
								cols="50"
								class="large-text code"
							><?php echo esc_textarea( $allowed ); ?></textarea>
							<p class="description">These IPs will never be rate limited. Useful for your own IP, office networks, or VPNs.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="blockade_banned_ips">Banned IPs (one per line, CIDR notation supported)</label>
						</th>
						<td>
							<textarea
								id="blockade_banned_ips"
								name="blockade_banned_ips"
								rows="8"
								cols="50"
								class="large-text code"
							><?php echo esc_textarea( $banned ); ?></textarea>
							<p class="description">These IPs will always be blocked from logging in.</p>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Save IP Lists' ); ?>
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
			echo '<div class="notice notice-success is-dismissible"><p>IP lists saved.</p></div>';
		} elseif ( 'saved_with_invalid' === $notice ) {
			$invalid = get_transient( 'blockade_invalid_entries_' . get_current_user_id() );
			delete_transient( 'blockade_invalid_entries_' . get_current_user_id() );

			echo '<div class="notice notice-warning is-dismissible"><p><strong>IP lists saved, but the following entries were invalid and discarded:</strong></p><ul style="list-style:disc;padding-left:20px;">';
			if ( is_array( $invalid ) ) {
				foreach ( $invalid as $entry ) {
					echo '<li><code>' . esc_html( $entry ) . '</code></li>';
				}
			}
			echo '</ul></div>';
		}
	}

	protected static function render_login_log_table() {
		$rows = Blockade_Database::get_recent_logins( 100 );

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>Username</th><th>IP Address</th><th>Date/Time</th>';
		echo '</tr></thead><tbody>';

		if ( empty( $rows ) ) {
			echo '<tr><td colspan="3"><em>No successful logins recorded yet.</em></td></tr>';
		} else {
			foreach ( $rows as $row ) {
				$username = $row->user_login ? $row->user_login : '(deleted user #' . (int) $row->user_id . ')';
				echo '<tr>';
				echo '<td>' . esc_html( $username ) . '</td>';
				echo '<td><code>' . esc_html( $row->ip ) . '</code></td>';
				echo '<td>' . esc_html( self::format_timestamp( $row->logged_in_at ) ) . '</td>';
				echo '</tr>';
			}
		}

		echo '</tbody></table>';
	}

	protected static function render_failed_attempts_table() {
		$rows = Blockade_Database::get_recent_attempts( 100 );

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>IP Address</th><th>Username Attempted</th><th>Date/Time</th>';
		echo '</tr></thead><tbody>';

		if ( empty( $rows ) ) {
			echo '<tr><td colspan="3"><em>No failed attempts recorded yet.</em></td></tr>';
		} else {
			foreach ( $rows as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( $row->ip ) . '</code></td>';
				echo '<td>' . esc_html( $row->username ) . '</td>';
				echo '<td>' . esc_html( self::format_timestamp( $row->attempted_at ) ) . '</td>';
				echo '</tr>';
			}
		}

		echo '</tbody></table>';
	}

	protected static function render_locked_out_table() {
		$max_window = 0;
		foreach ( BLOCKADE_TIERS as $tier ) {
			if ( $tier[1] > $max_window ) {
				$max_window = $tier[1];
			}
		}

		$ips = Blockade_Database::get_distinct_recent_ips( $max_window );

		$locked = array();
		foreach ( $ips as $ip ) {
			foreach ( BLOCKADE_TIERS as $index => $tier ) {
				list( $max_attempts, $window_seconds, $lockout_seconds ) = $tier;
				$count = Blockade_Database::count_failures_for_ip( $ip, $window_seconds );
				if ( $count >= $max_attempts ) {
					$tier_number  = count( BLOCKADE_TIERS ) - $index;
					$latest       = Blockade_Database::latest_attempt_for_ip( $ip );
					$expires_at   = $latest ? strtotime( $latest . ' UTC' ) + $lockout_seconds : time() + $lockout_seconds;

					$locked[] = array(
						'ip'         => $ip,
						'tier'       => $tier_number,
						'count'      => $count,
						'expires_at' => $expires_at,
					);
					break;
				}
			}
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>IP Address</th><th>Tier</th><th>Failures in Window</th><th>Lockout Expires (approx.)</th>';
		echo '</tr></thead><tbody>';

		if ( empty( $locked ) ) {
			echo '<tr><td colspan="4"><em>No IPs currently locked out.</em></td></tr>';
		} else {
			foreach ( $locked as $entry ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( $entry['ip'] ) . '</code></td>';
				echo '<td>Tier ' . (int) $entry['tier'] . '</td>';
				echo '<td>' . (int) $entry['count'] . '</td>';
				echo '<td>' . esc_html( self::format_timestamp( gmdate( 'Y-m-d H:i:s', $entry['expires_at'] ) ) ) . '</td>';
				echo '</tr>';
			}
		}

		echo '</tbody></table>';
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
