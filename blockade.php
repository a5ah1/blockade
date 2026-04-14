<?php
/**
 * Plugin Name: Blockade
 * Plugin URI:  https://github.com/a5ah1/blockade
 * Description: Brute force login protection, login audit logging, and IP allow/ban list management.
 * Version:     1.0.2
 * Author:      a5ah1
 * Author URI:  https://github.com/a5ah1
 * License:     MIT
 * License URI: https://opensource.org/licenses/MIT
 * Text Domain: blockade
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'BLOCKADE_VERSION', '1.0.2' );
define( 'BLOCKADE_FILE', __FILE__ );
define( 'BLOCKADE_DIR', plugin_dir_path( __FILE__ ) );

const BLOCKADE_TIERS = array(
	array( 30, 86400, 86400 ),
	array( 15, 86400, 3600 ),
	array( 5, 900, 900 ),
);

const BLOCKADE_KNOWN_IP_TIERS = array(
	array( 45, 86400, 86400 ),
	array( 30, 86400, 3600 ),
	array( 15, 900, 900 ),
);

const BLOCKADE_ATTEMPTS_RETENTION = 48 * HOUR_IN_SECONDS;
const BLOCKADE_LOG_RETENTION      = 60 * DAY_IN_SECONDS;

const BLOCKADE_CRON_HOOK = 'blockade_daily_cleanup';

require_once BLOCKADE_DIR . 'includes/class-database.php';
require_once BLOCKADE_DIR . 'includes/class-ip-utils.php';
require_once BLOCKADE_DIR . 'includes/class-auth-guard.php';
require_once BLOCKADE_DIR . 'includes/class-cron.php';
require_once BLOCKADE_DIR . 'includes/class-admin.php';

register_activation_hook( __FILE__, array( 'Blockade_Database', 'install' ) );
register_activation_hook( __FILE__, array( 'Blockade_Cron', 'schedule' ) );
register_deactivation_hook( __FILE__, array( 'Blockade_Cron', 'unschedule' ) );

add_action( 'plugins_loaded', 'blockade_bootstrap' );

function blockade_bootstrap() {
	Blockade_Auth_Guard::register();
	Blockade_Cron::register();

	if ( is_admin() ) {
		Blockade_Admin::register();
	}
}

$blockade_autoload = BLOCKADE_DIR . 'vendor/autoload.php';
if ( file_exists( $blockade_autoload ) ) {
	require_once $blockade_autoload;
	// Skip on front-end requests; update checks only fire in admin/cron/CLI contexts.
	if ( is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
		add_action( 'plugins_loaded', 'blockade_updates_init' );
	}
}

function blockade_updates_init() {
	$checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
		'https://github.com/a5ah1/blockade/',
		__FILE__,
		'blockade'
	);
	$checker->setBranch( 'main' );
	$checker->getVcsApi()->enableReleaseAssets();
}
