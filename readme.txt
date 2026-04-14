=== Blockade ===
Contributors: blockade
Tags: login, security, brute force, rate limit, ip ban
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.0.1
License: MIT
License URI: https://opensource.org/licenses/MIT

Lightweight brute force login protection, login audit logging, and IP allow/ban management.

== Description ==

Blockade is a focused, performant WordPress plugin that:

* Rate limits login attempts with a tiered lockout system (friendly warning on first tier, hard 403 on higher tiers).
* Applies more generous thresholds to IPs that have a successful login history for the username being attempted.
* Logs successful logins and notifies users by email the first time they log in from a new IP.
* Supports allow/ban lists with IPv4, IPv6, and CIDR notation.
* Detects the real client IP behind Cloudflare and common reverse proxies.
* Automatically prunes old records daily.

It intentionally does not include XML-RPC protection, 2FA, CAPTCHA, or firewalling. It does one thing well: login rate limiting and audit logging.

== Installation ==

1. Upload the `blockade` directory to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to Settings → Blockade to view logs and configure IP lists.

== Changelog ==

= 1.0.1 =
* Collapse per-tier failure-count queries into one aggregate query on the login hot path.
* Collapse the admin locked-out table's N+1 lookup into one aggregate query.
* Skip update-checker initialization on front-end requests.
* Internal refactors: shared threshold/cleanup/render helpers; option keys promoted to constants; uninstall now uses shared table accessors.

= 1.0.0 =
* Initial release.
