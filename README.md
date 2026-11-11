# Blockade

A focused WordPress plugin for brute-force login protection, login audit logging, and IP allow/ban list management. Minimal by design — a lean alternative to heavier security suites.

## Features

- **Tiered rate limiting.** Three progressive lockout tiers. Tier 1 shows a friendly error on the login form; tiers 2 and 3 return a hard HTTP 403 so the origin does almost no work — and Cloudflare's rate limiter can pick up the pattern at the edge for free.
- **Known-IP leniency.** Users with a prior successful login from the current IP get roughly 3× more generous thresholds, so a real user fumbling their password isn't treated like an attacker.
- **Admin overrides.** Unlock a single IP inline, or clear every active lockout in one click from Settings → Blockade.
- **Login audit log.** Every successful login is recorded. The admin page shows the most recent 100.
- **New-location email alerts.** When a user in an alerted role (Administrator by default) logs in from an IP they haven't used before, Blockade emails their registered address. A user's first recorded login is logged silently and sets their baseline, so installing on an existing site sends no emails. You can choose the roles or turn alerts off on the settings page.
- **IP allow/ban lists.** One entry per line, IPv4/IPv6, CIDR supported. Allowed IPs skip all rate limiting. Banned IPs are hard-blocked with the same generic 403 used for rate-limit lockouts — an attacker cannot distinguish the two.
- **Configurable client-IP detection.** Choose Direct, Cloudflare, or Trusted proxy, with an on-page check that suggests the right mode for your server. See [Client IP detection](#client-ip-detection).
- **Automatic retention.** Failed attempts are pruned after 48 hours; the login log after 60 days, via a single daily WP-Cron job.

## What it doesn't do (intentionally)

Blockade is single-purpose. It does **not** include XML-RPC hardening, 2FA, CAPTCHA, geo-blocking, a WAF, file-integrity monitoring, or user-enumeration protection. If you need those, install a plugin that does them well. Blockade refuses to bloat.

## Installation

### From a release (recommended)

1. Download the latest `blockade-v<VERSION>.zip` from the [Releases page](https://github.com/a5ah1/blockade/releases).
2. In WordPress admin: **Plugins → Add New → Upload Plugin**. Choose the zip, install, activate.

The release zip bundles Composer dependencies; nothing else needs to be installed on the server.

### From source (development)

```bash
git clone https://github.com/a5ah1/blockade.git
cd blockade
composer install --no-dev
```

Symlink or copy the directory into `wp-content/plugins/`. `vendor/` must be present — the auto-update checker lives there.

### Automatic updates

Once installed, Blockade uses [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) to pull new versions directly from GitHub Releases, so updates appear in the normal WordPress Plugins screen.

## Usage

After activation, go to **Settings → Blockade**. The single page contains:

1. **Notifications**: turn new-location login email alerts on or off, and choose which roles receive them.
2. **Client IP Detection**: choose where Blockade reads the visitor's IP from. The section shows how your own request is seen in each mode and suggests one.
3. **Allowed IPs** — whitelist that bypasses rate limiting. One per line, CIDR supported.
4. **Banned IPs** — permanent hard-block list. One per line, CIDR supported.
5. **Currently Locked Out IPs** — live view of IPs that have tripped a tier threshold, with per-row **Unlock** and a bulk **Clear all lockouts** action.
6. **Recent Successful Logins** — most recent 100.
7. **Recent Failed Attempts** — most recent 100.

Defaults are tuned for typical sites. The one setting worth checking after install is **Client IP Detection**.

## How rate limiting works

Every login attempt runs a check (before WordPress compares the password hash) against:

1. **Banned list** — hard block.
2. **Allowed list** — skip all checks.
3. **Tiered lockout** — count failures from the client's IP over three rolling windows:

| Tier | Threshold | Window | Lockout | Response |
|------|-----------|--------|---------|----------|
| 1    | 5         | 15 min | 15 min  | Soft — login-page error |
| 2    | 15        | 24 hr  | 1 hr    | Hard — HTTP 403 |
| 3    | 30        | 24 hr  | 24 hr   | Hard — HTTP 403 |

If the attempted username or email already has a successful-login history from the current IP, thresholds are roughly tripled (15 / 30 / 45).

Limits are per IP. A distributed password spray, where each address tries once or twice, stays under every threshold. Blockade won't stop that on its own; strong passwords, 2FA, or edge rate limiting (such as a Cloudflare rule on `/wp-login.php`) are the tools for it.

## Client IP detection

Every limit, ban and allow-list entry keys on the client IP, so Blockade has to know which address to trust. **Settings → Blockade → Client IP Detection** offers four modes:

| Mode | Uses | Pick it when |
|------|------|--------------|
| Legacy (default) | `CF-Connecting-IP`, then the first `X-Forwarded-For` entry, then `REMOTE_ADDR`, trusting the headers from anyone | Only for backward compatibility. |
| Direct | `REMOTE_ADDR` only | No proxy, or the web server already restores the visitor IP (Apache `mod_remoteip`, nginx `real_ip`). |
| Cloudflare | `CF-Connecting-IP`, but only when `REMOTE_ADDR` is in Cloudflare's IP ranges; otherwise `REMOTE_ADDR` | The site is proxied by Cloudflare and `REMOTE_ADDR` shows Cloudflare's addresses. |
| Trusted proxy | `X-Forwarded-For` read right to left, skipping the proxies you list | A load balancer or reverse proxy you control sits in front of WordPress. |

The section shows your own request's `REMOTE_ADDR` and forwarding headers, what each mode would resolve to, and a suggested mode.

**Why Legacy is risky.** Clients can send `CF-Connecting-IP` and `X-Forwarded-For` themselves. If the server can be reached without passing through Cloudflare or your proxy (for example by its IP address), Legacy trusts those forged headers. An attacker can send a new fake address with every attempt so no limit is ever reached, or send someone else's address to get them locked out. Legacy stays the default only so upgrades don't change behavior silently; switch to the suggested mode.

**Locking the origin to Cloudflare.** If your site is behind Cloudflare, also consider allowing only [Cloudflare's IP ranges](https://www.cloudflare.com/ips/) to reach the web server, at the firewall or host level. That's outside Blockade's scope, but it stops direct-to-origin traffic entirely.

The bundled Cloudflare ranges can be overridden with the `blockade_cloudflare_ranges` filter:

```php
add_filter( 'blockade_cloudflare_ranges', function ( $ranges ) {
    return array_merge( $ranges, array( '203.0.113.0/24' ) );
} );
```

## Tuning

Thresholds are constants at the top of `blockade.php`:

```php
const BLOCKADE_TIERS = [
    [30, 86400, 86400],
    [15, 86400, 3600],
    [5,  900,   900],
];

const BLOCKADE_KNOWN_IP_TIERS = [
    [45, 86400, 86400],
    [30, 86400, 3600],
    [15, 900,   900],
];
```

Each tuple is `[max_attempts, window_seconds, lockout_seconds]`. Order is highest-severity first; the last entry is the soft tier.

## Storage

Two custom tables, both `InnoDB`:

- `{prefix}blockade_attempts` — failed login attempts (auto-pruned after 48h)
- `{prefix}blockade_log` — successful logins (auto-pruned after 60d)

These `wp_options` entries hold the settings:

- `blockade_allowed_ips`
- `blockade_banned_ips`
- `blockade_email_new_location_enabled`
- `blockade_email_alert_roles`
- `blockade_ip_source` (`legacy`, `direct`, `cloudflare` or `proxy`)
- `blockade_trusted_proxies`

Options that already exist are left alone on activation, so you can set them with WP-CLI before activating. For example, to start with alerts off and Direct IP detection:

```bash
wp option add blockade_email_new_location_enabled 0
wp option add blockade_email_alert_roles '[]' --format=json
wp option add blockade_ip_source direct
wp plugin activate blockade
```

Client IPs are the only personal data stored. User agents are deliberately **not** logged (trivially spoofed; your web server's access log already has them).

## Requirements

- WordPress 5.0+
- PHP 7.4+
- MySQL or MariaDB (uses standard `$wpdb`, InnoDB)
- Composer — only required when installing from source

## Uninstall

Deleting the plugin via WordPress runs `uninstall.php`, which drops both tables and deletes all Blockade options. **Deactivating does not remove data** — the assumption is that the user may be toggling.

## Contributing

Non-obvious security invariants (filter-priority ordering, password-hash-bypass guarantee, tier ordering, shared error strings) are documented in [`CLAUDE.md`](CLAUDE.md). Please read it before sending a PR — the invariants are easy to regress without noticing.

## License

MIT — see [`LICENSE`](LICENSE).
