# Blockade

A focused WordPress plugin for brute-force login protection, login audit logging, and IP allow/ban list management. Minimal by design — a lean alternative to heavier security suites.

## Features

- **Tiered rate limiting.** Three progressive lockout tiers. Tier 1 shows a friendly error on the login form; tiers 2 and 3 return a hard HTTP 403 so the origin does almost no work — and Cloudflare's rate limiter can pick up the pattern at the edge for free.
- **Known-IP leniency.** Users with a prior successful login from the current IP get roughly 3× more generous thresholds, so a real user fumbling their password isn't treated like an attacker.
- **Login audit log.** Every successful login is recorded. The admin page shows the most recent 100.
- **New-location email alerts.** The first successful login from a new IP (per user) triggers an email to the user's registered address.
- **IP allow/ban lists.** One entry per line, IPv4/IPv6, CIDR supported. Allowed IPs skip all rate limiting. Banned IPs are hard-blocked with the same generic 403 used for rate-limit lockouts — an attacker cannot distinguish the two.
- **Reverse-proxy aware.** Detects the real client IP via `CF-Connecting-IP`, then `X-Forwarded-For`, falling back to `REMOTE_ADDR`.
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

1. **Allowed IPs** — whitelist that bypasses rate limiting. One per line, CIDR supported.
2. **Banned IPs** — permanent hard-block list. One per line, CIDR supported.
3. **Currently Locked Out IPs** — live view of IPs that have tripped a tier threshold.
4. **Recent Successful Logins** — most recent 100.
5. **Recent Failed Attempts** — most recent 100.

No other configuration is needed. Defaults are tuned for typical sites.

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

If the attempted username already has a successful-login history from the current IP, thresholds are roughly tripled (15 / 30 / 45).

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

Two `wp_options` entries hold the IP lists:

- `blockade_allowed_ips`
- `blockade_banned_ips`

Client IPs are the only personal data stored. User agents are deliberately **not** logged (trivially spoofed; your web server's access log already has them).

## Requirements

- WordPress 5.0+
- PHP 7.4+
- MySQL or MariaDB (uses standard `$wpdb`, InnoDB)
- Composer — only required when installing from source

## Uninstall

Deleting the plugin via WordPress runs `uninstall.php`, which drops both tables and deletes the two option keys. **Deactivating does not remove data** — the assumption is that the user may be toggling.

## Contributing

Non-obvious security invariants (filter-priority ordering, password-hash-bypass guarantee, tier ordering, shared error strings) are documented in [`CLAUDE.md`](CLAUDE.md). Please read it before sending a PR — the invariants are easy to regress without noticing.

## License

GPL-2.0-or-later.
