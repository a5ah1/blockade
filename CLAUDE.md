# Blockade

WordPress plugin: brute-force login rate limiting, login audit logging, and IP allow/ban lists. The value prop is a focused, minimal replacement for heavier security plugins — not a general-purpose WAF.

## Layout

Repo root is the plugin root (standard WP plugin convention). The whole directory is what gets zipped and shipped to `wp-content/plugins/`.

```
.
├── blockade.php              # plugin header, constants, bootstrap, PUC init
├── uninstall.php             # drop tables + options on uninstall
├── readme.txt                # WordPress plugin readme format
├── includes/
│   ├── class-database.php    # schema + every $wpdb query
│   ├── class-ip-utils.php    # client IP detection, CIDR match, list parsing
│   ├── class-auth-guard.php  # authenticate filter, login hooks, lockout
│   ├── class-cron.php        # daily cleanup
│   └── class-admin.php       # Settings → Blockade page
├── composer.json             # pins yahnis-elsts/plugin-update-checker
├── composer.lock             # tracked, for reproducible installs
├── build.sh                  # produces vendor-inclusive release zip
├── vendor/                   # gitignored; populated by composer install
├── LICENSE                   # MIT
├── CLAUDE.md                 # this file
└── README.md                 # public-facing docs
```

## Critical invariants

Breaking any of these silently weakens the plugin:

- **Locked-out IPs must never cause a password hash comparison.** `Blockade_Auth_Guard::pre_authenticate` hooks `authenticate` at priority 5 (before WP's default priority 20). Hard blocks call `wp_die` (exits before WP can run password checks). For tier-1 soft blocks, we `remove_filter` on `wp_authenticate_username_password` and `wp_authenticate_email_password` before returning `WP_Error`. Do not change the priority, and do not drop the `remove_filter` calls.

- **Tier array order is highest-severity first.** `BLOCKADE_TIERS[0]` is tier 3, the last entry is tier 1. The loop short-circuits on first match, and tier 1 is the *only* soft block — detected via `$index === count($tiers) - 1`. Reordering the array breaks soft/hard discrimination.

- **Banned IPs and tier-2/3 lockouts share the same error string** (`HARD_BLOCK_MESSAGE`). An attacker must not be able to tell a permanent ban apart from rate limiting. Edit both call sites together if you change the copy.

- **All DB queries go through `$wpdb->prepare()`.** Table names are interpolated from the trusted `$wpdb->prefix`; all values are placeholders.

- **Timestamps are stored in UTC** via `current_time('mysql', true)`. Admin display converts to the site timezone with `wp_date`.

- **No user-agent storage.** Intentional: UAs are trivially spoofed and server access logs cover forensics.

- **PUC init must keep `enableReleaseAssets()`.** The update-checker block in `blockade.php` calls `$checker->getVcsApi()->enableReleaseAssets()`. Without it, PUC downloads the GitHub-generated source tarball — which lacks `/vendor/` (gitignored) and so is missing PUC itself. Updates would install a broken plugin. See "Releasing" below for the paired requirement on release assets.

- **"Clear all lockouts" is scoped, not a truncate.** `Blockade_Admin::handle_clear_lockouts` computes currently-locked IPs via the shared `compute_locked_out_rows` helper and deletes attempts only for those IPs. Do not "simplify" to `TRUNCATE blockade_attempts` — that would wipe the Recent Failed Attempts audit trail for IPs that were merely below threshold.

- **Email-alert toggle defaults to `'1'` at the read site, not just at install.** `Blockade_Auth_Guard::send_new_ip_notification` reads `get_option( OPTION_EMAIL_NEW_LOCATION_ENABLED, '1' )`. The `'1'` default is load-bearing: it preserves pre-1.0.2 behavior (emails on) for installs that upgrade before the admin touches the new setting, since activation only runs on fresh installs. Don't refactor the default to `false` or drop it.

- **Alert roles default to `administrator` at the read site.** `Blockade_Database::get_email_alert_roles()` falls back to `DEFAULT_EMAIL_ALERT_ROLES` when the option is missing. Nothing is seeded at activation, so this fallback is the only reason upgraded installs move to admin-only alerts. A saved empty array is valid and means "alert no one". Never default to all roles: on WooCommerce sites that emails every customer.

- **IP source defaults to `legacy` at the read site.** `Blockade_Database::get_ip_source()` falls back to `legacy` for a missing or unknown value, and activation does not seed it. Upgraded installs must keep pre-1.0.5 IP identity until an admin picks a mode. Don't change the default without asking the user.

- **Activation never overwrites existing options.** `install()` only `add_option`s keys that are absent, and newer options aren't seeded at all. Site operators set options with WP-CLI *before* activating (e.g. alerts off, `ip_source=direct`) and rely on that surviving activation. README documents this.

- **Known-IP leniency matches username or email.** `ip_has_login_history_for_user` compares the typed value against both `user_login` and `user_email`, since WooCommerce customers mostly log in with email.

- **A user's first recorded login never sends an alert.** `on_login_success` only alerts when the IP is new *and* the user already has login history (`user_has_login_history`). This keeps installs on existing sites quiet, and covers users whose history aged out after the 60-day retention.

## Client IP resolution

`Blockade_IP_Utils::get_client_ip` delegates to `resolve_ip( $source, $_SERVER, $trusted_proxies )`, keyed by the `blockade_ip_source` option (1.0.5+):

- `legacy` (default): `HTTP_CF_CONNECTING_IP`, then the first `HTTP_X_FORWARDED_FOR` entry, then `REMOTE_ADDR`, trusting headers from anyone. Spoofable when the origin is reachable directly. Kept byte-for-byte as pre-1.0.5 behavior; don't "harden" it in place, because that silently changes IP identity on upgrade. Steer users to another mode via the admin diagnostic instead.
- `direct`: `REMOTE_ADDR` only.
- `cloudflare`: `CF-Connecting-IP` only when `REMOTE_ADDR` is in `CLOUDFLARE_RANGES` (filterable via `blockade_cloudflare_ranges`), else `REMOTE_ADDR`.
- `proxy`: walk `X-Forwarded-For` right to left from `REMOTE_ADDR`, skipping entries in `blockade_trusted_proxies`; return the first untrusted hop. Never take the leftmost entry: the client wrote it.

`resolve_ip` must stay side-effect free (apart from the ranges filter): the admin diagnostic calls it for every mode to preview what each would resolve to. `Blockade_Admin::recommend_ip_source` / `ip_source_warnings` drive the suggestions; they read only the passed `$server` array so they can be tested.

`CLOUDFLARE_RANGES` is copied from https://www.cloudflare.com/ips/. Re-check it when releasing.

## Lifecycle

- **Activation:** `dbDelta` creates both tables, option keys are initialized, daily cron is scheduled.
- **Deactivation:** cron is cleared. Tables and options are **not** dropped (user may be toggling).
- **Uninstall:** `uninstall.php` drops tables and deletes options. Preferred over `register_uninstall_hook` for reliability.

## Scope (intentional)

Does not do: XML-RPC protection, 2FA, CAPTCHA, geo-blocking, WAF rules, file integrity, user-enumeration hardening. Don't expand scope without discussing — the focus is the value prop.

## Commands

Lint all plugin PHP:

```
for f in *.php includes/*.php; do php -l "$f"; done
```

Install Composer deps (for a dev checkout; required for auto-updates to work locally):

```
composer install --no-dev
```

## Releasing

Auto-updates use [yahnis-elsts/plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker) pointed at GitHub Releases with `enableReleaseAssets()`. The update checker pulls the **ZIP asset attached to each Release** — not the auto-generated source tarball, because `/vendor/` is gitignored and the tarball would be missing PUC itself.

**This means: every Release MUST carry the built zip as an asset. Without it, updates install a broken plugin.**

Release steps:

1. Bump version in three places (keep them aligned):
   - `Version:` header in `blockade.php`
   - `BLOCKADE_VERSION` constant in `blockade.php`
   - `Stable tag:` in `readme.txt`
2. `./build.sh` produces `blockade-v<VERSION>.zip` with `vendor/` bundled. It ships **only git-tracked files plus `vendor/`**, minus the dev files listed in its `grep -v` (for example `CLAUDE.md` and the composer files). That way untracked local files such as `ignore/`, `TODO.md` or `.env` can't leak, as they did in the first v1.0.3 zip. Any new file that should ship must be tracked in git before building. Always check the result with `unzip -Z1 blockade-v<VERSION>.zip | grep -v vendor/`.
3. Commit the version bump, push to `main`.
4. Tag and push:
   ```
   git tag v<VERSION> && git push origin v<VERSION>
   ```
5. Create the GitHub Release with the built zip attached:
   ```
   gh release create v<VERSION> blockade-v<VERSION>.zip --title "v<VERSION>" --generate-notes
   ```

If a release ever ships without the zip asset, existing installs will try to update from the source tarball and break. Always verify the asset is attached before closing out a release.
