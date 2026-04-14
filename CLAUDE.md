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

## Client IP resolution

`Blockade_IP_Utils::get_client_ip` trusts `HTTP_CF_CONNECTING_IP`, then the first entry of `HTTP_X_FORWARDED_FOR`, then `REMOTE_ADDR`. Known limitation: sites not behind a trusted proxy can be spoofed via forged `X-Forwarded-For`. If configurability is added, gate header trust behind an option — don't silently change the fallback order.

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
2. `./build.sh` — produces `blockade-v<VERSION>.zip` with `vendor/` bundled.
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
