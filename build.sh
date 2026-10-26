#!/usr/bin/env bash
# Build a distributable ZIP with Composer dependencies bundled.
#
# The produced ZIP is the asset attached to each GitHub Release so that
# yahnis-elsts/plugin-update-checker serves vendor-inclusive updates.
# Without this asset, PUC falls back to the auto-generated source tarball,
# which lacks /vendor/ — updates would install a broken plugin.
#
# Usage: ./build.sh
set -e

PLUGIN_SLUG="blockade"
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION=$(grep -m1 "Version:" "$PLUGIN_DIR/$PLUGIN_SLUG.php" | sed 's/.*Version: *//' | tr -d '[:space:]')
BUILD_DIR=$(mktemp -d)
ZIP_FILE="$PLUGIN_DIR/${PLUGIN_SLUG}-v${VERSION}.zip"

echo "Building ${PLUGIN_SLUG} v${VERSION}..."

cd "$PLUGIN_DIR"
echo "Installing Composer dependencies (production)..."
composer install --no-dev --optimize-autoloader --quiet

mkdir -p "$BUILD_DIR/$PLUGIN_SLUG"

# Ship only git-tracked files plus vendor/. Untracked local files (test harness,
# notes, .env) can never leak into a release, whatever .gitignore says.
{
  git -C "$PLUGIN_DIR" ls-files
  find vendor -type f
} | grep -v -x -E 'CLAUDE\.md|composer\.(json|lock)|build\.sh|\.gitignore' \
  | rsync -a --files-from=- "$PLUGIN_DIR/" "$BUILD_DIR/$PLUGIN_SLUG/"

echo "Creating ZIP archive..."
cd "$BUILD_DIR"
# zip -r updates an existing archive in place, so stale entries would survive.
rm -f "$ZIP_FILE"
zip -rq "$ZIP_FILE" "$PLUGIN_SLUG/"

rm -rf "$BUILD_DIR"

echo "Build complete: $ZIP_FILE"
