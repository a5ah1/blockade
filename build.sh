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

rsync -a \
  --exclude='.git' \
  --exclude='.gitignore' \
  --exclude='.claude' \
  --exclude='CLAUDE.md' \
  --exclude='composer.json' \
  --exclude='composer.lock' \
  --exclude='build.sh' \
  --exclude='*.zip' \
  --exclude='.DS_Store' \
  --exclude='*.log' \
  --exclude='.idea' \
  --exclude='.vscode' \
  --exclude='node_modules' \
  "$PLUGIN_DIR/" "$BUILD_DIR/$PLUGIN_SLUG/"

echo "Creating ZIP archive..."
cd "$BUILD_DIR"
zip -rq "$ZIP_FILE" "$PLUGIN_SLUG/"

rm -rf "$BUILD_DIR"

echo "Build complete: $ZIP_FILE"
