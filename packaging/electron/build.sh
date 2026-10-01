#!/usr/bin/env bash
# Build the Meridian Platform windowed application (Electron) for Windows.
#
# Output: build/Meridian-Platform-win32-x64/  — a ready-to-run app folder
# (Meridian.exe + resources/app with the launcher, icon and platform payload).
# The one-file setup (packaging/installer) embeds this tree.
#
# Requirements: network (downloads Electron once into .cache), python3.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="1.0.1"
ELECTRON_VERSION="44.5.1"
CACHE=".cache"
OUT="build/Meridian-Platform-win32-x64"

# ---- 1. platform payload: package.json + src + webroot + fixtures/vuln-app ----
REPO_ROOT="$(cd ../.. && pwd)"
echo "staging platform payload from the repo..."
rm -rf payload-tree
mkdir -p payload-tree/fixtures
cp "$REPO_ROOT/package.json" payload-tree/
cp -r "$REPO_ROOT/src" "$REPO_ROOT/webroot" payload-tree/
cp -r "$REPO_ROOT/fixtures/vuln-app" payload-tree/fixtures/
python3 patch-seed.py payload-tree/src/seed/seed.js   # fixture ports follow FIXTURE_*_PORT envs
FILES=$(find payload-tree -type f | wc -l)
echo "payload: $FILES files"
mkdir -p payload
tar --format=ustar -czf payload/app.tgz -C payload-tree .

# ---- 2. electron runtime ----
ZIP="$CACHE/electron.zip"
if [ ! -s "$ZIP" ]; then
  echo "downloading Electron v$ELECTRON_VERSION (win32-x64)..." >&2
  mkdir -p "$CACHE"
  curl -sSL -o "$ZIP" "https://github.com/electron/electron/releases/download/v$ELECTRON_VERSION/electron-v$ELECTRON_VERSION-win32-x64.zip" >&2
fi
rm -rf "$CACHE/extracted" "$OUT"
python3 - "$ZIP" "$CACHE/extracted" << 'PYEOF'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
print("electron extracted")
PYEOF
mkdir -p "$OUT"
cp -r "$CACHE/extracted/." "$OUT/"
mv "$OUT/electron.exe" "$OUT/Meridian.exe"
rm -f "$OUT/resources/default_app.asar"
( cd "$OUT/locales" && for f in *.pak; do [ "$f" != "en-US.pak" ] && rm -f "$f"; done )

# ---- 3. application ----
mkdir -p "$OUT/resources/app/payload"
cp main.cjs "$OUT/resources/app/main.cjs"
cp app-package.json "$OUT/resources/app/package.json"
cp "$REPO_ROOT/apps/desktop/src-tauri/icons/icon.png" "$OUT/resources/app/icon.png"
cp payload/app.tgz "$OUT/resources/app/payload/app.tgz"

echo "built: $OUT ($(find "$OUT" -type f | wc -l) files, $(du -sh "$OUT" | cut -f1))"
