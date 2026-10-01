#!/usr/bin/env bash
# Build the Meridian Platform ONE-FILE SETUP.
#
# Architecture (same overlay technique commercial installers use):
#   [node.exe + tiny SEA blob (launcher)] [app.tar.gz overlay] [64-byte footer]
# The launcher (installer.cjs) reads the overlay from its own file tail,
# installs the windowed app, creates shortcuts + uninstall entry, launches it.
#
# Prerequisites: packaging/electron built first (build/Meridian-Platform-win32-x64).
# Requirements: network (downloads Node once into .cache), python3, npx postject.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="1.0.1"
NODE_VERSION="v24.21.0"   # must match the SEA blob generator
SENTINEL="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"
CACHE=".cache"

APPDIR="../electron/build/Meridian-Platform-win32-x64"
[ -d "$APPDIR" ] || { echo "error: run packaging/electron/build.sh first" >&2; exit 1; }

# node binaries (downloaded once)
if [ ! -x "$CACHE/node-linux/bin/node" ]; then
  echo "downloading Node $NODE_VERSION (win+linux)..." >&2
  mkdir -p "$CACHE/node-win" "$CACHE/node-linux"
  curl -sSL -o "$CACHE/node-win/node.zip" "https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-win-x64.zip" >&2
  curl -sSL -o "$CACHE/node-linux/node.tar.xz" "https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-linux-x64.tar.xz" >&2
  ( cd "$CACHE/node-win" && python3 -c "import zipfile; zipfile.ZipFile('node.zip').extractall('.')" )
  [ -d "$CACHE/node-win/node-$NODE_VERSION-win-x64" ] && mv "$CACHE/node-win/node-$NODE_VERSION-win-x64"/* "$CACHE/node-win/"
  tar -xf "$CACHE/node-linux/node.tar.xz" -C "$CACHE/node-linux" --strip-components=1
fi
[ -f "$CACHE/node-win/node.exe" ] && [ -x "$CACHE/node-linux/bin/node" ] || { echo "error: node binaries missing" >&2; exit 1; }

echo "staging application tree (the windowed app)..."
mkdir -p payload
tar --format=ustar -czf payload/app.tgz -C "$APPDIR" .
echo "payload: $(du -h payload/app.tgz | cut -f1) ($(tar -tzf payload/app.tgz | grep -vc '/$') files)"

# tiny SEA blob (launcher only — the app travels as the overlay)
"$CACHE/node-linux/bin/node" --experimental-sea-config sea-config.json
echo "blob: $(du -h sea-prep.blob | cut -f1)"

append_overlay() { # $1 = exe — appends payload + 64-byte footer
  python3 - "$1" payload/app.tgz << 'PYEOF'
import struct, sys
exe, tgz = sys.argv[1], sys.argv[2]
payload = open(tgz, 'rb').read()
footer = b'MERIDIAN-OVL1' + struct.pack('<Q', len(payload)) + b'\x00' * 43
assert len(footer) == 64
with open(exe, 'ab') as f:
    f.write(payload)
    f.write(footer)
print(f'overlay appended: {len(payload)/1048576:.1f} MB -> {exe}')
PYEOF
}

# ---- Linux twin (verification target; same code, same overlay) ----
LINUX_OUT="Meridian-Setup-$VERSION-linux-x64"
rm -f "$LINUX_OUT"
cp "$CACHE/node-linux/bin/node" "$LINUX_OUT"
chmod +w "$LINUX_OUT"
npx --yes postject "$LINUX_OUT" NODE_SEA_BLOB sea-prep.blob --sentinel-fuse "$SENTINEL" 2>&1 | grep -v "string offset" >&2 || true
chmod +x "$LINUX_OUT"
append_overlay "$LINUX_OUT"
echo "built: $LINUX_OUT ($(du -h "$LINUX_OUT" | cut -f1))"

# ---- Windows setup ----
WIN_OUT="Meridian-Setup-$VERSION.exe"
rm -f "$WIN_OUT"
cp "$CACHE/node-win/node.exe" "$WIN_OUT"
python3 - "$WIN_OUT" << 'PYEOF'
import struct, sys
p = sys.argv[1]
data = bytearray(open(p, 'rb').read())
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
sec_dir = e_lfanew + 24 + 112 + 4 * 8
va, size = struct.unpack_from('<II', data, sec_dir)
if va and size:
    struct.pack_into('<II', data, sec_dir, 0, 0)
    open(p, 'wb').write(data)
    print(f'signature stripped ({size} bytes)')
PYEOF
npx --yes postject "$WIN_OUT" NODE_SEA_BLOB sea-prep.blob --sentinel-fuse "$SENTINEL" 2>&1 | grep -v "string offset" >&2 || true
append_overlay "$WIN_OUT"
echo "built: $WIN_OUT ($(du -h "$WIN_OUT" | cut -f1))"
echo "sha256: $(sha256sum "$WIN_OUT" | cut -d' ' -f1)"
