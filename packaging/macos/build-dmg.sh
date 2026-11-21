#!/bin/bash
# Builds WG2FA.app (universal arm64+x86_64) and wraps it in a DMG.
# Usage: packaging/macos/build-dmg.sh <version> [outdir]
set -euo pipefail
VERSION="${1:-dev}"
OUT="${2:-dist}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
APP="$WORK/stage/WG2FA.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$OUT"

cd "$ROOT"
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$WORK/wg2fa-client-$arch" ./cmd/wg2fa-client
done
lipo -create -output "$APP/Contents/Resources/wg2fa-client" "$WORK/wg2fa-client-arm64" "$WORK/wg2fa-client-amd64"
chmod 755 "$APP/Contents/Resources/wg2fa-client"

cp packaging/macos/launcher.sh "$APP/Contents/MacOS/WG2FA"
chmod 755 "$APP/Contents/MacOS/WG2FA"
sed "s/__VERSION__/${VERSION#v}/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"

# App icon (.icns) from icon.png
if [ -f packaging/macos/icon.png ] && command -v iconutil >/dev/null; then
  ICONSET="$WORK/WG2FA.iconset"; mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z $s $s packaging/macos/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s*2)) $((s*2)) packaging/macos/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/WG2FA.icns"
fi

# Sign: Developer ID if provided, otherwise ad-hoc (required on Apple Silicon)
IDENTITY="${MACOS_SIGN_IDENTITY:--}"
TS="--timestamp=none"; [ "$IDENTITY" != "-" ] && TS="--timestamp"
codesign --force --options runtime $TS -s "$IDENTITY" "$APP/Contents/Resources/wg2fa-client"
codesign --force --options runtime $TS -s "$IDENTITY" "$APP"

cp packaging/macos/uninstall.command "$WORK/stage/Uninstall WG2FA.command"
chmod 755 "$WORK/stage/Uninstall WG2FA.command"
ln -s /Applications "$WORK/stage/Applications"

DMG="$OUT/WG2FA-${VERSION}-macos-universal.dmg"
hdiutil create -volname "WG2FA ${VERSION}" -srcfolder "$WORK/stage" -ov -format UDZO "$DMG"
if [ "$IDENTITY" != "-" ]; then codesign -s "$IDENTITY" --timestamp "$DMG"; fi
echo "built $DMG"
