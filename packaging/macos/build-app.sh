#!/usr/bin/env bash
# Build Kalo.app and a distributable ZIP for macOS.
#
# Usage (from the repository root on macOS):
#   ./packaging/macos/build-app.sh
#
# By default both Apple Silicon and Intel binaries are built and combined into
# a universal app. Set KALO_MACOS_UNIVERSAL=0 to build only the host
# architecture. KALO_CODESIGN_IDENTITY can point at a Developer ID identity;
# without it the app is ad-hoc signed, which is enough for local testing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the macOS app bundle can only be built on macOS" >&2
  exit 1
fi

VERSION="$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
  echo "error: cannot read package version from Cargo.toml" >&2
  exit 1
fi

APP_NAME="Kalo"
APP="$ROOT/dist/$APP_NAME.app"
IDENTITY="${KALO_CODESIGN_IDENTITY:--}"

if [[ "${KALO_MACOS_UNIVERSAL:-1}" == "0" ]]; then
  HOST="$(rustc -vV | awk '/^host: / { print $2 }')"
  TARGETS=("$HOST")
else
  TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
fi

BINARIES=()
for target in "${TARGETS[@]}"; do
  cargo build --release --locked --target "$target"
  BINARIES+=("$ROOT/target/$target/release/kalo")
done

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
install -m644 packaging/macos/Kalo.icns "$APP/Contents/Resources/Kalo.icns"
sed "s/__VERSION__/$VERSION/g" packaging/macos/Info.plist \
  > "$APP/Contents/Info.plist"

if [[ "${#BINARIES[@]}" -gt 1 ]]; then
  lipo -create "${BINARIES[@]}" -output "$APP/Contents/MacOS/kalo"
else
  install -m755 "${BINARIES[0]}" "$APP/Contents/MacOS/kalo"
fi
chmod 0755 "$APP/Contents/MacOS/kalo"

# Ad-hoc signing keeps Gatekeeper's integrity check meaningful; a Developer ID
# can be supplied for distribution outside the rolling development builds.
codesign --force --timestamp=none --sign "$IDENTITY" "$APP"
codesign --verify --deep --strict "$APP"

mkdir -p "$ROOT/dist"
if [[ "${#BINARIES[@]}" -gt 1 ]]; then
  ZIP="$ROOT/dist/kalo-macos-universal.zip"
else
  case "$(uname -m)" in
    arm64) ARCH="arm64" ;;
    x86_64) ARCH="x64" ;;
    *) ARCH="$(uname -m)" ;;
  esac
  ZIP="$ROOT/dist/kalo-macos-$ARCH.zip"
fi
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"

echo "Built $APP"
echo "Built $ZIP"
