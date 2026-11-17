#!/usr/bin/env bash
# Build an Ubuntu/Debian .deb for Kalo without needing debhelper or cargo-deb.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PKG="kalo"
VERSION="$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
  echo "error: cannot read package version from Cargo.toml" >&2
  exit 1
fi
DEB_VERSION="${VERSION}-1"
ARCH="${DEB_ARCH:-$(dpkg --print-architecture)}"
OUT="$ROOT/dist"
DEB="$OUT/${PKG}_${DEB_VERSION}_${ARCH}.deb"

MAINTAINER="${DEB_MAINTAINER:-}"
if [[ -z "$MAINTAINER" ]]; then
  name="$(git config user.name 2>/dev/null || true)"
  email="$(git config user.email 2>/dev/null || true)"
  if [[ -n "$name" && -n "$email" ]]; then
    MAINTAINER="$name <$email>"
  else
    MAINTAINER="Kalo Maintainers <kalo@localhost>"
  fi
fi

if ! command -v dpkg-deb >/dev/null; then
  echo "error: dpkg-deb not found (install the 'dpkg' package)" >&2
  exit 1
fi

if [[ "${1:-}" != "--no-build" ]]; then
  cargo build --release --locked
fi

mkdir -p "$OUT"
STAGE="$(mktemp -d "$OUT/.stage.XXXXXX")"
chmod 0755 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT

install -Dm755 target/release/kalo "$STAGE/usr/bin/kalo"
install -Dm644 packaging/common/kalo.desktop \
  "$STAGE/usr/share/applications/kalo.desktop"
install -Dm644 packaging/common/kalo.svg \
  "$STAGE/usr/share/icons/hicolor/scalable/apps/kalo.svg"
install -Dm644 packaging/ubuntu/copyright \
  "$STAGE/usr/share/doc/$PKG/copyright"
install -Dm644 packaging/common/kalo.1 "$STAGE/usr/share/man/man1/kalo.1"
gzip -9n "$STAGE/usr/share/man/man1/kalo.1"
chmod 0644 "$STAGE/usr/share/man/man1/kalo.1.gz"

# Debian ships stripped binaries; the Cargo artifact stays untouched.
if command -v strip >/dev/null 2>&1; then
  strip --strip-unneeded "$STAGE/usr/bin/kalo"
fi

{
  printf '%s (%s) stable; urgency=medium\n\n' "$PKG" "$DEB_VERSION"
  printf '  * Local package built from Cargo.toml version %s.\n\n' "$VERSION"
  printf ' -- %s  %s\n' "$MAINTAINER" "$(date -R)"
} | gzip -9n > "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"

INSTALLED_SIZE="$(du -sk "$STAGE/usr" | cut -f1)"
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $DEB_VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_SIZE
Section: net
Priority: optional
Depends: libc6, libgcc-s1, libxkbcommon0, libxkbcommon-x11-0, libx11-6, libwayland-client0
Recommends: bluez, bluez-obexd, xdg-desktop-portal, xdg-desktop-portal-gtk | xdg-desktop-portal-kde, libvulkan1
Description: Bluetooth file sharing for Ubuntu
 Kalo sends and receives files over Bluetooth OPP/OBEX. It provides a
 desktop UI, a receiver agent that saves incoming files to ~/Downloads,
 and CLI commands for discovering devices, pairing, and transfers.
EOF

dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$DEB" >/dev/null
echo "Built $DEB ($(du -h "$DEB" | cut -f1))"
