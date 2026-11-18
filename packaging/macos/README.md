# macOS packaging

Kalo for macOS is distributed as an ad-hoc signed application bundle inside a
ZIP archive. Sending uses Apple's IOBluetooth Object Push support; receiving is
handled by macOS itself through **System Settings → General → Sharing →
Bluetooth Sharing**, because Apple does not expose a public API for hosting an
OPP receiver.

The published development build is a universal app (Apple Silicon and Intel)
and is named `kalo-macos-universal.zip`. It is not notarized, so the first
launch requires **Control-click → Open**, or **System Settings → Privacy &
Security → Open Anyway**.

## Build

Build on macOS with the Rust toolchain and both Apple targets installed:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
./packaging/macos/build-app.sh
```

The script writes `dist/Kalo.app` and `dist/kalo-macos-universal.zip`. To build
only the host architecture, run:

```sh
KALO_MACOS_UNIVERSAL=0 ./packaging/macos/build-app.sh
```

For a signed build, provide an identity from `security find-identity -v -p
codesigning`:

```sh
KALO_CODESIGN_IDENTITY="Developer ID Application: Example (TEAMID)" \
  ./packaging/macos/build-app.sh
```

The default is an ad-hoc signature (`-`), which is suitable for local use and
for the rolling GitHub development builds.

## Bundle contents

- `Contents/MacOS/kalo` — the universal executable.
- `Contents/Info.plist` — version, bundle identifier
  `com.github.ogalesha.kalo`, minimum macOS 11, and the Bluetooth usage
  description macOS requires.
- `Contents/Resources/Kalo.icns` — the app icon, generated from the Kalo
  artwork.

## Runtime requirements

- macOS 11 or newer.
- Bluetooth enabled, and the destination device paired in System Settings.
- Permission granted when macOS asks Kalo to use Bluetooth.
- To receive files, enable **Bluetooth Sharing** and choose a destination
  folder in System Settings.

Kalo cannot register a receiver on macOS, so its receiver status explains this
and points at Bluetooth Sharing. The CLI reports the same limitation for
`kalo receive` and `kalo agent-check`.
